import { SigHash, Transaction } from '@scure/btc-signer';
import { schnorr, secp256k1 } from '@noble/curves/secp256k1';
import { deriveAccountNode } from '../keys/derivation';
import { scriptPubKeyHex } from '../keys/script-hash';
import { zeroize } from '../vault/vault';
import { getCryptoProvider } from '../vault/crypto-provider';
import type { Network } from '../keys/derivation';
import type { PlanInput, PlanOutput, TransactionPlan } from './plan';
import { assertPlanHash } from './plan';
import {
  analysisContextFromPlan,
  analyzePsbtHex,
  analyzeRawTransactionHex,
} from './analysis';
import { DEFAULT_POSTAGE_SATS, FINAL_SEQUENCE, scriptDustSats } from './fees';
import { publicAccountFromSeed } from '../accounts/public-account';
import { parseCanonicalSatpoint } from '../ordinals/satpoint';
import { canonicalOrdinalBatchSelections } from './ordinal-transfer';
import { resolveOrdinalPostageTarget } from './postage-manage';

/** MAX_STANDARD_TX_WEIGHT / 4, conservative because vsize rounds weight up. */
export const MAX_STANDARD_TRANSACTION_VSIZE = 100_000n;

export function assertStandardTransactionVsize(vsize: bigint, serialized = false): void {
  if (vsize > MAX_STANDARD_TRANSACTION_VSIZE) {
    throw new Error(`${serialized ? 'signed ' : ''}transaction exceeds standard weight limit`);
  }
}

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0 || !/^[0-9a-f]*$/.test(hex)) throw new Error('invalid hex');
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i += 1) bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function walletDerivation(input: PlanInput) {
  if (input.ownership === 'external' || input.derivation === null) {
    throw new Error('external input cannot be signed by native plan signer');
  }
  return input.derivation;
}

export function buildPsbtHex(inputs: readonly PlanInput[], outputs: readonly PlanOutput[]): string {
  const tx = new Transaction({ lowR: true });
  for (const input of inputs) {
    const derivation = walletDerivation(input);
    const update = {
      txid: input.txid,
      index: input.vout,
      sequence: input.sequence,
      witnessUtxo: { script: hexToBytes(input.scriptPubKey), amount: input.valueSats },
      sighashType: input.sighash,
      ...(derivation.lane === 'ordinals'
        ? { tapInternalKey: hexToBytes(derivation.publicKeyHex).slice(1) }
        : {}),
    };
    tx.addInput(update);
  }
  for (const output of outputs) {
    tx.addOutput({ script: hexToBytes(output.scriptPubKey), amount: output.valueSats });
  }
  return bytesToHex(tx.toPSBT());
}

export interface SignedTransaction {
  transactionHex: string;
  txid: string;
  wtxid: string;
  vsize: bigint;
}

export function signAndValidatePlan(
  plan: TransactionPlan,
  seed: Uint8Array,
  random: (length: number) => Uint8Array,
): SignedTransaction {
  assertPlanHash(plan);
  assertStandardTransactionVsize(plan.vsize);
  const signerAccount = publicAccountFromSeed(seed, plan.network, plan.account);
  if (signerAccount.accountId !== plan.accountId) {
    throw new Error('signer public account does not match transaction plan');
  }
  const before = analyzePsbtHex(plan.psbtHex, analysisContextFromPlan(plan));
  if (!before.ok || before.analysisHash !== plan.analysisHash || before.analysis.hardViolations.length > 0) {
    throw new Error('transaction analysis differs from plan');
  }
  const tx = Transaction.fromPSBT(hexToBytes(plan.psbtHex), { lowR: true });
  if (tx.inputsLength !== plan.inputs.length || tx.outputsLength !== plan.outputs.length) {
    throw new Error('PSBT shape differs from plan');
  }
  validatePsbtAgainstPlan(tx, plan);
  validateProtectedSatFlow(plan);

  for (let index = 0; index < plan.inputs.length; index += 1) {
    const input = plan.inputs[index]!;
    const derivation = walletDerivation(input);
    if (derivation.accountId !== plan.accountId || derivation.account !== plan.account) {
      throw new Error('input public account identity differs from plan');
    }
    if ((derivation.lane === 'payment' && input.sighash !== 1) ||
        (derivation.lane === 'ordinals' && input.sighash !== 0)) {
      throw new Error('sighash policy mismatch');
    }
    const account = deriveAccountNode(seed, derivation.lane, plan.network, derivation.account);
    const chain = account.deriveChild(derivation.chain);
    const key = chain.deriveChild(derivation.index);
    try {
      if (!key.publicKey || !key.privateKey) throw new Error('derived signing key unavailable');
      const publicKeyHex = bytesToHex(key.publicKey);
      if (
        publicKeyHex !== derivation.publicKeyHex ||
        scriptPubKeyHex(publicKeyHex, derivation.lane, plan.network) !== input.scriptPubKey
      ) {
        throw new Error('input ownership proof mismatch');
      }
      const privateKey = key.privateKey;
      try {
        tx.signIdx(
          privateKey,
          index,
          [input.sighash === 0 ? SigHash.DEFAULT : SigHash.ALL],
          input.sighash === 0 ? random(32) : undefined,
        );
      } finally {
        zeroize(privateKey);
      }
      const signedInput = tx.getInput(index);
      if (input.sighash === 0) {
        if (!signedInput.tapKeySig || signedInput.tapKeySig.length !== 64) {
          throw new Error('missing Taproot signature');
        }
      } else if (!signedInput.partialSig || signedInput.partialSig.length !== 1) {
        throw new Error('missing P2WPKH signature');
      }
    } finally {
      key.wipePrivateData();
      chain.wipePrivateData();
      account.wipePrivateData();
    }
  }
  tx.finalize();
  const raw = tx.extract();
  return validateSignedTransactionHex(plan, bytesToHex(raw));
}

/** Shared post-transport validator for software now and Ledger/offline later. */
export function validateSignedTransactionHex(
  plan: TransactionPlan,
  transactionHex: string,
): SignedTransaction {
  assertPlanHash(plan);
  let reparsed: Transaction;
  let analyzed: ReturnType<typeof analyzeRawTransactionHex>;
  try {
    reparsed = Transaction.fromRaw(hexToBytes(transactionHex));
    analyzed = analyzeRawTransactionHex(transactionHex, analysisContextFromPlan(plan));
  } catch {
    throw new Error('signed transaction analysis could not parse exact bytes');
  }
  if (!analyzed.ok || analyzed.analysisHash !== plan.analysisHash || analyzed.analysis.hardViolations.length > 0) {
    throw new Error('signed transaction analysis differs from approved plan');
  }
  validateRawAgainstPlan(reparsed, plan);
  assertStandardTransactionVsize(BigInt(reparsed.vsize), true);
  validateProtectedSatFlow(plan);
  verifySerializedSignatures(reparsed, plan);
  const raw = hexToBytes(transactionHex);
  const digest = getCryptoProvider().sha256(getCryptoProvider().sha256(raw));
  const wtxid = bytesToHex(Uint8Array.from(digest).reverse());
  return { transactionHex, txid: reparsed.id, wtxid, vsize: BigInt(reparsed.vsize) };
}

function verifySerializedSignatures(tx: Transaction, plan: TransactionPlan): void {
  const prevoutScripts = plan.inputs.map((input) => hexToBytes(input.scriptPubKey));
  const amounts = plan.inputs.map((input) => input.valueSats);
  for (let index = 0; index < plan.inputs.length; index += 1) {
    const expected = plan.inputs[index]!;
    const derivation = walletDerivation(expected);
    const witness = tx.getInput(index).finalScriptWitness ?? [];
    if (derivation.lane === 'payment') {
      const signatureWithType = witness[0];
      const publicKey = witness[1];
      if (!signatureWithType || signatureWithType.length < 2 || !publicKey ||
          bytesToHex(publicKey) !== derivation.publicKeyHex ||
          signatureWithType[signatureWithType.length - 1] !== expected.sighash) {
        throw new Error('invalid P2WPKH witness');
      }
      const keyHash = expected.scriptPubKey.slice(4);
      const scriptCode = hexToBytes(`76a914${keyHash}88ac`);
      const message = tx.preimageWitnessV0(index, scriptCode, expected.sighash, expected.valueSats);
      const signature = signatureWithType.slice(0, -1);
      if (!secp256k1.verify(signature, message, publicKey, { format: 'der', prehash: false, lowS: true })) {
        throw new Error('invalid P2WPKH signature');
      }
    } else {
      if (witness.length !== 1) throw new Error('unsupported Taproot script-path witness');
      const signatureWithType = witness[0];
      if (!signatureWithType || (signatureWithType.length !== 64 && signatureWithType.length !== 65)) {
        throw new Error('invalid Taproot witness');
      }
      const sighash = signatureWithType.length === 64 ? 0 : signatureWithType[64]!;
      if (sighash !== expected.sighash) throw new Error('Taproot sighash differs from plan');
      const message = tx.preimageWitnessV1(index, prevoutScripts, sighash, amounts);
      const outputKey = hexToBytes(expected.scriptPubKey).slice(2);
      if (!schnorr.verify(signatureWithType.slice(0, 64), message, outputKey)) {
        throw new Error('invalid Taproot signature');
      }
    }
  }
}

function validatePsbtAgainstPlan(tx: Transaction, plan: TransactionPlan): void {
  for (let index = 0; index < plan.inputs.length; index += 1) {
    const expected = plan.inputs[index]!;
    const actual = tx.getInput(index);
    if (!actual.txid || bytesToHex(actual.txid) !== expected.txid || actual.index !== expected.vout ||
        actual.sequence !== expected.sequence || actual.sighashType !== expected.sighash ||
        actual.witnessUtxo?.amount !== expected.valueSats || !actual.witnessUtxo.script ||
        bytesToHex(actual.witnessUtxo.script) !== expected.scriptPubKey) {
      throw new Error('PSBT prevout or sighash differs from plan');
    }
  }
  for (let index = 0; index < plan.outputs.length; index += 1) {
    const expected = plan.outputs[index]!;
    const actual = tx.getOutput(index);
    if (!actual.script || bytesToHex(actual.script) !== expected.scriptPubKey || actual.amount !== expected.valueSats) {
      throw new Error('PSBT output differs from plan');
    }
  }
  const inputTotal = plan.inputs.reduce((sum, input) => sum + input.valueSats, 0n);
  const outputTotal = plan.outputs.reduce((sum, output) => sum + output.valueSats, 0n);
  if (inputTotal <= outputTotal || inputTotal - outputTotal !== plan.feeSats) {
    throw new Error('plan fee is inconsistent');
  }
}

function validateProtectedSatFlow(plan: TransactionPlan): void {
  for (const flow of plan.protectedSatFlow) {
    const input = plan.inputs[flow.inputIndex];
    const output = plan.outputs[flow.outputIndex];
    if (!input || !output || flow.inputOffset >= input.valueSats || flow.outputOffset >= output.valueSats ||
        !input.classification.inscriptions.some((item) => item.inscriptionId === flow.inscriptionId)) {
      throw new Error('protected sat flow is invalid');
    }
    const inputPosition = plan.inputs.slice(0, flow.inputIndex)
      .reduce((sum, item) => sum + item.valueSats, 0n) + flow.inputOffset;
    const outputPosition = plan.outputs.slice(0, flow.outputIndex)
      .reduce((sum, item) => sum + item.valueSats, 0n) + flow.outputOffset;
    if (inputPosition !== outputPosition) throw new Error('protected sat moved');
  }
  if (plan.kind === 'rescue') {
    const intent = plan.policy.intent;
    const source = plan.inputs[0];
    const flow = plan.protectedSatFlow[0];
    if (intent.kind !== 'rescue' || !source ||
        source.txid !== intent.outpoint.txid || source.vout !== intent.outpoint.vout ||
        plan.protectedSatFlow.length !== 1 || !flow ||
        flow.inputIndex !== 0 || flow.outputIndex !== 0 ||
        plan.outputs[0]?.role !== 'postage' || plan.outputs[0].valueSats < DEFAULT_POSTAGE_SATS ||
        source.derivation?.lane !== 'payment' ||
        source.classification.primaryClass !== 'inscribed' ||
        source.classification.inscriptions.length !== 1 ||
        source.classification.confidence !== 'authoritative' ||
        source.classification.unsupportedAssetDetected ||
        source.classification.satRanges?.some((range) =>
          range.rarity !== undefined && range.rarity !== 'common') ||
        plan.inputs.some((input, index) => index > 0 && !isAuthoritativeCleanFunding(input)) ||
        plan.inputs.some((input) => input.sequence !== FINAL_SEQUENCE) ||
        plan.outputs[0].derivation?.lane !== 'ordinals' ||
        plan.rbf) {
      throw new Error('rescue policy mismatch');
    }
  }
  if (plan.kind === 'ordinal_transfer') {
    const intent = plan.policy.intent;
    const source = plan.inputs[0];
    if (intent.kind !== 'ordinal_transfer' || !source ||
        source.txid !== intent.outpoint.txid || source.vout !== intent.outpoint.vout ||
        source.derivation?.account !== intent.account || source.derivation.lane !== 'ordinals' ||
        source.classification.confidence !== 'authoritative' ||
        source.classification.unsupportedAssetDetected ||
        source.classification.satRanges?.some((range) =>
          range.rarity !== undefined && range.rarity !== 'common') ||
        (source.classification.primaryClass !== 'inscribed' &&
          source.classification.primaryClass !== 'mixed') ||
        plan.account !== intent.account || plan.rbf ||
        plan.inputs.some((input, index) => index > 0 && !isAuthoritativeCleanFunding(input)) ||
        plan.inputs.some((input) => input.sequence !== FINAL_SEQUENCE)) {
      throw new Error('ordinal transfer input policy mismatch');
    }
    const targetFlow = plan.protectedSatFlow.filter(
      (flow) => flow.inscriptionId === intent.inscriptionId,
    );
    if (targetFlow.length !== 1) throw new Error('ordinal transfer target is ambiguous');
    const target = targetFlow[0]!;
    const targetOutput = plan.outputs[target.outputIndex];
    if (
      target.inputIndex !== 0 ||
      !targetOutput ||
      targetOutput.role !== 'postage' ||
      targetOutput.address !== intent.recipient ||
      targetOutput.derivation !== undefined ||
      targetOutput.valueSats < scriptDustSats(targetOutput.scriptPubKey) ||
      plan.protectedSatFlow.some((flow) =>
        flow.inscriptionId !== intent.inscriptionId &&
        flow.inputIndex === target.inputIndex &&
        flow.inputOffset === target.inputOffset)
    ) {
      throw new Error('ordinal transfer target policy mismatch');
    }
    const sourceInscriptionIds = new Set(
      source.classification.inscriptions.map((item) => item.inscriptionId),
    );
    const flowInscriptionIds = new Set(plan.protectedSatFlow.map((flow) => flow.inscriptionId));
    if (
      sourceInscriptionIds.size !== flowInscriptionIds.size ||
      [...sourceInscriptionIds].some((id) => !flowInscriptionIds.has(id)) ||
      plan.protectedSatFlow.some((flow) => {
        if (flow.inputIndex !== 0) return true;
        if (flow.inscriptionId === intent.inscriptionId) return false;
        const output = plan.outputs[flow.outputIndex];
        return output?.role !== 'ordinal_change' || output.derivation?.lane !== 'ordinals';
      })
    ) {
      throw new Error('ordinal transfer retained-inscription policy mismatch');
    }
  }
  if (plan.kind === 'ordinal_batch_transfer') {
    validateOrdinalBatchPolicy(plan);
  }
  if (plan.kind === 'ordinal_postage_manage') {
    validateOrdinalPostagePolicy(plan);
  }
  if (plan.kind === 'ordinal_sweep') {
    const intent = plan.policy.intent;
    const source = plan.inputs[0];
    if (
      intent.kind !== 'ordinal_sweep' ||
      !source ||
      source.txid !== intent.outpoint.txid ||
      source.vout !== intent.outpoint.vout ||
      plan.protectedSatFlow.length !== 0 ||
      plan.inputs.length !== 1 ||
      source.sequence !== FINAL_SEQUENCE ||
      source.derivation?.lane !== 'ordinals' ||
      !isAuthoritativeCleanFunding(source, 'ordinals') ||
      plan.outputs.length !== 2 ||
      plan.outputs[0]?.role !== 'ordinal_change' ||
      plan.outputs[0].derivation?.lane !== 'ordinals' ||
      plan.outputs[0].valueSats !== DEFAULT_POSTAGE_SATS ||
      plan.outputs[1]?.role !== 'payment_change' ||
      plan.outputs[1].derivation?.lane !== 'payment' ||
      plan.rbf
    ) {
      throw new Error('ordinal sweep policy mismatch');
    }
  }
}

function validateOrdinalPostagePolicy(plan: TransactionPlan): void {
  const intent = plan.policy.intent;
  if (intent.kind !== 'ordinal_postage_manage' || intent.selections.length < 1 ||
      intent.selections.length > 16 || plan.account !== intent.account || plan.rbf ||
      plan.inputs.some((input) => input.sequence !== FINAL_SEQUENCE)) {
    throw new Error('ordinal postage management policy mismatch');
  }
  const selected = canonicalOrdinalBatchSelections(intent.selections);
  if (selected.length !== intent.selections.length || selected.some((item, index) =>
    item.inscriptionId !== intent.selections[index]?.inscriptionId)) {
    throw new Error('ordinal postage selections are not canonical');
  }
  const sourceIndexes: number[] = [];
  for (const selection of intent.selections) {
    const inputIndex = plan.inputs.findIndex((input) =>
      input.txid === selection.outpoint.txid && input.vout === selection.outpoint.vout);
    const source = plan.inputs[inputIndex];
    const parsed = parseCanonicalSatpoint(selection.satpoint);
    const flow = plan.protectedSatFlow.find((item) =>
      item.inputIndex === inputIndex && item.inscriptionId === selection.inscriptionId);
    const output = flow ? plan.outputs[flow.outputIndex] : undefined;
    if (!source || !parsed || parsed.offset !== 0n || sourceIndexes.includes(inputIndex) ||
        source.derivation?.lane !== 'ordinals' || source.derivation.account !== intent.account ||
        source.classification.primaryClass !== 'inscribed' ||
        source.classification.confidence !== 'authoritative' ||
        source.classification.unsupportedAssetDetected ||
        source.classification.inscriptions.length !== 1 ||
        source.classification.inscriptions[0]?.inscriptionId !== selection.inscriptionId ||
        source.classification.inscriptions[0]?.satpoint !== selection.satpoint ||
        source.classification.classificationRevision !== selection.classificationRevision ||
        source.classification.classificationRevision !== plan.source.classificationRevision ||
        source.classification.satRanges === null ||
        source.classification.satRanges.some((range) =>
          range.rarity !== undefined && range.rarity !== 'common') ||
        !flow || flow.inputOffset !== 0n || flow.outputOffset !== 0n ||
        !output || output.role !== 'postage' || output.derivation?.lane !== 'ordinals' ||
        output.valueSats < scriptDustSats(output.scriptPubKey)) {
      throw new Error('ordinal postage source policy mismatch');
    }
    const requested = resolveOrdinalPostageTarget(intent.target, source.valueSats, scriptDustSats(output.scriptPubKey));
    if (requested > source.valueSats && output.valueSats !== requested) {
      throw new Error('ordinal postage top-up differs from target');
    }
    if (requested <= source.valueSats &&
        (output.valueSats < requested || output.valueSats > source.valueSats)) {
      throw new Error('ordinal postage recovery differs from target');
    }
    sourceIndexes.push(inputIndex);
  }
  const sortedIndexes = [...sourceIndexes].sort((a, b) => a - b);
  if (sortedIndexes.some((index, position) => index !== position) ||
      plan.inputs.some((_input, index) => index >= sortedIndexes.length &&
        !isAuthoritativeCleanFunding(plan.inputs[index]!)) ||
      plan.outputs.some((output) => output.role === 'payment_change' &&
        (output.derivation?.lane !== 'payment' || output.valueSats < scriptDustSats(output.scriptPubKey))) ||
      plan.outputs.some((output) => output.role === 'recipient' || output.role === 'ordinal_change')) {
    throw new Error('ordinal postage funding or output policy mismatch');
  }
}

function validateOrdinalBatchPolicy(plan: TransactionPlan): void {
  const intent = plan.policy.intent;
  if (intent.kind !== 'ordinal_batch_transfer' || intent.selections.length < 1 ||
      intent.selections.length > 16 || plan.account !== intent.account || plan.rbf ||
      plan.inputs.some((input) => input.sequence !== FINAL_SEQUENCE)) {
    throw new Error('ordinal batch transfer policy mismatch');
  }
  const selectedIds = new Set(intent.selections.map((selection) => selection.inscriptionId));
  if (selectedIds.size !== intent.selections.length) {
    throw new Error('ordinal batch selection is ambiguous');
  }
  const canonicalSelections = canonicalOrdinalBatchSelections(intent.selections);
  if (canonicalSelections.some((selection, index) => {
    const actual = intent.selections[index];
    return !actual || selection.inscriptionId !== actual.inscriptionId ||
      selection.outpoint.txid !== actual.outpoint.txid || selection.outpoint.vout !== actual.outpoint.vout ||
      selection.satpoint !== actual.satpoint ||
      selection.classificationRevision !== actual.classificationRevision;
  })) {
    throw new Error('ordinal batch selection is not canonical');
  }
  const sourceIndexByOutpoint = new Map<string, number>();
  for (const selection of intent.selections) {
    const key = `${selection.outpoint.txid}:${selection.outpoint.vout}`;
    let inputIndex = sourceIndexByOutpoint.get(key);
    if (inputIndex === undefined) {
      inputIndex = plan.inputs.findIndex((input) =>
        input.txid === selection.outpoint.txid && input.vout === selection.outpoint.vout);
      if (inputIndex < 0) throw new Error('ordinal batch source is missing');
      sourceIndexByOutpoint.set(key, inputIndex);
    }
    const source = plan.inputs[inputIndex]!;
    const parsed = parseCanonicalSatpoint(selection.satpoint);
    const fact = source.classification.inscriptions.find((item) =>
      item.inscriptionId === selection.inscriptionId);
    if (!parsed || parsed.txid !== source.txid || parsed.vout !== source.vout ||
        parsed.offset >= source.valueSats || fact?.satpoint !== selection.satpoint ||
        source.classification.classificationRevision !== selection.classificationRevision ||
        source.classification.classificationRevision !== plan.source.classificationRevision) {
      throw new Error('ordinal batch selection binding changed');
    }
  }
  const protectedIndexes = [...sourceIndexByOutpoint.values()].sort((a, b) => a - b);
  if (protectedIndexes.some((inputIndex, index) => inputIndex !== index) ||
      protectedIndexes.length !== sourceIndexByOutpoint.size) {
    throw new Error('ordinal batch protected inputs are not a prefix');
  }
  for (const inputIndex of protectedIndexes) {
    const source = plan.inputs[inputIndex]!;
    if (source.derivation?.account !== intent.account || source.derivation.lane !== 'ordinals' ||
        source.classification.confidence !== 'authoritative' ||
        source.classification.unsupportedAssetDetected ||
        source.classification.satRanges?.some((range) =>
          range.rarity !== undefined && range.rarity !== 'common') ||
        (source.classification.primaryClass !== 'inscribed' &&
          source.classification.primaryClass !== 'mixed')) {
      throw new Error('ordinal batch source policy mismatch');
    }
    const sourceIds = new Set(source.classification.inscriptions.map((item) => item.inscriptionId));
    const selectedSourceIds = new Set(intent.selections
      .filter((selection) => selection.outpoint.txid === source.txid && selection.outpoint.vout === source.vout)
      .map((selection) => selection.inscriptionId));
    const sourceFlows = plan.protectedSatFlow.filter((flow) => flow.inputIndex === inputIndex);
    const flowIds = new Set(sourceFlows.map((flow) => flow.inscriptionId));
    if (sourceIds.size !== selectedSourceIds.size || sourceIds.size !== flowIds.size ||
        [...sourceIds].some((id) => !selectedSourceIds.has(id) || !flowIds.has(id))) {
      throw new Error('ordinal batch source selection is incomplete');
    }
  }
  if (plan.inputs.some((_input, index) =>
    index >= protectedIndexes.length && !isAuthoritativeCleanFunding(plan.inputs[index]!))) {
    throw new Error('ordinal batch fee input is not cardinal clean');
  }
  if (plan.outputs.some((output) =>
    output.role === 'payment_change' && (output.derivation?.lane !== 'payment' ||
      output.valueSats < scriptDustSats(output.scriptPubKey)))) {
    throw new Error('ordinal batch returned BTC is not wallet-owned payment change');
  }
  const destinationOutputBySatpoint = new Map<string, number>();
  for (const flow of plan.protectedSatFlow) {
    if (!selectedIds.has(flow.inscriptionId) || !protectedIndexes.includes(flow.inputIndex)) {
      throw new Error('ordinal batch flow is not selected');
    }
    const output = plan.outputs[flow.outputIndex];
    if (!output || output.role !== 'postage' || output.address !== intent.recipient ||
        output.valueSats < scriptDustSats(output.scriptPubKey) ||
        (output.derivation !== undefined && output.derivation.lane !== 'ordinals')) {
      throw new Error('ordinal batch destination policy mismatch');
    }
    const satpoint = `${flow.inputIndex}:${flow.inputOffset}`;
    const priorOutput = destinationOutputBySatpoint.get(satpoint);
    if (priorOutput !== undefined && priorOutput !== flow.outputIndex) {
      throw new Error('co-located ordinal batch inscriptions were separated');
    }
    destinationOutputBySatpoint.set(satpoint, flow.outputIndex);
  }
  if (new Set(destinationOutputBySatpoint.values()).size !== destinationOutputBySatpoint.size) {
    throw new Error('distinct ordinal batch satpoints share a destination output');
  }
}

function isAuthoritativeCleanFunding(
  input: PlanInput,
  lane: 'payment' | 'ordinals' = 'payment',
): boolean {
  return input.derivation?.lane === lane &&
    input.classification.primaryClass === 'cardinal_clean' &&
    input.classification.inscriptions.length === 0 &&
    input.classification.confidence === 'authoritative' &&
    !input.classification.unsupportedAssetDetected &&
    !input.classification.satRanges?.some((range) =>
      range.rarity !== undefined && range.rarity !== 'common');
}

function validateRawAgainstPlan(tx: Transaction, plan: TransactionPlan): void {
  if (tx.inputsLength !== plan.inputs.length || tx.outputsLength !== plan.outputs.length) {
    throw new Error('signed transaction shape differs from plan');
  }
  for (let index = 0; index < plan.inputs.length; index += 1) {
    const expected = plan.inputs[index]!;
    const actual = tx.getInput(index);
    if (
      !actual.txid ||
      bytesToHex(actual.txid) !== expected.txid ||
      actual.index !== expected.vout ||
      actual.sequence !== expected.sequence
    ) {
      throw new Error('signed transaction input differs from plan');
    }
  }
  for (let index = 0; index < plan.outputs.length; index += 1) {
    const expected = plan.outputs[index]!;
    const actual = tx.getOutput(index);
    if (
      !actual.script ||
      bytesToHex(actual.script) !== expected.scriptPubKey ||
      actual.amount !== expected.valueSats
    ) {
      throw new Error('signed transaction output differs from plan');
    }
  }
  const inputTotal = plan.inputs.reduce((sum, input) => sum + input.valueSats, 0n);
  const outputTotal = plan.outputs.reduce((sum, output) => sum + output.valueSats, 0n);
  if (inputTotal - outputTotal !== plan.feeSats) throw new Error('signed fee differs from plan');
  if (BigInt(tx.vsize) > plan.vsize) throw new Error('signed vsize exceeds approved bound');
}

export function assertPlanNetwork(plan: TransactionPlan, network: Network): void {
  if (plan.network !== network) throw new Error('transaction network mismatch');
}
