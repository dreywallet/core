import { NETWORK, RawTx, SigHash, TEST_NETWORK, Transaction } from '@scure/btc-signer';
import { schnorr, secp256k1 } from '@noble/curves/secp256k1';
import type { UtxoClassification } from '../gateway/contract';
import { deriveAccountNode, type Network } from '../keys/derivation';
import { scriptPubKeyHex } from '../keys/script-hash';
import { base64ToBytes, bytesToBase64, bytesToHex } from '../vault/encoding';
import { getCryptoProvider } from '../vault/crypto-provider';
import { analyzePsbtHex, analyzeRawTransactionHex, type TransactionAnalysis } from './analysis';
import { estimateVsize, scriptKind } from './fees';
import type { PlanDerivation, PlanInput, PlanOutput, TransactionPlan } from './plan';
import type { InscriptionPreviewSet, StoredInscriptionPreviewSet } from './inscription-previews';
import { approvalInscriptionItems, storedPreviewSet } from './inscription-previews';
import type { MarketplaceContext, MarketplaceResolution } from '../marketplaces/types';
import { publicAccountFromSeed } from '../accounts/public-account';
import {
  analyzeMarketplaceCommitment,
  assertMarketplaceWalletInputs,
  type MarketplaceCommitmentAnalysis,
} from '../marketplaces/commitment';
import { templateForResolution } from '../marketplaces/resolver';
import { verifyOrdnetSaleScriptPath } from '../marketplaces/ordnet-script-path';
export {
  partitionOrdinalSatFlow,
  type OrdinalPartition,
  type OrdinalPartitionRequest,
} from './ordinal-transfer';

export interface ProviderAuthorityBinding {
  origin: string;
  tabId: number;
  frameId: number;
  documentId: string;
  requestNonce: string;
  providerMethod: 'signPsbt' | 'sendTransfer' | 'ord_sendInscriptions';
}

export interface ProviderPsbtPlanV3 {
  version: 4;
  planId: string;
  createdAt: number;
  expiresAt: number;
  network: Network;
  vaultId: string;
  sessionId: string;
  /** Stable public-account identity; numeric account is BIP32 metadata only. */
  accountId: string;
  account: number;
  kind: 'provider_psbt' | 'provider_transfer' | 'provider_ordinal_transfer' | 'marketplace_psbt';
  provider: ProviderAuthorityBinding;
  broadcast: boolean;
  requiresAdvanced: boolean;
  /** Exact input indexes approved for this provider request. */
  selectedInputIndexes?: number[];
  /** §21.1 generic listing: origin-independent flexible sale proven from the PSBT. */
  genericListing?: {
    selectedInputIndexes: number[];
    commitment: MarketplaceCommitmentAnalysis;
  };
  inputs: PlanInput[];
  outputs: PlanOutput[];
  source: TransactionPlan['source'];
  feeSats: bigint;
  vsize: bigint;
  feeRateSatPerKvB: bigint;
  rbf: boolean;
  protectedSatFlow: TransactionPlan['protectedSatFlow'];
  psbtHex: string;
  psbtHash: string;
  analysis: TransactionAnalysis;
  analysisHash: string;
  transactionCommitmentHash: string;
  inscriptionPreviews: StoredInscriptionPreviewSet | null;
  planHash: string;
  marketplace?: {
    context: MarketplaceContext;
    resolution: MarketplaceResolution;
    selectedInputIndexes: number[];
    commitment: MarketplaceCommitmentAnalysis;
    allowTaprootScriptPath: boolean;
  };
}

/** Compatibility name for call sites; only version 4 is constructible. */
export type ProviderPsbtPlanV4 = ProviderPsbtPlanV3;

const liveProviderPreviews = new WeakMap<ProviderPsbtPlanV3, InscriptionPreviewSet>();

export interface WalletPsbtInput {
  outpoint: string;
  derivation: PlanDerivation;
}

function inferExternalInscriptionFlows(
  inputs: readonly PlanInput[],
  outputs: readonly PlanOutput[],
): TransactionPlan['protectedSatFlow'] {
  const flows: TransactionPlan['protectedSatFlow'] = [];
  for (let inputIndex = 0; inputIndex < inputs.length; inputIndex += 1) {
    const input = inputs[inputIndex]!;
    if (input.ownership !== 'external' || input.classification.inscriptions.length === 0 ||
        input.classification.unsupportedAssetDetected || input.classification.satRanges !== null) continue;
    for (const inscription of input.classification.inscriptions) {
      const match = /^([0-9a-f]{64}):(\d+):(\d+)$/u.exec(inscription.satpoint);
      if (!match || match[1] !== input.txid || Number(match[2]) !== input.vout) continue;
      const inputOffset = BigInt(match[3]!);
      if (inputOffset < 0n || inputOffset >= input.valueSats) continue;
      const absolutePosition = inputs.slice(0, inputIndex)
        .reduce((sum, item) => sum + item.valueSats, 0n) + inputOffset;
      let outputStart = 0n;
      for (let outputIndex = 0; outputIndex < outputs.length; outputIndex += 1) {
        const output = outputs[outputIndex]!;
        const outputEnd = outputStart + output.valueSats;
        if (absolutePosition >= outputStart && absolutePosition < outputEnd &&
            output.derivation?.lane === 'ordinals') {
          flows.push({
            inputIndex,
            inputOffset,
            outputIndex,
            outputOffset: absolutePosition - outputStart,
            inscriptionId: inscription.inscriptionId,
          });
          break;
        }
        outputStart = outputEnd;
      }
    }
  }
  return flows;
}

function inferMarketplaceInscriptionFlows(
  inputs: readonly PlanInput[],
  outputs: readonly PlanOutput[],
): TransactionPlan['protectedSatFlow'] {
  const flows: TransactionPlan['protectedSatFlow'] = [];
  let inputStart = 0n;
  for (let inputIndex = 0; inputIndex < inputs.length; inputIndex += 1) {
    const input = inputs[inputIndex]!;
    for (const inscription of input.classification.inscriptions) {
      const match = /^([0-9a-f]{64}):(\d+):(\d+)$/u.exec(inscription.satpoint);
      if (!match || match[1] !== input.txid || Number(match[2]) !== input.vout) continue;
      const inputOffset = BigInt(match[3]!);
      if (inputOffset < 0n || inputOffset >= input.valueSats) continue;
      const absolutePosition = inputStart + inputOffset;
      let outputStart = 0n;
      for (let outputIndex = 0; outputIndex < outputs.length; outputIndex += 1) {
        const output = outputs[outputIndex]!;
        if (absolutePosition >= outputStart && absolutePosition < outputStart + output.valueSats) {
          flows.push({
            inputIndex,
            inputOffset,
            outputIndex,
            outputOffset: absolutePosition - outputStart,
            inscriptionId: inscription.inscriptionId,
          });
          break;
        }
        outputStart += output.valueSats;
      }
    }
    inputStart += input.valueSats;
  }
  return flows;
}

/**
 * Partition one input's FIFO sat stream into one non-dust output per protected
 * inscription. Earliest-safe boundaries preserve the maximum value for later
 * inscriptions; if they fail, no other boundary placement can succeed.
 */
export function providerPsbtOutpoints(psbtBase64: string): Array<{ txid: string; vout: number }> {
  const bytes = base64ToBytes(psbtBase64);
  if (bytesToBase64(bytes) !== psbtBase64) throw new Error('non-canonical PSBT base64');
  const tx = Transaction.fromPSBT(bytes);
  const outpoints: Array<{ txid: string; vout: number }> = [];
  for (let index = 0; index < tx.inputsLength; index += 1) {
    const item = tx.getInput(index);
    if (!item.txid || item.index === undefined) throw new Error('PSBT input outpoint missing');
    outpoints.push({ txid: bytesToHex(item.txid), vout: item.index });
  }
  return outpoints;
}

function hexToBytes(hex: string): Uint8Array {
  if (!/^(?:[0-9a-f]{2})+$/u.test(hex)) throw new Error('invalid hex');
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i += 1) bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return bytes;
}

function hash(value: string | Uint8Array): string {
  const bytes = typeof value === 'string' ? new TextEncoder().encode(value) : value;
  return bytesToHex(getCryptoProvider().sha256(bytes));
}

function canonical(value: unknown): unknown {
  if (typeof value === 'bigint') return value.toString();
  if (value instanceof Uint8Array) return bytesToHex(value);
  if (Array.isArray(value)) return value.map(canonical);
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .filter(([key]) => key !== 'planHash' && key !== 'bytesBase64')
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([key, child]) => [key, canonical(child)]),
    );
  }
  return value;
}

function providerTransactionCommitmentHash(plan: object): string {
  const {
    planHash: _planHash,
    transactionCommitmentHash: _transactionCommitmentHash,
    inscriptionPreviews: _inscriptionPreviews,
    ...transaction
  } = plan as ProviderPsbtPlanV3;
  void _planHash;
  void _transactionCommitmentHash;
  void _inscriptionPreviews;
  return hash(JSON.stringify(canonical(transaction)));
}

function withoutSignatureFields(value: Record<string, unknown>): Record<string, unknown> {
  const {
    partialSig: _partialSig,
    tapKeySig: _tapKeySig,
    tapScriptSig: _tapScriptSig,
    finalScriptSig: _finalScriptSig,
    finalScriptWitness: _finalScriptWitness,
    ...unsigned
  } = value;
  void _partialSig;
  void _tapKeySig;
  void _tapScriptSig;
  void _finalScriptSig;
  void _finalScriptWitness;
  return unsigned;
}

function assertSignatureOnlyMutation(
  before: Transaction,
  after: Transaction,
  selected: readonly number[],
): void {
  if (before.inputsLength !== after.inputsLength || before.outputsLength !== after.outputsLength) {
    throw new Error('signed marketplace PSBT shape changed');
  }
  for (let index = 0; index < before.inputsLength; index += 1) {
    const a = JSON.stringify(canonical(withoutSignatureFields(before.getInput(index) as Record<string, unknown>)));
    const b = JSON.stringify(canonical(withoutSignatureFields(after.getInput(index) as Record<string, unknown>)));
    if (a !== b) throw new Error('signed marketplace PSBT metadata changed');
    if (!selected.includes(index) &&
        JSON.stringify(canonical(before.getInput(index))) !== JSON.stringify(canonical(after.getInput(index)))) {
      throw new Error('unselected marketplace input changed');
    }
  }
  for (let index = 0; index < before.outputsLength; index += 1) {
    if (JSON.stringify(canonical(before.getOutput(index))) !== JSON.stringify(canonical(after.getOutput(index)))) {
      throw new Error('signed marketplace output metadata changed');
    }
  }
}

function sourceFacts(classification: UtxoClassification) {
  return {
    primaryClass: classification.primaryClass,
    inscriptions: classification.inscriptions,
    satRanges: classification.satRanges,
    unsupportedAssetDetected: classification.unsupportedAssetDetected,
    confidence: classification.confidence,
    classifiedTip: classification.classifiedTip,
    classificationRevision: classification.classificationRevision,
  };
}

function previousOutput(tx: Transaction, index: number): { valueSats: bigint; scriptPubKey: string } {
  const input = tx.getInput(index);
  let witness = input.witnessUtxo;
  if (input.nonWitnessUtxo) {
    const previous = Transaction.fromRaw(RawTx.encode(input.nonWitnessUtxo));
    if (!input.txid || previous.id !== bytesToHex(input.txid)) throw new Error('non-witness transaction id mismatch');
    const output = input.index === undefined ? undefined : previous.getOutput(input.index);
    if (!output?.script || output.amount === undefined) throw new Error('non-witness prevout missing');
    const decoded = { valueSats: output.amount, scriptPubKey: bytesToHex(output.script) };
    if (witness && (witness.amount !== decoded.valueSats || bytesToHex(witness.script) !== decoded.scriptPubKey)) {
      throw new Error('witness and non-witness prevouts disagree');
    }
    witness = { amount: decoded.valueSats, script: output.script };
  }
  if (!witness) throw new Error('PSBT input is missing its previous output');
  return { valueSats: witness.amount, scriptPubKey: bytesToHex(witness.script) };
}

function outputAddress(tx: Transaction, index: number, network: Network): string {
  const address = tx.getOutputAddress(index, network === 'mainnet' ? NETWORK : TEST_NETWORK);
  if (!address) throw new Error('unsupported non-address output');
  return address;
}

export function createProviderPsbtPlan(input: {
  psbtBase64: string;
  binding: ProviderAuthorityBinding;
  network: Network;
  vaultId: string;
  sessionId: string;
  accountId: string;
  account: number;
  classifications: UtxoClassification[];
  walletInputs: WalletPsbtInput[];
  source: TransactionPlan['source'];
  broadcast: boolean;
  planId: string;
  now: number;
  kind?: ProviderPsbtPlanV3['kind'];
  walletOutputs?: Array<{ scriptPubKey: string; output: PlanOutput }>;
  protectedSatFlow?: TransactionPlan['protectedSatFlow'];
  requiresAdvanced?: boolean;
  selectedInputIndexes?: number[];
  marketplace?: {
    context: MarketplaceContext;
    resolution: MarketplaceResolution;
    selectedInputIndexes?: number[];
  };
}): ProviderPsbtPlanV3 {
  if (!new RegExp(`^acct_${input.network}_[0-9a-f]{64}$`, 'u').test(input.accountId)) {
    throw new Error('provider public account identity differs from network');
  }
  const decoded = base64ToBytes(input.psbtBase64);
  if (bytesToBase64(decoded) !== input.psbtBase64) throw new Error('non-canonical PSBT base64');
  const tx = Transaction.fromPSBT(decoded, { lowR: true });
  if (tx.inputsLength === 0 || tx.outputsLength === 0) throw new Error('empty PSBT');
  const byOutpoint = new Map(input.classifications.map((item) => [`${item.txid}:${item.vout}`, item]));
  if (byOutpoint.size !== input.classifications.length) throw new Error('duplicate gateway classification');
  const wallet = new Map(input.walletInputs.map((item) => [item.outpoint, item.derivation]));
  if ([...wallet.values()].some((derivation) =>
    derivation.accountId !== input.accountId || derivation.account !== input.account)) {
    throw new Error('provider wallet input public account identity mismatch');
  }
  if (input.walletOutputs?.some(({ output }) => {
    const derivation = output.derivation;
    const change = output.role === 'payment_change' || output.role === 'ordinal_change';
    return (change && derivation === undefined) ||
      (derivation !== undefined &&
        (derivation.accountId !== input.accountId || derivation.account !== input.account));
  })) {
    throw new Error('provider wallet output public account identity mismatch');
  }
  const marketplaceTemplate = input.marketplace ? templateForResolution(input.marketplace.resolution) : null;
  const marketplaceRule = marketplaceTemplate?.steps.find((rule) => rule.step === input.marketplace!.context.step) ??
    (marketplaceTemplate?.stepCount === 'context' ? marketplaceTemplate.steps[0] : undefined);
  const selectedMarketplaceIndexes = input.marketplace?.selectedInputIndexes === undefined
    ? []
    : [...new Set(input.marketplace.selectedInputIndexes)].sort((a, b) => a - b);
  const requestedIndexes = input.marketplace
    ? selectedMarketplaceIndexes
    : input.selectedInputIndexes === undefined
      ? undefined
      : [...new Set(input.selectedInputIndexes)].sort((a, b) => a - b);
  if (input.marketplace && (!marketplaceTemplate || !marketplaceRule || input.marketplace.resolution.status !== 'recognized')) {
    throw new Error('marketplace template resolution changed');
  }
  if (input.marketplace && marketplaceTemplate && (
    !marketplaceTemplate.origins.includes(input.binding.origin) ||
    !marketplaceTemplate.networks.includes(input.network) ||
    marketplaceTemplate.marketplaceId !== input.marketplace.context.marketplaceId ||
    marketplaceTemplate.templateVersion !== input.marketplace.context.templateVersion ||
    marketplaceTemplate.action !== input.marketplace.context.action ||
    marketplaceTemplate.role !== input.marketplace.context.role ||
    marketplaceTemplate.assetKind !== input.marketplace.context.assetKind
  )) throw new Error('marketplace authority or context differs from the pinned template');
  if (input.marketplace && input.broadcast !== (input.marketplace.context.broadcaster === 'wallet')) {
    throw new Error('marketplace broadcaster differs from the provider broadcast request');
  }
  const marketplaceCommitment = input.marketplace
    ? analyzeMarketplaceCommitment({
        psbtBase64: input.psbtBase64,
        network: input.network,
        context: input.marketplace.context,
        selectedInputIndexes: selectedMarketplaceIndexes,
      })
    : null;
  const planInputs: PlanInput[] = [];
  const consumedOutpoints = new Set<string>();
  for (let index = 0; index < tx.inputsLength; index += 1) {
    const actual = tx.getInput(index);
    if (!actual.txid || actual.index === undefined) throw new Error('PSBT input outpoint missing');
    const txid = bytesToHex(actual.txid);
    const outpoint = `${txid}:${actual.index}`;
    if (consumedOutpoints.has(outpoint)) throw new Error('duplicate PSBT input');
    consumedOutpoints.add(outpoint);
    const classification = byOutpoint.get(outpoint);
    if (!classification) throw new Error('gateway did not classify every input');
    if (classification.confidence !== 'authoritative' ||
        classification.classificationRevision !== input.source.classificationRevision ||
        classification.classifiedTip.height !== input.source.coreTip.height ||
        classification.classifiedTip.hash !== input.source.coreTip.hash) {
      throw new Error('gateway classification is not current and authoritative');
    }
    const previous = previousOutput(tx, index);
    if (
      classification.valueSats !== previous.valueSats.toString() ||
      classification.scriptPubKey !== previous.scriptPubKey
    ) throw new Error('signed classification differs from PSBT prevout');
    const derivation = wallet.get(outpoint) ?? null;
    if (derivation) {
      if (actual.tapLeafScript?.length) {
        if (!input.marketplace || marketplaceTemplate?.marketplaceId !== 'ordnet' || !marketplaceRule?.allowTaprootScriptPath ||
            derivation.lane !== 'ordinals') throw new Error('Taproot script-path signing is unsupported');
        verifyOrdnetSaleScriptPath(tx, index, derivation.publicKeyHex.slice(2));
      } else if (scriptPubKeyHex(derivation.publicKeyHex, derivation.lane, input.network) !== previous.scriptPubKey) {
        throw new Error('wallet ownership proof mismatch');
      }
    }
    const kind = scriptKind(previous.scriptPubKey);
    const sighash = actual.sighashType ?? (kind === 'p2wpkh' ? SigHash.ALL : SigHash.DEFAULT);
    const allowedSighashes = input.marketplace
      ? selectedMarketplaceIndexes.includes(index)
        ? marketplaceRule!.allowedSighashes
        : [SigHash.DEFAULT, SigHash.ALL, SigHash.ALL_ANYONECANPAY, SigHash.SINGLE_ANYONECANPAY]
      : derivation
        // Flexible values pass this per-input gate only tentatively: they are
        // legal solely as a §21.1 generic listing, whose whole-transaction
        // invariants are enforced after outputs are known (below). A defaulted
        // sighash never reaches here as flexible — only an explicit PSBT
        // sighashType can carry 0x81/0x83.
        ? kind === 'p2wpkh'
          ? [SigHash.ALL, SigHash.ALL_ANYONECANPAY, SigHash.SINGLE_ANYONECANPAY]
          : [SigHash.DEFAULT, SigHash.ALL, SigHash.ALL_ANYONECANPAY, SigHash.SINGLE_ANYONECANPAY]
        : [SigHash.DEFAULT, SigHash.ALL, SigHash.ALL_ANYONECANPAY, SigHash.SINGLE_ANYONECANPAY];
    if (!allowedSighashes.includes(sighash)) {
      throw new Error('unsupported provider sighash');
    }
    if (actual.tapLeafScript?.length && derivation && !marketplaceRule?.allowTaprootScriptPath) {
      throw new Error('Taproot script-path signing is unsupported');
    }
    tx.updateInput(index, { sighashType: sighash });
    planInputs.push({
      txid,
      vout: actual.index,
      valueSats: previous.valueSats,
      scriptPubKey: previous.scriptPubKey,
      sequence: actual.sequence ?? 0xffffffff,
      sighash: sighash as 0 | 1 | 129 | 131,
      ownership: derivation ? 'wallet' : 'external',
      derivation,
      classification: sourceFacts(classification),
    });
  }
  const outputs: PlanOutput[] = [];
  for (let index = 0; index < tx.outputsLength; index += 1) {
    const output = tx.getOutput(index);
    if (!output.script || output.amount === undefined) throw new Error('PSBT output missing');
    const scriptPubKey = bytesToHex(output.script);
    const owned = input.walletOutputs?.find((item) => item.scriptPubKey === scriptPubKey)?.output;
    outputs.push(owned
      ? { ...owned, valueSats: output.amount, scriptPubKey }
      : { valueSats: output.amount, scriptPubKey, address: outputAddress(tx, index, input.network), role: 'recipient' });
  }
  if (input.marketplace) {
    assertMarketplaceWalletInputs({
      planInputs,
      selectedInputIndexes: selectedMarketplaceIndexes,
      context: input.marketplace.context,
    });
  }
  const selectedInputIndexes = requestedIndexes ?? planInputs
    .map((item, index) => item.ownership === 'wallet' ? index : -1)
    .filter((index) => index >= 0);
  if (selectedInputIndexes.length === 0 || selectedInputIndexes.some((index) =>
    !planInputs[index] || planInputs[index]!.ownership !== 'wallet')) {
    throw new Error('requested input is not owned by the active account');
  }
  // §21.1 generic listing: without a recognized marketplace template, a wallet
  // input may carry a flexible sighash only as the classic listing shape, with
  // every wallet guarantee proven from the PSBT itself rather than from origin
  // trust: SINGLE|ANYONECANPAY requires the corresponding output to pay the
  // active account at least the input's value, ALL|ANYONECANPAY commits every
  // output, and in both cases the wallet-owned outputs must return at least
  // the full wallet input value. Price sanity is the approval's disclosure;
  // value loss and asset misuse remain hard failures.
  const genericFlexibleIndexes = input.marketplace ? [] : selectedInputIndexes.filter((index) =>
    planInputs[index]!.sighash === SigHash.ALL_ANYONECANPAY ||
    planInputs[index]!.sighash === SigHash.SINGLE_ANYONECANPAY);
  let genericCommitment: MarketplaceCommitmentAnalysis | null = null;
  if (genericFlexibleIndexes.length > 0) {
    if (genericFlexibleIndexes.length !== selectedInputIndexes.length) {
      throw new Error('generic listing may not mix flexible and deterministic wallet signatures');
    }
    for (let index = 0; index < planInputs.length; index += 1) {
      if (planInputs[index]!.ownership === 'wallet' && !selectedInputIndexes.includes(index)) {
        throw new Error('generic listing contains an unapproved wallet input');
      }
    }
    for (const index of genericFlexibleIndexes) {
      const item = planInputs[index]!;
      if (item.classification.unsupportedAssetDetected || item.classification.satRanges !== null) {
        throw new Error('generic listing may not spend unsupported-asset or rare-sat inputs');
      }
      if (item.sighash === SigHash.SINGLE_ANYONECANPAY) {
        const corresponding = outputs[index];
        if (!corresponding?.derivation) {
          throw new Error('generic listing payout must return to the active account');
        }
        if (corresponding.valueSats < item.valueSats) {
          throw new Error('generic listing payout is below the listed input value');
        }
      }
    }
    const walletInSats = selectedInputIndexes.reduce((sum, index) => sum + planInputs[index]!.valueSats, 0n);
    const walletOutSats = outputs.reduce((sum, output) => output.derivation ? sum + output.valueSats : sum, 0n);
    if (walletOutSats < walletInSats) {
      throw new Error('generic listing does not guarantee the wallet value it spends');
    }
    genericCommitment = analyzeMarketplaceCommitment({
      psbtBase64: input.psbtBase64,
      network: input.network,
      context: {
        version: 1,
        marketplaceId: 'generic',
        templateVersion: 'generic',
        action: 'list',
        role: 'seller',
        assetKind: 'inscription',
        workflowId: input.planId,
        step: 1,
        stepCount: 1,
        broadcaster: 'site',
      },
      selectedInputIndexes: [...selectedInputIndexes],
    });
  }
  const flexibleCommitment = marketplaceCommitment ?? genericCommitment;
  const protectedSatFlow = input.protectedSatFlow ?? (input.marketplace || genericCommitment
    ? inferMarketplaceInscriptionFlows(planInputs, outputs)
    : inferExternalInscriptionFlows(planInputs, outputs));
  const totalIn = planInputs.reduce((sum, item) => sum + item.valueSats, 0n);
  const totalOut = outputs.reduce((sum, item) => sum + item.valueSats, 0n);
  // Only a partial commitment may legitimately show outputs at or above inputs:
  // the counterparty's inputs are still missing. An exact commitment is a whole
  // transaction, so the guard applies to it exactly as to a non-marketplace PSBT
  // -- otherwise feeSats goes zero or negative and propagates into the fee rate,
  // the analysis context and the plan hash.
  if (flexibleCommitment?.mode !== 'partial' && totalIn <= totalOut) {
    throw new Error('PSBT fee is not positive');
  }
  const feeSats = flexibleCommitment?.mode === 'partial'
    ? flexibleCommitment.walletFeeExposureSats
    : totalIn - totalOut;
  const vsize = estimateVsize(planInputs.map((item) => item.scriptPubKey), outputs.map((item) => item.scriptPubKey));
  const feeRateSatPerKvB = (feeSats * 1000n + vsize - 1n) / vsize;
  const psbt = tx.toPSBT();
  const psbtHex = bytesToHex(psbt);
  const analysisResult = analyzePsbtHex(psbtHex, {
    network: input.network,
    account: input.account,
    kind: input.marketplace ? 'marketplace_psbt' : input.kind ?? 'provider_psbt',
    source: input.source,
    inputs: planInputs,
    outputs,
    protectedSatFlow,
    feeSats,
    vsize,
    feeRateSatPerKvB,
    rbf: planInputs.some((item) => item.sequence < 0xfffffffe),
    ...(marketplaceCommitment ? { marketplace: {
      allowedSighashesByInput: Object.fromEntries(selectedMarketplaceIndexes.map((index) =>
        [index, marketplaceRule!.allowedSighashes])),
      allowTaprootScriptPathInputIndexes: marketplaceRule!.allowTaprootScriptPath
        ? selectedMarketplaceIndexes : [],
      permittedProtectedInputIndexes: selectedMarketplaceIndexes,
      commitment: marketplaceCommitment,
    } } : genericCommitment ? { marketplace: {
      // The generic listing pins each input to exactly the sighash the page
      // declared and validated above; no script path is ever permitted.
      allowedSighashesByInput: Object.fromEntries(genericFlexibleIndexes.map((index) =>
        [index, [planInputs[index]!.sighash]])),
      allowTaprootScriptPathInputIndexes: [],
      permittedProtectedInputIndexes: genericFlexibleIndexes,
      commitment: genericCommitment,
    } } : {}),
  });
  if (!analysisResult.ok || analysisResult.analysis.hardViolations.length > 0) {
    throw new Error(`provider PSBT violates transaction safety policy${
      analysisResult.ok ? `: ${analysisResult.analysis.hardViolations.map((item) => item.code).join(',')}` : ''
    }`);
  }
  if (!input.marketplace && (input.kind ?? 'provider_psbt') === 'provider_psbt' && analysisResult.analysis.warnings.some(
    (warning) => warning.code === 'high_absolute_fee' || warning.code === 'high_relative_fee',
  )) {
    // Advanced signing may acknowledge an unknown deterministic business
    // template, but it never overrides the material-fee invariant (§16.3).
    throw new Error('provider PSBT has a non-overridable fee anomaly');
  }
  const withoutHash = {
    version: 4 as const,
    planId: input.planId,
    createdAt: input.now,
    expiresAt: input.now + 5 * 60_000,
    network: input.network,
    vaultId: input.vaultId,
    sessionId: input.sessionId,
    accountId: input.accountId,
    account: input.account,
    kind: input.marketplace ? 'marketplace_psbt' as const : input.kind ?? 'provider_psbt',
    provider: input.binding,
    broadcast: input.broadcast,
    requiresAdvanced: input.marketplace || genericCommitment ? false : input.requiresAdvanced !== false,
    selectedInputIndexes,
    ...(genericCommitment ? { genericListing: {
      selectedInputIndexes: [...selectedInputIndexes],
      commitment: genericCommitment,
    } } : {}),
    inputs: planInputs,
    outputs,
    source: input.source,
    feeSats,
    vsize,
    feeRateSatPerKvB,
    rbf: planInputs.some((item) => item.sequence < 0xfffffffe),
    protectedSatFlow,
    psbtHex,
    psbtHash: hash(psbt),
    analysis: analysisResult.analysis,
    analysisHash: analysisResult.analysisHash,
    ...(input.marketplace && marketplaceCommitment ? { marketplace: {
      context: input.marketplace.context,
      resolution: input.marketplace.resolution,
      selectedInputIndexes: selectedMarketplaceIndexes,
      commitment: marketplaceCommitment,
      allowTaprootScriptPath: marketplaceRule!.allowTaprootScriptPath,
    } } : {}),
  };
  const transactionCommitmentHash = providerTransactionCommitmentHash(withoutHash);
  const inscriptionPreviews: StoredInscriptionPreviewSet | null =
    analysisResult.analysis.assetEffects.inscriptions.length === 0
      ? {
          transactionCommitmentHash,
          analysisHash: analysisResult.analysisHash,
          psbtHash: withoutHash.psbtHash,
          effectSetHash: analysisResult.analysis.assetEffects.effectSetHash,
          classificationRevision: input.source.classificationRevision,
          verifiedAtMs: input.now,
          items: [],
        }
      : null;
  const bound = { ...withoutHash, transactionCommitmentHash, inscriptionPreviews };
  return { ...bound, planHash: hash(JSON.stringify(canonical(bound))) };
}

export function bindProviderPsbtPlanPreviews(
  plan: ProviderPsbtPlanV3,
  previews: InscriptionPreviewSet,
): ProviderPsbtPlanV3 {
  if (providerTransactionCommitmentHash(plan) !== plan.transactionCommitmentHash ||
      previews.transactionCommitmentHash !== plan.transactionCommitmentHash ||
      previews.analysisHash !== plan.analysisHash || previews.psbtHash !== plan.psbtHash ||
      previews.effectSetHash !== plan.analysis.assetEffects.effectSetHash ||
      previews.classificationRevision !== plan.source.classificationRevision ||
      previews.items.length !== plan.analysis.assetEffects.inscriptions.length) {
    throw new Error('provider inscription previews differ from transaction plan');
  }
  approvalInscriptionItems(plan.analysis, previews);
  const descriptors = storedPreviewSet(previews);
  const withoutHash = { ...plan, inscriptionPreviews: descriptors };
  const rebound = {
    ...withoutHash,
    planHash: hash(JSON.stringify(canonical(withoutHash))),
  };
  liveProviderPreviews.set(rebound, previews);
  return rebound;
}

export function providerPsbtPlanPreviews(plan: ProviderPsbtPlanV3): InscriptionPreviewSet {
  const previews = liveProviderPreviews.get(plan);
  if (!previews) {
    if (plan.inscriptionPreviews && plan.inscriptionPreviews.items.every(
      (item) => item.preview.disposition === 'placeholder',
    )) {
      return {
        ...plan.inscriptionPreviews,
        items: plan.inscriptionPreviews.items.map((item) => {
          if (item.preview.disposition !== 'placeholder') {
            throw new Error('provider raster bytes unavailable');
          }
          return {
            metadata: item.metadata,
            preview: { ...item.preview, bytesBase64: null },
          };
        }),
      };
    }
    throw new Error('provider inscription preview bytes unavailable');
  }
  return previews;
}

export function reattachProviderPsbtPlanPreviews(
  plan: ProviderPsbtPlanV3,
  previews: InscriptionPreviewSet,
): void {
  assertProviderPsbtPlan(plan);
  const stored = storedPreviewSet(previews);
  if (!plan.inscriptionPreviews ||
      JSON.stringify({ ...stored, verifiedAtMs: plan.inscriptionPreviews.verifiedAtMs }) !==
        JSON.stringify(plan.inscriptionPreviews)) {
    throw new Error('provider inscription preview provenance changed');
  }
  liveProviderPreviews.set(plan, previews);
}

export function signProviderPsbtPlan(input: {
  plan: ProviderPsbtPlanV3;
  seed: Uint8Array;
  requestedInputIndexes?: number[];
  random: (length: number) => Uint8Array;
}): { psbtBase64: string; transactionHex?: string } {
  assertProviderPsbtPlan(input.plan);
  if (publicAccountFromSeed(input.seed, input.plan.network, input.plan.account).accountId !==
      input.plan.accountId) {
    throw new Error('provider signer public account does not match transaction plan');
  }
  const approvedIndexes = input.plan.selectedInputIndexes ?? input.plan.marketplace?.selectedInputIndexes ??
    input.plan.inputs.map((item, index) => item.ownership === 'wallet' ? index : -1).filter((index) => index >= 0);
  const selected = input.requestedInputIndexes === undefined
    ? [...approvedIndexes]
    : [...new Set(input.requestedInputIndexes)];
  const expected = [...approvedIndexes].sort((a, b) => a - b);
  const actualSelected = [...selected].sort((a, b) => a - b);
  if (expected.length !== actualSelected.length || expected.some((index, position) => index !== actualSelected[position])) {
    throw new Error('provider signer indexes changed after approval');
  }
  const tx = Transaction.fromPSBT(hexToBytes(input.plan.psbtHex), { lowR: true });
  const beforeSigning = Transaction.fromPSBT(hexToBytes(input.plan.psbtHex), { lowR: true });
  for (const index of selected) {
    const planned = input.plan.inputs[index];
    if (!planned || planned.ownership !== 'wallet' || !planned.derivation || planned.derivation.account !== input.plan.account) {
      throw new Error('requested input is not owned by the active account');
    }
    const derivation = planned.derivation;
    if (derivation.accountId !== input.plan.accountId) {
      throw new Error('provider input public account identity differs from plan');
    }
    const account = deriveAccountNode(input.seed, derivation.lane, input.plan.network, derivation.account);
    const chain = account.deriveChild(derivation.chain);
    const key = chain.deriveChild(derivation.index);
    try {
      if (!key.privateKey || !key.publicKey || bytesToHex(key.publicKey) !== derivation.publicKeyHex) {
        throw new Error('derived provider key mismatch');
      }
      const original = tx.getInput(index);
      const scriptPathInternalKey = original.tapLeafScript?.length ? original.tapInternalKey : undefined;
      if (scriptPathInternalKey) {
        // @scure otherwise creates both a tweaked key-path signature and the
        // requested script-path signature. This is the explicit equivalent of
        // disableTweakSigner; metadata is restored before serialization.
        tx.updateInput(
          index,
          { tapInternalKey: undefined } as unknown as Parameters<Transaction['updateInput']>[1],
          true,
        );
      }
      tx.signIdx(
        key.privateKey,
        index,
        [planned.sighash as SigHash],
        planned.derivation.lane === 'ordinals' ? input.random(32) : undefined,
      );
      if (scriptPathInternalKey) {
        tx.updateInput(
          index,
          { tapInternalKey: scriptPathInternalKey, tapKeySig: undefined } as unknown as
            Parameters<Transaction['updateInput']>[1],
          true,
        );
      }
    } finally {
      key.privateKey?.fill(0);
      key.wipePrivateData();
      chain.wipePrivateData();
      account.wipePrivateData();
    }
  }
  verifyProviderPartialSignatures(tx, input.plan, selected);
  assertSignatureOnlyMutation(beforeSigning, tx, selected);
  const signed = tx.toPSBT();
  const reparsed = analyzePsbtHex(bytesToHex(signed), {
    network: input.plan.network,
    account: input.plan.account,
    kind: input.plan.kind,
    source: input.plan.source,
    inputs: input.plan.inputs,
    outputs: input.plan.outputs,
    protectedSatFlow: input.plan.protectedSatFlow,
    feeSats: input.plan.feeSats,
    vsize: input.plan.vsize,
    feeRateSatPerKvB: input.plan.feeRateSatPerKvB,
    rbf: input.plan.rbf,
    ...(input.plan.marketplace ? { marketplace: {
      allowedSighashesByInput: Object.fromEntries(input.plan.marketplace.selectedInputIndexes.map((index) =>
        [index, [input.plan.inputs[index]!.sighash]])),
      allowTaprootScriptPathInputIndexes: input.plan.marketplace.allowTaprootScriptPath
        ? input.plan.marketplace.selectedInputIndexes : [],
      permittedProtectedInputIndexes: input.plan.marketplace.selectedInputIndexes,
      commitment: input.plan.marketplace.commitment,
    } } : input.plan.genericListing ? { marketplace: {
      allowedSighashesByInput: Object.fromEntries(input.plan.genericListing.selectedInputIndexes.map((index) =>
        [index, [input.plan.inputs[index]!.sighash]])),
      allowTaprootScriptPathInputIndexes: [],
      permittedProtectedInputIndexes: input.plan.genericListing.selectedInputIndexes,
      commitment: input.plan.genericListing.commitment,
    } } : {}),
  });
  if (!reparsed.ok || reparsed.analysisHash !== input.plan.analysisHash || reparsed.analysis.hardViolations.length > 0) {
    throw new Error('signed provider PSBT differs from approved analysis');
  }
  if (!input.plan.broadcast) return { psbtBase64: bytesToBase64(signed) };
  tx.finalize();
  const transactionHex = bytesToHex(tx.extract());
  validateProviderTransactionHex(input.plan, transactionHex);
  return { psbtBase64: bytesToBase64(signed), transactionHex };
}

export function assertProviderPsbtPlan(plan: ProviderPsbtPlanV3): void {
  if (!plan || plan.version !== 4 || !plan.inscriptionPreviews ||
      !new RegExp(`^acct_${plan.network}_[0-9a-f]{64}$`, 'u').test(plan.accountId) ||
      plan.inputs.some((input) => input.ownership === 'wallet' &&
        (input.derivation?.accountId !== plan.accountId || input.derivation.account !== plan.account)) ||
      plan.outputs.some((output) => output.derivation !== undefined &&
        (output.derivation.accountId !== plan.accountId || output.derivation.account !== plan.account)) ||
      !['provider_psbt', 'provider_transfer', 'provider_ordinal_transfer', 'marketplace_psbt'].includes(plan.kind) ||
      !Array.isArray(plan.inputs) || !Array.isArray(plan.outputs) ||
      (plan.selectedInputIndexes !== undefined &&
        (!Array.isArray(plan.selectedInputIndexes) || plan.selectedInputIndexes.length === 0)) ||
      providerTransactionCommitmentHash(plan) !== plan.transactionCommitmentHash ||
      plan.inscriptionPreviews.transactionCommitmentHash !== plan.transactionCommitmentHash ||
      plan.inscriptionPreviews.analysisHash !== plan.analysisHash ||
      plan.inscriptionPreviews.psbtHash !== plan.psbtHash ||
      plan.inscriptionPreviews.effectSetHash !== plan.analysis.assetEffects.effectSetHash ||
      plan.inscriptionPreviews.items.length !== plan.analysis.assetEffects.inscriptions.length ||
      hash(JSON.stringify(canonical(plan))) !== plan.planHash) {
    throw new Error('provider plan mutated');
  }
}

export function validateProviderTransactionHex(plan: ProviderPsbtPlanV3, transactionHex: string): string {
  assertProviderPsbtPlan(plan);
  const analyzed = analyzeRawTransactionHex(transactionHex, {
    network: plan.network, account: plan.account, kind: plan.kind, source: plan.source,
    inputs: plan.inputs, outputs: plan.outputs, protectedSatFlow: plan.protectedSatFlow, feeSats: plan.feeSats,
    vsize: plan.vsize, feeRateSatPerKvB: plan.feeRateSatPerKvB, rbf: plan.rbf,
    ...(plan.marketplace ? { marketplace: {
      allowedSighashesByInput: Object.fromEntries(plan.marketplace.selectedInputIndexes.map((index) =>
        [index, [plan.inputs[index]!.sighash]])),
      allowTaprootScriptPathInputIndexes: plan.marketplace.allowTaprootScriptPath
        ? plan.marketplace.selectedInputIndexes : [],
      permittedProtectedInputIndexes: plan.marketplace.selectedInputIndexes,
      commitment: plan.marketplace.commitment,
    } } : {}),
  });
  if (!analyzed.ok || analyzed.analysisHash !== plan.analysisHash || analyzed.analysis.hardViolations.length > 0) {
    throw new Error('provider transaction differs from approved analysis');
  }
  const tx = Transaction.fromRaw(hexToBytes(transactionHex));
  if (tx.inputsLength !== plan.inputs.length || tx.outputsLength !== plan.outputs.length) {
    throw new Error('provider transaction shape changed');
  }
  if (BigInt(tx.vsize) > plan.vsize) throw new Error('provider transaction exceeds approved vsize bound');
  const scripts = plan.inputs.map((item) => hexToBytes(item.scriptPubKey));
  const amounts = plan.inputs.map((item) => item.valueSats);
  for (let index = 0; index < plan.inputs.length; index += 1) {
    const expected = plan.inputs[index]!;
    const witness = tx.getInput(index).finalScriptWitness ?? [];
    if (scriptKind(expected.scriptPubKey) === 'p2wpkh') {
      const signature = witness[0];
      const publicKey = witness[1];
      if (!signature || !publicKey || signature.at(-1) !== SigHash.ALL) throw new Error('invalid provider P2WPKH witness');
      const keyHash = expected.scriptPubKey.slice(4);
      const preimage = tx.preimageWitnessV0(index, hexToBytes(`76a914${keyHash}88ac`), SigHash.ALL, expected.valueSats);
      if (scriptPubKeyHex(bytesToHex(publicKey), 'payment', plan.network) !== expected.scriptPubKey ||
          !secp256k1.verify(signature.slice(0, -1), preimage, publicKey, {
            format: 'der', prehash: false, lowS: true,
          })) throw new Error('invalid provider P2WPKH signature');
    } else {
      if (witness.length !== 1) throw new Error('unsupported provider Taproot witness');
      const signature = witness[0];
      if (!signature || (signature.length !== 64 && signature.length !== 65)) throw new Error('invalid provider Taproot signature');
      const sighash = signature.length === 64 ? SigHash.DEFAULT : signature[64]!;
      const preimage = tx.preimageWitnessV1(index, scripts, sighash, amounts);
      if (!schnorr.verify(signature.slice(0, 64), preimage, hexToBytes(expected.scriptPubKey).slice(2))) {
        throw new Error('invalid provider Taproot signature');
      }
    }
  }
  return tx.id;
}

function verifyProviderPartialSignatures(tx: Transaction, plan: ProviderPsbtPlanV3, indexes: number[]): void {
  const scripts = plan.inputs.map((item) => hexToBytes(item.scriptPubKey));
  const amounts = plan.inputs.map((item) => item.valueSats);
  for (const index of indexes) {
    const planned = plan.inputs[index]!;
    const actual = tx.getInput(index);
    if (!planned.derivation) throw new Error('missing signing derivation');
    if (planned.derivation.lane === 'payment') {
      const signed = actual.partialSig?.find(([pubkey]) => bytesToHex(pubkey) === planned.derivation!.publicKeyHex);
      if (!signed || signed[1].at(-1) !== planned.sighash) throw new Error('missing P2WPKH partial signature');
      const keyHash = planned.scriptPubKey.slice(4);
      const preimage = tx.preimageWitnessV0(
        index,
        hexToBytes(`76a914${keyHash}88ac`),
        planned.sighash,
        planned.valueSats,
      );
      if (!secp256k1.verify(signed[1].slice(0, -1), preimage, signed[0], {
        format: 'der', prehash: false, lowS: true,
      })) throw new Error('invalid P2WPKH partial signature');
    } else {
      if (actual.tapLeafScript?.length) {
        if (actual.tapLeafScript.length !== 1) throw new Error('unexpected Taproot leaf count');
        const scriptWithVersion = actual.tapLeafScript[0]![1];
        const script = scriptWithVersion.slice(0, -1);
        const version = scriptWithVersion.at(-1)!;
        const sellerKey = hexToBytes(planned.derivation.publicKeyHex).slice(1);
        const signed = actual.tapScriptSig?.find(([key]) => bytesToHex(key.pubKey) === bytesToHex(sellerKey));
        if (!signed || (signed[1].length !== 65 && planned.sighash !== SigHash.DEFAULT) ||
            (signed[1].length === 65 && signed[1].at(-1) !== planned.sighash)) {
          throw new Error('missing Taproot script-path partial signature');
        }
        const preimage = tx.preimageWitnessV1(index, scripts, planned.sighash, amounts, undefined, script, version);
        if (!schnorr.verify(signed[1].slice(0, 64), preimage, sellerKey)) {
          throw new Error('invalid Taproot script-path partial signature');
        }
        continue;
      }
      const signature = actual.tapKeySig;
      if (!signature || (signature.length !== 64 && signature.length !== 65)) throw new Error('missing Taproot signature');
      const sighash = signature.length === 64 ? SigHash.DEFAULT : signature[64]!;
      if (sighash !== planned.sighash) throw new Error('Taproot sighash differs from plan');
      const preimage = tx.preimageWitnessV1(index, scripts, sighash, amounts);
      if (!schnorr.verify(signature.slice(0, 64), preimage, hexToBytes(planned.scriptPubKey).slice(2))) {
        throw new Error('invalid Taproot signature');
      }
    }
  }
}
