import { NETWORK, TEST_NETWORK, Transaction } from '@scure/btc-signer';
import { scriptPubKeyHex } from '../keys/script-hash';
import { getCryptoProvider } from '../vault/crypto-provider';
import {
  DEFAULT_POSTAGE_SATS,
  estimateVsize,
  scriptDustSats,
  scriptKind,
  type ScriptKind,
} from './fees';
import type {
  PlanDerivation,
  PlanInput,
  PlanOutput,
  ProtectedSatFlow,
  LegacyTransactionPlan,
  TransactionKind,
  TransactionPlan,
} from './plan';
import type { Network } from '../keys/derivation';
import { parseCanonicalSatpoint } from '../ordinals/satpoint';
import { isAuthoritativeCardinalClean } from '../gateway/contract';

export type AnalysisTransactionKind = TransactionKind |
  'provider_psbt' | 'provider_transfer' | 'provider_ordinal_transfer' | 'marketplace_psbt';

export type SighashOutputMode = 'default' | 'all' | 'none' | 'single';

export interface SighashAnalysis {
  raw: number;
  outputMode: SighashOutputMode;
  anyoneCanPay: boolean;
  committedOutputIndexes: number[] | 'all';
  validEncoding: boolean;
}

export type TransactionWarningCode =
  | 'high_absolute_fee'
  | 'high_relative_fee'
  | 'fee_above_target';

export type TransactionViolationCode =
  | 'shape_mismatch'
  | 'prevout_mismatch'
  | 'missing_prevout'
  | 'ownership_mismatch'
  | 'classification_revision_mismatch'
  | 'unsafe_input_classification'
  | 'protected_asset_misuse'
  | 'inscription_effect_mismatch'
  | 'output_mismatch'
  | 'change_ownership_mismatch'
  | 'unsupported_sighash'
  | 'unsupported_taproot_script_path'
  | 'rbf_mismatch'
  | 'fee_mismatch'
  | 'vsize_mismatch';

export interface AnalysisFinding<C extends string> {
  code: C;
  inputIndex?: number;
  outputIndex?: number;
}

export interface TransactionAnalysisInput {
  index: number;
  txid: string;
  vout: number;
  valueSats: bigint;
  scriptPubKey: string;
  scriptKind: ScriptKind;
  sequence: number;
  ownership: 'wallet' | 'external' | 'unproven';
  derivation: PlanDerivation | null;
  classification: PlanInput['classification'];
  sighash: SighashAnalysis;
}

export interface TransactionAnalysisOutput {
  index: number;
  valueSats: bigint;
  scriptPubKey: string;
  address: string | null;
  role: PlanOutput['role'] | 'unknown';
  ownership: 'wallet' | 'external' | 'unproven';
  derivation: PlanDerivation | null;
}

export interface InscriptionEffect {
  inscriptionId: string;
  satpoint: string;
  outpoint: { txid: string; vout: number };
  inputIndex: number;
  inputOffset: bigint;
  outputIndex: number;
  outputOffset: bigint;
  inputOwnership: 'wallet' | 'external';
  outputOwnership: 'wallet' | 'external';
  movement: 'received' | 'sent' | 'retained';
  coLocationGroup: string;
  qualifiedPartialAuthorization: boolean;
}

export interface TransactionAnalysis {
  version: 1;
  network: Network;
  account: number;
  kind: AnalysisTransactionKind;
  source: TransactionPlan['source'];
  inputs: TransactionAnalysisInput[];
  outputs: TransactionAnalysisOutput[];
  assetEffects: {
    protectedSatFlow: ProtectedSatFlow[];
    protectedInputIndexes: number[];
    protectedValueExposedToFees: bigint;
    inscriptions: InscriptionEffect[];
    effectSetHash: string;
  };
  fee: {
    sats: bigint;
    vsize: bigint;
    targetSatPerKvB: bigint;
    effectiveRateNumerator: bigint;
    effectiveRateDenominator: bigint;
  };
  rbf: { replaceable: boolean; sequences: number[] };
  warnings: Array<AnalysisFinding<TransactionWarningCode>>;
  hardViolations: Array<AnalysisFinding<TransactionViolationCode>>;
  marketplaceCommitment: {
    mode: 'exact' | 'partial';
    selectedInputIndexes: number[];
    guaranteedOutputIndexes: number[] | 'all';
    guaranteedProceedsSats: bigint;
    walletFeeExposureSats: bigint;
    uncommittedDimensions: string[];
  } | null;
}

export interface TransactionAnalysisContext {
  network: Network;
  account: number;
  kind: AnalysisTransactionKind;
  source: TransactionPlan['source'];
  inputs: readonly PlanInput[];
  outputs: readonly PlanOutput[];
  protectedSatFlow: readonly ProtectedSatFlow[];
  feeSats: bigint;
  vsize: bigint;
  feeRateSatPerKvB: bigint;
  rbf: boolean;
  marketplace?: {
    allowedSighashesByInput: Readonly<Record<number, readonly number[]>>;
    allowTaprootScriptPathInputIndexes: readonly number[];
    permittedProtectedInputIndexes: readonly number[];
    commitment: NonNullable<TransactionAnalysis['marketplaceCommitment']>;
  };
}

export type AnalyzeResult =
  | { ok: true; analysis: TransactionAnalysis; analysisHash: string }
  | { ok: false; reason: 'parse_error' };

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0 || !/^[0-9a-f]+$/u.test(hex)) throw new Error('invalid hex');
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function canonical(value: unknown): unknown {
  if (typeof value === 'bigint') return value.toString();
  if (Array.isArray(value)) return value.map(canonical);
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([key, child]) => [key, canonical(child)]),
    );
  }
  return value;
}

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value as Record<string, unknown>)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

export function hashAnalysis(analysis: TransactionAnalysis): string {
  const bytes = new TextEncoder().encode(JSON.stringify(canonical(analysis)));
  return bytesToHex(getCryptoProvider().sha256(bytes));
}

function hashInscriptionEffects(effects: readonly InscriptionEffect[]): string {
  const bytes = new TextEncoder().encode(JSON.stringify(canonical(effects)));
  return bytesToHex(getCryptoProvider().sha256(bytes));
}

export function decodeSighash(raw: number, inputIndex: number, outputCount: number): SighashAnalysis {
  const anyoneCanPay = (raw & 0x80) !== 0;
  const base = raw & 0x03;
  const validEncoding = (raw & ~0x83) === 0;
  const outputMode: SighashOutputMode = base === 0 ? 'default' : base === 1 ? 'all' : base === 2 ? 'none' : 'single';
  const committedOutputIndexes =
    outputMode === 'default' || outputMode === 'all'
      ? 'all'
      : outputMode === 'none'
        ? []
        : inputIndex < outputCount
          ? [inputIndex]
          : [];
  return { raw, outputMode, anyoneCanPay, committedOutputIndexes, validEncoding };
}

function canonicalPath(derivation: PlanDerivation, network: Network): string {
  const purpose = derivation.lane === 'payment' ? 84 : 86;
  const coin = network === 'mainnet' ? 0 : 1;
  return `m/${purpose}'/${coin}'/${derivation.account}'/${derivation.chain}/${derivation.index}`;
}

function provesOwnership(derivation: PlanDerivation, script: string, network: Network): boolean {
  return derivation.path === canonicalPath(derivation, network) &&
    scriptPubKeyHex(derivation.publicKeyHex, derivation.lane, network) === script;
}

function rawSighash(tx: Transaction, index: number, kind: ScriptKind): { raw: number; scriptPath: boolean } {
  const witness = tx.getInput(index).finalScriptWitness ?? [];
  if (kind === 'p2wpkh') {
    const signature = witness[0];
    return { raw: signature && signature.length > 0 ? signature[signature.length - 1]! : -1, scriptPath: false };
  }
  if (witness.length !== 1) return { raw: -1, scriptPath: witness.length > 1 };
  const signature = witness[0];
  if (!signature) return { raw: -1, scriptPath: false };
  return { raw: signature.length === 64 ? 0 : signature.length === 65 ? signature[64]! : -1, scriptPath: false };
}

function outputAddress(tx: Transaction, index: number, network: Network): string | null {
  try {
    return tx.getOutputAddress(index, network === 'mainnet' ? NETWORK : TEST_NETWORK) ?? null;
  } catch {
    return null;
  }
}

function inscriptionEffects(
  context: TransactionAnalysisContext,
  inputs: readonly TransactionAnalysisInput[],
  outputs: readonly TransactionAnalysisOutput[],
  violations: Array<AnalysisFinding<TransactionViolationCode>>,
): InscriptionEffect[] {
  const effects: InscriptionEffect[] = [];
  const matchedFlows = new Set<number>();
  const inputStarts: bigint[] = [];
  let inputStart = 0n;
  for (const input of context.inputs) {
    inputStarts.push(inputStart);
    inputStart += input.valueSats;
  }
  const outputStarts: bigint[] = [];
  let outputTotal = 0n;
  for (const output of context.outputs) {
    outputStarts.push(outputTotal);
    outputTotal += output.valueSats;
  }

  // Look the analyzed input up by its own index rather than by array position:
  // analyzeParsed skips pushing an entry for a transaction input the context
  // does not describe, so positional alignment holds only because those skips
  // are always trailing. Keying on `.index` states the pairing outright.
  const analyzedByIndex = new Map(inputs.map((item) => [item.index, item]));
  for (let inputIndex = 0; inputIndex < context.inputs.length; inputIndex += 1) {
    const input = context.inputs[inputIndex]!;
    const analyzedInput = analyzedByIndex.get(inputIndex);
    if (!analyzedInput || analyzedInput.ownership === 'unproven') continue;
    for (const inscription of input.classification.inscriptions) {
      const parsed = parseCanonicalSatpoint(inscription.satpoint);
      if (!parsed || parsed.txid !== input.txid || parsed.vout !== input.vout) {
        violations.push({ code: 'inscription_effect_mismatch', inputIndex });
        continue;
      }
      const inputOffset = parsed.offset;
      if (inputOffset >= input.valueSats) {
        violations.push({ code: 'inscription_effect_mismatch', inputIndex });
        continue;
      }
      const absolutePosition = inputStarts[inputIndex]! + inputOffset;
      const outputIndex = context.outputs.findIndex((output, index) =>
        absolutePosition >= outputStarts[index]! && absolutePosition < outputStarts[index]! + output.valueSats);
      if (outputIndex < 0) {
        // The inscription would be consumed by fees. Never represent that as
        // an unavailable preview: it is a transaction-safety violation.
        violations.push({ code: 'inscription_effect_mismatch', inputIndex });
        continue;
      }
      const outputOffset = absolutePosition - outputStarts[outputIndex]!;
      const analyzedOutput = outputs[outputIndex];
      const output = context.outputs[outputIndex];
      // A partial SINGLE|ANYONECANPAY sale leg: the FIFO mapping of the
      // unassembled listing places the inscription in the wallet's own
      // committed payout output, but the assembled purchase reorders inputs
      // freely, so the true effect is a sale. The signature always guarantees
      // the payout output, so the seller cannot lose both asset and proceeds.
      const saleLeg = context.marketplace?.commitment.mode === 'partial' &&
        analyzedInput.ownership === 'wallet' &&
        analyzedInput.sighash.raw === 0x83 &&
        context.marketplace.commitment.selectedInputIndexes.includes(inputIndex) &&
        outputIndex === inputIndex;
      if (!analyzedOutput || !output || analyzedOutput.ownership === 'unproven' ||
          (analyzedOutput.ownership === 'wallet' && output.derivation?.lane !== 'ordinals' &&
            !saleLeg && (context.kind !== 'ordinal_batch_transfer' ||
              output.derivation?.lane === 'payment'))) {
        violations.push({ code: 'inscription_effect_mismatch', inputIndex, outputIndex });
        continue;
      }
      const matchingFlowIndexes = context.protectedSatFlow
        .map((flow, index) => ({ flow, index }))
        .filter(({ flow }) => flow.inscriptionId === inscription.inscriptionId &&
          flow.inputIndex === inputIndex && flow.inputOffset === inputOffset &&
          flow.outputIndex === outputIndex && flow.outputOffset === outputOffset)
        .map(({ index }) => index);
      if (matchingFlowIndexes.length !== 1) {
        violations.push({ code: 'inscription_effect_mismatch', inputIndex, outputIndex });
        continue;
      }
      matchedFlows.add(matchingFlowIndexes[0]!);
      const movement = analyzedInput.ownership === 'external'
        ? analyzedOutput.ownership === 'wallet' ? 'received' : null
        : analyzedOutput.ownership === 'wallet' && !saleLeg ? 'retained' : 'sent';
      // An external inscription which never enters the wallet is not part of
      // the approval's wallet-relevant effect set. Its explicit FIFO flow is
      // still cross-checked above so it cannot be used as an unmatched extra.
      if (movement === null) continue;
      const partial = context.marketplace?.commitment.mode === 'partial';
      const guaranteed = context.marketplace?.commitment.guaranteedOutputIndexes;
      const destinationCommitted = guaranteed === 'all' || guaranteed?.includes(outputIndex) === true;
      const qualifiedPartialAuthorization = movement === 'sent' && partial &&
        context.marketplace?.commitment.selectedInputIndexes.includes(inputIndex) === true &&
        destinationCommitted;
      // A partial commitment leaves every uncommitted output rewritable by the
      // counterparty, so an inscription landing in one is unauthorized whichever
      // direction it moves -- not only on the way out. `retained` is the trap: a
      // seller signing SINGLE|ACP commits to one output, and a second
      // inscription at a higher sat offset flows by FIFO into a later
      // wallet-owned output the signature does not cover, which the
      // counterparty can then redirect while the signature stays valid. A send
      // additionally has to originate from an input the user chose to sign.
      if (partial && !(movement === 'sent' ? qualifiedPartialAuthorization : destinationCommitted)) {
        violations.push({ code: 'inscription_effect_mismatch', inputIndex, outputIndex });
        continue;
      }
      effects.push({
        inscriptionId: inscription.inscriptionId,
        satpoint: inscription.satpoint,
        outpoint: { txid: input.txid, vout: input.vout },
        inputIndex,
        inputOffset,
        outputIndex,
        outputOffset,
        inputOwnership: analyzedInput.ownership,
        outputOwnership: analyzedOutput.ownership,
        movement,
        coLocationGroup: `${input.txid}:${input.vout}:${inputOffset.toString()}`,
        qualifiedPartialAuthorization,
      });
    }
  }
  for (let index = 0; index < context.protectedSatFlow.length; index += 1) {
    if (!matchedFlows.has(index)) {
      violations.push({ code: 'inscription_effect_mismatch', inputIndex: context.protectedSatFlow[index]!.inputIndex });
    }
  }
  return effects.sort((a, b) => a.inputIndex - b.inputIndex ||
    (a.inputOffset < b.inputOffset ? -1 : a.inputOffset > b.inputOffset ? 1 :
      a.inscriptionId.localeCompare(b.inscriptionId)));
}

function analyzeParsed(
  tx: Transaction,
  context: TransactionAnalysisContext,
  serialized: 'psbt' | 'raw',
): TransactionAnalysis {
  const violations: Array<AnalysisFinding<TransactionViolationCode>> = [];
  const warnings: Array<AnalysisFinding<TransactionWarningCode>> = [];
  if (tx.inputsLength !== context.inputs.length || tx.outputsLength !== context.outputs.length) {
    violations.push({ code: 'shape_mismatch' });
  }

  const inputs: TransactionAnalysisInput[] = [];
  for (let index = 0; index < tx.inputsLength; index += 1) {
    const expected = context.inputs[index];
    const actual = tx.getInput(index);
    if (!expected) {
      violations.push({ code: 'missing_prevout', inputIndex: index });
      continue;
    }
    const actualTxid = actual.txid ? bytesToHex(actual.txid) : '';
    if (actualTxid !== expected.txid || actual.index !== expected.vout || actual.sequence !== expected.sequence) {
      violations.push({ code: 'prevout_mismatch', inputIndex: index });
    }
    if (serialized === 'psbt' &&
        (actual.witnessUtxo?.amount !== expected.valueSats || !actual.witnessUtxo.script ||
          bytesToHex(actual.witnessUtxo.script) !== expected.scriptPubKey)) {
      violations.push({ code: 'prevout_mismatch', inputIndex: index });
    }
    const kind = scriptKind(expected.scriptPubKey);
    const providerKind = context.kind === 'provider_psbt' || context.kind === 'provider_transfer' ||
      context.kind === 'provider_ordinal_transfer' || context.kind === 'marketplace_psbt';
    const declaredExternal = providerKind && expected.ownership === 'external' && expected.derivation === null;
    const invalidExternalDeclaration = expected.ownership === 'external' && !declaredExternal;
    const verifiedMarketplaceScriptPath = context.kind === 'marketplace_psbt' &&
      context.marketplace?.allowTaprootScriptPathInputIndexes.includes(index) === true &&
      Boolean(actual.tapLeafScript?.length) && expected.ownership === 'wallet' && expected.derivation !== null;
    const ownership: TransactionAnalysisInput['ownership'] = declaredExternal
      ? 'external'
      : verifiedMarketplaceScriptPath
        ? 'wallet'
        : !invalidExternalDeclaration && expected.derivation !== null &&
          provesOwnership(expected.derivation, expected.scriptPubKey, context.network)
        ? 'wallet'
        : 'unproven';
    if (ownership === 'unproven') {
      violations.push({ code: 'ownership_mismatch', inputIndex: index });
    }
    if (expected.classification.classificationRevision !== context.source.classificationRevision) {
      violations.push({ code: 'classification_revision_mismatch', inputIndex: index });
    }
    const rawInfo = serialized === 'raw'
      ? rawSighash(tx, index, kind)
      : { raw: actual.sighashType ?? -1, scriptPath: Boolean(actual.tapLeafScript?.length) };
    const sighash = decodeSighash(rawInfo.raw, index, tx.outputsLength);
    const marketplaceAllowed = context.marketplace?.allowedSighashesByInput[index];
    const allowed = marketplaceAllowed
      ? marketplaceAllowed.includes(rawInfo.raw)
      : ownership === 'external'
        ? [0, 1, 0x81, 0x83].includes(rawInfo.raw)
        : kind === 'p2wpkh' ? rawInfo.raw === 1 : rawInfo.raw === 0 || rawInfo.raw === 1;
    if (!sighash.validEncoding || !allowed) violations.push({ code: 'unsupported_sighash', inputIndex: index });
    if (rawInfo.scriptPath && ownership !== 'external' &&
        !context.marketplace?.allowTaprootScriptPathInputIndexes.includes(index)) {
      violations.push({ code: 'unsupported_taproot_script_path', inputIndex: index });
    }
    inputs.push({
      index,
      txid: expected.txid,
      vout: expected.vout,
      valueSats: expected.valueSats,
      scriptPubKey: expected.scriptPubKey,
      scriptKind: kind,
      sequence: actual.sequence ?? expected.sequence,
      ownership,
      derivation: expected.derivation ? { ...expected.derivation } : null,
      classification: {
        ...expected.classification,
        inscriptions: expected.classification.inscriptions.map((inscription) => ({ ...inscription })),
        satRanges: expected.classification.satRanges?.map((range) => ({ ...range })) ?? null,
        classifiedTip: { ...expected.classification.classifiedTip },
      },
      sighash,
    });
  }

  const outputs: TransactionAnalysisOutput[] = [];
  for (let index = 0; index < tx.outputsLength; index += 1) {
    const expected = context.outputs[index];
    const actual = tx.getOutput(index);
    const script = actual.script ? bytesToHex(actual.script) : '';
    const matches = Boolean(expected && actual.amount === expected.valueSats && script === expected.scriptPubKey);
    if (!matches) violations.push({ code: 'output_mismatch', outputIndex: index });
    const derivation = expected?.derivation ?? null;
    let ownership: TransactionAnalysisOutput['ownership'] = 'external';
    if (derivation) {
      ownership = provesOwnership(derivation, script, context.network) ? 'wallet' : 'unproven';
      if (ownership !== 'wallet') violations.push({ code: 'change_ownership_mismatch', outputIndex: index });
    }
    const address = outputAddress(tx, index, context.network);
    if (expected && (address === null || address !== expected.address)) {
      violations.push({ code: 'output_mismatch', outputIndex: index });
    }
    outputs.push({
      index,
      valueSats: actual.amount ?? 0n,
      scriptPubKey: script,
      address,
      role: matches && expected ? expected.role : 'unknown',
      ownership,
      derivation: derivation ? { ...derivation } : null,
    });
  }

  const protectedInputIndexes = context.inputs
    .map((input, index) => ({ input, index }))
    .filter(({ input }) => input.classification.primaryClass !== 'cardinal_clean' || input.classification.unsupportedAssetDetected)
    .map(({ index }) => index);
  const rescueProtected =
    (context.kind === 'rescue' || context.kind === 'ordinal_transfer' ||
      context.kind === 'provider_ordinal_transfer') &&
    protectedInputIndexes.length === 1;
  const batchProtected = (context.kind === 'ordinal_batch_transfer' ||
    context.kind === 'ordinal_postage_manage') && protectedInputIndexes.length > 0;
  if (protectedInputIndexes.length > 0 && !rescueProtected && !batchProtected) {
    const permitted = new Set(context.marketplace?.permittedProtectedInputIndexes ?? []);
    for (const inputIndex of protectedInputIndexes) {
      const protectedInput = context.inputs[inputIndex]!;
      const externalPurchase = context.kind === 'provider_psbt' && protectedInput.ownership === 'external' &&
        !protectedInput.classification.unsupportedAssetDetected && protectedInput.classification.satRanges === null &&
        protectedInput.classification.inscriptions.length > 0;
      const expectedIds = new Set(protectedInput.classification.inscriptions.map((item) => item.inscriptionId));
      const flows = context.protectedSatFlow.filter((flow) => flow.inputIndex === inputIndex);
      const safelyReceived = externalPurchase && flows.length === expectedIds.size &&
        new Set(flows.map((flow) => flow.inscriptionId)).size === expectedIds.size &&
        flows.every((flow) => {
          const output = context.outputs[flow.outputIndex];
          const analyzedOutput = outputs[flow.outputIndex];
          const inputPosition = context.inputs.slice(0, flow.inputIndex)
            .reduce((sum, item) => sum + item.valueSats, 0n) + flow.inputOffset;
          const outputPosition = context.outputs.slice(0, flow.outputIndex)
            .reduce((sum, item) => sum + item.valueSats, 0n) + flow.outputOffset;
          return expectedIds.has(flow.inscriptionId) && flow.inputOffset >= 0n &&
            flow.inputOffset < protectedInput.valueSats && output !== undefined &&
            flow.outputOffset >= 0n && flow.outputOffset < output.valueSats &&
            inputPosition === outputPosition && analyzedOutput?.ownership === 'wallet' &&
            output.derivation?.lane === 'ordinals';
        });
      if (!permitted.has(inputIndex) && !safelyReceived) {
        violations.push({ code: 'unsafe_input_classification', inputIndex });
      }
    }
  }
  let protectedValueExposedToFees = 0n;
  if (rescueProtected) {
    const protectedIndex = protectedInputIndexes[0]!;
    const protectedInput = context.inputs[protectedIndex]!;
    const flows = context.protectedSatFlow.filter((flow) => flow.inputIndex === protectedIndex);
    const partitionedTransfer =
      context.kind === 'ordinal_transfer' || context.kind === 'provider_ordinal_transfer';
    const expectedIds = new Set(protectedInput.classification.inscriptions.map((item) => item.inscriptionId));
    const flowIds = new Set(flows.map((flow) => flow.inscriptionId));
    const valid = protectedInput.classification.inscriptions.length > 0 &&
      flows.length === protectedInput.classification.inscriptions.length &&
      flowIds.size === expectedIds.size && [...flowIds].every((id) => expectedIds.has(id)) &&
      (!partitionedTransfer || new Set(flows
        .filter((flow) => context.outputs[flow.outputIndex]?.role === 'postage')
        .map((flow) => flow.outputIndex)).size === 1) &&
      flows.every((flow) => {
      const output = context.outputs[flow.outputIndex];
      const analyzedOutput = outputs[flow.outputIndex];
      const inputPosition = context.inputs.slice(0, flow.inputIndex)
        .reduce((sum, input) => sum + input.valueSats, 0n) + flow.inputOffset;
      const outputPosition = context.outputs.slice(0, flow.outputIndex)
        .reduce((sum, item) => sum + item.valueSats, 0n) + flow.outputOffset;
      const safeDestination = output !== undefined && (
        (output.role === 'postage' &&
          output.valueSats >= (partitionedTransfer
            ? scriptDustSats(output.scriptPubKey)
            : DEFAULT_POSTAGE_SATS) &&
          (partitionedTransfer
            ? analyzedOutput?.ownership === 'external'
            : analyzedOutput?.ownership === 'wallet')) ||
        (partitionedTransfer && output.role === 'ordinal_change' && analyzedOutput?.ownership === 'wallet' &&
          output.derivation?.lane === 'ordinals' &&
          output.valueSats >= scriptDustSats(output.scriptPubKey))
      );
      return safeDestination &&
        flow.inputOffset >= 0n && flow.inputOffset < protectedInput.valueSats &&
        flow.outputOffset >= 0n && flow.outputOffset < output.valueSats &&
        inputPosition === outputPosition &&
        expectedIds.has(flow.inscriptionId);
    });
    if (!valid) {
      violations.push({ code: 'protected_asset_misuse', inputIndex: protectedIndex });
      protectedValueExposedToFees = protectedInput.valueSats;
    }
  }
  if (batchProtected) {
    const protectedPrefix = protectedInputIndexes.every((inputIndex, index) => inputIndex === index);
    for (const inputIndex of protectedInputIndexes) {
      const protectedInput = context.inputs[inputIndex]!;
      const expectedIds = new Set(protectedInput.classification.inscriptions.map((item) => item.inscriptionId));
      const flows = context.protectedSatFlow.filter((flow) => flow.inputIndex === inputIndex);
      const flowIds = new Set(flows.map((flow) => flow.inscriptionId));
      const sourceValid = protectedInput.classification.inscriptions.length > 0 &&
        protectedInput.classification.confidence === 'authoritative' &&
        !protectedInput.classification.unsupportedAssetDetected &&
        !protectedInput.classification.satRanges?.some((range) =>
          range.rarity !== undefined && range.rarity !== 'common') &&
        flows.length === protectedInput.classification.inscriptions.length &&
        flowIds.size === expectedIds.size && [...flowIds].every((id) => expectedIds.has(id)) &&
        flows.every((flow) => {
          const output = context.outputs[flow.outputIndex];
          const analyzedOutput = outputs[flow.outputIndex];
          const inputPosition = context.inputs.slice(0, flow.inputIndex)
            .reduce((sum, input) => sum + input.valueSats, 0n) + flow.inputOffset;
          const outputPosition = context.outputs.slice(0, flow.outputIndex)
            .reduce((sum, item) => sum + item.valueSats, 0n) + flow.outputOffset;
          return output?.role === 'postage' && analyzedOutput?.ownership !== 'unproven' &&
            output.valueSats >= scriptDustSats(output.scriptPubKey) &&
            flow.inputOffset >= 0n && flow.inputOffset < protectedInput.valueSats &&
            flow.outputOffset >= 0n && flow.outputOffset < output.valueSats &&
            inputPosition === outputPosition && expectedIds.has(flow.inscriptionId);
        });
      if (!sourceValid) {
        violations.push({ code: 'protected_asset_misuse', inputIndex });
        protectedValueExposedToFees += protectedInput.valueSats;
      }
    }
    if (!protectedPrefix && protectedInputIndexes.length > 0) {
      // A clean input before a protected one changes that source's absolute
      // FIFO position; attach the ordering failure to the first protected input.
      violations.push({ code: 'protected_asset_misuse', inputIndex: protectedInputIndexes[0]! });
      protectedValueExposedToFees += protectedInputIndexes.reduce(
        (sum, inputIndex) => sum + context.inputs[inputIndex]!.valueSats,
        0n,
      );
    }
    for (let inputIndex = protectedInputIndexes.length; inputIndex < context.inputs.length; inputIndex += 1) {
      const funding = context.inputs[inputIndex]!;
      if (funding.derivation?.lane !== 'payment' || !isAuthoritativeCardinalClean(funding.classification)) {
        violations.push({ code: 'unsafe_input_classification', inputIndex });
      }
    }
    for (let outputIndex = 0; outputIndex < context.outputs.length; outputIndex += 1) {
      const output = context.outputs[outputIndex]!;
      if (output.role === 'payment_change' &&
          (output.derivation?.lane !== 'payment' || outputs[outputIndex]?.ownership !== 'wallet')) {
        violations.push({ code: 'change_ownership_mismatch', outputIndex });
      }
    }
  }

  const inputTotal = context.inputs.reduce((sum, input) => sum + input.valueSats, 0n);
  const outputTotal = outputs.reduce((sum, output) => sum + output.valueSats, 0n);
  const aggregateFeeSats = inputTotal - outputTotal;
  const feeSats = context.marketplace?.commitment.mode === 'partial'
    ? context.marketplace.commitment.walletFeeExposureSats
    : aggregateFeeSats;
  if (context.marketplace?.commitment.mode !== 'partial' &&
      (feeSats !== context.feeSats || feeSats <= 0n)) violations.push({ code: 'fee_mismatch' });
  if (context.marketplace?.commitment.mode === 'partial' && feeSats !== context.feeSats) {
    violations.push({ code: 'fee_mismatch' });
  }
  const vsize = estimateVsize(context.inputs.map((input) => input.scriptPubKey), outputs.map((output) => output.scriptPubKey));
  if (vsize !== context.vsize) violations.push({ code: 'vsize_mismatch' });
  if (feeSats > 100_000n) warnings.push({ code: 'high_absolute_fee' });
  const sent = context.outputs.filter((output) => output.role === 'recipient' || output.role === 'postage')
    .reduce((sum, output) => sum + output.valueSats, 0n);
  // Postage is a carrier for the inscription, not the principal being sent, so
  // fee-to-`sent` says nothing useful about these kinds -- at the default
  // 10,000-sat postage the ratio trips above roughly 6 sat/vB, and at dust
  // postage it trips essentially always. reviewFromPlan already excludes them
  // for exactly this reason; matching it here keeps a real anomaly legible
  // instead of burying it in a warning users learn to dismiss. high_absolute_fee
  // still covers a genuinely extortionate fee.
  const postageIsNotPrincipal = context.kind === 'ordinal_transfer' ||
    context.kind === 'ordinal_batch_transfer' ||
    context.kind === 'ordinal_postage_manage' ||
    context.kind === 'rescue' || context.kind === 'ordinal_sweep' ||
    context.kind === 'provider_ordinal_transfer';
  if (!postageIsNotPrincipal && sent > 0n && feeSats * 10n > sent) {
    warnings.push({ code: 'high_relative_fee' });
  }
  if (feeSats > (context.feeRateSatPerKvB * vsize + 999n) / 1000n) warnings.push({ code: 'fee_above_target' });
  const sequences = inputs.map((input) => input.sequence);
  const replaceable = sequences.some((sequence) => sequence < 0xfffffffe);
  if (replaceable !== context.rbf) violations.push({ code: 'rbf_mismatch' });
  const inscriptions = inscriptionEffects(context, inputs, outputs, violations);
  const effectSetHash = hashInscriptionEffects(inscriptions);

  return deepFreeze({
    version: 1,
    network: context.network,
    account: context.account,
    kind: context.kind,
    source: {
      ...context.source,
      coreTip: { ...context.source.coreTip },
      indexTip: { ...context.source.indexTip },
    },
    inputs,
    outputs,
    assetEffects: {
      protectedSatFlow: context.protectedSatFlow.map((flow) => ({ ...flow })),
      protectedInputIndexes,
      protectedValueExposedToFees,
      inscriptions,
      effectSetHash,
    },
    fee: {
      sats: feeSats,
      vsize,
      targetSatPerKvB: context.feeRateSatPerKvB,
      effectiveRateNumerator: feeSats,
      effectiveRateDenominator: vsize,
    },
    rbf: { replaceable, sequences },
    warnings,
    hardViolations: violations,
    marketplaceCommitment: context.marketplace ? {
      ...context.marketplace.commitment,
      selectedInputIndexes: [...context.marketplace.commitment.selectedInputIndexes],
      guaranteedOutputIndexes: context.marketplace.commitment.guaranteedOutputIndexes === 'all'
        ? 'all'
        : [...context.marketplace.commitment.guaranteedOutputIndexes],
      uncommittedDimensions: [...context.marketplace.commitment.uncommittedDimensions],
    } : null,
  });
}

function analyze(hex: string, context: TransactionAnalysisContext, serialized: 'psbt' | 'raw'): AnalyzeResult {
  try {
    const bytes = hexToBytes(hex);
    const tx = serialized === 'psbt' ? Transaction.fromPSBT(bytes, { lowR: true }) : Transaction.fromRaw(bytes);
    const analysis = analyzeParsed(tx, context, serialized);
    return { ok: true, analysis, analysisHash: hashAnalysis(analysis) };
  } catch {
    return { ok: false, reason: 'parse_error' };
  }
}

export function analyzePsbtHex(hex: string, context: TransactionAnalysisContext): AnalyzeResult {
  return analyze(hex, context, 'psbt');
}

export function analyzeRawTransactionHex(hex: string, context: TransactionAnalysisContext): AnalyzeResult {
  return analyze(hex, context, 'raw');
}

export function analysisContextFromPlan(
  plan: TransactionPlan | LegacyTransactionPlan,
): TransactionAnalysisContext {
  return {
    network: plan.network,
    account: plan.account,
    kind: plan.kind,
    source: plan.source,
    inputs: plan.inputs,
    outputs: plan.outputs,
    protectedSatFlow: plan.protectedSatFlow,
    feeSats: plan.feeSats,
    vsize: plan.vsize,
    feeRateSatPerKvB: plan.feeRateSatPerKvB,
    rbf: plan.rbf,
  };
}
