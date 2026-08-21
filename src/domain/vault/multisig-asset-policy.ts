/**
 * ADR 0007 Workstream B3 closed BTC/inscription policy for Vault plans.
 *
 * B0 commits the immutable plan and an evidence hash for every input. B1 proves
 * complete-policy ownership. B2 reconstructs and validates the exact PSBT. This
 * module is the asset-safety boundary layered over all three: it accepts only a
 * fresh Full Sat Safety evidence projection, recomputes every evidence hash,
 * validates FIFO sat placement, and calls the B2 parser before returning a
 * supported result or before any wrapper below uses a signing root.
 *
 * The evidence records contain public classification data only. They are not a
 * transport or signature-verification format; callers must obtain them from the
 * already verified gateway/core evidence path. Remote values cannot select a
 * policy: the accepted capability set and all movement rules are closed here.
 */
import { Transaction } from '@scure/btc-signer';
import { z } from 'zod';
import { getCryptoProvider } from './crypto-provider';
import { bytesToHex, hexToBytes } from './encoding';
import { MAX_FEE_RATE_SAT_PER_KVB } from '../transactions/fees';
import {
  vaultUnsignedPlanSchema,
  type VaultPartialSignatureInputV1,
  type VaultPartialSignatureResultV1,
  type VaultPolicyIdentityV1,
  type VaultSignerRole,
  type VaultUnsignedPlanV1,
} from './multisig-contracts';
import { assertVaultUnsignedPlan, canonicalVaultPlanBytes } from './multisig-encoding';
import { decimalU64Schema } from './u64';
import {
  combineVaultPartialSignatureResults,
  createVaultPartialSignatureInput,
  finalizeVaultPsbt,
  signVaultPartialSignature,
  validateVaultPsbt,
  type CombinedVaultPsbt,
  type FinalizedVaultTransaction,
} from './multisig-psbt';

const HEX_32 = /^[0-9a-f]{64}$/u;
const HEX_SCRIPT = /^(?:[0-9a-f]{2})+$/u;
const DECIMAL = /^(?:0|[1-9][0-9]*)$/u;
const INSCRIPTION_ID = /^[0-9a-f]{64}i(?:0|[1-9][0-9]*)$/u;
const U32_MAX = 0xffff_ffff;

export const VAULT_ASSET_POLICY_VERSION = 1 as const;
export const VAULT_FULL_SAT_SAFETY_CAPABILITIES = [
  'address_history',
  'inscription_index',
  'mempool_overlay',
  'rarity',
  'rune_detection',
  'sat_index',
  'unsupported_asset_detection',
] as const;

export type VaultAssetPolicyErrorCode =
  | 'invalid_evidence'
  | 'stale_evidence'
  | 'conflicting_source'
  | 'input_binding_mismatch'
  | 'unsupported_classification'
  | 'ordinary_btc_policy'
  | 'inscription_policy'
  | 'protected_fee_exposure'
  | 'rbf_policy'
  | 'cpfp_policy';

export class VaultAssetPolicyError extends Error {
  override readonly name = 'VaultAssetPolicyError';

  constructor(readonly code: VaultAssetPolicyErrorCode, message: string) {
    super(message);
  }
}

export interface VaultInscriptionEvidenceV1 {
  inscriptionId: string;
  offsetSats: string;
}

export interface VaultInputAssetEvidenceV1 {
  version: 1;
  network: 'mainnet' | 'signet' | 'regtest';
  inputIndex: number;
  txid: string;
  vout: number;
  valueSats: string;
  scriptPubKeyHex: string;
  primaryClass: 'cardinal_clean' | 'inscribed' | 'rare_sat' | 'runic_or_unsupported' | 'mixed' | 'unknown';
  confidence: 'authoritative' | 'degraded';
  confirmations: number;
  walletCreatedUnconfirmedChange: boolean;
  userFrozen: boolean;
  dustQuarantined: boolean;
  classificationComplete: boolean;
  satRangesComplete: boolean;
  inscriptions: VaultInscriptionEvidenceV1[];
  rareSatDetected: boolean;
  unsupportedAssetDetected: boolean;
  classificationRevisionHash: string;
  classifiedTip: { height: number; hash: string };
  evidenceHash: string;
}

export interface VaultAssetPolicyEvidenceV1 {
  version: 1;
  network: 'mainnet' | 'signet' | 'regtest';
  policyId: string;
  planId: string;
  planDigest: string;
  safetyMode: 'full_sat_safety';
  capabilities: [...typeof VAULT_FULL_SAT_SAFETY_CAPABILITIES];
  backendInstanceIdHash: string;
  classificationRevisionHash: string;
  coreTip: { height: number; hash: string };
  indexTip: { height: number; hash: string };
  historyTip: { height: number; hash: string };
  ordTip: { height: number; hash: string };
  observedAtMs: string;
  validUntilMs: string;
  inputs: VaultInputAssetEvidenceV1[];
}

export interface VaultAssetPolicyValidationV1 {
  version: 1;
  network: 'mainnet' | 'signet' | 'regtest';
  policyId: string;
  planId: string;
  planDigest: string;
  movement: 'cardinal' | 'inscription';
  protectedAssetId: string | null;
  protectedOutputIndex: number | null;
  replacement: 'none' | 'rbf' | 'cpfp';
  /** Candidates only. A later CPFP child still requires a fresh clean classification. */
  cpfpCandidateOutputIndexes: number[];
  psbtHash: string;
}

const decimal = decimalU64Schema;
const hex32 = z.string().regex(HEX_32);
const tipSchema = z.object({ height: z.number().int().min(0).max(U32_MAX), hash: hex32 }).strict();
const inscriptionEvidenceSchema: z.ZodType<VaultInscriptionEvidenceV1> = z.object({
  inscriptionId: z.string().regex(INSCRIPTION_ID),
  offsetSats: decimal,
}).strict();

export const vaultInputAssetEvidenceSchema: z.ZodType<VaultInputAssetEvidenceV1> = z.object({
  version: z.literal(1),
  network: z.enum(['mainnet', 'signet', 'regtest']),
  inputIndex: z.number().int().min(0).max(U32_MAX),
  txid: hex32,
  vout: z.number().int().min(0).max(U32_MAX),
  valueSats: decimal,
  scriptPubKeyHex: z.string().regex(HEX_SCRIPT),
  primaryClass: z.enum(['cardinal_clean', 'inscribed', 'rare_sat', 'runic_or_unsupported', 'mixed', 'unknown']),
  confidence: z.enum(['authoritative', 'degraded']),
  confirmations: z.number().int().min(0).max(U32_MAX),
  walletCreatedUnconfirmedChange: z.boolean(),
  userFrozen: z.boolean(),
  dustQuarantined: z.boolean(),
  classificationComplete: z.boolean(),
  satRangesComplete: z.boolean(),
  inscriptions: z.array(inscriptionEvidenceSchema).max(1024),
  rareSatDetected: z.boolean(),
  unsupportedAssetDetected: z.boolean(),
  classificationRevisionHash: hex32,
  classifiedTip: tipSchema,
  evidenceHash: hex32,
}).strict().superRefine((evidence, context) => {
  if (new Set(evidence.inscriptions.map((item) => item.inscriptionId)).size !== evidence.inscriptions.length) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ['inscriptions'], message: 'duplicate inscription identity' });
  }
  if (evidence.inscriptions.some((item) => BigInt(item.offsetSats) >= BigInt(evidence.valueSats))) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ['inscriptions'], message: 'inscription offset outside prevout' });
  }
  if (evidence.confirmations > 0 && evidence.walletCreatedUnconfirmedChange) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ['walletCreatedUnconfirmedChange'], message: 'confirmed input cannot be unconfirmed change' });
  }
});

export const vaultAssetPolicyEvidenceSchema: z.ZodType<VaultAssetPolicyEvidenceV1> = z.object({
  version: z.literal(1),
  network: z.enum(['mainnet', 'signet', 'regtest']),
  policyId: hex32,
  planId: z.string().regex(/^[0-9a-f]{32}$/u),
  planDigest: hex32,
  safetyMode: z.literal('full_sat_safety'),
  capabilities: z.tuple(VAULT_FULL_SAT_SAFETY_CAPABILITIES.map((value) => z.literal(value)) as [
    z.ZodLiteral<'address_history'>,
    z.ZodLiteral<'inscription_index'>,
    z.ZodLiteral<'mempool_overlay'>,
    z.ZodLiteral<'rarity'>,
    z.ZodLiteral<'rune_detection'>,
    z.ZodLiteral<'sat_index'>,
    z.ZodLiteral<'unsupported_asset_detection'>,
  ]),
  backendInstanceIdHash: hex32,
  classificationRevisionHash: hex32,
  coreTip: tipSchema,
  indexTip: tipSchema,
  historyTip: tipSchema,
  ordTip: tipSchema,
  observedAtMs: decimal,
  validUntilMs: decimal,
  inputs: z.array(vaultInputAssetEvidenceSchema).min(1).max(10_000),
}).strict();

class EvidenceWriter {
  private readonly chunks: Uint8Array[] = [];

  private push(bytes: Uint8Array): void { this.chunks.push(bytes); }
  raw(bytes: Uint8Array): void { this.push(bytes); }
  u8(value: number): void { this.push(Uint8Array.of(value)); }
  u32(value: number): void {
    const bytes = new Uint8Array(4);
    new DataView(bytes.buffer).setUint32(0, value, false);
    this.push(bytes);
  }
  u64(value: string): void {
    const bytes = new Uint8Array(8);
    new DataView(bytes.buffer).setBigUint64(0, BigInt(value), false);
    this.push(bytes);
  }
  bytes(value: Uint8Array): void { this.u32(value.length); this.push(value); }
  text(value: string): void { this.bytes(new TextEncoder().encode(value)); }
  finish(): Uint8Array {
    const result = new Uint8Array(this.chunks.reduce((sum, chunk) => sum + chunk.length, 0));
    let offset = 0;
    for (const chunk of this.chunks) { result.set(chunk, offset); offset += chunk.length; }
    return result;
  }
}

const CLASS_BYTE: Record<VaultInputAssetEvidenceV1['primaryClass'], number> = {
  cardinal_clean: 0,
  inscribed: 1,
  rare_sat: 2,
  runic_or_unsupported: 3,
  mixed: 4,
  unknown: 5,
};

/** Fixed-order SQVE bytes used only for a B0 input's classification evidence hash. */
export function canonicalVaultInputAssetEvidenceBytes(
  input: Omit<VaultInputAssetEvidenceV1, 'evidenceHash'> | VaultInputAssetEvidenceV1,
): Uint8Array {
  const value = vaultInputAssetEvidenceSchema.parse({
    ...input,
    evidenceHash: 'evidenceHash' in input ? input.evidenceHash : '00'.repeat(32),
  });
  const writer = new EvidenceWriter();
  writer.raw(Uint8Array.of(0x53, 0x51, 0x56, 0x45)); // SQVE
  writer.u8(1);
  writer.u8(value.network === 'mainnet' ? 0 : value.network === 'signet' ? 1 : 2);
  writer.u32(value.inputIndex);
  writer.bytes(hexToBytes(value.txid));
  writer.u32(value.vout);
  writer.u64(value.valueSats);
  writer.bytes(hexToBytes(value.scriptPubKeyHex));
  writer.u8(CLASS_BYTE[value.primaryClass]);
  writer.u8(value.confidence === 'authoritative' ? 0 : 1);
  writer.u32(value.confirmations);
  for (const flag of [value.walletCreatedUnconfirmedChange, value.userFrozen, value.dustQuarantined,
    value.classificationComplete, value.satRangesComplete]) writer.u8(flag ? 1 : 0);
  writer.u32(value.inscriptions.length);
  for (const inscription of value.inscriptions) {
    writer.text(inscription.inscriptionId);
    writer.u64(inscription.offsetSats);
  }
  writer.u8(value.rareSatDetected ? 1 : 0);
  writer.u8(value.unsupportedAssetDetected ? 1 : 0);
  writer.bytes(hexToBytes(value.classificationRevisionHash));
  writer.u32(value.classifiedTip.height);
  writer.bytes(hexToBytes(value.classifiedTip.hash));
  return writer.finish();
}

export function computeVaultInputAssetEvidenceHash(
  input: Omit<VaultInputAssetEvidenceV1, 'evidenceHash'> | VaultInputAssetEvidenceV1,
): string {
  const domain = new TextEncoder().encode('drey-vault-classification-evidence-v1');
  const bytes = canonicalVaultInputAssetEvidenceBytes(input);
  const framed = new Uint8Array(domain.length + 1 + bytes.length);
  framed.set(domain);
  framed[domain.length] = 0;
  framed.set(bytes, domain.length + 1);
  return bytesToHex(getCryptoProvider().sha256(framed));
}

export function finalizeVaultInputAssetEvidence(
  input: Omit<VaultInputAssetEvidenceV1, 'evidenceHash'>,
): VaultInputAssetEvidenceV1 {
  const value = vaultInputAssetEvidenceSchema.parse({ ...input, evidenceHash: '00'.repeat(32) });
  return Object.freeze({ ...value, evidenceHash: computeVaultInputAssetEvidenceHash(value) });
}

function fail(code: VaultAssetPolicyErrorCode, message: string): never {
  throw new VaultAssetPolicyError(code, message);
}

function sameTip(left: { height: number; hash: string }, right: { height: number; hash: string }): boolean {
  return left.height === right.height && left.hash === right.hash;
}

function assertFreshAndConsistent(
  plan: VaultUnsignedPlanV1,
  evidence: VaultAssetPolicyEvidenceV1,
  nowMs: string,
): void {
  if (!DECIMAL.test(nowMs)) fail('stale_evidence', 'canonical validation time required');
  const now = BigInt(nowMs);
  if (BigInt(evidence.validUntilMs) <= BigInt(evidence.observedAtMs) ||
      now < BigInt(evidence.observedAtMs) || now > BigInt(evidence.validUntilMs) ||
      now < BigInt(plan.createdAtMs) || now > BigInt(plan.expiresAtMs) ||
      evidence.observedAtMs !== plan.source.observedAtMs || evidence.validUntilMs !== plan.source.validUntilMs) {
    fail('stale_evidence', 'Vault classification evidence is outside its validity window');
  }
  const tips = [evidence.indexTip, evidence.historyTip, evidence.ordTip];
  if (tips.some((tip) => !sameTip(evidence.coreTip, tip)) ||
      !sameTip(evidence.coreTip, plan.source.coreTip) || !sameTip(evidence.indexTip, plan.source.indexTip) ||
      evidence.backendInstanceIdHash !== plan.source.backendInstanceIdHash ||
      evidence.classificationRevisionHash !== plan.source.classificationRevisionHash) {
    fail('conflicting_source', 'Vault Full Sat Safety tips, backend, or classification revision conflict');
  }
}

function assertEvidenceInput(
  plan: VaultUnsignedPlanV1,
  evidence: VaultInputAssetEvidenceV1,
  index: number,
): void {
  const input = plan.inputs[index];
  if (!input || evidence.inputIndex !== index || evidence.network !== plan.network || evidence.txid !== input.txid ||
      evidence.vout !== input.vout || evidence.valueSats !== input.valueSats ||
      evidence.scriptPubKeyHex !== input.scriptPubKeyHex || evidence.primaryClass !== input.classification ||
      evidence.classificationRevisionHash !== plan.source.classificationRevisionHash ||
      !sameTip(evidence.classifiedTip, plan.source.coreTip) ||
      evidence.evidenceHash !== input.classificationEvidenceHash ||
      computeVaultInputAssetEvidenceHash(evidence) !== evidence.evidenceHash) {
    fail('input_binding_mismatch', `Vault input ${index} classification evidence does not match the immutable plan`);
  }
  if (evidence.confidence !== 'authoritative' || !evidence.classificationComplete || !evidence.satRangesComplete ||
      evidence.userFrozen || evidence.dustQuarantined || evidence.rareSatDetected || evidence.unsupportedAssetDetected ||
      (evidence.confirmations === 0 && !evidence.walletCreatedUnconfirmedChange)) {
    fail('unsupported_classification', `Vault input ${index} is degraded, suspicious, incomplete, unsupported, or unconfirmed`);
  }
}

function isClean(evidence: VaultInputAssetEvidenceV1): boolean {
  return evidence.primaryClass === 'cardinal_clean' && evidence.inscriptions.length === 0;
}

function assertCardinalPlan(plan: VaultUnsignedPlanV1, evidence: VaultAssetPolicyEvidenceV1): void {
  const effectIndexes = plan.assetEffects.map((effect) => effect.inputIndex);
  if (evidence.inputs.some((input) => !isClean(input)) || plan.assetEffects.length !== plan.inputs.length ||
      new Set(effectIndexes).size !== plan.inputs.length ||
      plan.inputs.some((_input, index) => !effectIndexes.includes(index)) ||
      plan.assetEffects.some((effect) => effect.kind !== 'cardinal' || effect.protected || effect.assetId !== '' ||
        effect.inputOffsetSats !== '0' || effect.outputOffsetSats !== '0' || effect.postageSats !== '0' ||
        effect.outputIndex !== plan.destination.outputIndex)) {
    fail('ordinary_btc_policy', 'ordinary Vault BTC movement may use only proven-clean cardinal inputs and effects');
  }
}

function fifoPosition(plan: VaultUnsignedPlanV1, inputIndex: number, inputOffset: bigint): {
  outputIndex: number;
  outputOffset: bigint;
} | null {
  let position = inputOffset;
  for (let index = 0; index < inputIndex; index += 1) position += BigInt(plan.inputs[index]!.valueSats);
  let outputStart = 0n;
  for (let index = 0; index < plan.outputs.length; index += 1) {
    const outputEnd = outputStart + BigInt(plan.outputs[index]!.valueSats);
    if (position < outputEnd) return { outputIndex: index, outputOffset: position - outputStart };
    outputStart = outputEnd;
  }
  return null;
}

function assertInscriptionPlan(
  plan: VaultUnsignedPlanV1,
  evidence: VaultAssetPolicyEvidenceV1,
): { assetId: string; outputIndex: number } {
  const protectedInputs = evidence.inputs.filter((input) => input.primaryClass === 'inscribed');
  const protectedEffects = plan.assetEffects.filter((effect) => effect.kind === 'inscription');
  const cardinalEffects = plan.assetEffects.filter((effect) => effect.kind === 'cardinal');
  const source = evidence.inputs[0];
  const effect = protectedEffects[0];
  if (protectedInputs.length !== 1 || protectedInputs[0] !== source || !source || source.inscriptions.length !== 1 ||
      source.confirmations === 0 || source.walletCreatedUnconfirmedChange ||
      protectedEffects.length !== 1 || !effect || effect.inputIndex !== 0 || !effect.protected ||
      effect.assetId !== source.inscriptions[0]!.inscriptionId || effect.inputOffsetSats !== source.inscriptions[0]!.offsetSats ||
      evidence.inputs.slice(1).some((input) => !isClean(input)) ||
      cardinalEffects.length !== evidence.inputs.length - 1 ||
      evidence.inputs.slice(1).some((_input, index) => !cardinalEffects.some((item) =>
        item.inputIndex === index + 1 && !item.protected && item.assetId === '' &&
        item.inputOffsetSats === '0' && item.outputOffsetSats === '0' && item.postageSats === '0' &&
        item.outputIndex === plan.destination.outputIndex)) ||
      new Set(cardinalEffects.map((item) => item.inputIndex)).size !== cardinalEffects.length) {
    fail('inscription_policy', 'Vault v1 supports exactly one complete inscription UTXO followed by clean fee inputs');
  }
  const destination = plan.outputs[plan.destination.outputIndex];
  const fifo = fifoPosition(plan, 0, BigInt(effect.inputOffsetSats));
  if (!destination || plan.destination.outputIndex !== 0 || !fifo || fifo.outputIndex !== 0 ||
      effect.outputIndex !== 0 || BigInt(effect.outputOffsetSats) !== fifo.outputOffset ||
      effect.outputOffsetSats !== effect.inputOffsetSats ||
      effect.postageSats !== destination.valueSats) {
    fail('inscription_policy', 'protected sat placement, whole-UTXO value, or postage changed');
  }
  const outputTotal = plan.outputs.reduce((sum, output) => sum + BigInt(output.valueSats), 0n);
  const protectedEnd = BigInt(source.valueSats);
  if (BigInt(destination.valueSats) < protectedEnd || outputTotal < protectedEnd ||
      fifoPosition(plan, 0, protectedEnd - 1n)?.outputIndex !== 0) {
    fail('protected_fee_exposure', 'protected UTXO value would split, burn, or become miner fee');
  }
  return { assetId: effect.assetId, outputIndex: 0 };
}

function txidOf(plan: VaultUnsignedPlanV1): string {
  const first = getCryptoProvider().sha256(hexToBytes(plan.unsignedTransactionHex));
  return bytesToHex(Uint8Array.from(getCryptoProvider().sha256(first)).reverse());
}

function assertPreviousPlanTransaction(plan: VaultUnsignedPlanV1): void {
  const transaction = Transaction.fromRaw(hexToBytes(plan.unsignedTransactionHex));
  if (bytesToHex(transaction.unsignedTx) !== plan.unsignedTransactionHex ||
      transaction.inputsLength !== plan.inputs.length || transaction.outputsLength !== plan.outputs.length ||
      plan.inputs.some((input, index) => {
        const actual = transaction.getInput(index);
        return !actual.txid || bytesToHex(actual.txid) !== input.txid || actual.index !== input.vout ||
          actual.sequence !== input.sequence;
      }) || plan.outputs.some((output, index) => {
        const actual = transaction.getOutput(index);
        return !actual.script || bytesToHex(actual.script) !== output.scriptPubKeyHex ||
          actual.amount !== BigInt(output.valueSats);
      })) {
    fail('input_binding_mismatch', 'previous immutable plan differs from its unsigned transaction bytes');
  }
}

function assertRbf(plan: VaultUnsignedPlanV1, previousPlan: VaultUnsignedPlanV1 | undefined): void {
  if (!previousPlan) fail('rbf_policy', 'RBF requires the complete prior immutable plan');
  assertVaultUnsignedPlan(previousPlan);
  assertPreviousPlanTransaction(previousPlan);
  const previousTxid = txidOf(previousPlan);
  if (previousPlan.network !== plan.network || previousPlan.policyId !== plan.policyId ||
      previousPlan.planId === plan.planId || previousPlan.requestId === plan.requestId || previousPlan.planDigest === plan.planDigest ||
      plan.replacement.replacesTxid !== previousTxid || previousPlan.replacement.kind === 'cpfp' ||
      BigInt(plan.feeSats) <= BigInt(previousPlan.feeSats) ||
      plan.inputs.length < previousPlan.inputs.length || previousPlan.inputs.some((input, index) => {
        const replacement = plan.inputs[index];
        return !replacement || replacement.txid !== input.txid || replacement.vout !== input.vout;
      }) || plan.inputs.slice(previousPlan.inputs.length).some((input) => input.txid === previousTxid) ||
      plan.inputs.some((input) => input.sequence >= 0xffff_fffe) ||
      previousPlan.destination.kind !== plan.destination.kind || previousPlan.destination.address !== plan.destination.address ||
      previousPlan.destination.pairedSpendingWalletIdHash !== plan.destination.pairedSpendingWalletIdHash ||
      previousPlan.destination.targetPolicyId !== plan.destination.targetPolicyId ||
      previousPlan.amountSats !== plan.amountSats) {
    fail('rbf_policy', 'RBF must be a distinct immutable plan preserving prior inputs, destination, and amount');
  }
}

function assertCpfp(
  plan: VaultUnsignedPlanV1,
  evidence: VaultAssetPolicyEvidenceV1,
  previousPlan: VaultUnsignedPlanV1 | undefined,
): void {
  if (!previousPlan) fail('cpfp_policy', 'CPFP requires the complete parent immutable plan');
  assertVaultUnsignedPlan(previousPlan);
  assertPreviousPlanTransaction(previousPlan);
  const input = plan.inputs[0];
  const facts = evidence.inputs[0];
  const parentOutput = input ? previousPlan.outputs[input.vout] : undefined;
  if (plan.inputs.length !== 1 || !input || !facts || !isClean(facts) || facts.confirmations !== 0 ||
      !facts.walletCreatedUnconfirmedChange || input.txid !== txidOf(previousPlan) ||
      previousPlan.network !== plan.network || previousPlan.policyId !== plan.policyId ||
      previousPlan.planId === plan.planId || previousPlan.planDigest === plan.planDigest ||
      plan.replacement.parentTxid !== input.txid || input.branch !== 'change' ||
      !parentOutput || parentOutput.purpose !== 'vault-change' || parentOutput.valueSats !== input.valueSats ||
      parentOutput.scriptPubKeyHex !== input.scriptPubKeyHex || parentOutput.branch !== input.branch ||
      parentOutput.derivationIndex !== input.derivationIndex ||
      plan.assetEffects.some((effect) => effect.kind !== 'cardinal' || effect.protected)) {
    fail('cpfp_policy', 'CPFP may spend only one freshly proven-clean cardinal Vault change output');
  }
}

/** Validate one B0 plan + B2 PSBT as a supported B3 movement. */
export function validateVaultAssetPolicy(input: {
  policy: VaultPolicyIdentityV1;
  plan: VaultUnsignedPlanV1;
  psbtHex: string;
  evidence: VaultAssetPolicyEvidenceV1;
  nowMs: string;
  previousPlan?: VaultUnsignedPlanV1;
}): VaultAssetPolicyValidationV1 {
  let evidence: VaultAssetPolicyEvidenceV1;
  try {
    assertVaultUnsignedPlan(input.plan);
    vaultUnsignedPlanSchema.parse(input.plan);
    evidence = vaultAssetPolicyEvidenceSchema.parse(input.evidence);
  } catch (error) {
    if (error instanceof VaultAssetPolicyError) throw error;
    fail('invalid_evidence', 'invalid Vault asset-policy plan or evidence record');
  }
  const { plan } = input;
  if (evidence.network !== plan.network || evidence.network !== input.policy.network ||
      evidence.policyId !== plan.policyId || evidence.policyId !== input.policy.policyId ||
      evidence.planId !== plan.planId || evidence.planDigest !== plan.planDigest ||
      evidence.inputs.length !== plan.inputs.length) {
    fail('input_binding_mismatch', 'Vault evidence does not bind the policy, plan, network, or ordered input set');
  }
  if (plan.replacement.kind === 'rbf' &&
      BigInt(plan.feeRateSatPerKvB) > BigInt(MAX_FEE_RATE_SAT_PER_KVB)) {
    fail('rbf_policy', 'RBF fee rate exceeds the shared compiled maximum');
  }
  assertFreshAndConsistent(plan, evidence, input.nowMs);
  evidence.inputs.forEach((item, index) => assertEvidenceInput(plan, item, index));
  if (plan.outputs.some((output, index) =>
    index !== plan.destination.outputIndex && output.purpose !== 'vault-change')) {
    fail('ordinary_btc_policy', 'Vault plans permit only the typed destination plus current-policy change');
  }
  // B2 reconstruction is intentionally inside the B3 boundary, not a caller assertion.
  const psbt = validateVaultPsbt(input.policy, plan, input.psbtHex);

  const hasInscription = evidence.inputs.some((item) => item.primaryClass === 'inscribed');
  if (evidence.inputs.some((item) => !['cardinal_clean', 'inscribed'].includes(item.primaryClass))) {
    fail('unsupported_classification', 'mixed, rare, runic, unsupported, or unknown Vault inputs are read-only');
  }
  let protectedAssetId: string | null = null;
  let protectedOutputIndex: number | null = null;
  if (hasInscription) {
    if (plan.replacement.kind === 'rbf') fail('rbf_policy', 'inscription movement does not permit parent RBF in v1');
    const protectedResult = assertInscriptionPlan(plan, evidence);
    protectedAssetId = protectedResult.assetId;
    protectedOutputIndex = protectedResult.outputIndex;
  } else {
    assertCardinalPlan(plan, evidence);
  }
  if (plan.replacement.kind === 'rbf') assertRbf(plan, input.previousPlan);
  if (plan.replacement.kind === 'cpfp') assertCpfp(plan, evidence, input.previousPlan);

  const result: VaultAssetPolicyValidationV1 = {
    version: 1,
    network: plan.network,
    policyId: plan.policyId,
    planId: plan.planId,
    planDigest: plan.planDigest,
    movement: hasInscription ? 'inscription' : 'cardinal',
    protectedAssetId,
    protectedOutputIndex,
    replacement: plan.replacement.kind,
    cpfpCandidateOutputIndexes: plan.outputs.flatMap((output) => output.purpose === 'vault-change' ? [output.outputIndex] : []),
    psbtHash: psbt.psbtHash,
  };
  return deepFreeze(result);
}

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value as Record<string, unknown>)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

export function createVaultAssetSafePartialSignatureInput(input: {
  policy: VaultPolicyIdentityV1;
  plan: VaultUnsignedPlanV1;
  role: VaultSignerRole;
  psbtHex: string;
  evidence: VaultAssetPolicyEvidenceV1;
  nowMs: string;
  previousPlan?: VaultUnsignedPlanV1;
}): VaultPartialSignatureInputV1 {
  validateVaultAssetPolicy(input);
  return createVaultPartialSignatureInput(input);
}

export function signVaultAssetSafePartialSignature(input: {
  policy: VaultPolicyIdentityV1;
  plan: VaultUnsignedPlanV1;
  request: VaultPartialSignatureInputV1;
  signerRoot: Parameters<typeof signVaultPartialSignature>[0]['signerRoot'];
  evidence: VaultAssetPolicyEvidenceV1;
  nowMs: string;
  previousPlan?: VaultUnsignedPlanV1;
}): VaultPartialSignatureResultV1 {
  const validation = validateVaultAssetPolicy({ ...input, psbtHex: input.request.psbtHex });
  if (input.request.canonicalPlanHex !== bytesToHex(canonicalVaultPlanBytes(input.plan)) ||
      input.request.network !== validation.network || input.request.policyId !== validation.policyId ||
      input.request.planId !== validation.planId || input.request.planDigest !== validation.planDigest ||
      input.request.psbtHash !== validation.psbtHash) {
    fail('input_binding_mismatch', 'asset-safe signing request differs from the exact B3-validated plan or PSBT');
  }
  return signVaultPartialSignature(input);
}

export function combineVaultAssetSafePartialSignatureResults(input: {
  policy: VaultPolicyIdentityV1;
  plan: VaultUnsignedPlanV1;
  results: readonly VaultPartialSignatureResultV1[];
  evidence: VaultAssetPolicyEvidenceV1;
  nowMs: string;
  previousPlan?: VaultUnsignedPlanV1;
}): CombinedVaultPsbt {
  for (const result of input.results) {
    validateVaultAssetPolicy({ ...input, psbtHex: result.signedPsbtHex });
  }
  return combineVaultPartialSignatureResults(input);
}

export function finalizeVaultAssetSafePsbt(input: {
  policy: VaultPolicyIdentityV1;
  plan: VaultUnsignedPlanV1;
  psbtHex: string;
  evidence: VaultAssetPolicyEvidenceV1;
  nowMs: string;
  previousPlan?: VaultUnsignedPlanV1;
}): FinalizedVaultTransaction {
  validateVaultAssetPolicy(input);
  return finalizeVaultPsbt(input);
}
