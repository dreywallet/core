import { z } from 'zod';
import { getCryptoProvider } from '../vault/crypto-provider';
import { detectedAssetSchema, isAuthoritativeCardinalClean, voutSchema } from '../gateway/contract';
import { inscriptionMetadataSchema, inscriptionPreviewDescriptorSchema } from '../gateway/contract';
import type { AssetFacts, WalletUtxo } from '../classification/types';
import type { Network, AddressKind } from '../keys/derivation';
import type { StoredInscriptionPreviewSet } from './inscription-previews';
import { formatFeeRateSatPerVb, parseCustomFeeRate } from './fees';

export type TransactionKind =
  | 'native_send'
  | 'ordinal_transfer'
  | 'consolidation'
  | 'rbf'
  | 'cpfp'
  | 'rescue'
  | 'ordinal_sweep';

export type PlanFeePolicy =
  | { type: 'automatic'; tier: 'priority' | 'standard' | 'economy' | 'recommended' }
  | { type: 'custom'; rateSatPerKvB: string; normalizedSatPerVb: string };

export type LegacyPlanFeePolicy =
  | { type: 'automatic'; tier: 'priority' | 'standard' | 'economy' | 'recommended' }
  | { type: 'custom'; satPerVb: number };

export function customPlanFeePolicy(rateSatPerVb: string): Extract<PlanFeePolicy, { type: 'custom' }> {
  const parsed = parseCustomFeeRate(rateSatPerVb);
  return {
    type: 'custom',
    rateSatPerKvB: parsed.satPerKvB.toString(),
    normalizedSatPerVb: parsed.normalizedSatPerVb,
  };
}

export type PlanIntent =
  | { kind: 'native_send'; account: number; recipient: string; amountSats: string; sendMax: boolean;
      selectedOutpoints?: Array<{ txid: string; vout: number }> | undefined }
  | { kind: 'ordinal_transfer'; account: number; inscriptionId: string;
      outpoint: { txid: string; vout: number }; recipient: string }
  | { kind: 'consolidation'; account: number; selectedOutpoints: Array<{ txid: string; vout: number }> }
  | { kind: 'rbf' | 'cpfp'; txid: string }
  | { kind: 'rescue' | 'ordinal_sweep'; outpoint: { txid: string; vout: number } };

export interface PlanDerivation {
  /** Stable public identity. Absent only in legacy read-only plans. */
  accountId?: string | undefined;
  account: number;
  lane: AddressKind;
  chain: 0 | 1;
  index: number;
  path: string;
  publicKeyHex: string;
}

export interface PlanInput {
  txid: string;
  vout: number;
  valueSats: bigint;
  scriptPubKey: string;
  sequence: number;
  /** Native plans use 0/1. Flexible values are accepted only by a recognized marketplace plan. */
  sighash: 0 | 1 | 129 | 131;
  ownership?: 'wallet' | 'external' | undefined;
  derivation: PlanDerivation | null;
  classification: AssetFacts;
}

export type PlanOutputRole = 'recipient' | 'payment_change' | 'ordinal_change' | 'postage';

export interface PlanOutput {
  valueSats: bigint;
  scriptPubKey: string;
  address: string;
  role: PlanOutputRole;
  derivation?: PlanDerivation | undefined;
}

export interface ProtectedSatFlow {
  inputIndex: number;
  inputOffset: bigint;
  outputIndex: number;
  outputOffset: bigint;
  inscriptionId: string;
}

export interface TransactionPlan {
  version: 4;
  planId: string;
  createdAt: number;
  expiresAt: number;
  network: Network;
  /** Stable public-account identity; the numeric field is only BIP32 metadata. */
  accountId: string;
  account: number;
  kind: TransactionKind;
  policy: { intent: PlanIntent; fee: PlanFeePolicy };
  source: {
    backend: string;
    instanceId: string;
    classificationRevision: string;
    coreTip: { height: number; hash: string };
    indexTip: { height: number; hash: string };
    feeQuoteTimestamp: string | null;
    mempoolState: string | null;
  };
  inputs: PlanInput[];
  outputs: PlanOutput[];
  protectedSatFlow: ProtectedSatFlow[];
  feeSats: bigint;
  vsize: bigint;
  feeRateSatPerKvB: bigint;
  urgency: 'priority' | 'standard' | 'economy' | 'recommended' | 'custom';
  rbf: boolean;
  parentTxid: string | null;
  replacesTxid: string | null;
  broadcast: true;
  psbtHex: string;
  psbtHash: string;
  analysisHash: string;
  transactionCommitmentHash: string;
  inscriptionPreviews: StoredInscriptionPreviewSet;
  planHash: string;
}

/** Read-only plan created before stable public-account IDs and exact custom fee policy. */
export type LegacyCurrentTransactionPlan = Omit<TransactionPlan, 'version' | 'accountId' | 'policy'> & {
  version: 3;
  policy: { intent: PlanIntent; fee: LegacyPlanFeePolicy };
};

/** Read-only shape for encrypted M7 records created before analysis binding. */
export type LegacyAnalyzedTransactionPlan = Omit<
  LegacyCurrentTransactionPlan,
  'version' | 'transactionCommitmentHash' | 'inscriptionPreviews'
> & {
  version: 2;
};

export type LegacyTransactionPlan = Omit<LegacyAnalyzedTransactionPlan, 'version' | 'analysisHash'> & {
  version: 1;
};

export type TransactionReauthReason =
  | 'high_security_mode'
  | 'high_absolute_fee'
  | 'high_relative_fee';

export interface OrdinalActionReview {
  action: 'transfer' | 'rescue' | 'sweep';
  inscriptionId: string | null;
  destination: {
    address: string;
    valueSats: string;
    ownership: 'external' | 'wallet';
  };
  postageSats: string;
  feeSats: string;
  protectedSource: {
    txid: string;
    vout: number;
    valueSats: string;
  };
  fundingInputs: Array<{
    txid: string;
    vout: number;
    valueSats: string;
  }>;
  retainedInscriptionIds: string[];
  returnedBtcSats: string;
  requiresNonTaprootAcknowledgement: boolean;
}

export interface TransactionReview {
  kind: TransactionKind;
  network: Network;
  accountId: string;
  recipients: Array<{ address: string; valueSats: string; role: PlanOutputRole }>;
  inputs: Array<{
    txid: string;
    vout: number;
    valueSats: string;
    classification: string;
    path: string;
  }>;
  change: Array<{ address: string; valueSats: string; role: PlanOutputRole }>;
  amountSats: string;
  feeSats: string;
  totalSats: string;
  vsize: string;
  feeRateSatPerKvB: string;
  feeRateSatPerVb: string;
  urgency: TransactionPlan['urgency'];
  rbf: boolean;
  psbtHash: string;
  standardModeMissingProtections: string[];
  requiresReauth: boolean;
  reauthReasons: TransactionReauthReason[];
  ordinalAction: OrdinalActionReview | null;
}

function normalized(value: unknown): unknown {
  if (typeof value === 'bigint') return value.toString();
  if (Array.isArray(value)) return value.map(normalized);
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .filter(([key]) => key !== 'planHash')
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([key, item]) => [key, normalized(item)]),
    );
  }
  return value;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

export function hashPlan(
  plan: Omit<TransactionPlan, 'planHash'> | TransactionPlan |
    Omit<LegacyCurrentTransactionPlan, 'planHash'> | LegacyCurrentTransactionPlan |
    Omit<LegacyAnalyzedTransactionPlan, 'planHash'> | LegacyAnalyzedTransactionPlan |
    Omit<LegacyTransactionPlan, 'planHash'> | LegacyTransactionPlan,
): string {
  const bytes = new TextEncoder().encode(JSON.stringify(normalized(plan)));
  return bytesToHex(getCryptoProvider().sha256(bytes));
}

export function hashHex(hex: string): string {
  // Validate rather than coerce: Number.parseInt returns NaN for a non-hex pair
  // and storing NaN in a Uint8Array silently writes 0, so malformed input would
  // hash to a real digest instead of failing.
  if (hex.length % 2 !== 0 || !/^[0-9a-f]*$/u.test(hex)) throw new Error('invalid hex');
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i += 1) bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return bytesToHex(getCryptoProvider().sha256(bytes));
}

export function transactionCommitmentHash(
  plan: object,
): string {
  const {
    planHash: _planHash,
    transactionCommitmentHash: _transactionCommitmentHash,
    inscriptionPreviews: _inscriptionPreviews,
    ...transaction
  } = plan as TransactionPlan;
  void _planHash;
  void _transactionCommitmentHash;
  void _inscriptionPreviews;
  const bytes = new TextEncoder().encode(JSON.stringify(normalized(transaction)));
  return bytesToHex(getCryptoProvider().sha256(bytes));
}

export function finalizePlan(
  plan: Omit<TransactionPlan, 'planHash' | 'transactionCommitmentHash'>,
): TransactionPlan {
  const withCommitment = { ...plan, transactionCommitmentHash: transactionCommitmentHash(plan) };
  const result = { ...withCommitment, planHash: hashPlan(withCommitment) };
  return deepFreeze(result);
}

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value as Record<string, unknown>)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

export function assertPlanHash(plan: TransactionPlan): void {
  assertPlanAccountIdentity(plan);
  if (transactionCommitmentHash(plan) !== plan.transactionCommitmentHash) {
    throw new Error('transaction commitment mutated');
  }
  if (hashPlan(plan) !== plan.planHash) throw new Error('transaction plan mutated');
}

function assertPlanAccountIdentity(plan: TransactionPlan): void {
  if (!plan.accountId.startsWith(`acct_${plan.network}_`)) {
    throw new Error('transaction plan public account network mismatch');
  }
  for (const input of plan.inputs) {
    if (input.ownership !== 'external' &&
        (input.derivation?.accountId !== plan.accountId || input.derivation.account !== plan.account)) {
      throw new Error('transaction input public account identity mismatch');
    }
  }
  for (const output of plan.outputs) {
    if (output.derivation !== undefined &&
        (output.derivation.accountId !== plan.accountId || output.derivation.account !== plan.account)) {
      throw new Error('transaction output public account identity mismatch');
    }
  }
}

export function assertLegacyCurrentPlanHash(plan: LegacyCurrentTransactionPlan): void {
  if (transactionCommitmentHash(plan) !== plan.transactionCommitmentHash) {
    throw new Error('legacy transaction commitment mutated');
  }
  if (hashPlan(plan) !== plan.planHash) throw new Error('legacy current transaction plan mutated');
}

export function assertLegacyAnalyzedPlanHash(plan: LegacyAnalyzedTransactionPlan): void {
  if (hashPlan(plan) !== plan.planHash) throw new Error('legacy analyzed transaction plan mutated');
}

export function assertLegacyPlanHash(plan: LegacyTransactionPlan): void {
  if (hashPlan(plan) !== plan.planHash) throw new Error('legacy transaction plan mutated');
}

export function inputFromUtxo(
  utxo: WalletUtxo,
  derivation: PlanDerivation,
  sequence: number,
): PlanInput {
  if (!utxo.facts) throw new Error('missing input classification');
  if (!utxo.accountId || derivation.accountId !== utxo.accountId) {
    throw new Error('input public account identity mismatch');
  }
  return {
    txid: utxo.outpoint.txid,
    vout: utxo.outpoint.vout,
    valueSats: utxo.valueSats,
    scriptPubKey: utxo.scriptPubKey,
    sequence,
    sighash: utxo.lane === 'payment' ? 1 : 0,
    ownership: 'wallet',
    derivation,
    classification: utxo.facts,
  };
}

export function reviewFromPlan(
  plan: TransactionPlan,
  missingProtections: readonly string[],
  highSecurityMode: boolean,
): TransactionReview {
  const recipients = plan.outputs.filter((output) => output.role === 'recipient' || output.role === 'postage');
  const sent = recipients.reduce((sum, output) => sum + output.valueSats, 0n);
  const reauthReasons: TransactionReauthReason[] = [];
  if (highSecurityMode) reauthReasons.push('high_security_mode');
  if (plan.feeSats > 100_000n) reauthReasons.push('high_absolute_fee');
  const postageIsNotPrincipal =
    plan.kind === 'ordinal_transfer' ||
    plan.kind === 'rescue' ||
    plan.kind === 'ordinal_sweep';
  if (!postageIsNotPrincipal && sent > 0n && plan.feeSats * 10n > sent) {
    reauthReasons.push('high_relative_fee');
  }
  return {
    kind: plan.kind,
    network: plan.network,
    accountId: plan.accountId,
    recipients: recipients.map((output) => ({
      address: output.address,
      valueSats: output.valueSats.toString(),
      role: output.role,
    })),
    inputs: plan.inputs.map((input) => ({
      txid: input.txid,
      vout: input.vout,
      valueSats: input.valueSats.toString(),
      classification: input.classification.primaryClass,
      path: input.derivation?.path ?? 'external',
    })),
    change: plan.outputs
      .filter((output) => output.role === 'payment_change' || output.role === 'ordinal_change')
      .map((output) => ({
        address: output.address,
        valueSats: output.valueSats.toString(),
        role: output.role,
      })),
    amountSats: sent.toString(),
    feeSats: plan.feeSats.toString(),
    totalSats: (sent + plan.feeSats).toString(),
    vsize: plan.vsize.toString(),
    feeRateSatPerKvB: plan.feeRateSatPerKvB.toString(),
    feeRateSatPerVb: formatFeeRateSatPerVb(plan.feeRateSatPerKvB),
    urgency: plan.urgency,
    rbf: plan.rbf,
    psbtHash: plan.psbtHash,
    standardModeMissingProtections: [...missingProtections],
    requiresReauth: reauthReasons.length > 0,
    reauthReasons,
    ordinalAction: ordinalActionReviewFromPlan(plan),
  };
}

export function ordinalActionReviewFromPlan(plan: TransactionPlan): OrdinalActionReview | null {
  if (
    plan.kind !== 'ordinal_transfer' &&
    plan.kind !== 'rescue' &&
    plan.kind !== 'ordinal_sweep'
  ) return null;
  const protectedSource = plan.inputs[0];
  if (!protectedSource) throw new Error('ordinal action source input is missing');
  const targetId = plan.kind === 'ordinal_transfer'
    ? (plan.policy.intent.kind === 'ordinal_transfer'
        ? plan.policy.intent.inscriptionId
        : null)
    : plan.kind === 'rescue'
      ? plan.protectedSatFlow[0]?.inscriptionId ?? null
      : null;
  const destinationOutput = plan.kind === 'ordinal_sweep'
    ? plan.outputs.find((output) => output.role === 'ordinal_change')
    : plan.outputs.find((output) => output.role === 'postage');
  if (!destinationOutput) throw new Error('ordinal action destination is missing');
  const retainedInscriptionIds = plan.protectedSatFlow
    .filter((flow) => flow.inscriptionId !== targetId)
    .map((flow) => flow.inscriptionId)
    .sort((a, b) => a.localeCompare(b));
  const returnedBtcSats = plan.outputs
    .filter((output) => output.role === 'payment_change')
    .reduce((sum, output) => sum + output.valueSats, 0n);
  return {
    action: plan.kind === 'ordinal_transfer'
      ? 'transfer'
      : plan.kind === 'rescue' ? 'rescue' : 'sweep',
    inscriptionId: targetId,
    destination: {
      address: destinationOutput.address,
      valueSats: destinationOutput.valueSats.toString(),
      ownership: destinationOutput.derivation === undefined ? 'external' : 'wallet',
    },
    postageSats: destinationOutput.valueSats.toString(),
    feeSats: plan.feeSats.toString(),
    protectedSource: {
      txid: protectedSource.txid,
      vout: protectedSource.vout,
      valueSats: protectedSource.valueSats.toString(),
    },
    fundingInputs: plan.inputs.slice(1).map((input) => ({
      txid: input.txid,
      vout: input.vout,
      valueSats: input.valueSats.toString(),
    })),
    retainedInscriptionIds,
    returnedBtcSats: returnedBtcSats.toString(),
    requiresNonTaprootAcknowledgement:
      plan.kind === 'ordinal_transfer' &&
      !(destinationOutput.scriptPubKey.startsWith('5120') && destinationOutput.scriptPubKey.length === 68),
  };
}

// Cache parsing is deliberately structural; the plan hash is rechecked after
// decrypt, making any accepted structural value immutable in practice.
const bigintSchema = z.bigint().nonnegative();
const derivationSchema = z.object({
  accountId: z.string().regex(/^acct_(?:mainnet|signet)_[0-9a-f]{64}$/u).optional(),
  account: z.number().int().nonnegative(), lane: z.enum(['payment', 'ordinals']),
  chain: z.union([z.literal(0), z.literal(1)]), index: z.number().int().nonnegative(),
  path: z.string().min(1), publicKeyHex: z.string().regex(/^[0-9a-f]+$/),
}).strict();
const classificationSchema = z.object({
  primaryClass: z.enum(['cardinal_clean', 'inscribed', 'rare_sat', 'runic_or_unsupported', 'mixed', 'unknown']),
  inscriptions: z.array(z.object({ inscriptionId: z.string(), number: z.number().int().optional(), satpoint: z.string() }).strict()),
  satRanges: z.array(z.object({ start: z.string(), end: z.string(), rarity: z.enum(['common','uncommon','rare','epic','legendary','mythic']).optional() }).strict()).nullable(),
  unsupportedAssetDetected: z.boolean(),
  detectedAssets: z.array(detectedAssetSchema).max(16).optional(),
  detectedAssetCount: z.number().int().nonnegative().optional(),
  assetIdentityComplete: z.boolean().optional(),
  confidence: z.enum(['authoritative','degraded']),
  classifiedTip: z.object({ height: z.number().int().nonnegative(), hash: z.string() }).strict(),
  classificationRevision: z.string(),
}).strict().superRefine((classification, ctx) => {
  if (classification.primaryClass === 'cardinal_clean' && !isAuthoritativeCardinalClean(classification)) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      path: ['primaryClass'],
      message: 'cardinal_clean classification contradicts protected asset facts',
    });
  }
});
const outpointSchema = z.object({ txid: z.string().regex(/^[0-9a-f]{64}$/), vout: voutSchema }).strict();
const planIntentSchema = z.discriminatedUnion('kind', [
  z.object({ kind: z.literal('native_send'), account: z.number().int().nonnegative(), recipient: z.string(),
    amountSats: z.string().regex(/^(0|[1-9][0-9]*)$/), sendMax: z.boolean(),
    selectedOutpoints: z.array(outpointSchema).optional() }).strict(),
  z.object({ kind: z.literal('ordinal_transfer'), account: z.number().int().nonnegative(),
    inscriptionId: z.string().regex(/^[0-9a-f]{64}i(?:0|[1-9][0-9]*)$/),
    outpoint: outpointSchema, recipient: z.string() }).strict(),
  z.object({ kind: z.literal('consolidation'), account: z.number().int().nonnegative(),
    selectedOutpoints: z.array(outpointSchema).min(1) }).strict(),
  z.object({ kind: z.literal('rbf'), txid: z.string().regex(/^[0-9a-f]{64}$/) }).strict(),
  z.object({ kind: z.literal('cpfp'), txid: z.string().regex(/^[0-9a-f]{64}$/) }).strict(),
  z.object({ kind: z.literal('rescue'), outpoint: outpointSchema }).strict(),
  z.object({ kind: z.literal('ordinal_sweep'), outpoint: outpointSchema }).strict(),
]);
const legacyPlanFeePolicySchema = z.discriminatedUnion('type', [
  z.object({
    type: z.literal('automatic'),
    tier: z.enum(['priority', 'standard', 'economy', 'recommended']),
  }).strict(),
  z.object({ type: z.literal('custom'), satPerVb: z.number().int().positive().max(10_000) }).strict(),
]);

const planFeePolicySchema: z.ZodType<PlanFeePolicy> = z.union([
  z.object({
    type: z.literal('automatic'),
    tier: z.enum(['priority', 'standard', 'economy', 'recommended']),
  }).strict(),
  z.object({
    type: z.literal('custom'),
    rateSatPerKvB: z.string().regex(/^[1-9][0-9]*$/u),
    normalizedSatPerVb: z.string().min(1).max(32),
  }).strict().superRefine((policy, context) => {
    try {
      const parsed = parseCustomFeeRate(policy.normalizedSatPerVb);
      if (parsed.satPerKvB.toString() !== policy.rateSatPerKvB ||
          parsed.normalizedSatPerVb !== policy.normalizedSatPerVb) {
        context.addIssue({ code: z.ZodIssueCode.custom, message: 'custom fee policy is not canonical' });
      }
    } catch {
      context.addIssue({ code: z.ZodIssueCode.custom, message: 'custom fee policy is invalid' });
    }
  }),
]);

const commonPlanShape = {
  planId: z.string().min(1), createdAt: z.number().int().nonnegative(),
  expiresAt: z.number().int().positive(), network: z.enum(['mainnet','signet']),
  account: z.number().int().nonnegative(), kind: z.enum([
    'native_send', 'ordinal_transfer', 'consolidation', 'rbf', 'cpfp', 'rescue', 'ordinal_sweep',
  ]),
  source: z.object({
    backend: z.string(), instanceId: z.string(), classificationRevision: z.string(),
    coreTip: z.object({ height: z.number().int().nonnegative(), hash: z.string() }).strict(),
    indexTip: z.object({ height: z.number().int().nonnegative(), hash: z.string() }).strict(),
    feeQuoteTimestamp: z.string().nullable(), mempoolState: z.string().nullable(),
  }).strict(),
  inputs: z.array(z.object({
    txid: z.string().regex(/^[0-9a-f]{64}$/), vout: voutSchema,
    valueSats: bigintSchema, scriptPubKey: z.string().regex(/^[0-9a-f]+$/),
    sequence: z.number().int().nonnegative(), sighash: z.union([z.literal(0), z.literal(1)]),
    ownership: z.enum(['wallet', 'external']).optional(),
    derivation: derivationSchema.nullable(), classification: classificationSchema,
  }).strict()).min(1),
  outputs: z.array(z.object({
    valueSats: bigintSchema, scriptPubKey: z.string().regex(/^[0-9a-f]+$/), address: z.string(),
    role: z.enum(['recipient','payment_change','ordinal_change','postage']), derivation: derivationSchema.optional(),
  }).strict()).min(1),
  protectedSatFlow: z.array(z.object({ inputIndex: z.number().int().nonnegative(), inputOffset: bigintSchema,
    outputIndex: z.number().int().nonnegative(), outputOffset: bigintSchema, inscriptionId: z.string() }).strict()),
  feeSats: bigintSchema, vsize: bigintSchema, feeRateSatPerKvB: bigintSchema,
  urgency: z.enum(['priority','standard','economy','recommended','custom']),
  rbf: z.boolean(), parentTxid: z.string().nullable(),
  replacesTxid: z.string().nullable(), broadcast: z.literal(true), psbtHex: z.string().regex(/^[0-9a-f]+$/),
  psbtHash: z.string().regex(/^[0-9a-f]{64}$/),
  planHash: z.string().regex(/^[0-9a-f]{64}$/),
};

export const transactionPlanSchema: z.ZodType<TransactionPlan> = z.object({
  version: z.literal(4),
  ...commonPlanShape,
  accountId: z.string().regex(/^acct_(?:mainnet|signet)_[0-9a-f]{64}$/u),
  policy: z.object({ intent: planIntentSchema, fee: planFeePolicySchema }).strict(),
  analysisHash: z.string().regex(/^[0-9a-f]{64}$/),
  transactionCommitmentHash: z.string().regex(/^[0-9a-f]{64}$/),
  inscriptionPreviews: z.object({
    transactionCommitmentHash: z.string().regex(/^[0-9a-f]{64}$/),
    analysisHash: z.string().regex(/^[0-9a-f]{64}$/),
    psbtHash: z.string().regex(/^[0-9a-f]{64}$/),
    effectSetHash: z.string().regex(/^[0-9a-f]{64}$/),
    classificationRevision: z.string().min(1),
    verifiedAtMs: z.number().int().nonnegative(),
    items: z.array(z.object({
      metadata: inscriptionMetadataSchema,
      preview: inscriptionPreviewDescriptorSchema,
    }).strict()).max(64),
  }).strict(),
}).strict().superRefine((plan, context) => {
  if (!plan.accountId.startsWith(`acct_${plan.network}_`)) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      path: ['accountId'],
      message: 'public account identity differs from plan network',
    });
  }
  if ('account' in plan.policy.intent && plan.policy.intent.account !== plan.account) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      path: ['policy', 'intent', 'account'],
      message: 'intent account metadata differs from plan',
    });
  }
  for (const [index, input] of plan.inputs.entries()) {
    if (input.ownership !== 'external' &&
        (input.derivation?.accountId !== plan.accountId || input.derivation.account !== plan.account)) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['inputs', index, 'derivation', 'account'],
        message: 'input account metadata differs from plan',
      });
    }
  }
  for (const [index, output] of plan.outputs.entries()) {
    if (output.derivation !== undefined &&
        (output.derivation.accountId !== plan.accountId || output.derivation.account !== plan.account)) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['outputs', index, 'derivation', 'account'],
        message: 'output account metadata differs from plan',
      });
    }
  }
  if (plan.policy.fee.type === 'custom' &&
      plan.policy.fee.rateSatPerKvB !== plan.feeRateSatPerKvB.toString()) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      path: ['policy', 'fee', 'rateSatPerKvB'],
      message: 'custom fee policy differs from exact plan rate',
    });
  }
  if ((plan.policy.fee.type === 'custom') !== (plan.urgency === 'custom')) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      path: ['urgency'],
      message: 'fee policy and urgency differ',
    });
  }
});

export const legacyCurrentTransactionPlanSchema: z.ZodType<LegacyCurrentTransactionPlan> = z.object({
  version: z.literal(3),
  ...commonPlanShape,
  policy: z.object({ intent: planIntentSchema, fee: legacyPlanFeePolicySchema }).strict(),
  analysisHash: z.string().regex(/^[0-9a-f]{64}$/),
  transactionCommitmentHash: z.string().regex(/^[0-9a-f]{64}$/),
  inscriptionPreviews: z.object({
    transactionCommitmentHash: z.string().regex(/^[0-9a-f]{64}$/),
    analysisHash: z.string().regex(/^[0-9a-f]{64}$/),
    psbtHash: z.string().regex(/^[0-9a-f]{64}$/),
    effectSetHash: z.string().regex(/^[0-9a-f]{64}$/),
    classificationRevision: z.string().min(1),
    verifiedAtMs: z.number().int().nonnegative(),
    items: z.array(z.object({
      metadata: inscriptionMetadataSchema,
      preview: inscriptionPreviewDescriptorSchema,
    }).strict()).max(64),
  }).strict(),
}).strict();

export const legacyAnalyzedTransactionPlanSchema: z.ZodType<LegacyAnalyzedTransactionPlan> = z.object({
  version: z.literal(2),
  ...commonPlanShape,
  policy: z.object({ intent: planIntentSchema, fee: legacyPlanFeePolicySchema }).strict(),
  analysisHash: z.string().regex(/^[0-9a-f]{64}$/),
}).strict();

export const legacyTransactionPlanSchema: z.ZodType<LegacyTransactionPlan> = z.object({
  version: z.literal(1),
  ...commonPlanShape,
  policy: z.object({ intent: planIntentSchema, fee: legacyPlanFeePolicySchema }).strict(),
}).strict();
