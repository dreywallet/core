import { z } from 'zod';
import { MAX_ACCOUNT_INDEX } from '../domain/accounts/limits';
import { utxoLabelSchema } from '../domain/classification/labels';
import { inscriptionRefSchema, voutSchema } from '../domain/gateway/contract';
import { parseCustomFeeRate } from '../domain/transactions/fees';
import { parseCanonicalSatpoint } from '../domain/ordinals/satpoint';

const hexId = z.string().regex(/^[0-9a-f]{64}$/);
const sats = z.string().regex(/^(0|[1-9][0-9]*)$/);
const session = {
  expectedVaultId: z.string().min(1),
  expectedSessionId: z.string().uuid(),
} as const;
const outpoint = z.object({ txid: hexId, vout: voutSchema }).strict();
const publicAccountId = z.string().regex(/^acct_(?:mainnet|signet|regtest)_[0-9a-f]{64}$/u);
const feePolicy = z.union([
  z.object({
    type: z.literal('automatic'),
    tier: z.enum(['priority', 'standard', 'economy', 'recommended']),
  }).strict(),
  z.object({ type: z.literal('custom'), rateSatPerVb: z.string().min(1).max(32) }).strict()
    .superRefine((policy, context) => {
      try { parseCustomFeeRate(policy.rateSatPerVb); }
      catch (error) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['rateSatPerVb'],
          message: error instanceof Error ? error.message : 'invalid custom fee rate',
        });
      }
    }),
]);

const nativePlan = z.object({
  kind: z.literal('native_send'), accountId: publicAccountId,
  account: z.number().int().min(0).max(MAX_ACCOUNT_INDEX),
  recipient: z.string().min(1).max(8 * 1024), amountSats: sats, sendMax: z.boolean(), fee: feePolicy,
  selectedOutpoints: z.array(outpoint).optional(), ...session,
}).strict();
const nativeBatchPlan = z.object({
  kind: z.literal('native_batch_send'), accountId: publicAccountId,
  account: z.number().int().min(0).max(MAX_ACCOUNT_INDEX),
  recipients: z.array(z.object({
    address: z.string().min(1).max(8 * 1024), amountSats: sats.refine((value) => value !== '0'),
  }).strict()).min(2).max(20),
  fee: feePolicy, selectedOutpoints: z.array(outpoint).optional(), ...session,
}).strict();
const ordinalTransferPlan = z.object({
  kind: z.literal('ordinal_transfer'),
  accountId: publicAccountId,
  account: z.number().int().min(0).max(MAX_ACCOUNT_INDEX),
  inscriptionId: z.string().regex(/^[0-9a-f]{64}i(?:0|[1-9][0-9]*)$/),
  outpoint,
  recipient: z.string().min(1),
  fee: feePolicy,
  ...session,
}).strict();
const ordinalBatchSelection = z.object({
  inscriptionId: z.string().regex(/^[0-9a-f]{64}i(?:0|[1-9][0-9]*)$/),
  outpoint,
  satpoint: z.string().regex(/^[0-9a-f]{64}:(?:0|[1-9][0-9]*):(?:0|[1-9][0-9]*)$/),
  classificationRevision: z.string().min(1),
}).strict();
const ordinalBatchTransferPlan = z.object({
  kind: z.literal('ordinal_batch_transfer'),
  accountId: publicAccountId,
  account: z.number().int().min(0).max(MAX_ACCOUNT_INDEX),
  selections: z.array(ordinalBatchSelection).min(1).max(16),
  recipient: z.string().min(1),
  fee: feePolicy,
  ...session,
}).strict();
const ordinalPostageManagePlan = z.object({
  kind: z.literal('ordinal_postage_manage'), accountId: publicAccountId,
  account: z.number().int().min(0).max(MAX_ACCOUNT_INDEX),
  selections: z.array(ordinalBatchSelection).min(1).max(16),
  target: z.discriminatedUnion('type', [
    z.object({ type: z.literal('common_546') }).strict(),
    z.object({ type: z.literal('compatible_10000') }).strict(),
    z.object({ type: z.literal('minimum_standard') }).strict(),
    z.object({ type: z.literal('keep_current') }).strict(),
    z.object({ type: z.literal('custom'), customSats: sats }).strict(),
  ]),
  fee: feePolicy,
  ...session,
}).strict();
const consolidationPlan = z.object({
  kind: z.literal('consolidation'), accountId: publicAccountId,
  account: z.number().int().min(0).max(MAX_ACCOUNT_INDEX),
  selectedOutpoints: z.array(outpoint).min(1), fee: feePolicy, ...session,
}).strict();
const accelerationPlan = <K extends 'rbf' | 'cpfp'>(kind: K) => z.object({
  kind: z.literal(kind), accountId: publicAccountId,
  account: z.number().int().min(0).max(MAX_ACCOUNT_INDEX), txid: hexId, fee: feePolicy, ...session,
}).strict();
const recoveryPlan = <K extends 'rescue' | 'ordinal_sweep'>(kind: K) => z.object({
  kind: z.literal(kind), accountId: publicAccountId,
  account: z.number().int().min(0).max(MAX_ACCOUNT_INDEX), outpoint, fee: feePolicy, ...session,
}).strict();

export const transactionPlanRequestSchema = z.discriminatedUnion('kind', [
  nativePlan,
  nativeBatchPlan,
  ordinalTransferPlan,
  ordinalBatchTransferPlan,
  ordinalPostageManagePlan,
  consolidationPlan,
  accelerationPlan('rbf'),
  accelerationPlan('cpfp'),
  recoveryPlan('rescue'),
  recoveryPlan('ordinal_sweep'),
]).superRefine((request, context) => {
  if (request.kind === 'native_batch_send' &&
      new Set(request.recipients.map((item) => item.address)).size !== request.recipients.length) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ['recipients'], message: 'duplicate batch recipient' });
  }
  if (request.kind !== 'ordinal_batch_transfer' && request.kind !== 'ordinal_postage_manage') return;
  if (new Set(request.selections.map((item) => item.inscriptionId)).size !== request.selections.length) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ['selections'], message: 'duplicate inscription selection' });
  }
  for (const [index, selection] of request.selections.entries()) {
    const parsed = parseCanonicalSatpoint(selection.satpoint);
    if (!parsed || parsed.txid !== selection.outpoint.txid || parsed.vout !== selection.outpoint.vout) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['selections', index, 'satpoint'],
        message: 'inscription satpoint differs from bound outpoint',
      });
    }
  }
});

const reviewOutput = z.object({
  address: z.string(), valueSats: sats,
  role: z.enum(['recipient', 'payment_change', 'ordinal_change', 'postage']),
}).strict();
const inscriptionReviewPreview = z.discriminatedUnion('kind', [
  z.object({
    kind: z.literal('raster'),
    rasterBase64: z.string().min(1),
    pngSha256: hexId,
    pngWidth: z.number().int().min(1).max(512),
    pngHeight: z.number().int().min(1).max(512),
  }).strict(),
  z.object({
    kind: z.literal('placeholder'),
    reason: z.enum([
      'active_content', 'recursive_content', 'unknown_content', 'unsupported_content',
      'oversized_content', 'mime_mismatch', 'content_length_mismatch', 'decode_failed',
      'render_pending', 'unavailable', 'approval_budget',
    ]),
  }).strict(),
  z.object({
    kind: z.literal('text'),
    textMime: z.enum(['text/plain', 'application/json']),
    excerpt: z.string().min(1).max(4096),
    truncated: z.boolean(),
  }).strict(),
  z.object({
    kind: z.literal('mediaBadge'),
    mediaKind: z.enum(['audio', 'video']),
    contentLength: z.number().int().nonnegative(),
  }).strict(),
]);
const inscriptionReviewItem = z.object({
  inscriptionId: z.string().regex(/^[0-9a-f]{64}i(?:0|[1-9][0-9]*)$/),
  satpoint: z.string().regex(/^[0-9a-f]{64}:(?:0|[1-9][0-9]*):(?:0|[1-9][0-9]*)$/),
  outpoint,
  inputIndex: z.number().int().nonnegative(),
  inputOffset: sats,
  outputIndex: z.number().int().nonnegative(),
  outputOffset: sats,
  movement: z.enum(['received', 'sent', 'retained']),
  coLocationGroup: z.string().min(1),
  qualifiedPartialAuthorization: z.boolean(),
  number: z.number().int().nullable(),
  contentType: z.string().nullable(),
  preview: inscriptionReviewPreview,
}).strict();
const ordinalActionReview = z.object({
  action: z.enum(['transfer', 'rescue', 'sweep']),
  inscriptionId: z.string().regex(/^[0-9a-f]{64}i(?:0|[1-9][0-9]*)$/).nullable(),
  destination: z.object({
    address: z.string(),
    valueSats: sats,
    ownership: z.enum(['external', 'wallet']),
  }).strict(),
  postageSats: sats,
  feeSats: sats,
  protectedSource: z.object({
    txid: hexId,
    vout: voutSchema,
    valueSats: sats,
  }).strict(),
  fundingInputs: z.array(z.object({
    txid: hexId,
    vout: voutSchema,
    valueSats: sats,
  }).strict()),
  retainedInscriptionIds: z.array(
    z.string().regex(/^[0-9a-f]{64}i(?:0|[1-9][0-9]*)$/),
  ),
  returnedBtcSats: sats,
  requiresNonTaprootAcknowledgement: z.boolean(),
}).strict();
const ordinalBatchActionReview = z.object({
  action: z.literal('batch_transfer'),
  inscriptionIds: z.array(z.string().regex(/^[0-9a-f]{64}i(?:0|[1-9][0-9]*)$/)).min(1).max(16),
  inscriptionCount: z.number().int().min(1).max(16),
  destination: z.object({ address: z.string(), ownership: z.enum(['external', 'wallet']) }).strict(),
  groups: z.array(z.object({
    inscriptionIds: z.array(z.string().regex(/^[0-9a-f]{64}i(?:0|[1-9][0-9]*)$/)).min(1).max(16),
    source: z.object({ txid: hexId, vout: voutSchema, valueSats: sats }).strict(),
    satpoint: z.string().regex(/^[0-9a-f]{64}:(?:0|[1-9][0-9]*):(?:0|[1-9][0-9]*)$/),
    destinationOutputIndex: z.number().int().nonnegative(),
    postageSats: sats,
    travelsTogether: z.boolean(),
  }).strict()).min(1).max(16),
  aggregatePostageSats: sats,
  feeSats: sats,
  fundingInputs: z.array(z.object({ txid: hexId, vout: voutSchema, valueSats: sats }).strict()),
  returnedBtcSats: sats,
  requiresNonTaprootAcknowledgement: z.boolean(),
}).strict().superRefine((review, context) => {
  if (review.inscriptionCount !== review.inscriptionIds.length ||
      new Set(review.inscriptionIds).size !== review.inscriptionIds.length) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ['inscriptionCount'], message: 'batch inscription count differs' });
  }
  const groupedIds = review.groups.flatMap((group) => group.inscriptionIds);
  if (groupedIds.length !== review.inscriptionCount ||
      new Set(groupedIds).size !== groupedIds.length ||
      groupedIds.some((id) => !review.inscriptionIds.includes(id))) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ['groups'], message: 'batch review groups are incomplete' });
  }
});
const ordinalPostageActionReview = z.object({
  action: z.literal('manage_postage'),
  target: z.discriminatedUnion('type', [
    z.object({ type: z.literal('common_546') }).strict(),
    z.object({ type: z.literal('compatible_10000') }).strict(),
    z.object({ type: z.literal('minimum_standard') }).strict(),
    z.object({ type: z.literal('keep_current') }).strict(),
    z.object({ type: z.literal('custom'), customSats: sats }).strict(),
  ]),
  items: z.array(z.object({
    inscriptionId: z.string().regex(/^[0-9a-f]{64}i(?:0|[1-9][0-9]*)$/),
    source: z.object({ txid: hexId, vout: voutSchema, valueSats: sats }).strict(),
    currentPostageSats: sats, retainedPostageSats: sats, recoveredSats: sats, addedSats: sats,
  }).strict()).min(1).max(16),
  feeSats: sats,
  fundingInputs: z.array(z.object({ txid: hexId, vout: voutSchema, valueSats: sats }).strict()),
  returnedBtcSats: sats,
  netReturnedBtcSats: sats,
}).strict();
export const transactionReviewSchema = z.object({
  kind: z.enum([
    'native_send', 'native_batch_send', 'ordinal_transfer', 'ordinal_batch_transfer', 'ordinal_postage_manage', 'consolidation', 'rbf', 'cpfp', 'rescue', 'ordinal_sweep',
  ]),
  network: z.enum(['mainnet', 'signet', 'regtest']), accountId: publicAccountId, recipients: z.array(reviewOutput),
  inputs: z.array(z.object({ txid: hexId, vout: voutSchema, valueSats: sats,
    classification: z.string(), path: z.string() }).strict()),
  change: z.array(reviewOutput), amountSats: sats, feeSats: sats, totalSats: sats, vsize: sats,
  feeRateSatPerKvB: sats, feeRateSatPerVb: z.string().regex(/^(?:0|[1-9][0-9]*)(?:\.[0-9]{1,3})?$/u),
  urgency: z.enum(['priority', 'standard', 'economy', 'recommended', 'custom']),
  rbf: z.boolean(),
  psbtHash: hexId, standardModeMissingProtections: z.array(z.string()), requiresReauth: z.boolean(),
  reauthReasons: z.array(z.enum(['high_security_mode', 'high_absolute_fee', 'high_relative_fee'])),
  effectCount: z.number().int().nonnegative(),
  inscriptions: z.array(inscriptionReviewItem).max(64),
  requiresPreviewAcknowledgement: z.boolean(),
  ordinalAction: z.union([ordinalActionReview, ordinalBatchActionReview, ordinalPostageActionReview]).nullable().default(null),
}).strict();

export const transactionPlanResultSchema = z.object({
  planId: z.string().min(1), planHash: hexId, expiresAt: z.number().int().positive(),
  review: transactionReviewSchema,
}).strict();
export const transactionReviewRequestSchema = z.object({
  accountId: publicAccountId, planId: z.string().min(1), ...session,
}).strict();
export const transactionCancelRequestSchema = transactionReviewRequestSchema;
export const transactionApproveRequestSchema = z.object({
  accountId: publicAccountId, planId: z.string().min(1), planHash: hexId,
  password: z.string().min(1).optional(),
  previewUnavailableAcknowledged: z.boolean().optional(),
  nonTaprootDestinationAcknowledged: z.boolean().optional(),
  ...session,
}).strict();
const replacementApproveResult = z.object({
  planId: z.string(), txid: z.null(), status: z.literal('review_required'),
  detail: z.string().nullable(), replacement: transactionPlanResultSchema,
}).strict();
export const transactionApproveResultSchema = z.discriminatedUnion('status', [
  z.object({ planId: z.string(), txid: hexId, status: z.literal('pending'), detail: z.string().nullable() }).strict(),
  z.object({ planId: z.string(), txid: hexId, status: z.literal('accepted'), detail: z.string().nullable() }).strict(),
  z.object({ planId: z.string(), txid: hexId, status: z.literal('already_known'), detail: z.string().nullable() }).strict(),
  z.object({ planId: z.string(), txid: hexId, status: z.literal('confirmed'), detail: z.string().nullable() }).strict(),
  z.object({ planId: z.string(), txid: hexId, status: z.literal('conflicted'), detail: z.string().nullable() }).strict(),
  z.object({ planId: z.string(), txid: hexId, status: z.literal('rejected'), detail: z.string().nullable() }).strict(),
  replacementApproveResult,
]);
export const transactionCancelResultSchema = z.object({ cancelled: z.boolean() }).strict();

export const feeQuoteRequestSchema = z.object(session).strict();
export const feeQuoteResultSchema = z.object({
  prioritySatPerKvB: z.number().int().positive(),
  standardSatPerKvB: z.number().int().positive(),
  economySatPerKvB: z.number().int().positive(),
  floorSatPerKvB: z.number().int().positive(), sampledAt: z.string().datetime(), expiresAt: z.string().datetime(),
}).strict();

export const utxoListRequestSchema = z.object({
  accountId: publicAccountId,
  feeRateSatPerKvB: z.number().int().positive().max(10_000_000),
  ...session,
}).strict();
export const utxoListResultSchema = z.object({ utxos: z.array(z.object({
  txid: hexId, vout: voutSchema, valueSats: sats, effectiveValueSats: sats,
  accountId: publicAccountId, account: z.number().int().nonnegative(),
  lane: z.enum(['payment','ordinals']), path: z.string(),
  classification: z.string(), eligible: z.boolean(), reasons: z.array(z.string()), frozen: z.boolean(),
  dustQuarantined: z.boolean(),
  wrongLane: z.enum(['normal','protected_wrong_address','reserved_ordinal_lane_btc']),
  /** Display-only inscription identities attached to this exact outpoint. */
  inscriptions: z.array(inscriptionRefSchema),
  /** §14.4 local label; null when unlabeled. Never leaves the device. */
  label: utxoLabelSchema.nullable(),
}).strict()),
  /** Wallet-wide WalletPrivacyNote list, reported once rather than per row. */
  privacyNotes: z.array(z.string()),
}).strict();

export const transactionStatusRequestSchema = z.object({ accountId: publicAccountId, ...session }).strict();
export const transactionStatusResultSchema = z.object({
  network: z.enum(['mainnet', 'signet', 'regtest']), accountId: publicAccountId,
  transactions: z.array(z.object({
  planId: z.string(), kind: z.string(), txid: hexId, createdAt: z.number().int().nonnegative(),
  amountSats: sats, feeSats: sats, status: z.string(), detail: z.string().nullable(),
  parentTxid: hexId.nullable(), replacesTxid: hexId.nullable(), recovering: z.boolean(),
  recommendedAcceleration: z.enum(['rbf', 'cpfp']).nullable().optional().default(null),
  accelerationUnavailableReason: z.string().nullable().optional().default(null),
  }).strict()),
}).strict();

export type TransactionPlanRequest = z.infer<typeof transactionPlanRequestSchema>;
export type TransactionApproveRequest = z.infer<typeof transactionApproveRequestSchema>;
export type TransactionReviewRequest = z.infer<typeof transactionReviewRequestSchema>;
export type TransactionPlanResult = z.infer<typeof transactionPlanResultSchema>;
export type FeeQuoteRequest = z.infer<typeof feeQuoteRequestSchema>;
export type UtxoListRequest = z.infer<typeof utxoListRequestSchema>;
