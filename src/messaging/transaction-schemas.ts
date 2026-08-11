import { z } from 'zod';
import { MAX_ACCOUNT_INDEX } from '../domain/accounts/limits';
import { utxoLabelSchema } from '../domain/classification/labels';
import { voutSchema } from '../domain/gateway/contract';
import { parseCustomFeeRate } from '../domain/transactions/fees';

const hexId = z.string().regex(/^[0-9a-f]{64}$/);
const sats = z.string().regex(/^(0|[1-9][0-9]*)$/);
const session = {
  expectedVaultId: z.string().min(1),
  expectedSessionId: z.string().uuid(),
} as const;
const outpoint = z.object({ txid: hexId, vout: voutSchema }).strict();
const publicAccountId = z.string().regex(/^acct_(?:mainnet|signet)_[0-9a-f]{64}$/u);
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
  ordinalTransferPlan,
  consolidationPlan,
  accelerationPlan('rbf'),
  accelerationPlan('cpfp'),
  recoveryPlan('rescue'),
  recoveryPlan('ordinal_sweep'),
]);

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
export const transactionReviewSchema = z.object({
  kind: z.enum([
    'native_send', 'ordinal_transfer', 'consolidation', 'rbf', 'cpfp', 'rescue', 'ordinal_sweep',
  ]),
  network: z.enum(['mainnet', 'signet']), accountId: publicAccountId, recipients: z.array(reviewOutput),
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
  ordinalAction: ordinalActionReview.nullable().default(null),
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
  /** §14.4 local label; null when unlabeled. Never leaves the device. */
  label: utxoLabelSchema.nullable(),
}).strict()),
  /** Wallet-wide WalletPrivacyNote list, reported once rather than per row. */
  privacyNotes: z.array(z.string()),
}).strict();

export const transactionStatusRequestSchema = z.object({ accountId: publicAccountId, ...session }).strict();
export const transactionStatusResultSchema = z.object({
  network: z.enum(['mainnet', 'signet']), accountId: publicAccountId,
  transactions: z.array(z.object({
  planId: z.string(), kind: z.string(), txid: hexId, createdAt: z.number().int().nonnegative(),
  amountSats: sats, feeSats: sats, status: z.string(), detail: z.string().nullable(),
  parentTxid: hexId.nullable(), replacesTxid: hexId.nullable(), recovering: z.boolean(),
  }).strict()),
}).strict();

export type TransactionPlanRequest = z.infer<typeof transactionPlanRequestSchema>;
export type TransactionApproveRequest = z.infer<typeof transactionApproveRequestSchema>;
export type TransactionReviewRequest = z.infer<typeof transactionReviewRequestSchema>;
export type TransactionPlanResult = z.infer<typeof transactionPlanResultSchema>;
export type FeeQuoteRequest = z.infer<typeof feeQuoteRequestSchema>;
export type UtxoListRequest = z.infer<typeof utxoListRequestSchema>;
