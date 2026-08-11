import { z } from 'zod';
import { marketplaceActionSchema, marketplaceAssetKindSchema, marketplaceIdSchema,
  marketplaceRoleSchema } from './types';

export const marketplaceWorkflowStateSchema = z.enum([
  'prepared',
  'needs_reapproval',
  'approved_unsigned',
  'signed_undelivered',
  'delivered_site_broadcast',
  'wallet_broadcast_pending',
  'completed',
  'cancelled',
  'invalidated',
]);
export type MarketplaceWorkflowState = z.infer<typeof marketplaceWorkflowStateSchema>;

export const marketplaceWorkflowSchema = z.object({
  version: z.literal(1),
  workflowId: z.string().min(1).max(128),
  marketplaceId: marketplaceIdSchema,
  templateId: z.string().min(1).max(128),
  templateVersion: z.string().min(1).max(64),
  origin: z.string().url(),
  network: z.enum(['mainnet', 'signet']),
  vaultId: z.string().min(1),
  sessionId: z.string().min(1),
  account: z.number().int().nonnegative(),
  role: marketplaceRoleSchema,
  action: marketplaceActionSchema,
  assetKind: marketplaceAssetKindSchema,
  step: z.number().int().positive(),
  stepCount: z.number().int().positive(),
  state: marketplaceWorkflowStateSchema,
  requestHash: z.string().regex(/^[0-9a-f]{64}$/u),
  psbtHash: z.string().regex(/^[0-9a-f]{64}$/u),
  analysisHash: z.string().regex(/^[0-9a-f]{64}$/u),
  planHash: z.string().regex(/^[0-9a-f]{64}$/u),
  priorSignedHash: z.string().regex(/^[0-9a-f]{64}$/u).nullable(),
  signedPsbtBase64: z.string().min(1).nullable(),
  reservedOutpoints: z.array(z.string().regex(/^[0-9a-f]{64}:[0-9]+$/u)).max(100),
  broadcaster: z.enum(['site', 'wallet']),
  revision: z.string().max(128).nullable(),
  expiresAt: z.number().int().positive(),
  createdAt: z.number().int().nonnegative(),
  updatedAt: z.number().int().nonnegative(),
}).strict().superRefine((value, ctx) => {
  if (value.step > value.stepCount) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['step'], message: 'step exceeds stepCount' });
  }
  if (value.state === 'signed_undelivered' && value.signedPsbtBase64 === null) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['signedPsbtBase64'], message: 'signed bytes required' });
  }
  if (new Set(value.reservedOutpoints).size !== value.reservedOutpoints.length) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['reservedOutpoints'], message: 'duplicate reserved outpoint' });
  }
});
export type MarketplaceWorkflow = z.infer<typeof marketplaceWorkflowSchema>;

export const marketplaceReservationSchema = z.object({
  version: z.literal(1),
  outpoint: z.string().regex(/^[0-9a-f]{64}:[0-9]+$/u),
  workflowId: z.string().min(1).max(128),
  marketplaceId: marketplaceIdSchema,
  templateId: z.string().min(1).max(128),
  vaultId: z.string().min(1),
  network: z.enum(['mainnet', 'signet']),
  account: z.number().int().nonnegative(),
  reason: z.enum(['exported_offer', 'exported_listing', 'funding_parent']),
  createdAt: z.number().int().nonnegative(),
  expiresAt: z.number().int().positive().nullable(),
  releasedAt: z.number().int().nonnegative().nullable(),
  releaseProof: z.enum(['settlement', 'conflicting_spend', 'template_cancellation']).nullable(),
}).strict();
export type MarketplaceReservation = z.infer<typeof marketplaceReservationSchema>;

const ALLOWED_TRANSITIONS: Readonly<Record<MarketplaceWorkflowState, readonly MarketplaceWorkflowState[]>> = {
  prepared: ['needs_reapproval', 'approved_unsigned', 'cancelled', 'invalidated'],
  needs_reapproval: ['approved_unsigned', 'cancelled', 'invalidated'],
  approved_unsigned: ['needs_reapproval', 'signed_undelivered', 'wallet_broadcast_pending', 'cancelled', 'invalidated'],
  signed_undelivered: ['delivered_site_broadcast', 'needs_reapproval', 'invalidated'],
  delivered_site_broadcast: ['completed', 'invalidated'],
  wallet_broadcast_pending: ['completed', 'invalidated'],
  completed: [],
  cancelled: [],
  invalidated: [],
};

export function transitionMarketplaceWorkflow(
  workflow: MarketplaceWorkflow,
  state: MarketplaceWorkflowState,
  now: number,
  patch: Partial<Pick<MarketplaceWorkflow, 'signedPsbtBase64' | 'priorSignedHash'>> = {},
): MarketplaceWorkflow {
  if (!ALLOWED_TRANSITIONS[workflow.state].includes(state)) {
    throw new Error(`invalid marketplace workflow transition ${workflow.state} -> ${state}`);
  }
  return marketplaceWorkflowSchema.parse({ ...workflow, ...patch, state, updatedAt: now });
}

/** Worker restart cannot preserve approval authority. */
export function recoverMarketplaceWorkflowAfterRestart(
  workflow: MarketplaceWorkflow,
  now: number,
): MarketplaceWorkflow {
  if (workflow.state === 'prepared' || workflow.state === 'approved_unsigned') {
    return transitionMarketplaceWorkflow(workflow, 'needs_reapproval', now);
  }
  return workflow;
}

export function canReleaseSignedResponse(input: {
  workflow: MarketplaceWorkflow;
  origin: string;
  vaultId: string;
  account: number;
  requestHash: string;
  psbtHash: string;
  now: number;
}): boolean {
  const { workflow } = input;
  return workflow.state === 'signed_undelivered' && workflow.signedPsbtBase64 !== null &&
    workflow.origin === input.origin && workflow.vaultId === input.vaultId && workflow.account === input.account &&
    workflow.requestHash === input.requestHash && workflow.psbtHash === input.psbtHash && input.now < workflow.expiresAt;
}

export function releaseMarketplaceReservation(
  reservation: MarketplaceReservation,
  proof: NonNullable<MarketplaceReservation['releaseProof']>,
  now: number,
): MarketplaceReservation {
  if (reservation.releasedAt !== null) throw new Error('marketplace reservation already released');
  return marketplaceReservationSchema.parse({ ...reservation, releasedAt: now, releaseProof: proof });
}
