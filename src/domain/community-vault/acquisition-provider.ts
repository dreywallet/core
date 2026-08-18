/** Provider binding for a single owner's Community Vault acquisition approval. */
import { z } from 'zod';
import { communityVaultPolicySchema, type CommunityVaultPolicyV1 } from './contracts';
import {
  communityVaultAcquisitionPlanSchema,
  communityVaultAcquisitionPreflightSchema,
  type CommunityVaultAcquisitionPlanV1,
  type CommunityVaultAcquisitionPreflightV1,
} from './acquisition-contracts';
import {
  assertCommunityVaultAcquisitionPreflight,
  validateCommunityVaultAcquisitionPsbt,
} from './acquisition';

const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;

export interface CommunityVaultAcquisitionProviderContextV1 {
  version: 1;
  ownerId: string;
  policy: CommunityVaultPolicyV1;
  plan: CommunityVaultAcquisitionPlanV1;
  preflight: CommunityVaultAcquisitionPreflightV1;
}

export const communityVaultAcquisitionProviderContextSchema:
z.ZodType<CommunityVaultAcquisitionProviderContextV1> = z.object({
  version: z.literal(1),
  ownerId: z.string().regex(IDENTIFIER),
  policy: communityVaultPolicySchema,
  plan: communityVaultAcquisitionPlanSchema,
  preflight: communityVaultAcquisitionPreflightSchema,
}).strict();

export interface CommunityVaultAcquisitionProviderReviewV1 {
  version: 1;
  campaignId: string;
  inscriptionId: string;
  source: 'listed' | 'creator-fronted';
  ownerId: string;
  units: number[];
  selectedInputIndexes: number[];
  assetCostShareSats: string;
  settlementFeeShareSats: string;
  cashDueSats: string;
  changeSats: string;
  vaultAddress: string;
  planDigest: string;
  expiresAtMs: string;
}

export function reviewCommunityVaultAcquisitionProviderRequest(input: {
  context: CommunityVaultAcquisitionProviderContextV1;
  psbtHex: string;
  selectedInputIndexes: readonly number[];
  nowMs: string;
}): CommunityVaultAcquisitionProviderReviewV1 {
  const context = communityVaultAcquisitionProviderContextSchema.parse(input.context);
  assertCommunityVaultAcquisitionPreflight({
    policy: context.policy,
    plan: context.plan,
    preflight: context.preflight,
    nowMs: input.nowMs,
  });
  const validation = validateCommunityVaultAcquisitionPsbt(
    context.policy,
    context.plan,
    input.psbtHex,
  );
  const owner = context.policy.owners.find((candidate) => candidate.ownerId === context.ownerId);
  const obligation = context.plan.ownerObligations.find(
    (candidate) => candidate.ownerId === context.ownerId,
  );
  if (!owner || !obligation) {
    throw new Error('Community Vault acquisition owner is absent from the frozen cap table');
  }
  const expected = context.plan.inputs
    .map((candidate, index) => candidate.ownerId === context.ownerId ? index : -1)
    .filter((index) => index >= 0);
  const requested = [...new Set(input.selectedInputIndexes)].sort((left, right) => left - right);
  if (expected.length === 0 || JSON.stringify(requested) !== JSON.stringify(expected)) {
    throw new Error('Community Vault acquisition signing inputs differ from this owner');
  }
  if (requested.some((index) => validation.signedInputIndexes.includes(index))) {
    throw new Error('Community Vault acquisition owner inputs are already signed');
  }
  return {
    version: 1,
    campaignId: context.plan.campaignId,
    inscriptionId: context.plan.inscriptionId,
    source: context.plan.source,
    ownerId: context.ownerId,
    units: [...owner.units],
    selectedInputIndexes: requested,
    assetCostShareSats: obligation.assetCostShareSats,
    settlementFeeShareSats: obligation.settlementFeeShareSats,
    cashDueSats: obligation.cashDueSats,
    changeSats: obligation.changeSats,
    vaultAddress: context.policy.address,
    planDigest: context.plan.planDigest,
    expiresAtMs: context.plan.expiresAtMs,
  };
}
