/** Provider binding for a single owner's exact Community Vault sale approval. */
import { z } from 'zod';
import { communityVaultPolicySchema, type CommunityVaultPolicyV1 } from './contracts';
import {
  communityVaultSalePlanSchema,
  communityVaultSalePreflightSchema,
  type CommunityVaultSalePlanV1,
  type CommunityVaultSalePreflightV1,
} from './sale-contracts';
import {
  assertCommunityVaultSalePreflight,
  validateCommunityVaultSalePsbt,
} from './sale';
import { validateCommunityVaultPsbt } from './psbt';
import { hexToBytes } from '../vault/encoding';
import { Transaction } from '@scure/btc-signer';

const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;

export interface CommunityVaultSaleProviderContextV1 {
  version: 1;
  ownerId: string;
  policy: CommunityVaultPolicyV1;
  plan: CommunityVaultSalePlanV1;
  preflight: CommunityVaultSalePreflightV1;
}

export const communityVaultSaleProviderContextSchema:
z.ZodType<CommunityVaultSaleProviderContextV1> = z.object({
  version: z.literal(1),
  ownerId: z.string().regex(IDENTIFIER),
  policy: communityVaultPolicySchema,
  plan: communityVaultSalePlanSchema,
  preflight: communityVaultSalePreflightSchema,
}).strict();

export interface CommunityVaultSaleProviderReviewV1 {
  version: 1;
  campaignId: string;
  inscriptionId: string;
  offerId: string;
  ownerId: string;
  units: number[];
  selectedInputIndexes: [number];
  grossOfferSats: string;
  ownerPayoutSats: string;
  payoutAddress: string;
  buyerDestinationAddress: string;
  buyerTotalSats: string;
  settlementFeeSats: string;
  offerDigest: string;
  expiresAtMs: string;
}

export function reviewCommunityVaultSaleProviderRequest(input: {
  context: CommunityVaultSaleProviderContextV1;
  psbtHex: string;
  selectedInputIndexes: readonly number[];
  nowMs: string;
}): CommunityVaultSaleProviderReviewV1 {
  const context = communityVaultSaleProviderContextSchema.parse(input.context);
  assertCommunityVaultSalePreflight({
    policy: context.policy,
    plan: context.plan,
    preflight: context.preflight,
    nowMs: input.nowMs,
  });
  const validation = validateCommunityVaultSalePsbt(
    context.policy,
    context.plan,
    input.psbtHex,
  );
  const owner = context.policy.owners.find((candidate) => candidate.ownerId === context.ownerId);
  const payout = context.plan.ownerPayouts.find((candidate) => candidate.ownerId === context.ownerId);
  if (!owner || !payout) {
    throw new Error('Community Vault sale owner is absent from the frozen cap table');
  }
  const requested = [...new Set(input.selectedInputIndexes)].sort((left, right) => left - right);
  const expected = [context.plan.spendPlan.vaultInputIndex];
  if (JSON.stringify(requested) !== JSON.stringify(expected)) {
    throw new Error('Community Vault sale signing input differs from the vault input');
  }
  if (validation.signedUnits.length > 0) {
    throw new Error('Community Vault sale owner package already contains unit signatures');
  }
  return {
    version: 1,
    campaignId: context.plan.campaignId,
    inscriptionId: context.plan.inscriptionId,
    offerId: context.plan.offerId,
    ownerId: context.ownerId,
    units: [...owner.units],
    selectedInputIndexes: [context.plan.spendPlan.vaultInputIndex],
    grossOfferSats: context.plan.grossOfferSats,
    ownerPayoutSats: payout.valueSats,
    payoutAddress: payout.payoutAddress,
    buyerDestinationAddress: context.plan.buyerDestinationAddress,
    buyerTotalSats: context.plan.buyerTotalSats,
    settlementFeeSats: context.plan.settlementFeeSats,
    offerDigest: context.plan.offerDigest,
    expiresAtMs: context.plan.expiresAtMs,
  };
}

/** Provider binding for the buyer funding an exact Community Vault offer. */
export interface CommunityVaultSaleBuyerProviderContextV1 {
  version: 1;
  policy: CommunityVaultPolicyV1;
  plan: CommunityVaultSalePlanV1;
  preflight: CommunityVaultSalePreflightV1;
}

export const communityVaultSaleBuyerProviderContextSchema:
z.ZodType<CommunityVaultSaleBuyerProviderContextV1> = z.object({
  version: z.literal(1),
  policy: communityVaultPolicySchema,
  plan: communityVaultSalePlanSchema,
  preflight: communityVaultSalePreflightSchema,
}).strict();

export interface CommunityVaultSaleBuyerProviderReviewV1 {
  version: 1;
  campaignId: string;
  inscriptionId: string;
  offerId: string;
  buyerId: string;
  selectedInputIndexes: number[];
  grossOfferSats: string;
  buyerDestinationAddress: string;
  buyerTotalSats: string;
  settlementFeeSats: string;
  offerDigest: string;
  expiresAtMs: string;
}

export function reviewCommunityVaultSaleBuyerProviderRequest(input: {
  context: CommunityVaultSaleBuyerProviderContextV1;
  psbtHex: string;
  selectedInputIndexes: readonly number[];
  nowMs: string;
}): CommunityVaultSaleBuyerProviderReviewV1 {
  const context = communityVaultSaleBuyerProviderContextSchema.parse(input.context);
  assertCommunityVaultSalePreflight({
    policy: context.policy,
    plan: context.plan,
    preflight: context.preflight,
    nowMs: input.nowMs,
  });
  const validation = validateCommunityVaultPsbt(
    context.policy,
    context.plan.spendPlan,
    input.psbtHex,
  );
  if (validation.signedUnits.length > 0) {
    throw new Error('Community Vault buyer offer already contains owner unit signatures');
  }
  const tx = Transaction.fromPSBT(hexToBytes(input.psbtHex), { PSBTVersion: 0, lowR: true });
  const expected = context.plan.buyerInputs.map((_item, index) => index + 1);
  for (const index of expected) {
    if ((tx.getInput(index).finalScriptWitness ?? []).length > 0) {
      throw new Error('Community Vault buyer input is already authorized');
    }
  }
  const requested = [...new Set(input.selectedInputIndexes)].sort((left, right) => left - right);
  if (JSON.stringify(requested) !== JSON.stringify(expected)) {
    throw new Error('Community Vault buyer signing inputs differ from exact offer funding');
  }
  return {
    version: 1,
    campaignId: context.plan.campaignId,
    inscriptionId: context.plan.inscriptionId,
    offerId: context.plan.offerId,
    buyerId: context.plan.buyerId,
    selectedInputIndexes: expected,
    grossOfferSats: context.plan.grossOfferSats,
    buyerDestinationAddress: context.plan.buyerDestinationAddress,
    buyerTotalSats: context.plan.buyerTotalSats,
    settlementFeeSats: context.plan.settlementFeeSats,
    offerDigest: context.plan.offerDigest,
    expiresAtMs: context.plan.expiresAtMs,
  };
}
