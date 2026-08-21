/** Provider review bindings for a private Community Vault position transfer. */
import { Transaction } from '@scure/btc-signer';
import { z } from 'zod';

import { hexToBytes } from '../vault/encoding';
import { communityVaultPolicySchema, type CommunityVaultPolicyV1 } from './contracts';
import {
  communityVaultPositionTransferPlanSchema,
  communityVaultPositionTransferPreflightSchema,
  type CommunityVaultPositionTransferPlanV1,
  type CommunityVaultPositionTransferPreflightV1,
} from './position-transfer-contracts';
import {
  assertCommunityVaultPositionTransferPreflight,
  validateCommunityVaultPositionTransferPsbt,
} from './position-transfer';

const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;

interface BaseContextV1 {
  version: 1;
  currentPolicy: CommunityVaultPolicyV1;
  plan: CommunityVaultPositionTransferPlanV1;
  preflight: CommunityVaultPositionTransferPreflightV1;
}

export interface CommunityVaultPositionTransferOwnerProviderContextV1 extends BaseContextV1 {
  ownerId: string;
}

export const communityVaultPositionTransferOwnerProviderContextSchema:
z.ZodType<CommunityVaultPositionTransferOwnerProviderContextV1> = z.object({
  version: z.literal(1),
  ownerId: z.string().regex(IDENTIFIER),
  currentPolicy: communityVaultPolicySchema,
  plan: communityVaultPositionTransferPlanSchema,
  preflight: communityVaultPositionTransferPreflightSchema,
}).strict();

export type CommunityVaultPositionTransferBuyerProviderContextV1 = BaseContextV1;

export const communityVaultPositionTransferBuyerProviderContextSchema:
z.ZodType<CommunityVaultPositionTransferBuyerProviderContextV1> = z.object({
  version: z.literal(1),
  currentPolicy: communityVaultPolicySchema,
  plan: communityVaultPositionTransferPlanSchema,
  preflight: communityVaultPositionTransferPreflightSchema,
}).strict();

export interface CommunityVaultPositionTransferProviderReviewV1 {
  version: 1;
  role: 'buyer' | 'owner';
  campaignId: string;
  inscriptionId: string;
  transferId: string;
  sellerOwnerId: string;
  buyerOwnerId: string;
  buyerCampaignXpub: string;
  units: number[];
  selectedInputIndexes: number[];
  sellerPriceSats: string;
  buyerTotalSats: string;
  settlementFeeSats: string;
  nextVaultAddress: string;
  transferDigest: string;
  expiresAtMs: string;
}

function reviewBase(input: {
  context: BaseContextV1;
  psbtHex: string;
  selectedInputIndexes: readonly number[];
  nowMs: string;
  role: 'buyer' | 'owner';
  ownerId?: string;
}): CommunityVaultPositionTransferProviderReviewV1 {
  assertCommunityVaultPositionTransferPreflight({
    currentPolicy: input.context.currentPolicy,
    plan: input.context.plan,
    preflight: input.context.preflight,
    nowMs: input.nowMs,
  });
  const requireBuyerFunding = input.role === 'owner';
  const validation = validateCommunityVaultPositionTransferPsbt({
    currentPolicy: input.context.currentPolicy,
    plan: input.context.plan,
    psbtHex: input.psbtHex,
    requireBuyerFunding,
  });
  if (validation.signedUnits.length > 0) {
    throw new Error('Community Vault position transfer already contains owner unit signatures');
  }
  const tx = Transaction.fromPSBT(hexToBytes(input.psbtHex), { PSBTVersion: 0, lowR: true });
  const buyerIndexes = input.context.plan.buyerInputs.map((_item, index) => index + 1);
  if (input.role === 'buyer') {
    for (const index of buyerIndexes) {
      if ((tx.getInput(index).finalScriptWitness ?? []).length > 0) {
        throw new Error('Community Vault position buyer input is already authorized');
      }
    }
  } else if (!input.ownerId ||
      !input.context.currentPolicy.owners.some((owner) => owner.ownerId === input.ownerId)) {
    throw new Error('Community Vault position approving owner is absent from the cap table');
  }
  const requested = [...new Set(input.selectedInputIndexes)].sort((left, right) => left - right);
  const expected = input.role === 'buyer' ? buyerIndexes : [input.context.plan.spendPlan.vaultInputIndex];
  if (JSON.stringify(requested) !== JSON.stringify(expected)) {
    throw new Error('Community Vault position transfer signing inputs differ from the exact request');
  }
  return {
    version: 1,
    role: input.role,
    campaignId: input.context.currentPolicy.campaignId,
    inscriptionId: input.context.currentPolicy.inscriptionId,
    transferId: input.context.plan.transferId,
    sellerOwnerId: input.context.plan.sellerOwnerId,
    buyerOwnerId: input.context.plan.buyer.ownerId,
    buyerCampaignXpub: input.context.plan.buyer.campaignRoot.campaignXpub,
    units: [...input.context.plan.transferredUnits],
    selectedInputIndexes: expected,
    sellerPriceSats: input.context.plan.sellerPriceSats,
    buyerTotalSats: input.context.plan.buyerTotalSats,
    settlementFeeSats: input.context.plan.settlementFeeSats,
    nextVaultAddress: input.context.plan.nextPolicy.address,
    transferDigest: input.context.plan.transferDigest,
    expiresAtMs: input.context.plan.spendPlan.expiresAtMs,
  };
}

export function reviewCommunityVaultPositionTransferBuyerProviderRequest(input: {
  context: CommunityVaultPositionTransferBuyerProviderContextV1;
  psbtHex: string;
  selectedInputIndexes: readonly number[];
  nowMs: string;
}): CommunityVaultPositionTransferProviderReviewV1 {
  const context = communityVaultPositionTransferBuyerProviderContextSchema.parse(input.context);
  return reviewBase({ ...input, context, role: 'buyer' });
}

export function reviewCommunityVaultPositionTransferOwnerProviderRequest(input: {
  context: CommunityVaultPositionTransferOwnerProviderContextV1;
  psbtHex: string;
  selectedInputIndexes: readonly number[];
  nowMs: string;
}): CommunityVaultPositionTransferProviderReviewV1 {
  const context = communityVaultPositionTransferOwnerProviderContextSchema.parse(input.context);
  return reviewBase({ ...input, context, role: 'owner', ownerId: context.ownerId });
}
