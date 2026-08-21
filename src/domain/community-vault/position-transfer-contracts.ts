/** Private, whole-position Community Vault transfer contracts. */
import { z } from 'zod';
import { communityVaultPolicySchema, communityVaultSpendPlanSchema } from './contracts';
import type {
  CommunityVaultCampaignRootV1,
  CommunityVaultPolicyV1,
  CommunityVaultSpendPlanV1,
} from './contracts';
import type {
  CommunityVaultSaleBuyerInputV1,
  CommunityVaultSalePreflightV1,
} from './sale-contracts';
import { communityVaultSalePreflightSchema } from './sale-contracts';

export const COMMUNITY_VAULT_POSITION_TRANSFER_PROFILE_VERSION = 1 as const;
export const COMMUNITY_VAULT_POSITION_TRANSFER_MAX_LIFETIME_MS = 86_400_000 as const;
export const COMMUNITY_VAULT_POSITION_TRANSFER_MAX_PREFLIGHT_AGE_MS = 120_000 as const;

export interface CommunityVaultPositionTransferBuyerV1 {
  ownerId: string;
  identityCommitmentHex: string;
  payoutAddress: string;
  payoutScriptPubKeyHex: string;
  campaignRoot: CommunityVaultCampaignRootV1;
  qualifyingInscriptionNumber: number | null;
}

export interface CommunityVaultPositionTransferSellerAuthorizationV1 {
  protocol: 'drey-community-vault-position-transfer';
  version: 1;
  network: 'mainnet';
  action: 'authorize-whole-position-transfer';
  transferId: string;
  campaignId: string;
  currentPolicyId: string;
  currentCapTableHash: string;
  currentCapTableVersion: number;
  currentVaultOutpoint: string;
  nextPolicyId: string;
  nextCapTableHash: string;
  nextCapTableVersion: number;
  sellerOwnerId: string;
  buyerOwnerId: string;
  buyerIdentityCommitmentHex: string;
  buyerCampaignXpub: string;
  buyerPayoutAddress: string;
  qualifyingInscriptionNumber: number | null;
  units: number[];
  sellerPriceSats: string;
  expiresAtMs: string;
  nonceHex: string;
}

export interface CommunityVaultPositionTransferPlanV1 {
  version: 1;
  profileVersion: 1;
  policyVersion: 1;
  network: 'mainnet';
  transferId: string;
  currentPolicyId: string;
  currentCapTableHash: string;
  currentCapTableVersion: number;
  nextPolicy: CommunityVaultPolicyV1;
  sellerOwnerId: string;
  buyer: CommunityVaultPositionTransferBuyerV1;
  transferredUnits: number[];
  sellerPriceSats: string;
  settlementFeeSats: string;
  buyerTotalSats: string;
  buyerInputs: CommunityVaultSaleBuyerInputV1[];
  buyerChange: {
    valueSats: string;
    scriptPubKeyHex: string;
    outputIndex: number;
  } | null;
  sellerAuthorization: {
    payload: CommunityVaultPositionTransferSellerAuthorizationV1;
    signature: string;
  };
  spendPlan: CommunityVaultSpendPlanV1;
  transferDigest: string;
}

export interface CommunityVaultPositionTransferDraftV1 {
  currentPolicy: CommunityVaultPolicyV1;
  nextPolicy: CommunityVaultPolicyV1;
  transferId: string;
  vaultOutpoint: { txid: string; vout: number };
  vaultValueSats: string;
  inscriptionInputOffsetSats: string;
  postageSats: string;
  sellerOwnerId: string;
  buyer: CommunityVaultPositionTransferBuyerV1;
  sellerPriceSats: string;
  settlementFeeSats: string;
  buyerInputs: CommunityVaultSaleBuyerInputV1[];
  buyerChange: { valueSats: string; scriptPubKeyHex: string } | null;
  createdAtMs: string;
  expiresAtMs: string;
  sellerAuthorization: {
    payload: CommunityVaultPositionTransferSellerAuthorizationV1;
    signature: string;
  };
}

export type CommunityVaultPositionTransferPreflightV1 = CommunityVaultSalePreflightV1;

const HEX_32 = /^[0-9a-f]{64}$/u;
const TXID = HEX_32;
const SCRIPT = /^(?:[0-9a-f]{2})+$/u;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const XPUB = /^xpub[1-9A-HJ-NP-Za-km-z]{107}$/u;
const decimalU64 = z.string().regex(/^(?:0|[1-9][0-9]*)$/u)
  .refine((value) => BigInt(value) <= 0xffff_ffff_ffff_ffffn);

const rootSchema: z.ZodType<CommunityVaultCampaignRootV1> = z.object({
  version: z.literal(1),
  masterFingerprintHex: z.string().regex(/^[0-9a-f]{8}$/u),
  originPath: z.literal('m'),
  campaignXpub: z.string().regex(XPUB),
}).strict();

const buyerSchema: z.ZodType<CommunityVaultPositionTransferBuyerV1> = z.object({
  ownerId: z.string().regex(IDENTIFIER),
  identityCommitmentHex: z.string().regex(HEX_32),
  payoutAddress: z.string().min(14).max(90),
  payoutScriptPubKeyHex: z.string().regex(SCRIPT).max(20_000),
  campaignRoot: rootSchema,
  qualifyingInscriptionNumber: z.number().int().positive().nullable(),
}).strict();

export const communityVaultPositionTransferSellerAuthorizationSchema:
z.ZodType<CommunityVaultPositionTransferSellerAuthorizationV1> = z.object({
  protocol: z.literal('drey-community-vault-position-transfer'),
  version: z.literal(1),
  network: z.literal('mainnet'),
  action: z.literal('authorize-whole-position-transfer'),
  transferId: z.string().regex(IDENTIFIER),
  campaignId: z.string().regex(IDENTIFIER),
  currentPolicyId: z.string().regex(HEX_32),
  currentCapTableHash: z.string().regex(HEX_32),
  currentCapTableVersion: z.number().int().min(1).max(0xffff_ffff),
  currentVaultOutpoint: z.string().regex(/^[0-9a-f]{64}:(?:0|[1-9][0-9]*)$/u),
  nextPolicyId: z.string().regex(HEX_32),
  nextCapTableHash: z.string().regex(HEX_32),
  nextCapTableVersion: z.number().int().min(2).max(0xffff_ffff),
  sellerOwnerId: z.string().regex(IDENTIFIER),
  buyerOwnerId: z.string().regex(IDENTIFIER),
  buyerIdentityCommitmentHex: z.string().regex(HEX_32),
  buyerCampaignXpub: z.string().regex(XPUB),
  buyerPayoutAddress: z.string().min(14).max(90),
  qualifyingInscriptionNumber: z.number().int().positive().nullable(),
  units: z.array(z.number().int().min(0).max(99)).min(1).max(20),
  sellerPriceSats: decimalU64,
  expiresAtMs: decimalU64,
  nonceHex: z.string().regex(HEX_32),
}).strict();

const buyerInputSchema = z.object({
  txid: z.string().regex(TXID),
  vout: z.number().int().min(0).max(0xffff_ffff),
  valueSats: decimalU64,
  scriptPubKeyHex: z.string().regex(SCRIPT).max(20_000),
  sequence: z.number().int().min(0).max(0xffff_ffff),
  scriptKind: z.enum(['p2wpkh', 'p2tr']),
  sighashType: z.union([z.literal(0), z.literal(1)]),
}).strict();

export const communityVaultPositionTransferPlanSchema:
z.ZodType<CommunityVaultPositionTransferPlanV1> = z.object({
  version: z.literal(1),
  profileVersion: z.literal(1),
  policyVersion: z.literal(1),
  network: z.literal('mainnet'),
  transferId: z.string().regex(IDENTIFIER),
  currentPolicyId: z.string().regex(HEX_32),
  currentCapTableHash: z.string().regex(HEX_32),
  currentCapTableVersion: z.number().int().min(1).max(0xffff_ffff),
  nextPolicy: communityVaultPolicySchema,
  sellerOwnerId: z.string().regex(IDENTIFIER),
  buyer: buyerSchema,
  transferredUnits: z.array(z.number().int().min(0).max(99)).min(1).max(20),
  sellerPriceSats: decimalU64,
  settlementFeeSats: decimalU64,
  buyerTotalSats: decimalU64,
  buyerInputs: z.array(buyerInputSchema).min(1).max(499),
  buyerChange: z.object({
    valueSats: decimalU64,
    scriptPubKeyHex: z.string().regex(SCRIPT).max(20_000),
    outputIndex: z.number().int().min(2).max(499),
  }).strict().nullable(),
  sellerAuthorization: z.object({
    payload: communityVaultPositionTransferSellerAuthorizationSchema,
    signature: z.string().min(4).max(20_000),
  }).strict(),
  spendPlan: communityVaultSpendPlanSchema,
  transferDigest: z.string().regex(HEX_32),
}).strict();

export const communityVaultPositionTransferPreflightSchema = communityVaultSalePreflightSchema;
