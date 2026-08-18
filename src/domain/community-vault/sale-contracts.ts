/** Exact-funded Community Vault v1 sale contracts. */
import { z } from 'zod';
import {
  communityVaultSpendPlanSchema,
  type CommunityVaultSpendInputV1,
  type CommunityVaultSpendPlanV1,
} from './contracts';

export const COMMUNITY_VAULT_SALE_PROFILE_VERSION = 1 as const;
export const COMMUNITY_VAULT_SALE_BUYER_PAYS_FEE = true as const;
export const COMMUNITY_VAULT_SALE_MAX_PREFLIGHT_AGE_MS = 120_000 as const;

export interface CommunityVaultSaleBuyerInputV1 extends CommunityVaultSpendInputV1 {
  scriptKind: 'p2wpkh' | 'p2tr';
  sighashType: 0 | 1;
}

export interface CommunityVaultSaleOwnerPayoutV1 {
  ownerId: string;
  capTableOrder: number;
  units: number;
  payoutAddress: string;
  payoutScriptPubKeyHex: string;
  valueSats: string;
  outputIndex: number;
}

export interface CommunityVaultSalePlanV1 {
  version: 1;
  profileVersion: 1;
  policyVersion: 1;
  network: 'mainnet';
  campaignId: string;
  policyId: string;
  capTableHash: string;
  capTableVersion: number;
  inscriptionId: string;
  offerId: string;
  buyerId: string;
  nonceHex: string;
  createdAtMs: string;
  expiresAtMs: string;
  grossOfferSats: string;
  buyerPaysFee: true;
  settlementFeeSats: string;
  buyerTotalSats: string;
  buyerDestinationAddress: string;
  buyerDestinationScriptPubKeyHex: string;
  buyerInputs: CommunityVaultSaleBuyerInputV1[];
  buyerChange: {
    valueSats: string;
    scriptPubKeyHex: string;
    outputIndex: number;
  } | null;
  ownerPayouts: CommunityVaultSaleOwnerPayoutV1[];
  payoutSnapshotHash: string;
  spendPlan: CommunityVaultSpendPlanV1;
  offerDigest: string;
}

export interface CommunityVaultSaleInputEvidenceV1 {
  inputIndex: number;
  txid: string;
  vout: number;
  valueSats: string;
  scriptPubKeyHex: string;
  unspent: boolean;
  inscriptionIds: string[];
  runeIds: string[];
}

export interface CommunityVaultSalePreflightV1 {
  version: 1;
  network: 'mainnet';
  source: 'ord';
  verifiedAtMs: string;
  blockHeight: number;
  blockHash: string;
  inputs: CommunityVaultSaleInputEvidenceV1[];
}

const HEX_32 = /^[0-9a-f]{64}$/u;
const TXID = HEX_32;
const INSCRIPTION_ID = /^[0-9a-f]{64}i(?:0|[1-9][0-9]*)$/u;
const SCRIPT = /^(?:[0-9a-f]{2})+$/u;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const decimalU64 = z.string().regex(/^(?:0|[1-9][0-9]*)$/u)
  .refine((value) => BigInt(value) <= 0xffff_ffff_ffff_ffffn);

const buyerInputSchema: z.ZodType<CommunityVaultSaleBuyerInputV1> = z.object({
  txid: z.string().regex(TXID),
  vout: z.number().int().min(0).max(0xffff_ffff),
  valueSats: decimalU64,
  scriptPubKeyHex: z.string().regex(SCRIPT).max(20_000),
  sequence: z.number().int().min(0).max(0xffff_ffff),
  scriptKind: z.enum(['p2wpkh', 'p2tr']),
  sighashType: z.union([z.literal(0), z.literal(1)]),
}).strict();

const ownerPayoutSchema: z.ZodType<CommunityVaultSaleOwnerPayoutV1> = z.object({
  ownerId: z.string().regex(IDENTIFIER),
  capTableOrder: z.number().int().min(0).max(99),
  units: z.number().int().min(1).max(33),
  payoutAddress: z.string().min(14).max(90),
  payoutScriptPubKeyHex: z.string().regex(SCRIPT).max(20_000),
  valueSats: decimalU64,
  outputIndex: z.number().int().min(1).max(499),
}).strict();

export const communityVaultSalePlanSchema: z.ZodType<CommunityVaultSalePlanV1> = z.object({
  version: z.literal(1),
  profileVersion: z.literal(1),
  policyVersion: z.literal(1),
  network: z.literal('mainnet'),
  campaignId: z.string().regex(IDENTIFIER),
  policyId: z.string().regex(HEX_32),
  capTableHash: z.string().regex(HEX_32),
  capTableVersion: z.number().int().min(1).max(0xffff_ffff),
  inscriptionId: z.string().regex(INSCRIPTION_ID),
  offerId: z.string().regex(HEX_32),
  buyerId: z.string().regex(IDENTIFIER),
  nonceHex: z.string().regex(HEX_32),
  createdAtMs: decimalU64,
  expiresAtMs: decimalU64,
  grossOfferSats: decimalU64,
  buyerPaysFee: z.literal(true),
  settlementFeeSats: decimalU64,
  buyerTotalSats: decimalU64,
  buyerDestinationAddress: z.string().min(14).max(90),
  buyerDestinationScriptPubKeyHex: z.string().regex(SCRIPT).max(20_000),
  buyerInputs: z.array(buyerInputSchema).min(1).max(499),
  buyerChange: z.object({
    valueSats: decimalU64,
    scriptPubKeyHex: z.string().regex(SCRIPT).max(20_000),
    outputIndex: z.number().int().min(1).max(499),
  }).strict().nullable(),
  ownerPayouts: z.array(ownerPayoutSchema).min(4).max(100),
  payoutSnapshotHash: z.string().regex(HEX_32),
  spendPlan: communityVaultSpendPlanSchema,
  offerDigest: z.string().regex(HEX_32),
}).strict();

const evidenceSchema: z.ZodType<CommunityVaultSaleInputEvidenceV1> = z.object({
  inputIndex: z.number().int().min(0).max(499),
  txid: z.string().regex(TXID),
  vout: z.number().int().min(0).max(0xffff_ffff),
  valueSats: decimalU64,
  scriptPubKeyHex: z.string().regex(SCRIPT).max(20_000),
  unspent: z.boolean(),
  inscriptionIds: z.array(z.string().regex(INSCRIPTION_ID)).max(100),
  runeIds: z.array(z.string().regex(IDENTIFIER)).max(100),
}).strict();

export const communityVaultSalePreflightSchema: z.ZodType<CommunityVaultSalePreflightV1> = z.object({
  version: z.literal(1),
  network: z.literal('mainnet'),
  source: z.literal('ord'),
  verifiedAtMs: decimalU64,
  blockHeight: z.number().int().positive(),
  blockHash: z.string().regex(HEX_32),
  inputs: z.array(evidenceSchema).min(2).max(500),
}).strict();

export interface CommunityVaultSaleDraftV1 {
  policy: import('./contracts').CommunityVaultPolicyV1;
  vaultOutpoint: { txid: string; vout: number };
  offerId: string;
  buyerId: string;
  nonceHex: string;
  createdAtMs: string;
  expiresAtMs: string;
  vaultValueSats: string;
  inscriptionInputOffsetSats: string;
  postageSats: string;
  grossOfferSats: string;
  settlementFeeSats: string;
  buyerDestinationAddress: string;
  buyerDestinationScriptPubKeyHex: string;
  buyerInputs: CommunityVaultSaleBuyerInputV1[];
  buyerChange: { valueSats: string; scriptPubKeyHex: string } | null;
}
