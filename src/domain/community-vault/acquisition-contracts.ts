/** Community Vault v1 listed and creator-fronted acquisition contracts. */
import { z } from 'zod';
import {
  COMMUNITY_VAULT_NETWORK,
  type CommunityVaultPolicyV1,
} from './contracts';

export const COMMUNITY_VAULT_ACQUISITION_PROFILE_VERSION = 1 as const;
export const COMMUNITY_VAULT_MAX_PREFLIGHT_AGE_MS = 120_000 as const;
export const COMMUNITY_VAULT_FRONTED_OPEN_WINDOW_MS = 86_400_000 as const;

export type CommunityVaultAcquisitionSource = 'listed' | 'creator-fronted';
export type CommunityVaultInputScriptKind = 'p2wpkh' | 'p2tr';

export interface CommunityVaultAcquisitionInputV1 {
  txid: string;
  vout: number;
  valueSats: string;
  scriptPubKeyHex: string;
  sequence: number;
  scriptKind: CommunityVaultInputScriptKind;
  role: 'inscription' | 'owner-funding';
  ownerId: string | null;
  /** Exact signature hash byte; Taproot DEFAULT is represented as 0. */
  sighashType: number;
}

export type CommunityVaultAcquisitionOutputRole =
  | 'vault'
  | 'seller-payment'
  | 'marketplace-fee'
  | 'creator-reimbursement'
  | 'owner-change';

export interface CommunityVaultAcquisitionOutputV1 {
  valueSats: string;
  scriptPubKeyHex: string;
  role: CommunityVaultAcquisitionOutputRole;
  ownerId: string | null;
  recipientId: string | null;
}

export interface CommunityVaultOwnerObligationV1 {
  ownerId: string;
  capTableOrder: number;
  units: number[];
  assetCostShareSats: string;
  settlementFeeShareSats: string;
  cashDueSats: string;
  fundingInputSats: string;
  changeSats: string;
}

export interface CommunityVaultListedTermsV1 {
  marketplaceId: string;
  listingId: string;
  listingFingerprintHex: string;
  observedAtMs: string;
  listingExpiresAtMs: string;
  sellerPaymentSats: string;
  sellerPayoutScriptPubKeyHex: string;
  maximumLandedCostSats: string;
}

export interface CommunityVaultFrontedTermsV1 {
  purchaseTxid: string;
  purchaseConfirmedAtMs: string;
  campaignOpenedAtMs: string;
  sellerPriceSats: string;
  marketplaceFeeSats: string;
  purchaseMinerFeeSats: string;
  requiredPostageSats: string;
  rebatesSats: string;
  refundsSats: string;
  verifiedLandedCostSats: string;
  creatorReimbursementSats: string;
}

export interface CommunityVaultAcquisitionPlanV1 {
  version: 1;
  profileVersion: 1;
  policyVersion: 1;
  network: typeof COMMUNITY_VAULT_NETWORK;
  source: CommunityVaultAcquisitionSource;
  campaignId: string;
  policyId: string;
  capTableHash: string;
  capTableVersion: number;
  inscriptionId: string;
  planId: string;
  createdAtMs: string;
  expiresAtMs: string;
  assetInputIndex: number;
  vaultOutputIndex: number;
  inscriptionInputOffsetSats: string;
  inscriptionOutputOffsetSats: string;
  postageSats: string;
  assetCostSats: string;
  settlementFeeSats: string;
  totalEconomicCostSats: string;
  inputs: CommunityVaultAcquisitionInputV1[];
  outputs: CommunityVaultAcquisitionOutputV1[];
  ownerObligations: CommunityVaultOwnerObligationV1[];
  listedTerms: CommunityVaultListedTermsV1 | null;
  frontedTerms: CommunityVaultFrontedTermsV1 | null;
  unsignedTransactionHex: string;
  planDigest: string;
}

export interface CommunityVaultAcquisitionInputEvidenceV1 {
  inputIndex: number;
  txid: string;
  vout: number;
  valueSats: string;
  scriptPubKeyHex: string;
  unspent: boolean;
  inscriptionIds: string[];
  runeIds: string[];
}

export interface CommunityVaultAcquisitionPreflightV1 {
  version: 1;
  network: 'mainnet';
  source: 'ord';
  verifiedAtMs: string;
  blockHeight: number;
  blockHash: string;
  inputs: CommunityVaultAcquisitionInputEvidenceV1[];
  listing: {
    marketplaceId: string;
    listingId: string;
    listingFingerprintHex: string;
    active: boolean;
    observedAtMs: string;
  } | null;
}

const HEX_32 = /^[0-9a-f]{64}$/u;
const TXID = HEX_32;
const INSCRIPTION_ID = /^[0-9a-f]{64}i(?:0|[1-9][0-9]*)$/u;
const SCRIPT = /^(?:[0-9a-f]{2})+$/u;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const decimalU64 = z.string().regex(/^(?:0|[1-9][0-9]*)$/u)
  .refine((value) => BigInt(value) <= 0xffff_ffff_ffff_ffffn);

const acquisitionInputSchema: z.ZodType<CommunityVaultAcquisitionInputV1> = z.object({
  txid: z.string().regex(TXID),
  vout: z.number().int().min(0).max(0xffff_ffff),
  valueSats: decimalU64,
  scriptPubKeyHex: z.string().regex(SCRIPT).max(20_000),
  sequence: z.number().int().min(0).max(0xffff_ffff),
  scriptKind: z.enum(['p2wpkh', 'p2tr']),
  role: z.enum(['inscription', 'owner-funding']),
  ownerId: z.string().regex(IDENTIFIER).nullable(),
  sighashType: z.number().int().min(0).max(255),
}).strict();

const acquisitionOutputSchema: z.ZodType<CommunityVaultAcquisitionOutputV1> = z.object({
  valueSats: decimalU64,
  scriptPubKeyHex: z.string().regex(SCRIPT).max(20_000),
  role: z.enum(['vault', 'seller-payment', 'marketplace-fee', 'creator-reimbursement', 'owner-change']),
  ownerId: z.string().regex(IDENTIFIER).nullable(),
  recipientId: z.string().regex(IDENTIFIER).nullable(),
}).strict();

const ownerObligationSchema: z.ZodType<CommunityVaultOwnerObligationV1> = z.object({
  ownerId: z.string().regex(IDENTIFIER),
  capTableOrder: z.number().int().min(0).max(99),
  units: z.array(z.number().int().min(0).max(99)).min(1).max(33),
  assetCostShareSats: decimalU64,
  settlementFeeShareSats: decimalU64,
  cashDueSats: decimalU64,
  fundingInputSats: decimalU64,
  changeSats: decimalU64,
}).strict();

const listedTermsSchema: z.ZodType<CommunityVaultListedTermsV1> = z.object({
  marketplaceId: z.string().regex(IDENTIFIER),
  listingId: z.string().regex(IDENTIFIER),
  listingFingerprintHex: z.string().regex(HEX_32),
  observedAtMs: decimalU64,
  listingExpiresAtMs: decimalU64,
  sellerPaymentSats: decimalU64,
  sellerPayoutScriptPubKeyHex: z.string().regex(SCRIPT).max(20_000),
  maximumLandedCostSats: decimalU64,
}).strict();

const frontedTermsSchema: z.ZodType<CommunityVaultFrontedTermsV1> = z.object({
  purchaseTxid: z.string().regex(TXID),
  purchaseConfirmedAtMs: decimalU64,
  campaignOpenedAtMs: decimalU64,
  sellerPriceSats: decimalU64,
  marketplaceFeeSats: decimalU64,
  purchaseMinerFeeSats: decimalU64,
  requiredPostageSats: decimalU64,
  rebatesSats: decimalU64,
  refundsSats: decimalU64,
  verifiedLandedCostSats: decimalU64,
  creatorReimbursementSats: decimalU64,
}).strict();

export const communityVaultAcquisitionPlanSchema: z.ZodType<CommunityVaultAcquisitionPlanV1> = z.object({
  version: z.literal(1),
  profileVersion: z.literal(1),
  policyVersion: z.literal(1),
  network: z.literal('mainnet'),
  source: z.enum(['listed', 'creator-fronted']),
  campaignId: z.string().regex(IDENTIFIER),
  policyId: z.string().regex(HEX_32),
  capTableHash: z.string().regex(HEX_32),
  capTableVersion: z.number().int().min(1).max(0xffff_ffff),
  inscriptionId: z.string().regex(INSCRIPTION_ID),
  planId: z.string().regex(IDENTIFIER),
  createdAtMs: decimalU64,
  expiresAtMs: decimalU64,
  assetInputIndex: z.number().int().min(0).max(499),
  vaultOutputIndex: z.number().int().min(0).max(499),
  inscriptionInputOffsetSats: decimalU64,
  inscriptionOutputOffsetSats: decimalU64,
  postageSats: decimalU64,
  assetCostSats: decimalU64,
  settlementFeeSats: decimalU64,
  totalEconomicCostSats: decimalU64,
  inputs: z.array(acquisitionInputSchema).min(2).max(500),
  outputs: z.array(acquisitionOutputSchema).min(2).max(500),
  ownerObligations: z.array(ownerObligationSchema).min(4).max(100),
  listedTerms: listedTermsSchema.nullable(),
  frontedTerms: frontedTermsSchema.nullable(),
  unsignedTransactionHex: z.string().regex(SCRIPT).max(2_000_000),
  planDigest: z.string().regex(HEX_32),
}).strict();

const inputEvidenceSchema: z.ZodType<CommunityVaultAcquisitionInputEvidenceV1> = z.object({
  inputIndex: z.number().int().min(0).max(499),
  txid: z.string().regex(TXID),
  vout: z.number().int().min(0).max(0xffff_ffff),
  valueSats: decimalU64,
  scriptPubKeyHex: z.string().regex(SCRIPT).max(20_000),
  unspent: z.boolean(),
  inscriptionIds: z.array(z.string().regex(INSCRIPTION_ID)).max(100),
  runeIds: z.array(z.string().regex(IDENTIFIER)).max(100),
}).strict();

export const communityVaultAcquisitionPreflightSchema: z.ZodType<CommunityVaultAcquisitionPreflightV1> = z.object({
  version: z.literal(1),
  network: z.literal('mainnet'),
  source: z.literal('ord'),
  verifiedAtMs: decimalU64,
  blockHeight: z.number().int().positive(),
  blockHash: z.string().regex(HEX_32),
  inputs: z.array(inputEvidenceSchema).min(2).max(500),
  listing: z.object({
    marketplaceId: z.string().regex(IDENTIFIER),
    listingId: z.string().regex(IDENTIFIER),
    listingFingerprintHex: z.string().regex(HEX_32),
    active: z.boolean(),
    observedAtMs: decimalU64,
  }).strict().nullable(),
}).strict();

export interface CommunityVaultAcquisitionDraftBaseV1 {
  policy: CommunityVaultPolicyV1;
  planId: string;
  createdAtMs: string;
  expiresAtMs: string;
  inputs: CommunityVaultAcquisitionInputV1[];
  outputs: CommunityVaultAcquisitionOutputV1[];
  assetInputIndex: number;
  vaultOutputIndex: number;
  inscriptionInputOffsetSats: string;
  inscriptionOutputOffsetSats: string;
  postageSats: string;
  settlementFeeSats: string;
}

export interface CommunityVaultListedAcquisitionDraftV1 extends CommunityVaultAcquisitionDraftBaseV1 {
  listedTerms: CommunityVaultListedTermsV1;
}

export interface CommunityVaultFrontedAcquisitionDraftV1 extends CommunityVaultAcquisitionDraftBaseV1 {
  frontedTerms: Omit<CommunityVaultFrontedTermsV1, 'creatorReimbursementSats'>;
}
