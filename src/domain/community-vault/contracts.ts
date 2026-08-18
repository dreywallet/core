/**
 * Drey Community Vault v1 public contracts.
 *
 * This family is intentionally separate from the personal Vault contracts. A
 * Community Vault holds one inscription behind one fixed 69-of-100 Taproot
 * script policy; it has no Drey, gallery, recovery, guardian, or key-path key.
 */
import { z } from 'zod';

export const COMMUNITY_VAULT_CONTRACT_VERSION = 1 as const;
export const COMMUNITY_VAULT_POLICY_VERSION = 1 as const;
export const COMMUNITY_VAULT_UNIT_COUNT = 100 as const;
export const COMMUNITY_VAULT_THRESHOLD = 69 as const;
export const COMMUNITY_VAULT_TAPLEAF_VERSION = 0xc0 as const;
export const COMMUNITY_VAULT_SIGHASH = 'default' as const;
export const COMMUNITY_VAULT_NETWORK = 'mainnet' as const;

/** BIP341's hash-of-G NUMS point, also exported by @scure/btc-signer. */
export const COMMUNITY_VAULT_NUMS_INTERNAL_KEY =
  '50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0' as const;

export const COMMUNITY_VAULT_MODES = ['anchored', 'open'] as const;
export type CommunityVaultMode = (typeof COMMUNITY_VAULT_MODES)[number];
export const COMMUNITY_VAULT_ELIGIBILITY = ['anyone', 'omb-holders-only'] as const;
export type CommunityVaultEligibility = (typeof COMMUNITY_VAULT_ELIGIBILITY)[number];

const HEX_32 = /^[0-9a-f]{64}$/u;
const TXID = HEX_32;
const INSCRIPTION_ID = /^[0-9a-f]{64}i(?:0|[1-9][0-9]*)$/u;
const XPUB = /^xpub[1-9A-HJ-NP-Za-km-z]{107}$/u;
const SCRIPT = /^(?:[0-9a-f]{2})+$/u;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;

export interface CommunityVaultCampaignRootV1 {
  version: 1;
  masterFingerprintHex: string;
  /** v1 roots are independent BIP32 master roots, not children of another wallet. */
  originPath: 'm';
  campaignXpub: string;
}

export interface CommunityVaultOwnerInputV1 {
  ownerId: string;
  capTableOrder: number;
  identityCommitmentHex: string;
  payoutAddress: string;
  payoutScriptPubKeyHex: string;
  campaignRoot: CommunityVaultCampaignRootV1;
  units: number[];
}

export interface CommunityVaultUnitV1 {
  unit: number;
  ownerId: string;
  capTableOrder: number;
  masterFingerprintHex: string;
  originPath: 'm';
  campaignXpub: string;
  derivationPath: string;
  publicKeyHex: string;
}

export interface CommunityVaultPolicyInputV1 {
  version: 1;
  policyVersion: 1;
  network: 'mainnet';
  campaignId: string;
  inscriptionId: string;
  currentOutpoint: { txid: string; vout: number };
  mode: CommunityVaultMode;
  eligibility: CommunityVaultEligibility;
  creatorOwnerId: string;
  termsVersion: string;
  capTableVersion: number;
  owners: CommunityVaultOwnerInputV1[];
}

export interface CommunityVaultPolicyV1 extends CommunityVaultPolicyInputV1 {
  unitCount: 100;
  threshold: 69;
  sighash: 'default';
  internalKeyHex: typeof COMMUNITY_VAULT_NUMS_INTERNAL_KEY;
  units: CommunityVaultUnitV1[];
  tapscriptHex: string;
  tapLeafHashHex: string;
  tapMerkleRootHex: string;
  controlBlockHex: string;
  scriptPubKeyHex: string;
  address: string;
  descriptor: string;
  capTableHash: string;
  policyId: string;
}

export interface CommunityVaultRecoveryKitV1 {
  version: 1;
  policyVersion: 1;
  policy: CommunityVaultPolicyV1;
  policyBytesHex: string;
  recoveryInstructions: string;
}

export interface CommunityVaultSpendInputV1 {
  txid: string;
  vout: number;
  valueSats: string;
  scriptPubKeyHex: string;
  sequence: number;
}

export interface CommunityVaultSpendOutputV1 {
  valueSats: string;
  scriptPubKeyHex: string;
}

export interface CommunityVaultOrdinalRouteV1 {
  inscriptionId: string;
  inputIndex: number;
  inputOffsetSats: string;
  outputIndex: number;
  outputOffsetSats: string;
  postageSats: string;
}

export interface CommunityVaultSpendPlanV1 {
  version: 1;
  policyVersion: 1;
  network: 'mainnet';
  policyId: string;
  capTableHash: string;
  capTableVersion: number;
  planId: string;
  kind: 'rotation' | 'sale';
  createdAtMs: string;
  expiresAtMs: string;
  inputs: CommunityVaultSpendInputV1[];
  vaultInputIndex: number;
  outputs: CommunityVaultSpendOutputV1[];
  feeSats: string;
  ordinalRoute: CommunityVaultOrdinalRouteV1;
  unsignedTransactionHex: string;
  planDigest: string;
}

const decimalU64 = z.string().regex(/^(?:0|[1-9][0-9]*)$/u).refine((value) => BigInt(value) <= 0xffff_ffff_ffff_ffffn);
const rootSchema: z.ZodType<CommunityVaultCampaignRootV1> = z.object({
  version: z.literal(1),
  masterFingerprintHex: z.string().regex(/^[0-9a-f]{8}$/u),
  originPath: z.literal('m'),
  campaignXpub: z.string().regex(XPUB),
}).strict();
const ownerSchema: z.ZodType<CommunityVaultOwnerInputV1> = z.object({
  ownerId: z.string().regex(IDENTIFIER),
  capTableOrder: z.number().int().min(0).max(99),
  identityCommitmentHex: z.string().regex(HEX_32),
  payoutAddress: z.string().min(14).max(90),
  payoutScriptPubKeyHex: z.string().regex(SCRIPT).max(20_000),
  campaignRoot: rootSchema,
  units: z.array(z.number().int().min(0).max(99)).min(1).max(33),
}).strict();

export const communityVaultPolicyInputSchema = z.object({
  version: z.literal(1),
  policyVersion: z.literal(1),
  network: z.literal('mainnet'),
  campaignId: z.string().regex(IDENTIFIER),
  inscriptionId: z.string().regex(INSCRIPTION_ID),
  currentOutpoint: z.object({ txid: z.string().regex(TXID), vout: z.number().int().min(0).max(0xffff_ffff) }).strict(),
  mode: z.enum(COMMUNITY_VAULT_MODES),
  eligibility: z.enum(COMMUNITY_VAULT_ELIGIBILITY),
  creatorOwnerId: z.string().regex(IDENTIFIER),
  termsVersion: z.string().regex(IDENTIFIER),
  capTableVersion: z.number().int().min(1).max(0xffff_ffff),
  owners: z.array(ownerSchema).min(4).max(100),
}).strict() satisfies z.ZodType<CommunityVaultPolicyInputV1>;

const unitSchema: z.ZodType<CommunityVaultUnitV1> = z.object({
  unit: z.number().int().min(0).max(99),
  ownerId: z.string().regex(IDENTIFIER),
  capTableOrder: z.number().int().min(0).max(99),
  masterFingerprintHex: z.string().regex(/^[0-9a-f]{8}$/u),
  originPath: z.literal('m'),
  campaignXpub: z.string().regex(XPUB),
  derivationPath: z.string().regex(/^m\/(?:0|[1-9][0-9]?)$/u),
  publicKeyHex: z.string().regex(HEX_32),
}).strict();

export const communityVaultPolicySchema: z.ZodType<CommunityVaultPolicyV1> = communityVaultPolicyInputSchema.extend({
  unitCount: z.literal(100),
  threshold: z.literal(69),
  sighash: z.literal('default'),
  internalKeyHex: z.literal(COMMUNITY_VAULT_NUMS_INTERNAL_KEY),
  units: z.array(unitSchema).length(100),
  tapscriptHex: z.string().regex(SCRIPT).max(20_000),
  tapLeafHashHex: z.string().regex(HEX_32),
  tapMerkleRootHex: z.string().regex(HEX_32),
  controlBlockHex: z.string().regex(SCRIPT).max(300),
  scriptPubKeyHex: z.string().regex(/^[0-9a-f]{68}$/u),
  address: z.string().regex(/^bc1p[ac-hj-np-z02-9]{58}$/u),
  descriptor: z.string().min(100).max(20_000),
  capTableHash: z.string().regex(HEX_32),
  policyId: z.string().regex(HEX_32),
}).strict();

export const communityVaultSpendPlanSchema: z.ZodType<CommunityVaultSpendPlanV1> = z.object({
  version: z.literal(1), policyVersion: z.literal(1), network: z.literal('mainnet'),
  policyId: z.string().regex(HEX_32), capTableHash: z.string().regex(HEX_32),
  capTableVersion: z.number().int().min(1).max(0xffff_ffff),
  planId: z.string().regex(IDENTIFIER), kind: z.enum(['rotation', 'sale']),
  createdAtMs: decimalU64, expiresAtMs: decimalU64,
  inputs: z.array(z.object({
    txid: z.string().regex(TXID), vout: z.number().int().min(0).max(0xffff_ffff),
    valueSats: decimalU64, scriptPubKeyHex: z.string().regex(SCRIPT).max(20_000),
    sequence: z.number().int().min(0).max(0xffff_ffff),
  }).strict()).min(1).max(500),
  vaultInputIndex: z.number().int().min(0).max(499),
  outputs: z.array(z.object({ valueSats: decimalU64, scriptPubKeyHex: z.string().regex(SCRIPT).max(20_000) }).strict()).min(1).max(500),
  feeSats: decimalU64,
  ordinalRoute: z.object({
    inscriptionId: z.string().regex(INSCRIPTION_ID), inputIndex: z.number().int().min(0).max(499),
    inputOffsetSats: decimalU64, outputIndex: z.number().int().min(0).max(499),
    outputOffsetSats: decimalU64, postageSats: decimalU64,
  }).strict(),
  unsignedTransactionHex: z.string().regex(SCRIPT).max(2_000_000),
  planDigest: z.string().regex(HEX_32),
}).strict();

export const COMMUNITY_VAULT_RECOVERY_INSTRUCTIONS =
  'This public kit cannot spend. Recover the exact Community Vault policy from the descriptor, cap table, and all key origins, then use an owner campaign root to derive that owner\'s numbered unit keys. One root may sign only its committed units. Drey and the OMB Gallery have no recovery key. Losing more than 31 unit keys can freeze an Open vault; losing the creator root freezes an Anchored vault because the other 67 units cannot spend.';
