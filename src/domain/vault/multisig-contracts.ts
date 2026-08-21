/**
 * ADR 0007 Workstream B0 public contracts.
 *
 * These records are deliberately role-agnostic and transport-neutral. They
 * describe public data and approval bindings only: no secret root, xprv,
 * mnemonic, passkey material, browser/native API, relay, or coordinator lives
 * here. Version 1 is the closed native-P2WSH 2-of-3 policy; adding a role,
 * network, sighash, policy, or signing-meaning field requires a new accepted
 * contract version and new vectors.
 *
 * Integer values that may exceed JavaScript's safe-integer range use canonical
 * unsigned decimal strings. Byte values use lowercase, even-length hex. The
 * binary codec in multisig-encoding.ts is the normative representation used by
 * policyId and planDigest; these object shapes are never JSON-hashed.
 */
import { HDKey } from '@scure/bip32';
import { z } from 'zod';
import type { Network } from '../keys/derivation';
import { descriptorChecksum } from '../keys/descriptor-checksum';
import { bip32Versions } from '../keys/extended-key';
export { descriptorChecksum } from '../keys/descriptor-checksum';
export { bip32Versions } from '../keys/extended-key';
import { decimalU64Schema } from './u64';

export const VAULT_CONTRACT_VERSION = 1 as const;
export const VAULT_POLICY_VERSION = 1 as const;
export const VAULT_THRESHOLD = 2 as const;
export const VAULT_SIGNER_COUNT = 3 as const;
export const VAULT_SIGHASH = 'all' as const;

/**
 * The prose a v1 public recovery kit carries (ADR 0007 §6).
 *
 * This lives in core rather than beside the coordinator that mints kits because
 * three separate programs must agree on it byte for byte: the extension that
 * writes a kit, the standalone recovery package that reads one, and the golden
 * vectors that pin the format. Prose duplicated across repositories drifts on
 * the first copy-edit, and a kit whose compatibility requirements no longer
 * describe the reader that must open it is worse than one with none.
 *
 * Treat any change here as a format change: it alters the bytes of every kit
 * minted afterwards, so it needs a vector regeneration and a reader that still
 * accepts kits written before it.
 */
export const VAULT_RECOVERY_KIT_TEXT_V1 = Object.freeze({
  compatibilityRequirements: Object.freeze([
    'Drey Vault policy version 1: native SegWit P2WSH wsh(sortedmulti(2,...)) over three BIP48 m/48h/coin_typeh/0h/2h origins.',
    'Spending requires two distinct logical roles; two copies of one role are one vote.',
    'SIGHASH_ALL only. No Taproot multisig, Miniscript, P2SH wrapper, or flexible sighash.',
    'Readable by any BIP380/BIP383 descriptor wallet; cross-checked against Bitcoin Core 30.x getdescriptorinfo and deriveaddresses.',
    'Moving an inscription-bearing UTXO additionally requires a current, independently operated Ordinals data source.',
  ] as readonly string[]),
  recoveryInstructions:
    'This kit cannot spend. It is the public description of a 2-of-3 Vault. Keep a durable copy: losing every copy can prevent recovery even if two role backups survive. Sharing it reveals every Vault address. ' +
    'To recover, import either descriptor into a descriptor-capable wallet to see the funds, then supply any two of the three roles — Desktop A, Mobile B, or the offline Recovery Key C — to sign. ' +
    'The Recovery Key words are NOT the Spending Recovery Phrase and cannot spend on their own. ' +
    'Store this kit separately from the Recovery Key: together they are two of the three things an attacker would need.',
  rotationInstructions:
    'Deleting a device, wiping an app, or removing a role from this coordinator is not revocation — the on-chain policy is unchanged and the old keys still sign. ' +
    'If a role is lost or believed compromised, generate a new independent root, create a new policy with a new policyId, and move the funds on chain to the new Vault. ' +
    'A funded policy is never edited in place.',
} as const);

export const VAULT_ROLES = ['desktop-a', 'mobile-b', 'recovery-c'] as const;
export type VaultSignerRole = (typeof VAULT_ROLES)[number];
export type VaultBranch = 'receive' | 'change';

export interface VaultSignerOriginV1 {
  version: 1;
  role: VaultSignerRole;
  network: Network;
  masterFingerprintHex: string;
  originPath: string;
  accountXpub: string;
}

export interface VaultProofOfPossessionInputV1 {
  version: 1;
  origin: VaultSignerOriginV1;
  sessionIdHex: string;
  challengeNonceHex: string;
  transcriptHashHex: string;
  expiresAtMs: string;
}

export interface VaultProofOfPossessionResultV1 {
  version: 1;
  role: VaultSignerRole;
  inputDigestHex: string;
  /** Compressed public key at account-xpub child /0/0. */
  proofPublicKeyHex: string;
  /** 64-byte compact, low-S secp256k1 ECDSA signature over inputDigest. */
  signatureHex: string;
  scheme: 'secp256k1-ecdsa-compact-low-s-v1';
}

/**
 * Public request carried from the coordinator to the offline Recovery C tool.
 * It deliberately cannot contain C's origin: that origin does not exist until
 * the offline ceremony has generated and confirmed the paper words.
 */
export interface RecoveryCSetupChallengeV1 {
  version: 1;
  role: 'recovery-c';
  network: Network;
  sessionIdHex: string;
  challengeNonceHex: string;
  transcriptHashHex: string;
  desktopOrigin: VaultSignerOriginV1 & { role: 'desktop-a' };
  createdAtMs: string;
  expiresAtMs: string;
}

/** Only public origin and proof bytes return from the offline generation. */
export interface RecoveryCSetupResponseV1 {
  version: 1;
  challengeDigestHex: string;
  origin: VaultSignerOriginV1 & { role: 'recovery-c' };
  proof: VaultProofOfPossessionResultV1 & { role: 'recovery-c' };
}

/**
 * Fresh challenge used after policy creation to prove that the words written
 * on paper recreate the exact C committed by the exported public kit.
 */
export interface RecoveryCBackupCheckChallengeV1 {
  version: 1;
  role: 'recovery-c';
  network: Network;
  policyId: string;
  recoveryOrigin: VaultSignerOriginV1 & { role: 'recovery-c' };
  sessionIdHex: string;
  challengeNonceHex: string;
  standaloneToolVersion: string;
  standaloneToolSourceDigest: string;
  standaloneToolArtifactDigest: string;
  createdAtMs: string;
  expiresAtMs: string;
}

/** A domain-separated signature from Recovery C; never a mnemonic receipt. */
export interface RecoveryCBackupCheckResponseV1 {
  version: 1;
  network: Network;
  policyId: string;
  challengeDigestHex: string;
  proofPublicKeyHex: string;
  signatureHex: string;
  scheme: 'recovery-c-backup-check-secp256k1-ecdsa-compact-low-s-v1';
}

export interface VaultPolicyIdentityV1 {
  version: 1;
  policyVersion: 1;
  network: Network;
  threshold: 2;
  signers: [VaultSignerOriginV1, VaultSignerOriginV1, VaultSignerOriginV1];
  receiveDescriptor: string;
  changeDescriptor: string;
  policyId: string;
}

export interface VaultPolicyMetadataV1 {
  version: 1;
  createdAtMs: string;
  birthdayHeight: number | null;
  vaultLabel: string;
  signerLabels: [string, string, string];
}

export interface VaultPolicyRecordV1 {
  version: 1;
  identity: VaultPolicyIdentityV1;
  metadata: VaultPolicyMetadataV1;
}

export interface VaultBranchDerivationV1 {
  version: 1;
  network: Network;
  policyId: string;
  branch: VaultBranch;
  index: number;
}

export type VaultPlanKind = 'withdrawal' | 'recovery' | 'rotation';
export type VaultOutputPurpose = 'paired-spending' | 'vault-change' | 'vault-rotation' | 'recovery-exit';
export type VaultAssetKind = 'cardinal' | 'inscription';

export interface VaultPlanInputV1 {
  txid: string;
  vout: number;
  valueSats: string;
  scriptPubKeyHex: string;
  witnessScriptHex: string;
  branch: VaultBranch;
  derivationIndex: number;
  sequence: number;
  sighash: 'all';
  classification: 'cardinal_clean' | 'inscribed' | 'rare_sat' | 'runic_or_unsupported' | 'mixed' | 'unknown';
  classificationEvidenceHash: string;
}

export interface VaultPlanOutputV1 {
  outputIndex: number;
  valueSats: string;
  scriptPubKeyHex: string;
  address: string;
  purpose: VaultOutputPurpose;
  branch: VaultBranch | null;
  derivationIndex: number | null;
}

export interface VaultAssetEffectV1 {
  kind: VaultAssetKind;
  assetId: string;
  inputIndex: number;
  inputOffsetSats: string;
  outputIndex: number;
  outputOffsetSats: string;
  postageSats: string;
  protected: boolean;
}

export interface VaultPlanSourceV1 {
  backendInstanceIdHash: string;
  classificationRevisionHash: string;
  coreTip: { height: number; hash: string };
  indexTip: { height: number; hash: string };
  observedAtMs: string;
  validUntilMs: string;
}

export interface VaultUnsignedPlanV1 {
  version: 1;
  policyVersion: 1;
  network: Network;
  policyId: string;
  planId: string;
  requestId: string;
  createdAtMs: string;
  expiresAtMs: string;
  kind: VaultPlanKind;
  unsignedTransactionHex: string;
  inputs: VaultPlanInputV1[];
  outputs: VaultPlanOutputV1[];
  destination: {
    kind: 'paired-spending' | 'vault-policy' | 'recovery-exit';
    pairedSpendingWalletIdHash: string | null;
    targetPolicyId: string | null;
    address: string;
    outputIndex: number;
  };
  amountSats: string;
  changeSats: string;
  feeSats: string;
  /** Conservative finalized native-P2WSH virtual-size upper bound. */
  vsize: number;
  feeRateSatPerKvB: string;
  sighash: 'all';
  assetEffects: VaultAssetEffectV1[];
  source: VaultPlanSourceV1;
  replacement: {
    kind: 'none' | 'rbf' | 'cpfp';
    replacesTxid: string | null;
    parentTxid: string | null;
  };
  broadcastIntent: 'broadcast' | 'return-psbt';
  planDigest: string;
}

export interface VaultPartialSignatureInputV1 {
  version: 1;
  network: Network;
  policyId: string;
  planId: string;
  planDigest: string;
  role: VaultSignerRole;
  canonicalPlanHex: string;
  psbtHex: string;
  psbtHash: string;
}

export interface VaultPartialSignatureResultV1 {
  version: 1;
  network: Network;
  policyId: string;
  planId: string;
  planDigest: string;
  roleAdded: VaultSignerRole;
  priorPsbtHash: string;
  signedPsbtHex: string;
  signedPsbtHash: string;
}

export interface VaultRecoveryKitV1 {
  version: 1;
  network: Network;
  policyVersion: 1;
  policyId: string;
  signers: [VaultSignerOriginV1, VaultSignerOriginV1, VaultSignerOriginV1];
  receiveDescriptor: string;
  changeDescriptor: string;
  createdAtMs: string;
  birthdayHeight: number | null;
  vaultLabel: string;
  signerLabels: [string, string, string];
  firstReceiveAddress: string;
  compatibilityRequirements: string[];
  minimumReaderVersion: 1;
  standaloneToolSourceDigest: string;
  standaloneToolArtifactDigest: string;
  recoveryInstructions: string;
  rotationInstructions: string;
  recoveryInstructionsVersion: 1;
}

export type VaultPairingMessageType = 'signer-origin' | 'pop-input' | 'pop-result' | 'policy';

export interface VaultPairingEnvelopeV1 {
  version: 1;
  network: Network;
  sessionIdHex: string;
  /** Canonical public sender origin, authenticated by this same envelope. */
  senderOriginHex: string;
  senderChannelIdHex: string;
  recipientChannelIdHex: string;
  counter: string;
  createdAtMs: string;
  expiresAtMs: string;
  antiReplayNonceHex: string;
  transcriptHashHex: string;
  messageType: VaultPairingMessageType;
  payloadHex: string;
  payloadHash: string;
  /** Low-S compact ECDSA by the sender origin's BIP48 /0/0 proof key. */
  authenticationSignatureHex: string;
}

export type VaultApprovalStage = 'request' | 'partial-signature';

export interface VaultPsbtApprovalEnvelopeV1 {
  version: 1;
  network: Network;
  policyId: string;
  planId: string;
  planDigest: string;
  /** Canonical public sender origin; receivers also match it to policy. */
  senderOriginHex: string;
  senderChannelIdHex: string;
  recipientChannelIdHex: string;
  counter: string;
  expiresAtMs: string;
  antiReplayNonceHex: string;
  transcriptHashHex: string;
  stage: VaultApprovalStage;
  payloadHex: string;
  payloadHash: string;
  /** Low-S compact ECDSA over every envelope field and payload hash. */
  authenticationSignatureHex: string;
}

const hex = (bytes: number) => z.string().regex(new RegExp(`^[0-9a-f]{${bytes * 2}}$`, 'u'));
const variableHex = z.string().regex(/^(?:[0-9a-f]{2})+$/u);
const decimalU64 = decimalU64Schema;
const u32 = z.number().int().min(0).max(0xffff_ffff);
const shortText = z.string().max(256);
const longText = z.string().min(1).max(4096);
const networkSchema = z.enum(['mainnet', 'signet', 'regtest']);
const roleSchema = z.enum(VAULT_ROLES);
const branchSchema = z.enum(['receive', 'change']);

export const vaultSignerOriginSchema: z.ZodType<VaultSignerOriginV1> = z.object({
  version: z.literal(1),
  role: roleSchema,
  network: networkSchema,
  masterFingerprintHex: hex(4),
  originPath: z.string().min(1).max(64),
  accountXpub: z.string().min(1).max(128),
}).strict().superRefine((origin, ctx) => {
  const expected = vaultAccountOriginPath(origin.network);
  if (origin.originPath !== expected) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['originPath'], message: `expected ${expected}` });
  }
  try {
    const node = HDKey.fromExtendedKey(origin.accountXpub, bip32Versions(origin.network));
    if (node.privateKey !== null || node.depth !== 4 || node.index !== 0x8000_0002 || !node.publicKey) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['accountXpub'], message: 'BIP48 account xpub required' });
    }
  } catch {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['accountXpub'], message: 'network-appropriate xpub required' });
  }
});

export const vaultProofOfPossessionInputSchema: z.ZodType<VaultProofOfPossessionInputV1> = z.object({
  version: z.literal(1), origin: vaultSignerOriginSchema,
  sessionIdHex: hex(16), challengeNonceHex: hex(32), transcriptHashHex: hex(32),
  expiresAtMs: decimalU64,
}).strict();

export const vaultProofOfPossessionResultSchema: z.ZodType<VaultProofOfPossessionResultV1> = z.object({
  version: z.literal(1), role: roleSchema, inputDigestHex: hex(32),
  proofPublicKeyHex: z.string().regex(/^(?:02|03)[0-9a-f]{64}$/u), signatureHex: hex(64),
  scheme: z.literal('secp256k1-ecdsa-compact-low-s-v1'),
}).strict();

export const RECOVERY_C_MAX_CHALLENGE_LIFETIME_MS = 86_400_000n;

function challengeTimesValid(createdAtMs: string, expiresAtMs: string): boolean {
  const created = BigInt(createdAtMs);
  const expires = BigInt(expiresAtMs);
  return expires > created && expires - created <= RECOVERY_C_MAX_CHALLENGE_LIFETIME_MS;
}

export const recoveryCSetupChallengeSchema: z.ZodType<RecoveryCSetupChallengeV1> = z.object({
  version: z.literal(1), role: z.literal('recovery-c'), network: networkSchema,
  sessionIdHex: hex(16), challengeNonceHex: hex(32), transcriptHashHex: hex(32),
  desktopOrigin: vaultSignerOriginSchema.and(z.object({ role: z.literal('desktop-a') })),
  createdAtMs: decimalU64, expiresAtMs: decimalU64,
}).strict().superRefine((challenge, ctx) => {
  if (challenge.desktopOrigin.network !== challenge.network) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['desktopOrigin'], message: 'desktop origin network differs from challenge' });
  }
  if (!challengeTimesValid(challenge.createdAtMs, challenge.expiresAtMs)) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['expiresAtMs'], message: 'challenge lifetime must be positive and at most 24 hours' });
  }
});

export const recoveryCSetupResponseSchema: z.ZodType<RecoveryCSetupResponseV1> = z.object({
  version: z.literal(1), challengeDigestHex: hex(32),
  origin: vaultSignerOriginSchema.and(z.object({ role: z.literal('recovery-c') })),
  proof: vaultProofOfPossessionResultSchema.and(z.object({ role: z.literal('recovery-c') })),
}).strict();

export const recoveryCBackupCheckChallengeSchema: z.ZodType<RecoveryCBackupCheckChallengeV1> = z.object({
  version: z.literal(1), role: z.literal('recovery-c'), network: networkSchema,
  policyId: hex(32),
  recoveryOrigin: vaultSignerOriginSchema.and(z.object({ role: z.literal('recovery-c') })),
  sessionIdHex: hex(16), challengeNonceHex: hex(32),
  standaloneToolVersion: z.string().min(1).max(128),
  standaloneToolSourceDigest: hex(32), standaloneToolArtifactDigest: hex(32),
  createdAtMs: decimalU64, expiresAtMs: decimalU64,
}).strict().superRefine((challenge, ctx) => {
  if (challenge.recoveryOrigin.network !== challenge.network) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['recoveryOrigin'], message: 'recovery origin network differs from challenge' });
  }
  if (!challengeTimesValid(challenge.createdAtMs, challenge.expiresAtMs)) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['expiresAtMs'], message: 'challenge lifetime must be positive and at most 24 hours' });
  }
});

export const recoveryCBackupCheckResponseSchema: z.ZodType<RecoveryCBackupCheckResponseV1> = z.object({
  version: z.literal(1), network: networkSchema, policyId: hex(32), challengeDigestHex: hex(32),
  proofPublicKeyHex: z.string().regex(/^(?:02|03)[0-9a-f]{64}$/u), signatureHex: hex(64),
  scheme: z.literal('recovery-c-backup-check-secp256k1-ecdsa-compact-low-s-v1'),
}).strict();

const policyIdentityWithoutRefinement = z.object({
  version: z.literal(1), policyVersion: z.literal(1), network: networkSchema,
  threshold: z.literal(2), signers: z.tuple([
    vaultSignerOriginSchema, vaultSignerOriginSchema, vaultSignerOriginSchema,
  ]), receiveDescriptor: z.string().min(1).max(2048), changeDescriptor: z.string().min(1).max(2048),
  policyId: hex(32),
}).strict();

export const vaultPolicyIdentitySchema: z.ZodType<VaultPolicyIdentityV1> = policyIdentityWithoutRefinement.superRefine(
  (policy, ctx) => {
    const roles = policy.signers.map((signer) => signer.role);
    if (roles.some((role, index) => role !== VAULT_ROLES[index])) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['signers'], message: 'roles must be canonical A/B/C order' });
    }
    if (policy.signers.some((signer) => signer.network !== policy.network)) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['signers'], message: 'signer network differs from policy' });
    }
    for (const field of ['masterFingerprintHex', 'accountXpub'] as const) {
      if (new Set(policy.signers.map((signer) => signer[field])).size !== VAULT_SIGNER_COUNT) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['signers'], message: `duplicate ${field}` });
      }
    }
    try {
      if (policy.receiveDescriptor !== canonicalVaultDescriptor(policy.signers, 'receive') ||
          policy.changeDescriptor !== canonicalVaultDescriptor(policy.signers, 'change')) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['receiveDescriptor'], message: 'descriptor differs from origins' });
      }
    } catch {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['receiveDescriptor'], message: 'invalid canonical descriptor' });
    }
  },
);

export const vaultPolicyMetadataSchema: z.ZodType<VaultPolicyMetadataV1> = z.object({
  version: z.literal(1), createdAtMs: decimalU64, birthdayHeight: u32.nullable(),
  vaultLabel: shortText, signerLabels: z.tuple([shortText, shortText, shortText]),
}).strict();

export const vaultPolicyRecordSchema: z.ZodType<VaultPolicyRecordV1> = z.object({
  version: z.literal(1), identity: vaultPolicyIdentitySchema, metadata: vaultPolicyMetadataSchema,
}).strict();

export const vaultBranchDerivationSchema: z.ZodType<VaultBranchDerivationV1> = z.object({
  version: z.literal(1), network: networkSchema, policyId: hex(32), branch: branchSchema,
  index: u32.max(0x7fff_ffff),
}).strict();

const planInputSchema: z.ZodType<VaultPlanInputV1> = z.object({
  txid: hex(32), vout: u32, valueSats: decimalU64, scriptPubKeyHex: variableHex,
  witnessScriptHex: variableHex, branch: branchSchema, derivationIndex: u32.max(0x7fff_ffff),
  sequence: u32, sighash: z.literal('all'),
  classification: z.enum(['cardinal_clean', 'inscribed', 'rare_sat', 'runic_or_unsupported', 'mixed', 'unknown']),
  classificationEvidenceHash: hex(32),
}).strict();

const planOutputSchema: z.ZodType<VaultPlanOutputV1> = z.object({
  outputIndex: u32, valueSats: decimalU64, scriptPubKeyHex: variableHex,
  address: z.string().min(1).max(128), purpose: z.enum(['paired-spending', 'vault-change', 'vault-rotation', 'recovery-exit']),
  branch: branchSchema.nullable(), derivationIndex: u32.max(0x7fff_ffff).nullable(),
}).strict().superRefine((output, ctx) => {
  const currentPolicyChange = output.purpose === 'vault-change';
  if ((currentPolicyChange && (output.branch !== 'change' || output.derivationIndex === null)) ||
      (!currentPolicyChange && (output.branch !== null || output.derivationIndex !== null))) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, message: 'only current-policy Vault change has a change derivation' });
  }
});

const assetEffectSchema: z.ZodType<VaultAssetEffectV1> = z.object({
  kind: z.enum(['cardinal', 'inscription']), assetId: z.string().max(128),
  inputIndex: u32, inputOffsetSats: decimalU64, outputIndex: u32,
  outputOffsetSats: decimalU64, postageSats: decimalU64, protected: z.boolean(),
}).strict().superRefine((effect, ctx) => {
  if ((effect.kind === 'cardinal' && (effect.assetId !== '' || effect.protected)) ||
      (effect.kind === 'inscription' && (!/^[0-9a-f]{64}i(?:0|[1-9][0-9]*)$/u.test(effect.assetId) || !effect.protected))) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, message: 'asset identity/protection mismatch' });
  }
});

const tipSchema = z.object({ height: u32, hash: hex(32) }).strict();
const planSourceSchema: z.ZodType<VaultPlanSourceV1> = z.object({
  backendInstanceIdHash: hex(32), classificationRevisionHash: hex(32),
  coreTip: tipSchema, indexTip: tipSchema, observedAtMs: decimalU64, validUntilMs: decimalU64,
}).strict().superRefine((source, ctx) => {
  if (BigInt(source.validUntilMs) <= BigInt(source.observedAtMs)) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['validUntilMs'], message: 'freshness window must be positive' });
  }
});

export const vaultUnsignedPlanSchema: z.ZodType<VaultUnsignedPlanV1> = z.object({
  version: z.literal(1), policyVersion: z.literal(1), network: networkSchema,
  policyId: hex(32), planId: hex(16), requestId: hex(16),
  createdAtMs: decimalU64, expiresAtMs: decimalU64,
  kind: z.enum(['withdrawal', 'recovery', 'rotation']), unsignedTransactionHex: variableHex,
  inputs: z.array(planInputSchema).min(1).max(10_000), outputs: z.array(planOutputSchema).min(1).max(10_000),
  destination: z.object({
    kind: z.enum(['paired-spending', 'vault-policy', 'recovery-exit']),
    pairedSpendingWalletIdHash: hex(32).nullable(), targetPolicyId: hex(32).nullable(),
    address: z.string().min(1).max(128), outputIndex: u32,
  }).strict(),
  amountSats: decimalU64, changeSats: decimalU64, feeSats: decimalU64, vsize: u32.min(1),
  feeRateSatPerKvB: decimalU64,
  sighash: z.literal('all'), assetEffects: z.array(assetEffectSchema).max(10_000),
  source: planSourceSchema,
  replacement: z.object({
    kind: z.enum(['none', 'rbf', 'cpfp']), replacesTxid: hex(32).nullable(), parentTxid: hex(32).nullable(),
  }).strict(),
  broadcastIntent: z.enum(['broadcast', 'return-psbt']), planDigest: hex(32),
}).strict().superRefine((plan, ctx) => {
  if (BigInt(plan.expiresAtMs) <= BigInt(plan.createdAtMs) ||
      BigInt(plan.createdAtMs) < BigInt(plan.source.observedAtMs) ||
      BigInt(plan.expiresAtMs) > BigInt(plan.source.validUntilMs)) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['expiresAtMs'], message: 'plan freshness binding mismatch' });
  }
  if (plan.outputs.some((output, index) => output.outputIndex !== index)) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['outputs'], message: 'output indexes must match canonical order' });
  }
  if (new Set(plan.inputs.map((input) => `${input.txid}:${input.vout}`)).size !== plan.inputs.length) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['inputs'], message: 'duplicate plan outpoint' });
  }
  const destination = plan.outputs[plan.destination.outputIndex];
  const expectedPurpose = plan.destination.kind === 'paired-spending' ? 'paired-spending'
    : plan.destination.kind === 'vault-policy' ? 'vault-rotation' : 'recovery-exit';
  if (!destination || destination.purpose !== expectedPurpose || destination.address !== plan.destination.address) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['destination'], message: 'destination output mismatch' });
  }
  const destinationBindingValid =
    (plan.kind === 'withdrawal' && plan.destination.kind === 'paired-spending' &&
      plan.destination.pairedSpendingWalletIdHash !== null && plan.destination.targetPolicyId === null) ||
    (plan.kind === 'recovery' && plan.destination.kind === 'recovery-exit' &&
      plan.destination.pairedSpendingWalletIdHash === null && plan.destination.targetPolicyId === null) ||
    (plan.kind === 'rotation' && plan.destination.kind === 'vault-policy' &&
      plan.destination.pairedSpendingWalletIdHash === null && plan.destination.targetPolicyId !== null &&
      plan.destination.targetPolicyId !== plan.policyId);
  if (!destinationBindingValid) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['destination'], message: 'plan kind/destination binding mismatch' });
  }
  const replacementValid =
    (plan.replacement.kind === 'none' && plan.replacement.replacesTxid === null && plan.replacement.parentTxid === null) ||
    (plan.replacement.kind === 'rbf' && plan.replacement.replacesTxid !== null && plan.replacement.parentTxid === null) ||
    (plan.replacement.kind === 'cpfp' && plan.replacement.replacesTxid === null && plan.replacement.parentTxid !== null);
  if (!replacementValid) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['replacement'], message: 'replacement transaction binding mismatch' });
  }
  if (plan.assetEffects.some((effect) => !plan.inputs[effect.inputIndex] || !plan.outputs[effect.outputIndex])) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['assetEffects'], message: 'asset effect index out of range' });
  }
});

export const vaultPartialSignatureInputSchema: z.ZodType<VaultPartialSignatureInputV1> = z.object({
  version: z.literal(1), network: networkSchema, policyId: hex(32), planId: hex(16),
  planDigest: hex(32), role: roleSchema, canonicalPlanHex: variableHex, psbtHex: variableHex, psbtHash: hex(32),
}).strict();

export const vaultPartialSignatureResultSchema: z.ZodType<VaultPartialSignatureResultV1> = z.object({
  version: z.literal(1), network: networkSchema, policyId: hex(32), planId: hex(16),
  planDigest: hex(32), roleAdded: roleSchema, priorPsbtHash: hex(32), signedPsbtHex: variableHex,
  signedPsbtHash: hex(32),
}).strict();

export const vaultRecoveryKitSchema: z.ZodType<VaultRecoveryKitV1> = z.object({
  version: z.literal(1), network: networkSchema, policyVersion: z.literal(1), policyId: hex(32),
  signers: z.tuple([vaultSignerOriginSchema, vaultSignerOriginSchema, vaultSignerOriginSchema]),
  receiveDescriptor: z.string().min(1).max(2048), changeDescriptor: z.string().min(1).max(2048),
  createdAtMs: decimalU64, birthdayHeight: u32.nullable(), vaultLabel: shortText,
  signerLabels: z.tuple([shortText, shortText, shortText]), firstReceiveAddress: z.string().min(1).max(128),
  compatibilityRequirements: z.array(z.string().min(1).max(256)).min(1).max(32),
  minimumReaderVersion: z.literal(1), standaloneToolSourceDigest: hex(32),
  standaloneToolArtifactDigest: hex(32), recoveryInstructions: longText, rotationInstructions: longText,
  recoveryInstructionsVersion: z.literal(1),
}).strict().superRefine((kit, ctx) => {
  const policyCandidate = {
    version: 1 as const, policyVersion: 1 as const, network: kit.network, threshold: 2 as const,
    signers: kit.signers, receiveDescriptor: kit.receiveDescriptor, changeDescriptor: kit.changeDescriptor,
    policyId: kit.policyId,
  };
  const parsed = vaultPolicyIdentitySchema.safeParse(policyCandidate);
  if (!parsed.success) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['policyId'], message: 'recovery policy fields invalid' });
});

export const vaultPairingEnvelopeSchema: z.ZodType<VaultPairingEnvelopeV1> = z.object({
  version: z.literal(1), network: networkSchema, sessionIdHex: hex(16), senderOriginHex: variableHex,
  senderChannelIdHex: hex(32),
  recipientChannelIdHex: hex(32), counter: decimalU64, createdAtMs: decimalU64, expiresAtMs: decimalU64,
  antiReplayNonceHex: hex(32), transcriptHashHex: hex(32),
  messageType: z.enum(['signer-origin', 'pop-input', 'pop-result', 'policy']),
  payloadHex: variableHex, payloadHash: hex(32), authenticationSignatureHex: hex(64),
}).strict().superRefine((envelope, ctx) => {
  if (BigInt(envelope.expiresAtMs) <= BigInt(envelope.createdAtMs)) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['expiresAtMs'], message: 'pairing envelope already expired at creation' });
  }
});

export const vaultPsbtApprovalEnvelopeSchema: z.ZodType<VaultPsbtApprovalEnvelopeV1> = z.object({
  version: z.literal(1), network: networkSchema, policyId: hex(32), planId: hex(16), planDigest: hex(32),
  senderOriginHex: variableHex,
  senderChannelIdHex: hex(32), recipientChannelIdHex: hex(32), counter: decimalU64,
  expiresAtMs: decimalU64, antiReplayNonceHex: hex(32), transcriptHashHex: hex(32),
  stage: z.enum(['request', 'partial-signature']), payloadHex: variableHex, payloadHash: hex(32),
  authenticationSignatureHex: hex(64),
}).strict();

export function vaultAccountOriginPath(network: Network): string {
  return `m/48'/${network === 'mainnet' ? 0 : 1}'/0'/2'`;
}

export function canonicalVaultDescriptor(
  signers: readonly VaultSignerOriginV1[],
  branch: VaultBranch,
): string {
  if (signers.length !== VAULT_SIGNER_COUNT) throw new Error('exactly three signer origins required');
  const chain = branch === 'receive' ? 0 : 1;
  const keys = signers.map((signer, index) => {
    const parsed = vaultSignerOriginSchema.parse(signer);
    if (parsed.role !== VAULT_ROLES[index]) throw new Error('roles must be canonical A/B/C order');
    const origin = parsed.originPath.slice(2).replaceAll("'", 'h');
    return `[${parsed.masterFingerprintHex}/${origin}]${parsed.accountXpub}/${chain}/*`;
  });
  const payload = `wsh(sortedmulti(2,${keys.join(',')}))`;
  return `${payload}#${descriptorChecksum(payload)}`;
}
