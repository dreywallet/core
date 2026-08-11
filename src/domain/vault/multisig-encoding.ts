/**
 * Normative deterministic binary encoding for ADR 0007 Workstream B0.
 *
 * This intentionally extends the core gateway signing convention instead of
 * introducing CBOR/protobuf and their profile/canonicalization surface:
 *
 *   header       = ASCII "SQVB" || record-type:u8 || version:u8
 *   enum/bool    = one explicitly assigned u8
 *   u32/u64      = unsigned big-endian
 *   bytes/text   = byte-length:u32 || bytes (UTF-8 is strict/fatal)
 *   array        = element-count:u32 || elements
 *   nullable     = 0x00, or 0x01 || value
 *
 * Fields occur in the order written below. Decoders require exact EOF. There
 * are no unknown fields, map keys, implicit defaults, indefinite lengths, or
 * alternative integer/text representations in v1, so trailing extensions and
 * downgrades fail closed. Txids are the usual display-order 32 bytes; raw
 * transaction and PSBT fields are preserved byte-for-byte.
 */
import { secp256k1 } from '@noble/curves/secp256k1';
import { HDKey } from '@scure/bip32';
import { getCryptoProvider } from './crypto-provider';
import { bytesToHex, hexToBytes } from './encoding';
import {
  VAULT_ROLES,
  bip32Versions,
  vaultAccountOriginPath,
  vaultBranchDerivationSchema,
  vaultPairingEnvelopeSchema,
  vaultPartialSignatureInputSchema,
  vaultPartialSignatureResultSchema,
  vaultPolicyIdentitySchema,
  vaultPolicyMetadataSchema,
  vaultPolicyRecordSchema,
  vaultProofOfPossessionInputSchema,
  vaultProofOfPossessionResultSchema,
  vaultPsbtApprovalEnvelopeSchema,
  recoveryCBackupCheckChallengeSchema,
  recoveryCBackupCheckResponseSchema,
  recoveryCSetupChallengeSchema,
  recoveryCSetupResponseSchema,
  vaultRecoveryKitSchema,
  vaultSignerOriginSchema,
  vaultUnsignedPlanSchema,
  type VaultApprovalStage,
  type VaultAssetEffectV1,
  type VaultBranch,
  type VaultBranchDerivationV1,
  type VaultPairingEnvelopeV1,
  type VaultPairingMessageType,
  type VaultPartialSignatureInputV1,
  type VaultPartialSignatureResultV1,
  type VaultPlanInputV1,
  type VaultPlanOutputV1,
  type VaultPolicyIdentityV1,
  type VaultPolicyMetadataV1,
  type VaultPolicyRecordV1,
  type VaultProofOfPossessionInputV1,
  type VaultProofOfPossessionResultV1,
  type VaultPsbtApprovalEnvelopeV1,
  type VaultRecoveryKitV1,
  type VaultSignerOriginV1,
  type VaultSignerRole,
  type VaultUnsignedPlanV1,
  type RecoveryCBackupCheckChallengeV1,
  type RecoveryCBackupCheckResponseV1,
  type RecoveryCSetupChallengeV1,
  type RecoveryCSetupResponseV1,
} from './multisig-contracts';
import type { Network } from '../keys/derivation';

const MAGIC = Uint8Array.of(0x53, 0x51, 0x56, 0x42); // SQVB
const MAX_FIELD_BYTES = 2_000_000;
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });

const RECORD = {
  signerOrigin: 1,
  proofInput: 2,
  proofResult: 3,
  policyIdentity: 4,
  policyRecord: 5,
  branchDerivation: 6,
  unsignedPlan: 7,
  partialInput: 8,
  partialResult: 9,
  recoveryKit: 10,
  pairingEnvelope: 11,
  approvalEnvelope: 12,
  recoveryCSetupChallenge: 13,
  recoveryCSetupResponse: 14,
  recoveryCBackupCheckChallenge: 15,
  recoveryCBackupCheckResponse: 16,
} as const;

class Writer {
  readonly parts: Uint8Array[] = [];

  header(type: number): void { this.parts.push(MAGIC, Uint8Array.of(type, 1)); }
  u8(value: number): void {
    if (!Number.isInteger(value) || value < 0 || value > 0xff) throw new Error('u8 out of range');
    this.parts.push(Uint8Array.of(value));
  }
  u32(value: number): void {
    if (!Number.isInteger(value) || value < 0 || value > 0xffff_ffff) throw new Error('u32 out of range');
    const bytes = new Uint8Array(4);
    new DataView(bytes.buffer).setUint32(0, value, false);
    this.parts.push(bytes);
  }
  u64(value: string): void {
    const integer = BigInt(value);
    if (integer < 0n || integer > 0xffff_ffff_ffff_ffffn || integer.toString() !== value) {
      throw new Error('canonical u64 decimal required');
    }
    const bytes = new Uint8Array(8);
    new DataView(bytes.buffer).setBigUint64(0, integer, false);
    this.parts.push(bytes);
  }
  fixedHex(value: string, byteLength: number): void {
    const bytes = hexToBytes(value);
    if (bytes.length !== byteLength || value !== bytesToHex(bytes)) throw new Error('non-canonical fixed hex');
    this.parts.push(bytes);
  }
  bytes(value: Uint8Array): void {
    if (value.length > MAX_FIELD_BYTES) throw new Error('field exceeds binary contract limit');
    this.u32(value.length);
    this.parts.push(value);
  }
  hex(value: string): void { this.bytes(hexToBytes(value)); }
  text(value: string): void { this.bytes(encoder.encode(value)); }
  nullableU32(value: number | null): void {
    this.u8(value === null ? 0 : 1);
    if (value !== null) this.u32(value);
  }
  nested(value: Uint8Array): void { this.bytes(value); }
  finish(): Uint8Array {
    const length = this.parts.reduce((sum, part) => sum + part.length, 0);
    const out = new Uint8Array(length);
    let offset = 0;
    for (const part of this.parts) { out.set(part, offset); offset += part.length; }
    return out;
  }
}

class Reader {
  private offset = 0;
  constructor(private readonly input: Uint8Array) {
    if (input.length > MAX_FIELD_BYTES * 4) throw new Error('record exceeds binary contract limit');
  }
  private take(length: number): Uint8Array {
    if (!Number.isInteger(length) || length < 0 || this.offset + length > this.input.length) {
      throw new Error('truncated binary contract');
    }
    const bytes = this.input.subarray(this.offset, this.offset + length);
    this.offset += length;
    return bytes;
  }
  header(type: number): void {
    const magic = this.take(4);
    if (magic.some((value, index) => value !== MAGIC[index])) throw new Error('invalid vault contract magic');
    if (this.u8() !== type) throw new Error('unexpected vault contract record type');
    if (this.u8() !== 1) throw new Error('unknown vault contract version');
  }
  u8(): number { return this.take(1)[0]!; }
  u32(): number { const value = this.take(4); return new DataView(value.buffer, value.byteOffset, 4).getUint32(0, false); }
  u64(): string { const value = this.take(8); return new DataView(value.buffer, value.byteOffset, 8).getBigUint64(0, false).toString(); }
  fixedHex(byteLength: number): string { return bytesToHex(this.take(byteLength)); }
  bytes(): Uint8Array {
    const length = this.u32();
    if (length > MAX_FIELD_BYTES) throw new Error('field exceeds binary contract limit');
    return this.take(length);
  }
  hex(): string { return bytesToHex(this.bytes()); }
  text(): string { return decoder.decode(this.bytes()); }
  nullableU32(): number | null {
    const tag = this.u8();
    if (tag === 0) return null;
    if (tag === 1) return this.u32();
    throw new Error('unknown nullable tag');
  }
  nested(): Uint8Array { return this.bytes(); }
  done(): void { if (this.offset !== this.input.length) throw new Error('trailing vault contract bytes'); }
}

const NETWORK_TO_BYTE: Record<Network, number> = { mainnet: 0, signet: 1 };
const BYTE_TO_NETWORK = ['mainnet', 'signet'] as const;
const ROLE_TO_BYTE: Record<VaultSignerRole, number> = { 'desktop-a': 0, 'mobile-b': 1, 'recovery-c': 2 };
const BRANCH_TO_BYTE: Record<VaultBranch, number> = { receive: 0, change: 1 };

function enumByte<T extends string>(value: T, values: Readonly<Record<T, number>>): number {
  const byte = values[value];
  if (byte === undefined) throw new Error(`unknown enum value: ${value}`);
  return byte;
}

function decodeEnum<T extends string>(byte: number, values: readonly T[], label: string): T {
  const value = values[byte];
  if (value === undefined) throw new Error(`unknown ${label}`);
  return value;
}

function writeNetwork(writer: Writer, network: Network): void { writer.u8(enumByte(network, NETWORK_TO_BYTE)); }
function readNetwork(reader: Reader): Network { return decodeEnum(reader.u8(), BYTE_TO_NETWORK, 'network'); }
function writeRole(writer: Writer, role: VaultSignerRole): void { writer.u8(enumByte(role, ROLE_TO_BYTE)); }
function readRole(reader: Reader): VaultSignerRole { return decodeEnum(reader.u8(), VAULT_ROLES, 'signer role'); }
function writeBranch(writer: Writer, branch: VaultBranch): void { writer.u8(enumByte(branch, BRANCH_TO_BYTE)); }
function readBranch(reader: Reader): VaultBranch { return decodeEnum(reader.u8(), ['receive', 'change'], 'branch'); }

function digest(domain: string, bytes: Uint8Array): string {
  const domainBytes = encoder.encode(domain);
  const input = new Uint8Array(domainBytes.length + 1 + bytes.length);
  input.set(domainBytes, 0);
  input[domainBytes.length] = 0;
  input.set(bytes, domainBytes.length + 1);
  return bytesToHex(getCryptoProvider().sha256(input));
}

export function serializeVaultSignerOrigin(origin: VaultSignerOriginV1): Uint8Array {
  const parsed = vaultSignerOriginSchema.parse(origin);
  const writer = new Writer();
  writer.header(RECORD.signerOrigin);
  writeRole(writer, parsed.role);
  writeNetwork(writer, parsed.network);
  writer.fixedHex(parsed.masterFingerprintHex, 4);
  writer.text(parsed.originPath);
  writer.text(parsed.accountXpub);
  return writer.finish();
}

export function parseVaultSignerOrigin(bytes: Uint8Array): VaultSignerOriginV1 {
  const reader = new Reader(bytes);
  reader.header(RECORD.signerOrigin);
  const value = vaultSignerOriginSchema.parse({
    version: 1, role: readRole(reader), network: readNetwork(reader),
    masterFingerprintHex: reader.fixedHex(4), originPath: reader.text(), accountXpub: reader.text(),
  });
  reader.done();
  return value;
}

export function serializeVaultProofInput(input: VaultProofOfPossessionInputV1): Uint8Array {
  const parsed = vaultProofOfPossessionInputSchema.parse(input);
  const writer = new Writer();
  writer.header(RECORD.proofInput);
  writer.nested(serializeVaultSignerOrigin(parsed.origin));
  writer.fixedHex(parsed.sessionIdHex, 16);
  writer.fixedHex(parsed.challengeNonceHex, 32);
  writer.fixedHex(parsed.transcriptHashHex, 32);
  writer.u64(parsed.expiresAtMs);
  return writer.finish();
}

export function parseVaultProofInput(bytes: Uint8Array): VaultProofOfPossessionInputV1 {
  const reader = new Reader(bytes);
  reader.header(RECORD.proofInput);
  const value = vaultProofOfPossessionInputSchema.parse({
    version: 1, origin: parseVaultSignerOrigin(reader.nested()), sessionIdHex: reader.fixedHex(16),
    challengeNonceHex: reader.fixedHex(32), transcriptHashHex: reader.fixedHex(32), expiresAtMs: reader.u64(),
  });
  reader.done();
  return value;
}

export function vaultProofInputDigest(input: VaultProofOfPossessionInputV1): string {
  return digest('drey-vault-pop-v1', serializeVaultProofInput(input));
}

export function serializeVaultProofResult(result: VaultProofOfPossessionResultV1): Uint8Array {
  const parsed = vaultProofOfPossessionResultSchema.parse(result);
  const writer = new Writer();
  writer.header(RECORD.proofResult);
  writeRole(writer, parsed.role);
  writer.fixedHex(parsed.inputDigestHex, 32);
  writer.fixedHex(parsed.proofPublicKeyHex, 33);
  writer.fixedHex(parsed.signatureHex, 64);
  writer.u8(0); // only secp256k1-ecdsa-compact-low-s-v1
  return writer.finish();
}

export function parseVaultProofResult(bytes: Uint8Array): VaultProofOfPossessionResultV1 {
  const reader = new Reader(bytes);
  reader.header(RECORD.proofResult);
  const role = readRole(reader);
  const inputDigestHex = reader.fixedHex(32);
  const proofPublicKeyHex = reader.fixedHex(33);
  const signatureHex = reader.fixedHex(64);
  if (reader.u8() !== 0) throw new Error('unknown proof-of-possession scheme');
  reader.done();
  return vaultProofOfPossessionResultSchema.parse({
    version: 1, role, inputDigestHex, proofPublicKeyHex, signatureHex,
    scheme: 'secp256k1-ecdsa-compact-low-s-v1',
  });
}

export function verifyVaultProofOfPossession(
  input: VaultProofOfPossessionInputV1,
  result: VaultProofOfPossessionResultV1,
  nowMs?: string,
): boolean {
  try {
    const parsedInput = vaultProofOfPossessionInputSchema.parse(input);
    const parsedResult = vaultProofOfPossessionResultSchema.parse(result);
    if (nowMs !== undefined && BigInt(nowMs) > BigInt(parsedInput.expiresAtMs)) return false;
    if (parsedResult.role !== parsedInput.origin.role || parsedResult.inputDigestHex !== vaultProofInputDigest(parsedInput)) {
      return false;
    }
    const account = HDKey.fromExtendedKey(parsedInput.origin.accountXpub, bip32Versions(parsedInput.origin.network));
    const proofKey = account.deriveChild(0).deriveChild(0).publicKey;
    if (!proofKey || bytesToHex(proofKey) !== parsedResult.proofPublicKeyHex) return false;
    return secp256k1.verify(
      hexToBytes(parsedResult.signatureHex),
      hexToBytes(parsedResult.inputDigestHex),
      hexToBytes(parsedResult.proofPublicKeyHex),
      { format: 'compact', prehash: false, lowS: true },
    );
  } catch {
    return false;
  }
}

export function serializeRecoveryCSetupChallenge(value: RecoveryCSetupChallengeV1): Uint8Array {
  const parsed = recoveryCSetupChallengeSchema.parse(value);
  const writer = new Writer();
  writer.header(RECORD.recoveryCSetupChallenge);
  writeRole(writer, parsed.role);
  writeNetwork(writer, parsed.network);
  writer.fixedHex(parsed.sessionIdHex, 16);
  writer.fixedHex(parsed.challengeNonceHex, 32);
  writer.fixedHex(parsed.transcriptHashHex, 32);
  writer.nested(serializeVaultSignerOrigin(parsed.desktopOrigin));
  writer.u64(parsed.createdAtMs);
  writer.u64(parsed.expiresAtMs);
  return writer.finish();
}

export function parseRecoveryCSetupChallenge(bytes: Uint8Array): RecoveryCSetupChallengeV1 {
  const reader = new Reader(bytes);
  reader.header(RECORD.recoveryCSetupChallenge);
  const value = recoveryCSetupChallengeSchema.parse({
    version: 1, role: readRole(reader), network: readNetwork(reader),
    sessionIdHex: reader.fixedHex(16), challengeNonceHex: reader.fixedHex(32),
    transcriptHashHex: reader.fixedHex(32), desktopOrigin: parseVaultSignerOrigin(reader.nested()),
    createdAtMs: reader.u64(), expiresAtMs: reader.u64(),
  });
  reader.done();
  return value;
}

export function recoveryCSetupChallengeDigest(value: RecoveryCSetupChallengeV1): string {
  return digest('drey-recovery-c-setup-challenge-v1', serializeRecoveryCSetupChallenge(value));
}

/** Short display value only; all security comparisons use the complete digest. */
export function recoveryCChallengeFingerprint(value: RecoveryCSetupChallengeV1 | RecoveryCBackupCheckChallengeV1): string {
  const full = 'policyId' in value
    ? recoveryCBackupCheckChallengeDigest(value)
    : recoveryCSetupChallengeDigest(value);
  return full.slice(0, 16).match(/.{4}/gu)!.join('-');
}

export function serializeRecoveryCSetupResponse(value: RecoveryCSetupResponseV1): Uint8Array {
  const parsed = recoveryCSetupResponseSchema.parse(value);
  const writer = new Writer();
  writer.header(RECORD.recoveryCSetupResponse);
  writer.fixedHex(parsed.challengeDigestHex, 32);
  writer.nested(serializeVaultSignerOrigin(parsed.origin));
  writer.nested(serializeVaultProofResult(parsed.proof));
  return writer.finish();
}

export function parseRecoveryCSetupResponse(bytes: Uint8Array): RecoveryCSetupResponseV1 {
  const reader = new Reader(bytes);
  reader.header(RECORD.recoveryCSetupResponse);
  const value = recoveryCSetupResponseSchema.parse({
    version: 1, challengeDigestHex: reader.fixedHex(32),
    origin: parseVaultSignerOrigin(reader.nested()), proof: parseVaultProofResult(reader.nested()),
  });
  reader.done();
  return value;
}

export function serializeRecoveryCBackupCheckChallenge(value: RecoveryCBackupCheckChallengeV1): Uint8Array {
  const parsed = recoveryCBackupCheckChallengeSchema.parse(value);
  const writer = new Writer();
  writer.header(RECORD.recoveryCBackupCheckChallenge);
  writeRole(writer, parsed.role);
  writeNetwork(writer, parsed.network);
  writer.fixedHex(parsed.policyId, 32);
  writer.nested(serializeVaultSignerOrigin(parsed.recoveryOrigin));
  writer.fixedHex(parsed.sessionIdHex, 16);
  writer.fixedHex(parsed.challengeNonceHex, 32);
  writer.text(parsed.standaloneToolVersion);
  writer.fixedHex(parsed.standaloneToolSourceDigest, 32);
  writer.fixedHex(parsed.standaloneToolArtifactDigest, 32);
  writer.u64(parsed.createdAtMs);
  writer.u64(parsed.expiresAtMs);
  return writer.finish();
}

export function parseRecoveryCBackupCheckChallenge(bytes: Uint8Array): RecoveryCBackupCheckChallengeV1 {
  const reader = new Reader(bytes);
  reader.header(RECORD.recoveryCBackupCheckChallenge);
  const value = recoveryCBackupCheckChallengeSchema.parse({
    version: 1, role: readRole(reader), network: readNetwork(reader), policyId: reader.fixedHex(32),
    recoveryOrigin: parseVaultSignerOrigin(reader.nested()), sessionIdHex: reader.fixedHex(16),
    challengeNonceHex: reader.fixedHex(32), standaloneToolVersion: reader.text(),
    standaloneToolSourceDigest: reader.fixedHex(32), standaloneToolArtifactDigest: reader.fixedHex(32),
    createdAtMs: reader.u64(), expiresAtMs: reader.u64(),
  });
  reader.done();
  return value;
}

export function recoveryCBackupCheckChallengeDigest(value: RecoveryCBackupCheckChallengeV1): string {
  return digest('drey-recovery-c-backup-check-challenge-v1', serializeRecoveryCBackupCheckChallenge(value));
}

export function serializeRecoveryCBackupCheckResponse(value: RecoveryCBackupCheckResponseV1): Uint8Array {
  const parsed = recoveryCBackupCheckResponseSchema.parse(value);
  const writer = new Writer();
  writer.header(RECORD.recoveryCBackupCheckResponse);
  writeNetwork(writer, parsed.network);
  writer.fixedHex(parsed.policyId, 32);
  writer.fixedHex(parsed.challengeDigestHex, 32);
  writer.fixedHex(parsed.proofPublicKeyHex, 33);
  writer.fixedHex(parsed.signatureHex, 64);
  writer.u8(0);
  return writer.finish();
}

export function parseRecoveryCBackupCheckResponse(bytes: Uint8Array): RecoveryCBackupCheckResponseV1 {
  const reader = new Reader(bytes);
  reader.header(RECORD.recoveryCBackupCheckResponse);
  const network = readNetwork(reader);
  const policyId = reader.fixedHex(32);
  const challengeDigestHex = reader.fixedHex(32);
  const proofPublicKeyHex = reader.fixedHex(33);
  const signatureHex = reader.fixedHex(64);
  if (reader.u8() !== 0) throw new Error('unknown Recovery C backup-check signature scheme');
  reader.done();
  return recoveryCBackupCheckResponseSchema.parse({
    version: 1, network, policyId, challengeDigestHex, proofPublicKeyHex, signatureHex,
    scheme: 'recovery-c-backup-check-secp256k1-ecdsa-compact-low-s-v1',
  });
}

function writePolicyFields(writer: Writer, policy: VaultPolicyIdentityV1): void {
  writer.u8(policy.policyVersion);
  writeNetwork(writer, policy.network);
  writer.u8(policy.threshold);
  writer.u32(policy.signers.length);
  for (const signer of policy.signers) writer.nested(serializeVaultSignerOrigin(signer));
  writer.text(policy.receiveDescriptor);
  writer.text(policy.changeDescriptor);
}

/** The exact canonicalPolicyBytes input to ADR 0007 policyId (policyId and metadata omitted). */
export function canonicalVaultPolicyBytes(policy: VaultPolicyIdentityV1): Uint8Array {
  const parsed = vaultPolicyIdentitySchema.parse(policy);
  const writer = new Writer();
  writer.header(RECORD.policyIdentity);
  writePolicyFields(writer, parsed);
  return writer.finish();
}

export function computeVaultPolicyId(policy: VaultPolicyIdentityV1): string {
  return digest('drey-vault-policy-v1', canonicalVaultPolicyBytes(policy));
}

export function finalizeVaultPolicyIdentity(input: Omit<VaultPolicyIdentityV1, 'policyId'>): VaultPolicyIdentityV1 {
  const candidate = vaultPolicyIdentitySchema.parse({ ...input, policyId: '00'.repeat(32) });
  const result = { ...candidate, policyId: computeVaultPolicyId(candidate) };
  return vaultPolicyIdentitySchema.parse(result);
}

export function assertVaultPolicyIdentity(policy: VaultPolicyIdentityV1): void {
  const parsed = vaultPolicyIdentitySchema.parse(policy);
  if (computeVaultPolicyId(parsed) !== parsed.policyId) throw new Error('vault policyId mismatch');
}

export function parseCanonicalVaultPolicy(bytes: Uint8Array): VaultPolicyIdentityV1 {
  const reader = new Reader(bytes);
  reader.header(RECORD.policyIdentity);
  if (reader.u8() !== 1) throw new Error('unknown vault policy version');
  const network = readNetwork(reader);
  if (reader.u8() !== 2) throw new Error('unknown vault threshold');
  if (reader.u32() !== 3) throw new Error('unknown vault signer count');
  const signers = [
    parseVaultSignerOrigin(reader.nested()), parseVaultSignerOrigin(reader.nested()), parseVaultSignerOrigin(reader.nested()),
  ] as [VaultSignerOriginV1, VaultSignerOriginV1, VaultSignerOriginV1];
  const receiveDescriptor = reader.text();
  const changeDescriptor = reader.text();
  reader.done();
  return finalizeVaultPolicyIdentity({
    version: 1, policyVersion: 1, network, threshold: 2, signers, receiveDescriptor, changeDescriptor,
  });
}

function writeMetadata(writer: Writer, metadata: VaultPolicyMetadataV1): void {
  writer.u64(metadata.createdAtMs);
  writer.nullableU32(metadata.birthdayHeight);
  writer.text(metadata.vaultLabel);
  for (const label of metadata.signerLabels) writer.text(label);
}

function readMetadata(reader: Reader): VaultPolicyMetadataV1 {
  return vaultPolicyMetadataSchema.parse({
    version: 1, createdAtMs: reader.u64(), birthdayHeight: reader.nullableU32(),
    vaultLabel: reader.text(), signerLabels: [reader.text(), reader.text(), reader.text()],
  });
}

export function serializeVaultPolicyRecord(record: VaultPolicyRecordV1): Uint8Array {
  const parsed = vaultPolicyRecordSchema.parse(record);
  assertVaultPolicyIdentity(parsed.identity);
  const writer = new Writer();
  writer.header(RECORD.policyRecord);
  writer.nested(canonicalVaultPolicyBytes(parsed.identity));
  writeMetadata(writer, parsed.metadata);
  return writer.finish();
}

export function parseVaultPolicyRecord(bytes: Uint8Array): VaultPolicyRecordV1 {
  const reader = new Reader(bytes);
  reader.header(RECORD.policyRecord);
  const identity = parseCanonicalVaultPolicy(reader.nested());
  const metadata = readMetadata(reader);
  reader.done();
  return vaultPolicyRecordSchema.parse({ version: 1, identity, metadata });
}

export function serializeVaultBranchDerivation(value: VaultBranchDerivationV1): Uint8Array {
  const parsed = vaultBranchDerivationSchema.parse(value);
  const writer = new Writer();
  writer.header(RECORD.branchDerivation);
  writeNetwork(writer, parsed.network);
  writer.fixedHex(parsed.policyId, 32);
  writeBranch(writer, parsed.branch);
  writer.u32(parsed.index);
  return writer.finish();
}

export function parseVaultBranchDerivation(bytes: Uint8Array): VaultBranchDerivationV1 {
  const reader = new Reader(bytes);
  reader.header(RECORD.branchDerivation);
  const value = vaultBranchDerivationSchema.parse({
    version: 1, network: readNetwork(reader), policyId: reader.fixedHex(32), branch: readBranch(reader), index: reader.u32(),
  });
  reader.done();
  return value;
}

function writePlanInput(writer: Writer, input: VaultPlanInputV1): void {
  writer.fixedHex(input.txid, 32); writer.u32(input.vout); writer.u64(input.valueSats);
  writer.hex(input.scriptPubKeyHex); writer.hex(input.witnessScriptHex); writeBranch(writer, input.branch);
  writer.u32(input.derivationIndex); writer.u32(input.sequence); writer.u8(1); // SIGHASH_ALL
  writer.u8(enumByte(input.classification, {
    cardinal_clean: 0, inscribed: 1, rare_sat: 2, runic_or_unsupported: 3, mixed: 4, unknown: 5,
  }));
  writer.fixedHex(input.classificationEvidenceHash, 32);
}

function readPlanInput(reader: Reader): VaultPlanInputV1 {
  const input = {
    txid: reader.fixedHex(32), vout: reader.u32(), valueSats: reader.u64(), scriptPubKeyHex: reader.hex(),
    witnessScriptHex: reader.hex(), branch: readBranch(reader), derivationIndex: reader.u32(),
    sequence: reader.u32(), sighash: 'all' as const,
  };
  if (reader.u8() !== 1) throw new Error('unsupported vault sighash');
  const classification = decodeEnum(
    reader.u8(), ['cardinal_clean', 'inscribed', 'rare_sat', 'runic_or_unsupported', 'mixed', 'unknown'],
    'input classification',
  );
  return { ...input, classification, classificationEvidenceHash: reader.fixedHex(32) };
}

function writePlanOutput(writer: Writer, output: VaultPlanOutputV1): void {
  writer.u32(output.outputIndex); writer.u64(output.valueSats); writer.hex(output.scriptPubKeyHex);
  writer.text(output.address);
  writer.u8(enumByte(output.purpose, {
    'paired-spending': 0, 'vault-change': 1, 'vault-rotation': 2, 'recovery-exit': 3,
  }));
  writer.u8(output.branch === null ? 0 : 1);
  if (output.branch !== null) writeBranch(writer, output.branch);
  writer.u8(output.derivationIndex === null ? 0 : 1);
  if (output.derivationIndex !== null) writer.u32(output.derivationIndex);
}

function readPlanOutput(reader: Reader): VaultPlanOutputV1 {
  const outputIndex = reader.u32(); const valueSats = reader.u64(); const scriptPubKeyHex = reader.hex();
  const address = reader.text();
  const purpose = decodeEnum(
    reader.u8(), ['paired-spending', 'vault-change', 'vault-rotation', 'recovery-exit'], 'output purpose',
  );
  const branchTag = reader.u8();
  const branch = branchTag === 0 ? null : branchTag === 1 ? readBranch(reader) : (() => { throw new Error('unknown branch tag'); })();
  const indexTag = reader.u8();
  const derivationIndex = indexTag === 0 ? null : indexTag === 1 ? reader.u32() : (() => { throw new Error('unknown index tag'); })();
  return { outputIndex, valueSats, scriptPubKeyHex, address, purpose, branch, derivationIndex };
}

function writeAssetEffect(writer: Writer, effect: VaultAssetEffectV1): void {
  writer.u8(effect.kind === 'cardinal' ? 0 : 1); writer.text(effect.assetId); writer.u32(effect.inputIndex);
  writer.u64(effect.inputOffsetSats); writer.u32(effect.outputIndex); writer.u64(effect.outputOffsetSats);
  writer.u64(effect.postageSats); writer.u8(effect.protected ? 1 : 0);
}

function readAssetEffect(reader: Reader): VaultAssetEffectV1 {
  const kind = decodeEnum(reader.u8(), ['cardinal', 'inscription'], 'asset kind');
  const assetId = reader.text(); const inputIndex = reader.u32(); const inputOffsetSats = reader.u64();
  const outputIndex = reader.u32(); const outputOffsetSats = reader.u64(); const postageSats = reader.u64();
  const protectedByte = reader.u8();
  if (protectedByte > 1) throw new Error('unknown protected flag');
  return { kind, assetId, inputIndex, inputOffsetSats, outputIndex, outputOffsetSats, postageSats, protected: protectedByte === 1 };
}

/** The exact canonicalPlanBytes input to ADR 0007 planDigest (planDigest omitted). */
export function canonicalVaultPlanBytes(plan: VaultUnsignedPlanV1): Uint8Array {
  const parsed = vaultUnsignedPlanSchema.parse(plan);
  const writer = new Writer();
  writer.header(RECORD.unsignedPlan);
  writer.u8(parsed.policyVersion); writeNetwork(writer, parsed.network); writer.fixedHex(parsed.policyId, 32);
  writer.fixedHex(parsed.planId, 16); writer.fixedHex(parsed.requestId, 16);
  writer.u64(parsed.createdAtMs); writer.u64(parsed.expiresAtMs);
  writer.u8(enumByte(parsed.kind, { withdrawal: 0, recovery: 1, rotation: 2 }));
  writer.hex(parsed.unsignedTransactionHex);
  writer.u32(parsed.inputs.length); for (const input of parsed.inputs) writePlanInput(writer, input);
  writer.u32(parsed.outputs.length); for (const output of parsed.outputs) writePlanOutput(writer, output);
  writer.u8(enumByte(parsed.destination.kind, { 'paired-spending': 0, 'vault-policy': 1, 'recovery-exit': 2 }));
  writer.u8(parsed.destination.pairedSpendingWalletIdHash === null ? 0 : 1);
  if (parsed.destination.pairedSpendingWalletIdHash !== null) {
    writer.fixedHex(parsed.destination.pairedSpendingWalletIdHash, 32);
  }
  writer.u8(parsed.destination.targetPolicyId === null ? 0 : 1);
  if (parsed.destination.targetPolicyId !== null) writer.fixedHex(parsed.destination.targetPolicyId, 32);
  writer.text(parsed.destination.address);
  writer.u32(parsed.destination.outputIndex); writer.u64(parsed.amountSats); writer.u64(parsed.changeSats);
  writer.u64(parsed.feeSats); writer.u32(parsed.vsize); writer.u64(parsed.feeRateSatPerKvB); writer.u8(1);
  writer.u32(parsed.assetEffects.length); for (const effect of parsed.assetEffects) writeAssetEffect(writer, effect);
  writer.fixedHex(parsed.source.backendInstanceIdHash, 32);
  writer.fixedHex(parsed.source.classificationRevisionHash, 32);
  writer.u32(parsed.source.coreTip.height); writer.fixedHex(parsed.source.coreTip.hash, 32);
  writer.u32(parsed.source.indexTip.height); writer.fixedHex(parsed.source.indexTip.hash, 32);
  writer.u64(parsed.source.observedAtMs); writer.u64(parsed.source.validUntilMs);
  writer.u8(enumByte(parsed.replacement.kind, { none: 0, rbf: 1, cpfp: 2 }));
  writer.u8(parsed.replacement.replacesTxid === null ? 0 : 1);
  if (parsed.replacement.replacesTxid !== null) writer.fixedHex(parsed.replacement.replacesTxid, 32);
  writer.u8(parsed.replacement.parentTxid === null ? 0 : 1);
  if (parsed.replacement.parentTxid !== null) writer.fixedHex(parsed.replacement.parentTxid, 32);
  writer.u8(parsed.broadcastIntent === 'broadcast' ? 0 : 1);
  return writer.finish();
}

export function computeVaultPlanDigest(plan: VaultUnsignedPlanV1): string {
  return digest('drey-vault-plan-v1', canonicalVaultPlanBytes(plan));
}

export function finalizeVaultUnsignedPlan(input: Omit<VaultUnsignedPlanV1, 'planDigest'>): VaultUnsignedPlanV1 {
  const candidate = vaultUnsignedPlanSchema.parse({ ...input, planDigest: '00'.repeat(32) });
  return vaultUnsignedPlanSchema.parse({ ...candidate, planDigest: computeVaultPlanDigest(candidate) });
}

export function assertVaultUnsignedPlan(plan: VaultUnsignedPlanV1): void {
  const parsed = vaultUnsignedPlanSchema.parse(plan);
  if (computeVaultPlanDigest(parsed) !== parsed.planDigest) throw new Error('vault planDigest mismatch');
}

export function parseCanonicalVaultPlan(bytes: Uint8Array): VaultUnsignedPlanV1 {
  const reader = new Reader(bytes);
  reader.header(RECORD.unsignedPlan);
  if (reader.u8() !== 1) throw new Error('unknown vault policy version');
  const network = readNetwork(reader); const policyId = reader.fixedHex(32); const planId = reader.fixedHex(16);
  const requestId = reader.fixedHex(16); const createdAtMs = reader.u64(); const expiresAtMs = reader.u64();
  const kind = decodeEnum(reader.u8(), ['withdrawal', 'recovery', 'rotation'], 'plan kind');
  const unsignedTransactionHex = reader.hex();
  const inputCount = reader.u32(); if (inputCount === 0 || inputCount > 10_000) throw new Error('invalid plan input count');
  const inputs: VaultPlanInputV1[] = []; for (let i = 0; i < inputCount; i += 1) inputs.push(readPlanInput(reader));
  const outputCount = reader.u32(); if (outputCount === 0 || outputCount > 10_000) throw new Error('invalid plan output count');
  const outputs: VaultPlanOutputV1[] = []; for (let i = 0; i < outputCount; i += 1) outputs.push(readPlanOutput(reader));
  const destinationKind = decodeEnum(reader.u8(), ['paired-spending', 'vault-policy', 'recovery-exit'], 'destination kind');
  const spendingTag = reader.u8();
  const pairedSpendingWalletIdHash = spendingTag === 0 ? null
    : spendingTag === 1 ? reader.fixedHex(32) : (() => { throw new Error('unknown spending-wallet tag'); })();
  const policyTag = reader.u8();
  const targetPolicyId = policyTag === 0 ? null
    : policyTag === 1 ? reader.fixedHex(32) : (() => { throw new Error('unknown target-policy tag'); })();
  const destination = {
    kind: destinationKind, pairedSpendingWalletIdHash, targetPolicyId,
    address: reader.text(), outputIndex: reader.u32(),
  };
  const amountSats = reader.u64(); const changeSats = reader.u64(); const feeSats = reader.u64(); const vsize = reader.u32();
  const feeRateSatPerKvB = reader.u64();
  if (reader.u8() !== 1) throw new Error('unsupported vault sighash');
  const effectCount = reader.u32(); if (effectCount > 10_000) throw new Error('invalid asset-effect count');
  const assetEffects: VaultAssetEffectV1[] = []; for (let i = 0; i < effectCount; i += 1) assetEffects.push(readAssetEffect(reader));
  const source = {
    backendInstanceIdHash: reader.fixedHex(32), classificationRevisionHash: reader.fixedHex(32),
    coreTip: { height: reader.u32(), hash: reader.fixedHex(32) },
    indexTip: { height: reader.u32(), hash: reader.fixedHex(32) },
    observedAtMs: reader.u64(), validUntilMs: reader.u64(),
  };
  const replacementKind = decodeEnum(reader.u8(), ['none', 'rbf', 'cpfp'], 'replacement kind');
  const replacesTag = reader.u8();
  const replacesTxid = replacesTag === 0 ? null
    : replacesTag === 1 ? reader.fixedHex(32) : (() => { throw new Error('unknown replacement-txid tag'); })();
  const parentTag = reader.u8();
  const parentTxid = parentTag === 0 ? null
    : parentTag === 1 ? reader.fixedHex(32) : (() => { throw new Error('unknown parent-txid tag'); })();
  const broadcastIntent = decodeEnum(reader.u8(), ['broadcast', 'return-psbt'], 'broadcast intent');
  reader.done();
  return finalizeVaultUnsignedPlan({
    version: 1, policyVersion: 1, network, policyId, planId, requestId, createdAtMs, expiresAtMs,
    kind, unsignedTransactionHex, inputs, outputs, destination, amountSats, changeSats, feeSats, vsize,
    feeRateSatPerKvB, sighash: 'all', assetEffects, source,
    replacement: { kind: replacementKind, replacesTxid, parentTxid }, broadcastIntent,
  });
}

export function vaultPsbtHash(psbtHex: string): string {
  return digest('drey-vault-psbt-v1', hexToBytes(psbtHex));
}

export function serializeVaultPartialSignatureInput(value: VaultPartialSignatureInputV1): Uint8Array {
  const parsed = vaultPartialSignatureInputSchema.parse(value);
  const plan = parseCanonicalVaultPlan(hexToBytes(parsed.canonicalPlanHex));
  if (plan.network !== parsed.network || plan.policyId !== parsed.policyId || plan.planId !== parsed.planId ||
      plan.planDigest !== parsed.planDigest || vaultPsbtHash(parsed.psbtHex) !== parsed.psbtHash) {
    throw new Error('partial-signature input binding mismatch');
  }
  const writer = new Writer(); writer.header(RECORD.partialInput); writeNetwork(writer, parsed.network);
  writer.fixedHex(parsed.policyId, 32); writer.fixedHex(parsed.planId, 16); writer.fixedHex(parsed.planDigest, 32);
  writeRole(writer, parsed.role); writer.hex(parsed.canonicalPlanHex); writer.hex(parsed.psbtHex); writer.fixedHex(parsed.psbtHash, 32);
  return writer.finish();
}

export function parseVaultPartialSignatureInput(bytes: Uint8Array): VaultPartialSignatureInputV1 {
  const reader = new Reader(bytes); reader.header(RECORD.partialInput);
  const value = vaultPartialSignatureInputSchema.parse({
    version: 1, network: readNetwork(reader), policyId: reader.fixedHex(32), planId: reader.fixedHex(16),
    planDigest: reader.fixedHex(32), role: readRole(reader), canonicalPlanHex: reader.hex(),
    psbtHex: reader.hex(), psbtHash: reader.fixedHex(32),
  });
  reader.done();
  serializeVaultPartialSignatureInput(value);
  return value;
}

export function serializeVaultPartialSignatureResult(value: VaultPartialSignatureResultV1): Uint8Array {
  const parsed = vaultPartialSignatureResultSchema.parse(value);
  if (vaultPsbtHash(parsed.signedPsbtHex) !== parsed.signedPsbtHash) throw new Error('signed PSBT hash mismatch');
  const writer = new Writer(); writer.header(RECORD.partialResult); writeNetwork(writer, parsed.network);
  writer.fixedHex(parsed.policyId, 32); writer.fixedHex(parsed.planId, 16); writer.fixedHex(parsed.planDigest, 32);
  writeRole(writer, parsed.roleAdded); writer.fixedHex(parsed.priorPsbtHash, 32); writer.hex(parsed.signedPsbtHex);
  writer.fixedHex(parsed.signedPsbtHash, 32); return writer.finish();
}

export function parseVaultPartialSignatureResult(bytes: Uint8Array): VaultPartialSignatureResultV1 {
  const reader = new Reader(bytes); reader.header(RECORD.partialResult);
  const value = vaultPartialSignatureResultSchema.parse({
    version: 1, network: readNetwork(reader), policyId: reader.fixedHex(32), planId: reader.fixedHex(16),
    planDigest: reader.fixedHex(32), roleAdded: readRole(reader), priorPsbtHash: reader.fixedHex(32),
    signedPsbtHex: reader.hex(), signedPsbtHash: reader.fixedHex(32),
  });
  reader.done(); serializeVaultPartialSignatureResult(value); return value;
}

export function assertVaultPartialSignatureResult(
  input: VaultPartialSignatureInputV1,
  result: VaultPartialSignatureResultV1,
): void {
  serializeVaultPartialSignatureInput(input); serializeVaultPartialSignatureResult(result);
  if (input.network !== result.network || input.policyId !== result.policyId || input.planId !== result.planId ||
      input.planDigest !== result.planDigest || input.role !== result.roleAdded || input.psbtHash !== result.priorPsbtHash) {
    throw new Error('partial-signature result binding mismatch');
  }
}

export function serializeVaultRecoveryKit(value: VaultRecoveryKitV1): Uint8Array {
  const parsed = vaultRecoveryKitSchema.parse(value);
  const identity = vaultPolicyIdentitySchema.parse({
    version: 1, policyVersion: 1, network: parsed.network, threshold: 2, signers: parsed.signers,
    receiveDescriptor: parsed.receiveDescriptor, changeDescriptor: parsed.changeDescriptor, policyId: parsed.policyId,
  });
  assertVaultPolicyIdentity(identity);
  const writer = new Writer(); writer.header(RECORD.recoveryKit); writer.nested(canonicalVaultPolicyBytes(identity));
  writer.fixedHex(parsed.policyId, 32); writeMetadata(writer, {
    version: 1, createdAtMs: parsed.createdAtMs, birthdayHeight: parsed.birthdayHeight,
    vaultLabel: parsed.vaultLabel, signerLabels: parsed.signerLabels,
  });
  writer.text(parsed.firstReceiveAddress);
  writer.u32(parsed.compatibilityRequirements.length);
  for (const requirement of parsed.compatibilityRequirements) writer.text(requirement);
  writer.u8(parsed.minimumReaderVersion);
  writer.fixedHex(parsed.standaloneToolSourceDigest, 32); writer.fixedHex(parsed.standaloneToolArtifactDigest, 32);
  writer.text(parsed.recoveryInstructions); writer.text(parsed.rotationInstructions);
  writer.u8(parsed.recoveryInstructionsVersion); return writer.finish();
}

export function parseVaultRecoveryKit(bytes: Uint8Array): VaultRecoveryKitV1 {
  const reader = new Reader(bytes); reader.header(RECORD.recoveryKit);
  const identity = parseCanonicalVaultPolicy(reader.nested()); const policyId = reader.fixedHex(32);
  if (identity.policyId !== policyId) throw new Error('recovery-kit policyId mismatch');
  const metadata = readMetadata(reader); const firstReceiveAddress = reader.text();
  const requirementCount = reader.u32();
  if (requirementCount === 0 || requirementCount > 32) throw new Error('invalid compatibility requirement count');
  const compatibilityRequirements: string[] = [];
  for (let index = 0; index < requirementCount; index += 1) compatibilityRequirements.push(reader.text());
  if (reader.u8() !== 1) throw new Error('unsupported recovery-kit reader version');
  const standaloneToolSourceDigest = reader.fixedHex(32); const standaloneToolArtifactDigest = reader.fixedHex(32);
  const recoveryInstructions = reader.text(); const rotationInstructions = reader.text();
  if (reader.u8() !== 1) throw new Error('unsupported recovery instructions version');
  reader.done();
  return vaultRecoveryKitSchema.parse({
    version: 1, network: identity.network, policyVersion: 1, policyId, signers: identity.signers,
    receiveDescriptor: identity.receiveDescriptor, changeDescriptor: identity.changeDescriptor,
    createdAtMs: metadata.createdAtMs, birthdayHeight: metadata.birthdayHeight, vaultLabel: metadata.vaultLabel,
    signerLabels: metadata.signerLabels, firstReceiveAddress, compatibilityRequirements, minimumReaderVersion: 1,
    standaloneToolSourceDigest, standaloneToolArtifactDigest, recoveryInstructions, rotationInstructions,
    recoveryInstructionsVersion: 1,
  });
}

function pairingPayloadHash(payloadHex: string): string { return digest('drey-vault-pairing-payload-v1', hexToBytes(payloadHex)); }
function approvalPayloadHash(payloadHex: string): string { return digest('drey-vault-approval-payload-v1', hexToBytes(payloadHex)); }

/** Stable public transport identifier for one signer origin. */
export function vaultTransportChannelId(origin: VaultSignerOriginV1): string {
  return digest('drey-vault-channel-v1', serializeVaultSignerOrigin(origin));
}

function writePairingAuthenticationFields(writer: Writer, parsed: VaultPairingEnvelopeV1): void {
  writeNetwork(writer, parsed.network); writer.fixedHex(parsed.sessionIdHex, 16);
  writer.hex(parsed.senderOriginHex);
  writer.fixedHex(parsed.senderChannelIdHex, 32); writer.fixedHex(parsed.recipientChannelIdHex, 32);
  writer.u64(parsed.counter); writer.u64(parsed.createdAtMs); writer.u64(parsed.expiresAtMs);
  writer.fixedHex(parsed.antiReplayNonceHex, 32); writer.fixedHex(parsed.transcriptHashHex, 32);
  writer.u8(enumByte(parsed.messageType, { 'signer-origin': 0, 'pop-input': 1, 'pop-result': 2, policy: 3 }));
  writer.hex(parsed.payloadHex); writer.fixedHex(parsed.payloadHash, 32);
}

function writeApprovalAuthenticationFields(writer: Writer, parsed: VaultPsbtApprovalEnvelopeV1): void {
  writeNetwork(writer, parsed.network); writer.fixedHex(parsed.policyId, 32); writer.fixedHex(parsed.planId, 16);
  writer.fixedHex(parsed.planDigest, 32); writer.hex(parsed.senderOriginHex); writer.fixedHex(parsed.senderChannelIdHex, 32);
  writer.fixedHex(parsed.recipientChannelIdHex, 32); writer.u64(parsed.counter); writer.u64(parsed.expiresAtMs);
  writer.fixedHex(parsed.antiReplayNonceHex, 32); writer.fixedHex(parsed.transcriptHashHex, 32);
  writer.u8(parsed.stage === 'request' ? 0 : 1); writer.hex(parsed.payloadHex); writer.fixedHex(parsed.payloadHash, 32);
}

export function vaultPairingEnvelopeAuthenticationDigest(value: VaultPairingEnvelopeV1): string {
  const parsed = vaultPairingEnvelopeSchema.parse(value);
  validatePairingPayload(parsed.messageType, parsed.payloadHex, parsed.network);
  if (pairingPayloadHash(parsed.payloadHex) !== parsed.payloadHash) throw new Error('pairing payload hash mismatch');
  const writer = new Writer(); writePairingAuthenticationFields(writer, parsed);
  return digest('drey-vault-pairing-envelope-auth-v1', writer.finish());
}

export function vaultPsbtApprovalEnvelopeAuthenticationDigest(value: VaultPsbtApprovalEnvelopeV1): string {
  const parsed = vaultPsbtApprovalEnvelopeSchema.parse(value);
  validateApprovalPayload(parsed.stage, parsed.payloadHex, parsed);
  if (approvalPayloadHash(parsed.payloadHex) !== parsed.payloadHash) throw new Error('approval payload hash mismatch');
  const writer = new Writer(); writeApprovalAuthenticationFields(writer, parsed);
  return digest('drey-vault-approval-envelope-auth-v1', writer.finish());
}

function signTransportDigest(
  signerRoot: HDKey,
  origin: VaultSignerOriginV1,
  digestHex: string,
): string {
  const parsedOrigin = vaultSignerOriginSchema.parse(origin);
  if (parsedOrigin.originPath !== vaultAccountOriginPath(parsedOrigin.network)) {
    throw new Error('transport signer origin path is not the Vault BIP48 account');
  }
  const account = signerRoot.derive(parsedOrigin.originPath);
  const child = account.deriveChild(0).deriveChild(0);
  try {
    if (!child.privateKey || !child.publicKey) throw new Error('transport authentication key is unavailable');
    const advertised = HDKey.fromExtendedKey(parsedOrigin.accountXpub, bip32Versions(parsedOrigin.network))
      .deriveChild(0).deriveChild(0).publicKey;
    if (!advertised || bytesToHex(child.publicKey) !== bytesToHex(advertised)) {
      throw new Error('transport signer does not hold the sender origin');
    }
    return bytesToHex(secp256k1.sign(hexToBytes(digestHex), child.privateKey, {
      prehash: false,
      lowS: true,
    }).toCompactRawBytes());
  } finally {
    child.wipePrivateData();
    account.wipePrivateData();
  }
}

function verifyTransportDigest(
  origin: VaultSignerOriginV1,
  digestHex: string,
  signatureHex: string,
): boolean {
  try {
    const parsedOrigin = vaultSignerOriginSchema.parse(origin);
    const account = HDKey.fromExtendedKey(parsedOrigin.accountXpub, bip32Versions(parsedOrigin.network));
    const child = account.deriveChild(0).deriveChild(0);
    if (!child.publicKey) return false;
    return secp256k1.verify(hexToBytes(signatureHex), hexToBytes(digestHex), child.publicKey, {
      format: 'compact', prehash: false, lowS: true,
    });
  } catch {
    return false;
  }
}

function validatePairingPayload(messageType: VaultPairingMessageType, payloadHex: string, network: Network): void {
  const payload = hexToBytes(payloadHex);
  const parsedNetwork = messageType === 'signer-origin' ? parseVaultSignerOrigin(payload).network
    : messageType === 'pop-input' ? parseVaultProofInput(payload).origin.network
      : messageType === 'policy' ? parseCanonicalVaultPolicy(payload).network : null;
  if (messageType === 'pop-result') parseVaultProofResult(payload);
  if (parsedNetwork !== null && parsedNetwork !== network) throw new Error('pairing payload network mismatch');
}

export function serializeVaultPairingEnvelope(value: VaultPairingEnvelopeV1): Uint8Array {
  const parsed = vaultPairingEnvelopeSchema.parse(value);
  validatePairingPayload(parsed.messageType, parsed.payloadHex, parsed.network);
  if (pairingPayloadHash(parsed.payloadHex) !== parsed.payloadHash) throw new Error('pairing payload hash mismatch');
  const writer = new Writer(); writer.header(RECORD.pairingEnvelope); writeNetwork(writer, parsed.network);
  writer.fixedHex(parsed.sessionIdHex, 16); writer.hex(parsed.senderOriginHex); writer.fixedHex(parsed.senderChannelIdHex, 32);
  writer.fixedHex(parsed.recipientChannelIdHex, 32); writer.u64(parsed.counter); writer.u64(parsed.createdAtMs);
  writer.u64(parsed.expiresAtMs); writer.fixedHex(parsed.antiReplayNonceHex, 32);
  writer.fixedHex(parsed.transcriptHashHex, 32);
  writer.u8(enumByte(parsed.messageType, { 'signer-origin': 0, 'pop-input': 1, 'pop-result': 2, policy: 3 }));
  writer.hex(parsed.payloadHex); writer.fixedHex(parsed.payloadHash, 32);
  writer.fixedHex(parsed.authenticationSignatureHex, 64); writer.u8(0); return writer.finish();
}

export function finalizeVaultPairingEnvelope(input: Omit<VaultPairingEnvelopeV1, 'payloadHash'>): VaultPairingEnvelopeV1 {
  return vaultPairingEnvelopeSchema.parse({ ...input, payloadHash: pairingPayloadHash(input.payloadHex) });
}

export function signVaultPairingEnvelope(
  input: Omit<VaultPairingEnvelopeV1, 'senderOriginHex' | 'payloadHash' | 'authenticationSignatureHex'>,
  signerRoot: HDKey,
  senderOrigin: VaultSignerOriginV1,
): VaultPairingEnvelopeV1 {
  const candidate = vaultPairingEnvelopeSchema.parse({
    ...input,
    senderOriginHex: bytesToHex(serializeVaultSignerOrigin(senderOrigin)),
    payloadHash: pairingPayloadHash(input.payloadHex),
    authenticationSignatureHex: '00'.repeat(64),
  });
  if (candidate.network !== senderOrigin.network ||
      candidate.senderChannelIdHex !== vaultTransportChannelId(senderOrigin)) {
    throw new Error('pairing envelope sender does not match the authenticating origin');
  }
  const authenticated = {
    ...candidate,
    authenticationSignatureHex: signTransportDigest(
      signerRoot,
      senderOrigin,
      vaultPairingEnvelopeAuthenticationDigest(candidate),
    ),
  };
  if (!verifyVaultPairingEnvelopeAuthentication(authenticated, senderOrigin)) {
    throw new Error('fresh pairing envelope authentication did not verify');
  }
  return authenticated;
}

export function verifyVaultPairingEnvelopeAuthentication(
  envelope: VaultPairingEnvelopeV1,
  expectedSenderOrigin?: VaultSignerOriginV1,
): boolean {
  try {
    const parsed = vaultPairingEnvelopeSchema.parse(envelope);
    const senderOrigin = parseVaultSignerOrigin(hexToBytes(parsed.senderOriginHex));
    if (expectedSenderOrigin !== undefined &&
        parsed.senderOriginHex !== bytesToHex(serializeVaultSignerOrigin(expectedSenderOrigin))) return false;
    return parsed.network === senderOrigin.network &&
      parsed.senderChannelIdHex === vaultTransportChannelId(senderOrigin) &&
      verifyTransportDigest(
        senderOrigin,
        vaultPairingEnvelopeAuthenticationDigest(parsed),
        parsed.authenticationSignatureHex,
      );
  } catch {
    return false;
  }
}

export function parseVaultPairingEnvelope(bytes: Uint8Array): VaultPairingEnvelopeV1 {
  const reader = new Reader(bytes); reader.header(RECORD.pairingEnvelope);
  const value = vaultPairingEnvelopeSchema.parse({
    version: 1, network: readNetwork(reader), sessionIdHex: reader.fixedHex(16),
    senderOriginHex: reader.hex(),
    senderChannelIdHex: reader.fixedHex(32), recipientChannelIdHex: reader.fixedHex(32), counter: reader.u64(),
    createdAtMs: reader.u64(), expiresAtMs: reader.u64(), antiReplayNonceHex: reader.fixedHex(32),
    transcriptHashHex: reader.fixedHex(32),
    messageType: decodeEnum(reader.u8(), ['signer-origin', 'pop-input', 'pop-result', 'policy'], 'pairing message type'),
    payloadHex: reader.hex(), payloadHash: reader.fixedHex(32),
    authenticationSignatureHex: reader.fixedHex(64),
  });
  if (reader.u8() !== 0) throw new Error('unknown pairing authentication scheme');
  reader.done(); serializeVaultPairingEnvelope(value); return value;
}

function validateApprovalPayload(stage: VaultApprovalStage, payloadHex: string, envelope: VaultPsbtApprovalEnvelopeV1): void {
  const payload = stage === 'request'
    ? parseVaultPartialSignatureInput(hexToBytes(payloadHex))
    : parseVaultPartialSignatureResult(hexToBytes(payloadHex));
  if (payload.network !== envelope.network || payload.policyId !== envelope.policyId ||
      payload.planId !== envelope.planId || payload.planDigest !== envelope.planDigest) {
    throw new Error('approval payload binding mismatch');
  }
}

export function serializeVaultPsbtApprovalEnvelope(value: VaultPsbtApprovalEnvelopeV1): Uint8Array {
  const parsed = vaultPsbtApprovalEnvelopeSchema.parse(value);
  validateApprovalPayload(parsed.stage, parsed.payloadHex, parsed);
  if (approvalPayloadHash(parsed.payloadHex) !== parsed.payloadHash) throw new Error('approval payload hash mismatch');
  const writer = new Writer(); writer.header(RECORD.approvalEnvelope); writeNetwork(writer, parsed.network);
  writer.fixedHex(parsed.policyId, 32); writer.fixedHex(parsed.planId, 16); writer.fixedHex(parsed.planDigest, 32);
  writer.hex(parsed.senderOriginHex);
  writer.fixedHex(parsed.senderChannelIdHex, 32); writer.fixedHex(parsed.recipientChannelIdHex, 32);
  writer.u64(parsed.counter); writer.u64(parsed.expiresAtMs); writer.fixedHex(parsed.antiReplayNonceHex, 32);
  writer.fixedHex(parsed.transcriptHashHex, 32); writer.u8(parsed.stage === 'request' ? 0 : 1);
  writer.hex(parsed.payloadHex); writer.fixedHex(parsed.payloadHash, 32);
  writer.fixedHex(parsed.authenticationSignatureHex, 64); writer.u8(0); return writer.finish();
}

export function finalizeVaultPsbtApprovalEnvelope(
  input: Omit<VaultPsbtApprovalEnvelopeV1, 'payloadHash'>,
): VaultPsbtApprovalEnvelopeV1 {
  return vaultPsbtApprovalEnvelopeSchema.parse({ ...input, payloadHash: approvalPayloadHash(input.payloadHex) });
}

export function signVaultPsbtApprovalEnvelope(
  input: Omit<VaultPsbtApprovalEnvelopeV1, 'senderOriginHex' | 'payloadHash' | 'authenticationSignatureHex'>,
  signerRoot: HDKey,
  senderOrigin: VaultSignerOriginV1,
): VaultPsbtApprovalEnvelopeV1 {
  const candidate = vaultPsbtApprovalEnvelopeSchema.parse({
    ...input,
    senderOriginHex: bytesToHex(serializeVaultSignerOrigin(senderOrigin)),
    payloadHash: approvalPayloadHash(input.payloadHex),
    authenticationSignatureHex: '00'.repeat(64),
  });
  if (candidate.network !== senderOrigin.network ||
      candidate.senderChannelIdHex !== vaultTransportChannelId(senderOrigin)) {
    throw new Error('approval envelope sender does not match the authenticating origin');
  }
  const authenticated = {
    ...candidate,
    authenticationSignatureHex: signTransportDigest(
      signerRoot,
      senderOrigin,
      vaultPsbtApprovalEnvelopeAuthenticationDigest(candidate),
    ),
  };
  if (!verifyVaultPsbtApprovalEnvelopeAuthentication(authenticated, senderOrigin)) {
    throw new Error('fresh approval envelope authentication did not verify');
  }
  return authenticated;
}

export function verifyVaultPsbtApprovalEnvelopeAuthentication(
  envelope: VaultPsbtApprovalEnvelopeV1,
  expectedSenderOrigin?: VaultSignerOriginV1,
): boolean {
  try {
    const parsed = vaultPsbtApprovalEnvelopeSchema.parse(envelope);
    const senderOrigin = parseVaultSignerOrigin(hexToBytes(parsed.senderOriginHex));
    if (expectedSenderOrigin !== undefined &&
        parsed.senderOriginHex !== bytesToHex(serializeVaultSignerOrigin(expectedSenderOrigin))) return false;
    return parsed.network === senderOrigin.network &&
      parsed.senderChannelIdHex === vaultTransportChannelId(senderOrigin) &&
      verifyTransportDigest(
        senderOrigin,
        vaultPsbtApprovalEnvelopeAuthenticationDigest(parsed),
        parsed.authenticationSignatureHex,
      );
  } catch {
    return false;
  }
}

export function parseVaultPsbtApprovalEnvelope(bytes: Uint8Array): VaultPsbtApprovalEnvelopeV1 {
  const reader = new Reader(bytes); reader.header(RECORD.approvalEnvelope);
  const value = vaultPsbtApprovalEnvelopeSchema.parse({
    version: 1, network: readNetwork(reader), policyId: reader.fixedHex(32), planId: reader.fixedHex(16),
    planDigest: reader.fixedHex(32), senderOriginHex: reader.hex(), senderChannelIdHex: reader.fixedHex(32),
    recipientChannelIdHex: reader.fixedHex(32),
    counter: reader.u64(), expiresAtMs: reader.u64(), antiReplayNonceHex: reader.fixedHex(32),
    transcriptHashHex: reader.fixedHex(32), stage: decodeEnum(reader.u8(), ['request', 'partial-signature'], 'approval stage'),
    payloadHex: reader.hex(), payloadHash: reader.fixedHex(32),
    authenticationSignatureHex: reader.fixedHex(64),
  });
  if (reader.u8() !== 0) throw new Error('unknown approval authentication scheme');
  reader.done(); serializeVaultPsbtApprovalEnvelope(value); return value;
}
