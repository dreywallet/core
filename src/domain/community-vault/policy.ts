/** Community Vault v1 policy construction, commitments, and recovery. */
import { HDKey } from '@scure/bip32';
import {
  Address,
  NETWORK,
  OutScript,
  TAPROOT_UNSPENDABLE_KEY,
  TaprootControlBlock,
  p2tr,
  p2tr_ms,
} from '@scure/btc-signer';
import { descriptorChecksum } from '../keys/descriptor-checksum';
import { bip32Versions } from '../keys/extended-key';
import { getCryptoProvider } from '../vault/crypto-provider';
import { bytesToHex, hexToBytes, utf8ToBytes } from '../vault/encoding';
import {
  COMMUNITY_VAULT_CONTRACT_VERSION,
  COMMUNITY_VAULT_ELIGIBILITY,
  COMMUNITY_VAULT_MODES,
  COMMUNITY_VAULT_NETWORK,
  COMMUNITY_VAULT_NUMS_INTERNAL_KEY,
  COMMUNITY_VAULT_POLICY_VERSION,
  COMMUNITY_VAULT_RECOVERY_INSTRUCTIONS,
  COMMUNITY_VAULT_SIGHASH,
  COMMUNITY_VAULT_THRESHOLD,
  COMMUNITY_VAULT_UNIT_COUNT,
  communityVaultPolicyInputSchema,
  communityVaultPolicySchema,
  type CommunityVaultOwnerInputV1,
  type CommunityVaultPolicyInputV1,
  type CommunityVaultPolicyV1,
  type CommunityVaultRecoveryKitV1,
  type CommunityVaultUnitV1,
} from './contracts';

const POLICY_INPUT_MAGIC = Uint8Array.of(0x44, 0x43, 0x56, 0x49); // DCVI
const CAP_TABLE_DOMAIN = 'drey-community-vault-cap-table-v1';
const POLICY_DOMAIN = 'drey-community-vault-policy-v1';
const MAX_POLICY_BYTES = 200_000;

class Writer {
  private readonly parts: Uint8Array[] = [];
  bytes(value: Uint8Array): void {
    this.u32(value.length);
    this.parts.push(value);
  }
  fixed(value: Uint8Array): void { this.parts.push(value); }
  text(value: string): void { this.bytes(utf8ToBytes(value)); }
  hex(value: string): void { this.bytes(hexToBytes(value)); }
  u8(value: number): void {
    if (!Number.isInteger(value) || value < 0 || value > 0xff) throw new Error('Community Vault u8 out of range');
    this.parts.push(Uint8Array.of(value));
  }
  u32(value: number): void {
    if (!Number.isInteger(value) || value < 0 || value > 0xffff_ffff) throw new Error('Community Vault u32 out of range');
    const out = new Uint8Array(4);
    new DataView(out.buffer).setUint32(0, value, false);
    this.parts.push(out);
  }
  finish(): Uint8Array {
    const size = this.parts.reduce((sum, part) => sum + part.length, 0);
    if (size > MAX_POLICY_BYTES) throw new Error('Community Vault policy bytes exceed limit');
    const out = new Uint8Array(size);
    let offset = 0;
    for (const part of this.parts) { out.set(part, offset); offset += part.length; }
    return out;
  }
}

class Reader {
  private offset = 0;
  constructor(private readonly bytes: Uint8Array) {
    if (bytes.length > MAX_POLICY_BYTES) throw new Error('Community Vault policy bytes exceed limit');
  }
  take(length: number): Uint8Array {
    if (!Number.isInteger(length) || length < 0 || this.offset + length > this.bytes.length) {
      throw new Error('truncated Community Vault policy bytes');
    }
    const out = this.bytes.slice(this.offset, this.offset + length);
    this.offset += length;
    return out;
  }
  u8(): number { return this.take(1)[0]!; }
  u32(): number {
    const value = this.take(4);
    return new DataView(value.buffer, value.byteOffset, 4).getUint32(0, false);
  }
  field(): Uint8Array {
    const length = this.u32();
    if (length > MAX_POLICY_BYTES) throw new Error('Community Vault field exceeds limit');
    return this.take(length);
  }
  text(): string { return new TextDecoder('utf-8', { fatal: true }).decode(this.field()); }
  hex(): string { return bytesToHex(this.field()); }
  done(): void { if (this.offset !== this.bytes.length) throw new Error('trailing Community Vault policy bytes'); }
}

function domainHash(domain: string, value: Uint8Array): string {
  const prefix = utf8ToBytes(domain);
  const input = new Uint8Array(prefix.length + 1 + value.length);
  input.set(prefix);
  input[prefix.length] = 0;
  input.set(value, prefix.length + 1);
  return bytesToHex(getCryptoProvider().sha256(input));
}

function fingerprintHex(key: HDKey): string {
  return key.fingerprint.toString(16).padStart(8, '0');
}

function canonicalOwners(owners: readonly CommunityVaultOwnerInputV1[]): CommunityVaultOwnerInputV1[] {
  return owners.map((owner) => ({
    ...owner,
    campaignRoot: { ...owner.campaignRoot },
    units: [...owner.units].sort((left, right) => left - right),
  })).sort((left, right) => left.capTableOrder - right.capTableOrder);
}

function assertPayout(owner: CommunityVaultOwnerInputV1): void {
  let script: Uint8Array;
  try {
    script = OutScript.encode(Address(NETWORK).decode(owner.payoutAddress));
  } catch {
    throw new Error(`owner ${owner.ownerId} payout address is not canonical mainnet`);
  }
  if (bytesToHex(script) !== owner.payoutScriptPubKeyHex) {
    throw new Error(`owner ${owner.ownerId} payout script differs from address`);
  }
}

function assertCapTableRules(input: CommunityVaultPolicyInputV1): CommunityVaultOwnerInputV1[] {
  const owners = canonicalOwners(input.owners);
  const unique = <T>(values: readonly T[], label: string) => {
    if (new Set(values).size !== values.length) throw new Error(`duplicate Community Vault ${label}`);
  };
  unique(owners.map((owner) => owner.ownerId), 'owner id');
  unique(owners.map((owner) => owner.capTableOrder), 'cap-table order');
  unique(owners.map((owner) => owner.identityCommitmentHex), 'recognized identity commitment');
  unique(owners.map((owner) => owner.campaignRoot.masterFingerprintHex), 'campaign-root fingerprint');
  unique(owners.map((owner) => owner.campaignRoot.campaignXpub), 'campaign root');
  if (owners.some((owner, index) => owner.capTableOrder !== index)) {
    throw new Error('Community Vault cap-table order must be contiguous from zero');
  }
  const creator = owners.find((owner) => owner.ownerId === input.creatorOwnerId);
  if (!creator) throw new Error('Community Vault creator is absent from cap table');
  const allUnits = owners.flatMap((owner) => owner.units);
  unique(allUnits, 'unit assignment');
  if (allUnits.length !== COMMUNITY_VAULT_UNIT_COUNT ||
      [...allUnits].sort((a, b) => a - b).some((unit, index) => unit !== index)) {
    throw new Error('Community Vault must assign every numbered unit 0 through 99 exactly once');
  }
  for (const owner of owners) {
    assertPayout(owner);
    if (input.mode === 'anchored') {
      if (owner.ownerId === creator.ownerId ? owner.units.length !== 33 : owner.units.length > 20) {
        throw new Error('Anchored Community Vault requires creator 33 and every other identity at most 20 units');
      }
    } else if (owner.units.length > 20) {
      throw new Error('Open Community Vault limits every recognized identity to 20 units');
    }
  }
  if (input.mode === 'open' && (creator.units.length < 1 || creator.units.length > 20)) {
    throw new Error('Open Community Vault creator must own 1 through 20 units');
  }
  return owners;
}

function deriveUnits(owners: readonly CommunityVaultOwnerInputV1[]): CommunityVaultUnitV1[] {
  const units: CommunityVaultUnitV1[] = [];
  for (const owner of owners) {
    let root: HDKey;
    try {
      root = HDKey.fromExtendedKey(owner.campaignRoot.campaignXpub, bip32Versions('mainnet'));
    } catch {
      throw new Error(`owner ${owner.ownerId} campaign root is not a valid mainnet xpub`);
    }
    if (root.depth !== 0 || root.index !== 0 || root.privateKey || !root.publicKey ||
        fingerprintHex(root) !== owner.campaignRoot.masterFingerprintHex ||
        root.publicExtendedKey !== owner.campaignRoot.campaignXpub) {
      throw new Error(`owner ${owner.ownerId} campaign root must be an independent BIP32 master xpub`);
    }
    for (const unit of owner.units) {
      const child = root.deriveChild(unit);
      try {
        if (!child.publicKey || child.depth !== 1 || child.index !== unit) {
          throw new Error(`owner ${owner.ownerId} unit ${unit} child key is unavailable`);
        }
        units.push({
          unit,
          ownerId: owner.ownerId,
          capTableOrder: owner.capTableOrder,
          masterFingerprintHex: owner.campaignRoot.masterFingerprintHex,
          originPath: 'm',
          campaignXpub: owner.campaignRoot.campaignXpub,
          derivationPath: `m/${unit}`,
          publicKeyHex: bytesToHex(child.publicKey.slice(1)),
        });
      } finally {
        child.wipePrivateData();
      }
    }
    root.wipePrivateData();
  }
  units.sort((left, right) => left.unit - right.unit);
  if (new Set(units.map((unit) => unit.publicKeyHex)).size !== COMMUNITY_VAULT_UNIT_COUNT) {
    throw new Error('Community Vault unit public keys must all be distinct');
  }
  return units;
}

function canonicalDescriptor(units: readonly CommunityVaultUnitV1[]): string {
  const payload = `tr(${COMMUNITY_VAULT_NUMS_INTERNAL_KEY},multi_a(${COMMUNITY_VAULT_THRESHOLD},${units.map((unit) => unit.publicKeyHex).join(',')}))`;
  return `${payload}#${descriptorChecksum(payload)}`;
}

function encodePolicyInput(input: CommunityVaultPolicyInputV1): Uint8Array {
  const writer = new Writer();
  writer.fixed(POLICY_INPUT_MAGIC);
  writer.u8(COMMUNITY_VAULT_CONTRACT_VERSION);
  writer.u8(COMMUNITY_VAULT_POLICY_VERSION);
  writer.u8(0); // mainnet
  writer.text(input.campaignId);
  writer.text(input.inscriptionId);
  writer.fixed(hexToBytes(input.currentOutpoint.txid));
  writer.u32(input.currentOutpoint.vout);
  writer.u8(COMMUNITY_VAULT_MODES.indexOf(input.mode));
  writer.u8(COMMUNITY_VAULT_ELIGIBILITY.indexOf(input.eligibility));
  writer.text(input.creatorOwnerId);
  writer.text(input.termsVersion);
  writer.u32(input.capTableVersion);
  writer.u32(input.owners.length);
  for (const owner of input.owners) {
    writer.text(owner.ownerId);
    writer.u8(owner.capTableOrder);
    writer.fixed(hexToBytes(owner.identityCommitmentHex));
    writer.text(owner.payoutAddress);
    writer.hex(owner.payoutScriptPubKeyHex);
    writer.fixed(hexToBytes(owner.campaignRoot.masterFingerprintHex));
    writer.text(owner.campaignRoot.campaignXpub);
    writer.u32(owner.units.length);
    for (const unit of owner.units) writer.u8(unit);
  }
  return writer.finish();
}

function capTableBytes(inputBytes: Uint8Array, units: readonly CommunityVaultUnitV1[], descriptor: string): Uint8Array {
  const writer = new Writer();
  writer.bytes(inputBytes);
  writer.u32(units.length);
  for (const unit of units) {
    writer.u8(unit.unit);
    writer.text(unit.ownerId);
    writer.u8(unit.capTableOrder);
    writer.fixed(hexToBytes(unit.masterFingerprintHex));
    writer.text(unit.derivationPath);
    writer.fixed(hexToBytes(unit.publicKeyHex));
  }
  writer.text(descriptor);
  return writer.finish();
}

function policyIdentityBytes(policy: Omit<CommunityVaultPolicyV1, 'policyId'>): Uint8Array {
  const writer = new Writer();
  writer.bytes(encodePolicyInput(policy));
  writer.u8(policy.unitCount);
  writer.u8(policy.threshold);
  writer.u8(0); // SIGHASH_DEFAULT
  writer.fixed(hexToBytes(policy.internalKeyHex));
  writer.hex(policy.tapscriptHex);
  writer.fixed(hexToBytes(policy.tapLeafHashHex));
  writer.fixed(hexToBytes(policy.tapMerkleRootHex));
  writer.hex(policy.controlBlockHex);
  writer.hex(policy.scriptPubKeyHex);
  writer.text(policy.address);
  writer.text(policy.descriptor);
  writer.fixed(hexToBytes(policy.capTableHash));
  return writer.finish();
}

export function createCommunityVaultPolicy(raw: CommunityVaultPolicyInputV1): CommunityVaultPolicyV1 {
  const parsed = communityVaultPolicyInputSchema.parse(raw);
  const owners = assertCapTableRules(parsed);
  const input: CommunityVaultPolicyInputV1 = { ...parsed, currentOutpoint: { ...parsed.currentOutpoint }, owners };
  const units = deriveUnits(owners);
  if (bytesToHex(TAPROOT_UNSPENDABLE_KEY) !== COMMUNITY_VAULT_NUMS_INTERNAL_KEY) {
    throw new Error('signing library NUMS point differs from Community Vault v1');
  }
  const leaf = p2tr_ms(COMMUNITY_VAULT_THRESHOLD, units.map((unit) => hexToBytes(unit.publicKeyHex)));
  const output = p2tr(TAPROOT_UNSPENDABLE_KEY, { script: leaf.script }, NETWORK);
  const leafRecord = output.leaves[0];
  const leafScript = output.tapLeafScript?.[0];
  if (!leafRecord || !leafScript || output.leaves.length !== 1 || output.tapLeafScript?.length !== 1 ||
      leafRecord.path.length !== 0 || leafScript[0].merklePath.length !== 0) {
    throw new Error('Community Vault v1 must contain one exact Taproot leaf');
  }
  const descriptor = canonicalDescriptor(units);
  const inputBytes = encodePolicyInput(input);
  const capTableHash = domainHash(CAP_TABLE_DOMAIN, capTableBytes(inputBytes, units, descriptor));
  const withoutId: Omit<CommunityVaultPolicyV1, 'policyId'> = {
    ...input,
    unitCount: COMMUNITY_VAULT_UNIT_COUNT,
    threshold: COMMUNITY_VAULT_THRESHOLD,
    sighash: COMMUNITY_VAULT_SIGHASH,
    internalKeyHex: COMMUNITY_VAULT_NUMS_INTERNAL_KEY,
    units,
    tapscriptHex: bytesToHex(leaf.script),
    tapLeafHashHex: bytesToHex(leafRecord.hash),
    tapMerkleRootHex: bytesToHex(output.tapMerkleRoot),
    controlBlockHex: bytesToHex(TaprootControlBlock.encode(leafScript[0])),
    scriptPubKeyHex: bytesToHex(output.script),
    address: output.address,
    descriptor,
    capTableHash,
  };
  return communityVaultPolicySchema.parse({ ...withoutId, policyId: domainHash(POLICY_DOMAIN, policyIdentityBytes(withoutId)) });
}

export function canonicalCommunityVaultPolicyBytes(policy: CommunityVaultPolicyV1): Uint8Array {
  assertCommunityVaultPolicy(policy);
  return policyIdentityBytes(policy);
}

function policyInputFromPolicy(policy: CommunityVaultPolicyV1): CommunityVaultPolicyInputV1 {
  return {
    version: policy.version,
    policyVersion: policy.policyVersion,
    network: policy.network,
    campaignId: policy.campaignId,
    inscriptionId: policy.inscriptionId,
    currentOutpoint: { ...policy.currentOutpoint },
    mode: policy.mode,
    eligibility: policy.eligibility,
    creatorOwnerId: policy.creatorOwnerId,
    termsVersion: policy.termsVersion,
    capTableVersion: policy.capTableVersion,
    owners: policy.owners.map((owner) => ({
      ...owner,
      campaignRoot: { ...owner.campaignRoot },
      units: [...owner.units],
    })),
  };
}

export function assertCommunityVaultPolicy(policy: CommunityVaultPolicyV1): void {
  const parsed = communityVaultPolicySchema.parse(policy);
  const rebuilt = createCommunityVaultPolicy(policyInputFromPolicy(parsed));
  if (rebuilt.policyId !== parsed.policyId || rebuilt.capTableHash !== parsed.capTableHash ||
      bytesToHex(policyIdentityBytes(rebuilt)) !== bytesToHex(policyIdentityBytes(parsed)) ||
      bytesToHex(capTableBytes(encodePolicyInput(rebuilt), rebuilt.units, rebuilt.descriptor)) !==
        bytesToHex(capTableBytes(encodePolicyInput(parsed), parsed.units, parsed.descriptor))) {
    throw new Error('Community Vault policy does not reproduce its exact commitment');
  }
}

/** Compact canonical recovery encoding; all derived policy data is reproduced, not trusted. */
export function serializeCommunityVaultPolicy(policy: CommunityVaultPolicyV1): Uint8Array {
  assertCommunityVaultPolicy(policy);
  return encodePolicyInput(policy);
}

export function parseCommunityVaultPolicy(bytes: Uint8Array): CommunityVaultPolicyV1 {
  const reader = new Reader(bytes);
  if (bytesToHex(reader.take(4)) !== bytesToHex(POLICY_INPUT_MAGIC) || reader.u8() !== 1 || reader.u8() !== 1 || reader.u8() !== 0) {
    throw new Error('unknown Community Vault policy encoding');
  }
  const campaignId = reader.text();
  const inscriptionId = reader.text();
  const txid = bytesToHex(reader.take(32));
  const vout = reader.u32();
  const mode = COMMUNITY_VAULT_MODES[reader.u8()];
  const eligibility = COMMUNITY_VAULT_ELIGIBILITY[reader.u8()];
  if (!mode || !eligibility) throw new Error('unknown Community Vault mode or eligibility');
  const creatorOwnerId = reader.text();
  const termsVersion = reader.text();
  const capTableVersion = reader.u32();
  const ownerCount = reader.u32();
  if (ownerCount < 4 || ownerCount > 100) throw new Error('invalid Community Vault owner count');
  const owners: CommunityVaultOwnerInputV1[] = [];
  for (let index = 0; index < ownerCount; index += 1) {
    const ownerId = reader.text();
    const capTableOrder = reader.u8();
    const identityCommitmentHex = bytesToHex(reader.take(32));
    const payoutAddress = reader.text();
    const payoutScriptPubKeyHex = reader.hex();
    const masterFingerprintHex = bytesToHex(reader.take(4));
    const campaignXpub = reader.text();
    const unitCount = reader.u32();
    if (unitCount < 1 || unitCount > 33) throw new Error('invalid Community Vault owner unit count');
    const units = Array.from({ length: unitCount }, () => reader.u8());
    owners.push({
      ownerId, capTableOrder, identityCommitmentHex, payoutAddress, payoutScriptPubKeyHex,
      campaignRoot: { version: 1, masterFingerprintHex, originPath: 'm', campaignXpub }, units,
    });
  }
  reader.done();
  return createCommunityVaultPolicy({
    version: 1, policyVersion: 1, network: COMMUNITY_VAULT_NETWORK,
    campaignId, inscriptionId, currentOutpoint: { txid, vout }, mode, eligibility,
    creatorOwnerId, termsVersion, capTableVersion, owners,
  });
}

export function createCommunityVaultRecoveryKit(policy: CommunityVaultPolicyV1): CommunityVaultRecoveryKitV1 {
  assertCommunityVaultPolicy(policy);
  return {
    version: 1,
    policyVersion: 1,
    policy,
    policyBytesHex: bytesToHex(serializeCommunityVaultPolicy(policy)),
    recoveryInstructions: COMMUNITY_VAULT_RECOVERY_INSTRUCTIONS,
  };
}

export function recoverCommunityVaultPolicy(kit: CommunityVaultRecoveryKitV1): CommunityVaultPolicyV1 {
  if (kit.version !== 1 || kit.policyVersion !== 1 ||
      kit.recoveryInstructions !== COMMUNITY_VAULT_RECOVERY_INSTRUCTIONS) {
    throw new Error('unknown Community Vault recovery kit');
  }
  const recovered = parseCommunityVaultPolicy(hexToBytes(kit.policyBytesHex));
  assertCommunityVaultPolicy(kit.policy);
  if (recovered.policyId !== kit.policy.policyId || recovered.address !== kit.policy.address ||
      recovered.descriptor !== kit.policy.descriptor) {
    throw new Error('Community Vault recovery kit policy differs from recovery bytes');
  }
  return recovered;
}
