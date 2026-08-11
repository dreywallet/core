/**
 * ADR 0007 Workstream B1 descriptor, derivation, and ownership support.
 *
 * This is deliberately not a general descriptor parser. Policy version 1 accepts
 * exactly two separately checksummed native-P2WSH descriptors in logical A/B/C
 * source order. No caller-provided metadata can select another descriptor
 * fragment, threshold, origin, child path, key family, network, or script type.
 */
import { HDKey } from '@scure/bip32';
import { NETWORK, TEST_NETWORK, p2ms, p2wsh } from '@scure/btc-signer';
import { z } from 'zod';
import { assertBip32Index, type Network } from '../keys/derivation';
import { bytesToHex, hexToBytes } from './encoding';
import {
  VAULT_ROLES,
  bip32Versions,
  canonicalVaultDescriptor,
  descriptorChecksum,
  vaultPolicyRecordSchema,
  vaultSignerOriginSchema,
  type VaultBranch,
  type VaultPolicyIdentityV1,
  type VaultPolicyRecordV1,
  type VaultSignerOriginV1,
  type VaultSignerRole,
} from './multisig-contracts';
import {
  assertVaultPolicyIdentity,
  finalizeVaultPolicyIdentity,
} from './multisig-encoding';

const CHECKSUM_CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const DESCRIPTOR_PREFIX = 'wsh(sortedmulti(2,';
const DESCRIPTOR_SUFFIX = '))';
const KEY_EXPRESSION = /^\[([0-9a-f]{8})\/48h\/(0|1)h\/0h\/2h\]([1-9A-HJ-NP-Za-km-z]{111})\/(0|1)\/\*$/u;
const COMPRESSED_KEY = /^(?:02|03)[0-9a-f]{64}$/u;
const HEX_32 = /^[0-9a-f]{64}$/u;

export interface ParsedVaultDescriptorV1 {
  version: 1;
  network: Network;
  branch: VaultBranch;
  signers: [VaultSignerOriginV1, VaultSignerOriginV1, VaultSignerOriginV1];
  descriptor: string;
}

export interface VaultDescriptorPairV1 {
  version: 1;
  network: Network;
  policyId: string;
  receiveDescriptor: string;
  changeDescriptor: string;
}

export interface VaultDerivedKeyV1 {
  role: VaultSignerRole;
  masterFingerprintHex: string;
  originPath: string;
  accountXpub: string;
  derivationPath: string;
  publicKeyHex: string;
}

export interface VaultDerivedOutputV1 {
  version: 1;
  network: Network;
  policyId: string;
  branch: VaultBranch;
  index: number;
  logicalKeys: [VaultDerivedKeyV1, VaultDerivedKeyV1, VaultDerivedKeyV1];
  bip67SortedPublicKeysHex: [string, string, string];
  witnessScriptHex: string;
  scriptPubKeyHex: string;
  address: string;
}

const derivedKeySchema: z.ZodType<VaultDerivedKeyV1> = z.object({
  role: z.enum(VAULT_ROLES),
  masterFingerprintHex: z.string().regex(/^[0-9a-f]{8}$/u),
  originPath: z.string().min(1).max(64),
  accountXpub: z.string().min(1).max(128),
  derivationPath: z.string().min(1).max(96),
  publicKeyHex: z.string().regex(COMPRESSED_KEY),
}).strict();

export const vaultDerivedOutputSchema: z.ZodType<VaultDerivedOutputV1> = z.object({
  version: z.literal(1),
  network: z.enum(['mainnet', 'signet']),
  policyId: z.string().regex(HEX_32),
  branch: z.enum(['receive', 'change']),
  index: z.number().int().min(0).max(0x7fff_ffff),
  logicalKeys: z.tuple([derivedKeySchema, derivedKeySchema, derivedKeySchema]),
  bip67SortedPublicKeysHex: z.tuple([
    z.string().regex(COMPRESSED_KEY), z.string().regex(COMPRESSED_KEY), z.string().regex(COMPRESSED_KEY),
  ]),
  witnessScriptHex: z.string().regex(/^[0-9a-f]{210}$/u),
  scriptPubKeyHex: z.string().regex(/^[0-9a-f]{68}$/u),
  address: z.string().min(14).max(74),
}).strict();

function tupleSigners(signers: readonly VaultSignerOriginV1[]): [
  VaultSignerOriginV1,
  VaultSignerOriginV1,
  VaultSignerOriginV1,
] {
  if (signers.length !== 3) throw new Error('exactly three Vault signer origins required');
  return [signers[0]!, signers[1]!, signers[2]!];
}

function sameOrigin(left: VaultSignerOriginV1, right: VaultSignerOriginV1): boolean {
  return left.version === right.version && left.role === right.role && left.network === right.network &&
    left.masterFingerprintHex === right.masterFingerprintHex && left.originPath === right.originPath &&
    left.accountXpub === right.accountXpub;
}

function compareBytes(left: Uint8Array, right: Uint8Array): number {
  const length = Math.min(left.length, right.length);
  for (let index = 0; index < length; index += 1) {
    const difference = left[index]! - right[index]!;
    if (difference !== 0) return difference;
  }
  return left.length - right.length;
}

function descriptorParts(descriptor: string): { payload: string; checksum: string } {
  if (descriptor.length < 10 || descriptor.at(-9) !== '#') throw new Error('checksummed Vault descriptor required');
  const payload = descriptor.slice(0, -9);
  const checksum = descriptor.slice(-8);
  if (payload.includes('#') || checksum.length !== 8 ||
      [...checksum].some((character) => !CHECKSUM_CHARSET.includes(character))) {
    throw new Error('malformed Vault descriptor checksum');
  }
  if (descriptorChecksum(payload) !== checksum) throw new Error('Vault descriptor checksum mismatch');
  return { payload, checksum };
}

/** Parse only ADR 0007's canonical, ranged native-P2WSH descriptor grammar. */
export function parseCanonicalVaultDescriptor(descriptor: string): ParsedVaultDescriptorV1 {
  if (typeof descriptor !== 'string' || descriptor.length > 2048) throw new Error('invalid Vault descriptor');
  const { payload } = descriptorParts(descriptor);
  if (!payload.startsWith(DESCRIPTOR_PREFIX) || !payload.endsWith(DESCRIPTOR_SUFFIX)) {
    throw new Error('unsupported Vault descriptor fragment');
  }
  const expressions = payload.slice(DESCRIPTOR_PREFIX.length, -DESCRIPTOR_SUFFIX.length).split(',');
  if (expressions.length !== 3) throw new Error('Vault descriptor requires exactly three keys');

  let network: Network | undefined;
  let branch: VaultBranch | undefined;
  const signers = expressions.map((expression, index) => {
    const match = KEY_EXPRESSION.exec(expression);
    if (!match) throw new Error('non-canonical Vault key expression');
    const [, fingerprint, coinType, accountXpub, chain] = match;
    const expressionNetwork: Network = coinType === '0' ? 'mainnet' : 'signet';
    const expressionBranch: VaultBranch = chain === '0' ? 'receive' : 'change';
    if (network !== undefined && network !== expressionNetwork) throw new Error('mixed Vault descriptor networks');
    if (branch !== undefined && branch !== expressionBranch) throw new Error('mixed Vault descriptor branches');
    network = expressionNetwork;
    branch = expressionBranch;
    if ((expressionNetwork === 'mainnet' && !accountXpub!.startsWith('xpub')) ||
        (expressionNetwork === 'signet' && !accountXpub!.startsWith('tpub'))) {
      throw new Error('network-appropriate account xpub required');
    }
    return vaultSignerOriginSchema.parse({
      version: 1,
      role: VAULT_ROLES[index],
      network: expressionNetwork,
      masterFingerprintHex: fingerprint,
      originPath: `m/48'/${coinType}'/0'/2'`,
      accountXpub,
    });
  });
  if (network === undefined || branch === undefined) throw new Error('empty Vault descriptor');
  const signerTuple = tupleSigners(signers);
  for (const field of ['masterFingerprintHex', 'accountXpub'] as const) {
    if (new Set(signerTuple.map((signer) => signer[field])).size !== 3) {
      throw new Error(`duplicate Vault signer ${field}`);
    }
  }
  if (canonicalVaultDescriptor(signerTuple, branch) !== descriptor) {
    throw new Error('Vault descriptor is valid but not canonical v1');
  }
  return { version: 1, network, branch, signers: signerTuple, descriptor };
}

/** Generate the only B1 policy identity from canonical B0 signer origins. */
export function generateVaultPolicyIdentity(
  network: Network,
  signers: readonly VaultSignerOriginV1[],
): VaultPolicyIdentityV1 {
  const signerTuple = tupleSigners(signers).map((signer, index) => {
    const parsed = vaultSignerOriginSchema.parse(signer);
    if (parsed.network !== network || parsed.role !== VAULT_ROLES[index]) {
      throw new Error('Vault signers must match network and canonical A/B/C roles');
    }
    return parsed;
  }) as [VaultSignerOriginV1, VaultSignerOriginV1, VaultSignerOriginV1];
  return finalizeVaultPolicyIdentity({
    version: 1,
    policyVersion: 1,
    network,
    threshold: 2,
    signers: signerTuple,
    receiveDescriptor: canonicalVaultDescriptor(signerTuple, 'receive'),
    changeDescriptor: canonicalVaultDescriptor(signerTuple, 'change'),
  });
}

/** Regenerate both canonical descriptors from a fully validated B0 identity. */
export function generateVaultDescriptors(policy: VaultPolicyIdentityV1): VaultDescriptorPairV1 {
  assertVaultPolicyIdentity(policy);
  const receiveDescriptor = canonicalVaultDescriptor(policy.signers, 'receive');
  const changeDescriptor = canonicalVaultDescriptor(policy.signers, 'change');
  if (receiveDescriptor !== policy.receiveDescriptor || changeDescriptor !== policy.changeDescriptor) {
    throw new Error('B0 policy descriptors are not canonical Vault v1');
  }
  return {
    version: 1,
    network: policy.network,
    policyId: policy.policyId,
    receiveDescriptor,
    changeDescriptor,
  };
}

/** Reconstruct the identical B0 identity from its two separately checksummed descriptors. */
export function parseCanonicalVaultPolicyDescriptors(
  receiveDescriptor: string,
  changeDescriptor: string,
): VaultPolicyIdentityV1 {
  const receive = parseCanonicalVaultDescriptor(receiveDescriptor);
  const change = parseCanonicalVaultDescriptor(changeDescriptor);
  if (receive.branch !== 'receive' || change.branch !== 'change') {
    throw new Error('receive/change Vault descriptors are swapped or duplicated');
  }
  if (receive.network !== change.network ||
      receive.signers.some((signer, index) => !sameOrigin(signer, change.signers[index]!))) {
    throw new Error('Vault descriptor pair does not describe one complete policy');
  }
  return generateVaultPolicyIdentity(receive.network, receive.signers);
}

/** Validate descriptor normalization and identity without dropping B0 birthday metadata. */
export function validateVaultPolicyRecordDescriptors(record: VaultPolicyRecordV1): VaultPolicyRecordV1 {
  const parsed = vaultPolicyRecordSchema.parse(record);
  assertVaultDescriptorPolicy(parsed.identity);
  return parsed;
}

export function assertVaultDescriptorPolicy(policy: VaultPolicyIdentityV1): void {
  assertVaultPolicyIdentity(policy);
  const parsed = parseCanonicalVaultPolicyDescriptors(policy.receiveDescriptor, policy.changeDescriptor);
  if (parsed.policyId !== policy.policyId || parsed.network !== policy.network ||
      parsed.signers.some((signer, index) => !sameOrigin(signer, policy.signers[index]!))) {
    throw new Error('Vault descriptor pair does not round-trip to the B0 policy identity');
  }
}

function deriveExactChild(parent: HDKey, index: number, label: string): HDKey {
  const child = parent.deriveChild(index);
  // @scure follows BIP32's astronomically rare invalid-child retry. A policy
  // derivation must not silently claim that the following index was requested.
  if (child.index !== index) throw new Error(`invalid BIP32 ${label} child at requested index`);
  return child;
}

/** Derive all three keys, the exact BIP67 script, and native P2WSH output. */
export function deriveVaultOutput(
  policy: VaultPolicyIdentityV1,
  branch: VaultBranch,
  index: number,
): VaultDerivedOutputV1 {
  assertBip32Index(index, 'Vault derivation index');
  assertVaultDescriptorPolicy(policy);
  const chain = branch === 'receive' ? 0 : 1;
  const logicalKeys = policy.signers.map((signer) => {
    const account = HDKey.fromExtendedKey(signer.accountXpub, bip32Versions(policy.network));
    const branchNode = deriveExactChild(account, chain, 'branch');
    const child = deriveExactChild(branchNode, index, 'address');
    const publicKey = child.publicKey;
    if (!publicKey || publicKey.length !== 33 || (publicKey[0] !== 0x02 && publicKey[0] !== 0x03)) {
      throw new Error('compressed derived Vault public key required');
    }
    return {
      role: signer.role,
      masterFingerprintHex: signer.masterFingerprintHex,
      originPath: signer.originPath,
      accountXpub: signer.accountXpub,
      derivationPath: `${signer.originPath}/${chain}/${index}`,
      publicKeyHex: bytesToHex(publicKey),
    };
  }) as [VaultDerivedKeyV1, VaultDerivedKeyV1, VaultDerivedKeyV1];
  if (new Set(logicalKeys.map((key) => key.publicKeyHex)).size !== 3) {
    throw new Error('duplicate derived Vault public key');
  }
  const sortedPublicKeys = logicalKeys
    .map((key) => hexToBytes(key.publicKeyHex))
    .sort(compareBytes);
  const payment = p2wsh(p2ms(2, sortedPublicKeys), policy.network === 'mainnet' ? NETWORK : TEST_NETWORK);
  return vaultDerivedOutputSchema.parse({
    version: 1,
    network: policy.network,
    policyId: policy.policyId,
    branch,
    index,
    logicalKeys,
    bip67SortedPublicKeysHex: sortedPublicKeys.map(bytesToHex),
    witnessScriptHex: bytesToHex(payment.witnessScript),
    scriptPubKeyHex: bytesToHex(payment.script),
    address: payment.address,
  });
}

/**
 * Prove ownership only when every policy, origin, key, script, and address fact
 * matches an independently regenerated output.
 */
export function assertVaultOwnership(
  policy: VaultPolicyIdentityV1,
  candidate: unknown,
): VaultDerivedOutputV1 {
  const parsed = vaultDerivedOutputSchema.parse(candidate);
  const expected = deriveVaultOutput(policy, parsed.branch, parsed.index);
  if (JSON.stringify(parsed) !== JSON.stringify(expected)) throw new Error('complete Vault ownership proof mismatch');
  return expected;
}

export function verifyVaultOwnership(policy: VaultPolicyIdentityV1, candidate: unknown): boolean {
  try {
    assertVaultOwnership(policy, candidate);
    return true;
  } catch {
    return false;
  }
}
