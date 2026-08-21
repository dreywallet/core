/**
 * Vault signer-role production: BIP48 origin derivation, proof of possession,
 * and the ADR 0007 §1 independence checks.
 *
 * This is the *signer* half of the pairing contract whose *verifier* half lives
 * in `multisig-encoding.ts`. Until v0.2.13 core shipped only
 * `verifyVaultProofOfPossession`, and the production side lived in
 * `extension/src/background/vault-role.ts` on the argument that minting a proof
 * was coordinator-side work. A second signer — the mobile role B of
 * `docs/mobile-vault-roleb-work-plan.md` — makes that argument false: the
 * alternative to promoting this module was a second, independently maintained
 * copy of BIP48 derivation and low-S ECDSA production in a repository that
 * deliberately holds no key-schedule code at all. One construction, verified
 * against one set of golden vectors, is the whole point of the pin.
 *
 * The module is deliberately narrow. It turns a BIP39 seed into the *public*
 * signer-origin record the Workstream B contracts consume, proves possession of
 * that origin on demand, and enforces the §1 checks. It never persists,
 * transports, or logs a secret: the caller owns the seed bytes and zeroizes
 * them.
 *
 * Which network a build may hold a role on is release policy and belongs to the
 * consumer — `extension/src/background/vault-capability.ts` and
 * `mobile/src/vault-role/role-capability.ts` each own that decision. This
 * module only borrows the network, because a derivation needs to know which
 * BIP32 versions and BIP48 coin type to use and nothing else.
 */
import { HDKey } from '@scure/bip32';
import { secp256k1 } from '@noble/curves/secp256k1';
import type { Network } from '../keys/derivation';
import { bytesToHex, hexToBytes } from './encoding';
import {
  bip32Versions,
  vaultAccountOriginPath,
  vaultSignerOriginSchema,
  type VaultProofOfPossessionInputV1,
  type VaultProofOfPossessionResultV1,
  type VaultSignerOriginV1,
  type VaultSignerRole,
} from './multisig-contracts';
import {
  parseVaultSignerOrigin,
  serializeVaultSignerOrigin,
  vaultProofInputDigest,
  verifyVaultProofOfPossession,
} from './multisig-encoding';

/**
 * The derivation network for a role generated without one named.
 *
 * Signet, because every shipping Vault capability today is signet-only and a
 * mainnet Vault is gated behind the ADR 0007 §8 joint release gates. Production
 * callers on both platforms pass the network explicitly from their capability
 * value; this default exists so a signet-only caller cannot spell it wrong.
 * When mainnet acquires an inhabitant, prefer making the argument required over
 * changing what this resolves to.
 */
export const DEFAULT_VAULT_ROLE_NETWORK = 'signet' as const satisfies Network;

/**
 * An ADR 0007 §1 independence violation: the candidate role is the Spending
 * wallet, or derives from it, or collides with it at the BIP48 account level.
 * Distinct from a malformed-input error so a consumer can map it to its own
 * wire code and explain what actually happened.
 */
export class VaultRoleIndependenceError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'VaultRoleIndependenceError';
  }
}

/**
 * The BIP32 master node for a Vault role's seed on `network`.
 *
 * Exported because it is also what `signVaultPartialSignature` takes as its
 * `signerRoot`: both consumers were otherwise obliged to open-code
 * `HDKey.fromMasterSeed(seed, bip32Versions(network))`, and a signer that built
 * its root with the wrong version bytes would derive a plausible key for the
 * wrong chain. The caller owns the returned node and should
 * `wipePrivateData()` it.
 */
export function vaultSignerRoot(seed: Uint8Array, network: Network): HDKey {
  return HDKey.fromMasterSeed(seed, bip32Versions(network));
}

function accountNode(seed: Uint8Array, network: Network): { root: HDKey; account: HDKey } {
  const root = vaultSignerRoot(seed, network);
  // vaultAccountOriginPath returns the BIP48 origin in `m/48'/…` form, which is
  // exactly what @scure/bip32 derive() parses. Deriving from the same string
  // the origin record advertises keeps the two from drifting apart.
  const account = root.derive(vaultAccountOriginPath(network));
  return { root, account };
}

/**
 * The public BIP48 `m/48'/coin'/0'/2'` signer-origin record for `seed`.
 *
 * The result is round-tripped through the SQVB binary encoding rather than only
 * its zod schema, so a record a signer mints is proven to be wire-canonical
 * before it can ever reach a policy, descriptor, or peer.
 */
export function deriveVaultRoleOrigin<R extends VaultSignerRole>(
  seed: Uint8Array,
  role: R,
): VaultSignerOriginV1 & { role: R; network: 'signet' };
export function deriveVaultRoleOrigin<R extends VaultSignerRole, N extends Network>(
  seed: Uint8Array,
  role: R,
  network: N,
): VaultSignerOriginV1 & { role: R; network: N };
export function deriveVaultRoleOrigin<R extends VaultSignerRole>(
  seed: Uint8Array,
  role: R,
  network: Network = DEFAULT_VAULT_ROLE_NETWORK,
): VaultSignerOriginV1 & { role: R; network: Network } {
  const { root, account } = accountNode(seed, network);
  try {
    if (!account.publicKey) throw new Error('BIP48 account derivation produced no public key');
    // The schema widens role/network to the full unions; the caller passed exact
    // literals and the parse just confirmed them, so re-narrowing here is a
    // restatement of what was validated, not an unchecked assumption.
    const origin = vaultSignerOriginSchema.parse({
      version: 1,
      role,
      network,
      // The master fingerprint is the first four bytes of the master key's
      // HASH160 identifier (BIP32). Taking it from `identifier` avoids depending
      // on how the library packs the same bytes into its numeric `fingerprint`.
      masterFingerprintHex: bytesToHex(root.identifier!.slice(0, 4)),
      originPath: vaultAccountOriginPath(network),
      accountXpub: account.publicExtendedKey,
    } satisfies VaultSignerOriginV1) as VaultSignerOriginV1 & { role: R; network: Network };
    const reparsed = parseVaultSignerOrigin(serializeVaultSignerOrigin(origin));
    if (
      reparsed.masterFingerprintHex !== origin.masterFingerprintHex ||
      reparsed.accountXpub !== origin.accountXpub ||
      reparsed.originPath !== origin.originPath ||
      reparsed.role !== origin.role ||
      reparsed.network !== origin.network
    ) {
      throw new Error('signer origin does not round-trip through the SQVB v1 encoding');
    }
    return origin;
  } finally {
    account.wipePrivateData();
    root.wipePrivateData();
  }
}

/**
 * ADR 0007 §1: reject a candidate Vault root that is the Spending seed S, is
 * the same mnemonic as S, or lands on the same master fingerprint or BIP48
 * account xpub as S would.
 *
 * These checks detect accidental reuse — a copy/paste, a restored-from-S
 * mistake, a stubbed RNG in a harness. They do NOT prove that two nominally
 * separate CSPRNG draws were independent; ADR 0007 §1 is explicit that no
 * descriptor-level check can. Generating C offline and keeping A and B on
 * different device categories remain the containment controls.
 */
export function assertVaultRoleIndependence(input: {
  role: VaultSignerOriginV1;
  roleEntropyHex: string;
  roleSeedHex: string;
  spendingEntropyHex: string;
  spendingSeedHex: string;
  network?: Network;
}): void {
  const network = input.network ?? DEFAULT_VAULT_ROLE_NETWORK;
  if (input.roleEntropyHex === input.spendingEntropyHex) {
    throw new VaultRoleIndependenceError('Vault role entropy equals the Spending wallet entropy');
  }
  if (input.roleSeedHex === input.spendingSeedHex) {
    throw new VaultRoleIndependenceError('Vault role seed equals the Spending wallet seed');
  }
  const spendingSeed = hexToBytes(input.spendingSeedHex);
  try {
    // The same BIP48 origin S would produce. Equality here means the candidate
    // is S, or a copy of S, however it was generated.
    const spendingAsRole = deriveVaultRoleOrigin(spendingSeed, input.role.role, network);
    if (spendingAsRole.masterFingerprintHex === input.role.masterFingerprintHex) {
      throw new VaultRoleIndependenceError(
        'Vault role master fingerprint equals the Spending wallet fingerprint',
      );
    }
    if (spendingAsRole.accountXpub === input.role.accountXpub) {
      throw new VaultRoleIndependenceError(
        'Vault role account xpub equals the Spending wallet BIP48 account xpub',
      );
    }
  } finally {
    spendingSeed.fill(0);
  }
}

/**
 * Sign a proof-of-possession challenge with the origin's non-hardened `/0/0`
 * child (scheme byte 0). This binds the complete origin and xpub, not a
 * four-byte fingerprint — ADR 0007 §2 rejects fingerprint-only matching.
 *
 * The result is verified with the same verifier a peer will use before
 * returning, so a derivation or encoding mistake fails here instead of at that
 * peer.
 */
export function signVaultProofOfPossession(
  seed: Uint8Array,
  input: VaultProofOfPossessionInputV1,
  nowMs?: string,
): VaultProofOfPossessionResultV1 {
  // Derive on the network the origin itself names. Taking it from a module
  // constant would silently produce a signet key for a mainnet origin and fail
  // the possession comparison below with a misleading error.
  const { root, account } = accountNode(seed, input.origin.network);
  const proofChild = account.deriveChild(0).deriveChild(0);
  try {
    if (!proofChild.privateKey || !proofChild.publicKey) {
      throw new Error('proof-of-possession child derivation produced no key pair');
    }
    if (bytesToHex(proofChild.publicKey) !== deriveProofPublicKeyHex(input.origin)) {
      throw new VaultRoleIndependenceError('this role does not hold the key for that signer origin');
    }
    const inputDigestHex = vaultProofInputDigest(input);
    const signature = secp256k1.sign(hexToBytes(inputDigestHex), proofChild.privateKey, {
      prehash: false,
      lowS: true,
    });
    const result: VaultProofOfPossessionResultV1 = {
      version: 1,
      role: input.origin.role,
      inputDigestHex,
      proofPublicKeyHex: bytesToHex(proofChild.publicKey),
      signatureHex: bytesToHex(signature.toCompactRawBytes()),
      scheme: 'secp256k1-ecdsa-compact-low-s-v1',
    };
    if (!verifyVaultProofOfPossession(input, result, nowMs)) {
      throw new Error('freshly produced proof of possession did not verify');
    }
    return result;
  } finally {
    proofChild.wipePrivateData();
    account.wipePrivateData();
    root.wipePrivateData();
  }
}

/** The `/0/0` proof public key an origin record advertises, from its xpub alone. */
export function deriveProofPublicKeyHex(origin: VaultSignerOriginV1): string {
  const account = HDKey.fromExtendedKey(origin.accountXpub, bip32Versions(origin.network));
  const child = account.deriveChild(0).deriveChild(0);
  if (!child.publicKey) throw new Error('signer origin xpub yields no /0/0 child key');
  return bytesToHex(child.publicKey);
}
