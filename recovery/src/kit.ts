/**
 * ADR 0007 §6, capability 1: "reconstruct and verify the complete descriptor
 * from the public kit."
 *
 * The load-bearing property here is that nothing in the kit is *believed*. The
 * kit states a `policyId` and two checksummed descriptors, and this module
 * throws all three away and regenerates them from the three signer origins
 * alone. If the regenerated identity disagrees with what the kit claims, the
 * kit is rejected — a tampered kit cannot make the tool derive, display, or
 * fund an address the policy does not actually own.
 */
import {
  parseVaultRecoveryKit,
  serializeVaultRecoveryKit,
} from '../../src/domain/vault/multisig-encoding';
import {
  assertVaultDescriptorPolicy,
  deriveVaultOutput,
  generateVaultPolicyIdentity,
  parseCanonicalVaultPolicyDescriptors,
  type VaultDerivedOutputV1,
} from '../../src/domain/vault/multisig-descriptors';
import type {
  VaultBranch,
  VaultPolicyIdentityV1,
  VaultRecoveryKitV1,
} from '../../src/domain/vault/multisig-contracts';
import { bytesToHex, hexToBytes } from '../../src/domain/vault/encoding';

export interface VerifiedKit {
  kit: VaultRecoveryKitV1;
  /** Regenerated from the signer origins, never read out of the kit. */
  identity: VaultPolicyIdentityV1;
}

/**
 * Parse a kit and prove it describes the policy it claims to describe.
 *
 * Four independent checks, in order of what they would catch:
 *
 * 1. `parseVaultRecoveryKit` re-derives the policy identity inside the SQVB
 *    reader and rejects a record whose `policyId` disagrees with its own
 *    descriptors.
 * 2. Regenerating the identity from the signer origins catches a kit whose
 *    descriptors and `policyId` agree with each other but not with its signers.
 * 3. Reparsing the canonical descriptors catches a checksum or key-expression
 *    that survives step 2 but is not canonical.
 * 4. Re-serializing catches any field the reader accepted but cannot reproduce,
 *    which would mean the tool and the writer disagree about the format.
 */
export function verifyKitBytes(bytes: Uint8Array): VerifiedKit {
  const kit = parseVaultRecoveryKit(bytes);

  const identity = generateVaultPolicyIdentity(kit.network, kit.signers);
  if (identity.policyId !== kit.policyId ||
      identity.receiveDescriptor !== kit.receiveDescriptor ||
      identity.changeDescriptor !== kit.changeDescriptor) {
    throw new Error(
      'recovery kit rejected: the policy regenerated from its three signer origins does not match the ' +
      'policy ID and descriptors the kit states. Do not fund or trust any address derived from this kit.',
    );
  }
  assertVaultDescriptorPolicy(identity);
  parseCanonicalVaultPolicyDescriptors(identity.receiveDescriptor, identity.changeDescriptor);

  const reserialized = bytesToHex(serializeVaultRecoveryKit(kit));
  if (reserialized !== bytesToHex(bytes)) {
    throw new Error('recovery kit rejected: it does not round-trip through this reader\'s own encoder');
  }

  const first = deriveVaultOutput(identity, 'receive', 0);
  if (first.address !== kit.firstReceiveAddress) {
    throw new Error(
      `recovery kit rejected: its stated first receive address is not the address this policy derives ` +
      `(kit says ${kit.firstReceiveAddress}, policy derives ${first.address})`,
    );
  }

  return { kit, identity };
}

export function verifyKitHex(hex: string): VerifiedKit {
  const trimmed = hex.trim().replace(/\s+/gu, '');
  if (!/^[0-9a-f]+$/iu.test(trimmed) || trimmed.length % 2 !== 0) {
    throw new Error('recovery kit input is not an even-length hex string');
  }
  return verifyKitBytes(hexToBytes(trimmed.toLowerCase()));
}

/**
 * Memoized derivation.
 *
 * `deriveVaultOutput` re-runs the full descriptor round-trip on every call —
 * correct for a wallet that derives an address at a time, ruinous for a tool
 * that scans two branches deep looking for an outpoint. Locating twenty UTXOs
 * at a search depth of 100 is 4,000 calls, and unmemoized that is minutes of an
 * operator staring at nothing during a recovery.
 *
 * Caching is safe here because the key includes the `policyId`, and the
 * identity that produced it was verified against its own signer origins by
 * `verifyKitBytes` before any of this runs. Two different policies can never
 * collide in the cache without colliding on SHA-256 first.
 */
const derivationCache = new Map<string, VaultDerivedOutputV1>();

export function derive(
  identity: VaultPolicyIdentityV1,
  branch: VaultBranch,
  index: number,
): VaultDerivedOutputV1 {
  const key = `${identity.policyId}:${branch}:${index}`;
  const cached = derivationCache.get(key);
  if (cached) return cached;
  const derived = deriveVaultOutput(identity, branch, index);
  derivationCache.set(key, derived);
  return derived;
}

export interface LadderEntry {
  branch: VaultBranch;
  index: number;
  address: string;
  scriptPubKeyHex: string;
  witnessScriptHex: string;
}

/** Derive an address ladder. Every entry is regenerated from the policy. */
export function deriveLadder(
  identity: VaultPolicyIdentityV1,
  branch: VaultBranch,
  from: number,
  to: number,
): LadderEntry[] {
  if (!Number.isInteger(from) || !Number.isInteger(to) || from < 0 || to < from) {
    throw new Error('invalid ladder range');
  }
  if (to - from > 999) throw new Error('ladder range is limited to 1000 entries per call');
  const entries: LadderEntry[] = [];
  for (let index = from; index <= to; index += 1) {
    const derived = derive(identity, branch, index);
    entries.push({
      branch, index,
      address: derived.address,
      scriptPubKeyHex: derived.scriptPubKeyHex,
      witnessScriptHex: derived.witnessScriptHex,
    });
  }
  return entries;
}

/**
 * Locate a UTXO's scriptPubKey in the policy's own derivation space.
 *
 * This is what lets the tool accept a UTXO set from any untrusted source: an
 * outpoint whose scriptPubKey the policy cannot regenerate is not spendable by
 * this Vault and is refused, so a data source cannot smuggle in an input the
 * user does not own.
 */
export function locateScript(
  identity: VaultPolicyIdentityV1,
  scriptPubKeyHex: string,
  searchDepth: number,
): { branch: VaultBranch; index: number; witnessScriptHex: string } | undefined {
  const wanted = scriptPubKeyHex.toLowerCase();
  for (const branch of ['receive', 'change'] as const) {
    for (let index = 0; index <= searchDepth; index += 1) {
      const derived = derive(identity, branch, index);
      if (derived.scriptPubKeyHex === wanted) {
        return { branch, index, witnessScriptHex: derived.witnessScriptHex };
      }
    }
  }
  return undefined;
}
