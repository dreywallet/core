/**
 * Vault role derivation and proof of possession (ADR 0007 §§1-3).
 *
 * Moved here from `extension/tests/background/vault-role.test.ts` when the
 * construction was promoted into core for the mobile signer
 * (`docs/mobile-vault-roleb-work-plan.md` MB2). Every assertion below is the
 * one the extension suite made; only the import paths changed, which is what
 * makes this file evidence that the promotion changed no behaviour.
 *
 * These tests deliberately reach for the committed conformance vectors rather
 * than only re-deriving from local seeds: a local round trip proves this module
 * is self-consistent, but only the vectors prove it agrees with the contract
 * every signer implements.
 *
 * All key material here is generated in-test from fixed labels or is the public
 * disposable fixture data core publishes. Nothing is funded or reused.
 */
import { beforeAll, describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { bytesToHex } from '../../src/domain/vault/encoding';
import {
  vaultAccountOriginPath,
  type VaultProofOfPossessionInputV1,
  type VaultProofOfPossessionResultV1,
  type VaultSignerOriginV1,
} from '../../src/domain/vault/multisig-contracts';
import {
  parseVaultProofResult,
  serializeVaultProofResult,
  serializeVaultSignerOrigin,
  vaultProofInputDigest,
  verifyVaultProofOfPossession,
} from '../../src/domain/vault/multisig-encoding';
import {
  assertVaultRoleIndependence,
  deriveProofPublicKeyHex,
  deriveVaultRoleOrigin,
  signVaultProofOfPossession,
  vaultSignerRoot,
  VaultRoleIndependenceError,
} from '../../src/domain/vault/multisig-role';
import { installTestCryptoProvider } from '../helpers/install-crypto-provider';

const CONTRACT_VECTORS = JSON.parse(
  readFileSync(join(import.meta.dirname, '..', '..', 'vectors', 'vault-contracts-v1.json'), 'utf8'),
) as {
  records: Record<
    'mainnet' | 'signet',
    {
      signers: VaultSignerOriginV1[];
      proofInput: VaultProofOfPossessionInputV1;
      proofResult: VaultProofOfPossessionResultV1;
    }
  >;
};

const ROLE_VECTORS = JSON.parse(
  readFileSync(join(import.meta.dirname, '..', '..', 'vectors', 'vault-role-v1.json'), 'utf8'),
) as {
  records: Record<
    'mainnet' | 'signet',
    {
      seedHex: string;
      role: VaultSignerOriginV1['role'];
      masterFingerprintHex: string;
      accountXpub: string;
      originPath: string;
      originHex: string;
      proofPublicKeyHex: string;
      proofInput: VaultProofOfPossessionInputV1;
      proofResult: VaultProofOfPossessionResultV1;
      proofResultHex: string;
      independence: {
        spendingSeedHex: string;
        spendingOriginPath: string;
        spendingMasterFingerprintHex: string;
        spendingAccountXpub: string;
      };
    }
  >;
};

/**
 * A deterministic disposable 64-byte BIP32 seed from a label. Test-only public
 * data: labelled so every case is independent and reproducible, and never
 * anything a wallet would produce for a user.
 */
function seedFrom(label: string): Uint8Array {
  return new Uint8Array(
    Buffer.concat([
      createHash('sha256').update(`drey-c0-test/${label}/0`).digest(),
      createHash('sha256').update(`drey-c0-test/${label}/1`).digest(),
    ]),
  );
}

function hash32(label: string): string {
  return createHash('sha256').update(label).digest('hex');
}

beforeAll(installTestCryptoProvider);

const SPENDING = seedFrom('spending-S');
const ROLE_A = seedFrom('vault-role-A');

describe('Vault role derivation', () => {
  it('derives a canonical BIP48 signet signer origin that round-trips through SQVB', () => {
    const origin = deriveVaultRoleOrigin(ROLE_A, 'desktop-a');
    expect(origin.version).toBe(1);
    expect(origin.role).toBe('desktop-a');
    expect(origin.network).toBe('signet');
    expect(origin.originPath).toBe(vaultAccountOriginPath('signet'));
    expect(origin.originPath).toBe("m/48'/1'/0'/2'");
    expect(origin.masterFingerprintHex).toMatch(/^[0-9a-f]{8}$/u);
    // Signet uses the test-network extended-key serialization, never xpub.
    expect(origin.accountXpub.startsWith('tpub')).toBe(true);
  });

  it('is deterministic for one seed and distinct across seeds', () => {
    expect(deriveVaultRoleOrigin(ROLE_A, 'desktop-a')).toEqual(
      deriveVaultRoleOrigin(ROLE_A, 'desktop-a'),
    );
    const other = deriveVaultRoleOrigin(seedFrom('vault-role-A-2'), 'desktop-a');
    expect(other.accountXpub).not.toBe(deriveVaultRoleOrigin(ROLE_A, 'desktop-a').accountXpub);
    expect(other.masterFingerprintHex).not.toBe(
      deriveVaultRoleOrigin(ROLE_A, 'desktop-a').masterFingerprintHex,
    );
  });

  it('reproduces the /0/0 proof key that the committed signet vector advertises', () => {
    // The strongest available cross-check: the vector's roots are not published,
    // only their xpubs, so agreeing on the derived proof key proves this module
    // reads origin records the same way the verifier does.
    const { proofInput, proofResult } = CONTRACT_VECTORS.records.signet;
    expect(deriveProofPublicKeyHex(proofInput.origin)).toBe(proofResult.proofPublicKeyHex);
    expect(vaultProofInputDigest(proofInput)).toBe(proofResult.inputDigestHex);
    expect(verifyVaultProofOfPossession(proofInput, proofResult)).toBe(true);
  });

  it('reproduces the mainnet vector\'s proof key too', () => {
    const { proofInput, proofResult } = CONTRACT_VECTORS.records.mainnet;
    expect(deriveProofPublicKeyHex(proofInput.origin)).toBe(proofResult.proofPublicKeyHex);
  });
});

describe('Vault role proof of possession', () => {
  const origin = deriveVaultRoleOrigin(ROLE_A, 'desktop-a');
  const challenge: VaultProofOfPossessionInputV1 = {
    version: 1,
    origin,
    sessionIdHex: hash32('session').slice(0, 32),
    challengeNonceHex: hash32('nonce'),
    transcriptHashHex: hash32('transcript'),
    expiresAtMs: '1785542700000',
  };

  it('produces a compact low-S result that verifies and re-parses', () => {
    const result = signVaultProofOfPossession(ROLE_A, challenge, '1785542600000');
    expect(result.scheme).toBe('secp256k1-ecdsa-compact-low-s-v1');
    expect(result.role).toBe('desktop-a');
    expect(result.signatureHex).toMatch(/^[0-9a-f]{128}$/u);
    expect(result.inputDigestHex).toBe(vaultProofInputDigest(challenge));
    expect(verifyVaultProofOfPossession(challenge, result, '1785542600000')).toBe(true);
    expect(parseVaultProofResult(serializeVaultProofResult(result))).toEqual(result);
  });

  it('binds the complete origin: a different origin\'s challenge is refused', () => {
    // ADR 0007 §2 rejects fingerprint-only matching. Signing a challenge whose
    // origin this role does not hold must fail here, not produce a signature a
    // peer would have to notice was wrong.
    const foreign = { ...challenge, origin: deriveVaultRoleOrigin(seedFrom('other'), 'desktop-a') };
    expect(() => signVaultProofOfPossession(ROLE_A, foreign)).toThrow(VaultRoleIndependenceError);
  });

  it('refuses to emit a proof that is already expired', () => {
    expect(() => signVaultProofOfPossession(ROLE_A, challenge, '1785542700001')).toThrow(
      /did not verify/u,
    );
  });

  it('does not verify once the challenge is mutated', () => {
    const result = signVaultProofOfPossession(ROLE_A, challenge);
    for (const mutated of [
      { ...challenge, challengeNonceHex: hash32('other') },
      { ...challenge, transcriptHashHex: hash32('other') },
      { ...challenge, expiresAtMs: '1785542700001' },
    ]) {
      expect(verifyVaultProofOfPossession(mutated, result)).toBe(false);
    }
  });
});

describe('ADR 0007 §1 role independence', () => {
  const spendingSeedHex = bytesToHex(SPENDING);
  const roleSeedHex = bytesToHex(ROLE_A);
  const base = {
    role: deriveVaultRoleOrigin(ROLE_A, 'desktop-a'),
    roleEntropyHex: 'aa'.repeat(16),
    roleSeedHex,
    spendingEntropyHex: 'bb'.repeat(16),
    spendingSeedHex,
  };

  it('accepts two independently generated roots', () => {
    expect(() => assertVaultRoleIndependence(base)).not.toThrow();
  });

  it('rejects identical entropy', () => {
    expect(() =>
      assertVaultRoleIndependence({ ...base, roleEntropyHex: base.spendingEntropyHex }),
    ).toThrow(VaultRoleIndependenceError);
  });

  it('rejects identical seeds even when the entropy fields differ', () => {
    // A wallet restored from S, then re-labelled, still has S's seed.
    expect(() =>
      assertVaultRoleIndependence({ ...base, roleSeedHex: spendingSeedHex }),
    ).toThrow(VaultRoleIndependenceError);
  });

  it('rejects a candidate that is the Spending seed by fingerprint and xpub', () => {
    // The most realistic accident: the caller is handed S itself. The entropy
    // fields could plausibly be filled in from elsewhere, so the check that
    // matters is the derived origin.
    expect(() =>
      assertVaultRoleIndependence({
        ...base,
        role: deriveVaultRoleOrigin(SPENDING, 'desktop-a'),
        roleSeedHex: 'cc'.repeat(64),
      }),
    ).toThrow(VaultRoleIndependenceError);
  });

  it('does not claim to prove RNG independence', () => {
    // Documentation-as-test: two distinct seeds pass, which is all these checks
    // can establish (ADR 0007 §1). Nothing here inspects entropy quality.
    expect(() =>
      assertVaultRoleIndependence({
        ...base,
        role: deriveVaultRoleOrigin(seedFrom('weak-but-distinct'), 'desktop-a'),
        roleSeedHex: bytesToHex(seedFrom('weak-but-distinct')),
      }),
    ).not.toThrow();
  });
});

/**
 * The half the extension suite could not cover, and the reason this promotion
 * ships vectors of its own.
 *
 * `vault-contracts-v1.json` publishes a proof but not the root that made it, so
 * it can only be *verified*. These vectors publish the disposable seed too, so
 * an independent implementation — a native signer, a second language, a future
 * hardware adapter — can produce the same bytes and compare, rather than
 * merely agreeing that somebody else's signature checks out. ECDSA here is
 * RFC 6979 deterministic and low-S normalized, so the signature is a fixed
 * string and not merely a valid one.
 */
describe('committed produced-proof vectors', () => {
  for (const network of ['mainnet', 'signet'] as const) {
    describe(network, () => {
      const vector = ROLE_VECTORS.records[network];

      it('re-derives the published origin from the published seed', () => {
        const seed = Uint8Array.from(Buffer.from(vector.seedHex, 'hex'));
        const origin = deriveVaultRoleOrigin(seed, vector.role, network);
        expect(origin.masterFingerprintHex).toBe(vector.masterFingerprintHex);
        expect(origin.accountXpub).toBe(vector.accountXpub);
        expect(origin.originPath).toBe(vector.originPath);
        expect(bytesToHex(serializeVaultSignerOrigin(origin))).toBe(vector.originHex);
        expect(deriveProofPublicKeyHex(origin)).toBe(vector.proofPublicKeyHex);
      });

      it('reproduces the published proof byte for byte', () => {
        const seed = Uint8Array.from(Buffer.from(vector.seedHex, 'hex'));
        // One millisecond inside the published expiry: the signature does not
        // depend on the clock, but the self-verification inside the producer
        // does, and a vector that could only be replayed before some wall-clock
        // date would rot.
        const nowMs = String(BigInt(vector.proofInput.expiresAtMs) - 1n);
        const result = signVaultProofOfPossession(seed, vector.proofInput, nowMs);
        expect(result).toEqual(vector.proofResult);
        expect(bytesToHex(serializeVaultProofResult(result))).toBe(vector.proofResultHex);
        expect(verifyVaultProofOfPossession(vector.proofInput, result, nowMs)).toBe(true);
      });

      it('rejects the published independence collision', () => {
        // The Spending seed the vector publishes derives to the origin the
        // vector also publishes, so an implementation that skips the derived
        // comparison and only checks the raw seed strings fails here.
        const spending = vector.independence;
        const spendingSeed = Uint8Array.from(Buffer.from(spending.spendingSeedHex, 'hex'));
        const asRole = deriveVaultRoleOrigin(spendingSeed, vector.role, network);
        expect(asRole.masterFingerprintHex).toBe(spending.spendingMasterFingerprintHex);
        expect(asRole.accountXpub).toBe(spending.spendingAccountXpub);
        expect(asRole.originPath).toBe(spending.spendingOriginPath);
        expect(() =>
          assertVaultRoleIndependence({
            role: asRole,
            roleEntropyHex: 'aa'.repeat(16),
            roleSeedHex: 'cc'.repeat(64),
            spendingEntropyHex: 'bb'.repeat(16),
            spendingSeedHex: spending.spendingSeedHex,
            network,
          }),
        ).toThrow(VaultRoleIndependenceError);
      });

      it('exposes a signer root that agrees with the origin it derives', () => {
        // MB5's `signVaultPartialSignature` takes this node. A root built with
        // the wrong version bytes would still derive *a* key, so the check that
        // matters is that it lands on the same account xpub the origin names.
        const seed = Uint8Array.from(Buffer.from(vector.seedHex, 'hex'));
        const root = vaultSignerRoot(seed, network);
        try {
          const account = root.derive(vector.originPath);
          expect(account.publicExtendedKey).toBe(vector.accountXpub);
        } finally {
          root.wipePrivateData();
        }
      });
    });
  }
});
