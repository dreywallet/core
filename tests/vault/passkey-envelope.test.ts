/**
 * ADR 0007 Workstream A1: passkey-wrapped-DEK envelope.
 *
 * The golden vectors in vectors/passkey-envelope-v1.json were generated with
 * the @noble/ciphers AEAD; this suite verifies them against the libsodium
 * reference provider, so the vectors only pass while the two independent
 * XChaCha20-Poly1305 implementations and the HKDF construction agree.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { beforeAll, describe, expect, it } from 'vitest';
import { KEY_BYTES, NONCE_BYTES } from '../../src/domain/vault/crypto';
import { base64ToBytes, bytesToBase64, bytesToHex, hexToBytes, utf8ToBytes } from '../../src/domain/vault/encoding';
import { VaultError } from '../../src/domain/vault/errors';
import {
  PASSKEY_HKDF_SALT_BYTES,
  PASSKEY_PRF_SALT_BYTES,
  assertUniquePasskeyCredentials,
  createPasskeyEnvelope,
  parsePasskeyEnvelope,
  passkeyPrfEvalInput,
  passkeyPrfEvalInputForEnvelope,
  unwrapPasskeyDek,
  type PasskeyEnvelopeV1,
} from '../../src/domain/vault/passkey-envelope';
import { installTestCryptoProvider } from '../helpers/install-crypto-provider';
import type { Network } from '../../src/domain/keys/derivation';

const TEST_RP_ORIGIN = 'chrome-extension://lgcnmmbgabemdkgacjpcdebbjmmblbmn';

interface NegativeCase {
  envelope: unknown;
  expected?: { rpOrigin: string; vaultId: string; network: Network };
  prfOutputHex?: string;
  expectedError: string;
}

interface PasskeyVectorRecord {
  rpOrigin: string;
  vaultId: string;
  network: Network;
  dekHex: string;
  prfOutputHex: string;
  prfEvalInputHex: string;
  aadJson: string;
  kekInfoJson: string;
  envelope: PasskeyEnvelopeV1;
  labelMutationStillDecrypts: PasskeyEnvelopeV1;
  negatives: Record<string, NegativeCase>;
}

const fixture = JSON.parse(
  readFileSync(join(import.meta.dirname, '..', '..', 'vectors', 'passkey-envelope-v1.json'), 'utf8'),
) as { vectorVersion: number; records: Record<'mainnet' | 'signet', PasskeyVectorRecord> };

beforeAll(async () => {
  await installTestCryptoProvider();
});

function enrollmentInput(overrides: Partial<Parameters<typeof createPasskeyEnvelope>[0]> = {}) {
  return {
    dek: new Uint8Array(KEY_BYTES).fill(1),
    prfOutput: new Uint8Array(32).fill(2),
    rpOrigin: TEST_RP_ORIGIN,
    vaultId: 'unit-vault',
    network: 'signet' as Network,
    credentialIdB64: bytesToBase64(new Uint8Array(16).fill(3)),
    label: 'Unit credential',
    createdAtMs: 1,
    prfSalt: new Uint8Array(PASSKEY_PRF_SALT_BYTES).fill(4),
    hkdfSalt: new Uint8Array(PASSKEY_HKDF_SALT_BYTES).fill(5),
    nonce: new Uint8Array(NONCE_BYTES).fill(6),
    ...overrides,
  };
}

describe('golden vectors (noble-generated, libsodium-verified)', () => {
  for (const network of ['mainnet', 'signet'] as const) {
    const record = () => fixture.records[network];

    it(`${network}: positive vector unwraps to the pinned DEK`, () => {
      const vector = record();
      const dek = unwrapPasskeyDek({
        envelope: vector.envelope,
        prfOutput: hexToBytes(vector.prfOutputHex),
        expected: { rpOrigin: vector.rpOrigin, vaultId: vector.vaultId, network: vector.network },
      });
      expect(bytesToHex(dek)).toBe(vector.dekHex);
    });

    it(`${network}: PRF eval input construction is pinned`, () => {
      const vector = record();
      expect(bytesToHex(passkeyPrfEvalInputForEnvelope(vector.envelope))).toBe(vector.prfEvalInputHex);
      const domain = utf8ToBytes('drey-passkey-prf/v1');
      expect(vector.prfEvalInputHex.startsWith(`${bytesToHex(domain)}00`)).toBe(true);
    });

    it(`${network}: label/createdAt are display metadata outside the AAD`, () => {
      const vector = record();
      const dek = unwrapPasskeyDek({
        envelope: { ...vector.labelMutationStillDecrypts, createdAtMs: 999 },
        prfOutput: hexToBytes(vector.prfOutputHex),
        expected: { rpOrigin: vector.rpOrigin, vaultId: vector.vaultId, network: vector.network },
      });
      expect(bytesToHex(dek)).toBe(vector.dekHex);
    });

    it(`${network}: every negative vector fails closed with its pinned code`, () => {
      const vector = record();
      const names = Object.keys(vector.negatives);
      expect(names.length).toBeGreaterThanOrEqual(16);
      for (const name of names) {
        const negative = vector.negatives[name]!;
        let thrown: unknown;
        try {
          unwrapPasskeyDek({
            envelope: negative.envelope,
            prfOutput: hexToBytes(negative.prfOutputHex ?? vector.prfOutputHex),
            expected: negative.expected ?? {
              rpOrigin: vector.rpOrigin,
              vaultId: vector.vaultId,
              network: vector.network,
            },
          });
        } catch (error) {
          thrown = error;
        }
        expect(thrown, name).toBeInstanceOf(VaultError);
        expect((thrown as VaultError).code, name).toBe(negative.expectedError);
      }
    });
  }

  it('mainnet and signet fixtures derive distinct key material', () => {
    const { mainnet, signet } = fixture.records;
    expect(mainnet.envelope.wrappedDek.ciphertextB64).not.toBe(signet.envelope.wrappedDek.ciphertextB64);
    expect(mainnet.prfEvalInputHex).not.toBe(signet.prfEvalInputHex);
  });
});

describe('createPasskeyEnvelope / unwrapPasskeyDek', () => {
  it('round-trips and produces a parseable envelope', () => {
    const input = enrollmentInput();
    const envelope = createPasskeyEnvelope(input);
    expect(parsePasskeyEnvelope(envelope)).toEqual(envelope);
    const dek = unwrapPasskeyDek({
      envelope,
      prfOutput: input.prfOutput,
      expected: { rpOrigin: input.rpOrigin, vaultId: input.vaultId, network: input.network },
    });
    expect(bytesToHex(dek)).toBe(bytesToHex(input.dek));
  });

  it('rejects an rpOrigin that is not an exact extension origin', () => {
    for (const rpOrigin of [
      'https://wallet.example',
      'chrome-extension://short',
      'chrome-extension://LGCNMMBGABEMDKGACJPCDEBBJMMBLBMN',
      'chrome-extension://lgcnmmbgabemdkgacjpcdebbjmmblbmn/',
      'chrome-extension://qgcnmmbgabemdkgacjpcdebbjmmblbmn',
    ]) {
      expect(() => createPasskeyEnvelope(enrollmentInput({ rpOrigin }))).toThrow(VaultError);
    }
  });

  it('rejects undersized and all-zero PRF output at enrollment', () => {
    expect(() => createPasskeyEnvelope(enrollmentInput({ prfOutput: new Uint8Array(31).fill(2) })))
      .toThrow(expect.objectContaining({ code: 'invalid-prf-output' }));
    expect(() => createPasskeyEnvelope(enrollmentInput({ prfOutput: new Uint8Array(32) })))
      .toThrow(expect.objectContaining({ code: 'invalid-prf-output' }));
  });

  it('rejects malformed dek, salts, nonce, and credential IDs', () => {
    expect(() => createPasskeyEnvelope(enrollmentInput({ dek: new Uint8Array(16) }))).toThrow(VaultError);
    expect(() => createPasskeyEnvelope(enrollmentInput({ prfSalt: new Uint8Array(16) }))).toThrow(VaultError);
    expect(() => createPasskeyEnvelope(enrollmentInput({ hkdfSalt: new Uint8Array(16) }))).toThrow(VaultError);
    expect(() => createPasskeyEnvelope(enrollmentInput({ nonce: new Uint8Array(12) }))).toThrow(VaultError);
    expect(() => createPasskeyEnvelope(enrollmentInput({ credentialIdB64: bytesToBase64(new Uint8Array(8)) })))
      .toThrow(VaultError);
    expect(() => createPasskeyEnvelope(enrollmentInput({ credentialIdB64: 'not base64 !!!' }))).toThrow(VaultError);
    expect(() => createPasskeyEnvelope(enrollmentInput({ credentialIdB64: bytesToBase64(new Uint8Array(1024)) })))
      .toThrow(VaultError);
  });

  it('rejects every non-canonical Base64 alias of a valid credential ID', () => {
    const canonical = bytesToBase64(new Uint8Array(16).fill(3)); // ends in '=='
    const envelope = createPasskeyEnvelope(enrollmentInput({ credentialIdB64: canonical }));
    for (const alias of [
      canonical.replace(/=+$/u, ''), // unpadded
      `${canonical.slice(0, 4)} ${canonical.slice(4)}`, // embedded whitespace
      `${canonical}\n`, // trailing whitespace
    ]) {
      expect(bytesToHex(base64ToBytes(alias)), alias).toBe(bytesToHex(base64ToBytes(canonical)));
      expect(() => parsePasskeyEnvelope({ ...envelope, credentialIdB64: alias }), alias).toThrow(
        expect.objectContaining({ code: 'tampered' }),
      );
    }
  });

  it('rejects wrappedDek boxes whose nonce or ciphertext length is not exact', () => {
    const envelope = createPasskeyEnvelope(enrollmentInput());
    const shortNonce = { ...envelope.wrappedDek, nonceB64: bytesToBase64(new Uint8Array(12)) };
    const shortCiphertext = {
      ...envelope.wrappedDek,
      ciphertextB64: bytesToBase64(base64ToBytes(envelope.wrappedDek.ciphertextB64).slice(0, 32)),
    };
    for (const wrappedDek of [shortNonce, shortCiphertext]) {
      expect(() => parsePasskeyEnvelope({ ...envelope, wrappedDek })).toThrow(
        expect.objectContaining({ code: 'tampered' }),
      );
    }
  });

  it('two credentials for one wallet produce independent envelopes', () => {
    const first = createPasskeyEnvelope(enrollmentInput());
    const second = createPasskeyEnvelope(enrollmentInput({
      credentialIdB64: bytesToBase64(new Uint8Array(16).fill(9)),
      prfOutput: new Uint8Array(32).fill(10),
      prfSalt: new Uint8Array(PASSKEY_PRF_SALT_BYTES).fill(11),
      hkdfSalt: new Uint8Array(PASSKEY_HKDF_SALT_BYTES).fill(12),
      nonce: new Uint8Array(NONCE_BYTES).fill(13),
    }));
    expect(first.wrappedDek.ciphertextB64).not.toBe(second.wrappedDek.ciphertextB64);
    expect(() => assertUniquePasskeyCredentials([first, second])).not.toThrow();
    expect(() => assertUniquePasskeyCredentials([first, second, first])).toThrow(
      expect.objectContaining({ code: 'duplicate-credential' }),
    );
    // The same credential may serve two different wallets.
    expect(() => assertUniquePasskeyCredentials([first, { ...first, vaultId: 'other-wallet' }])).not.toThrow();
  });

  it('parsePasskeyEnvelope fails closed on non-objects and missing fields', () => {
    for (const value of [null, undefined, 42, 'envelope', [], {}]) {
      expect(() => parsePasskeyEnvelope(value)).toThrow(VaultError);
    }
    const missingBox: Record<string, unknown> = { ...createPasskeyEnvelope(enrollmentInput()) };
    delete missingBox['wrappedDek'];
    expect(() => parsePasskeyEnvelope(missingBox)).toThrow(
      expect.objectContaining({ code: 'tampered' }),
    );
  });

  it('passkeyPrfEvalInputForEnvelope parses fail-closed before any ceremony input exists', () => {
    const envelope = createPasskeyEnvelope(enrollmentInput());
    expect(() => passkeyPrfEvalInputForEnvelope({ ...envelope, version: 2 })).toThrow(
      expect.objectContaining({ code: 'unsupported-version' }),
    );
    expect(() => passkeyPrfEvalInputForEnvelope({ ...envelope, extra: true })).toThrow(
      expect.objectContaining({ code: 'tampered' }),
    );
  });

  it('passkeyPrfEvalInput requires the exact salt length', () => {
    expect(() => passkeyPrfEvalInput(new Uint8Array(16))).toThrow(VaultError);
    const input = passkeyPrfEvalInput(new Uint8Array(PASSKEY_PRF_SALT_BYTES).fill(1));
    expect(input.length).toBe('drey-passkey-prf/v1'.length + 1 + PASSKEY_PRF_SALT_BYTES);
  });
});
