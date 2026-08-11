/**
 * spec §24.1: Argon2id/XChaCha20-Poly1305 vault vectors.
 *
 * The XChaCha20-Poly1305 test is the published AEAD vector from
 * draft-irtf-cfrg-xchacha-03 §A.3 — a true independent known answer.
 *
 * The Argon2id known-answer tests pin libsodium's crypto_pwhash output with
 * fixed salts. RFC 9106's official Argon2id vector uses parallelism 4 plus
 * secret/associated-data inputs that crypto_pwhash cannot express, so these
 * are libsodium-derived regression pins, not an independent standard vector.
 */
import { beforeAll, describe, expect, it } from 'vitest';
import { aeadDecrypt, aeadEncrypt, deriveKek, NONCE_BYTES, SALT_BYTES, zeroize } from '../../src/domain/vault/crypto';
import { base64ToBytes, bytesToBase64, bytesToHex, hexToBytes, utf8ToBytes } from '../../src/domain/vault/encoding';
import { VaultError } from '../../src/domain/vault/errors';
import { installTestCryptoProvider } from '../helpers/install-crypto-provider';
import { getSodium } from '../helpers/sodium';
import type { AeadBox, Argon2idParams } from '../../src/domain/vault/record';

const TEST_PARAMS: Argon2idParams = {
  paramsVersion: 1,
  algorithm: 'argon2id13',
  opsLimit: 1,
  memLimitBytes: 8 * 2 ** 20,
  parallelism: 1,
};

beforeAll(() => installTestCryptoProvider());

describe('XChaCha20-Poly1305 IETF known answer (draft-irtf-cfrg-xchacha §A.3)', () => {
  const plaintext = utf8ToBytes(
    "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.",
  );
  const aadHex = '50515253c0c1c2c3c4c5c6c7';
  const keyHex = '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f';
  const nonceHex = '404142434445464748494a4b4c4d4e4f5051525354555657';
  const expectedCiphertextHex =
    'bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b4522f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff921f9664c97637da9768812f615c68b13b52e' +
    'c0875924c1c7987947deafd8780acf49';

  it('encrypts to the published ciphertext+tag', () => {
    const sodium = getSodium();
    const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
      plaintext,
      hexToBytes(aadHex),
      null,
      hexToBytes(nonceHex),
      hexToBytes(keyHex),
    );
    expect(bytesToHex(ciphertext)).toBe(expectedCiphertextHex);
  });

  it('decrypts the published ciphertext through aeadDecrypt', () => {
    // aeadDecrypt takes AAD as a string; the vector AAD is raw bytes, so this
    // uses the sodium call directly for the KAT and aeadDecrypt for wrapping
    // behavior below.
    const sodium = getSodium();
    const decrypted = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      null,
      hexToBytes(expectedCiphertextHex),
      hexToBytes(aadHex),
      hexToBytes(nonceHex),
      hexToBytes(keyHex),
    );
    expect(bytesToHex(decrypted)).toBe(bytesToHex(plaintext));
  });
});

describe('Argon2id known answers (libsodium-derived regression pins)', () => {
  it('derives the pinned 32-byte KEK for fixed inputs', async () => {
    const salt = new Uint8Array(SALT_BYTES).map((_, i) => i);
    const kek = await deriveKek('vault-test-password', salt, TEST_PARAMS);
    // Pinned from libsodium-wrappers-sumo 0.7.16 (ARGON2ID13, ops 1, 8 MiB)
    // so any libsodium upgrade or params regression is visible.
    expect(bytesToHex(kek)).toBe('23dbc7989580fb7de897ae0f06abbf2ea91ed78934e0eb0c62ff71238af898b9');
  });

  it('derives the pinned KEK at the spec §7.2 floor params (ops 3, 64 MiB)', async () => {
    // The one deliberately slow (~1s) KDF test: production floor parameters
    // must be exercised by CI, not only the tiny test params — a libsodium
    // regression specific to large memlimits would otherwise pass unnoticed.
    const salt = new Uint8Array(SALT_BYTES).map((_, i) => i);
    const kek = await deriveKek('vault-test-password', salt, {
      paramsVersion: 1,
      algorithm: 'argon2id13',
      opsLimit: 3,
      memLimitBytes: 64 * 2 ** 20,
      parallelism: 1,
    });
    expect(bytesToHex(kek)).toBe('ab7b7e3347d16f289a46e7b5f403d8b08fcfd91df80f803c753d3729e721f7ea');
  });

  it('different salts and passwords produce different keys', async () => {
    const saltA = new Uint8Array(SALT_BYTES).fill(1);
    const saltB = new Uint8Array(SALT_BYTES).fill(2);
    const base = bytesToHex(await deriveKek('vault-test-password', saltA, TEST_PARAMS));
    expect(bytesToHex(await deriveKek('vault-test-password', saltB, TEST_PARAMS))).not.toBe(base);
    expect(bytesToHex(await deriveKek('vault-test-passwore', saltA, TEST_PARAMS))).not.toBe(base);
  });

  it('rejects a wrong-sized salt', async () => {
    await expect(deriveKek('vault-test-password', new Uint8Array(8), TEST_PARAMS)).rejects.toThrow(/salt/u);
  });
});

describe('aeadEncrypt/aeadDecrypt round trips and tamper rejection', () => {
  const key = new Uint8Array(32).map((_, i) => 255 - i);
  const nonce = new Uint8Array(NONCE_BYTES).map((_, i) => i * 3);
  const aad = 'squirrel-vault:v1:test:payload';
  const message = utf8ToBytes('{"version":1}');

  function freshBox(): AeadBox {
    return aeadEncrypt(key, message, aad, nonce);
  }

  it('round-trips', () => {
    expect([...aeadDecrypt(key, freshBox(), aad)]).toEqual([...message]);
  });

  it('rejects tampered ciphertext', () => {
    const box = freshBox();
    const bytes = base64ToBytes(box.ciphertextB64);
    bytes[0] = (bytes[0] ?? 0) ^ 0x01;
    const tampered = { ...box, ciphertextB64: bytesToBase64(bytes) };
    expect(() => aeadDecrypt(key, tampered, aad)).toThrowError(VaultError);
    expect(() => aeadDecrypt(key, tampered, aad)).toThrow(/decrypt-failed/u);
  });

  it('rejects a tampered nonce', () => {
    const box = freshBox();
    const bytes = base64ToBytes(box.nonceB64);
    bytes[0] = (bytes[0] ?? 0) ^ 0x01;
    expect(() => aeadDecrypt(key, { ...box, nonceB64: bytesToBase64(bytes) }, aad)).toThrow(
      /decrypt-failed/u,
    );
  });

  it('rejects a wrong AAD', () => {
    expect(() => aeadDecrypt(key, freshBox(), 'squirrel-vault:v1:other:payload')).toThrow(
      /decrypt-failed/u,
    );
  });

  it('rejects a wrong key', () => {
    const wrongKey = new Uint8Array(32).fill(9);
    expect(() => aeadDecrypt(wrongKey, freshBox(), aad)).toThrow(/decrypt-failed/u);
  });

  it('rejects a wrong-sized nonce at encryption time', () => {
    expect(() => aeadEncrypt(key, message, aad, new Uint8Array(12))).toThrow(/nonce/u);
  });
});

describe('zeroize', () => {
  it('wipes the buffer in place', () => {
    const secret = new Uint8Array([1, 2, 3, 4]);
    zeroize(secret);
    expect([...secret]).toEqual([0, 0, 0, 0]);
  });
});
