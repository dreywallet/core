/**
 * HMAC-SHA256 / HKDF-SHA256 (Workstream A1 KEK derivation primitives).
 *
 * Two independent anchors: the RFC 5869 A.1 known-answer vector, and a
 * cross-check against node:crypto's createHmac/hkdfSync across boundary
 * shapes (empty/short/block-length/oversized keys, multi-block expansion), so
 * a defect in the provider-based construction cannot agree with OpenSSL by
 * accident.
 */
import { createHmac, hkdfSync } from 'node:crypto';
import { beforeAll, describe, expect, it } from 'vitest';
import { bytesToHex, hexToBytes, utf8ToBytes } from '../../src/domain/vault/encoding';
import { hkdfSha256, hmacSha256 } from '../../src/domain/vault/hkdf';
import { installTestCryptoProvider } from '../helpers/install-crypto-provider';

beforeAll(async () => {
  await installTestCryptoProvider();
});

describe('hmacSha256', () => {
  it('matches node:crypto across key/message shapes', () => {
    const cases: Array<[Uint8Array, Uint8Array]> = [
      [new Uint8Array(0), new Uint8Array(0)],
      [utf8ToBytes('key'), utf8ToBytes('The quick brown fox jumps over the lazy dog')],
      [new Uint8Array(64).fill(0xaa), utf8ToBytes('block-length key')],
      [new Uint8Array(131).fill(0x0b), utf8ToBytes('oversized key is pre-hashed')],
      [hexToBytes('0b'.repeat(20)), utf8ToBytes('Hi There')],
    ];
    for (const [key, message] of cases) {
      const reference = new Uint8Array(createHmac('sha256', key).update(message).digest());
      expect(bytesToHex(hmacSha256(key, message))).toBe(bytesToHex(reference));
    }
  });
});

describe('hkdfSha256', () => {
  it('reproduces the RFC 5869 A.1 known answer', () => {
    const okm = hkdfSha256(
      hexToBytes('0b'.repeat(22)),
      hexToBytes('000102030405060708090a0b0c'),
      hexToBytes('f0f1f2f3f4f5f6f7f8f9'),
      42,
    );
    expect(bytesToHex(okm)).toBe(
      '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865',
    );
  });

  it('matches node:crypto hkdfSync across lengths and salts', () => {
    const ikm = utf8ToBytes('input keying material');
    const info = utf8ToBytes('drey-passkey-kek cross-check');
    for (const [salt, length] of [
      [new Uint8Array(0), 32],
      [new Uint8Array(32).fill(7), 16],
      [utf8ToBytes('salt'), 64],
      [new Uint8Array(32).fill(7), 255 * 32],
    ] as Array<[Uint8Array, number]>) {
      const reference = new Uint8Array(hkdfSync('sha256', ikm, salt, info, length));
      expect(bytesToHex(hkdfSha256(ikm, salt, info, length))).toBe(bytesToHex(reference));
    }
  });

  it('rejects out-of-range output lengths', () => {
    const ikm = utf8ToBytes('ikm');
    expect(() => hkdfSha256(ikm, new Uint8Array(0), new Uint8Array(0), 0)).toThrow();
    expect(() => hkdfSha256(ikm, new Uint8Array(0), new Uint8Array(0), 255 * 32 + 1)).toThrow();
    expect(() => hkdfSha256(ikm, new Uint8Array(0), new Uint8Array(0), 1.5)).toThrow();
  });
});
