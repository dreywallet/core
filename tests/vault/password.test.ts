/**
 * spec §7.2: minimum 12 characters, no other rules. NFKD is an internal
 * determinism measure only — two Unicode spellings of the same password must
 * derive the same key.
 */
import { beforeAll, describe, expect, it } from 'vitest';
import { checkPasswordPolicy, MIN_PASSWORD_LENGTH, normalizePassword } from '../../src/domain/vault/password';
import { deriveKek, SALT_BYTES } from '../../src/domain/vault/crypto';
import { installTestCryptoProvider } from '../helpers/install-crypto-provider';
import type { Argon2idParams } from '../../src/domain/vault/record';

beforeAll(() => installTestCryptoProvider());

// Deliberately tiny params: these tests exercise policy, not KDF strength.
const TEST_PARAMS: Argon2idParams = {
  paramsVersion: 1,
  algorithm: 'argon2id13',
  opsLimit: 1,
  memLimitBytes: 8 * 2 ** 20,
  parallelism: 1,
};

describe('checkPasswordPolicy', () => {
  it('accepts any 12-character password, including all digits', () => {
    expect(checkPasswordPolicy('123456789012')).toEqual({ ok: true });
    expect(checkPasswordPolicy('correct horse battery staple')).toEqual({ ok: true });
    expect(checkPasswordPolicy('ññññññññññññ')).toEqual({ ok: true });
  });

  it('rejects 11 characters', () => {
    expect(checkPasswordPolicy('12345678901')).toEqual({ ok: false, reason: 'too-short' });
    expect(MIN_PASSWORD_LENGTH).toBe(12);
  });

  it('counts code points of the normalized form', () => {
    // 12 precomposed characters that decompose to 24 code points still pass
    // via their composed length? No — NFKD length governs; é (1 cp) → e + ́ (2 cp).
    // 6 precomposed é = 12 NFKD code points, so this passes:
    expect(checkPasswordPolicy('éééééé')).toEqual({ ok: true });
  });
});

describe('normalization determinism', () => {
  it('NFC and NFD spellings normalize identically and derive the same KEK', async () => {
    const composed = 'pässword123é'; // é precomposed
    const decomposed = 'pässword123é'; // a+diaeresis, e+acute
    expect(normalizePassword(composed)).toBe(normalizePassword(decomposed));

    const salt = new Uint8Array(SALT_BYTES).fill(7);
    const kekA = await deriveKek(composed, salt, TEST_PARAMS);
    const kekB = await deriveKek(decomposed, salt, TEST_PARAMS);
    expect([...kekA]).toEqual([...kekB]);
  });
});
