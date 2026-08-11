/**
 * spec §24.1: BIP39 vectors for all supported mnemonic lengths and passphrases,
 * and BIP32 chains via the fixture root xprvs. Same official Trezor vectors as
 * the §5.3 prototype (fixture copied; prototype stays untouched).
 */
import { describe, expect, it } from 'vitest';
import { HDKey } from '@scure/bip32';
import {
  entropyToMnemonic,
  generateMnemonic,
  mnemonicToSeed,
  restoreMnemonic,
  validateMnemonic,
} from '../../src/domain/keys/mnemonic';
import vectors from '../fixtures/bip39-trezor-vectors.json';

const TREZOR_PASSPHRASE = 'TREZOR';

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function bytesToHex(bytes: Uint8Array): string {
  return [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
}

function asVector(raw: (string | undefined)[]): [string, string, string, string] {
  const [entropyHex, mnemonic, seedHex, rootXprv] = raw;
  if (!entropyHex || !mnemonic || !seedHex || !rootXprv) throw new Error('malformed fixture row');
  return [entropyHex, mnemonic, seedHex, rootXprv];
}

describe('Trezor BIP39 vectors', () => {
  for (const raw of vectors.english) {
    const [entropyHex, mnemonic, seedHex, rootXprv] = asVector(raw);
    const words = mnemonic.split(' ').length;
    it(`${words}-word vector ${entropyHex.slice(0, 8)}…`, () => {
      expect(entropyToMnemonic(hexToBytes(entropyHex))).toBe(mnemonic);
      expect(validateMnemonic(mnemonic)).toBe(true);

      const { entropy, seed } = restoreMnemonic(mnemonic, TREZOR_PASSPHRASE);
      expect(bytesToHex(entropy)).toBe(entropyHex);
      expect(bytesToHex(seed)).toBe(seedHex);

      // BIP32 chain check: master node from the vector seed matches the fixture xprv.
      expect(HDKey.fromMasterSeed(seed).privateExtendedKey).toBe(rootXprv);
    });
  }

  it('covers the officially published word lengths', () => {
    const lengths = new Set(vectors.english.map((raw) => asVector(raw)[1].split(' ').length));
    expect([...lengths].sort((a, b) => a - b)).toEqual([12, 18, 24]);
  });
});

describe('15- and 21-word lengths (no published Trezor vectors)', () => {
  // Same approach as the §5.3 prototype: fixed entropy → mnemonic must be
  // valid and restore back to the identical entropy.
  for (const [bytes, words] of [
    [20, 15],
    [28, 21],
  ] as const) {
    it(`round-trips ${bytes}-byte entropy (${words} words)`, () => {
      const entropy = new Uint8Array(bytes).map((_, i) => (i * 37 + 11) % 256);
      const mnemonic = entropyToMnemonic(entropy);
      expect(mnemonic.split(' ')).toHaveLength(words);
      expect(validateMnemonic(mnemonic)).toBe(true);
      const restored = restoreMnemonic(mnemonic);
      expect(bytesToHex(restored.entropy)).toBe(bytesToHex(entropy));
      expect(restored.seed).toHaveLength(64);
    });
  }
});

describe('validateMnemonic', () => {
  const valid12 =
    'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

  it('rejects unsupported word counts', () => {
    expect(validateMnemonic(`${valid12} abandon`)).toBe(false); // 13 words
    expect(validateMnemonic('abandon ability')).toBe(false);
  });

  it('rejects a bad checksum', () => {
    expect(validateMnemonic(valid12.replace(/about$/u, 'abandon'))).toBe(false);
  });

  it('rejects words outside the english wordlist', () => {
    expect(validateMnemonic(valid12.replace(/about$/u, 'zzzzzz'))).toBe(false);
  });

  it('tolerates surrounding and repeated whitespace', () => {
    expect(validateMnemonic(`  ${valid12.replace(/ /gu, '   ')}  `)).toBe(true);
  });
});

describe('generateMnemonic (create path, spec §7.1)', () => {
  // Deterministic non-constant RNG: byte i of draw d is ((d*16 + i) * 37 + 11) mod 256.
  const counterRng = () => {
    let i = 0;
    return (n: number) => new Uint8Array(n).map(() => (i++ * 37 + 11) % 256);
  };

  it('is deterministic for a fixed rng and yields 12 words from 16 bytes', () => {
    const a = generateMnemonic(counterRng());
    const b = generateMnemonic(counterRng());
    expect(a.mnemonic).toBe(b.mnemonic);
    expect(a.mnemonic.split(' ')).toHaveLength(12);
    expect(a.entropy).toHaveLength(16);
    expect(validateMnemonic(a.mnemonic)).toBe(true);
  });

  it('has no passphrase parameter — passphrases exist on restore only', () => {
    expect(generateMnemonic.length).toBe(1);
  });

  it('rejects an rng that returns a short buffer', () => {
    expect(() => generateMnemonic(() => new Uint8Array(8))).toThrow(/expected 16$/u);
  });

  it('fails closed on a constant (stubbed or zero-filled) rng', () => {
    expect(() => generateMnemonic((n) => new Uint8Array(n))).toThrow(
      /rng self-test failed: constant output/u,
    );
  });

  it('fails closed when consecutive draws repeat (non-reseeding rng)', () => {
    const fixed = new Uint8Array(16).map((_, i) => i + 1);
    expect(() => generateMnemonic(() => fixed.slice())).toThrow(
      /rng self-test failed: repeated output/u,
    );
  });
});

describe('restoreMnemonic', () => {
  it('throws on an invalid mnemonic', () => {
    expect(() => restoreMnemonic('abandon ability')).toThrow(/invalid mnemonic/u);
  });

  it('derives different seeds with and without a passphrase', () => {
    const mnemonic = vectors.english[0]![1]!;
    expect(bytesToHex(mnemonicToSeed(mnemonic))).not.toBe(
      bytesToHex(mnemonicToSeed(mnemonic, TREZOR_PASSPHRASE)),
    );
  });
});
