/**
 * BIP39 mnemonic create/restore (spec §7.1).
 *
 * Create always produces 12 words from injected entropy and never takes a
 * passphrase; passphrases are accepted on the restore path only in v1.
 *
 * The create path runs an RNG plumbing smoke test before deriving anything:
 * a stubbed, zero-filled, or non-reseeding RNG must fail closed rather than
 * mint a predictable seed. This is not a statistical randomness test — it
 * catches broken wiring, not subtle bias.
 */
import {
  entropyToMnemonic as bip39EntropyToMnemonic,
  mnemonicToEntropy as bip39MnemonicToEntropy,
  mnemonicToSeedSync,
  validateMnemonic as bip39ValidateMnemonic,
} from '@scure/bip39';
import { wordlist as english } from '@scure/bip39/wordlists/english';

/** Returns cryptographically secure random bytes; production callers pass crypto.getRandomValues. */
export type Rng = (byteLength: number) => Uint8Array;

const CREATE_ENTROPY_BYTES = 16; // 128 bits → 12 words (spec §7.1)
const SUPPORTED_WORD_COUNTS = new Set([12, 15, 18, 21, 24]);

function isConstant(bytes: Uint8Array): boolean {
  return bytes.every((b) => b === bytes[0]);
}

/**
 * Draws the entropy plus a throwaway probe draw and rejects an RNG whose
 * output is constant or identical across consecutive draws.
 */
function drawCheckedEntropy(rng: Rng): Uint8Array {
  const entropy = rng(CREATE_ENTROPY_BYTES);
  if (entropy.length !== CREATE_ENTROPY_BYTES) {
    throw new Error(`rng returned ${entropy.length} bytes, expected ${CREATE_ENTROPY_BYTES}`);
  }
  const probe = rng(CREATE_ENTROPY_BYTES);
  if (probe.length !== CREATE_ENTROPY_BYTES) {
    throw new Error(`rng returned ${probe.length} bytes, expected ${CREATE_ENTROPY_BYTES}`);
  }
  if (isConstant(entropy) || isConstant(probe)) {
    throw new Error('rng self-test failed: constant output');
  }
  const repeated = entropy.every((b, i) => b === probe[i]);
  probe.fill(0); // probe material is never used; discard it
  if (repeated) {
    throw new Error('rng self-test failed: repeated output across draws');
  }
  return entropy;
}

export function generateMnemonic(rng: Rng): { mnemonic: string; entropy: Uint8Array } {
  const entropy = drawCheckedEntropy(rng);
  return { mnemonic: bip39EntropyToMnemonic(entropy, english), entropy };
}

export function validateMnemonic(mnemonic: string): boolean {
  const words = mnemonic.trim().split(/\s+/u);
  if (!SUPPORTED_WORD_COUNTS.has(words.length)) return false;
  return bip39ValidateMnemonic(words.join(' '), english);
}

export function entropyToMnemonic(entropy: Uint8Array): string {
  return bip39EntropyToMnemonic(entropy, english);
}

export function mnemonicToSeed(mnemonic: string, passphrase?: string): Uint8Array {
  return mnemonicToSeedSync(mnemonic, passphrase);
}

/**
 * Restore path: checksum-validated 12/15/18/21/24-word mnemonic, optional
 * passphrase. Returns the canonical entropy plus the 64-byte BIP39 seed.
 */
export function restoreMnemonic(
  mnemonic: string,
  passphrase?: string,
): { entropy: Uint8Array; seed: Uint8Array } {
  const normalized = mnemonic.trim().split(/\s+/u).join(' ');
  if (!validateMnemonic(normalized)) {
    throw new Error('invalid mnemonic: unsupported length or bad checksum');
  }
  return {
    entropy: bip39MnemonicToEntropy(normalized, english),
    seed: mnemonicToSeedSync(normalized, passphrase),
  };
}
