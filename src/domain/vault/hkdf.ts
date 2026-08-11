/**
 * HMAC-SHA256 (RFC 2104) and HKDF-SHA256 (RFC 5869) built on the injected
 * CryptoProvider's sha256.
 *
 * Deliberately implemented here rather than through a new CryptoProvider
 * method: every platform provider would otherwise need a simultaneous
 * interface change, while the textbook constructions below are pure byte
 * manipulation around the one hash primitive the seam already guarantees.
 * Correctness is pinned by the RFC 5869 test vectors in the vault suite and
 * by the passkey-envelope golden vectors, which are generated with an
 * independent implementation and verified against this one.
 *
 * Zeroization here is best effort only: every buffer this module allocates is
 * cleared, but the provider's sha256 makes internal copies that cannot be
 * reached, and callers remain responsible for clearing the ikm/key buffers
 * they own (for the passkey path, the WebAuthn PRF output).
 */
import { getCryptoProvider } from './crypto-provider';

const BLOCK_BYTES = 64; // SHA-256 block size
const HASH_BYTES = 32;

export function hmacSha256(key: Uint8Array, message: Uint8Array): Uint8Array {
  const sha256 = (data: Uint8Array): Uint8Array => getCryptoProvider().sha256(data);
  const hashedKey = key.length > BLOCK_BYTES ? sha256(key) : undefined;
  const paddedKey = new Uint8Array(BLOCK_BYTES);
  paddedKey.set(hashedKey ?? key);
  const inner = new Uint8Array(BLOCK_BYTES + message.length);
  const outer = new Uint8Array(BLOCK_BYTES + HASH_BYTES);
  try {
    for (let index = 0; index < BLOCK_BYTES; index += 1) {
      inner[index] = paddedKey[index]! ^ 0x36;
      outer[index] = paddedKey[index]! ^ 0x5c;
    }
    inner.set(message, BLOCK_BYTES);
    const innerDigest = sha256(inner);
    outer.set(innerDigest, BLOCK_BYTES);
    innerDigest.fill(0);
    return sha256(outer);
  } finally {
    inner.fill(0);
    outer.fill(0);
    paddedKey.fill(0);
    hashedKey?.fill(0);
  }
}

export function hkdfSha256(
  ikm: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  length: number,
): Uint8Array {
  if (!Number.isInteger(length) || length < 1 || length > 255 * HASH_BYTES) {
    throw new Error('hkdf output length out of range');
  }
  // Extract. RFC 5869 defaults an absent salt to HashLen zero bytes; callers
  // here always pass an explicit salt.
  const prk = hmacSha256(salt.length > 0 ? salt : new Uint8Array(HASH_BYTES), ikm);
  // Expand.
  const blocks = Math.ceil(length / HASH_BYTES);
  const okm = new Uint8Array(blocks * HASH_BYTES);
  let previous: Uint8Array = new Uint8Array(0);
  try {
    for (let block = 1; block <= blocks; block += 1) {
      const input = new Uint8Array(previous.length + info.length + 1);
      input.set(previous);
      input.set(info, previous.length);
      input[input.length - 1] = block;
      previous.fill(0);
      previous = hmacSha256(prk, input);
      input.fill(0);
      okm.set(previous, (block - 1) * HASH_BYTES);
    }
    return okm.slice(0, length);
  } finally {
    prk.fill(0);
    previous.fill(0);
    okm.fill(0);
  }
}
