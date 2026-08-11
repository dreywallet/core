/**
 * Vault crypto primitives (spec §7.2): Argon2id key derivation and
 * XChaCha20-Poly1305 authenticated encryption via the injected CryptoProvider.
 */
import { base64ToBytes, bytesToBase64, utf8ToBytes } from './encoding';
import { getCryptoProvider } from './crypto-provider';
import { VaultError } from './errors';
import { normalizePassword } from './password';
import type { AeadBox, Argon2idParams } from './record';

export const KEY_BYTES = 32;
export const SALT_BYTES = 16; // crypto_pwhash_SALTBYTES
export const NONCE_BYTES = 24; // crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
export const AEAD_TAG_BYTES = 16; // crypto_aead_xchacha20poly1305_ietf_ABYTES

export async function deriveKek(
  password: string,
  salt: Uint8Array,
  params: Argon2idParams,
): Promise<Uint8Array> {
  if (salt.length !== SALT_BYTES) throw new Error(`salt must be ${SALT_BYTES} bytes`);
  const passwordBytes = utf8ToBytes(normalizePassword(password));
  try {
    return await getCryptoProvider().argon2id(passwordBytes, salt, params);
  } finally {
    passwordBytes.fill(0);
  }
}

export function aeadEncrypt(
  key: Uint8Array,
  plaintext: Uint8Array,
  aad: string,
  nonce: Uint8Array,
): AeadBox {
  if (nonce.length !== NONCE_BYTES) throw new Error(`nonce must be ${NONCE_BYTES} bytes`);
  const ciphertext = getCryptoProvider().xchaEncrypt(plaintext, utf8ToBytes(aad), nonce, key);
  return { nonceB64: bytesToBase64(nonce), ciphertextB64: bytesToBase64(ciphertext) };
}

export function aeadDecrypt(key: Uint8Array, box: AeadBox, aad: string): Uint8Array {
  try {
    return getCryptoProvider().xchaDecrypt(
      base64ToBytes(box.ciphertextB64),
      utf8ToBytes(aad),
      base64ToBytes(box.nonceB64),
      key,
    );
  } catch {
    throw new VaultError('decrypt-failed');
  }
}

export function zeroize(bytes: Uint8Array): void {
  bytes.fill(0);
}
