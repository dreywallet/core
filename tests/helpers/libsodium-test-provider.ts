/**
 * Reference CryptoProvider for core's own test suite: packaged libsodium WASM
 * (a devDependency — core ships ZERO runtime libsodium). This mirrors the
 * extension's LibsodiumCryptoProvider byte-for-byte so core's tests exercise
 * the same primitives the extension ships, keeping the golden vectors honest.
 */
import type { Argon2idParams } from '../../src/domain/vault/record';
import type { CryptoProvider } from '../../src/domain/vault/crypto-provider';
import { getSodium, initSodium } from './sodium';

export async function createLibsodiumCryptoProvider(): Promise<CryptoProvider> {
  await initSodium();
  const sodium = getSodium();
  return {
    argon2id(password: Uint8Array, salt: Uint8Array, params: Argon2idParams): Promise<Uint8Array> {
      if (params.parallelism !== 1) {
        return Promise.reject(new Error('libsodium argon2id supports only parallelism 1'));
      }
      try {
        return Promise.resolve(
          sodium.crypto_pwhash(
            32,
            password,
            salt,
            params.opsLimit,
            params.memLimitBytes,
            sodium.crypto_pwhash_ALG_ARGON2ID13,
          ),
        );
      } catch (err) {
        return Promise.reject(err instanceof Error ? err : new Error(String(err)));
      }
    },
    xchaEncrypt(plaintext, aad, nonce, key) {
      return sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, aad, null, nonce, key);
    },
    xchaDecrypt(box, aad, nonce, key) {
      return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, box, aad, nonce, key);
    },
    sha256(data) {
      return sodium.crypto_hash_sha256(data);
    },
    ed25519Verify(signature, message, publicKey) {
      try {
        return sodium.crypto_sign_verify_detached(signature, message, publicKey);
      } catch {
        return false;
      }
    },
    randomBytes(byteLength) {
      return sodium.randombytes_buf(byteLength);
    },
  };
}
