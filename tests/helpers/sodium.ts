/**
 * libsodium initialization gate (spec §5.1: packaged libsodium WASM).
 *
 * The sumo build is required: the standard libsodium-wrappers build omits
 * crypto_pwhash (Argon2id) entirely — verified empirically against 0.7.16.
 *
 * libsodium populates its API only after the WASM module loads, so every
 * consumer must go through getSodium() after awaiting initSodium(). Shipping
 * in MV3 will require 'wasm-unsafe-eval' in the extension CSP; under
 * Node/vitest no configuration is needed.
 */
import sodium from 'libsodium-wrappers-sumo';
import { VaultError } from '../../src/domain/vault/errors';

let ready = false;
let readyPromise: Promise<void> | undefined;

export function initSodium(): Promise<void> {
  readyPromise ??= sodium.ready.then(() => {
    // Fail loudly if a packaging change ever drops a required primitive
    // (the standard build ships without crypto_pwhash, so this is real).
    if (
      typeof sodium.crypto_pwhash !== 'function' ||
      typeof sodium.crypto_aead_xchacha20poly1305_ietf_encrypt !== 'function'
    ) {
      throw new Error('libsodium build is missing crypto_pwhash or XChaCha20-Poly1305');
    }
    ready = true;
  });
  return readyPromise;
}

export function getSodium(): typeof sodium {
  if (!ready) {
    throw new VaultError(
      'crypto-provider-not-initialized',
      'call await initSodium() before vault crypto',
    );
  }
  return sodium;
}
