/**
 * CryptoProvider port (spec §7.2): the single seam between platform-free
 * wallet logic and a platform's crypto implementation. The extension injects
 * libsodium; mobile injects quick-crypto + @noble/ciphers.
 *
 * Only argon2id is asynchronous — on every target it either runs off-thread
 * (mobile) or is slow enough that callers must already treat it as blocking
 * work. Everything else stays synchronous on purpose: sha256/ed25519Verify/
 * randomBytes are called from pure functions deep in transaction planning,
 * gateway verification, and scanning, and forcing a Promise through those
 * call graphs would asynchronize half the codebase for no benefit.
 *
 * The provider object is obtained after asynchronous platform init through a
 * module-level gate, mirroring the previous libsodium ready-gate: consumers
 * call getCryptoProvider() only after the composition root has awaited
 * provider construction and called setCryptoProvider().
 */
import { VaultError } from './errors';
import type { Argon2idParams } from './record';

export interface CryptoProvider {
  /**
   * Argon2id (ALG_ARGON2ID13). `params` must come from the vault record —
   * never pass constants; parallelism is pinned to 1 by the record schema and
   * memLimitBytes is in BYTES (implementations taking KiB divide internally).
   */
  argon2id(password: Uint8Array, salt: Uint8Array, params: Argon2idParams): Promise<Uint8Array>;
  /** XChaCha20-Poly1305 seal; returns ciphertext‖tag(16) in one buffer (libsodium layout). */
  xchaEncrypt(plaintext: Uint8Array, aad: Uint8Array, nonce: Uint8Array, key: Uint8Array): Uint8Array;
  /** XChaCha20-Poly1305 open; throws on authentication failure. */
  xchaDecrypt(box: Uint8Array, aad: Uint8Array, nonce: Uint8Array, key: Uint8Array): Uint8Array;
  sha256(data: Uint8Array): Uint8Array;
  /** Ed25519 detached-signature verification over a raw 32-byte public key. */
  ed25519Verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean;
  /** Cryptographically secure random bytes. */
  randomBytes(byteLength: number): Uint8Array;
}

let provider: CryptoProvider | undefined;

export function setCryptoProvider(next: CryptoProvider): void {
  provider = next;
}

export function getCryptoProvider(): CryptoProvider {
  if (!provider) {
    throw new VaultError(
      'crypto-provider-not-initialized',
      'call setCryptoProvider() before any vault crypto',
    );
  }
  return provider;
}

export function resetCryptoProviderForTests(): void {
  provider = undefined;
}
