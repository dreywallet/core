/**
 * The standalone recovery tool's crypto provider.
 *
 * Core's contract encoders and the B2 PSBT path together touch exactly one
 * primitive: SHA-256. Every other `CryptoProvider` method throws rather than
 * being stubbed, so that if a future core change quietly pulls Argon2id,
 * XChaCha20-Poly1305, Ed25519, or the CSPRNG into the recovery path, this tool
 * fails loudly on a clean offline machine instead of computing something
 * plausible with a placeholder.
 *
 * `randomBytes` is the one deliberate exception: plan and request identifiers
 * are 16 fresh bytes each, and they come from the OS CSPRNG through
 * `node:crypto` rather than from any wallet entropy path.
 */
import { createHash, randomBytes as nodeRandomBytes } from 'node:crypto';
import { setCryptoProvider, type CryptoProvider } from '../../src/domain/vault/crypto-provider';

const unavailable = (name: string) => (): never => {
  throw new Error(
    `the standalone recovery tool has no ${name} implementation: ` +
    'the recovery path is specified to need only SHA-256, so reaching this is a defect, not a configuration problem',
  );
};

export const nodeCryptoProvider: CryptoProvider = {
  argon2id: unavailable('Argon2id'),
  xchaEncrypt: unavailable('XChaCha20-Poly1305 encryption'),
  xchaDecrypt: unavailable('XChaCha20-Poly1305 decryption'),
  sha256: (bytes) => new Uint8Array(createHash('sha256').update(bytes).digest()),
  ed25519Verify: unavailable('Ed25519 verification'),
  randomBytes: (length) => new Uint8Array(nodeRandomBytes(length)),
};

export function installNodeCryptoProvider(): void {
  setCryptoProvider(nodeCryptoProvider);
}

export function sha256Hex(value: string | Uint8Array): string {
  return createHash('sha256').update(value).digest('hex');
}
