/**
 * Shared test bootstrap for the CryptoProvider seam: installs the libsodium
 * reference provider. Await it from beforeAll in any suite that touches vault
 * crypto, hashing, signing, or gateway verification.
 */
import { setCryptoProvider } from '../../src/domain/vault/crypto-provider';
import { createLibsodiumCryptoProvider } from './libsodium-test-provider';

export async function installTestCryptoProvider(): Promise<void> {
  setCryptoProvider(await createLibsodiumCryptoProvider());
}
