/**
 * The crypto init gates: any use before initialization completes must fail
 * with the typed error, never a confusing undefined-function crash. This file
 * must not initialize either gate before its first assertion.
 */
import { afterEach, describe, expect, it } from 'vitest';
import { createLibsodiumCryptoProvider } from '../helpers/libsodium-test-provider';
import { getSodium, initSodium } from '../helpers/sodium';
import {
  getCryptoProvider,
  resetCryptoProviderForTests,
  setCryptoProvider,
} from '../../src/domain/vault/crypto-provider';
import { VaultError } from '../../src/domain/vault/errors';

function expectGateError(fn: () => unknown): void {
  let thrown: unknown;
  try {
    fn();
  } catch (e) {
    thrown = e;
  }
  expect(thrown).toBeInstanceOf(VaultError);
  expect((thrown as VaultError).code).toBe('crypto-provider-not-initialized');
}

describe('crypto init gates', () => {
  afterEach(() => {
    resetCryptoProviderForTests();
  });

  // This case must run first: the provider-gate case below initializes
  // libsodium as a side effect, and getSodium's gate can only be observed
  // un-initialized once per process.
  it('getSodium throws the typed error before init, works after', async () => {
    expectGateError(() => getSodium());

    await initSodium();
    await initSodium(); // idempotent
    expect(typeof getSodium().crypto_pwhash).toBe('function');
    expect(typeof getSodium().crypto_aead_xchacha20poly1305_ietf_encrypt).toBe('function');
  });

  it('getCryptoProvider throws the typed error before set, works after', async () => {
    expectGateError(() => getCryptoProvider());

    setCryptoProvider(await createLibsodiumCryptoProvider());
    const provider = getCryptoProvider();
    expect(provider.sha256(new Uint8Array(0))).toHaveLength(32);
    expect(provider.randomBytes(16)).toHaveLength(16);
  });
});
