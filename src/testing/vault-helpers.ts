/** Shared vault test helpers. Tiny KDF params — format tests, not KDF strength. */
import type { Argon2idParams, VaultPayloadV1, VaultRecordV1 } from '../domain/vault/record';
import { entropyToMnemonic, mnemonicToSeed } from '../domain/keys/mnemonic';
import { bytesToHex, hexToBytes } from '../domain/vault/encoding';
import { createVaultRecord, type VaultDeps } from '../domain/vault/vault';

export const TEST_PARAMS: Argon2idParams = {
  paramsVersion: 1,
  algorithm: 'argon2id13',
  opsLimit: 1,
  memLimitBytes: 8 * 2 ** 20,
  parallelism: 1,
};

export const PASSWORD = 'squirrel-test-password';

export function makeDeps(seed = 1): VaultDeps {
  let counter = seed;
  return {
    random: (n) => new Uint8Array(n).map((_, i) => (i * 31 + counter++ * 97) % 256),
    now: () => 1_752_969_600_000,
  };
}

export function makePayload(overrides: Partial<VaultPayloadV1> = {}): VaultPayloadV1 {
  const payload: Omit<VaultPayloadV1, 'seedHex'> = {
    version: 1,
    entropyHex: overrides.entropyHex ?? '000102030405060708090a0b0c0d0e0f',
    ...(overrides.passphrase !== undefined ? { passphrase: overrides.passphrase } : {}),
  };
  if (overrides.seedHex !== undefined) return { ...payload, seedHex: overrides.seedHex };

  const entropy = hexToBytes(payload.entropyHex);
  const seed = mnemonicToSeed(entropyToMnemonic(entropy), payload.passphrase);
  try {
    return { ...payload, seedHex: bytesToHex(seed) };
  } finally {
    entropy.fill(0);
    seed.fill(0);
  }
}

export function makeRecord(
  vaultId: string,
  overrides: Partial<VaultPayloadV1> = {},
): Promise<VaultRecordV1> {
  return createVaultRecord(
    {
      vaultId,
      name: `vault ${vaultId}`,
      password: PASSWORD,
      payload: makePayload(overrides),
      kdfParams: TEST_PARAMS,
    },
    makeDeps([...vaultId].reduce((acc, ch) => acc * 31 + ch.charCodeAt(0), 7)),
  );
}
