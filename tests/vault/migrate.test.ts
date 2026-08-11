/**
 * spec §24.1/§25.2: versioned vault-record migration. The v0 fixture is a
 * synthetic pre-versioned record (flat KDF fields, no schemaVersion) encrypted
 * with the same crypto and AAD scheme; password "squirrel-test-password" with
 * tiny KDF params (ops 1, 8 MiB — test-only).
 */
import { beforeAll, describe, expect, it } from 'vitest';
import { installTestCryptoProvider } from '../helpers/install-crypto-provider';
import { VaultError } from '../../src/domain/vault/errors';
import { entropyToMnemonic, mnemonicToSeed } from '../../src/domain/keys/mnemonic';
import { bytesToHex, hexToBytes } from '../../src/domain/vault/encoding';
import { CURRENT_VAULT_SCHEMA_VERSION, migrateVaultRecord } from '../../src/domain/vault/migrate';
import { unlockVault } from '../../src/domain/vault/vault';
import { makeRecord, PASSWORD } from './helpers';
import v0Fixture from '../fixtures/vault-record-v0.json';

beforeAll(() => installTestCryptoProvider());

describe('migrateVaultRecord', () => {
  it('migrates the v0 fixture to a valid v1 record that still unlocks', async () => {
    const { record, migrated } = migrateVaultRecord(v0Fixture);
    expect(migrated).toBe(true);
    expect(record.schemaVersion).toBe(CURRENT_VAULT_SCHEMA_VERSION);
    expect(record.cipherVersion).toBe(1);
    expect(record.vaultId).toBe('vault-legacy');
    expect(record.kdf.opsLimit).toBe(1);
    // Ciphertexts were carried over byte-identical, so the migrated record
    // must decrypt with the original password.
    const unlocked = await unlockVault(record, PASSWORD);
    expect(unlocked.payload.entropyHex).toBe('000102030405060708090a0b0c0d0e0f');
    const entropy = hexToBytes(unlocked.payload.entropyHex);
    const expectedSeed = mnemonicToSeed(entropyToMnemonic(entropy));
    try {
      expect(unlocked.payload.seedHex).toBe(bytesToHex(expectedSeed));
    } finally {
      unlocked.dek.fill(0);
      entropy.fill(0);
      expectedSeed.fill(0);
    }
  });

  it('passes a v1 record through unchanged with migrated: false', async () => {
    const v1 = await makeRecord('vault-a');
    const { record, migrated } = migrateVaultRecord(JSON.parse(JSON.stringify(v1)));
    expect(migrated).toBe(false);
    expect(record).toEqual(v1);
  });

  it('rejects a tampered v0 record without partial output (§25.2 swap safety)', () => {
    // Two-slot holder modeling the caller contract: the prior encrypted
    // record stays until the migrated one is validated and persisted.
    const holder: { active: unknown; migrated?: unknown } = { active: { ...v0Fixture, opslimit: -1 } };
    let thrown: unknown;
    try {
      holder.migrated = migrateVaultRecord(holder.active).record;
    } catch (e) {
      thrown = e;
    }
    expect((thrown as VaultError).code).toBe('unsupported-version');
    expect(holder.migrated).toBeUndefined();
    expect(holder.active).toEqual({ ...v0Fixture, opslimit: -1 }); // untouched
  });

  it('rejects a v0 record whose KDF params exceed the v1 absolute bounds', () => {
    let thrown: unknown;
    try {
      migrateVaultRecord({ ...v0Fixture, memlimit: 2 ** 31 });
    } catch (e) {
      thrown = e;
    }
    expect(thrown).toBeInstanceOf(VaultError);
    expect((thrown as VaultError).code).toBe('unsupported-version');
  });

  it('rejects an unrecognized shape', () => {
    let thrown: unknown;
    try {
      migrateVaultRecord({ hello: 'world' });
    } catch (e) {
      thrown = e;
    }
    expect((thrown as VaultError).code).toBe('unsupported-version');
  });

  it('rejects a future schemaVersion', () => {
    let thrown: unknown;
    try {
      migrateVaultRecord({ schemaVersion: 99 });
    } catch (e) {
      thrown = e;
    }
    expect((thrown as VaultError).code).toBe('unsupported-version');
    expect((thrown as VaultError).message).toMatch(/newer than supported/u);
  });
});
