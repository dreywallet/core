/**
 * spec §7.2: atomic password change — every vault DEK rewrapped, seed payloads
 * never re-encrypted, no partial output on any failure.
 */
import { beforeAll, describe, expect, it, vi } from 'vitest';
import { installTestCryptoProvider } from '../helpers/install-crypto-provider';
import { VaultError } from '../../src/domain/vault/errors';
import type { VaultRecordV1 } from '../../src/domain/vault/record';
import {
  changePassword,
  createVaultRecord,
  unlockVault,
  type VaultDeps,
} from '../../src/domain/vault/vault';
import { makeDeps, makePayload, makeRecord, PASSWORD, TEST_PARAMS } from './helpers';

beforeAll(() => installTestCryptoProvider());

const NEW_PASSWORD = 'a-brand-new-password';

function deepFreezeRecord(record: VaultRecordV1): VaultRecordV1 {
  Object.freeze(record.kdf);
  Object.freeze(record.wrappedDek);
  Object.freeze(record.payload);
  return Object.freeze(record);
}

describe('changePassword', () => {
  it('rewraps every vault: old password rejected, new accepted, payloads intact', async () => {
    const records = [await makeRecord('vault-a'), await makeRecord('vault-b')];
    const originalPayloads = [];
    for (const r of records) originalPayloads.push((await unlockVault(r, PASSWORD)).payload);

    const rewrapped = await changePassword(records, PASSWORD, NEW_PASSWORD, makeDeps(1000));
    expect(rewrapped).toHaveLength(2);

    for (const [i, record] of rewrapped.entries()) {
      let thrown: unknown;
      try {
        await unlockVault(record, PASSWORD);
      } catch (e) {
        thrown = e;
      }
      expect((thrown as VaultError).code).toBe('wrong-password');
      expect((await unlockVault(record, NEW_PASSWORD)).payload).toEqual(originalPayloads[i]);
    }
  });

  it('carries payload boxes over byte-identical — seed material is never re-encrypted', async () => {
    const records = [await makeRecord('vault-a')];
    const rewrapped = await changePassword(records, PASSWORD, NEW_PASSWORD, makeDeps(1000));
    expect(rewrapped[0]!.payload).toEqual(records[0]!.payload);
    // ...while the wrap actually changed:
    expect(rewrapped[0]!.wrappedDek).not.toEqual(records[0]!.wrappedDek);
    expect(rewrapped[0]!.kdf.saltB64).not.toBe(records[0]!.kdf.saltB64);
  });

  it('uses fresh salts and nonces per record', async () => {
    const records = [await makeRecord('vault-a'), await makeRecord('vault-b')];
    const rewrapped = await changePassword(records, PASSWORD, NEW_PASSWORD, makeDeps(1000));
    expect(rewrapped[0]!.kdf.saltB64).not.toBe(rewrapped[1]!.kdf.saltB64);
    expect(rewrapped[0]!.wrappedDek.nonceB64).not.toBe(rewrapped[1]!.wrappedDek.nonceB64);
  });

  it('wrong old password throws before any work and leaves inputs untouched', async () => {
    const records = [deepFreezeRecord(await makeRecord('vault-a'))];
    let thrown: unknown;
    try {
      await changePassword(records, 'wrong-old-password', NEW_PASSWORD, makeDeps(1000));
    } catch (e) {
      thrown = e;
    }
    expect((thrown as VaultError).code).toBe('wrong-password');
    expect((await unlockVault(records[0]!, PASSWORD)).payload.version).toBe(1);
  });

  it('zeroizes DEKs already unwrapped when a later record rejects the old password', async () => {
    const first = await makeRecord('vault-a');
    const second = await createRecordWithPassword('vault-b', 'different-old-password');
    const expectedDek = (await unlockVault(first, PASSWORD)).dek;
    const expectedBytes = [...expectedDek];
    expectedDek.fill(0);

    const originalFill = Uint8Array.prototype.fill;
    let firstDekWasWiped = false;
    const fillSpy = vi.spyOn(Uint8Array.prototype, 'fill').mockImplementation(function (
      this: Uint8Array,
      value: number,
      start?: number,
      end?: number,
    ): Uint8Array {
      if (value === 0 && this.length === expectedBytes.length && expectedBytes.every((b, i) => this[i] === b)) {
        firstDekWasWiped = true;
      }
      return originalFill.call(this, value, start, end);
    });
    try {
      await expect(
        changePassword([first, second], PASSWORD, NEW_PASSWORD, makeDeps(1000)),
      ).rejects.toThrow();
      expect(firstDekWasWiped).toBe(true);
    } finally {
      fillSpy.mockRestore();
    }
  });

  it('rejects a weak new password up front', async () => {
    const records = [await makeRecord('vault-a')];
    let thrown: unknown;
    try {
      await changePassword(records, PASSWORD, 'short', makeDeps(1000));
    } catch (e) {
      thrown = e;
    }
    expect((thrown as VaultError).code).toBe('weak-password');
  });

  it('optionally upgrades KDF params during rewrap (spec §7.2 floor recovery)', async () => {
    const records = [await makeRecord('vault-a')];
    const upgraded = await changePassword(records, PASSWORD, NEW_PASSWORD, makeDeps(1000), {
      paramsVersion: 1,
      algorithm: 'argon2id13',
      opsLimit: 2,
      memLimitBytes: 16 * 2 ** 20,
      parallelism: 1,
    });
    expect(upgraded[0]!.kdf.opsLimit).toBe(2);
    expect(upgraded[0]!.kdf.memLimitBytes).toBe(16 * 2 ** 20);
    // Payload untouched, new params actually used for the wrap:
    expect(upgraded[0]!.payload).toEqual(records[0]!.payload);
    expect((await unlockVault(upgraded[0]!, NEW_PASSWORD)).payload.version).toBe(1);
  });

  it('rejects out-of-bounds newKdfParams up front', async () => {
    const records = [await makeRecord('vault-a')];
    await expect(
      changePassword(records, PASSWORD, NEW_PASSWORD, makeDeps(1000), {
        paramsVersion: 1,
        algorithm: 'argon2id13',
        opsLimit: 2,
        memLimitBytes: 2 ** 31,
        parallelism: 1,
      }),
    ).rejects.toThrow(/KDF_ABSOLUTE_BOUNDS/u);
  });

  it('mid-rewrap failure produces no partial output and never mutates inputs', async () => {
    const records = [
      deepFreezeRecord(await makeRecord('vault-a')),
      deepFreezeRecord(await makeRecord('vault-b')),
    ];
    // Fail on the second record's salt generation: first record's rewrap has
    // already happened, proving no partial result escapes.
    const base = makeDeps(1000);
    let calls = 0;
    const failing: VaultDeps = {
      now: base.now,
      random: (n) => {
        calls++;
        if (calls === 3) throw new Error('injected rng failure');
        return base.random(n);
      },
    };
    await expect(changePassword(records, PASSWORD, NEW_PASSWORD, failing)).rejects.toThrow(
      /injected rng failure/u,
    );
    // Old records still unlock with the old password — nothing was mutated.
    for (const record of records) {
      expect((await unlockVault(record, PASSWORD)).payload.version).toBe(1);
    }
  });
});

function createRecordWithPassword(vaultId: string, password: string): Promise<VaultRecordV1> {
  return createVaultRecord(
    { vaultId, name: vaultId, password, payload: makePayload(), kdfParams: TEST_PARAMS },
    makeDeps(2000),
  );
}
