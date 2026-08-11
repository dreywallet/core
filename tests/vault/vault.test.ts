/**
 * spec §7.2/§7.3: create→unlock round trip, wrong-password and tamper
 * rejection, and multi-vault isolation including AAD-bound cross-record
 * grafting.
 */
import { beforeAll, describe, expect, it } from 'vitest';
import { installTestCryptoProvider } from '../helpers/install-crypto-provider';
import { VaultError } from '../../src/domain/vault/errors';
import { aeadEncrypt, NONCE_BYTES } from '../../src/domain/vault/crypto';
import { base64ToBytes, bytesToBase64, utf8ToBytes } from '../../src/domain/vault/encoding';
import {
  KDF_ABSOLUTE_BOUNDS,
  payloadAad,
  vaultPayloadV1Schema,
  type VaultRecordV1,
} from '../../src/domain/vault/record';
import { createVaultRecord, unlockVault, verifyVaultPassword } from '../../src/domain/vault/vault';
import { makeDeps, makePayload, makeRecord, PASSWORD, TEST_PARAMS } from './helpers';

beforeAll(() => installTestCryptoProvider());

describe('createVaultRecord', () => {
  it('produces a serializable v1 record and unlocks back to the payload', async () => {
    const payload = makePayload({ passphrase: 'restore-passphrase' });
    const record = await createVaultRecord(
      { vaultId: 'vault-a', name: 'Main', password: PASSWORD, payload, kdfParams: TEST_PARAMS },
      makeDeps(),
    );
    expect(record.schemaVersion).toBe(1);
    expect(record.kdf.opsLimit).toBe(TEST_PARAMS.opsLimit);

    const revived = JSON.parse(JSON.stringify(record)) as VaultRecordV1;
    const unlocked = await unlockVault(revived, PASSWORD);
    expect(unlocked.vaultId).toBe('vault-a');
    expect(unlocked.payload).toEqual(payload); // cached seed + passphrase intact
    expect(unlocked.dek).toHaveLength(32);
  });

  it('rejects a password under 12 characters', async () => {
    await expect(
      createVaultRecord(
        { vaultId: 'v', name: 'v', password: 'short', payload: makePayload(), kdfParams: TEST_PARAMS },
        makeDeps(),
      ),
    ).rejects.toThrow(/weak-password|12 characters/u);
  });

  it('accepts only the five BIP39 entropy sizes', () => {
    for (const bytes of [16, 20, 24, 28, 32]) {
      expect(vaultPayloadV1Schema.safeParse(makePayload({ entropyHex: '00'.repeat(bytes) })).success).toBe(
        true,
      );
    }
    for (const bytes of [15, 17, 19, 21, 23, 25, 27, 29, 31, 33]) {
      expect(
        vaultPayloadV1Schema.safeParse({ ...makePayload(), entropyHex: '00'.repeat(bytes) }).success,
      ).toBe(false);
    }
  });

  it('rejects a writer payload whose cached seed does not match entropy and passphrase', async () => {
    await expect(
      createVaultRecord(
        {
          vaultId: 'v',
          name: 'v',
          password: PASSWORD,
          payload: makePayload({ seedHex: 'ff'.repeat(64) }),
          kdfParams: TEST_PARAMS,
        },
        makeDeps(),
      ),
    ).rejects.toThrow(/entropy, passphrase, and seed/u);

    const withoutPassphrase = makePayload();
    await expect(
      createVaultRecord(
        {
          vaultId: 'v',
          name: 'v',
          password: PASSWORD,
          payload: { ...withoutPassphrase, passphrase: 'changes-the-seed' },
          kdfParams: TEST_PARAMS,
        },
        makeDeps(),
      ),
    ).rejects.toThrow(/entropy, passphrase, and seed/u);
  });
});

describe('unlockVault failure modes', () => {
  it('reauthenticates without decrypting or validating seed payload plaintext', async () => {
    const record = await makeRecord('vault-public-only');
    const ciphertext = base64ToBytes(record.payload.ciphertextB64);
    ciphertext[0] = ciphertext[0]! ^ 1;
    const payloadTampered = {
      ...record,
      payload: { ...record.payload, ciphertextB64: bytesToBase64(ciphertext) },
    };
    await expect(verifyVaultPassword(payloadTampered, PASSWORD)).resolves.toBeUndefined();
    await expect(unlockVault(payloadTampered, PASSWORD)).rejects.toMatchObject({ code: 'tampered' });
    await expect(verifyVaultPassword(record, 'not-the-password-1'))
      .rejects.toMatchObject({ code: 'wrong-password' });
  });
  it('wrong password → wrong-password', async () => {
    const record = await makeRecord('vault-a');
    let thrown: unknown;
    try {
      await unlockVault(record, 'not-the-password-1');
    } catch (e) {
      thrown = e;
    }
    expect((thrown as VaultError).code).toBe('wrong-password');
  });

  it('tampered payload after a correct DEK unwrap → tampered', async () => {
    const record = await makeRecord('vault-a');
    const bytes = base64ToBytes(record.payload.ciphertextB64);
    bytes[0] = (bytes[0] ?? 0) ^ 0x01;
    const tampered: VaultRecordV1 = {
      ...record,
      payload: { ...record.payload, ciphertextB64: bytesToBase64(bytes) },
    };
    let thrown: unknown;
    try {
      await unlockVault(tampered, PASSWORD);
    } catch (e) {
      thrown = e;
    }
    expect((thrown as VaultError).code).toBe('tampered');
  });

  it('authenticated but mismatched entropy/seed payload fails closed', async () => {
    const record = await makeRecord('vault-a');
    const unlocked = await unlockVault(record, PASSWORD);
    try {
      const mismatched = { ...unlocked.payload, seedHex: 'ff'.repeat(64) };
      const box = aeadEncrypt(
        unlocked.dek,
        utf8ToBytes(JSON.stringify(mismatched)),
        payloadAad(record.cipherVersion, record.vaultId),
        new Uint8Array(NONCE_BYTES).fill(7),
      );
      let thrown: unknown;
      try {
        await unlockVault({ ...record, payload: box }, PASSWORD);
      } catch (error) {
        thrown = error;
      }
      expect(thrown).toBeInstanceOf(VaultError);
      expect((thrown as VaultError).code).toBe('tampered');
      expect((thrown as VaultError).message).toMatch(/do not correspond/u);
    } finally {
      unlocked.dek.fill(0);
    }
  });
});

describe('structurally corrupt records (provable tampering, no password needed)', () => {
  async function expectTampered(mutate: (r: VaultRecordV1) => VaultRecordV1): Promise<void> {
    const record = mutate(await makeRecord('vault-a'));
    let thrown: unknown;
    try {
      await unlockVault(record, PASSWORD);
    } catch (e) {
      thrown = e;
    }
    expect(thrown).toBeInstanceOf(VaultError);
    expect((thrown as VaultError).code).toBe('tampered');
  }

  it('invalid base64 salt → tampered, not an untyped atob error', async () => {
    await expectTampered((r) => ({ ...r, kdf: { ...r.kdf, saltB64: '!!not-base64!!' } }));
  });

  it('wrong-length salt (valid base64) → tampered, not a generic Error', async () => {
    await expectTampered((r) => ({ ...r, kdf: { ...r.kdf, saltB64: bytesToBase64(new Uint8Array(8)) } }));
  });

  it('invalid base64 nonce → tampered, not wrong-password', async () => {
    await expectTampered((r) => ({ ...r, wrappedDek: { ...r.wrappedDek, nonceB64: '%%%' } }));
  });

  it('truncated nonce → tampered, not wrong-password', async () => {
    await expectTampered((r) => ({
      ...r,
      wrappedDek: { ...r.wrappedDek, nonceB64: bytesToBase64(new Uint8Array(12)) },
    }));
  });

  it('empty payload ciphertext → tampered', async () => {
    await expectTampered((r) => ({
      ...r,
      payload: { ...r.payload, ciphertextB64: bytesToBase64(new Uint8Array(4)) },
    }));
  });

  it('inflated KDF params → tampered before any derivation runs (DoS guard)', async () => {
    // Must fail fast: with a 2 GiB memlimit the assertion below would hang or
    // OOM if the bounds check did not run before the KDF.
    await expectTampered((r) => ({ ...r, kdf: { ...r.kdf, memLimitBytes: 2 ** 31 } }));
    await expectTampered((r) => ({ ...r, kdf: { ...r.kdf, opsLimit: 2 ** 32 - 1 } }));
    await expectTampered((r) => ({
      ...r,
      kdf: { ...r.kdf, memLimitBytes: KDF_ABSOLUTE_BOUNDS.memLimitBytes.max + 1 },
    }));
  });

  it('authenticated but non-JSON payload → tampered, secrets handled on the typed path', async () => {
    const record = await makeRecord('vault-a');
    const { dek } = await unlockVault(record, PASSWORD);
    // Forge a payload that authenticates under the real DEK and AAD but is
    // not UTF-8 JSON — models a writer bug or a partially-migrated record.
    const garbage = aeadEncrypt(
      dek,
      new Uint8Array([0xff, 0xfe, 0x00, 0x01]),
      payloadAad(record.cipherVersion, record.vaultId),
      new Uint8Array(NONCE_BYTES).fill(9),
    );
    let thrown: unknown;
    try {
      await unlockVault({ ...record, payload: garbage }, PASSWORD);
    } catch (e) {
      thrown = e;
    }
    expect(thrown).toBeInstanceOf(VaultError);
    expect((thrown as VaultError).code).toBe('tampered');
  });
});

describe('multi-vault isolation (spec §7.3)', () => {
  it('unlocking A yields only A, and DEKs are per-vault', async () => {
    const a = await makeRecord('vault-a');
    const b = await makeRecord('vault-b', { entropyHex: '0f0e0d0c0b0a09080706050403020100' });
    const unlockedA = await unlockVault(a, PASSWORD);
    const unlockedB = await unlockVault(b, PASSWORD);
    expect(unlockedA.vaultId).toBe('vault-a');
    expect(unlockedA.payload.entropyHex).not.toBe(unlockedB.payload.entropyHex);
    expect([...unlockedA.dek]).not.toEqual([...unlockedB.dek]);
  });

  it("grafting B's wrappedDek into A's record fails via AAD vaultId binding", async () => {
    const a = await makeRecord('vault-a');
    const b = await makeRecord('vault-b');
    // Same password wraps both DEKs, but the AAD binds each box to its vaultId
    // — a swapped box must not unwrap even with the right password. The graft
    // also carries B's kdf so the KEK itself is derivable.
    const grafted: VaultRecordV1 = { ...a, kdf: b.kdf, wrappedDek: b.wrappedDek };
    let thrown: unknown;
    try {
      await unlockVault(grafted, PASSWORD);
    } catch (e) {
      thrown = e;
    }
    expect((thrown as VaultError).code).toBe('wrong-password');
  });

  it("grafting B's payload box into A's record fails via AAD vaultId binding", async () => {
    const a = await makeRecord('vault-a');
    const b = await makeRecord('vault-b');
    const grafted: VaultRecordV1 = { ...a, payload: b.payload };
    let thrown: unknown;
    try {
      await unlockVault(grafted, PASSWORD);
    } catch (e) {
      thrown = e;
    }
    expect((thrown as VaultError).code).toBe('tampered');
  });
});
