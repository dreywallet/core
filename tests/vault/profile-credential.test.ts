import { beforeAll, describe, expect, it } from 'vitest';
import { installTestCryptoProvider } from '../helpers/install-crypto-provider';
import { bytesToBase64 } from '../../src/domain/vault/encoding';
import {
  addProfileSecret,
  createProfileCredential,
  linkLegacyVaultToProfile,
  profileCredentialV1Schema,
  profileWrappedSecretV1Schema,
  removeProfileSecret,
  rewrapProfilePassword,
  unlockProfileCredential,
  unwrapProfileSecret,
  validateProfileCredentialStructure,
  zeroizeProfileSession,
} from '../../src/domain/vault/profile-credential';
import { makeDeps, makeRecord, PASSWORD, TEST_PARAMS } from './helpers';

beforeAll(() => installTestCryptoProvider());

describe('profile credential', () => {
  it('creates one password wrapper and unlocks the profile key', async () => {
    const created = await createProfileCredential({
      profileId: 'profile-1', password: PASSWORD, kdfParams: TEST_PARAMS,
    }, makeDeps(11));
    expect(profileCredentialV1Schema.safeParse(created.credential).success).toBe(true);
    const unlocked = await unlockProfileCredential(created.credential, PASSWORD);
    expect([...unlocked]).toEqual([...created.profileKey]);
    unlocked.fill(0);
    created.profileKey.fill(0);
  });

  it('rejects wrong passwords, structural tampering, and credential substitution', async () => {
    const a = await createProfileCredential({
      profileId: 'profile-a', password: PASSWORD, kdfParams: TEST_PARAMS,
    }, makeDeps(12));
    const b = await createProfileCredential({
      profileId: 'profile-b', password: PASSWORD, kdfParams: TEST_PARAMS,
    }, makeDeps(13));
    await expect(unlockProfileCredential(a.credential, 'different-password-1'))
      .rejects.toMatchObject({ code: 'wrong-password' });
    expect(() => validateProfileCredentialStructure({
      ...a.credential,
      kdf: { ...a.credential.kdf, saltB64: 'not-base64' },
    })).toThrowError(expect.objectContaining({ code: 'tampered' }));
    await expect(unlockProfileCredential({
      ...a.credential,
      wrappedProfileKey: b.credential.wrappedProfileKey,
      kdf: b.credential.kdf,
    }, PASSWORD)).rejects.toMatchObject({ code: 'wrong-password' });
    a.profileKey.fill(0);
    b.profileKey.fill(0);
  });

  it('adds, opens, removes, and AAD-binds wallet and owner secrets', async () => {
    const { credential, profileKey } = await createProfileCredential({
      profileId: 'profile-1', password: PASSWORD, kdfParams: TEST_PARAMS,
    }, makeDeps(14));
    const walletDek = new Uint8Array(32).fill(7);
    const ownerDek = new Uint8Array(32).fill(8);
    const wallet = addProfileSecret({
      profileId: credential.profileId, profileKey, secretId: 'wallet-1',
      kind: 'wallet-dek', secret: walletDek,
    }, makeDeps(15));
    const owner = addProfileSecret({
      profileId: credential.profileId, profileKey, secretId: 'campaign-1',
      kind: 'community-vault-owner-dek', secret: ownerDek,
    }, makeDeps(16));
    expect(profileWrappedSecretV1Schema.safeParse(wallet).success).toBe(true);
    const opened = unwrapProfileSecret(wallet, profileKey);
    expect([...opened]).toEqual([...walletDek]);
    opened.fill(0);

    expect(() => unwrapProfileSecret({ ...wallet, secretId: 'wallet-2' }, profileKey))
      .toThrowError(expect.objectContaining({ code: 'tampered' }));
    expect(() => unwrapProfileSecret({ ...wallet, kind: owner.kind }, profileKey))
      .toThrowError(expect.objectContaining({ code: 'tampered' }));
    const remaining = removeProfileSecret([wallet, owner], {
      profileId: credential.profileId, secretId: wallet.secretId, kind: wallet.kind,
    });
    expect(remaining).toEqual([owner]);
    profileKey.fill(0);
    walletDek.fill(0);
    ownerDek.fill(0);
  });

  it('changes the password by rewrapping only the profile key', async () => {
    const created = await createProfileCredential({
      profileId: 'profile-1', password: PASSWORD, kdfParams: TEST_PARAMS,
    }, makeDeps(17));
    const secret = addProfileSecret({
      profileId: 'profile-1', profileKey: created.profileKey, secretId: 'wallet-1',
      kind: 'wallet-dek', secret: new Uint8Array(32).fill(9),
    }, makeDeps(18));
    const originalSecret = structuredClone(secret);
    const next = await rewrapProfilePassword(
      created.credential, PASSWORD, 'new-profile-password', makeDeps(19),
    );
    expect(next.wrappedProfileKey).not.toEqual(created.credential.wrappedProfileKey);
    expect(secret).toEqual(originalSecret);
    await expect(unlockProfileCredential(next, PASSWORD))
      .rejects.toMatchObject({ code: 'wrong-password' });
    const unlocked = await unlockProfileCredential(next, 'new-profile-password');
    const opened = unwrapProfileSecret(secret, unlocked);
    expect([...opened]).toEqual(new Array(32).fill(9));
    opened.fill(0);
    unlocked.fill(0);
    created.profileKey.fill(0);
  });

  it('links a matching legacy wallet without mutating it and preserves it on interruption', async () => {
    const legacy = await makeRecord('legacy-wallet');
    const original = JSON.parse(JSON.stringify(legacy));
    const created = await createProfileCredential({
      profileId: 'profile-1', password: PASSWORD, kdfParams: TEST_PARAMS,
    }, makeDeps(20));
    const linked = await linkLegacyVaultToProfile({
      record: legacy, password: PASSWORD, profileId: 'profile-1', profileKey: created.profileKey,
    }, makeDeps(21));
    expect(linked.secretId).toBe(legacy.vaultId);
    expect(legacy).toEqual(original);
    await expect(linkLegacyVaultToProfile({
      record: legacy, password: 'different-password-1', profileId: 'profile-1',
      profileKey: created.profileKey,
    }, makeDeps(22))).rejects.toMatchObject({ code: 'wrong-password' });
    await expect(linkLegacyVaultToProfile({
      record: legacy, password: PASSWORD, profileId: 'profile-1', profileKey: created.profileKey,
    }, { random: () => { throw new Error('persistence preparation interrupted'); } }))
      .rejects.toThrow('interrupted');
    expect(legacy).toEqual(original);
    created.profileKey.fill(0);
  });

  it('rejects tampered wrapped secrets before returning plaintext', async () => {
    const created = await createProfileCredential({
      profileId: 'profile-1', password: PASSWORD, kdfParams: TEST_PARAMS,
    }, makeDeps(23));
    const record = addProfileSecret({
      profileId: 'profile-1', profileKey: created.profileKey, secretId: 'wallet-1',
      kind: 'wallet-dek', secret: new Uint8Array(32).fill(4),
    }, makeDeps(24));
    const malformed = {
      ...record,
      wrappedSecret: { ...record.wrappedSecret, ciphertextB64: bytesToBase64(new Uint8Array(47)) },
    };
    expect(() => unwrapProfileSecret(malformed, created.profileKey))
      .toThrowError(expect.objectContaining({ code: 'tampered' }));
    created.profileKey.fill(0);
  });

  it('zeroizes both profile and active-wallet session keys', () => {
    const profileKey = new Uint8Array(32).fill(3);
    const walletDek = new Uint8Array(32).fill(4);
    zeroizeProfileSession(profileKey, walletDek);
    expect([...profileKey]).toEqual(new Array(32).fill(0));
    expect([...walletDek]).toEqual(new Array(32).fill(0));
  });
});
