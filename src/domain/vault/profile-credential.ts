/**
 * Versioned, platform-neutral profile credential.
 *
 * A password-derived KEK wraps one random profile key. The profile key then
 * wraps wallet and Community Vault owner DEKs independently. Platforms may
 * cache the profile key behind device authentication, but persistent records
 * never contain it in plaintext.
 */
import { z } from 'zod';
import { VaultError } from './errors';
import { checkPasswordPolicy } from './password';
import {
  AEAD_TAG_BYTES,
  KEY_BYTES,
  NONCE_BYTES,
  SALT_BYTES,
  aeadDecrypt,
  aeadEncrypt,
  deriveKek,
} from './crypto';
import { base64ToBytes, bytesToBase64 } from './encoding';
import {
  KDF_ABSOLUTE_BOUNDS,
  kdfParamsWithinBounds,
  type AeadBox,
  type Argon2idParams,
  type VaultRecordV1,
} from './record';
import { openVaultPayload, unlockVault, type VaultDeps } from './vault';

export const profileSecretKindSchema = z.enum([
  'wallet-dek',
  'community-vault-owner-dek',
]);
export type ProfileSecretKind = z.infer<typeof profileSecretKindSchema>;

export interface ProfileCredentialV1 {
  schemaVersion: 1;
  cipherVersion: 1;
  profileId: string;
  createdAt: number;
  kdf: Argon2idParams & { saltB64: string };
  wrappedProfileKey: AeadBox;
}

export interface ProfileWrappedSecretV1 {
  schemaVersion: 1;
  cipherVersion: 1;
  profileId: string;
  secretId: string;
  kind: ProfileSecretKind;
  wrappedSecret: AeadBox;
}

const base64Length = (bytes: number): number => 4 * Math.ceil(bytes / 3);
const decodedLength = (value: string, expected: number): boolean => {
  try { return base64ToBytes(value).length === expected; } catch { return false; }
};
const nonceSchema = z.string().length(base64Length(NONCE_BYTES))
  .refine((value) => decodedLength(value, NONCE_BYTES));
const keyBoxSchema = z.object({
  nonceB64: nonceSchema,
  ciphertextB64: z.string().length(base64Length(KEY_BYTES + AEAD_TAG_BYTES))
    .refine((value) => decodedLength(value, KEY_BYTES + AEAD_TAG_BYTES)),
}).strict();
const kdfSchema = z.object({
  paramsVersion: z.literal(1),
  algorithm: z.literal('argon2id13'),
  opsLimit: z.number().int()
    .min(KDF_ABSOLUTE_BOUNDS.opsLimit.min).max(KDF_ABSOLUTE_BOUNDS.opsLimit.max),
  memLimitBytes: z.number().int()
    .min(KDF_ABSOLUTE_BOUNDS.memLimitBytes.min).max(KDF_ABSOLUTE_BOUNDS.memLimitBytes.max),
  parallelism: z.literal(1),
  saltB64: z.string().length(base64Length(SALT_BYTES))
    .refine((value) => decodedLength(value, SALT_BYTES)),
}).strict();

export const profileCredentialV1Schema: z.ZodType<ProfileCredentialV1> = z.object({
  schemaVersion: z.literal(1),
  cipherVersion: z.literal(1),
  profileId: z.string().min(1),
  createdAt: z.number().int().nonnegative(),
  kdf: kdfSchema,
  wrappedProfileKey: keyBoxSchema,
}).strict();

export const profileWrappedSecretV1Schema: z.ZodType<ProfileWrappedSecretV1> = z.object({
  schemaVersion: z.literal(1),
  cipherVersion: z.literal(1),
  profileId: z.string().min(1),
  secretId: z.string().min(1),
  kind: profileSecretKindSchema,
  wrappedSecret: keyBoxSchema,
}).strict();

function profileKeyAad(credential: Pick<ProfileCredentialV1, 'cipherVersion' | 'profileId'>): string {
  return `drey-profile:v${credential.cipherVersion}:${credential.profileId}:profile-key`;
}

function secretAad(record: Pick<ProfileWrappedSecretV1,
  'cipherVersion' | 'profileId' | 'kind' | 'secretId'>): string {
  return `drey-profile:v${record.cipherVersion}:${record.profileId}:${record.kind}:${record.secretId}`;
}

function assertKey(key: Uint8Array, label: string): void {
  if (key.length !== KEY_BYTES) throw new Error(`${label} must be ${KEY_BYTES} bytes`);
}

export function validateProfileCredentialStructure(raw: unknown): ProfileCredentialV1 {
  const parsed = profileCredentialV1Schema.safeParse(raw);
  if (!parsed.success || !kdfParamsWithinBounds(parsed.data.kdf)) {
    throw new VaultError('tampered', 'profile credential is malformed');
  }
  return parsed.data;
}

export function validateProfileWrappedSecretStructure(raw: unknown): ProfileWrappedSecretV1 {
  const parsed = profileWrappedSecretV1Schema.safeParse(raw);
  if (!parsed.success) throw new VaultError('tampered', 'profile-wrapped secret is malformed');
  return parsed.data;
}

export async function createProfileCredential(
  input: { profileId: string; password: string; kdfParams: Argon2idParams },
  deps: VaultDeps,
): Promise<{ credential: ProfileCredentialV1; profileKey: Uint8Array }> {
  if (!checkPasswordPolicy(input.password).ok) throw new VaultError('weak-password');
  if (!kdfParamsWithinBounds(input.kdfParams)) {
    throw new Error('kdfParams outside KDF_ABSOLUTE_BOUNDS');
  }
  const salt = deps.random(SALT_BYTES);
  const profileKey = deps.random(KEY_BYTES);
  assertKey(profileKey, 'profile key');
  let kek: Uint8Array | undefined;
  try {
    kek = await deriveKek(input.password, salt, input.kdfParams);
    const credential: ProfileCredentialV1 = {
      schemaVersion: 1,
      cipherVersion: 1,
      profileId: input.profileId,
      createdAt: deps.now(),
      kdf: { ...input.kdfParams, saltB64: bytesToBase64(salt) },
      wrappedProfileKey: aeadEncrypt(
        kek,
        profileKey,
        profileKeyAad({ cipherVersion: 1, profileId: input.profileId }),
        deps.random(NONCE_BYTES),
      ),
    };
    const verify = aeadDecrypt(kek, credential.wrappedProfileKey, profileKeyAad(credential));
    const valid = verify.length === profileKey.length && verify.every((byte, index) =>
      byte === profileKey[index]);
    verify.fill(0);
    if (!valid) throw new VaultError('decrypt-failed', 'profile-key self-verification failed');
    return { credential, profileKey };
  } catch (error) {
    profileKey.fill(0);
    throw error;
  } finally {
    kek?.fill(0);
  }
}

export async function unlockProfileCredential(
  raw: unknown,
  password: string,
): Promise<Uint8Array> {
  const credential = validateProfileCredentialStructure(raw);
  const salt = base64ToBytes(credential.kdf.saltB64);
  const kek = await deriveKek(password, salt, credential.kdf);
  try {
    const profileKey = aeadDecrypt(kek, credential.wrappedProfileKey, profileKeyAad(credential));
    assertKey(profileKey, 'profile key');
    return profileKey;
  } catch (error) {
    if (error instanceof VaultError && error.code === 'tampered') throw error;
    throw new VaultError('wrong-password');
  } finally {
    kek.fill(0);
  }
}

export function addProfileSecret(
  input: {
    profileId: string;
    profileKey: Uint8Array;
    secretId: string;
    kind: ProfileSecretKind;
    secret: Uint8Array;
  },
  deps: Pick<VaultDeps, 'random'>,
): ProfileWrappedSecretV1 {
  assertKey(input.profileKey, 'profile key');
  assertKey(input.secret, 'secret');
  const record: ProfileWrappedSecretV1 = {
    schemaVersion: 1,
    cipherVersion: 1,
    profileId: input.profileId,
    secretId: input.secretId,
    kind: input.kind,
    wrappedSecret: { nonceB64: '', ciphertextB64: '' },
  };
  record.wrappedSecret = aeadEncrypt(
    input.profileKey,
    input.secret,
    secretAad(record),
    deps.random(NONCE_BYTES),
  );
  const verify = unwrapProfileSecret(record, input.profileKey);
  const valid = verify.every((byte, index) => byte === input.secret[index]);
  verify.fill(0);
  if (!valid) throw new VaultError('decrypt-failed', 'profile secret self-verification failed');
  return record;
}

export function unwrapProfileSecret(raw: unknown, profileKey: Uint8Array): Uint8Array {
  assertKey(profileKey, 'profile key');
  const record = validateProfileWrappedSecretStructure(raw);
  try {
    const secret = aeadDecrypt(profileKey, record.wrappedSecret, secretAad(record));
    assertKey(secret, 'profile secret');
    return secret;
  } catch {
    throw new VaultError('tampered', 'profile secret authentication failed');
  }
}

export function removeProfileSecret(
  records: readonly ProfileWrappedSecretV1[],
  input: { profileId: string; secretId: string; kind: ProfileSecretKind },
): ProfileWrappedSecretV1[] {
  return records.filter((record) => !(record.profileId === input.profileId &&
    record.secretId === input.secretId && record.kind === input.kind));
}

/** Wipes the complete in-memory profile unlock scope on lock/background. */
export function zeroizeProfileSession(
  profileKey: Uint8Array | null,
  activeSecret: Uint8Array | null,
): void {
  activeSecret?.fill(0);
  if (profileKey !== activeSecret) profileKey?.fill(0);
}

export async function rewrapProfilePassword(
  raw: unknown,
  oldPassword: string,
  newPassword: string,
  deps: VaultDeps,
  newKdfParams?: Argon2idParams,
): Promise<ProfileCredentialV1> {
  if (!checkPasswordPolicy(newPassword).ok) throw new VaultError('weak-password');
  const credential = validateProfileCredentialStructure(raw);
  const profileKey = await unlockProfileCredential(credential, oldPassword);
  try {
    const kdf = newKdfParams ?? credential.kdf;
    if (!kdfParamsWithinBounds(kdf)) throw new Error('newKdfParams outside KDF_ABSOLUTE_BOUNDS');
    const salt = deps.random(SALT_BYTES);
    const kek = await deriveKek(newPassword, salt, kdf);
    try {
      const next: ProfileCredentialV1 = {
        ...credential,
        kdf: { ...kdf, saltB64: bytesToBase64(salt) },
        wrappedProfileKey: aeadEncrypt(
          kek, profileKey, profileKeyAad(credential), deps.random(NONCE_BYTES),
        ),
      };
      const verify = aeadDecrypt(kek, next.wrappedProfileKey, profileKeyAad(next));
      const valid = verify.every((byte, index) => byte === profileKey[index]);
      verify.fill(0);
      if (!valid) throw new VaultError('decrypt-failed', 'profile rewrap self-verification failed');
      return next;
    } finally {
      kek.fill(0);
    }
  } finally {
    profileKey.fill(0);
  }
}

/**
 * Verify-first legacy link. The input record is never modified: callers keep
 * it until the returned wrapper and their complete persistence transaction
 * have both succeeded.
 */
export async function linkLegacyVaultToProfile(
  input: {
    record: VaultRecordV1;
    password: string;
    profileId: string;
    profileKey: Uint8Array;
  },
  deps: Pick<VaultDeps, 'random'>,
): Promise<ProfileWrappedSecretV1> {
  const unlocked = await unlockVault(input.record, input.password);
  try {
    // Re-open with the returned DEK before constructing replacement state so
    // authenticated-but-invalid legacy payloads can never be linked.
    openVaultPayload(input.record, unlocked.dek);
    return addProfileSecret({
      profileId: input.profileId,
      profileKey: input.profileKey,
      secretId: input.record.vaultId,
      kind: 'wallet-dek',
      secret: unlocked.dek,
    }, deps);
  } finally {
    unlocked.dek.fill(0);
  }
}
