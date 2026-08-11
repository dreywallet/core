/**
 * Versioned vault-record migration runner (spec §25.2).
 *
 * Migrations are pure metadata transforms: no password is available, so a
 * migration may only reshape the envelope — ciphertexts, nonces, salts, and
 * the cipherVersion baked into their AEAD additional data are carried forward
 * byte-identical.
 *
 * Caller contract: keep the prior encrypted record persisted until the
 * migrated record has been written and re-validated; this function throws
 * without partial output on any failure, which makes that swap trivially safe.
 *
 * The v0 shape below is the pre-versioned flat layout used before this module
 * existed (no schemaVersion field, flat KDF fields).
 */
import { z } from 'zod';
import { VaultError } from './errors';
import { vaultRecordV1Schema, type VaultRecordV1 } from './record';

export const CURRENT_VAULT_SCHEMA_VERSION = 1;

const aeadBoxV0Schema = z.object({ nonceB64: z.string().min(1), ciphertextB64: z.string().min(1) }).strict();

const vaultRecordV0Schema = z
  .object({
    vaultId: z.string().min(1),
    name: z.string(),
    createdAt: z.number().int().nonnegative(),
    salt: z.string().min(1),
    opslimit: z.number().int().positive(),
    memlimit: z.number().int().positive(),
    wrappedDek: aeadBoxV0Schema,
    payload: aeadBoxV0Schema,
  })
  .strict();

type VaultRecordV0 = z.infer<typeof vaultRecordV0Schema>;

function migrateV0ToV1(v0: VaultRecordV0): VaultRecordV1 {
  return {
    schemaVersion: 1,
    // v0 records were encrypted with the v1 AAD scheme's cipherVersion 1.
    cipherVersion: 1,
    vaultId: v0.vaultId,
    name: v0.name,
    createdAt: v0.createdAt,
    kdf: {
      paramsVersion: 1,
      algorithm: 'argon2id13',
      opsLimit: v0.opslimit,
      memLimitBytes: v0.memlimit,
      parallelism: 1,
      saltB64: v0.salt,
    },
    wrappedDek: v0.wrappedDek,
    payload: v0.payload,
  };
}

export function migrateVaultRecord(raw: unknown): { record: VaultRecordV1; migrated: boolean } {
  const versioned = z.object({ schemaVersion: z.number() }).safeParse(raw);

  if (!versioned.success) {
    // No schemaVersion field: the only known unversioned shape is v0.
    const v0 = vaultRecordV0Schema.safeParse(raw);
    if (!v0.success) throw new VaultError('unsupported-version', 'unrecognized vault record shape');
    const migrated = vaultRecordV1Schema.safeParse(migrateV0ToV1(v0.data));
    if (!migrated.success) {
      // e.g. v0 KDF params outside the v1 absolute bounds — typed, no partial output.
      throw new VaultError('unsupported-version', 'migrated record failed v1 validation');
    }
    return { record: migrated.data, migrated: true };
  }

  if (versioned.data.schemaVersion === 1) {
    const v1 = vaultRecordV1Schema.safeParse(raw);
    if (!v1.success) throw new VaultError('unsupported-version', 'invalid v1 vault record');
    return { record: v1.data, migrated: false };
  }

  throw new VaultError(
    'unsupported-version',
    `vault record schemaVersion ${versioned.data.schemaVersion} is newer than supported (${CURRENT_VAULT_SCHEMA_VERSION})`,
  );
}
