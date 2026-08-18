/**
 * Versioned vault record format (spec §7.2, §25.2).
 *
 * Two version fields on purpose:
 * - schemaVersion: the JSON envelope shape; migrations bump it freely because
 *   they are pure metadata transforms run without the password.
 * - cipherVersion: baked into the AEAD additional data at encryption time; it
 *   changes only when material is actually re-encrypted (create, password
 *   change), so a schema migration carries it forward and old ciphertexts
 *   still authenticate.
 */
import { z } from 'zod';
import { base64ToBytes } from './encoding';

export interface Argon2idParams {
  paramsVersion: 1;
  algorithm: 'argon2id13';
  opsLimit: number; // iterations; floor 3 (spec §7.2)
  memLimitBytes: number; // floor 64 MiB (spec §7.2)
  parallelism: 1; // libsodium crypto_pwhash is fixed at 1
}

/**
 * Absolute sanity bounds on stored KDF params, enforced at parse time and
 * again before any derivation runs. Records are stored in extension storage
 * an attacker may be able to write (§6.3): without an upper bound, tampered
 * params (e.g. memLimitBytes 2^31) would OOM or hang the service worker at
 * unlock — a DoS that AAD cannot catch because the KDF must run before any
 * authentication check. The opsLimit maximum equals the calibration cap; the
 * memLimitBytes maximum deliberately exceeds the 64 MiB creation ceiling
 * (ADR 0006) so records calibrated under the pre-D4 memory-first ladder (up
 * to 256 MiB, but never above opsLimit 10 — its cap at the time) still parse
 * and unlock. The two maxima are NOT a free cross-product: no legitimate
 * ladder ever emitted >64 MiB together with >10 ops, so that combination is
 * rejected to keep the tampered-record worst case at its pre-D4 level. The
 * minima stay permissive because sub-floor records (tests, migrated legacy
 * data) must still unlock — spec §7.2 floors are a creation-time rule,
 * enforced by calibrateArgon2id.
 */
export const KDF_ABSOLUTE_BOUNDS = {
  opsLimit: { min: 1, max: 16 },
  memLimitBytes: { min: 8 * 2 ** 20, max: 256 * 2 ** 20 },
  /** Records above the 64 MiB creation ceiling (pre-D4 ladder) never exceeded ops 10. */
  legacyHighMemory: { aboveMemLimitBytes: 64 * 2 ** 20, opsLimitMax: 10 },
} as const;

export function kdfParamsWithinBounds(params: Argon2idParams): boolean {
  return (
    Number.isInteger(params.opsLimit) &&
    params.opsLimit >= KDF_ABSOLUTE_BOUNDS.opsLimit.min &&
    params.opsLimit <= KDF_ABSOLUTE_BOUNDS.opsLimit.max &&
    Number.isInteger(params.memLimitBytes) &&
    params.memLimitBytes >= KDF_ABSOLUTE_BOUNDS.memLimitBytes.min &&
    params.memLimitBytes <= KDF_ABSOLUTE_BOUNDS.memLimitBytes.max &&
    (params.memLimitBytes <= KDF_ABSOLUTE_BOUNDS.legacyHighMemory.aboveMemLimitBytes ||
      params.opsLimit <= KDF_ABSOLUTE_BOUNDS.legacyHighMemory.opsLimitMax)
  );
}

export interface AeadBox {
  nonceB64: string; // 24-byte XChaCha20 nonce
  ciphertextB64: string;
}

export interface VaultRecordV1 {
  schemaVersion: 1;
  cipherVersion: 1;
  vaultId: string;
  // name and createdAt are deliberately OUTSIDE the AEAD additional data:
  // renaming a vault must work without the password, so display metadata is
  // unauthenticated. Nothing security-relevant may ever branch on these
  // fields; everything that matters is bound via vaultId/cipherVersion AAD.
  name: string;
  createdAt: number;
  kdf: Argon2idParams & { saltB64: string }; // independent 16-byte salt + calibrated params per record
  wrappedDek: AeadBox; // AEAD(KEK = Argon2id(password, salt, params), DEK)
  payload: AeadBox; // AEAD(DEK, utf8(JSON(VaultPayloadV1)))
}

export interface VaultPayloadV1 {
  version: 1;
  entropyHex: string; // BIP39 entropy, 16–32 bytes
  passphrase?: string; // present only for passphrase restores
  seedHex: string; // cached 64-byte BIP39 seed so unlock skips PBKDF2
}

export const VAULT_PAYLOAD_PLAINTEXT_MAX_BYTES = 1024 * 1024;
export const VAULT_PAYLOAD_CIPHERTEXT_MAX_BYTES = VAULT_PAYLOAD_PLAINTEXT_MAX_BYTES + 16;
export const VAULT_WRAPPED_DEK_CIPHERTEXT_BYTES = 32 + 16;

const base64Length = (bytes: number): number => 4 * Math.ceil(bytes / 3);
const hasDecodedLength = (value: string, predicate: (length: number) => boolean): boolean => {
  try {
    return predicate(base64ToBytes(value).length);
  } catch {
    return false;
  }
};

const argon2idParamsSchema = z
  .object({
    paramsVersion: z.literal(1),
    algorithm: z.literal('argon2id13'),
    opsLimit: z.number().int().min(KDF_ABSOLUTE_BOUNDS.opsLimit.min).max(KDF_ABSOLUTE_BOUNDS.opsLimit.max),
    memLimitBytes: z
      .number()
      .int()
      .min(KDF_ABSOLUTE_BOUNDS.memLimitBytes.min)
      .max(KDF_ABSOLUTE_BOUNDS.memLimitBytes.max),
    parallelism: z.literal(1),
  })
  .strict();

const nonceB64Schema = z.string().length(base64Length(24))
  .refine((value) => hasDecodedLength(value, (length) => length === 24));
const wrappedDekBoxSchema = z.object({
  nonceB64: nonceB64Schema,
  ciphertextB64: z.string().length(base64Length(VAULT_WRAPPED_DEK_CIPHERTEXT_BYTES))
    .refine((value) => hasDecodedLength(
      value, (length) => length === VAULT_WRAPPED_DEK_CIPHERTEXT_BYTES,
    )),
}).strict();
const payloadBoxSchema = z.object({
  nonceB64: nonceB64Schema,
  ciphertextB64: z.string()
    .min(base64Length(17))
    .max(base64Length(VAULT_PAYLOAD_CIPHERTEXT_MAX_BYTES))
    .refine((value) => hasDecodedLength(
      value, (length) => length > 16 && length <= VAULT_PAYLOAD_CIPHERTEXT_MAX_BYTES,
    )),
}).strict();

export const vaultRecordV1Schema = z
  .object({
    schemaVersion: z.literal(1),
    cipherVersion: z.literal(1),
    vaultId: z.string().min(1),
    name: z.string(),
    createdAt: z.number().int().nonnegative(),
    kdf: argon2idParamsSchema.extend({
      saltB64: z.string().length(base64Length(16))
        .refine((value) => hasDecodedLength(value, (length) => length === 16)),
    }).strict(),
    wrappedDek: wrappedDekBoxSchema,
    payload: payloadBoxSchema,
  })
  .strict();

export const vaultPayloadV1Schema = z
  .object({
    version: z.literal(1),
    // BIP39 permits only 128/160/192/224/256 bits. A generic 16–32 byte
    // range also admits lengths that entropyToMnemonic cannot represent.
    entropyHex: z
      .string()
      .regex(/^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{48}|[0-9a-f]{56}|[0-9a-f]{64})$/u),
    passphrase: z.string().optional(),
    seedHex: z.string().regex(/^[0-9a-f]{128}$/u),
  })
  .strict();

export function dekAad(cipherVersion: number, vaultId: string): string {
  return `squirrel-vault:v${cipherVersion}:${vaultId}:dek`;
}

export function payloadAad(cipherVersion: number, vaultId: string): string {
  return `squirrel-vault:v${cipherVersion}:${vaultId}:payload`;
}
