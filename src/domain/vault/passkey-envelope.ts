/**
 * ADR 0007 Workstream A1: platform-neutral passkey-wrapped-DEK envelope.
 *
 * A passkey envelope lets a WebAuthn PRF output unwrap the same random DEK a
 * vault record wraps under the password KEK. The PRF output is convenience
 * key-wrapping material only: it never derives Spending seed S, Vault roots
 * A/B/C, a BIP32 child, or any signing material (spec §7.7), and the app
 * password path remains a peer, never a fallback of last resort.
 *
 * Identity binding follows the A0 spike (docs/passkey-a0-identity-and-
 * compatibility.md): Chromium rewrites an extension's claimed RP ID to the
 * full serialized origin, so v1 binds `rpOrigin` as the exact
 * `chrome-extension://<id>` string. A different platform identity (mobile
 * biometrics, another scheme) is a new envelope version, not a loosened
 * pattern.
 *
 * Fail-closed rules: unknown versions, unknown fields, non-v1 KDF labels,
 * wrong RP/wallet/network expectations, malformed salts, and undersized or
 * all-zero PRF output are all rejected before any key derivation. Everything
 * identity-relevant is additionally bound as AEAD additional data, so a
 * record edited in storage cannot decrypt. `label` and `createdAtMs` are
 * display metadata outside the AAD, mirroring VaultRecordV1: renaming an
 * enrollment must work without the credential, and nothing security-relevant
 * may branch on them.
 *
 * One envelope per enrolled credential (ADR 0007 §5): two credentials never
 * share PRF output, so they never share an envelope. Enrollment lists are
 * validated with assertUniquePasskeyCredentials.
 */
import { z } from 'zod';
import { AEAD_TAG_BYTES, aeadDecrypt, aeadEncrypt, KEY_BYTES, NONCE_BYTES, zeroize } from './crypto';
import { base64ToBytes, bytesToBase64, utf8ToBytes } from './encoding';
import { VaultError } from './errors';
import { hkdfSha256 } from './hkdf';
import type { AeadBox } from './record';
import type { Network } from '../keys/derivation';

export const PASSKEY_ENVELOPE_VERSION = 1 as const;
export const PASSKEY_ENVELOPE_KDF = 'hkdf-sha256-v1' as const;
export const PASSKEY_PRF_OUTPUT_BYTES = 32;
export const PASSKEY_PRF_SALT_BYTES = 32;
export const PASSKEY_HKDF_SALT_BYTES = 32;

const PRF_INPUT_DOMAIN = 'drey-passkey-prf/v1';
const KEK_INFO_DOMAIN = 'drey-passkey-kek';
const AAD_DOMAIN = 'drey-passkey-envelope';

/** Exact Chromium extension origin, per the A0 identity decision. */
const RP_ORIGIN_PATTERN = /^chrome-extension:\/\/[a-p]{32}$/u;

export interface PasskeyEnvelopeV1 {
  version: 1;
  kdf: typeof PASSKEY_ENVELOPE_KDF;
  rpOrigin: string;
  vaultId: string;
  network: Network;
  credentialIdB64: string;
  prfSaltB64: string; // 32 bytes; WebAuthn PRF eval input = domain ‖ 0x00 ‖ salt
  hkdfSaltB64: string; // 32 bytes; HKDF-SHA256 extract salt
  // Display metadata, deliberately OUTSIDE the AEAD additional data (see
  // module docblock).
  label: string;
  createdAtMs: number;
  wrappedDek: AeadBox; // XChaCha20-Poly1305(KEK, DEK) with identity AAD
}

/** WebAuthn credential IDs are at most 1023 bytes. */
const CREDENTIAL_ID_MIN_BYTES = 16;
const CREDENTIAL_ID_MAX_BYTES = 1023;

/**
 * atob() is forgiving (missing padding, embedded whitespace), so one byte
 * string has many accepted encodings. Every Base64 field is required to be
 * the exact canonical padded encoding, otherwise two envelopes for one
 * physical credential could alias past assertUniquePasskeyCredentials and
 * the AAD would bind an ambiguous spelling.
 */
const canonicalBase64Bytes = (value: string): Uint8Array | undefined => {
  try {
    const bytes = base64ToBytes(value);
    return bytesToBase64(bytes) === value ? bytes : undefined;
  } catch {
    return undefined;
  }
};

const base64Schema = (byteLength: number): z.ZodType<string> =>
  z.string().refine((value) => canonicalBase64Bytes(value)?.length === byteLength);

const aeadBoxSchema = z
  .object({
    // Exactly one 24-byte nonce and one 32-byte DEK plus 16-byte tag: an
    // envelope that authenticates must only ever unwrap to a 32-byte DEK.
    nonceB64: base64Schema(NONCE_BYTES),
    ciphertextB64: base64Schema(KEY_BYTES + AEAD_TAG_BYTES),
  })
  .strict();

export const passkeyEnvelopeV1Schema = z
  .object({
    version: z.literal(PASSKEY_ENVELOPE_VERSION),
    kdf: z.literal(PASSKEY_ENVELOPE_KDF),
    rpOrigin: z.string().regex(RP_ORIGIN_PATTERN),
    vaultId: z.string().min(1),
    network: z.enum(['mainnet', 'signet']),
    credentialIdB64: z.string().refine((value) => {
      const length = canonicalBase64Bytes(value)?.length ?? 0;
      return length >= CREDENTIAL_ID_MIN_BYTES && length <= CREDENTIAL_ID_MAX_BYTES;
    }),
    prfSaltB64: base64Schema(PASSKEY_PRF_SALT_BYTES),
    hkdfSaltB64: base64Schema(PASSKEY_HKDF_SALT_BYTES),
    label: z.string(),
    createdAtMs: z.number().int().nonnegative(),
    wrappedDek: aeadBoxSchema,
  })
  .strict();

export function parsePasskeyEnvelope(value: unknown): PasskeyEnvelopeV1 {
  if (typeof value === 'object' && value !== null) {
    const version = (value as { version?: unknown }).version;
    if (version !== PASSKEY_ENVELOPE_VERSION) {
      throw new VaultError('unsupported-version', 'unknown passkey envelope version');
    }
  }
  const parsed = passkeyEnvelopeV1Schema.safeParse(value);
  if (!parsed.success) throw new VaultError('tampered', 'malformed passkey envelope');
  return parsed.data;
}

/**
 * Bytes the WebAuthn adapter passes as `prf.eval.first`. The salt keeps PRF
 * inputs distinct per enrollment; the domain prefix keeps Drey's evaluations
 * disjoint from any other application's use of the same credential.
 */
export function passkeyPrfEvalInput(prfSalt: Uint8Array): Uint8Array {
  if (prfSalt.length !== PASSKEY_PRF_SALT_BYTES) {
    throw new VaultError('tampered', `prf salt must be ${PASSKEY_PRF_SALT_BYTES} bytes`);
  }
  const domain = utf8ToBytes(PRF_INPUT_DOMAIN);
  const input = new Uint8Array(domain.length + 1 + prfSalt.length);
  input.set(domain);
  input.set(prfSalt, domain.length + 1);
  return input;
}

/**
 * Accepts the raw stored value and parses it fail-closed first: an unknown or
 * malformed record must never be able to provoke a WebAuthn user-verification
 * ceremony before it would be rejected by unwrapPasskeyDek anyway.
 */
export function passkeyPrfEvalInputForEnvelope(envelope: unknown): Uint8Array {
  return passkeyPrfEvalInput(base64ToBytes(parsePasskeyEnvelope(envelope).prfSaltB64));
}

interface EnvelopeIdentity {
  rpOrigin: string;
  vaultId: string;
  network: Network;
  credentialIdB64: string;
}

/**
 * JSON-array joining rather than the vault record's colon joining: rpOrigin
 * contains separator characters, and an ambiguous concatenation would let two
 * different identities produce one authenticated string.
 */
function envelopeAad(identity: EnvelopeIdentity, prfSaltB64: string, hkdfSaltB64: string): string {
  return JSON.stringify([
    AAD_DOMAIN,
    PASSKEY_ENVELOPE_VERSION,
    identity.rpOrigin,
    identity.vaultId,
    identity.network,
    identity.credentialIdB64,
    prfSaltB64,
    hkdfSaltB64,
  ]);
}

function kekInfo(identity: EnvelopeIdentity): Uint8Array {
  return utf8ToBytes(
    JSON.stringify([
      KEK_INFO_DOMAIN,
      PASSKEY_ENVELOPE_VERSION,
      identity.rpOrigin,
      identity.vaultId,
      identity.network,
      identity.credentialIdB64,
    ]),
  );
}

function assertPrfOutput(prfOutput: Uint8Array): void {
  if (prfOutput.length !== PASSKEY_PRF_OUTPUT_BYTES) {
    throw new VaultError('invalid-prf-output', 'prf output must be 32 bytes');
  }
  if (prfOutput.every((byte) => byte === 0)) {
    throw new VaultError('invalid-prf-output', 'prf output is all zero');
  }
}

function derivePasskeyKek(prfOutput: Uint8Array, hkdfSalt: Uint8Array, identity: EnvelopeIdentity): Uint8Array {
  assertPrfOutput(prfOutput);
  return hkdfSha256(prfOutput, hkdfSalt, kekInfo(identity), KEY_BYTES);
}

export interface CreatePasskeyEnvelopeInput {
  dek: Uint8Array;
  prfOutput: Uint8Array;
  rpOrigin: string;
  vaultId: string;
  network: Network;
  credentialIdB64: string;
  label: string;
  createdAtMs: number;
  /** Fresh CSPRNG bytes from the platform provider; fixed only in vectors. */
  prfSalt: Uint8Array;
  hkdfSalt: Uint8Array;
  nonce: Uint8Array;
}

export function createPasskeyEnvelope(input: CreatePasskeyEnvelopeInput): PasskeyEnvelopeV1 {
  if (input.dek.length !== KEY_BYTES) throw new VaultError('tampered', 'dek must be 32 bytes');
  if (input.prfSalt.length !== PASSKEY_PRF_SALT_BYTES) {
    throw new VaultError('tampered', 'prf salt must be 32 bytes');
  }
  if (input.hkdfSalt.length !== PASSKEY_HKDF_SALT_BYTES) {
    throw new VaultError('tampered', 'hkdf salt must be 32 bytes');
  }
  if (input.nonce.length !== NONCE_BYTES) throw new VaultError('tampered', 'nonce must be 24 bytes');
  const identity: EnvelopeIdentity = {
    rpOrigin: input.rpOrigin,
    vaultId: input.vaultId,
    network: input.network,
    credentialIdB64: input.credentialIdB64,
  };
  const prfSaltB64 = bytesToBase64(input.prfSalt);
  const hkdfSaltB64 = bytesToBase64(input.hkdfSalt);
  const kek = derivePasskeyKek(input.prfOutput, input.hkdfSalt, identity);
  try {
    const wrappedDek = aeadEncrypt(
      kek,
      input.dek,
      envelopeAad(identity, prfSaltB64, hkdfSaltB64),
      input.nonce,
    );
    const envelope: PasskeyEnvelopeV1 = {
      version: PASSKEY_ENVELOPE_VERSION,
      kdf: PASSKEY_ENVELOPE_KDF,
      rpOrigin: input.rpOrigin,
      vaultId: input.vaultId,
      network: input.network,
      credentialIdB64: input.credentialIdB64,
      prfSaltB64,
      hkdfSaltB64,
      label: input.label,
      createdAtMs: input.createdAtMs,
      wrappedDek,
    };
    // Reject at creation anything parse would reject later (bad rpOrigin,
    // short credential ID): an unstorable envelope must never be handed out.
    return parsePasskeyEnvelope(envelope);
  } finally {
    zeroize(kek);
  }
}

export interface UnwrapPasskeyDekInput {
  envelope: unknown;
  prfOutput: Uint8Array;
  expected: { rpOrigin: string; vaultId: string; network: Network };
}

export function unwrapPasskeyDek(input: UnwrapPasskeyDekInput): Uint8Array {
  const envelope = parsePasskeyEnvelope(input.envelope);
  // Explicit identity checks first: a wrong-context envelope is rejected with
  // a typed mismatch before any key derivation, and the AAD binding below
  // still enforces the same facts cryptographically.
  if (
    envelope.rpOrigin !== input.expected.rpOrigin ||
    envelope.vaultId !== input.expected.vaultId ||
    envelope.network !== input.expected.network
  ) {
    throw new VaultError('identity-mismatch', 'passkey envelope does not match this wallet identity');
  }
  const identity: EnvelopeIdentity = {
    rpOrigin: envelope.rpOrigin,
    vaultId: envelope.vaultId,
    network: envelope.network,
    credentialIdB64: envelope.credentialIdB64,
  };
  const kek = derivePasskeyKek(input.prfOutput, base64ToBytes(envelope.hkdfSaltB64), identity);
  try {
    const dek = aeadDecrypt(
      kek,
      envelope.wrappedDek,
      envelopeAad(identity, envelope.prfSaltB64, envelope.hkdfSaltB64),
    );
    // The schema already pins the ciphertext to DEK + tag; keep the invariant
    // explicit at the boundary that hands out key material.
    if (dek.length !== KEY_BYTES) {
      zeroize(dek);
      throw new VaultError('tampered', 'unwrapped dek has the wrong length');
    }
    return dek;
  } finally {
    zeroize(kek);
  }
}

/**
 * ADR 0007 §5: one envelope per enrolled credential. String comparison is
 * byte comparison because the schema admits only canonical Base64; callers
 * must pass parsed envelopes, never type-asserted storage.
 */
export function assertUniquePasskeyCredentials(envelopes: readonly PasskeyEnvelopeV1[]): void {
  const seen = new Set<string>();
  for (const envelope of envelopes) {
    const key = `${envelope.vaultId} ${envelope.credentialIdB64}`;
    if (seen.has(key)) {
      throw new VaultError('duplicate-credential', 'credential already has an envelope for this wallet');
    }
    seen.add(key);
  }
}
