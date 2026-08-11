/**
 * Vault operations (spec §7.2, §7.3): pure functions over serializable
 * encrypted records. Callers own persistence; nothing here touches storage.
 *
 * Each record carries its own KDF salt and calibrated params, so unlock reads
 * exactly one record and password change is a pure map over records. The cost
 * is that changePassword runs two Argon2id derivations per vault — acceptable
 * for a rare operation over a handful of vaults.
 */
import { aeadDecrypt, aeadEncrypt, deriveKek, KEY_BYTES, NONCE_BYTES, SALT_BYTES } from './crypto';
import { entropyToMnemonic, mnemonicToSeed } from '../keys/mnemonic';
import { base64ToBytes, bytesToBase64, bytesToUtf8, hexToBytes, utf8ToBytes } from './encoding';
import { VaultError } from './errors';
import { checkPasswordPolicy } from './password';
import {
  dekAad,
  kdfParamsWithinBounds,
  payloadAad,
  vaultPayloadV1Schema,
  type AeadBox,
  type Argon2idParams,
  type VaultPayloadV1,
  type VaultRecordV1,
} from './record';

export interface VaultDeps {
  random: (byteLength: number) => Uint8Array;
  now: () => number;
}

export function webCryptoDeps(): VaultDeps {
  return {
    random: (n) => globalThis.crypto.getRandomValues(new Uint8Array(n)),
    now: () => Date.now(),
  };
}

export async function createVaultRecord(
  args: {
    vaultId: string;
    name: string;
    password: string;
    payload: VaultPayloadV1;
    kdfParams: Argon2idParams;
  },
  deps: VaultDeps,
): Promise<VaultRecordV1> {
  const policy = checkPasswordPolicy(args.password);
  if (!policy.ok) throw new VaultError('weak-password', 'password must be at least 12 characters');
  if (!kdfParamsWithinBounds(args.kdfParams)) {
    throw new Error('kdfParams outside KDF_ABSOLUTE_BOUNDS'); // programmer error, not tampering
  }
  const parsedPayload = vaultPayloadV1Schema.safeParse(args.payload);
  if (!parsedPayload.success || !payloadSeedMatchesEntropy(parsedPayload.data)) {
    throw new Error('invalid vault payload: entropy, passphrase, and seed must describe one mnemonic');
  }

  const salt = deps.random(SALT_BYTES);
  const dek = deps.random(KEY_BYTES);
  let kek: Uint8Array | undefined;
  try {
    // The await stays inside the cleanup region: a rejecting KDF (native
    // provider cancellation/allocation failure) must still wipe the fresh DEK.
    kek = await deriveKek(args.password, salt, args.kdfParams);
    return {
      schemaVersion: 1,
      cipherVersion: 1,
      vaultId: args.vaultId,
      name: args.name,
      createdAt: deps.now(),
      kdf: { ...args.kdfParams, saltB64: bytesToBase64(salt) },
      wrappedDek: aeadEncrypt(kek, dek, dekAad(1, args.vaultId), deps.random(NONCE_BYTES)),
      payload: aeadEncrypt(
        dek,
        utf8ToBytes(JSON.stringify(args.payload)),
        payloadAad(1, args.vaultId),
        deps.random(NONCE_BYTES),
      ),
    };
  } finally {
    kek?.fill(0);
    dek.fill(0);
  }
}

export interface UnlockedVault {
  vaultId: string;
  dek: Uint8Array;
  payload: VaultPayloadV1;
}

function tryBase64(b64: string): Uint8Array | undefined {
  try {
    return base64ToBytes(b64);
  } catch {
    return undefined;
  }
}

const AEAD_TAG_BYTES = 16; // Poly1305 tag appended to every ciphertext

function checkBox(box: AeadBox, what: string): void {
  const nonce = tryBase64(box.nonceB64);
  if (!nonce || nonce.length !== NONCE_BYTES) {
    throw new VaultError('tampered', `${what} nonce is malformed`);
  }
  const ciphertext = tryBase64(box.ciphertextB64);
  if (!ciphertext || ciphertext.length <= AEAD_TAG_BYTES) {
    throw new VaultError('tampered', `${what} ciphertext is malformed`);
  }
}

/**
 * Structural validation of a stored record before any key derivation runs.
 * Malformed base64, wrong-length salts/nonces, and out-of-bounds KDF params
 * are provable tampering — no password needed to detect them — so they must
 * surface as 'tampered', never as 'wrong-password' (which per §7.6 would
 * steer a user toward a destructive reset) and never as an untyped error.
 * The KDF bound check also blocks the resource-exhaustion attack of inflating
 * opsLimit/memLimitBytes in storage to hang the worker at unlock.
 */
function validateRecordStructure(record: VaultRecordV1): void {
  if (!kdfParamsWithinBounds(record.kdf)) {
    throw new VaultError('tampered', 'kdf params outside absolute bounds');
  }
  const salt = tryBase64(record.kdf.saltB64);
  if (!salt || salt.length !== SALT_BYTES) {
    throw new VaultError('tampered', 'kdf salt is malformed');
  }
  checkBox(record.wrappedDek, 'wrappedDek');
  checkBox(record.payload, 'payload');
}

async function unwrapDek(record: VaultRecordV1, password: string): Promise<Uint8Array> {
  validateRecordStructure(record);
  const kek = await deriveKek(password, base64Salt(record), record.kdf);
  try {
    return aeadDecrypt(kek, record.wrappedDek, dekAad(record.cipherVersion, record.vaultId));
  } catch {
    throw new VaultError('wrong-password');
  } finally {
    kek.fill(0);
  }
}

/**
 * Decrypts a record's payload with an already-unwrapped DEK (e.g. the active
 * session's). Never mutates or zeroizes `dek`; the caller owns it.
 */
export function openVaultPayload(record: VaultRecordV1, dek: Uint8Array): VaultPayloadV1 {
  let plaintext: Uint8Array;
  try {
    plaintext = aeadDecrypt(dek, record.payload, payloadAad(record.cipherVersion, record.vaultId));
  } catch {
    // A DEK that unwrapped under the password (or came from a live session)
    // failing here means the payload was altered.
    throw new VaultError('tampered');
  }
  let parsed: ReturnType<typeof vaultPayloadV1Schema.safeParse>;
  try {
    parsed = vaultPayloadV1Schema.safeParse(JSON.parse(bytesToUtf8(plaintext)));
  } catch {
    // Authenticated but not valid UTF-8 JSON: still tampering (or a writer
    // bug), and secrets must be wiped on this path like every other.
    plaintext.fill(0);
    throw new VaultError('tampered', 'payload is not valid UTF-8 JSON');
  }
  plaintext.fill(0);
  if (!parsed.success) {
    throw new VaultError('tampered', 'payload failed schema validation');
  }
  if (!payloadSeedMatchesEntropy(parsed.data)) {
    // This is an authenticated writer/migration invariant violation. Never
    // silently choose one half: either choice could hide the funded wallet or
    // display a backup for a different one. Preserve the encrypted record and
    // fail closed so dedicated recovery tooling can inspect it later.
    throw new VaultError('tampered', 'payload entropy and seed do not correspond');
  }
  return parsed.data as VaultPayloadV1;
}

function payloadSeedMatchesEntropy(payload: {
  entropyHex: string;
  seedHex: string;
  passphrase?: string | undefined;
}): boolean {
  const entropy = hexToBytes(payload.entropyHex);
  const storedSeed = hexToBytes(payload.seedHex);
  let expectedSeed: Uint8Array | undefined;
  try {
    expectedSeed = mnemonicToSeed(entropyToMnemonic(entropy), payload.passphrase);
    if (expectedSeed.length !== storedSeed.length) return false;
    let difference = 0;
    for (let i = 0; i < expectedSeed.length; i += 1) {
      difference |= (expectedSeed[i] ?? 0) ^ (storedSeed[i] ?? 0);
    }
    return difference === 0;
  } finally {
    entropy.fill(0);
    storedSeed.fill(0);
    expectedSeed?.fill(0);
  }
}

/**
 * Unlocks exactly one vault (spec §7.3 active-vault isolation): only this
 * record's DEK and payload are ever derived or returned.
 */
export async function unlockVault(record: VaultRecordV1, password: string): Promise<UnlockedVault> {
  const dek = await unwrapDek(record, password);
  try {
    return { vaultId: record.vaultId, dek, payload: openVaultPayload(record, dek) };
  } catch (err) {
    dek.fill(0);
    throw err;
  }
}

/**
 * Reauthenticate without opening the encrypted seed payload. This unwraps only
 * the random DEK, proving the password against wrappedDek, and immediately
 * destroys it. Public-only operations use this boundary so seed plaintext is
 * never materialized as a side effect of authentication.
 */
export async function verifyVaultPassword(record: VaultRecordV1, password: string): Promise<void> {
  const dek = await unwrapDek(record, password);
  dek.fill(0);
}

/**
 * Atomic password change (spec §7.2): rewraps every vault's DEK under the new
 * password without re-encrypting any payload. Two phases — first every DEK is
 * unwrapped with the old password (any failure throws before anything is
 * built), then each rewrap is self-verified. Inputs are never mutated; the
 * caller swaps in the returned records only as one atomic persistence step.
 *
 * newKdfParams (optional) upgrades every record's KDF parameters during the
 * rewrap — the one moment the password is in hand for free — so records
 * migrated from legacy formats with sub-floor params can be brought up to a
 * freshly calibrated strength (spec §7.2).
 */
export async function changePassword(
  records: readonly VaultRecordV1[],
  oldPassword: string,
  newPassword: string,
  deps: VaultDeps,
  newKdfParams?: Argon2idParams,
): Promise<VaultRecordV1[]> {
  const policy = checkPasswordPolicy(newPassword);
  if (!policy.ok) throw new VaultError('weak-password', 'password must be at least 12 characters');
  if (newKdfParams && !kdfParamsWithinBounds(newKdfParams)) {
    throw new Error('newKdfParams outside KDF_ABSOLUTE_BOUNDS'); // programmer error, not tampering
  }

  const deks: Uint8Array[] = [];
  try {
    // Keep acquisition inside the cleanup region: if a later record rejects
    // the old password, every DEK already unwrapped is still zeroized. The
    // two phases stay strictly sequential under the asynchronous KDF — every
    // DEK must unwrap before the first rewrap is built, so a mid-list failure
    // can never leave a half-rewrapped result.
    for (const record of records) deks.push(await unwrapDek(record, oldPassword));
    const rewrapped: VaultRecordV1[] = [];
    for (const [i, record] of records.entries()) {
      const dek = deks[i];
      if (!dek) throw new VaultError('decrypt-failed');
      const kdfParams: Argon2idParams = newKdfParams ?? {
        paramsVersion: record.kdf.paramsVersion,
        algorithm: record.kdf.algorithm,
        opsLimit: record.kdf.opsLimit,
        memLimitBytes: record.kdf.memLimitBytes,
        parallelism: record.kdf.parallelism,
      };
      const salt = deps.random(SALT_BYTES);
      const kek = await deriveKek(newPassword, salt, kdfParams);
      try {
        const wrappedDek = aeadEncrypt(
          kek,
          dek,
          dekAad(record.cipherVersion, record.vaultId),
          deps.random(NONCE_BYTES),
        );
        const verify = aeadDecrypt(kek, wrappedDek, dekAad(record.cipherVersion, record.vaultId));
        const matches = verify.length === dek.length && verify.every((b, j) => b === dek[j]);
        verify.fill(0);
        if (!matches) throw new VaultError('decrypt-failed', 'rewrap self-verification failed');
        rewrapped.push({ ...record, kdf: { ...kdfParams, saltB64: bytesToBase64(salt) }, wrappedDek });
      } finally {
        kek.fill(0);
      }
    }
    return rewrapped;
  } finally {
    for (const dek of deks) dek.fill(0);
  }
}

function base64Salt(record: VaultRecordV1): Uint8Array {
  return base64ToBytes(record.kdf.saltB64);
}

export { zeroize } from './crypto';
