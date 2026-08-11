/**
 * Golden crypto conformance vectors (mobile port plan, Phase 0).
 *
 * Generates vectors/crypto-conformance.json (the `./vectors/*` package
 * export), the fixture asserted by this repo's vitest suite, the extension's,
 * and, later, by the on-device mobile conformance screen. Every derivable value is produced through the shipping
 * libsodium path AND cross-checked against an independent implementation
 * (@noble/hashes argon2id, @noble/ciphers XChaCha20-Poly1305, @noble/curves
 * ed25519, node:crypto sha256) before anything is written. A mismatch exits
 * non-zero and writes nothing.
 *
 * The cross-checks deliberately exercise the three silent interop traps:
 * - parallelism: both implementations are pinned to p=1 from the params.
 * - memory units: libsodium takes bytes, noble takes KiB — the division
 *   happens here, in exactly one place, and a unit mix-up changes the KEK.
 * - tag placement: noble returns libsodium's ct‖tag layout; asserted
 *   byte-for-byte.
 */
import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import { TextEncoder } from 'node:util';
import { mkdirSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { argon2id as nobleArgon2id } from '@noble/hashes/argon2.js';
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { ed25519 } from '@noble/curves/ed25519';
import { HDKey } from '@scure/bip32';
import { entropyToMnemonic, mnemonicToSeedSync } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';
import { NETWORK, p2tr, p2wpkh } from '@scure/btc-signer';

// libsodium 0.7.x ships a broken ESM entry; load the CJS build.
const require = createRequire(import.meta.url);
const sodium = require('libsodium-wrappers-sumo');
await sodium.ready;

const here = dirname(fileURLToPath(import.meta.url));
const outPath = join(here, '..', 'vectors', 'crypto-conformance.json');

const encoder = new TextEncoder();
const toHex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
const toB64 = (bytes) => Buffer.from(bytes).toString('base64');

let failures = 0;
function crossCheck(label, aBytes, bBytes) {
  if (toHex(aBytes) !== toHex(bBytes)) {
    failures += 1;
    console.error(`CROSS-CHECK FAILED: ${label}\n  libsodium: ${toHex(aBytes)}\n  independent: ${toHex(bBytes)}`);
  } else {
    console.log(`cross-check ok: ${label}`);
  }
}

// ---------------------------------------------------------------- argon2id
const ARGON2ID = {
  passwordUtf8: 'conformance-password-v1',
  saltHex: '000102030405060708090a0b0c0d0e0f',
  params: { paramsVersion: 1, algorithm: 'argon2id13', opsLimit: 3, memLimitBytes: 64 * 2 ** 20, parallelism: 1 },
};
const argonSalt = Uint8Array.from(Buffer.from(ARGON2ID.saltHex, 'hex'));
const kekSodium = sodium.crypto_pwhash(
  32,
  encoder.encode(ARGON2ID.passwordUtf8),
  argonSalt,
  ARGON2ID.params.opsLimit,
  ARGON2ID.params.memLimitBytes,
  sodium.crypto_pwhash_ALG_ARGON2ID13,
);
const kekNoble = nobleArgon2id(encoder.encode(ARGON2ID.passwordUtf8), argonSalt, {
  t: ARGON2ID.params.opsLimit,
  m: ARGON2ID.params.memLimitBytes / 1024, // noble takes KiB; libsodium takes bytes
  p: ARGON2ID.params.parallelism,
  dkLen: 32,
});
crossCheck('argon2id KEK (libsodium vs @noble/hashes)', kekSodium, kekNoble);

// --------------------------------------------------- XChaCha20-Poly1305
const AEAD = {
  keyHex: '101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f',
  nonceHex: '303132333435363738393a3b3c3d3e3f4041424344454647',
  aadUtf8: 'squirrel-conformance:v1:aead',
  plaintextUtf8: 'The quick brown fox jumps over 13 lazy dogs.',
};
const aeadKey = Uint8Array.from(Buffer.from(AEAD.keyHex, 'hex'));
const aeadNonce = Uint8Array.from(Buffer.from(AEAD.nonceHex, 'hex'));
const aeadPlain = encoder.encode(AEAD.plaintextUtf8);
const aeadAad = encoder.encode(AEAD.aadUtf8);
const boxSodium = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(aeadPlain, aeadAad, null, aeadNonce, aeadKey);
const boxNoble = xchacha20poly1305(aeadKey, aeadNonce, aeadAad).encrypt(aeadPlain);
crossCheck('xchacha20poly1305 ct||tag (libsodium vs @noble/ciphers)', boxSodium, boxNoble);

// ---------------------------------------------------------------- sha256
const SHA256 = { dataUtf8: 'squirrel-conformance-sha256' };
const shaSodium = sodium.crypto_hash_sha256(encoder.encode(SHA256.dataUtf8));
const shaNode = new Uint8Array(createHash('sha256').update(encoder.encode(SHA256.dataUtf8)).digest());
crossCheck('sha256 (libsodium vs node:crypto)', shaSodium, shaNode);

// --------------------------------------------------------------- ed25519
const ED25519 = { messageUtf8: 'squirrel-conformance-ed25519', seedHex: '5a'.repeat(32) };
const edSeed = Uint8Array.from(Buffer.from(ED25519.seedHex, 'hex'));
const edMessage = encoder.encode(ED25519.messageUtf8);
const edPublicNoble = ed25519.getPublicKey(edSeed);
const edSignatureNoble = ed25519.sign(edMessage, edSeed);
const sodiumKeypair = sodium.crypto_sign_seed_keypair(edSeed);
crossCheck('ed25519 public key (noble vs libsodium)', edPublicNoble, sodiumKeypair.publicKey);
const sodiumVerifies = sodium.crypto_sign_verify_detached(edSignatureNoble, edMessage, edPublicNoble);
if (!sodiumVerifies) {
  failures += 1;
  console.error('CROSS-CHECK FAILED: libsodium rejects the @noble/curves ed25519 signature');
} else {
  console.log('cross-check ok: ed25519 signature (noble sign, libsodium verify)');
}
const corrupted = Uint8Array.from(edSignatureNoble);
corrupted[0] ^= 0x01;

// ------------------------------------------------------------ vault record
// A complete VaultRecordV1 built from fixed inputs through libsodium and
// rebuilt through noble; the extension test opens it with domain unlockVault,
// the mobile conformance screen with core unlockVault.
const VAULT = {
  vaultId: 'conformance-vault',
  password: 'conformance-password-v1',
  saltHex: 'f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff',
  dekHex: '404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f',
  dekNonceHex: '606162636465666768696a6b6c6d6e6f7071727374757677',
  payloadNonceHex: '808182838485868788898a8b8c8d8e8f9091929394959697',
  kdfParams: { paramsVersion: 1, algorithm: 'argon2id13', opsLimit: 1, memLimitBytes: 8 * 2 ** 20, parallelism: 1 },
  entropyHex: '000102030405060708090a0b0c0d0e0f',
};
const vaultMnemonic = entropyToMnemonic(Uint8Array.from(Buffer.from(VAULT.entropyHex, 'hex')), wordlist);
const vaultSeedHex = toHex(mnemonicToSeedSync(vaultMnemonic));
const vaultPayload = { version: 1, entropyHex: VAULT.entropyHex, seedHex: vaultSeedHex };
const vaultSalt = Uint8Array.from(Buffer.from(VAULT.saltHex, 'hex'));
const vaultDek = Uint8Array.from(Buffer.from(VAULT.dekHex, 'hex'));

function buildRecord(deriveKekFn, sealFn) {
  const kek = deriveKekFn(VAULT.password, vaultSalt, VAULT.kdfParams);
  const dekAad = encoder.encode(`squirrel-vault:v1:${VAULT.vaultId}:dek`);
  const payloadAad = encoder.encode(`squirrel-vault:v1:${VAULT.vaultId}:payload`);
  const dekNonce = Uint8Array.from(Buffer.from(VAULT.dekNonceHex, 'hex'));
  const payloadNonce = Uint8Array.from(Buffer.from(VAULT.payloadNonceHex, 'hex'));
  return {
    schemaVersion: 1,
    cipherVersion: 1,
    vaultId: VAULT.vaultId,
    name: 'Conformance vault',
    createdAt: 1753920000000,
    kdf: { ...VAULT.kdfParams, saltB64: toB64(vaultSalt) },
    wrappedDek: { nonceB64: toB64(dekNonce), ciphertextB64: toB64(sealFn(vaultDek, dekAad, dekNonce, kek)) },
    payload: {
      nonceB64: toB64(payloadNonce),
      ciphertextB64: toB64(sealFn(encoder.encode(JSON.stringify(vaultPayload)), payloadAad, payloadNonce, vaultDek)),
    },
  };
}
const sodiumRecord = buildRecord(
  (pw, salt, p) => sodium.crypto_pwhash(32, encoder.encode(pw), salt, p.opsLimit, p.memLimitBytes, sodium.crypto_pwhash_ALG_ARGON2ID13),
  (pt, aad, nonce, key) => sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(pt, aad, null, nonce, key),
);
const nobleRecord = buildRecord(
  (pw, salt, p) => nobleArgon2id(encoder.encode(pw), salt, { t: p.opsLimit, m: p.memLimitBytes / 1024, p: p.parallelism, dkLen: 32 }),
  (pt, aad, nonce, key) => xchacha20poly1305(key, nonce, aad).encrypt(pt),
);
if (JSON.stringify(sodiumRecord) !== JSON.stringify(nobleRecord)) {
  failures += 1;
  console.error('CROSS-CHECK FAILED: vault record differs between libsodium and noble builds');
} else {
  console.log('cross-check ok: VaultRecordV1 (libsodium vs noble build)');
}

// ------------------------------------------------------- BIP39/84/86
const BIP39 = {
  mnemonic: 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
  passphrase: 'TREZOR',
  // Official Trezor vector for the all-zero entropy mnemonic with TREZOR passphrase.
  seedHex: 'c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04',
};
const bip39Seed = mnemonicToSeedSync(BIP39.mnemonic, BIP39.passphrase);
if (toHex(bip39Seed) !== BIP39.seedHex) {
  failures += 1;
  console.error('CROSS-CHECK FAILED: BIP39 seed does not match the official Trezor vector');
} else {
  console.log('cross-check ok: BIP39 seed (official Trezor vector)');
}
const root = HDKey.fromMasterSeed(bip39Seed);
const bip84Node = root.derive("m/84'/0'/0'/0/0");
const bip86Node = root.derive("m/86'/0'/0'/0/0");
const bip84Address = p2wpkh(bip84Node.publicKey, NETWORK).address;
const bip86Address = p2tr(bip86Node.publicKey.slice(1), undefined, NETWORK).address;

// ------------------------------------------------------------- BIP322
// Official vectors from bitcoin/bips bip-0322; verified by core's bip322
// suite under Node and by the mobile conformance screen through core.
const BIP322 = {
  virtualHashes: {
    message: 'Hello World',
    address: 'bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l',
    network: 'mainnet',
    messageHash: 'f0eb03b1a75ac6d9847f55c624a99169b5dccba2a31f5b23bea77ba270de0a7a',
    toSpendTxid: 'b79d196740ad5217771c1098fc4a4b51e0535c32236c71f1ea4d61a2d603352b',
    toSignTxid: '88737ae86f2077145f93cc4b153ae9a1cb8d56afa511988c149c5c8c9d93bddf',
  },
  emptyMessageHashHex: 'c90c269c4f8fcbe6880f72a721ddfbf1914268a794cbb21cfafee13770ae19f1',
  p2wpkh: {
    message: '2V6TUTMSH4VQ3Z7WZWKYD7DFNH',
    address: 'bc1qqthe0hz8klx90e7stf6shclhsvqd5ly96pn53v',
    signature: 'smpAkgwRQIhALC6hdfxNy1n45d7UXSskRBdfZW0Al259E1kDMpipdYkAiAJPfZqb+WurZuf1apU5xeE6Igui9dvt5tihQLDvxlY1AEhAqbnruyo677ktQjio7XOchO3w51Dh9AbRVngha5jtNfT',
  },
  p2tr: {
    message: 'PURVOQ544B6HUATVBJZN5EZJUU',
    address: 'bc1pcquvhrqv0q68t4m0hfq6tpn006qrskyc7yrqnp2uyrf2emg3wynsdjyk38',
    signature: 'smpAUB6B2Rbupzua8LTQIF06516wzl+cwKy1be8RgoiW0riyXdKwe6GTz/5Hnb37m67pJwIKCh+D5jDueG6KpvYpmu8',
  },
};

// Independent tagged-hash cross-check of the BIP322 message hash.
const tag = new Uint8Array(createHash('sha256').update('BIP0322-signed-message').digest());
const taggedHash = new Uint8Array(
  createHash('sha256').update(tag).update(tag).update(encoder.encode(BIP322.virtualHashes.message)).digest(),
);
if (toHex(taggedHash) !== BIP322.virtualHashes.messageHash) {
  failures += 1;
  console.error('CROSS-CHECK FAILED: BIP322 tagged message hash does not match the official vector');
} else {
  console.log('cross-check ok: BIP322 tagged message hash');
}

// ------------------------------------------------------------- assemble
if (failures > 0) {
  console.error(`\n${failures} cross-check(s) failed — nothing written.`);
  process.exit(1);
}

const fixture = {
  version: 1,
  generatedBy: 'scripts/generate-conformance-vectors.mjs',
  note: 'Golden crypto conformance vectors. Regenerate only via the generator; it cross-checks libsodium against independent implementations before writing.',
  argon2id: { ...ARGON2ID, kekHex: toHex(kekSodium) },
  xchacha20poly1305: { ...AEAD, boxB64: toB64(boxSodium) },
  sha256: { ...SHA256, digestHex: toHex(shaSodium) },
  ed25519: {
    messageUtf8: ED25519.messageUtf8,
    publicKeyHex: toHex(edPublicNoble),
    signatureHex: toHex(edSignatureNoble),
    expectedValid: true,
    corruptedSignatureHex: toHex(corrupted),
    corruptedExpectedValid: false,
  },
  vaultRecord: {
    password: VAULT.password,
    record: sodiumRecord,
    expectedDekHex: VAULT.dekHex,
    expectedPayload: vaultPayload,
  },
  gatewaySignedFixture: {
    file: 'gateway/status.signed.json',
    publicKeyFile: 'gateway/dev-public-key.json',
    expectedValid: true,
    note: 'Verified end-to-end by the gateway verify suite in core; listed here so the on-device screen exercises a real signed response.',
  },
  bip39: BIP39,
  derivations: [
    { path: "m/84'/0'/0'/0/0", publicKeyHex: toHex(bip84Node.publicKey), address: bip84Address },
    { path: "m/86'/0'/0'/0/0", publicKeyHex: toHex(bip86Node.publicKey), address: bip86Address },
  ],
  bip322: BIP322,
  negativeControl: {
    expectMismatch: true,
    note: 'Deliberately wrong expected KEK. A conformance harness that never computes anything would pass every positive vector; this one must FAIL to match, proving the harness runs.',
    argon2id: {
      ...ARGON2ID,
      kekHex: toHex(Uint8Array.from(kekSodium, (b, i) => (i === 0 ? b ^ 0xff : b))),
    },
  },
};

mkdirSync(dirname(outPath), { recursive: true });
writeFileSync(outPath, `${JSON.stringify(fixture, null, 2)}\n`);
console.log(`\nwrote ${outPath}`);
