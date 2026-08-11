/**
 * Golden crypto conformance vectors (mobile port plan, Phase 0).
 *
 * Every assertion goes through the CryptoProvider port or domain code, never
 * libsodium directly, so this exact suite validates any provider — the
 * extension's libsodium today, mobile's quick-crypto + noble later. The
 * negative control MUST mismatch: a harness that stops computing would pass
 * every positive vector forever; the sentinel proves the harness runs.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { beforeAll, describe, expect, it } from 'vitest';
import { HDKey } from '@scure/bip32';
import { installTestCryptoProvider } from '../helpers/install-crypto-provider';
import { getCryptoProvider } from '../../src/domain/vault/crypto-provider';
import { deriveKek } from '../../src/domain/vault/crypto';
import { base64ToBytes, bytesToHex, hexToBytes, utf8ToBytes } from '../../src/domain/vault/encoding';
import { mnemonicToSeed } from '../../src/domain/keys/mnemonic';
import { stableExternalAddress } from '../../src/domain/keys/derivation';
import { bip322VirtualHashes, bip322MessageHash, verifyBip322Simple } from '../../src/domain/transactions/bip322';
import { MAX_CLOCK_SKEW_MS, verifyStatus } from '../../src/domain/gateway/verify';
import type { Argon2idParams, VaultRecordV1 } from '../../src/domain/vault/record';
import { unlockVault } from '../../src/domain/vault/vault';

const fixturesDir = join(import.meta.dirname, '..', 'fixtures');
const vectors = JSON.parse(
  readFileSync(join(import.meta.dirname, '..', '..', 'vectors', 'crypto-conformance.json'), 'utf8'),
) as {
  argon2id: { passwordUtf8: string; saltHex: string; params: Argon2idParams; kekHex: string };
  xchacha20poly1305: { keyHex: string; nonceHex: string; aadUtf8: string; plaintextUtf8: string; boxB64: string };
  sha256: { dataUtf8: string; digestHex: string };
  ed25519: {
    messageUtf8: string;
    publicKeyHex: string;
    signatureHex: string;
    expectedValid: boolean;
    corruptedSignatureHex: string;
    corruptedExpectedValid: boolean;
  };
  vaultRecord: {
    password: string;
    record: VaultRecordV1;
    expectedDekHex: string;
    expectedPayload: { version: 1; entropyHex: string; seedHex: string };
  };
  gatewaySignedFixture: { file: string; publicKeyFile: string; expectedValid: boolean };
  bip39: { mnemonic: string; passphrase: string; seedHex: string };
  derivations: readonly { path: string; publicKeyHex: string; address: string }[];
  bip322: {
    virtualHashes: {
      message: string;
      address: string;
      network: 'mainnet';
      messageHash: string;
      toSpendTxid: string;
      toSignTxid: string;
    };
    emptyMessageHashHex: string;
    p2wpkh: { message: string; address: string; signature: string };
    p2tr: { message: string; address: string; signature: string };
  };
  negativeControl: {
    expectMismatch: true;
    argon2id: { passwordUtf8: string; saltHex: string; params: Argon2idParams; kekHex: string };
  };
};

beforeAll(() => installTestCryptoProvider());

describe('crypto conformance vectors', () => {
  it('argon2id derives the pinned KEK', async () => {
    const kek = await deriveKek(
      vectors.argon2id.passwordUtf8,
      hexToBytes(vectors.argon2id.saltHex),
      vectors.argon2id.params,
    );
    expect(bytesToHex(kek)).toBe(vectors.argon2id.kekHex);
  });

  it('xchacha20poly1305 seals to the pinned ct||tag layout and opens back', () => {
    const provider = getCryptoProvider();
    const key = hexToBytes(vectors.xchacha20poly1305.keyHex);
    const nonce = hexToBytes(vectors.xchacha20poly1305.nonceHex);
    const aad = utf8ToBytes(vectors.xchacha20poly1305.aadUtf8);
    const plaintext = utf8ToBytes(vectors.xchacha20poly1305.plaintextUtf8);
    const box = provider.xchaEncrypt(plaintext, aad, nonce, key);
    expect(Buffer.from(box).toString('base64')).toBe(vectors.xchacha20poly1305.boxB64);
    expect(box).toHaveLength(plaintext.length + 16); // ciphertext‖tag(16), one buffer

    const opened = provider.xchaDecrypt(base64ToBytes(vectors.xchacha20poly1305.boxB64), aad, nonce, key);
    expect(new TextDecoder().decode(opened)).toBe(vectors.xchacha20poly1305.plaintextUtf8);
  });

  it('sha256 matches the pinned digest', () => {
    const digest = getCryptoProvider().sha256(utf8ToBytes(vectors.sha256.dataUtf8));
    expect(bytesToHex(digest)).toBe(vectors.sha256.digestHex);
  });

  it('ed25519 accepts the pinned signature and rejects the corrupted one', () => {
    const provider = getCryptoProvider();
    const message = utf8ToBytes(vectors.ed25519.messageUtf8);
    const publicKey = hexToBytes(vectors.ed25519.publicKeyHex);
    expect(provider.ed25519Verify(hexToBytes(vectors.ed25519.signatureHex), message, publicKey)).toBe(
      vectors.ed25519.expectedValid,
    );
    expect(
      provider.ed25519Verify(hexToBytes(vectors.ed25519.corruptedSignatureHex), message, publicKey),
    ).toBe(vectors.ed25519.corruptedExpectedValid);
  });

  it('opens the pinned VaultRecordV1 to the expected DEK and payload', async () => {
    const unlocked = await unlockVault(vectors.vaultRecord.record, vectors.vaultRecord.password);
    try {
      expect(bytesToHex(unlocked.dek)).toBe(vectors.vaultRecord.expectedDekHex);
      expect(unlocked.payload).toEqual(vectors.vaultRecord.expectedPayload);
    } finally {
      unlocked.dek.fill(0);
    }
  });

  it('verifies the real signed gateway fixture end to end', () => {
    const bodyBytes = new Uint8Array(
      readFileSync(join(fixturesDir, vectors.gatewaySignedFixture.file)),
    );
    const { publicKeyHex } = JSON.parse(
      readFileSync(join(fixturesDir, vectors.gatewaySignedFixture.publicKeyFile), 'utf8'),
    ) as { publicKeyHex: string };
    const body = JSON.parse(new TextDecoder().decode(bodyBytes)) as {
      timestamp: string;
      requestNonce: string;
    };
    const result = verifyStatus({
      bodyBytes,
      expectedNonce: body.requestNonce,
      expectedNetwork: 'signet',
      publicKeyHex,
      nowMs: Date.parse(body.timestamp),
      maxSkewMs: MAX_CLOCK_SKEW_MS,
      allowedProtocolVersions: [1, 2],
    });
    expect(result.ok).toBe(vectors.gatewaySignedFixture.expectedValid);
  });

  it('BIP39 seed matches the official vector through the domain path', () => {
    const seed = mnemonicToSeed(vectors.bip39.mnemonic, vectors.bip39.passphrase);
    try {
      expect(bytesToHex(seed)).toBe(vectors.bip39.seedHex);
    } finally {
      seed.fill(0);
    }
  });

  it('BIP84 and BIP86 derivations match the pinned pubkeys and addresses through the domain path', () => {
    const seed = mnemonicToSeed(vectors.bip39.mnemonic, vectors.bip39.passphrase);
    const root = HDKey.fromMasterSeed(seed);
    try {
      for (const derivation of vectors.derivations) {
        // Raw HDKey check first: isolates a BIP32 failure from an address-encoding one.
        const node = root.derive(derivation.path);
        expect(node.publicKey && bytesToHex(node.publicKey)).toBe(derivation.publicKeyHex);
        // Then the shipping derivation path, so a bech32/bech32m or taproot
        // tweak regression cannot slip past the conformance suite.
        const kind = derivation.path.startsWith("m/84'") ? 'payment' : 'ordinals';
        const info = stableExternalAddress(seed, kind, 'mainnet', 0);
        expect(info.path).toBe(derivation.path);
        expect(info.publicKeyHex).toBe(derivation.publicKeyHex);
        expect(info.address).toBe(derivation.address);
      }
    } finally {
      seed.fill(0);
      root.wipePrivateData();
    }
  });

  it('BIP322 hashes and official signatures verify through the domain path', () => {
    const { virtualHashes } = vectors.bip322;
    expect(bip322VirtualHashes(virtualHashes.message, virtualHashes.address, virtualHashes.network)).toEqual({
      messageHash: virtualHashes.messageHash,
      toSpendTxid: virtualHashes.toSpendTxid,
      toSignTxid: virtualHashes.toSignTxid,
    });
    expect(bytesToHex(bip322MessageHash(new Uint8Array(0)))).toBe(vectors.bip322.emptyMessageHashHex);
    for (const vector of [vectors.bip322.p2wpkh, vectors.bip322.p2tr]) {
      expect(verifyBip322Simple(vector.message, vector.address, 'mainnet', vector.signature)).toBe(true);
    }
    expect(
      verifyBip322Simple('tampered message', vectors.bip322.p2wpkh.address, 'mainnet', vectors.bip322.p2wpkh.signature),
    ).toBe(false);
  });

  it('NEGATIVE CONTROL: the sentinel vector must mismatch, proving the harness computes', async () => {
    expect(vectors.negativeControl.expectMismatch).toBe(true);
    const kek = await deriveKek(
      vectors.negativeControl.argon2id.passwordUtf8,
      hexToBytes(vectors.negativeControl.argon2id.saltHex),
      vectors.negativeControl.argon2id.params,
    );
    expect(bytesToHex(kek)).not.toBe(vectors.negativeControl.argon2id.kekHex);
  });
});
