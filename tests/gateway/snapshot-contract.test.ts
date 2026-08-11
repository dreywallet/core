/**
 * Contract tests for the M6 snapshot/classify wire types against the signed
 * fixtures committed from the gateway repo (spec §4), plus the cross-repo
 * script-hash-encoding drift test: the extension's own derivation must
 * reproduce the script hashes the gateway's fixture generator keyed its
 * scenario maps with (sha256(scriptPubKey), natural byte order — see gateway
 * docs/design/wallet-snapshot.md).
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { beforeAll, describe, expect, it } from 'vitest';
import { mnemonicToSeedSync } from '@scure/bip39';
import { installTestCryptoProvider } from '../helpers/install-crypto-provider';
import {
  outpointsClassifyResponseSchema,
  outpointSchema,
  snapshotUtxoSchema,
  utxoClassificationSchema,
  walletSnapshotResponseSchema,
} from '../../src/domain/gateway/contract';
import { MAX_CLOCK_SKEW_MS, verifySignedResponse } from '../../src/domain/gateway/verify';
import { deriveAccountNode, deriveAddress } from '../../src/domain/keys/derivation';
import { scriptHashForPublicKey } from '../../src/domain/keys/script-hash';

const fixturesDir = join(import.meta.dirname, '..', 'fixtures', 'gateway');
const readFixture = (name: string) => new Uint8Array(readFileSync(join(fixturesDir, name)));
const devPublicKeyHex = (
  JSON.parse(readFileSync(join(fixturesDir, 'dev-public-key.json'), 'utf8')) as {
    publicKeyHex: string;
  }
).publicKeyHex;

// Matches the gateway's fixture signer (scripts/sign-fixtures.ts).
const FIXED_NONCE = '00112233445566778899aabbccddeeff';

const scenariosFile = JSON.parse(
  readFileSync(join(fixturesDir, 'snapshot-scenarios.json'), 'utf8'),
) as {
  network: 'signet';
  derived: Record<string, { address: string; scriptHash: string }>;
  scenarios: Record<string, { envelopeOverrides?: { classificationRevision?: string } }>;
};

// The well-known dev mnemonic (gateway fixtures/dev-wallet.json). Committed
// test data, signet only.
const DEV_MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

function verifyInput(name: string) {
  const bodyBytes = readFixture(name);
  const body = JSON.parse(new TextDecoder().decode(bodyBytes)) as {
    timestamp: string;
  };
  return {
    bodyBytes,
    expectedNonce: FIXED_NONCE,
    expectedNetwork: 'signet' as const,
    publicKeyHex: devPublicKeyHex,
    nowMs: Date.parse(body.timestamp),
    maxSkewMs: MAX_CLOCK_SKEW_MS,
  };
}

beforeAll(async () => {
  await installTestCryptoProvider();
});

describe('snapshot/classify signed fixtures', () => {
  it('verifies and parses the snapshot fixtures with the mirror schema', () => {
    for (const name of [
      'snapshot.clean.signed.json',
      'snapshot.wrong-lane.signed.json',
      'snapshot.stale-revision.signed.json',
    ]) {
      const result = verifySignedResponse(walletSnapshotResponseSchema, verifyInput(name));
      expect(result.ok, name).toBe(true);
      if (result.ok) {
        expect(result.value.utxos.length).toBeGreaterThan(0);
        expect(result.value.requestedScriptHashes.length).toBe(40);
      }
    }
  });

  it('verifies and parses the classify fixtures with the mirror schema', () => {
    for (const name of ['classify.mixed.signed.json', 'classify.revision-skew.signed.json']) {
      const result = verifySignedResponse(outpointsClassifyResponseSchema, verifyInput(name));
      expect(result.ok, name).toBe(true);
      if (result.ok) {
        expect(result.value.classifications.length).toBeGreaterThan(0);
        expect(result.value.unknownOutpoints).toEqual([{ txid: 'f'.repeat(64), vout: 0 }]);
      }
    }
  });

  it('rejects the tampered snapshot fixture fail-closed', () => {
    const result = verifySignedResponse(
      walletSnapshotResponseSchema,
      verifyInput('snapshot.tampered-signature.json'),
    );
    expect(result).toEqual({ ok: false, reason: 'signature' });
  });

  it('carries the stale revision the client must reject against activeRevision', () => {
    const result = verifySignedResponse(
      walletSnapshotResponseSchema,
      verifyInput('snapshot.stale-revision.signed.json'),
    );
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.value.classificationRevision).toBe('rev-0000');
  });

  it('classify revision-skew fixture disagrees with the snapshot revision', () => {
    const snapshot = verifySignedResponse(
      walletSnapshotResponseSchema,
      verifyInput('snapshot.clean.signed.json'),
    );
    const classify = verifySignedResponse(
      outpointsClassifyResponseSchema,
      verifyInput('classify.revision-skew.signed.json'),
    );
    expect(snapshot.ok && classify.ok).toBe(true);
    if (snapshot.ok && classify.ok) {
      expect(classify.value.classificationRevision).not.toBe(
        snapshot.value.classificationRevision,
      );
    }
  });

  it('rejects contradictory clean classifications', () => {
    const clean = {
      txid: 'a'.repeat(64),
      vout: 0,
      valueSats: '10000',
      scriptPubKey: `0014${'b'.repeat(40)}`,
      confirmations: 1,
      primaryClass: 'cardinal_clean',
      inscriptions: [],
      satRanges: null,
      unsupportedAssetDetected: false,
      confidence: 'authoritative',
      classifiedTip: { height: 1, hash: 'c'.repeat(64) },
      classificationRevision: 'rev-0001',
    } as const;
    expect(utxoClassificationSchema.safeParse(clean).success).toBe(true);
    expect(
      utxoClassificationSchema.safeParse({ ...clean, confidence: 'degraded' }).success,
    ).toBe(false);
    expect(
      utxoClassificationSchema.safeParse({
        ...clean,
        inscriptions: [{ inscriptionId: 'i0', satpoint: `${'a'.repeat(64)}:0:0` }],
      }).success,
    ).toBe(false);
    expect(
      utxoClassificationSchema.safeParse({
        ...clean,
        satRanges: [{ start: '0', end: '1', rarity: 'uncommon' }],
      }).success,
    ).toBe(false);
    expect(
      utxoClassificationSchema.safeParse({ ...clean, unsupportedAssetDetected: true }).success,
    ).toBe(false);
  });

  it('bounds every wire outpoint index to uint32', () => {
    const txid = 'a'.repeat(64);
    expect(outpointSchema.safeParse({ txid, vout: 0xffffffff }).success).toBe(true);
    expect(outpointSchema.safeParse({ txid, vout: 0x100000000 }).success).toBe(false);
    expect(
      snapshotUtxoSchema.safeParse({
        txid,
        vout: 0x100000000,
        valueSats: '1',
        scriptHash: 'b'.repeat(64),
        scriptPubKey: '00',
        height: null,
        fundingSpendsOnlyRequested: false,
      }).success,
    ).toBe(false);
    expect(
      utxoClassificationSchema.safeParse({
        txid,
        vout: 0x100000000,
        valueSats: '1',
        scriptPubKey: '00',
        confirmations: 0,
        primaryClass: 'unknown',
        inscriptions: [],
        satRanges: null,
        unsupportedAssetDetected: false,
        confidence: 'degraded',
        classifiedTip: { height: 1, hash: 'c'.repeat(64) },
        classificationRevision: 'rev-0001',
      }).success,
    ).toBe(false);
  });
});

describe('cross-repo script-hash encoding', () => {
  it('locally derived script hashes match the gateway scenario keys byte-for-byte', () => {
    const seed = mnemonicToSeedSync(DEV_MNEMONIC);
    const mismatches: string[] = [];
    for (const [key, expected] of Object.entries(scenariosFile.derived)) {
      const match = /^a(\d+):(payment|ordinals):([01]):(\d+)$/.exec(key);
      if (!match) throw new Error(`unparseable derived key ${key}`);
      const account = Number(match[1]);
      const lane = match[2] as 'payment' | 'ordinals';
      const chain = Number(match[3]) as 0 | 1;
      const index = Number(match[4]);
      const node = deriveAccountNode(seed, lane, 'signet', account);
      const info = deriveAddress(node, lane, 'signet', chain, index);
      if (info.address !== expected.address) mismatches.push(`${key}: address`);
      if (scriptHashForPublicKey(info.publicKeyHex, lane, 'signet') !== expected.scriptHash) {
        mismatches.push(`${key}: scriptHash`);
      }
    }
    expect(Object.keys(scenariosFile.derived).length).toBeGreaterThan(200);
    expect(mismatches).toEqual([]);
  });
});
