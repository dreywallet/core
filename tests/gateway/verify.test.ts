import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { beforeAll, describe, expect, it } from 'vitest';
import { installTestCryptoProvider } from '../helpers/install-crypto-provider';
import {
  MAX_CLOCK_SKEW_MS,
  verifyStatus,
  type VerifyStatusInput,
} from '../../src/domain/gateway/verify';
import { makeTestKeypair, signTestBody, type TestKeypair } from './sign-helper';

const fixturesDir = join(import.meta.dirname, '..', 'fixtures', 'gateway');
const readFixture = (name: string) => new Uint8Array(readFileSync(join(fixturesDir, name)));
const devPublicKeyHex = (
  JSON.parse(readFileSync(join(fixturesDir, 'dev-public-key.json'), 'utf8')) as {
    publicKeyHex: string;
  }
).publicKeyHex;

const signedFixture = () => readFixture('status.signed.json');
const fixtureStatus = JSON.parse(new TextDecoder().decode(signedFixture())) as Record<
  string,
  unknown
> & { timestamp: string; requestNonce: string };

const baseInput = (): VerifyStatusInput => ({
  bodyBytes: signedFixture(),
  expectedNonce: fixtureStatus.requestNonce,
  expectedNetwork: 'signet',
  publicKeyHex: devPublicKeyHex,
  nowMs: Date.parse(fixtureStatus.timestamp),
  maxSkewMs: MAX_CLOCK_SKEW_MS,
  allowedProtocolVersions: [1, 2],
});

let keypair: TestKeypair;

beforeAll(async () => {
  await installTestCryptoProvider();
  keypair = makeTestKeypair();
});

describe('verifyStatus against committed contract fixtures', () => {
  it('accepts the signed fixture', () => {
    const result = verifyStatus(baseInput());
    expect(result).toMatchObject({ ok: true });
    if (result.ok) {
      expect(result.status.network).toBe('signet');
      expect(result.status.coreTip.height).toBe(250000);
    }
  });

  it('rejects the tampered-signature fixture (§6.2)', () => {
    expect(
      verifyStatus({ ...baseInput(), bodyBytes: readFixture('status.tampered-signature.json') }),
    ).toEqual({ ok: false, reason: 'signature' });
  });

  it('rejects the wrong-network fixture on network policy, not signature (§3.2)', () => {
    expect(
      verifyStatus({ ...baseInput(), bodyBytes: readFixture('status.wrong-network.json') }),
    ).toEqual({ ok: false, reason: 'wrong_network' });
  });

  it('rejects a body byte tampered after signing', () => {
    const text = new TextDecoder()
      .decode(signedFixture())
      .replace('"height":250000', '"height":250001');
    expect(verifyStatus({ ...baseInput(), bodyBytes: new TextEncoder().encode(text) })).toEqual({
      ok: false,
      reason: 'signature',
    });
  });

  it('rejects a nonce that does not match the outstanding request', () => {
    expect(verifyStatus({ ...baseInput(), expectedNonce: 'someone-elses-nonce' })).toEqual({
      ok: false,
      reason: 'nonce_mismatch',
    });
  });

  it('rejects the wrong pinned key', () => {
    expect(verifyStatus({ ...baseInput(), publicKeyHex: '00'.repeat(32) })).toEqual({
      ok: false,
      reason: 'signature',
    });
  });

  it('fails closed with an unprovisioned pinned key', () => {
    expect(verifyStatus({ ...baseInput(), publicKeyHex: '' })).toEqual({
      ok: false,
      reason: 'key_unprovisioned',
    });
    expect(verifyStatus({ ...baseInput(), publicKeyHex: 'NOT-HEX' })).toEqual({
      ok: false,
      reason: 'key_unprovisioned',
    });
  });

  it('rejects malformed JSON and schema-violating bodies as schema failures', () => {
    expect(
      verifyStatus({ ...baseInput(), bodyBytes: new TextEncoder().encode('not json') }),
    ).toEqual({ ok: false, reason: 'schema' });
    expect(verifyStatus({ ...baseInput(), bodyBytes: new TextEncoder().encode('{}') })).toEqual({
      ok: false,
      reason: 'schema',
    });
  });
});

describe('verifyStatus policy checks on freshly signed bodies', () => {
  const signedWith = (mutations: Record<string, unknown>) =>
    signTestBody({ ...fixtureStatus, ...mutations }, keypair);
  const inputWith = (mutations: Record<string, unknown>): VerifyStatusInput => ({
    ...baseInput(),
    bodyBytes: signedWith(mutations),
    publicKeyHex: keypair.publicKeyHex,
  });

  it('accepts an untouched re-signed body under the test key', () => {
    expect(verifyStatus(inputWith({})).ok).toBe(true);
  });

  it('selects and verifies the strict v2 schema before applying the channel policy', () => {
    const body = signedWith({ protocolVersion: 2, protocolMin: 2, protocolMax: 2, readiness: {
      walletDataReady: true, spendingReady: false, reasons: ['spending_endpoints_unavailable'],
      dependencies: { core: 'ready', ord: 'ready', electrs: 'ready', classification: 'ready', capacity: 'ready', signing: 'ready' },
      core: { initialBlockDownload: false, headersSynced: true, txindexSynced: true, peersReady: true, mempoolLoaded: true },
      coherentCoreSampling: true, commonTip: true, mempoolFresh: true, reorgState: 'clear',
      classificationState: 'active', capacityState: 'ready', signingKeyAvailable: true,
    } });
    const input = { ...baseInput(), bodyBytes: body, publicKeyHex: keypair.publicKeyHex };
    expect(verifyStatus({ ...input, allowedProtocolVersions: [2] })).toMatchObject({ ok: true });
    expect(verifyStatus({ ...input, allowedProtocolVersions: [1] })).toEqual({ ok: false, reason: 'protocol' });
  });

  it('rejects a v2 protocol range that is not exactly v2', () => {
    expect(verifyStatus(inputWith({ protocolMin: 3, protocolMax: 3 }))).toEqual(
      { ok: false, reason: 'schema' },
    );
  });

  it('rejects a declared protocolVersion forbidden by the build channel', () => {
    expect(verifyStatus({ ...inputWith({}), allowedProtocolVersions: [1] })).toEqual({
      ok: false,
      reason: 'protocol',
    });
  });

  it('accepts skew at exactly the inclusive bound and rejects one ms past it', () => {
    const ts = Date.parse(fixtureStatus.timestamp);
    expect(verifyStatus({ ...inputWith({}), nowMs: ts + MAX_CLOCK_SKEW_MS }).ok).toBe(true);
    expect(verifyStatus({ ...inputWith({}), nowMs: ts + MAX_CLOCK_SKEW_MS + 1 })).toEqual({
      ok: false,
      reason: 'skew',
    });
  });

  it('rejects future timestamps beyond the bound (skew is two-sided)', () => {
    const ts = Date.parse(fixtureStatus.timestamp);
    expect(verifyStatus({ ...inputWith({}), nowMs: ts - MAX_CLOCK_SKEW_MS - 1 })).toEqual({
      ok: false,
      reason: 'skew',
    });
  });

  it('rejects unknown extra fields (strict contract)', () => {
    expect(verifyStatus(inputWith({ surprise: true }))).toEqual({ ok: false, reason: 'schema' });
  });
});
