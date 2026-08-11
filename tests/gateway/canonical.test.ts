import { describe, expect, it } from 'vitest';
import {
  blankSignatureInBody,
  canonicalEnvelopeBytes,
  signingInput,
  DOMAIN_TAG,
} from '../../src/domain/gateway/canonical';
import type { EnvelopeFields } from '../../src/domain/gateway/contract';

const toHex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');

const vectorEnvelope: EnvelopeFields = {
  instanceId: 'i',
  network: 'signet',
  protocolVersion: 1,
  requestNonce: 'n',
  timestamp: '2026-07-20T00:00:00.000Z',
  coreTip: { height: 0, hash: 'a'.repeat(64) },
  indexTip: { height: 250000, hash: 'b'.repeat(64) },
  classificationRevision: 'r',
  capabilities: ['broadcast', 'address_history'],
};

// Recorded byte vector shared with gateway/tests/signing.test.ts — the two
// repos implement this format independently; a mismatch is a protocol break.
const vectorHex =
  '0000000169000000067369676e65740000000131000000016e00000018323032362d30372d32305430303a30303a30302e3030305a000000013000000040616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161610000000632353030303000000040626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262620000000172000000020000000962726f6164636173740000000f616464726573735f686973746f7279';

describe('canonicalEnvelopeBytes', () => {
  it('matches the recorded cross-repo byte vector', () => {
    expect(toHex(canonicalEnvelopeBytes(vectorEnvelope))).toBe(vectorHex);
  });

  it('is sensitive to capability order (order is signed, never sorted)', () => {
    const reordered: EnvelopeFields = {
      ...vectorEnvelope,
      capabilities: ['address_history', 'broadcast'],
    };
    expect(toHex(canonicalEnvelopeBytes(reordered))).not.toBe(vectorHex);
  });

  it('serializes zero heights as "0" and large heights in full decimal', () => {
    const env: EnvelopeFields = {
      ...vectorEnvelope,
      coreTip: { height: 0, hash: 'a'.repeat(64) },
      indexTip: { height: 2_100_000, hash: 'b'.repeat(64) },
    };
    const hex = toHex(canonicalEnvelopeBytes(env));
    expect(hex).toContain(`00000001${Buffer.from('0').toString('hex')}`);
    expect(hex).toContain(`00000007${Buffer.from('2100000').toString('hex')}`);
  });

  it('rejects non-integer heights instead of serializing them loosely', () => {
    const env = {
      ...vectorEnvelope,
      coreTip: { height: 1.5, hash: 'a'.repeat(64) },
    } as unknown as EnvelopeFields;
    expect(() => canonicalEnvelopeBytes(env)).toThrow(/safe integer/);
  });
});

describe('signingInput', () => {
  it('prefixes the raw domain tag and appends the body hash', () => {
    const bodyHash = new Uint8Array(32).fill(7);
    const input = signingInput(vectorEnvelope, bodyHash);
    const tag = new TextEncoder().encode(DOMAIN_TAG);
    expect(toHex(input.subarray(0, tag.length))).toBe(toHex(tag));
    expect(toHex(input.subarray(input.length - 32))).toBe(toHex(bodyHash));
    expect(toHex(input.subarray(tag.length, input.length - 32))).toBe(vectorHex);
  });
});

describe('blankSignatureInBody', () => {
  const sig = 'ab'.repeat(64);
  const encode = (s: string) => new TextEncoder().encode(s);
  const decode = (b: Uint8Array | null) => (b === null ? null : new TextDecoder().decode(b));

  it('blanks exactly one occurrence', () => {
    expect(decode(blankSignatureInBody(encode(`{"x":1,"signature":"${sig}"}`), sig))).toBe(
      '{"x":1,"signature":""}',
    );
  });

  it('rejects a body without the transmitted signature pattern', () => {
    expect(blankSignatureInBody(encode('{"x":1}'), sig)).toBeNull();
  });

  it('rejects duplicate occurrences (adversarial nesting)', () => {
    const one = `"signature":"${sig}"`;
    expect(blankSignatureInBody(encode(`{${one},"y":{${one}}}`), sig)).toBeNull();
  });
});
