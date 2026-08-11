/**
 * Fixed-field-order canonicalization for gateway response signing
 * (spec §18.1; gateway/docs/design/response-signing.md).
 *
 * Independent client-side implementation of the byte layout the gateway
 * signs. Both repos pin the same recorded byte vector in tests, so any drift
 * between the two implementations is a contract-test failure, not a silent
 * verification mismatch. Pure byte-shuffling — no crypto in this module.
 */
import type { EnvelopeFields } from './contract';

export const DOMAIN_TAG = 'squirrel-gateway-v1:';

const encoder = new TextEncoder();

function u32be(n: number): Uint8Array {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, n, false);
  return out;
}

function str(s: string): Uint8Array[] {
  const bytes = encoder.encode(s);
  return [u32be(bytes.byteLength), bytes];
}

function dec(n: number): string {
  if (!Number.isSafeInteger(n) || n < 0) {
    throw new Error(`canonical dec() requires a nonnegative safe integer, got ${n}`);
  }
  return String(n);
}

function concat(parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, p) => sum + p.byteLength, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.byteLength;
  }
  return out;
}

/**
 * Serialize the §18.1 envelope fields (signature omitted) in the normative
 * fixed order. All values come from the parsed body byte-for-byte; the
 * capabilities array keeps its transmitted order (order is signed, never
 * sorted).
 */
export function canonicalEnvelopeBytes(env: EnvelopeFields): Uint8Array {
  const parts: Uint8Array[] = [
    ...str(env.instanceId),
    ...str(env.network),
    ...str(dec(env.protocolVersion)),
    ...str(env.requestNonce),
    ...str(env.timestamp),
    ...str(dec(env.coreTip.height)),
    ...str(env.coreTip.hash),
    ...str(dec(env.indexTip.height)),
    ...str(env.indexTip.hash),
    ...str(env.classificationRevision),
    u32be(env.capabilities.length),
  ];
  for (const capability of env.capabilities) parts.push(...str(capability));
  return concat(parts);
}

/** `domainTag || env || sha256(blanked body)` — the exact bytes Ed25519 signs. */
export function signingInput(env: EnvelopeFields, bodySha256: Uint8Array): Uint8Array {
  return concat([encoder.encode(DOMAIN_TAG), canonicalEnvelopeBytes(env), bodySha256]);
}

/**
 * Blank the transmitted signature value inside the exact received body bytes:
 * `"signature":"<sigHex>"` → `"signature":""`. The pattern must occur exactly
 * once; zero or multiple occurrences mark a malformed or adversarial body and
 * return null (verification then fails closed).
 */
export function blankSignatureInBody(
  bodyBytes: Uint8Array,
  signatureHex: string,
): Uint8Array | null {
  const needle = encoder.encode(`"signature":"${signatureHex}"`);
  const replacement = encoder.encode('"signature":""');
  const indices: number[] = [];
  outer: for (let i = 0; i + needle.length <= bodyBytes.length; i += 1) {
    for (let j = 0; j < needle.length; j += 1) {
      if (bodyBytes[i + j] !== needle[j]) continue outer;
    }
    indices.push(i);
  }
  const at = indices.length === 1 ? indices[0] : undefined;
  if (at === undefined) return null;
  return concat([bodyBytes.subarray(0, at), replacement, bodyBytes.subarray(at + needle.length)]);
}
