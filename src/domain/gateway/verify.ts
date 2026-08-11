/**
 * Signed /v1/status verification (spec §18.1, §6.2).
 *
 * Fail-closed policy gate over the raw HTTP body bytes: schema, signature
 * (Ed25519 via the packaged libsodium, pinned key), request-nonce binding,
 * network, protocol range, and clock skew — in that order, first failure
 * wins. Callers must have awaited initSodium() (the worker composition root
 * does this at startup).
 */
import type { z } from 'zod';
import { getCryptoProvider } from '../vault/crypto-provider';
import { blankSignatureInBody, signingInput } from './canonical';
import {
  signedEnvelopeFieldsSchema,
  statusCapabilitiesV1Schema,
  statusCapabilitiesV2Schema,
  type GatewayProtocolVersion,
  type GatewayNetwork,
  type SignedEnvelopeFields,
  type StatusCapabilities,
} from './contract';

/**
 * Every stable gateway failure reason. Transport and reconciliation reasons
 * are produced outside this verifier; verification returns the narrowed type
 * below.
 */
export type GatewayRejectReason =
  | 'http'
  | 'rate_limited'
  | 'network_error'
  | 'timeout'
  | 'response_too_large'
  | 'aborted'
  | 'schema'
  | 'signature'
  | 'nonce_mismatch'
  | 'wrong_network'
  | 'protocol'
  | 'skew'
  | 'conflicting_sources'
  | 'key_unprovisioned';

export type GatewayVerificationRejectReason = Exclude<
  GatewayRejectReason,
  'http' | 'rate_limited' | 'network_error' | 'timeout' | 'response_too_large' | 'aborted' | 'conflicting_sources'
>;

export type VerifyStatusResult =
  | { ok: true; status: StatusCapabilities }
  | { ok: false; reason: GatewayVerificationRejectReason };

export interface VerifyStatusInput {
  bodyBytes: Uint8Array;
  expectedNonce: string;
  expectedNetwork: GatewayNetwork;
  /** Pinned server public key, 32 bytes lowercase hex. */
  publicKeyHex: string;
  nowMs: number;
  /** Inclusive skew bound; ±300 000 ms per the settled signing design. */
  maxSkewMs: number;
  /** Build-channel policy. Production/preview pass [2]; development/test pass [1, 2]. */
  allowedProtocolVersions?: readonly GatewayProtocolVersion[];
}

export const MAX_CLOCK_SKEW_MS = 300_000;

const PUBKEY_HEX = /^[0-9a-f]{64}$/;
const SIGNATURE_HEX = /^[0-9a-f]{128}$/;

function fromHex(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/** Any envelope-bearing response body (spec §18.1). */
export type VerifySignedInput = VerifyStatusInput;

export type VerifySignedResult<T> =
  | { ok: true; value: T }
  | { ok: false; reason: GatewayVerificationRejectReason };

/**
 * Fail-closed verification of any §18.1 envelope-signed response body against
 * the given full-body schema. Same order as the M5 status verifier: schema →
 * pinned key → signature (blanking + Ed25519 over domainTag || env ||
 * sha256(blanked body)) → nonce → network → protocol version → skew.
 *
 * Status-specific policy (protocolMin/Max range) stays in verifyStatus.
 */
export function verifySignedResponse<S extends z.ZodTypeAny>(
  schema: S,
  input: VerifySignedInput,
): VerifySignedResult<z.infer<S>> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder().decode(input.bodyBytes));
  } catch {
    return { ok: false, reason: 'schema' };
  }
  const result = schema.safeParse(parsed);
  if (!result.success) return { ok: false, reason: 'schema' };
  const envelopeParse = signedEnvelopeFieldsSchema.safeParse(parsed);
  if (!envelopeParse.success) return { ok: false, reason: 'schema' };
  const envelope: SignedEnvelopeFields = envelopeParse.data;

  // An unprovisioned/malformed pinned key can never verify anything: fail
  // closed with a distinct reason so a production build without the hosted
  // key reads as misconfiguration, not as a hostile gateway.
  if (!PUBKEY_HEX.test(input.publicKeyHex)) return { ok: false, reason: 'key_unprovisioned' };

  if (!SIGNATURE_HEX.test(envelope.signature)) return { ok: false, reason: 'signature' };
  const blanked = blankSignatureInBody(input.bodyBytes, envelope.signature);
  if (blanked === null) return { ok: false, reason: 'signature' };
  const crypto = getCryptoProvider();
  const bodyHash = crypto.sha256(blanked);
  const { signature, ...rest } = envelope;
  const env = {
    instanceId: rest.instanceId,
    network: rest.network,
    protocolVersion: rest.protocolVersion,
    requestNonce: rest.requestNonce,
    timestamp: rest.timestamp,
    coreTip: rest.coreTip,
    indexTip: rest.indexTip,
    classificationRevision: rest.classificationRevision,
    capabilities: rest.capabilities,
  };
  const valid = crypto.ed25519Verify(
    fromHex(signature),
    signingInput(env, bodyHash),
    fromHex(input.publicKeyHex),
  );
  if (!valid) return { ok: false, reason: 'signature' };

  if (envelope.requestNonce !== input.expectedNonce) return { ok: false, reason: 'nonce_mismatch' };
  if (envelope.network !== input.expectedNetwork) return { ok: false, reason: 'wrong_network' };
  const allowed = input.allowedProtocolVersions ?? [1, 2];
  if (!allowed.includes(envelope.protocolVersion as GatewayProtocolVersion)) return { ok: false, reason: 'protocol' };
  const skew = Math.abs(Date.parse(envelope.timestamp) - input.nowMs);
  if (!Number.isFinite(skew) || skew > input.maxSkewMs) return { ok: false, reason: 'skew' };

  return { ok: true, value: result.data as z.infer<S> };
}

export function verifyStatus(input: VerifyStatusInput): VerifyStatusResult {
  let envelope: SignedEnvelopeFields;
  try {
    envelope = signedEnvelopeFieldsSchema.parse(JSON.parse(new TextDecoder().decode(input.bodyBytes)));
  } catch { return { ok: false, reason: 'schema' }; }
  const schema = envelope.protocolVersion === 1 ? statusCapabilitiesV1Schema :
    envelope.protocolVersion === 2 ? statusCapabilitiesV2Schema : null;
  if (schema === null) return { ok: false, reason: 'protocol' };
  const verified = verifySignedResponse(schema, input);
  if (!verified.ok) return verified;
  const status: StatusCapabilities = verified.value;
  const allowed = input.allowedProtocolVersions ?? [1, 2];
  if (!allowed.includes(status.protocolVersion) || status.protocolMin > status.protocolVersion || status.protocolMax < status.protocolVersion) {
    return { ok: false, reason: 'protocol' };
  }
  return { ok: true, status };
}
