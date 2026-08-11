/**
 * Gateway /v1 HTTP client (spec §18) — the ONLY module in the extension that
 * performs network I/O toward a gateway, and the only network destination the
 * wallet ever contacts.
 *
 * Privacy contract (spec §6.2, §18.5) binding on every future endpoint added
 * here:
 * - Never query a public indexer as a hidden cross-check.
 * - Never send xpubs or descriptors; the client derives scripts locally and
 *   sends only required script hashes and outpoints.
 * - Batch script-hash requests per account per request — enough batching to
 *   avoid correlation-friendly chatter, without unused lookahead beyond
 *   discovery needs.
 *
 * The class is fetch-agnostic (injected ports) so tests drive it with a fake;
 * the composition root wires the real fetch, clock, and CSPRNG nonce.
 */
import type { z } from 'zod';
import {
  broadcastResultSchema,
  feeQuoteResponseSchema,
  fiatPriceQuoteSchema,
  inscriptionActivityBatchRequestSchema,
  inscriptionActivityBatchResponseSchema,
  inscriptionApprovalBatchRequestSchema,
  inscriptionApprovalBatchResponseSchema,
  inscriptionGalleryBatchRequestSchema,
  inscriptionGalleryBatchResponseSchema,
  inscriptionGalleryEnrichedBatchResponseSchema,
  inscriptionIdSchema,
  inscriptionMediaRequestSchema,
  inscriptionMediaResponseSchema,
  inscriptionMetadataResponseSchema,
  inscriptionPreviewResponseSchema,
  INSCRIPTION_APPROVAL_MAX_RASTERS,
  INSCRIPTION_APPROVAL_BATCH_MAX_PREVIEW_BYTES,
  INSCRIPTION_APPROVAL_BATCH_MAX_RESPONSE_BYTES,
  INSCRIPTION_PREVIEW_MAX_BYTES,
  INSCRIPTION_MEDIA_MAX_BYTES,
  outpointsClassifyResponseSchema,
  walletActivitySnapshotResponseSchema,
  walletSnapshotResponseSchema,
  type BroadcastRequest,
  type BroadcastResult,
  type FeeQuoteResponse,
  type FiatPriceQuote,
  type GatewayNetwork,
  type GatewayProtocolVersion,
  type InscriptionApprovalBatchRequest,
  type InscriptionApprovalBatchResponse,
  type InscriptionActivityBatchRequest,
  type InscriptionActivityBatchResponse,
  type InscriptionIdentity,
  type InscriptionGalleryBatchRequest,
  type InscriptionGalleryBatchResponse,
  type InscriptionGalleryEnrichedBatchResponse,
  type InscriptionMediaRequest,
  type InscriptionMediaResponse,
  type InscriptionMetadataResponse,
  type InscriptionPreviewPayload,
  type InscriptionPreviewResponse,
  type OutpointsClassifyRequest,
  type OutpointsClassifyResponse,
  type StatusCapabilities,
  type WalletSnapshotRequest,
  type WalletSnapshotResponse,
} from './domain/gateway/contract';
import { base64ToBytes, bytesToBase64, bytesToHex } from './domain/vault/encoding';
import { getCryptoProvider } from './domain/vault/crypto-provider';
import {
  MAX_CLOCK_SKEW_MS,
  verifySignedResponse,
  verifyStatus,
  type GatewayRejectReason,
  type GatewayVerificationRejectReason,
} from './domain/gateway/verify';

export const NONCE_HEADER = 'x-squirrel-request-nonce';
export const STATUS_DEADLINE_MS = 10_000;
export const SIGNED_ENDPOINT_DEADLINE_MS = 30_000;
export const MIN_RETRY_JITTER_MS = 250;
export const MAX_RETRY_JITTER_MS = 750;
export const TRANSIENT_READ_RETRY_FLOORS_MS = [0, 500, 1_250, 2_250, 2_750] as const;
export const STATUS_MAX_RESPONSE_BYTES = 256 * 1024;
export const SIGNED_MAX_RESPONSE_BYTES = 2 * 1024 * 1024;

type Sleep = (delayMs: number, signal?: AbortSignal) => Promise<void>;

export interface GatewayClientDeps {
  fetchFn: typeof fetch;
  /** Origin + optional path prefix, no trailing slash, e.g. "http://127.0.0.1:8080". */
  baseUrl: string;
  /** Pinned server public key, 32 bytes lowercase hex ('' = unprovisioned). */
  publicKeyHex: string;
  expectedNetwork: GatewayNetwork;
  allowedProtocolVersions?: readonly GatewayProtocolVersion[];
  /** Returns 16 CSPRNG bytes as 32 lowercase hex chars. */
  randomNonce: () => string;
  now: () => number;
  /** Test seam; production uses a random 250-750 ms delay. */
  retryJitterMs?: () => number;
  /** Test seam; production uses an abortable setTimeout. */
  sleep?: Sleep;
}

export type GatewayFailure =
  | {
      ok: false;
      reason: 'rate_limited';
      httpStatus: 429;
      /** Delay from receipt, or null when Retry-After is absent/malformed. */
      retryAfterMs: number | null;
      /** Absolute local-clock instant, or null when Retry-After is absent/malformed. */
      retryAfterAtMs: number | null;
    }
  | { ok: false; reason: 'http'; httpStatus: number }
  | {
      ok: false;
      reason: Exclude<GatewayRejectReason, 'http' | 'rate_limited'>;
    };

export type FetchStatusResult =
  | { ok: true; status: StatusCapabilities; verifiedAtMs: number }
  | GatewayFailure;

export type FetchSignedResult<T> =
  | { ok: true; value: T; verifiedAtMs: number }
  | GatewayFailure;

interface AttemptResult<T> {
  result: FetchSignedResult<T>;
  retryable: boolean;
}

interface RequestPolicy {
  deadlineMs: number;
  maxRetries: number;
  retryTimeoutOnce: boolean;
  maxResponseBytes: number;
}

type BodyVerification<T> =
  | { ok: true; value: T }
  | { ok: false; reason: GatewayVerificationRejectReason };
type BodyVerifier<T> = (bodyBytes: Uint8Array, nonce: string, nowMs: number) => BodyVerification<T>;

const NO_RETRY_30S: RequestPolicy = {
  deadlineMs: SIGNED_ENDPOINT_DEADLINE_MS,
  maxRetries: 0,
  retryTimeoutOnce: false,
  maxResponseBytes: SIGNED_MAX_RESPONSE_BYTES,
};

const TRANSIENT_READ_POLICY: RequestPolicy = {
  deadlineMs: SIGNED_ENDPOINT_DEADLINE_MS,
  maxRetries: TRANSIENT_READ_RETRY_FLOORS_MS.length,
  retryTimeoutOnce: true,
  maxResponseBytes: SIGNED_MAX_RESPONSE_BYTES,
};

const INSCRIPTION_BATCH_POLICY: RequestPolicy = {
  deadlineMs: SIGNED_ENDPOINT_DEADLINE_MS,
  maxRetries: 0,
  retryTimeoutOnce: false,
  maxResponseBytes: INSCRIPTION_APPROVAL_BATCH_MAX_RESPONSE_BYTES,
};

function sameIdentity(a: InscriptionIdentity, b: InscriptionIdentity): boolean {
  return a.inscriptionId === b.inscriptionId && a.satpoint === b.satpoint &&
    a.outpoint.txid === b.outpoint.txid && a.outpoint.vout === b.outpoint.vout &&
    a.classificationRevision === b.classificationRevision;
}

function readUint32(bytes: Uint8Array, offset: number): number {
  return ((bytes[offset]! * 0x1000000) + (bytes[offset + 1]! << 16) +
    (bytes[offset + 2]! << 8) + bytes[offset + 3]!) >>> 0;
}

function crc32(bytes: Uint8Array): number {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit += 1) {
      crc = (crc >>> 1) ^ ((crc & 1) === 1 ? 0xedb88320 : 0);
    }
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function validBoundedPng(bytes: Uint8Array, width: number, height: number): boolean {
  const signature = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
  if (bytes.length < 45 || signature.some((byte, index) => bytes[index] !== byte)) return false;
  let offset = 8;
  let chunkIndex = 0;
  let sawIend = false;
  while (offset + 12 <= bytes.length) {
    const length = readUint32(bytes, offset);
    const dataStart = offset + 8;
    const dataEnd = dataStart + length;
    const crcOffset = dataEnd;
    if (length > INSCRIPTION_PREVIEW_MAX_BYTES || dataEnd < dataStart || crcOffset + 4 > bytes.length) return false;
    const type = String.fromCharCode(...bytes.slice(offset + 4, offset + 8));
    if (readUint32(bytes, crcOffset) !== crc32(bytes.slice(offset + 4, dataEnd))) return false;
    if (chunkIndex === 0) {
      if (type !== 'IHDR' || length !== 13 || readUint32(bytes, dataStart) !== width ||
          readUint32(bytes, dataStart + 4) !== height) return false;
    } else if (type === 'IHDR') {
      return false;
    }
    offset = crcOffset + 4;
    chunkIndex += 1;
    if (type === 'IEND') {
      if (length !== 0 || offset !== bytes.length) return false;
      sawIend = true;
      break;
    }
  }
  return sawIend;
}

function verifiedPreviewBytes(preview: InscriptionPreviewPayload): Uint8Array | null {
  if (preview.disposition !== 'raster') {
    // Placeholders, text excerpts, and media badges carry no preview bytes;
    // their content is inside the signed envelope itself.
    return preview.bytesBase64 === null ? new Uint8Array() : null;
  }
  let bytes: Uint8Array;
  try {
    bytes = base64ToBytes(preview.bytesBase64);
  } catch {
    return null;
  }
  if (bytes.length === 0 || bytes.length > INSCRIPTION_PREVIEW_MAX_BYTES ||
      bytes.length !== preview.pngByteLength ||
      bytesToBase64(bytes) !== preview.bytesBase64) return null;
  if (!validBoundedPng(bytes, preview.pngWidth, preview.pngHeight)) return null;
  return bytesToHex(getCryptoProvider().sha256(bytes)) === preview.pngSha256 ? bytes : null;
}

function verifyApprovalBatchBinding(
  request: InscriptionApprovalBatchRequest,
  response: InscriptionApprovalBatchResponse,
): boolean {
  if (response.network !== request.network || response.analysisHash !== request.analysisHash ||
      response.psbtHash !== request.psbtHash ||
      response.transactionCommitmentHash !== request.transactionCommitmentHash ||
      response.effectSetHash !== request.effectSetHash ||
      response.classificationRevision !== request.inscriptions[0]?.classificationRevision ||
      response.items.length !== request.inscriptions.length) return false;
  let totalBytes = 0;
  let rasterCount = 0;
  for (let index = 0; index < request.inscriptions.length; index += 1) {
    const expected = request.inscriptions[index]!;
    const item = response.items[index];
    if (!item || !sameIdentity(expected, item.metadata) ||
        item.preview.requestedInscriptionId !== expected.inscriptionId ||
        item.metadata.classificationRevision !== response.classificationRevision) return false;
    const bytes = verifiedPreviewBytes(item.preview);
    if (!bytes) return false;
    totalBytes += bytes.length;
    if (item.preview.disposition === 'raster') rasterCount += 1;
    if (rasterCount > INSCRIPTION_APPROVAL_MAX_RASTERS) return false;
    if (totalBytes > INSCRIPTION_APPROVAL_BATCH_MAX_PREVIEW_BYTES) return false;
  }
  return true;
}

function verifyGalleryBatchBinding(
  request: InscriptionGalleryBatchRequest,
  response: InscriptionGalleryBatchResponse,
): boolean {
  if (response.network !== request.network ||
      response.classificationRevision !== request.inscriptions[0]?.classificationRevision ||
      response.items.length !== request.inscriptions.length) return false;
  for (let index = 0; index < request.inscriptions.length; index += 1) {
    const expected = request.inscriptions[index]!;
    const item = response.items[index];
    if (!item || !sameIdentity(expected, item.metadata) ||
        item.preview.requestedInscriptionId !== expected.inscriptionId ||
        !verifiedPreviewBytes(item.preview)) return false;
  }
  return true;
}

function verifyActivityBatchBinding(
  request: InscriptionActivityBatchRequest,
  response: InscriptionActivityBatchResponse,
): boolean {
  if (response.network !== request.network ||
      response.items.length !== request.inscriptionIds.length) return false;
  for (let index = 0; index < request.inscriptionIds.length; index += 1) {
    const inscriptionId = request.inscriptionIds[index]!;
    const item = response.items[index];
    if (!item ||
        item.metadata.inscriptionId !== inscriptionId ||
        item.metadata.classificationRevision !== response.classificationRevision ||
        item.preview.requestedInscriptionId !== inscriptionId ||
        !verifiedPreviewBytes(item.preview)) return false;
  }
  return true;
}

function verifyGalleryEnrichedBatchBinding(
  request: InscriptionGalleryBatchRequest,
  response: InscriptionGalleryEnrichedBatchResponse,
): boolean {
  if (response.network !== request.network ||
      response.classificationRevision !== request.inscriptions[0]?.classificationRevision ||
      response.items.length !== request.inscriptions.length) return false;
  for (let index = 0; index < request.inscriptions.length; index += 1) {
    const expected = request.inscriptions[index]!;
    const item = response.items[index];
    if (!item || !sameIdentity(expected, item.metadata) ||
        item.preview.requestedInscriptionId !== expected.inscriptionId ||
        !verifiedPreviewBytes(item.preview)) return false;
  }
  return true;
}

function verifyMediaBinding(
  request: InscriptionMediaRequest,
  response: InscriptionMediaResponse,
): boolean {
  if (response.network !== request.network || !sameIdentity(request.identity, response.identity) ||
      response.media.requestedInscriptionId !== request.identity.inscriptionId) return false;
  if (response.media.disposition === 'unavailable') return response.media.bytesBase64 === null;
  let bytes: Uint8Array;
  try { bytes = base64ToBytes(response.media.bytesBase64); } catch { return false; }
  return bytes.length > 0 && bytes.length <= INSCRIPTION_MEDIA_MAX_BYTES &&
    bytes.length === response.media.contentByteLength &&
    bytesToBase64(bytes) === response.media.bytesBase64 &&
    bytesToHex(getCryptoProvider().sha256(bytes)) === response.media.contentSha256;
}

async function readBoundedBody(response: Response, limit: number): Promise<Uint8Array | null> {
  const declaredLength = response.headers.get('content-length');
  if (declaredLength !== null && /^(?:0|[1-9][0-9]*)$/u.test(declaredLength) &&
      Number(declaredLength) > limit) return null;
  if (!response.body) {
    const bytes = new Uint8Array(await response.arrayBuffer());
    return bytes.length <= limit ? bytes : null;
  }
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      length += value.length;
      if (length > limit) {
        await reader.cancel();
        return null;
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const body = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.length;
  }
  return body;
}

function defaultSleep(delayMs: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(signal.reason);
      return;
    }
    const onAbort = () => {
      globalThis.clearTimeout(timer);
      reject(signal?.reason);
    };
    const timer = globalThis.setTimeout(() => {
      signal?.removeEventListener('abort', onAbort);
      resolve();
    }, delayMs);
    signal?.addEventListener('abort', onAbort, { once: true });
  });
}

function retryAfter(response: Response, nowMs: number): Pick<
  Extract<GatewayFailure, { reason: 'rate_limited' }>,
  'retryAfterMs' | 'retryAfterAtMs'
> {
  const raw = response.headers.get('retry-after')?.trim();
  if (raw === undefined || raw === '') return { retryAfterMs: null, retryAfterAtMs: null };
  if (/^[0-9]+$/.test(raw)) {
    const seconds = Number(raw);
    if (!Number.isSafeInteger(seconds)) return { retryAfterMs: null, retryAfterAtMs: null };
    const retryAfterMs = seconds * 1_000;
    if (!Number.isSafeInteger(retryAfterMs) || !Number.isSafeInteger(nowMs + retryAfterMs)) {
      return { retryAfterMs: null, retryAfterAtMs: null };
    }
    return { retryAfterMs, retryAfterAtMs: nowMs + retryAfterMs };
  }
  const retryAfterAtMs = Date.parse(raw);
  if (!Number.isFinite(retryAfterAtMs)) return { retryAfterMs: null, retryAfterAtMs: null };
  return { retryAfterMs: Math.max(0, retryAfterAtMs - nowMs), retryAfterAtMs };
}

export class GatewayClient {
  constructor(private readonly deps: GatewayClientDeps) {}

  get endpoint(): string {
    return this.deps.baseUrl;
  }

  get protocolVersions(): readonly GatewayProtocolVersion[] {
    return this.deps.allowedProtocolVersions ?? [1, 2];
  }

  async fetchStatus(signal?: AbortSignal): Promise<FetchStatusResult> {
    const attempted = await this.requestAttempt(
      '/v1/status',
      { method: 'GET' },
      STATUS_DEADLINE_MS,
      STATUS_MAX_RESPONSE_BYTES,
      (bodyBytes, nonce, nowMs) => {
        const verified = verifyStatus({
          bodyBytes,
          expectedNonce: nonce,
          expectedNetwork: this.deps.expectedNetwork,
          publicKeyHex: this.deps.publicKeyHex,
          nowMs,
          maxSkewMs: MAX_CLOCK_SKEW_MS,
          allowedProtocolVersions: this.protocolVersions,
        });
        return verified.ok
          ? { ok: true, value: verified.status }
          : verified;
      },
      signal,
    );
    if (!attempted.result.ok) return attempted.result;
    return {
      ok: true,
      status: attempted.result.value,
      verifiedAtMs: attempted.result.verifiedAtMs,
    };
  }

  /**
   * One request per (account index, lane): external + internal script hashes
   * for the current gap window (spec §18.5 batching; see the module header's
   * privacy contract).
   */
  async fetchSnapshot(
    req: WalletSnapshotRequest,
    signal?: AbortSignal,
  ): Promise<FetchSignedResult<WalletSnapshotResponse>> {
    const activity = await this.postSigned(
      '/v1/wallet/activity-snapshot',
      req,
      walletActivitySnapshotResponseSchema,
      NO_RETRY_30S,
      signal,
    );
    if (activity.ok || activity.reason !== 'http' || activity.httpStatus !== 404) {
      return activity;
    }
    // Protocol-v2 gateways predating activity/ordinal-flow enrichment parse
    // snapshot requests strictly. Forwarding includeOrdinalFlow to that
    // endpoint turns a compatible 404 fallback into a 400 and prevents an
    // Ordinals-lane scan during a staggered rollout. Send exactly the legacy
    // request shape; the missing flow evidence only limits display enrichment.
    const legacyRequest = {
      network: req.network,
      scriptHashes: req.scriptHashes,
    };
    return this.postSigned(
      '/v1/wallet/snapshot',
      legacyRequest,
      walletSnapshotResponseSchema,
      TRANSIENT_READ_POLICY,
      signal,
    );
  }

  /** Batched per account, ≤200 outpoints per chunk (caller chunks). */
  async classifyOutpoints(
    req: OutpointsClassifyRequest,
    signal?: AbortSignal,
  ): Promise<FetchSignedResult<OutpointsClassifyResponse>> {
    return this.postSigned('/v1/outpoints/classify', req, outpointsClassifyResponseSchema, TRANSIENT_READ_POLICY, signal);
  }

  async fetchFees(signal?: AbortSignal): Promise<FetchSignedResult<FeeQuoteResponse>> {
    return this.getSigned('/v1/fees', feeQuoteResponseSchema, NO_RETRY_30S, signal);
  }

  async fetchPrice(signal?: AbortSignal): Promise<FetchSignedResult<FiatPriceQuote>> {
    return this.getSigned('/v1/price', fiatPriceQuoteSchema, NO_RETRY_30S, signal);
  }

  async broadcastTransaction(
    req: BroadcastRequest,
    signal?: AbortSignal,
  ): Promise<FetchSignedResult<BroadcastResult>> {
    const result = await this.postSigned(
      '/v1/transactions/broadcast',
      req,
      broadcastResultSchema,
      NO_RETRY_30S,
      signal,
    );
    if (result.ok && (result.value.submittedTxid !== req.txid || result.value.submittedWtxid !== req.wtxid)) {
      return { ok: false, reason: 'schema' };
    }
    return result;
  }

  async fetchInscriptionMetadata(
    inscriptionId: string,
    signal?: AbortSignal,
  ): Promise<FetchSignedResult<InscriptionMetadataResponse>> {
    if (!inscriptionIdSchema.safeParse(inscriptionId).success) return { ok: false, reason: 'schema' };
    const result = await this.getSigned(
      `/v1/inscriptions/${encodeURIComponent(inscriptionId)}`,
      inscriptionMetadataResponseSchema,
      NO_RETRY_30S,
      signal,
    );
    if (result.ok && (result.value.metadata.inscriptionId !== inscriptionId ||
        result.value.metadata.classificationRevision !== result.value.classificationRevision)) {
      return { ok: false, reason: 'schema' };
    }
    return result;
  }

  async fetchInscriptionPreview(
    identity: InscriptionIdentity,
    signal?: AbortSignal,
  ): Promise<FetchSignedResult<InscriptionPreviewResponse>> {
    const result = await this.getSigned(
      `/v1/inscriptions/${encodeURIComponent(identity.inscriptionId)}/preview`,
      inscriptionPreviewResponseSchema,
      NO_RETRY_30S,
      signal,
    );
    if (result.ok && (!sameIdentity(identity, result.value.identity) ||
        result.value.classificationRevision !== identity.classificationRevision ||
        !verifiedPreviewBytes(result.value.preview))) return { ok: false, reason: 'schema' };
    return result;
  }

  async fetchInscriptionApprovalBatch(
    request: InscriptionApprovalBatchRequest,
    signal?: AbortSignal,
  ): Promise<FetchSignedResult<InscriptionApprovalBatchResponse>> {
    const parsed = inscriptionApprovalBatchRequestSchema.safeParse(request);
    if (!parsed.success) return { ok: false, reason: 'schema' };
    const result = await this.postSigned(
      '/v1/inscriptions/approval-batch',
      parsed.data,
      inscriptionApprovalBatchResponseSchema,
      INSCRIPTION_BATCH_POLICY,
      signal,
    );
    if (result.ok && !verifyApprovalBatchBinding(parsed.data, result.value)) {
      return { ok: false, reason: 'schema' };
    }
    return result;
  }

  async fetchInscriptionActivityBatch(
    request: InscriptionActivityBatchRequest,
    signal?: AbortSignal,
  ): Promise<FetchSignedResult<InscriptionActivityBatchResponse>> {
    const parsed = inscriptionActivityBatchRequestSchema.safeParse(request);
    if (!parsed.success) return { ok: false, reason: 'schema' };
    const result = await this.postSigned(
      '/v1/inscriptions/activity-batch',
      parsed.data,
      inscriptionActivityBatchResponseSchema,
      INSCRIPTION_BATCH_POLICY,
      signal,
    );
    if (result.ok && !verifyActivityBatchBinding(parsed.data, result.value)) {
      return { ok: false, reason: 'schema' };
    }
    return result;
  }

  async fetchInscriptionGalleryBatch(
    request: InscriptionGalleryBatchRequest,
    signal?: AbortSignal,
  ): Promise<FetchSignedResult<InscriptionGalleryBatchResponse>> {
    const parsed = inscriptionGalleryBatchRequestSchema.safeParse(request);
    if (!parsed.success) return { ok: false, reason: 'schema' };
    const result = await this.postSigned(
      '/v1/inscriptions/gallery-batch',
      parsed.data,
      inscriptionGalleryBatchResponseSchema,
      INSCRIPTION_BATCH_POLICY,
      signal,
    );
    if (result.ok && !verifyGalleryBatchBinding(parsed.data, result.value)) {
      return { ok: false, reason: 'schema' };
    }
    return result;
  }

  async fetchInscriptionGalleryEnrichedBatch(
    request: InscriptionGalleryBatchRequest,
    signal?: AbortSignal,
  ): Promise<FetchSignedResult<InscriptionGalleryEnrichedBatchResponse>> {
    const parsed = inscriptionGalleryBatchRequestSchema.safeParse(request);
    if (!parsed.success) return { ok: false, reason: 'schema' };
    const result = await this.postSigned(
      '/v1/inscriptions/gallery-batch-enriched',
      parsed.data,
      inscriptionGalleryEnrichedBatchResponseSchema,
      INSCRIPTION_BATCH_POLICY,
      signal,
    );
    if (result.ok && !verifyGalleryEnrichedBatchBinding(parsed.data, result.value)) {
      return { ok: false, reason: 'schema' };
    }
    return result;
  }

  async fetchInscriptionMedia(
    request: InscriptionMediaRequest,
    signal?: AbortSignal,
  ): Promise<FetchSignedResult<InscriptionMediaResponse>> {
    const parsed = inscriptionMediaRequestSchema.safeParse(request);
    if (!parsed.success) return { ok: false, reason: 'schema' };
    const result = await this.postSigned(
      '/v1/inscriptions/media',
      parsed.data,
      inscriptionMediaResponseSchema,
      { ...NO_RETRY_30S, maxResponseBytes: 3 * 1024 * 1024 },
      signal,
    );
    if (result.ok && !verifyMediaBinding(parsed.data, result.value)) {
      return { ok: false, reason: 'schema' };
    }
    return result;
  }

  private async getSigned<S extends z.ZodTypeAny>(
    path: string,
    schema: S,
    policy: RequestPolicy,
    signal?: AbortSignal,
  ): Promise<FetchSignedResult<z.infer<S>>> {
    return this.requestWithPolicy(path, { method: 'GET' }, schema, policy, signal);
  }

  private async postSigned<S extends z.ZodTypeAny>(
    path: string,
    body: unknown,
    schema: S,
    policy: RequestPolicy,
    signal?: AbortSignal,
  ): Promise<FetchSignedResult<z.infer<S>>> {
    return this.requestWithPolicy(
      path,
      {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(body),
      },
      schema,
      policy,
      signal,
    );
  }

  private async requestWithPolicy<S extends z.ZodTypeAny>(
    path: string,
    init: RequestInit,
    schema: S,
    policy: RequestPolicy,
    signal?: AbortSignal,
  ): Promise<FetchSignedResult<z.infer<S>>> {
    const verify: BodyVerifier<z.infer<S>> = (bodyBytes, nonce, nowMs) =>
      verifySignedResponse(schema, {
        bodyBytes,
        expectedNonce: nonce,
        expectedNetwork: this.deps.expectedNetwork,
        publicKeyHex: this.deps.publicKeyHex,
        nowMs,
        maxSkewMs: MAX_CLOCK_SKEW_MS,
        allowedProtocolVersions: this.protocolVersions,
      });
    let attempted = await this.requestAttempt(
      path,
      init,
      policy.deadlineMs,
      policy.maxResponseBytes,
      verify,
      signal,
    );
    for (let retryIndex = 0; retryIndex < policy.maxRetries; retryIndex += 1) {
      if (!attempted.retryable || attempted.result.ok || signal?.aborted) return attempted.result;
      if (attempted.result.reason === 'timeout' &&
          (!policy.retryTimeoutOnce || retryIndex > 0)) return attempted.result;

      const rawJitter = this.deps.retryJitterMs?.() ??
        MIN_RETRY_JITTER_MS + Math.floor(Math.random() * (MAX_RETRY_JITTER_MS - MIN_RETRY_JITTER_MS + 1));
      const jitterCandidate = Number.isFinite(rawJitter) ? Math.floor(rawJitter) : MIN_RETRY_JITTER_MS;
      const jitter = Math.min(MAX_RETRY_JITTER_MS, Math.max(MIN_RETRY_JITTER_MS, jitterCandidate));
      const retryFloor = TRANSIENT_READ_RETRY_FLOORS_MS[retryIndex] ?? 0;
      try {
        await (this.deps.sleep ?? defaultSleep)(retryFloor + jitter, signal);
      } catch {
        return { ok: false, reason: 'aborted' };
      }
      if (signal?.aborted) return { ok: false, reason: 'aborted' };
      attempted = await this.requestAttempt(
        path,
        init,
        policy.deadlineMs,
        policy.maxResponseBytes,
        verify,
        signal,
      );
    }
    return attempted.result;
  }

  private async requestAttempt<T>(
    path: string,
    init: RequestInit,
    deadlineMs: number,
    maxResponseBytes: number,
    verify: BodyVerifier<T>,
    callerSignal?: AbortSignal,
  ): Promise<AttemptResult<T>> {
    if (callerSignal?.aborted) {
      return { result: { ok: false, reason: 'aborted' }, retryable: false };
    }

    const nonce = this.deps.randomNonce();
    const controller = new AbortController();
    let deadlineExpired = false;
    let callerAborted = false;
    const abortFromCaller = () => {
      callerAborted = true;
      controller.abort(callerSignal?.reason);
    };
    callerSignal?.addEventListener('abort', abortFromCaller, { once: true });
    const timer = globalThis.setTimeout(() => {
      deadlineExpired = true;
      controller.abort();
    }, deadlineMs);

    try {
      const headers = new Headers(init.headers);
      headers.set(NONCE_HEADER, nonce);
      const response = await this.deps.fetchFn(`${this.deps.baseUrl}${path}`, {
        ...init,
        headers,
        signal: controller.signal,
      });
      if (response.status === 429) {
        const parsedRetryAfter = retryAfter(response, this.deps.now());
        return {
          result: { ok: false, reason: 'rate_limited', httpStatus: 429, ...parsedRetryAfter },
          retryable: false,
        };
      }
      if (!response.ok) {
        return {
          result: { ok: false, reason: 'http', httpStatus: response.status },
          retryable: response.status >= 500 && response.status <= 599,
        };
      }

      let bodyBytes: Uint8Array;
      try {
        const bounded = await readBoundedBody(response, maxResponseBytes);
        if (bounded === null) {
          return { result: { ok: false, reason: 'response_too_large' }, retryable: false };
        }
        bodyBytes = bounded;
      } catch {
        if (deadlineExpired) return { result: { ok: false, reason: 'timeout' }, retryable: true };
        if (callerAborted) return { result: { ok: false, reason: 'aborted' }, retryable: false };
        return { result: { ok: false, reason: 'network_error' }, retryable: true };
      }
      if (deadlineExpired) return { result: { ok: false, reason: 'timeout' }, retryable: true };
      if (callerAborted) return { result: { ok: false, reason: 'aborted' }, retryable: false };
      const nowMs = this.deps.now();
      const verified = verify(bodyBytes, nonce, nowMs);
      if (!verified.ok) return { result: verified, retryable: false };
      return { result: { ok: true, value: verified.value, verifiedAtMs: nowMs }, retryable: false };
    } catch {
      if (deadlineExpired) return { result: { ok: false, reason: 'timeout' }, retryable: true };
      if (callerAborted) return { result: { ok: false, reason: 'aborted' }, retryable: false };
      return { result: { ok: false, reason: 'network_error' }, retryable: true };
    } finally {
      globalThis.clearTimeout(timer);
      callerSignal?.removeEventListener('abort', abortFromCaller);
    }
  }
}
