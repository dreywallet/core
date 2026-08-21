/**
 * Client mirror of the /v1 gateway contract (spec §18.1, §18.2) — M5 subset.
 *
 * The gateway repo (`gateway/src/schemas.ts`) is the source of truth for
 * these schemas (spec §4); this file is a deliberate field-for-field mirror,
 * and drift is caught by the contract tests against the committed fixture
 * copies in tests/fixtures/gateway/. All amounts anywhere in the contract are
 * decimal-string sats; fee rates are positive integer sat/vB; no JSON
 * floating-point amount is ever accepted.
 */
import { z } from 'zod';
import { parseCanonicalSatpoint } from '../ordinals/satpoint';

export const networkSchema = z.enum(['mainnet', 'signet', 'regtest']);
export type GatewayNetwork = z.infer<typeof networkSchema>;

export const hexIdSchema = z.string().regex(/^[0-9a-f]{64}$/, '32-byte hex id');
export const voutSchema = z.number().int().min(0).max(0xffffffff);

export const tipSchema = z
  .object({
    height: z.number().int().nonnegative(),
    hash: hexIdSchema,
  })
  .strict();
export type Tip = z.infer<typeof tipSchema>;

export const capabilitySchema = z.enum([
  'address_history',
  'inscription_index',
  'sat_index',
  'rarity',
  'rune_detection',
  'unsupported_asset_detection',
  'mempool_overlay',
  'preview_service',
  'fee_estimation',
  'broadcast',
]);
export type Capability = z.infer<typeof capabilitySchema>;

export const safetyModeSchema = z.enum(['full_sat_safety', 'standard_ordinals_safety']);
export type SafetyMode = z.infer<typeof safetyModeSchema>;

// spec §18.1: every security-relevant response carries this envelope.
export const signedEnvelopeFieldsSchema = z.object({
  instanceId: z.string().min(1),
  network: networkSchema,
  protocolVersion: z.number().int().positive(),
  requestNonce: z.string().min(1),
  timestamp: z.string().datetime(),
  coreTip: tipSchema,
  indexTip: tipSchema,
  classificationRevision: z.string().min(1),
  capabilities: z.array(capabilitySchema),
  signature: z.string().min(1),
});
export type SignedEnvelopeFields = z.infer<typeof signedEnvelopeFieldsSchema>;
export type EnvelopeFields = Omit<SignedEnvelopeFields, 'signature'>;

export const statusCapabilitiesV1Schema = signedEnvelopeFieldsSchema
  .extend({
    protocolVersion: z.literal(1),
    protocolMin: z.number().int().positive(),
    protocolMax: z.number().int().positive(),
    historyTip: tipSchema,
    ordTip: tipSchema,
    mempoolObservedAt: z.string().datetime(),
    eligibleSafetyModes: z.array(safetyModeSchema),
    activeRevision: z.string().min(1),
    serverTime: z.string().datetime(),
  })
  .strict();

export const productionReadOnlyReasonSchema = z.enum([
  'capacity_low', 'capacity_unavailable', 'classification_inactive', 'classification_revision_mismatch',
  'classification_tip_mismatch', 'classification_unavailable', 'classification_bootstrapping', 'classification_advancing',
  'core_headers_behind', 'core_ibd', 'core_mempool_unloaded', 'core_tip_changed', 'core_unavailable',
  'electrs_unavailable', 'mempool_stale', 'ord_unavailable', 'peers_insufficient', 'reorg_verifying',
  'reorg_reconciling', 'reorg_manual_intervention', 'spending_endpoints_unavailable', 'tip_mismatch',
  'txindex_unsynced', 'wrong_network',
]);

const dependencyStateSchema = z.enum(['ready', 'unready', 'stale', 'mismatched', 'unavailable']);
export const productionReadinessSchema = z.object({
  walletDataReady: z.boolean(),
  spendingReady: z.boolean(),
  reasons: z.array(productionReadOnlyReasonSchema),
  dependencies: z.object({ core: dependencyStateSchema, ord: dependencyStateSchema, electrs: dependencyStateSchema,
    classification: dependencyStateSchema, capacity: dependencyStateSchema, signing: z.literal('ready') }).strict(),
  core: z.object({ initialBlockDownload: z.boolean().nullable(), headersSynced: z.boolean().nullable(),
    txindexSynced: z.boolean().nullable(), peersReady: z.boolean().nullable(), mempoolLoaded: z.boolean().nullable() }).strict(),
  coherentCoreSampling: z.boolean(), commonTip: z.boolean(), mempoolFresh: z.boolean(),
  reorgState: z.enum(['clear', 'verifying', 'reconciling', 'manual_intervention', 'unknown']),
  classificationState: z.enum(['bootstrapping', 'active', 'advancing', 'reconciling', 'blocked', 'unavailable']),
  capacityState: z.enum(['ready', 'low', 'unavailable']), signingKeyAvailable: z.literal(true),
}).strict().superRefine((readiness, ctx) => {
  if (readiness.spendingReady && !readiness.walletDataReady) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['spendingReady'], message: 'spending requires wallet data' });
  }
  if (new Set(readiness.reasons).size !== readiness.reasons.length) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['reasons'], message: 'readiness reasons must be unique' });
  }
});

export const statusCapabilitiesV2Schema = signedEnvelopeFieldsSchema.extend({
  protocolVersion: z.literal(2), protocolMin: z.literal(2), protocolMax: z.literal(2), historyTip: tipSchema,
  ordTip: tipSchema, mempoolObservedAt: z.string().datetime(), eligibleSafetyModes: z.array(safetyModeSchema),
  activeRevision: z.string().min(1), serverTime: z.string().datetime(), readiness: productionReadinessSchema,
}).strict().superRefine((status, ctx) => {
  if (status.readiness.spendingReady && !status.capabilities.includes('broadcast')) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['readiness', 'spendingReady'], message: 'spending requires broadcast capability' });
  }
});

export const statusCapabilitiesSchema = z.union([
  statusCapabilitiesV1Schema,
  statusCapabilitiesV2Schema,
]);
export type StatusCapabilities = z.infer<typeof statusCapabilitiesSchema>;

export const fiatPriceQuoteSchema = signedEnvelopeFieldsSchema.extend({
  protocolVersion: z.literal(2),
  base: z.literal('BTC'),
  quote: z.literal('USD'),
  priceUsdCentsPerBtc: z.string().regex(/^[1-9][0-9]*$/),
  observedAt: z.string().datetime(),
  expiresAt: z.string().datetime(),
  quality: z.enum(['consensus', 'degraded', 'stale']),
  sourceCount: z.number().int().min(2).max(3),
  maxDeviationBps: z.number().int().min(0).max(100),
}).strict().superRefine((quote, ctx) => {
  const observedAt = Date.parse(quote.observedAt);
  const expiresAt = Date.parse(quote.expiresAt);
  if (expiresAt <= observedAt) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['expiresAt'], message: 'price expiry must follow observation' });
  }
  if (quote.quality === 'consensus' && quote.sourceCount !== 3) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['sourceCount'], message: 'consensus requires three sources' });
  }
  if (quote.quality === 'degraded' && quote.sourceCount !== 2) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['sourceCount'], message: 'degraded quote requires two sources' });
  }
  if (quote.quality === 'stale' && Date.parse(quote.timestamp) <= expiresAt) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['quality'], message: 'stale quote must be expired' });
  }
});
export type FiatPriceQuote = z.infer<typeof fiatPriceQuoteSchema>;

/** The protocol version this client implements (spec §18.1 compatible range). */
export const CLIENT_PROTOCOL_VERSION = 2;
export type GatewayProtocolVersion = 1 | 2;

// --- M6: wallet snapshot + outpoint classification (spec §18.2, §18.5) ------
//
// Script hash encoding (normative, gateway docs/design/wallet-snapshot.md):
// sha256(scriptPubKey) in natural output byte order, lowercase hex — NOT the
// Electrum reversed-byte convention.

export const scriptHashSchema = hexIdSchema;

export const SNAPSHOT_MAX_SCRIPT_HASHES = 200;
export const SNAPSHOT_MAX_HISTORY = 1_000;
export const CLASSIFY_MAX_OUTPOINTS = 200;

export const outpointSchema = z
  .object({
    txid: hexIdSchema,
    vout: voutSchema,
  })
  .strict();
export type GatewayOutpoint = z.infer<typeof outpointSchema>;

// --- M9P: signed inscription approval previews ------------------------------

export const inscriptionIdSchema = z.string().regex(
  /^[0-9a-f]{64}i(?:0|[1-9][0-9]*)$/u,
  'canonical inscription id',
);
export const satpointSchema = z.string().refine(
  (value) => parseCanonicalSatpoint(value) !== null,
  'canonical satpoint',
);

const inscriptionIdentityFieldsSchema = z
  .object({
    inscriptionId: inscriptionIdSchema,
    satpoint: satpointSchema,
    outpoint: outpointSchema,
    classificationRevision: z.string().min(1),
  })
  .strict();

export const inscriptionIdentitySchema = inscriptionIdentityFieldsSchema.superRefine((identity, ctx) => {
    const [txid, vout] = identity.satpoint.split(':');
    if (txid !== identity.outpoint.txid || Number(vout) !== identity.outpoint.vout) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['satpoint'],
        message: 'satpoint does not identify the bound outpoint',
      });
    }
  });
export type InscriptionIdentity = z.infer<typeof inscriptionIdentitySchema>;

export const inscriptionMetadataSchema = inscriptionIdentityFieldsSchema
  .extend({
    number: z.number().int().nullable(),
    contentType: z.string().min(1).nullable(),
    contentLength: z.number().int().nonnegative().nullable(),
    confirmations: z.number().int().nonnegative(),
    parent: inscriptionIdSchema.nullable(),
    delegate: inscriptionIdSchema.nullable(),
    reinscription: z.boolean(),
    cursed: z.boolean(),
  })
  .strict()
  .superRefine((metadata, ctx) => {
    const [txid, vout] = metadata.satpoint.split(':');
    if (txid !== metadata.outpoint.txid || Number(vout) !== metadata.outpoint.vout) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['satpoint'],
        message: 'satpoint does not identify the bound outpoint',
      });
    }
  });
export type InscriptionMetadata = z.infer<typeof inscriptionMetadataSchema>;

export const inscriptionPreviewReasonSchema = z.enum([
  'active_content',
  'recursive_content',
  'unknown_content',
  'unsupported_content',
  'oversized_content',
  'mime_mismatch',
  'content_length_mismatch',
  'decode_failed',
  'render_pending',
  'unavailable',
  'approval_budget',
]);
export type InscriptionPreviewReason = z.infer<typeof inscriptionPreviewReasonSchema>;

// Dual-accept transition: updated clients parse both the deployed v2 gateway
// and the v3 universal-preview gateway. Everything v3 introduces (svg/html
// screenshot rasters, text excerpts, media badges, render_pending) is guarded
// below so a v2 payload can never smuggle a v3 shape.
export const INSCRIPTION_PREVIEW_POLICY_REVISIONS = ['m9p-preview-v2', 'm9p-preview-v3'] as const;
const supportedImageMimeSchema = z.enum([
  'image/jpeg', 'image/png', 'image/webp', 'image/gif', 'image/avif', 'image/svg+xml', 'text/html',
]);
const detectedImageFormatSchema = z.enum(['jpeg', 'png', 'webp', 'gif', 'avif', 'svg', 'html']);
export const INSCRIPTION_PREVIEW_TEXT_EXCERPT_MAX_BYTES = 1024;
const previewProvenanceFields = {
  requestedInscriptionId: inscriptionIdSchema,
  sourceInscriptionId: inscriptionIdSchema.nullable(),
  resolvedInscriptionId: inscriptionIdSchema.nullable(),
  delegateInscriptionId: inscriptionIdSchema.nullable(),
  sourceContentSha256: hexIdSchema.nullable(),
  declaredMime: z.string().min(1).nullable(),
  declaredContentLength: z.number().int().nonnegative().nullable(),
  detectedMime: supportedImageMimeSchema.nullable(),
  detectedFormat: detectedImageFormatSchema.nullable(),
  sourceContentLength: z.number().int().nonnegative().nullable(),
  policyRevision: z.enum(INSCRIPTION_PREVIEW_POLICY_REVISIONS),
  rendererRevision: z.string().min(1),
} as const;

const inscriptionRasterDescriptorSchema = z.object({
  disposition: z.literal('raster'),
  reason: z.null(),
  ...previewProvenanceFields,
  sourceInscriptionId: inscriptionIdSchema,
  resolvedInscriptionId: inscriptionIdSchema,
  sourceContentSha256: hexIdSchema,
  declaredMime: supportedImageMimeSchema,
  declaredContentLength: z.number().int().nonnegative(),
  detectedMime: supportedImageMimeSchema,
  detectedFormat: detectedImageFormatSchema,
  sourceContentLength: z.number().int().nonnegative(),
  pngSha256: hexIdSchema,
  pngWidth: z.number().int().min(1).max(512),
  pngHeight: z.number().int().min(1).max(512),
  pngByteLength: z.number().int().min(1).max(1024 * 1024),
}).strict();

const inscriptionPlaceholderDescriptorSchema = z.object({
  disposition: z.literal('placeholder'),
  reason: inscriptionPreviewReasonSchema,
  ...previewProvenanceFields,
  pngSha256: z.null(),
  pngWidth: z.null(),
  pngHeight: z.null(),
  pngByteLength: z.null(),
}).strict();

const inscriptionTextExcerptDescriptorSchema = z.object({
  disposition: z.literal('text'),
  reason: z.null(),
  ...previewProvenanceFields,
  sourceInscriptionId: inscriptionIdSchema,
  resolvedInscriptionId: inscriptionIdSchema,
  sourceContentSha256: hexIdSchema,
  declaredMime: z.enum(['text/plain', 'application/json']),
  declaredContentLength: z.number().int().nonnegative(),
  detectedMime: z.null(),
  detectedFormat: z.null(),
  sourceContentLength: z.number().int().nonnegative(),
  excerpt: z.string().min(1),
  excerptByteLength: z.number().int().min(1).max(INSCRIPTION_PREVIEW_TEXT_EXCERPT_MAX_BYTES),
  truncated: z.boolean(),
  pngSha256: z.null(),
  pngWidth: z.null(),
  pngHeight: z.null(),
  pngByteLength: z.null(),
}).strict();

const inscriptionMediaBadgeDescriptorSchema = z.object({
  disposition: z.literal('mediaBadge'),
  reason: z.null(),
  ...previewProvenanceFields,
  sourceInscriptionId: inscriptionIdSchema,
  resolvedInscriptionId: inscriptionIdSchema,
  declaredMime: z.enum(['audio/mpeg', 'audio/ogg', 'audio/wav', 'video/mp4', 'video/webm']),
  declaredContentLength: z.number().int().nonnegative(),
  detectedMime: z.null(),
  detectedFormat: z.null(),
  mediaKind: z.enum(['audio', 'video']),
  pngSha256: z.null(),
  pngWidth: z.null(),
  pngHeight: z.null(),
  pngByteLength: z.null(),
}).strict();

function utf8ByteLength(value: string): number {
  return new TextEncoder().encode(value).byteLength;
}

function addPreviewRevisionIssues(
  descriptor: {
    disposition: string;
    policyRevision: string;
    detectedFormat?: string | null;
    reason?: string | null;
    declaredMime?: string | null;
    mediaKind?: string;
    excerpt?: string;
    excerptByteLength?: number;
  },
  ctx: z.RefinementCtx,
): void {
  const requiresV3 =
    descriptor.disposition === 'text' ||
    descriptor.disposition === 'mediaBadge' ||
    descriptor.reason === 'render_pending' ||
    descriptor.detectedFormat === 'avif' ||
    descriptor.detectedFormat === 'svg' ||
    descriptor.detectedFormat === 'html';
  if (requiresV3 && descriptor.policyRevision !== 'm9p-preview-v3') {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      path: ['policyRevision'],
      message: 'universal preview shapes require policy revision m9p-preview-v3',
    });
  }
  if (descriptor.disposition === 'text' &&
      utf8ByteLength(descriptor.excerpt ?? '') !== descriptor.excerptByteLength) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      path: ['excerptByteLength'],
      message: 'excerpt byte length must match the excerpt',
    });
  }
  if (descriptor.disposition === 'mediaBadge' &&
      descriptor.mediaKind !==
        ((descriptor.declaredMime ?? '').startsWith('audio/') ? 'audio' : 'video')) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      path: ['mediaKind'],
      message: 'media badge kind must match the declared MIME',
    });
  }
}

export const inscriptionPreviewDescriptorSchema = z.discriminatedUnion('disposition', [
  inscriptionRasterDescriptorSchema,
  inscriptionPlaceholderDescriptorSchema,
  inscriptionTextExcerptDescriptorSchema,
  inscriptionMediaBadgeDescriptorSchema,
]).superRefine(addPreviewRevisionIssues);
export type InscriptionPreviewDescriptor = z.infer<typeof inscriptionPreviewDescriptorSchema>;

function decodedBase64Length(value: string): number {
  const padding = value.endsWith('==') ? 2 : value.endsWith('=') ? 1 : 0;
  return (value.length / 4) * 3 - padding;
}

const previewBytesBase64Schema = z.string()
  .max(Math.ceil((1024 * 1024) / 3) * 4)
  .regex(/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/, 'canonical base64')
  .refine((value) => decodedBase64Length(value) <= 1024 * 1024, {
    message: 'decoded preview exceeds byte limit',
  });

export const inscriptionPreviewPayloadSchema = z.discriminatedUnion('disposition', [
  inscriptionRasterDescriptorSchema.extend({ bytesBase64: previewBytesBase64Schema }).strict(),
  inscriptionPlaceholderDescriptorSchema.extend({ bytesBase64: z.null() }).strict(),
  inscriptionTextExcerptDescriptorSchema.extend({ bytesBase64: z.null() }).strict(),
  inscriptionMediaBadgeDescriptorSchema.extend({ bytesBase64: z.null() }).strict(),
]).superRefine(addPreviewRevisionIssues);
export type InscriptionPreviewPayload = z.infer<typeof inscriptionPreviewPayloadSchema>;

export const INSCRIPTION_APPROVAL_MAX_ITEMS = 64;
export const INSCRIPTION_ACTIVITY_MAX_ITEMS = 8;
export const INSCRIPTION_APPROVAL_MAX_RASTERS = 16;
export const INSCRIPTION_PREVIEW_MAX_BYTES = 1024 * 1024;
export const INSCRIPTION_APPROVAL_BATCH_MAX_PREVIEW_BYTES = 8 * 1024 * 1024;
export const INSCRIPTION_APPROVAL_BATCH_MAX_RESPONSE_BYTES = 12 * 1024 * 1024;
export const INSCRIPTION_MEDIA_MAX_BYTES = 2 * 1024 * 1024;
export const INSCRIPTION_TEXT_MAX_BYTES = 256 * 1024;
export const INSCRIPTION_MEDIA_POLICY_REVISIONS = [
  'm11-gallery-media-v2', 'm11-gallery-media-v3',
] as const;
export const INSCRIPTION_MEDIA_POLICY_REVISION = 'm11-gallery-media-v3';

export const inscriptionApprovalBatchRequestSchema = z
  .object({
    network: networkSchema,
    analysisHash: hexIdSchema,
    psbtHash: hexIdSchema,
    transactionCommitmentHash: hexIdSchema,
    effectSetHash: hexIdSchema,
    inscriptions: z.array(inscriptionIdentitySchema).min(1).max(INSCRIPTION_APPROVAL_MAX_ITEMS),
  })
  .strict()
  .superRefine((request, ctx) => {
    const ids = new Set(request.inscriptions.map((identity) => identity.inscriptionId));
    if (ids.size !== request.inscriptions.length) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['inscriptions'], message: 'duplicate inscription id' });
    }
  });
export type InscriptionApprovalBatchRequest = z.infer<typeof inscriptionApprovalBatchRequestSchema>;

export const inscriptionApprovalItemSchema = z
  .object({
    metadata: inscriptionMetadataSchema,
    preview: inscriptionPreviewPayloadSchema,
  })
  .strict();
export type InscriptionApprovalItem = z.infer<typeof inscriptionApprovalItemSchema>;

function normalizedContentType(value: string | null): string | null {
  if (value === null) return null;
  const [essence] = value.split(';', 1);
  return essence?.trim().toLowerCase() || null;
}

function addMetadataPreviewBindingIssues(
  metadata: InscriptionMetadata,
  preview: InscriptionPreviewDescriptor,
  ctx: z.RefinementCtx,
  path: Array<string | number>,
): void {
  const checks: Array<[boolean, string, string]> = [
    [metadata.inscriptionId === preview.requestedInscriptionId, 'requestedInscriptionId', 'preview must bind metadata id'],
    [metadata.inscriptionId === preview.sourceInscriptionId, 'sourceInscriptionId', 'preview source must bind metadata id'],
    [(metadata.delegate ?? metadata.inscriptionId) === preview.resolvedInscriptionId,
      'resolvedInscriptionId', 'preview resolution must bind metadata delegation'],
    [normalizedContentType(metadata.contentType) === preview.declaredMime, 'declaredMime', 'preview MIME must match metadata'],
    [metadata.contentLength === preview.declaredContentLength, 'declaredContentLength', 'preview length must match metadata'],
    [metadata.delegate === preview.delegateInscriptionId, 'delegateInscriptionId', 'preview delegate must match metadata'],
  ];
  for (const [valid, field, message] of checks) {
    if (!valid) ctx.addIssue({ code: z.ZodIssueCode.custom, path: [...path, field], message });
  }
}

export const inscriptionApprovalBatchResponseSchema = signedEnvelopeFieldsSchema
  .extend({
    analysisHash: hexIdSchema,
    psbtHash: hexIdSchema,
    transactionCommitmentHash: hexIdSchema,
    effectSetHash: hexIdSchema,
    items: z.array(inscriptionApprovalItemSchema).min(1).max(INSCRIPTION_APPROVAL_MAX_ITEMS),
  })
  .strict()
  .superRefine((response, ctx) => {
    let totalBytes = 0;
    let rasterCount = 0;
    for (const [index, item] of response.items.entries()) {
      if (item.metadata.classificationRevision !== response.classificationRevision) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['items', index, 'metadata', 'classificationRevision'],
          message: 'item revision must match envelope' });
      }
      addMetadataPreviewBindingIssues(item.metadata, item.preview, ctx, ['items', index, 'preview']);
      if (item.preview.disposition === 'raster') {
        rasterCount += 1;
        const length = decodedBase64Length(item.preview.bytesBase64);
        totalBytes += length;
        if (length !== item.preview.pngByteLength) {
          ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['items', index, 'preview', 'pngByteLength'],
            message: 'PNG byte length must match bytes' });
        }
      }
    }
    if (rasterCount > INSCRIPTION_APPROVAL_MAX_RASTERS) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['items'], message: 'too many raster previews' });
    }
    if (totalBytes > INSCRIPTION_APPROVAL_BATCH_MAX_PREVIEW_BYTES) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['items'], message: 'preview byte budget exceeded' });
    }
  });
export type InscriptionApprovalBatchResponse = z.infer<typeof inscriptionApprovalBatchResponseSchema>;

export const inscriptionGalleryBatchRequestSchema = z.object({
  network: networkSchema,
  inscriptions: z.array(inscriptionIdentitySchema).min(1).max(INSCRIPTION_APPROVAL_MAX_ITEMS),
}).strict().superRefine((request, ctx) => {
  const ids = request.inscriptions.map((identity) => identity.inscriptionId);
  if (new Set(ids).size !== ids.length) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['inscriptions'], message: 'duplicate gallery identity' });
  }
});
export type InscriptionGalleryBatchRequest = z.infer<typeof inscriptionGalleryBatchRequestSchema>;

export const inscriptionGalleryBatchResponseSchema = signedEnvelopeFieldsSchema.extend({
  items: z.array(inscriptionApprovalItemSchema).min(1).max(INSCRIPTION_APPROVAL_MAX_ITEMS),
}).strict().superRefine((response, ctx) => {
  let totalBytes = 0;
  let rasterCount = 0;
  for (const [index, item] of response.items.entries()) {
    if (item.metadata.classificationRevision !== response.classificationRevision) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['items', index, 'metadata', 'classificationRevision'],
        message: 'gallery item revision must match envelope' });
    }
    addMetadataPreviewBindingIssues(item.metadata, item.preview, ctx, ['items', index, 'preview']);
    if (item.preview.disposition === 'raster') {
      rasterCount += 1;
      const length = decodedBase64Length(item.preview.bytesBase64);
      totalBytes += length;
      if (length !== item.preview.pngByteLength) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['items', index, 'preview', 'pngByteLength'],
          message: 'gallery PNG length mismatch' });
      }
    }
  }
  if (rasterCount > INSCRIPTION_APPROVAL_MAX_RASTERS ||
      totalBytes > INSCRIPTION_APPROVAL_BATCH_MAX_PREVIEW_BYTES) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['items'], message: 'gallery preview budget exceeded' });
  }
});
export type InscriptionGalleryBatchResponse = z.infer<typeof inscriptionGalleryBatchResponseSchema>;

function hasUnsafeDisplayText(value: string): boolean {
  return [...value].some((character) => {
    const codePoint = character.codePointAt(0)!;
    return codePoint <= 0x1f ||
      (codePoint >= 0x7f && codePoint <= 0x9f) ||
      (codePoint >= 0x202a && codePoint <= 0x202e) ||
      (codePoint >= 0x2066 && codePoint <= 0x2069);
  });
}

const inscriptionDisplayTitleSchema = z.object({
  text: z.string().min(1).max(256).refine(
    (value) => new TextEncoder().encode(value).byteLength <= 512,
    'title exceeds UTF-8 byte limit',
  ).refine((value) => !hasUnsafeDisplayText(value), 'title contains unsafe display controls'),
  source: z.literal('ord_properties'),
}).strict();

export const inscriptionCollectionSchema = z.object({
  slug: z.string().min(1).max(64).regex(/^[a-z0-9_-]+$/),
  name: z.string().min(1).max(96).refine(
    (value) => new TextEncoder().encode(value).byteLength <= 96,
    'collection name exceeds UTF-8 byte limit',
  ).refine((value) => !hasUnsafeDisplayText(value),
    'collection name contains unsafe display controls'),
  kind: z.enum(['parent', 'gallery']),
  rootInscriptionIds: z.array(inscriptionIdSchema).min(1).max(16),
}).strict();
export type InscriptionCollection = z.infer<typeof inscriptionCollectionSchema>;

export const inscriptionDisplayMetadataSchema = z.object({
  title: inscriptionDisplayTitleSchema.nullable(),
  collections: z.array(inscriptionCollectionSchema).max(16),
}).strict();
export type InscriptionDisplayMetadata = z.infer<typeof inscriptionDisplayMetadataSchema>;

const inscriptionCollectionCatalogSchema = z.object({
  source: z.literal('TheWizardsOfOrd/ordinals-collections'),
  revision: z.string().regex(/^[0-9a-f]{40}$/),
  sha256: hexIdSchema,
  galleryIndexStatus: z.enum(['ready', 'unavailable']),
}).strict();

const inscriptionGalleryEnrichedItemSchema = z.object({
  metadata: inscriptionMetadataSchema,
  preview: inscriptionPreviewPayloadSchema,
  display: inscriptionDisplayMetadataSchema,
}).strict();

export const inscriptionGalleryEnrichedBatchResponseSchema = signedEnvelopeFieldsSchema.extend({
  collectionCatalog: inscriptionCollectionCatalogSchema,
  items: z.array(inscriptionGalleryEnrichedItemSchema).min(1).max(INSCRIPTION_APPROVAL_MAX_ITEMS),
}).strict().superRefine((response, ctx) => {
  let totalBytes = 0;
  let rasterCount = 0;
  for (const [index, item] of response.items.entries()) {
    if (item.metadata.classificationRevision !== response.classificationRevision) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['items', index, 'metadata', 'classificationRevision'],
        message: 'enriched gallery item revision must match envelope' });
    }
    addMetadataPreviewBindingIssues(item.metadata, item.preview, ctx, ['items', index, 'preview']);
    if (item.preview.disposition === 'raster') {
      rasterCount += 1;
      const length = decodedBase64Length(item.preview.bytesBase64);
      totalBytes += length;
      if (length !== item.preview.pngByteLength) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['items', index, 'preview', 'pngByteLength'],
          message: 'enriched gallery PNG length mismatch' });
      }
    }
  }
  if (rasterCount > INSCRIPTION_APPROVAL_MAX_RASTERS ||
      totalBytes > INSCRIPTION_APPROVAL_BATCH_MAX_PREVIEW_BYTES) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['items'],
      message: 'enriched gallery preview budget exceeded' });
  }
});
export type InscriptionGalleryEnrichedBatchResponse =
  z.infer<typeof inscriptionGalleryEnrichedBatchResponseSchema>;

export const inscriptionMediaMimeSchema = z.enum([
  'image/jpeg', 'image/png', 'image/webp', 'image/gif', 'audio/mpeg', 'audio/ogg', 'audio/wav',
  'video/mp4', 'video/webm', 'text/plain', 'application/json',
]);
export type InscriptionMediaMime = z.infer<typeof inscriptionMediaMimeSchema>;

export const inscriptionMediaRequestSchema = z.object({
  network: networkSchema,
  identity: inscriptionIdentitySchema,
}).strict();
export type InscriptionMediaRequest = z.infer<typeof inscriptionMediaRequestSchema>;

const inscriptionMediaBase = {
  requestedInscriptionId: inscriptionIdSchema,
  sourceInscriptionId: inscriptionIdSchema.nullable(),
  resolvedInscriptionId: inscriptionIdSchema.nullable(),
  delegateInscriptionId: inscriptionIdSchema.nullable(),
  declaredMime: z.string().min(1).nullable(),
  declaredContentLength: z.number().int().nonnegative().nullable(),
  policyRevision: z.enum(INSCRIPTION_MEDIA_POLICY_REVISIONS),
} as const;

const inscriptionMediaBytesBase64 = z.string()
  .max(Math.ceil(INSCRIPTION_MEDIA_MAX_BYTES / 3) * 4)
  .regex(/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/, 'canonical base64')
  .refine((value) => decodedBase64Length(value) <= INSCRIPTION_MEDIA_MAX_BYTES, {
    message: 'decoded media exceeds limit',
  });

export const inscriptionMediaPayloadSchema = z.union([
  z.object({
    disposition: z.literal('media'), reason: z.null(), ...inscriptionMediaBase,
    sourceInscriptionId: inscriptionIdSchema, resolvedInscriptionId: inscriptionIdSchema,
    declaredMime: inscriptionMediaMimeSchema,
    declaredContentLength: z.number().int().positive().max(INSCRIPTION_MEDIA_MAX_BYTES),
    detectedMime: inscriptionMediaMimeSchema,
    contentSha256: hexIdSchema,
    contentByteLength: z.number().int().positive().max(INSCRIPTION_MEDIA_MAX_BYTES),
    bytesBase64: inscriptionMediaBytesBase64,
  }).strict().superRefine((media, ctx) => {
    if (media.declaredMime !== media.detectedMime ||
        media.declaredContentLength !== media.contentByteLength ||
        decodedBase64Length(media.bytesBase64) !== media.contentByteLength) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['detectedMime'], message: 'media binding mismatch' });
    }
    if ((media.detectedMime === 'text/plain' || media.detectedMime === 'application/json') &&
        media.contentByteLength > INSCRIPTION_TEXT_MAX_BYTES) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['contentByteLength'], message: 'text exceeds limit' });
    }
    if (media.detectedMime === 'application/json' &&
        media.policyRevision !== 'm11-gallery-media-v3') {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['policyRevision'], message: 'JSON media requires policy revision m11-gallery-media-v3' });
    }
  }),
  z.object({
    disposition: z.literal('unavailable'), reason: inscriptionPreviewReasonSchema,
    ...inscriptionMediaBase, detectedMime: z.null(), contentSha256: z.null(),
    contentByteLength: z.null(), bytesBase64: z.null(),
  }).strict(),
]);
export type InscriptionMediaPayload = z.infer<typeof inscriptionMediaPayloadSchema>;

export const inscriptionMediaResponseSchema = signedEnvelopeFieldsSchema.extend({
  identity: inscriptionIdentitySchema,
  media: inscriptionMediaPayloadSchema,
}).strict().superRefine((response, ctx) => {
  if (response.identity.classificationRevision !== response.classificationRevision ||
      response.identity.inscriptionId !== response.media.requestedInscriptionId) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['identity'], message: 'media identity mismatch' });
  }
  const expectedResolved = response.media.delegateInscriptionId ??
    (response.media.sourceInscriptionId === null ? null : response.identity.inscriptionId);
  if ((response.media.sourceInscriptionId !== null &&
       response.media.sourceInscriptionId !== response.identity.inscriptionId) ||
      response.media.resolvedInscriptionId !== expectedResolved) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['media'], message: 'media provenance mismatch' });
  }
});
export type InscriptionMediaResponse = z.infer<typeof inscriptionMediaResponseSchema>;

export const inscriptionMetadataResponseSchema = signedEnvelopeFieldsSchema
  .extend({
    metadata: inscriptionMetadataSchema,
    preview: inscriptionPreviewDescriptorSchema,
  })
  .strict()
  .superRefine((response, ctx) => {
    if (response.metadata.classificationRevision !== response.classificationRevision) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['metadata', 'classificationRevision'],
        message: 'metadata revision must match envelope' });
    }
    addMetadataPreviewBindingIssues(response.metadata, response.preview, ctx, ['preview']);
  });
export type InscriptionMetadataResponse = z.infer<typeof inscriptionMetadataResponseSchema>;

export const inscriptionPreviewResponseSchema = signedEnvelopeFieldsSchema
  .extend({
    identity: inscriptionIdentitySchema,
    preview: inscriptionPreviewPayloadSchema,
  })
  .strict()
  .superRefine((response, ctx) => {
    if (response.identity.classificationRevision !== response.classificationRevision) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['identity', 'classificationRevision'],
        message: 'identity revision must match envelope' });
    }
    if (response.identity.inscriptionId !== response.preview.requestedInscriptionId) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['preview', 'requestedInscriptionId'],
        message: 'preview must bind requested id' });
    }
    if (response.preview.disposition === 'raster' &&
        decodedBase64Length(response.preview.bytesBase64) !== response.preview.pngByteLength) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['preview', 'pngByteLength'],
        message: 'PNG byte length must match bytes' });
    }
  });
export type InscriptionPreviewResponse = z.infer<typeof inscriptionPreviewResponseSchema>;

export const inscriptionActivityBatchRequestSchema = z.object({
  network: networkSchema,
  inscriptionIds: z.array(inscriptionIdSchema).min(1).max(INSCRIPTION_ACTIVITY_MAX_ITEMS),
}).strict().superRefine((request, ctx) => {
  if (new Set(request.inscriptionIds).size !== request.inscriptionIds.length) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      path: ['inscriptionIds'],
      message: 'activity inscription ids must be unique',
    });
  }
});
export type InscriptionActivityBatchRequest =
  z.infer<typeof inscriptionActivityBatchRequestSchema>;

export const inscriptionActivityBatchResponseSchema = signedEnvelopeFieldsSchema.extend({
  items: z.array(inscriptionApprovalItemSchema).min(1).max(INSCRIPTION_ACTIVITY_MAX_ITEMS),
}).strict().superRefine((response, ctx) => {
  let totalBytes = 0;
  for (const [index, item] of response.items.entries()) {
    if (item.metadata.classificationRevision !== response.classificationRevision) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['items', index, 'metadata', 'classificationRevision'],
        message: 'activity item revision must match envelope',
      });
    }
    addMetadataPreviewBindingIssues(item.metadata, item.preview, ctx, ['items', index, 'preview']);
    if (item.preview.disposition === 'raster') {
      const length = decodedBase64Length(item.preview.bytesBase64);
      totalBytes += length;
      if (length !== item.preview.pngByteLength) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['items', index, 'preview', 'pngByteLength'],
          message: 'activity PNG length mismatch',
        });
      }
    }
  }
  if (totalBytes > INSCRIPTION_APPROVAL_BATCH_MAX_PREVIEW_BYTES) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      path: ['items'],
      message: 'activity preview budget exceeded',
    });
  }
});
export type InscriptionActivityBatchResponse =
  z.infer<typeof inscriptionActivityBatchResponseSchema>;

export const walletSnapshotRequestSchema = z
  .object({
    network: networkSchema,
    scriptHashes: z.array(scriptHashSchema).min(1).max(SNAPSHOT_MAX_SCRIPT_HASHES),
    includeOrdinalFlow: z.boolean().optional(),
  })
  .strict();
export type WalletSnapshotRequest = z.infer<typeof walletSnapshotRequestSchema>;

export const snapshotUtxoSchema = z
  .object({
    txid: hexIdSchema,
    vout: voutSchema,
    valueSats: z.string().regex(/^(0|[1-9][0-9]*)$/, 'decimal-string sats'),
    scriptHash: scriptHashSchema,
    scriptPubKey: z.string().regex(/^[0-9a-f]+$/),
    height: z.number().int().nonnegative().nullable(),
    // §18.2 wallet-created-change signal, requested-set-relative (see the
    // contract doc); the client additionally requires an internal-chain
    // address with a burned change index.
    fundingSpendsOnlyRequested: z.boolean(),
  })
  .strict();
export type SnapshotUtxo = z.infer<typeof snapshotUtxoSchema>;

export const SNAPSHOT_MAX_ORDINAL_FLOW_EDGES_PER_TX = 256;
export const SNAPSHOT_MAX_ORDINAL_FLOW_EDGES = 2_048;

export const ordinalFlowPointSchema = z
  .object({
    txid: hexIdSchema,
    vout: voutSchema,
    offsetSats: z.string().regex(/^(0|[1-9][0-9]*)$/, 'decimal-string sats'),
  })
  .strict();
export type OrdinalFlowPoint = z.infer<typeof ordinalFlowPointSchema>;

export const ordinalFlowEdgeSchema = z
  .object({
    source: ordinalFlowPointSchema,
    destination: ordinalFlowPointSchema.nullable(),
    lengthSats: z.string().regex(/^[1-9][0-9]*$/, 'positive decimal-string sats'),
    sourceRequested: z.boolean(),
    destinationRequested: z.boolean(),
  })
  .strict()
  .superRefine((edge, ctx) => {
    if (!edge.sourceRequested && !edge.destinationRequested) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: 'flow edge must touch a requested script' });
    }
    if (edge.destination === null && edge.destinationRequested) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['destinationRequested'],
        message: 'fee flow cannot fund a requested script',
      });
    }
  });
export type OrdinalFlowEdge = z.infer<typeof ordinalFlowEdgeSchema>;

export const ordinalFlowEvidenceSchema = z.discriminatedUnion('kind', [
  z.object({
    kind: z.literal('complete'),
    edges: z.array(ordinalFlowEdgeSchema).max(SNAPSHOT_MAX_ORDINAL_FLOW_EDGES_PER_TX),
  }).strict(),
  z.object({
    kind: z.literal('unavailable'),
    reason: z.enum(['transaction_limit', 'response_budget']),
  }).strict(),
]).superRefine((evidence, ctx) => {
  if (evidence.kind !== 'complete') return;
  for (const field of ['source', 'destination'] as const) {
    const ranges = new Map<string, Array<{ start: bigint; end: bigint; index: number }>>();
    evidence.edges.forEach((edge, index) => {
      const point = edge[field];
      if (point === null) return;
      const key = `${point.txid}:${point.vout}`;
      const items = ranges.get(key) ?? [];
      const start = BigInt(point.offsetSats);
      items.push({ start, end: start + BigInt(edge.lengthSats), index });
      ranges.set(key, items);
    });
    for (const items of ranges.values()) {
      items.sort((a, b) => a.start < b.start ? -1 : a.start > b.start ? 1 : 0);
      for (let index = 1; index < items.length; index += 1) {
        if (items[index]!.start < items[index - 1]!.end) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            path: ['edges', items[index]!.index, field],
            message: `flow ${field} ranges must not overlap`,
          });
        }
      }
    }
  }
});
export type OrdinalFlowEvidence = z.infer<typeof ordinalFlowEvidenceSchema>;

export const activitySourceSummarySchema = z
  .object({
    inputCount: z.number().int().nonnegative().max(100_000),
    singleInputAddress: z.string().min(1).max(128).nullable(),
  })
  .strict()
  .superRefine((summary, ctx) => {
    if (summary.inputCount !== 1 && summary.singleInputAddress !== null) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['singleInputAddress'],
        message: 'only a single-input transaction can name one source address',
      });
    }
  });
export type ActivitySourceSummary = z.infer<typeof activitySourceSummarySchema>;

export const snapshotHistoryEntrySchema = z
  .object({
    txid: hexIdSchema,
    height: z.number().int().nonnegative().nullable(),
    timestamp: z.string().datetime().nullable(),
    fundedScriptHashes: z.array(scriptHashSchema),
    spentScriptHashes: z.array(scriptHashSchema),
    deltaSats: z.string().regex(/^(0|-?[1-9][0-9]*)$/, 'signed decimal-string sats'),
    replacesTxid: hexIdSchema.nullable(),
    replacedByTxid: hexIdSchema.nullable(),
    confirmationState: z.enum(['confirmed', 'mempool', 'replaced', 'conflicted']),
    feeSats: z.string().regex(/^(0|[1-9][0-9]*)$/).nullable(),
    vsize: z.number().int().positive().nullable(),
    replaceable: z.boolean().nullable(),
    packageFeeSats: z.string().regex(/^(0|[1-9][0-9]*)$/).nullable(),
    packageVsize: z.number().int().positive().nullable(),
    cpfpEligible: z.boolean(),
    activitySource: activitySourceSummarySchema.optional(),
    ordinalFlow: ordinalFlowEvidenceSchema.optional(),
  })
  .strict();
export type SnapshotHistoryEntry = z.infer<typeof snapshotHistoryEntrySchema>;

// Envelope-signed. The classification reference is the envelope's
// classificationRevision; full records come from /v1/outpoints/classify and
// the client requires revision equality across the snapshot/classify pair.
export const walletSnapshotResponseSchema = signedEnvelopeFieldsSchema
  .extend({
    requestedScriptHashes: z.array(scriptHashSchema),
    utxos: z.array(snapshotUtxoSchema),
    history: z.array(snapshotHistoryEntrySchema),
  })
  .strict()
  .superRefine((response, ctx) => {
    const edgeCount = response.history.reduce((total, entry) =>
      total + (entry.ordinalFlow?.kind === 'complete' ? entry.ordinalFlow.edges.length : 0), 0);
    if (edgeCount > SNAPSHOT_MAX_ORDINAL_FLOW_EDGES) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['history'],
        message: 'snapshot ordinal flow exceeds response edge budget',
      });
    }
  });
export type WalletSnapshotResponse = z.infer<typeof walletSnapshotResponseSchema>;

/**
 * Coverage for the bounded account-scan route. `partial` is positive metadata:
 * UTXOs are still complete and independently verified, while some transaction
 * history could not be returned within the reviewed response/backend bounds.
 */
export const historyCoverageSchema = z
  .object({
    status: z.enum(['complete', 'partial']),
    limitedScriptHashes: z.array(scriptHashSchema),
  })
  .strict()
  .superRefine((coverage, ctx) => {
    if (new Set(coverage.limitedScriptHashes).size !== coverage.limitedScriptHashes.length) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['limitedScriptHashes'],
        message: 'limited script hashes must be unique',
      });
    }
    if (coverage.status === 'complete' && coverage.limitedScriptHashes.length > 0) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['status'],
        message: 'complete history cannot contain limited scripts',
      });
    }
  });
export type HistoryCoverage = z.infer<typeof historyCoverageSchema>;

export const walletScanSnapshotResponseSchema = signedEnvelopeFieldsSchema
  .extend({
    requestedScriptHashes: z.array(scriptHashSchema),
    utxos: z.array(snapshotUtxoSchema),
    history: z.array(snapshotHistoryEntrySchema).max(SNAPSHOT_MAX_HISTORY),
    activeScriptHashes: z.array(scriptHashSchema),
    historyCoverage: historyCoverageSchema,
  })
  .strict()
  .superRefine((response, ctx) => {
    const requested = new Set(response.requestedScriptHashes);
    const active = new Set(response.activeScriptHashes);
    if (requested.size !== response.requestedScriptHashes.length) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['requestedScriptHashes'],
        message: 'requested script hashes must be unique',
      });
    }
    if (active.size !== response.activeScriptHashes.length) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['activeScriptHashes'],
        message: 'active script hashes must be unique',
      });
    }
    for (const [index, hash] of response.activeScriptHashes.entries()) {
      if (!requested.has(hash)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['activeScriptHashes', index],
          message: 'active script hash was not requested',
        });
      }
    }
    for (const [index, hash] of response.historyCoverage.limitedScriptHashes.entries()) {
      if (!requested.has(hash)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['historyCoverage', 'limitedScriptHashes', index],
          message: 'limited script hash was not requested',
        });
      }
      if (!active.has(hash)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['historyCoverage', 'limitedScriptHashes', index],
          message: 'a history-limited script must be active',
        });
      }
    }
    const responseHashes: Array<{ path: (string | number)[]; hash: string }> = [];
    response.utxos.forEach((utxo, index) => {
      responseHashes.push({ path: ['utxos', index, 'scriptHash'], hash: utxo.scriptHash });
    });
    response.history.forEach((entry, index) => {
      entry.fundedScriptHashes.forEach((hash, hashIndex) => {
        responseHashes.push({
          path: ['history', index, 'fundedScriptHashes', hashIndex],
          hash,
        });
      });
      entry.spentScriptHashes.forEach((hash, hashIndex) => {
        responseHashes.push({
          path: ['history', index, 'spentScriptHashes', hashIndex],
          hash,
        });
      });
    });
    for (const { path, hash } of responseHashes) {
      if (!requested.has(hash)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path,
          message: 'response script hash was not requested',
        });
      }
      if (!active.has(hash)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path,
          message: 'response activity must be represented by an active script hash',
        });
      }
    }
    const outpoints = response.utxos.map((utxo) => `${utxo.txid}:${utxo.vout}`);
    if (new Set(outpoints).size !== outpoints.length) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['utxos'],
        message: 'UTXO outpoints must be unique',
      });
    }
    const historyTxids = response.history.map((entry) => entry.txid);
    if (new Set(historyTxids).size !== historyTxids.length) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['history'],
        message: 'history transaction ids must be unique',
      });
    }
    const edgeCount = response.history.reduce((total, entry) =>
      total + (entry.ordinalFlow?.kind === 'complete' ? entry.ordinalFlow.edges.length : 0), 0);
    if (edgeCount > SNAPSHOT_MAX_ORDINAL_FLOW_EDGES) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['history'],
        message: 'bounded scan ordinal flow exceeds response edge budget',
      });
    }
  });
export type WalletScanSnapshotResponse = z.infer<typeof walletScanSnapshotResponseSchema>;

export const walletActivitySnapshotResponseSchema = walletSnapshotResponseSchema
  .superRefine((response, ctx) => {
    response.history.forEach((entry, index) => {
      if (entry.activitySource === undefined) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['history', index, 'activitySource'],
          message: 'activity snapshot source summary is required',
        });
      }
    });
  });

export const primaryClassSchema = z.enum([
  'cardinal_clean',
  'inscribed',
  'rare_sat',
  'runic_or_unsupported',
  'mixed',
  'unknown',
]);
export type PrimaryClass = z.infer<typeof primaryClassSchema>;

export const satRangeSchema = z
  .object({
    start: z.string().regex(/^(0|[1-9][0-9]*)$/),
    end: z.string().regex(/^(0|[1-9][0-9]*)$/),
    rarity: z.enum(['common', 'uncommon', 'rare', 'epic', 'legendary', 'mythic']).optional(),
  })
  .strict();
export type SatRange = z.infer<typeof satRangeSchema>;

export const inscriptionRefSchema = z
  .object({
    inscriptionId: z.string().min(1),
    number: z.number().int().optional(),
    satpoint: z.string().min(1),
  })
  .strict();
export type InscriptionRef = z.infer<typeof inscriptionRefSchema>;

export const DETECTED_ASSET_DISPLAY_LIMIT = 16;
const U128_MAX = (1n << 128n) - 1n;
export const detectedAssetSchema = z.object({
  protocol: z.literal('rune'),
  name: z.string().regex(/^[A-Z]+(?:•[A-Z]+)*$/u).max(64),
  amountAtoms: z.string().regex(/^(0|[1-9][0-9]*)$/u)
    .refine((amount) => BigInt(amount) <= U128_MAX, 'Rune amount exceeds u128'),
  divisibility: z.number().int().min(0).max(38),
  symbol: z.string().regex(/^.$/u).nullable(),
}).strict();
export type DetectedAsset = z.infer<typeof detectedAssetSchema>;

export function formatDetectedAssetAmount(asset: DetectedAsset): string {
  const amount = asset.amountAtoms.padStart(asset.divisibility + 1, '0');
  if (asset.divisibility === 0) return amount;
  const split = amount.length - asset.divisibility;
  const whole = amount.slice(0, split);
  const fractional = amount.slice(split).replace(/0+$/u, '');
  return fractional === '' ? whole : `${whole}.${fractional}`;
}

interface ClassificationFacts {
  primaryClass: PrimaryClass;
  inscriptions: readonly InscriptionRef[];
  satRanges: readonly SatRange[] | null;
  unsupportedAssetDetected: boolean;
  confidence: 'authoritative' | 'degraded';
}

export function isAuthoritativeCardinalClean(
  facts: ClassificationFacts | null | undefined,
): boolean {
  return facts?.primaryClass === 'cardinal_clean'
    && facts.confidence === 'authoritative'
    && facts.inscriptions.length === 0
    && !facts.unsupportedAssetDetected
    && facts.satRanges?.some(
      (range) => range.rarity !== undefined && range.rarity !== 'common',
    ) !== true;
}

export const utxoClassificationSchema = z
  .object({
    txid: hexIdSchema,
    vout: voutSchema,
    valueSats: z.string().regex(/^(0|[1-9][0-9]*)$/),
    scriptPubKey: z.string().regex(/^[0-9a-f]*$/),
    confirmations: z.number().int().nonnegative(),
    primaryClass: primaryClassSchema,
    inscriptions: z.array(inscriptionRefSchema),
    satRanges: z.array(satRangeSchema).nullable(),
    unsupportedAssetDetected: z.boolean(),
    detectedAssets: z.array(detectedAssetSchema).max(DETECTED_ASSET_DISPLAY_LIMIT).optional(),
    detectedAssetCount: z.number().int().nonnegative().optional(),
    assetIdentityComplete: z.boolean().optional(),
    confidence: z.enum(['authoritative', 'degraded']),
    classifiedTip: tipSchema,
    classificationRevision: z.string().min(1),
  })
  .strict()
  .superRefine((classification, ctx) => {
    if ((classification.detectedAssets?.length ?? 0) > (classification.detectedAssetCount ?? 0)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['detectedAssetCount'],
        message: 'detected asset count is smaller than the displayed identity set',
      });
    }
    if ((classification.detectedAssets?.length ?? 0) > 0 && !classification.unsupportedAssetDetected) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['detectedAssets'],
        message: 'detected asset identities require the unsupported-asset safety flag',
      });
    }
    if (
      classification.primaryClass === 'cardinal_clean'
      && !isAuthoritativeCardinalClean(classification)
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['primaryClass'],
        message: 'cardinal_clean classification contradicts protected asset facts',
      });
    }
  });
export type UtxoClassification = z.infer<typeof utxoClassificationSchema>;

export const outpointsClassifyRequestSchema = z
  .object({
    network: networkSchema,
    outpoints: z.array(outpointSchema).min(1).max(CLASSIFY_MAX_OUTPOINTS),
  })
  .strict().superRefine((request, ctx) => {
    const keys = request.outpoints.map(({ txid, vout }) => `${txid}:${vout}`);
    if (new Set(keys).size !== keys.length) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['outpoints'], message: 'duplicate outpoint' });
  });
export type OutpointsClassifyRequest = z.infer<typeof outpointsClassifyRequestSchema>;

export const outpointsClassifyResponseSchema = signedEnvelopeFieldsSchema
  .extend({
    classifications: z.array(utxoClassificationSchema),
    unknownOutpoints: z.array(outpointSchema),
  })
  .strict().superRefine((response, ctx) => {
    const classified = response.classifications.map(({ txid, vout }) => `${txid}:${vout}`);
    const unknown = response.unknownOutpoints.map(({ txid, vout }) => `${txid}:${vout}`);
    if (new Set([...classified, ...unknown]).size !== classified.length + unknown.length) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['unknownOutpoints'], message: 'classification partition overlaps or duplicates' });
    }
  });
export type OutpointsClassifyResponse = z.infer<typeof outpointsClassifyResponseSchema>;

// --- M7: fees and broadcast -------------------------------------------------

export const feeTargetSchema = z.union([z.literal(2), z.literal(6), z.literal(12)]);
export type FeeTarget = z.infer<typeof feeTargetSchema>;
const feeTierSchema = z.object({
  target: feeTargetSchema,
  returnedTarget: z.number().int().positive(),
  mode: z.literal('economical'),
  rawSatPerKvB: z.number().int().positive().safe(),
  effectiveSatPerKvB: z.number().int().positive().safe(),
}).strict();

export const feeQuoteResponseSchema = signedEnvelopeFieldsSchema.extend({
  protocolVersion: z.literal(2),
  quoteId: hexIdSchema,
  source: z.literal('bitcoin_core_31_1'),
  sampledAt: z.string().datetime(),
  expiresAt: z.string().datetime(),
  ageSeconds: z.number().int().nonnegative(),
  tip: tipSchema,
  floorSatPerKvB: z.number().int().positive().safe(),
  incrementalRelaySatPerKvB: z.number().int().positive().safe(),
  tiers: z.tuple([feeTierSchema, feeTierSchema, feeTierSchema]),
}).strict().superRefine((quote, ctx) => {
  if (quote.tip.height !== quote.coreTip.height || quote.tip.hash !== quote.coreTip.hash) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['tip'], message: 'fee tip mismatch' });
  }
  if (quote.tiers.map((tier) => tier.target).join(',') !== '2,6,12') {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['tiers'], message: 'unexpected fee targets' });
  }
  quote.tiers.forEach((tier, index) => {
    if (tier.effectiveSatPerKvB < quote.floorSatPerKvB ||
        (quote.tiers[index + 1] && tier.effectiveSatPerKvB < quote.tiers[index + 1]!.effectiveSatPerKvB)) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['tiers', index], message: 'unsafe effective fee tier' });
    }
  });
});
export type FeeQuoteResponse = z.infer<typeof feeQuoteResponseSchema>;

const quotedBroadcastRequestSchema = z
  .object({
    network: networkSchema,
    transactionHex: z.string().regex(/^(?:[0-9a-f]{2})+$/),
    txid: hexIdSchema,
    wtxid: hexIdSchema,
    feeTarget: feeTargetSchema,
    feeQuote: feeQuoteResponseSchema,
  })
  .strict();

const customFeeBroadcastRequestSchema = z
  .object({
    network: networkSchema,
    transactionHex: z.string().regex(/^(?:[0-9a-f]{2})+$/),
    txid: hexIdSchema,
    wtxid: hexIdSchema,
    customFeeRateSatPerKvB: z.number().int().positive().safe().max(10_000_000),
    status: statusCapabilitiesV2Schema,
  })
  .strict();

export const broadcastRequestSchema = z.union([
  quotedBroadcastRequestSchema,
  customFeeBroadcastRequestSchema,
]);
export type BroadcastRequest = z.infer<typeof broadcastRequestSchema>;

export const broadcastResultSchema = signedEnvelopeFieldsSchema
  .extend({
    submittedTxid: hexIdSchema,
    submittedWtxid: hexIdSchema,
    status: z.enum(['accepted', 'already_known', 'confirmed', 'conflicted', 'rejected', 'indeterminate']),
    txid: hexIdSchema.nullable(),
    errorCode: z.string().nullable(),
    detail: z.string().nullable(),
  })
  .strict();
export type BroadcastResult = z.infer<typeof broadcastResultSchema>;
