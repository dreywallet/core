import { beforeAll, describe, expect, it } from 'vitest';
import { GatewayClient } from '../../src/gateway-client';
import type {
  InscriptionApprovalBatchRequest,
  InscriptionApprovalBatchResponse,
  InscriptionActivityBatchRequest,
  InscriptionGalleryBatchRequest,
  InscriptionMediaRequest,
} from '../../src/domain/gateway/contract';
import {
  inscriptionPreviewDescriptorSchema,
  inscriptionPreviewPayloadSchema,
  satpointSchema,
} from '../../src/domain/gateway/contract';
import { bytesToBase64, bytesToHex } from '../../src/domain/vault/encoding';
import { installTestCryptoProvider } from '../helpers/install-crypto-provider';
import { getSodium } from '../helpers/sodium';
import {
  assertPreviewAcknowledged,
  bindInscriptionPreviews,
} from '../../src/domain/transactions/inscription-previews';
import { makeTestKeypair, signTestBody } from './sign-helper';

const nonce = '00112233445566778899aabbccddeeff';
const now = Date.parse('2026-07-22T12:00:00.000Z');
const id = `${'ab'.repeat(32)}i0`;
const txid = 'cd'.repeat(32);
const revision = 'rev-m9p-1';
const png = Uint8Array.from(Buffer.from(
  'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=',
  'base64',
));

beforeAll(() => installTestCryptoProvider());

function request(): InscriptionApprovalBatchRequest {
  return {
    network: 'signet',
    analysisHash: '01'.repeat(32),
    psbtHash: '02'.repeat(32),
    transactionCommitmentHash: '03'.repeat(32),
    effectSetHash: '04'.repeat(32),
    inscriptions: [{
      inscriptionId: id,
      satpoint: `${txid}:0:0`,
      outpoint: { txid, vout: 0 },
      classificationRevision: revision,
    }],
  };
}

function responseBody(req: InscriptionApprovalBatchRequest): Omit<InscriptionApprovalBatchResponse, 'signature'> & {
  signature: string;
} {
  const digest = bytesToHex(getSodium().crypto_hash_sha256(png));
  return {
    instanceId: 'fixture-m9p', network: 'signet', protocolVersion: 1, requestNonce: nonce,
    timestamp: new Date(now).toISOString(),
    coreTip: { height: 100, hash: '10'.repeat(32) },
    indexTip: { height: 100, hash: '10'.repeat(32) },
    classificationRevision: revision,
    capabilities: ['inscription_index', 'preview_service'],
    signature: '',
    analysisHash: req.analysisHash,
    psbtHash: req.psbtHash,
    transactionCommitmentHash: req.transactionCommitmentHash,
    effectSetHash: req.effectSetHash,
    items: [{
      metadata: {
        ...req.inscriptions[0]!, number: 7, contentType: 'image/png', contentLength: png.length,
        confirmations: 3, parent: null, delegate: null, reinscription: false, cursed: false,
      },
      preview: {
        disposition: 'raster', reason: null, requestedInscriptionId: id,
        sourceInscriptionId: id, resolvedInscriptionId: id, delegateInscriptionId: null,
        sourceContentSha256: digest, declaredMime: 'image/png', declaredContentLength: png.length,
        detectedMime: 'image/png', detectedFormat: 'png', sourceContentLength: png.length,
        policyRevision: 'm9p-preview-v2', rendererRevision: 'fixture-renderer-v1',
        pngSha256: digest, pngWidth: 1, pngHeight: 1, pngByteLength: png.length,
        bytesBase64: bytesToBase64(png),
      },
    }],
  };
}

function clientFor(body: Record<string, unknown>) {
  const keypair = makeTestKeypair();
  const bytes = signTestBody(body, keypair);
  return new GatewayClient({
    fetchFn: async () => new Response(bytes.slice().buffer, { status: 200 }),
    baseUrl: 'http://127.0.0.1:8080', publicKeyHex: keypair.publicKeyHex,
    expectedNetwork: 'signet', randomNonce: () => nonce, now: () => now,
  });
}

describe('M9P signed inscription approval batches', () => {
  it('rejects satpoint offsets outside Ord unsigned 64-bit range', () => {
    expect(satpointSchema.safeParse(`${txid}:0:18446744073709551615`).success).toBe(true);
    expect(satpointSchema.safeParse(`${txid}:0:18446744073709551616`).success).toBe(false);
  });

  it('accepts only the exact ordered binding and independently hashes inert PNG bytes', async () => {
    const req = request();
    const result = await clientFor(responseBody(req) as unknown as Record<string, unknown>)
      .fetchInscriptionApprovalBatch(req);
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.value.items[0]?.preview.disposition).toBe('raster');
  });

  it('accepts an AVIF source descriptor while independently verifying inert PNG bytes', async () => {
    const req = request();
    const body = responseBody(req);
    body.items[0]!.metadata.contentType = 'image/avif';
    const preview = body.items[0]!.preview;
    if (preview.disposition !== 'raster') throw new Error('raster fixture expected');
    body.items[0]!.preview = {
      ...preview,
      declaredMime: 'image/avif',
      detectedMime: 'image/avif',
      detectedFormat: 'avif',
      policyRevision: 'm9p-preview-v3',
    };
    const result = await clientFor(body as unknown as Record<string, unknown>)
      .fetchInscriptionApprovalBatch(req);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.items[0]?.preview).toMatchObject({
        disposition: 'raster',
        declaredMime: 'image/avif',
        detectedMime: 'image/avif',
        detectedFormat: 'avif',
      });
    }
    if (body.items[0]!.preview.disposition !== 'raster') throw new Error('raster fixture expected');
    body.items[0]!.preview.policyRevision = 'm9p-preview-v2';
    await expect(clientFor(body as unknown as Record<string, unknown>)
      .fetchInscriptionApprovalBatch(req)).resolves.toMatchObject({
      ok: false,
      reason: 'schema',
    });
  });

  it('rejects cache substitution even when the hostile response is freshly signed', async () => {
    const req = request();
    const body = responseBody(req);
    const original = body.items[0]!.preview;
    if (original.disposition !== 'raster') throw new Error('raster fixture expected');
    body.items[0]!.preview = {
      ...original,
      bytesBase64: bytesToBase64(Uint8Array.from([...png.slice(0, -1), 0x00])),
    };
    await expect(clientFor(body as unknown as Record<string, unknown>).fetchInscriptionApprovalBatch(req))
      .resolves.toEqual({ ok: false, reason: 'schema' });
  });

  it('rejects truncated PNG structure and descriptor/IHDR dimension mismatches', async () => {
    const req = request();
    const truncatedBody = responseBody(req);
    const truncated = png.slice(0, -12);
    const truncatedPreview = truncatedBody.items[0]!.preview;
    if (truncatedPreview.disposition !== 'raster') throw new Error('raster fixture expected');
    truncatedBody.items[0]!.preview = {
      ...truncatedPreview,
      bytesBase64: bytesToBase64(truncated),
      pngByteLength: truncated.length,
      pngSha256: bytesToHex(getSodium().crypto_hash_sha256(truncated)),
    };
    await expect(clientFor(truncatedBody as unknown as Record<string, unknown>)
      .fetchInscriptionApprovalBatch(req)).resolves.toEqual({ ok: false, reason: 'schema' });

    const wrongDimensions = responseBody(req);
    const wrongPreview = wrongDimensions.items[0]!.preview;
    if (wrongPreview.disposition !== 'raster') throw new Error('raster fixture expected');
    wrongDimensions.items[0]!.preview = { ...wrongPreview, pngWidth: 2 };
    await expect(clientFor(wrongDimensions as unknown as Record<string, unknown>)
      .fetchInscriptionApprovalBatch(req)).resolves.toEqual({ ok: false, reason: 'schema' });
  });

  it('rejects stale revisions, substituted IDs, and transaction commitment mismatches', async () => {
    const req = request();
    for (const mutate of [
      (body: ReturnType<typeof responseBody>) => { body.classificationRevision = 'stale'; },
      (body: ReturnType<typeof responseBody>) => { body.items[0]!.metadata.inscriptionId = `${'ef'.repeat(32)}i0`; },
      (body: ReturnType<typeof responseBody>) => { body.transactionCommitmentHash = 'ff'.repeat(32); },
    ]) {
      const body = responseBody(req);
      mutate(body);
      const result = await clientFor(body as unknown as Record<string, unknown>)
        .fetchInscriptionApprovalBatch(req);
      expect(result).toEqual({ ok: false, reason: 'schema' });
    }
  });

  it('rejects missing, extra, duplicate, and unrelated provenance records', async () => {
    const req = request();
    const missing = responseBody(req);
    missing.items = [];
    const extra = responseBody(req);
    extra.items.push(structuredClone(extra.items[0]!));
    const unrelated = responseBody(req);
    unrelated.items[0]!.preview.sourceInscriptionId = `${'ef'.repeat(32)}i0`;
    for (const body of [missing, extra, unrelated]) {
      const result = await clientFor(body as unknown as Record<string, unknown>)
        .fetchInscriptionApprovalBatch(req);
      expect(result).toEqual({ ok: false, reason: 'schema' });
    }
  });

  it('accepts a signed identifiers-only placeholder but never invents raster bytes', async () => {
    const req = request();
    const body = responseBody(req);
    body.items[0]!.metadata.contentType = 'text/html';
    body.items[0]!.preview = {
      disposition: 'placeholder', reason: 'active_content', requestedInscriptionId: id,
      sourceInscriptionId: id, resolvedInscriptionId: id, delegateInscriptionId: null,
      sourceContentSha256: '33'.repeat(32), declaredMime: 'text/html',
      declaredContentLength: png.length, detectedMime: null, detectedFormat: null,
      sourceContentLength: png.length, policyRevision: 'm9p-preview-v2',
      rendererRevision: 'fixture-renderer-v1', pngSha256: null, pngWidth: null,
      pngHeight: null, pngByteLength: null, bytesBase64: null,
    };
    const result = await clientFor(body as unknown as Record<string, unknown>)
      .fetchInscriptionApprovalBatch(req);
    expect(result.ok && result.value.items[0]?.preview).toMatchObject({
      disposition: 'placeholder', reason: 'active_content', bytesBase64: null,
    });
    if (!result.ok) return;
    const previews = bindInscriptionPreviews({
      request: req,
      response: result.value,
      verifiedAtMs: result.verifiedAtMs,
    });
    expect(() => assertPreviewAcknowledged(previews, undefined)).toThrow(/verify inscription IDs/u);
    expect(() => assertPreviewAcknowledged(previews, false)).toThrow(/verify inscription IDs/u);
    expect(() => assertPreviewAcknowledged(previews, true)).not.toThrow();
  });
});

describe('signed gallery and media contracts', () => {
  const identity = request().inscriptions[0]!;
  const envelope = () => ({
    instanceId: 'fixture-m9p', network: 'signet', protocolVersion: 1,
    requestNonce: nonce, timestamp: new Date(now).toISOString(),
    coreTip: { height: 100, hash: '10'.repeat(32) },
    indexTip: { height: 100, hash: '10'.repeat(32) },
    classificationRevision: revision,
    capabilities: ['inscription_index', 'preview_service'],
    signature: '',
  });

  it('accepts an ordered activity-id batch and rejects item substitution', async () => {
    const req: InscriptionActivityBatchRequest = {
      network: 'signet',
      inscriptionIds: [id],
    };
    const approval = responseBody(request());
    const body = { ...envelope(), items: approval.items };
    await expect(clientFor(body).fetchInscriptionActivityBatch(req))
      .resolves.toMatchObject({ ok: true });
    body.items[0]!.metadata.inscriptionId = `${'ef'.repeat(32)}i0`;
    await expect(clientFor(body).fetchInscriptionActivityBatch(req))
      .resolves.toEqual({ ok: false, reason: 'schema' });
  });

  it('accepts an exact ordered gallery batch and rejects a freshly signed substitution', async () => {
    const req: InscriptionGalleryBatchRequest = { network: 'signet', inscriptions: [identity] };
    const approval = responseBody(request());
    const body = { ...envelope(), items: approval.items };
    await expect(clientFor(body).fetchInscriptionGalleryBatch(req))
      .resolves.toMatchObject({ ok: true });
    body.items[0]!.metadata.satpoint = `${txid}:0:1`;
    await expect(clientFor(body).fetchInscriptionGalleryBatch(req))
      .resolves.toEqual({ ok: false, reason: 'schema' });
  });

  it('accepts display-only protocol titles and curated collection provenance', async () => {
    const req: InscriptionGalleryBatchRequest = { network: 'signet', inscriptions: [identity] };
    const approval = responseBody(request());
    const body = {
      ...envelope(),
      collectionCatalog: {
        source: 'TheWizardsOfOrd/ordinals-collections',
        revision: '1'.repeat(40),
        sha256: '2'.repeat(64),
        galleryIndexStatus: 'ready',
      },
      items: approval.items.map((item) => ({
        ...item,
        display: {
          title: { text: 'NodeMonke #1', source: 'ord_properties' },
          collections: [{
            slug: 'nodemonkes',
            name: 'NodeMonkes',
            kind: 'gallery',
            rootInscriptionIds: [
              '2ebbd9b93006b69714dd517fbe0d4bf7f8462ffe213105e03048d49ed46eba04i0',
            ],
          }],
        },
      })),
    };
    await expect(clientFor(body).fetchInscriptionGalleryEnrichedBatch(req))
      .resolves.toMatchObject({ ok: true });

    const substitution = structuredClone(body);
    substitution.items[0]!.metadata.inscriptionId = `${'ef'.repeat(32)}i0`;
    await expect(clientFor(substitution).fetchInscriptionGalleryEnrichedBatch(req))
      .resolves.toEqual({ ok: false, reason: 'schema' });
  });

  it('rehashes media bytes and rejects substituted provenance', async () => {
    const req: InscriptionMediaRequest = { network: 'signet', identity };
    const digest = bytesToHex(getSodium().crypto_hash_sha256(png));
    const body = {
      ...envelope(),
      identity,
      media: {
        disposition: 'media', reason: null, requestedInscriptionId: id,
        sourceInscriptionId: id, resolvedInscriptionId: id, delegateInscriptionId: null,
        declaredMime: 'image/png', declaredContentLength: png.length,
        detectedMime: 'image/png', contentSha256: digest, contentByteLength: png.length,
        bytesBase64: bytesToBase64(png), policyRevision: 'm11-gallery-media-v2',
      },
    };
    await expect(clientFor(body).fetchInscriptionMedia(req)).resolves.toMatchObject({ ok: true });

    const badHash = structuredClone(body);
    badHash.media.contentSha256 = 'ff'.repeat(32);
    await expect(clientFor(badHash).fetchInscriptionMedia(req))
      .resolves.toEqual({ ok: false, reason: 'schema' });

    const badProvenance = structuredClone(body);
    badProvenance.media.sourceInscriptionId = `${'ef'.repeat(32)}i0`;
    await expect(clientFor(badProvenance).fetchInscriptionMedia(req))
      .resolves.toEqual({ ok: false, reason: 'schema' });
  });
});

describe('universal preview contract (m9p-preview-v3 dual-accept)', () => {
  const digest = 'aa'.repeat(32);
  const provenance = {
    requestedInscriptionId: id,
    sourceInscriptionId: id,
    resolvedInscriptionId: id,
    delegateInscriptionId: null,
    sourceContentSha256: digest,
    sourceContentLength: 24,
    rendererRevision: 'fixture-renderer-v3',
  };

  it('accepts a v3 svg-sourced raster and rejects it under v2', () => {
    const raster = {
      disposition: 'raster', reason: null, ...provenance,
      declaredMime: 'image/svg+xml', declaredContentLength: 24,
      detectedMime: 'image/svg+xml', detectedFormat: 'svg',
      pngSha256: digest, pngWidth: 8, pngHeight: 8, pngByteLength: 68,
      policyRevision: 'm9p-preview-v3',
    };
    expect(inscriptionPreviewDescriptorSchema.safeParse(raster).success).toBe(true);
    expect(inscriptionPreviewDescriptorSchema.safeParse({
      ...raster, policyRevision: 'm9p-preview-v2',
    }).success).toBe(false);
  });

  it('accepts v3 text excerpts with exact byte binding and rejects mismatches', () => {
    const text = {
      disposition: 'text', reason: null, ...provenance,
      declaredMime: 'text/plain', declaredContentLength: 24,
      detectedMime: null, detectedFormat: null,
      excerpt: 'hello ordinals', excerptByteLength: 14, truncated: false,
      pngSha256: null, pngWidth: null, pngHeight: null, pngByteLength: null,
      policyRevision: 'm9p-preview-v3',
    };
    expect(inscriptionPreviewDescriptorSchema.safeParse(text).success).toBe(true);
    expect(inscriptionPreviewDescriptorSchema.safeParse({
      ...text, excerptByteLength: 13,
    }).success).toBe(false);
    expect(inscriptionPreviewDescriptorSchema.safeParse({
      ...text, policyRevision: 'm9p-preview-v2',
    }).success).toBe(false);
    expect(inscriptionPreviewPayloadSchema.safeParse({
      ...text, bytesBase64: null,
    }).success).toBe(true);
  });

  it('accepts v3 media badges bound to their MIME kind', () => {
    const badge = {
      disposition: 'mediaBadge', reason: null, ...provenance,
      sourceContentSha256: null, sourceContentLength: null,
      declaredMime: 'audio/ogg', declaredContentLength: 4_096,
      detectedMime: null, detectedFormat: null, mediaKind: 'audio',
      pngSha256: null, pngWidth: null, pngHeight: null, pngByteLength: null,
      policyRevision: 'm9p-preview-v3',
    };
    expect(inscriptionPreviewDescriptorSchema.safeParse(badge).success).toBe(true);
    expect(inscriptionPreviewDescriptorSchema.safeParse({
      ...badge, mediaKind: 'video',
    }).success).toBe(false);
  });

  it('rejects render_pending under v2 and keeps it acknowledgement-gated', () => {
    const pending = {
      disposition: 'placeholder', reason: 'render_pending', ...provenance,
      sourceContentSha256: null, sourceContentLength: null,
      declaredMime: 'text/html', declaredContentLength: 24,
      detectedMime: null, detectedFormat: null,
      pngSha256: null, pngWidth: null, pngHeight: null, pngByteLength: null,
      policyRevision: 'm9p-preview-v3',
    };
    const parsed = inscriptionPreviewDescriptorSchema.safeParse(pending);
    expect(parsed.success).toBe(true);
    expect(inscriptionPreviewDescriptorSchema.safeParse({
      ...pending, policyRevision: 'm9p-preview-v2',
    }).success).toBe(false);

    const set = {
      transactionCommitmentHash: '03'.repeat(32), analysisHash: '01'.repeat(32),
      psbtHash: '02'.repeat(32), effectSetHash: '04'.repeat(32),
      classificationRevision: revision, verifiedAtMs: now,
      items: [{ metadata: {} as never, preview: { ...pending, bytesBase64: null } as never }],
    };
    expect(() => assertPreviewAcknowledged(set as never, undefined)).toThrow(/verify inscription/i);
    expect(() => assertPreviewAcknowledged(set as never, true)).not.toThrow();
  });
});
