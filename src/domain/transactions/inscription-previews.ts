import {
  inscriptionApprovalBatchRequestSchema,
  type InscriptionApprovalBatchRequest,
  type InscriptionApprovalBatchResponse,
  type InscriptionApprovalItem,
  type InscriptionIdentity,
  type InscriptionPreviewDescriptor,
} from '../gateway/contract';
import type { Network } from '../keys/derivation';
import type { InscriptionEffect, TransactionAnalysis } from './analysis';

export interface InscriptionPreviewSet {
  transactionCommitmentHash: string;
  analysisHash: string;
  psbtHash: string;
  effectSetHash: string;
  classificationRevision: string;
  verifiedAtMs: number;
  items: InscriptionApprovalItem[];
}

export interface StoredInscriptionPreviewSet extends Omit<InscriptionPreviewSet, 'items'> {
  items: Array<{
    metadata: InscriptionApprovalItem['metadata'];
    preview: InscriptionPreviewDescriptor;
  }>;
}

export type ApprovalInscriptionPreview =
  | {
      kind: 'raster';
      rasterBase64: string;
      pngSha256: string;
      pngWidth: number;
      pngHeight: number;
    }
  | { kind: 'placeholder'; reason: NonNullable<InscriptionPreviewDescriptor['reason']> }
  | {
      kind: 'text';
      textMime: 'text/plain' | 'application/json';
      excerpt: string;
      truncated: boolean;
    }
  | { kind: 'mediaBadge'; mediaKind: 'audio' | 'video'; contentLength: number };

export interface ApprovalInscriptionItem {
  inscriptionId: string;
  satpoint: string;
  outpoint: { txid: string; vout: number };
  inputIndex: number;
  inputOffset: string;
  outputIndex: number;
  outputOffset: string;
  movement: InscriptionEffect['movement'];
  coLocationGroup: string;
  qualifiedPartialAuthorization: boolean;
  number: number | null;
  contentType: string | null;
  preview: ApprovalInscriptionPreview;
}

function sameIdentity(a: InscriptionIdentity, b: InscriptionIdentity): boolean {
  return a.inscriptionId === b.inscriptionId && a.satpoint === b.satpoint &&
    a.outpoint.txid === b.outpoint.txid && a.outpoint.vout === b.outpoint.vout &&
    a.classificationRevision === b.classificationRevision;
}

export function identitiesForAnalysis(analysis: TransactionAnalysis): InscriptionIdentity[] {
  return analysis.assetEffects.inscriptions.map((effect) => ({
    inscriptionId: effect.inscriptionId,
    satpoint: effect.satpoint,
    outpoint: { ...effect.outpoint },
    classificationRevision: analysis.source.classificationRevision,
  }));
}

export function inscriptionApprovalRequest(input: {
  network: Network;
  analysis: TransactionAnalysis;
  analysisHash: string;
  psbtHash: string;
  transactionCommitmentHash: string;
}): InscriptionApprovalBatchRequest {
  return inscriptionApprovalBatchRequestSchema.parse({
    network: input.network,
    analysisHash: input.analysisHash,
    psbtHash: input.psbtHash,
    transactionCommitmentHash: input.transactionCommitmentHash,
    effectSetHash: input.analysis.assetEffects.effectSetHash,
    inscriptions: identitiesForAnalysis(input.analysis),
  });
}

export function bindInscriptionPreviews(input: {
  request: InscriptionApprovalBatchRequest;
  response: InscriptionApprovalBatchResponse;
  verifiedAtMs: number;
}): InscriptionPreviewSet {
  const { request, response } = input;
  if (response.network !== request.network || response.analysisHash !== request.analysisHash ||
      response.psbtHash !== request.psbtHash ||
      response.transactionCommitmentHash !== request.transactionCommitmentHash ||
      response.effectSetHash !== request.effectSetHash ||
      response.classificationRevision !== request.inscriptions[0]?.classificationRevision ||
      response.items.length !== request.inscriptions.length) {
    throw new Error('inscription preview response binding mismatch');
  }
  for (let index = 0; index < request.inscriptions.length; index += 1) {
    const expected = request.inscriptions[index]!;
    const item = response.items[index];
    if (!item || !sameIdentity(expected, item.metadata) ||
        item.preview.requestedInscriptionId !== expected.inscriptionId ||
        item.preview.sourceInscriptionId !== expected.inscriptionId ||
        item.preview.resolvedInscriptionId !== (item.metadata.delegate ?? expected.inscriptionId) ||
        item.preview.delegateInscriptionId !== item.metadata.delegate) {
      throw new Error('inscription preview identity mismatch');
    }
  }
  return {
    transactionCommitmentHash: response.transactionCommitmentHash,
    analysisHash: response.analysisHash,
    psbtHash: response.psbtHash,
    effectSetHash: response.effectSetHash,
    classificationRevision: response.classificationRevision,
    verifiedAtMs: input.verifiedAtMs,
    items: response.items.map((item) => ({
      metadata: { ...item.metadata, outpoint: { ...item.metadata.outpoint } },
      preview: { ...item.preview },
    })),
  };
}

export function storedPreviewSet(previews: InscriptionPreviewSet): StoredInscriptionPreviewSet {
  return {
    ...previews,
    items: previews.items.map((item) => {
      const { bytesBase64: _bytesBase64, ...descriptor } = item.preview;
      void _bytesBase64;
      return {
        metadata: { ...item.metadata, outpoint: { ...item.metadata.outpoint } },
        preview: descriptor,
      };
    }),
  };
}

export function approvalInscriptionItems(
  analysis: TransactionAnalysis,
  previews: InscriptionPreviewSet,
): ApprovalInscriptionItem[] {
  const effects = analysis.assetEffects.inscriptions;
  if (previews.effectSetHash !== analysis.assetEffects.effectSetHash ||
      previews.analysisHash.length !== 64 || previews.items.length !== effects.length) {
    throw new Error('inscription preview effect set mismatch');
  }
  const seen = new Set<string>();
  return effects.map((effect, index) => {
    const item = previews.items[index];
    if (!item || seen.has(effect.inscriptionId) || item.metadata.inscriptionId !== effect.inscriptionId ||
        item.metadata.satpoint !== effect.satpoint || item.metadata.outpoint.txid !== effect.outpoint.txid ||
        item.metadata.outpoint.vout !== effect.outpoint.vout ||
        item.preview.requestedInscriptionId !== effect.inscriptionId) {
      throw new Error('inscription preview presentation mismatch');
    }
    seen.add(effect.inscriptionId);
    const preview: ApprovalInscriptionPreview = item.preview.disposition === 'raster'
      ? {
          kind: 'raster',
          rasterBase64: item.preview.bytesBase64,
          pngSha256: item.preview.pngSha256,
          pngWidth: item.preview.pngWidth,
          pngHeight: item.preview.pngHeight,
        }
      : item.preview.disposition === 'text'
        ? {
            kind: 'text',
            textMime: item.preview.declaredMime,
            excerpt: item.preview.excerpt,
            truncated: item.preview.truncated,
          }
        : item.preview.disposition === 'mediaBadge'
          ? {
              kind: 'mediaBadge',
              mediaKind: item.preview.mediaKind,
              contentLength: item.preview.declaredContentLength,
            }
          : { kind: 'placeholder', reason: item.preview.reason };
    return {
      inscriptionId: effect.inscriptionId,
      satpoint: effect.satpoint,
      outpoint: { ...effect.outpoint },
      inputIndex: effect.inputIndex,
      inputOffset: effect.inputOffset.toString(),
      outputIndex: effect.outputIndex,
      outputOffset: effect.outputOffset.toString(),
      movement: effect.movement,
      coLocationGroup: effect.coLocationGroup,
      qualifiedPartialAuthorization: effect.qualifiedPartialAuthorization,
      number: item.metadata.number,
      contentType: item.metadata.contentType,
      preview,
    };
  });
}

export function requiresPreviewAcknowledgement(previews: InscriptionPreviewSet): boolean {
  return previews.items.some((item) => item.preview.disposition === 'placeholder');
}

export function assertPreviewAcknowledged(
  previews: InscriptionPreviewSet,
  acknowledged: boolean | undefined,
): void {
  if (requiresPreviewAcknowledgement(previews) && acknowledged !== true) {
    throw new Error('Preview unavailable; verify inscription IDs before approval');
  }
}
