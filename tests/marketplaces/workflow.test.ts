import { describe, expect, it } from 'vitest';
import {
  canReleaseSignedResponse,
  recoverMarketplaceWorkflowAfterRestart,
  releaseMarketplaceReservation,
  transitionMarketplaceWorkflow,
  type MarketplaceReservation,
  type MarketplaceWorkflow,
} from '../../src/domain/marketplaces/workflow';

const workflow: MarketplaceWorkflow = {
  version: 1,
  workflowId: 'wf-1',
  marketplaceId: 'ordnet',
  templateId: 'ordnet-list',
  templateVersion: 'drey-1',
  origin: 'https://ord.net',
  network: 'mainnet',
  vaultId: 'vault-1',
  sessionId: 'session-1',
  account: 0,
  role: 'seller',
  action: 'list',
  assetKind: 'inscription',
  step: 1,
  stepCount: 3,
  state: 'prepared',
  requestHash: '11'.repeat(32),
  psbtHash: '22'.repeat(32),
  analysisHash: '33'.repeat(32),
  planHash: '44'.repeat(32),
  priorSignedHash: null,
  signedPsbtBase64: null,
  reservedOutpoints: [`${'aa'.repeat(32)}:0`],
  broadcaster: 'site',
  revision: 'preflight-1',
  expiresAt: 2_000,
  createdAt: 1_000,
  updatedAt: 1_000,
};

describe('durable marketplace workflow invariants', () => {
  it('turns prepared or approved unsigned work into needs_reapproval on restart', () => {
    expect(recoverMarketplaceWorkflowAfterRestart(workflow, 1_100).state).toBe('needs_reapproval');
    const approved = transitionMarketplaceWorkflow(workflow, 'approved_unsigned', 1_050);
    expect(recoverMarketplaceWorkflowAfterRestart(approved, 1_100).state).toBe('needs_reapproval');
  });

  it('releases signed bytes only for an identical fresh authority binding', () => {
    const approved = transitionMarketplaceWorkflow(workflow, 'approved_unsigned', 1_050);
    const signed = transitionMarketplaceWorkflow(approved, 'signed_undelivered', 1_100, {
      signedPsbtBase64: 'cHNidP8=',
    });
    const exact = {
      workflow: signed, origin: signed.origin, vaultId: signed.vaultId, account: signed.account,
      requestHash: signed.requestHash, psbtHash: signed.psbtHash, now: 1_500,
    };
    expect(canReleaseSignedResponse(exact)).toBe(true);
    expect(canReleaseSignedResponse({ ...exact, origin: 'https://evil.example' })).toBe(false);
    expect(canReleaseSignedResponse({ ...exact, psbtHash: 'ff'.repeat(32) })).toBe(false);
    expect(canReleaseSignedResponse({ ...exact, now: 2_000 })).toBe(false);
    expect(() => transitionMarketplaceWorkflow(signed, 'completed', 1_200)).toThrow(/invalid/u);
  });

  it('requires an independently provable reason to release a reserved outpoint', () => {
    const reservation: MarketplaceReservation = {
      version: 1, outpoint: `${'aa'.repeat(32)}:0`, workflowId: 'wf-1', marketplaceId: 'ordnet',
      templateId: 'ordnet-offer', vaultId: 'vault-1', network: 'mainnet', account: 0,
      reason: 'exported_offer', createdAt: 1_000, expiresAt: null, releasedAt: null, releaseProof: null,
    };
    expect(releaseMarketplaceReservation(reservation, 'conflicting_spend', 1_500)).toMatchObject({
      releasedAt: 1_500, releaseProof: 'conflicting_spend',
    });
    expect(() => releaseMarketplaceReservation(
      { ...reservation, releasedAt: 1_200, releaseProof: 'settlement' }, 'settlement', 1_500,
    )).toThrow(/already released/u);
  });
});
