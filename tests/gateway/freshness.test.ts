import { describe, expect, it } from 'vitest';
import {
  evaluateFreshness,
  MEMPOOL_HEARTBEAT_MAX_AGE_MS,
} from '../../src/domain/gateway/freshness';
import type { StatusCapabilities, Tip } from '../../src/domain/gateway/contract';

const tip = (height: number, fill: string): Tip => ({ height, hash: fill.repeat(64) });

const base: StatusCapabilities = {
  instanceId: 'test',
  network: 'signet',
  protocolVersion: 1,
  protocolMin: 1,
  protocolMax: 1,
  requestNonce: 'n',
  timestamp: '2026-07-20T00:00:00.000Z',
  coreTip: tip(100, 'a'),
  indexTip: tip(100, 'a'),
  historyTip: tip(100, 'a'),
  ordTip: tip(100, 'a'),
  mempoolObservedAt: '2026-07-20T00:00:00.000Z',
  capabilities: ['address_history', 'inscription_index', 'mempool_overlay'],
  eligibleSafetyModes: ['standard_ordinals_safety'],
  classificationRevision: 'rev-1',
  activeRevision: 'rev-1',
  serverTime: '2026-07-20T00:00:00.000Z',
  signature: 'aa'.repeat(64),
};

const observedAtMs = Date.parse(base.mempoolObservedAt);

describe('evaluateFreshness (§18.4)', () => {
  it('reports fully fresh when all tips agree, heartbeat is recent, revision active', () => {
    expect(evaluateFreshness(base, observedAtMs)).toEqual({
      commonTip: true,
      heartbeatFresh: true,
      revisionActive: true,
      walletDataFresh: true,
      spendingReady: true,
      spendEligible: true,
    });
  });

  it('detects an ord index lagging behind core', () => {
    const report = evaluateFreshness({ ...base, ordTip: tip(99, 'a') }, observedAtMs);
    expect(report.commonTip).toBe(false);
    expect(report.spendEligible).toBe(false);
  });

  it('detects a hash mismatch at the same height (reorg reconciliation)', () => {
    const report = evaluateFreshness({ ...base, historyTip: tip(100, 'b') }, observedAtMs);
    expect(report.commonTip).toBe(false);
  });

  it('treats a heartbeat at exactly 30 000 ms as fresh and 30 001 ms as stale', () => {
    expect(
      evaluateFreshness(base, observedAtMs + MEMPOOL_HEARTBEAT_MAX_AGE_MS).heartbeatFresh,
    ).toBe(true);
    expect(
      evaluateFreshness(base, observedAtMs + MEMPOOL_HEARTBEAT_MAX_AGE_MS + 1).heartbeatFresh,
    ).toBe(false);
  });

  it('treats a heartbeat ahead of signed server time as stale (inconsistent data)', () => {
    const futureHeartbeat = {
      ...base,
      mempoolObservedAt: new Date(observedAtMs + 1).toISOString(),
    };
    expect(evaluateFreshness(futureHeartbeat, observedAtMs).heartbeatFresh).toBe(false);
  });

  it('accepts a freshly verified response when the signed server clock is slightly ahead', () => {
    const serverTimeMs = observedAtMs + 70;
    const v2 = {
      ...base,
      protocolVersion: 2 as const,
      protocolMin: 2 as const,
      protocolMax: 2 as const,
      timestamp: new Date(serverTimeMs).toISOString(),
      serverTime: new Date(serverTimeMs).toISOString(),
      mempoolObservedAt: new Date(serverTimeMs - 50).toISOString(),
      readiness: {
        walletDataReady: true,
        spendingReady: true,
        reasons: [],
        dependencies: {
          core: 'ready' as const,
          ord: 'ready' as const,
          electrs: 'ready' as const,
          classification: 'ready' as const,
          capacity: 'ready' as const,
          signing: 'ready' as const,
        },
        core: {
          initialBlockDownload: false,
          headersSynced: true,
          txindexSynced: true,
          peersReady: true,
          mempoolLoaded: true,
        },
        coherentCoreSampling: true,
        commonTip: true,
        mempoolFresh: true,
        reorgState: 'clear' as const,
        classificationState: 'active' as const,
        capacityState: 'ready' as const,
        signingKeyAvailable: true as const,
      },
    };

    expect(evaluateFreshness(v2, observedAtMs).heartbeatFresh).toBe(true);
    expect(evaluateFreshness(v2, observedAtMs).spendEligible).toBe(true);
  });

  it('detects a superseded classification revision', () => {
    const report = evaluateFreshness({ ...base, activeRevision: 'rev-2' }, observedAtMs);
    expect(report.revisionActive).toBe(false);
    expect(report.spendEligible).toBe(false);
  });

  it('spendEligible is the conjunction of all three checks', () => {
    const broken = evaluateFreshness(
      { ...base, ordTip: tip(99, 'a'), activeRevision: 'rev-2' },
      observedAtMs + MEMPOOL_HEARTBEAT_MAX_AGE_MS + 1,
    );
    expect(broken).toEqual({
      commonTip: false,
      heartbeatFresh: false,
      revisionActive: false,
      walletDataFresh: false,
      spendingReady: true,
      spendEligible: false,
    });
  });

  it('keeps coherent v2 wallet data fresh while spendingReady is false', () => {
    const v2 = { ...base, protocolVersion: 2 as const, protocolMin: 2 as const, protocolMax: 2 as const,
      readiness: { walletDataReady: true, spendingReady: false, reasons: ['spending_endpoints_unavailable' as const],
        dependencies: { core: 'ready' as const, ord: 'ready' as const, electrs: 'ready' as const,
          classification: 'ready' as const, capacity: 'ready' as const, signing: 'ready' as const },
        core: { initialBlockDownload: false, headersSynced: true, txindexSynced: true, peersReady: true, mempoolLoaded: true },
        coherentCoreSampling: true, commonTip: true, mempoolFresh: true, reorgState: 'clear' as const,
        classificationState: 'active' as const, capacityState: 'ready' as const, signingKeyAvailable: true as const } };
    expect(evaluateFreshness(v2, observedAtMs)).toMatchObject({ walletDataFresh: true, spendingReady: false, spendEligible: false });
  });
});
