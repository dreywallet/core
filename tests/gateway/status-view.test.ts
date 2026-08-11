import { describe, expect, it } from 'vitest';
import {
  deriveGatewayView,
  isGatewaySyncing,
  STATUS_STALE_AFTER_MS,
  type CachedGatewayStatus,
} from '../../src/domain/gateway/status-view';
import type { Capability, StatusCapabilities, Tip } from '../../src/domain/gateway/contract';
import { FULL_REQUIRED } from '../../src/domain/gateway/safety-mode';

const tip = (height: number, fill: string): Tip => ({ height, hash: fill.repeat(64) });
const T0 = Date.parse('2026-07-20T00:00:00.000Z');

function makeStatus(overrides: Partial<StatusCapabilities> = {}): StatusCapabilities {
  return {
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
    ...overrides,
  } as StatusCapabilities;
}

const cachedAt = (status: StatusCapabilities, verifiedAtMs: number): CachedGatewayStatus => ({
  status,
  verifiedAtMs,
  endpoint: 'http://127.0.0.1:8080',
});

const FULL_CAPS: Capability[] = [...FULL_REQUIRED, 'fee_estimation', 'broadcast'];

describe('deriveGatewayView', () => {
  it('reports unreachable with no cached status, carrying the failure reason', () => {
    const view = deriveGatewayView(null, 'network_error', T0);
    expect(view.state).toBe('unreachable');
    expect(view.network).toBeNull();
    expect(view.lastReason).toBe('network_error');
  });

  it('reports connected for a fresh Full Sat Safety status', () => {
    const status = makeStatus({
      capabilities: FULL_CAPS,
      eligibleSafetyModes: ['full_sat_safety', 'standard_ordinals_safety'],
    });
    const view = deriveGatewayView(cachedAt(status, T0), null, T0);
    expect(view.state).toBe('connected');
    expect(view.mode).toBe('full_sat_safety');
    expect(view.missingProtections).toEqual([]);
    expect(view.tipHeight).toBe(100);
  });

  it('stays connected when the signed server clock is slightly ahead at verification', () => {
    const serverTimeMs = T0 + 70;
    const status = makeStatus({
      protocolVersion: 2,
      protocolMin: 2,
      protocolMax: 2,
      timestamp: new Date(serverTimeMs).toISOString(),
      serverTime: new Date(serverTimeMs).toISOString(),
      mempoolObservedAt: new Date(serverTimeMs - 50).toISOString(),
      capabilities: FULL_CAPS,
      eligibleSafetyModes: ['full_sat_safety', 'standard_ordinals_safety'],
      readiness: {
        walletDataReady: true,
        spendingReady: true,
        reasons: [],
        dependencies: {
          core: 'ready', ord: 'ready', electrs: 'ready', classification: 'ready', capacity: 'ready', signing: 'ready',
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
        reorgState: 'clear',
        classificationState: 'active',
        capacityState: 'ready',
        signingKeyAvailable: true,
      },
    });

    expect(deriveGatewayView(cachedAt(status, T0), null, T0).state).toBe('connected');
  });

  it('reports degraded for a fresh Standard Ordinals Safety status', () => {
    const view = deriveGatewayView(cachedAt(makeStatus(), T0), null, T0);
    expect(view.state).toBe('degraded');
    expect(view.mode).toBe('standard_ordinals_safety');
    expect(view.missingProtections).toEqual([
      'sat_index',
      'rarity',
      'rune_detection',
      'unsupported_asset_detection',
    ]);
  });

  it('reports read_only when inscription indexing is unreliable', () => {
    const status = makeStatus({ capabilities: ['address_history', 'mempool_overlay'] });
    const view = deriveGatewayView(cachedAt(status, T0), null, T0);
    expect(view.state).toBe('read_only');
    expect(view.mode).toBeNull();
  });

  it('evaluates staleness at read time: same cache, different now', () => {
    const cached = cachedAt(makeStatus(), T0);
    expect(deriveGatewayView(cached, null, T0 + 10_000).state).toBe('degraded');
    expect(deriveGatewayView(cached, null, T0 + STATUS_STALE_AFTER_MS + 1).state).toBe('stale');
  });

  it('reports stale when §18.4 freshness fails even with a young cache', () => {
    const status = makeStatus({ ordTip: tip(99, 'a') });
    expect(deriveGatewayView(cachedAt(status, T0), null, T0).state).toBe('stale');
  });

  it('identifies normal tip convergence without masking unrelated failures', () => {
    const converging = deriveGatewayView(cachedAt(makeStatus({
      protocolVersion: 2,
      protocolMin: 2,
      protocolMax: 2,
      capabilities: FULL_CAPS,
      eligibleSafetyModes: ['full_sat_safety', 'standard_ordinals_safety'],
      readiness: {
        walletDataReady: false,
        spendingReady: false,
        reasons: ['tip_mismatch'],
        dependencies: {
          core: 'ready', ord: 'ready', electrs: 'ready', classification: 'ready', capacity: 'ready', signing: 'ready',
        },
        core: {
          initialBlockDownload: false,
          headersSynced: true,
          txindexSynced: true,
          peersReady: true,
          mempoolLoaded: true,
        },
        coherentCoreSampling: true,
        commonTip: false,
        mempoolFresh: true,
        reorgState: 'clear',
        classificationState: 'advancing',
        capacityState: 'ready',
        signingKeyAvailable: true,
      },
      indexTip: tip(99, 'b'),
    }), T0), null, T0);
    expect(isGatewaySyncing(converging)).toBe(true);
    expect(converging.readinessReasons).toEqual(['tip_mismatch']);

    const unavailable = deriveGatewayView(null, 'network_error', T0);
    expect(isGatewaySyncing(unavailable)).toBe(false);

    const ordUnavailable = deriveGatewayView(cachedAt(makeStatus({
      protocolVersion: 2,
      protocolMin: 2,
      protocolMax: 2,
      capabilities: [],
      eligibleSafetyModes: [],
      readiness: {
        walletDataReady: false,
        spendingReady: false,
        reasons: ['ord_unavailable', 'spending_endpoints_unavailable', 'tip_mismatch'],
        dependencies: {
          core: 'ready', ord: 'unavailable', electrs: 'ready', classification: 'ready', capacity: 'ready', signing: 'ready',
        },
        core: {
          initialBlockDownload: false,
          headersSynced: true,
          txindexSynced: true,
          peersReady: true,
          mempoolLoaded: true,
        },
        coherentCoreSampling: true,
        commonTip: false,
        mempoolFresh: true,
        reorgState: 'clear',
        classificationState: 'active',
        capacityState: 'ready',
        signingKeyAvailable: true,
      },
      ordTip: tip(0, '0'),
      indexTip: tip(0, '0'),
    }), T0), null, T0);
    expect(isGatewaySyncing(ordUnavailable)).toBe(false);

    expect(isGatewaySyncing({
      ...converging,
      reorgState: 'reconciling',
      readinessReasons: ['tip_mismatch'],
    })).toBe(false);
    expect(isGatewaySyncing({
      ...converging,
      lastReason: 'conflicting_sources',
    })).toBe(false);
    expect(isGatewaySyncing({
      ...converging,
      state: 'read_only',
    })).toBe(true);
    expect(isGatewaySyncing({
      ...converging,
      state: 'read_only',
      readinessReasons: [],
    })).toBe(false);
    expect(isGatewaySyncing({
      ...converging,
      state: 'read_only',
      readinessReasons: ['capacity_low', 'spending_endpoints_unavailable'],
    })).toBe(false);
    expect(isGatewaySyncing({
      ...converging,
      state: 'read_only',
      readinessReasons: undefined,
    })).toBe(false);
  });

  it('recognizes the capability-cleared production convergence shape', () => {
    const productionConvergence = deriveGatewayView(cachedAt(makeStatus({
      protocolVersion: 2,
      protocolMin: 2,
      protocolMax: 2,
      capabilities: [],
      eligibleSafetyModes: [],
      readiness: {
        walletDataReady: false,
        spendingReady: false,
        reasons: [
          'classification_revision_mismatch',
          'classification_tip_mismatch',
          'spending_endpoints_unavailable',
          'tip_mismatch',
        ],
        dependencies: {
          core: 'ready', ord: 'mismatched', electrs: 'ready', classification: 'mismatched', capacity: 'ready', signing: 'ready',
        },
        core: {
          initialBlockDownload: false,
          headersSynced: true,
          txindexSynced: true,
          peersReady: true,
          mempoolLoaded: true,
        },
        coherentCoreSampling: true,
        commonTip: false,
        mempoolFresh: true,
        reorgState: 'clear',
        classificationState: 'active',
        capacityState: 'ready',
        signingKeyAvailable: true,
      },
      indexTip: tip(0, '0'),
      ordTip: tip(99, 'b'),
    }), T0), null, T0);

    expect(productionConvergence.state).toBe('read_only');
    expect(productionConvergence.mode).toBeNull();
    expect(isGatewaySyncing(productionConvergence)).toBe(true);
  });

  it('reports unreachable, not stale, when expired with a failing fetch behind it', () => {
    const cached = cachedAt(makeStatus(), T0);
    const later = T0 + STATUS_STALE_AFTER_MS + 1;
    const view = deriveGatewayView(cached, 'http', later);
    expect(view.state).toBe('unreachable');
    // Last-known data still surfaces for the UI.
    expect(view.network).toBe('signet');
    expect(view.tipHeight).toBe(100);
  });

  it('read_only outranks stale for a fresh-but-crippled backend', () => {
    const status = makeStatus({ capabilities: ['address_history', 'mempool_overlay'] });
    const view = deriveGatewayView(cachedAt(status, T0), null, T0 + STATUS_STALE_AFTER_MS + 1);
    expect(view.state).toBe('read_only');
  });
});
