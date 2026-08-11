import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { laneState } from '../../src/domain/classification/lanes';
import { isSuspiciousDust } from '../../src/domain/classification/dust';
import {
  BLOCKED_WHILE_STALE,
  deriveDataGating,
} from '../../src/domain/classification/staleness';
import type { GatewayStatusView } from '../../src/domain/gateway/status-view';
import { utxoArb } from './arbitraries';

describe('§12 lane states (detection only)', () => {
  it('never reports normal for a protected class in the payment lane', () => {
    fc.assert(
      fc.property(utxoArb, (utxo) => {
        const primary = utxo.facts?.primaryClass ?? 'unknown';
        const state = laneState(utxo);
        if (
          utxo.lane === 'payment' &&
          ['inscribed', 'rare_sat', 'runic_or_unsupported', 'mixed'].includes(primary)
        ) {
          expect(state).toBe('protected_wrong_address');
        }
      }),
    );
  });

  it('unknown at a payment address is not claimed as a wrong-lane detection', () => {
    fc.assert(
      fc.property(utxoArb, (utxo) => {
        const primary = utxo.facts?.primaryClass ?? 'unknown';
        if (utxo.lane === 'payment' && (primary === 'unknown' || primary === 'cardinal_clean')) {
          expect(laneState(utxo)).toBe('normal');
        }
      }),
    );
  });

  it('clean BTC in the ordinals lane is reserved, everything protected there is normal', () => {
    fc.assert(
      fc.property(utxoArb, (utxo) => {
        if (utxo.lane !== 'ordinals') return;
        const primary = utxo.facts?.primaryClass ?? 'unknown';
        expect(laneState(utxo)).toBe(
          primary === 'cardinal_clean' ? 'reserved_ordinal_lane_btc' : 'normal',
        );
      }),
    );
  });
});

describe('dust quarantine heuristic', () => {
  const dustyBase = {
    outpoint: { txid: 'a'.repeat(64), vout: 0 },
    valueSats: 293n,
    scriptPubKey: `0014${'1'.repeat(40)}`,
    account: 0,
    lane: 'payment' as const,
    chain: 0 as const,
    addressIndex: 0,
    height: 100,
    walletCreatedChange: false,
    facts: null,
    flags: { userFrozen: false, dustQuarantined: false },
  };

  it('quarantines unsolicited value below the script-specific dust limit', () => {
    expect(isSuspiciousDust(dustyBase, false)).toBe(true);
    expect(
      isSuspiciousDust(
        { ...dustyBase, valueSats: 329n, scriptPubKey: `5120${'1'.repeat(64)}` },
        false,
      ),
    ).toBe(true);
  });

  it('spares wallet-created change, first fundings, and values at the script dust limit', () => {
    expect(isSuspiciousDust({ ...dustyBase, walletCreatedChange: true }, false)).toBe(false);
    expect(isSuspiciousDust(dustyBase, true)).toBe(false);
    expect(isSuspiciousDust({ ...dustyBase, valueSats: 294n }, false)).toBe(false);
    expect(
      isSuspiciousDust(
        { ...dustyBase, valueSats: 330n, scriptPubKey: `5120${'1'.repeat(64)}` },
        false,
      ),
    ).toBe(false);
  });

  it('never quarantines an ordinary 1,000-sat payment', () => {
    expect(isSuspiciousDust({ ...dustyBase, valueSats: 1_000n }, false)).toBe(false);
  });
});

describe('§11.4 data gating', () => {
  const view = (state: GatewayStatusView['state']): GatewayStatusView => ({
    state,
    network: 'signet',
    mode: 'standard_ordinals_safety',
    missingProtections: [],
    tipHeight: 1,
    verifiedAtMs: 0,
    ageMs: 0,
    lastReason: null,
  });

  const clear = {
    hasConflictingSources: false,
    tipsDivergeByHashOnly: false,
    cachedRevisionStale: false,
  };

  it('distinguishes the four §11.4 non-fresh states', () => {
    expect(deriveDataGating(view('connected'), { ...clear, hasConflictingSources: true }).state).toBe(
      'conflicting_sources',
    );
    expect(deriveDataGating(view('unreachable'), clear).state).toBe('backend_unreachable');
    expect(deriveDataGating(view('read_only'), clear).state).toBe('backend_read_only');
    expect(deriveDataGating(view('stale'), { ...clear, tipsDivergeByHashOnly: true }).state).toBe(
      'reorg_reconciliation',
    );
    expect(deriveDataGating(view('stale'), clear).state).toBe('index_lag');
  });

  it('a stale cached revision gates as index lag even while the gateway is healthy', () => {
    const gated = deriveDataGating(view('connected'), { ...clear, cachedRevisionStale: true });
    expect(gated.state).toBe('index_lag');
    expect(gated.blockedActions).toEqual(BLOCKED_WHILE_STALE);
    // Positive inconsistency still outranks it.
    expect(
      deriveDataGating(view('connected'), {
        ...clear,
        cachedRevisionStale: true,
        hasConflictingSources: true,
      }).state,
    ).toBe('conflicting_sources');
  });

  it('treats signed block-convergence reasons as index lag without weakening the gate', () => {
    const transitioning = deriveDataGating({
      ...view('read_only'),
      mode: null,
      walletDataFresh: false,
      spendingReady: false,
      commonTip: true,
      classificationState: 'active',
      reorgState: 'clear',
      readinessReasons: [
        'classification_revision_mismatch',
        'classification_tip_mismatch',
        'spending_endpoints_unavailable',
      ],
    }, clear);
    expect(transitioning.state).toBe('index_lag');
    expect(transitioning.blockedActions).toEqual(BLOCKED_WHILE_STALE);

    const unavailable = deriveDataGating({
      ...view('read_only'),
      walletDataFresh: false,
      spendingReady: false,
      commonTip: false,
      classificationState: 'active',
      reorgState: 'clear',
      readinessReasons: ['ord_unavailable', 'spending_endpoints_unavailable', 'tip_mismatch'],
    }, clear);
    expect(unavailable.state).toBe('backend_read_only');
  });

  it('blocks every spend-shaped action exactly when not fresh', () => {
    const fresh = deriveDataGating(view('connected'), clear);
    expect(fresh).toEqual({ state: 'fresh', blockedActions: [] });
    const gated = deriveDataGating(view('unreachable'), clear);
    expect(gated.blockedActions).toEqual(BLOCKED_WHILE_STALE);
  });

  it('degraded (Standard mode) still reads as fresh — capability gating is §11.3, not §11.4', () => {
    expect(deriveDataGating(view('degraded'), clear).state).toBe('fresh');
  });
});
