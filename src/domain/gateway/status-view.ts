/**
 * Read-time projection of the cached gateway status for UI surfaces
 * (spec §10.2 degraded-status slot, §11.3 safety badges).
 *
 * Staleness is always computed here, at read time, from the cached
 * verification instant — never stored — so a worker that slept through the
 * cache's shelf life reports stale without any timer having run.
 */
import { z } from 'zod';
import {
  capabilitySchema,
  networkSchema,
  productionReadOnlyReasonSchema,
  safetyModeSchema,
  type StatusCapabilities,
} from './contract';
import { evaluateFreshness } from './freshness';
import { deriveSafetyMode } from './safety-mode';
import type { GatewayRejectReason } from './verify';

/** A verified status older than this is presented as stale (read view only). */
export const STATUS_STALE_AFTER_MS = 90_000;

export type GatewayBadgeState = 'connected' | 'degraded' | 'stale' | 'unreachable' | 'read_only';

export interface CachedGatewayStatus {
  status: StatusCapabilities;
  /** Local clock instant at which the signed response verified. */
  verifiedAtMs: number;
  endpoint: string;
}

const rejectReasonSchema = z.enum([
  'http',
  'rate_limited',
  'network_error',
  'timeout',
  'response_too_large',
  'aborted',
  'schema',
  'signature',
  'nonce_mismatch',
  'wrong_network',
  'protocol',
  'skew',
  'conflicting_sources',
  'key_unprovisioned',
]);

/**
 * Wire shape of the `gateway.status` op response. Contains no wallet data —
 * no addresses, balances, or activity — which is why the op may answer while
 * locked (§7.5: security checks continue).
 */
export const gatewayStatusViewSchema = z
  .object({
    state: z.enum(['connected', 'degraded', 'stale', 'unreachable', 'read_only']),
    network: networkSchema.nullable(),
    mode: safetyModeSchema.nullable(),
    missingProtections: z.array(capabilitySchema),
    tipHeight: z.number().int().nonnegative().nullable(),
    verifiedAtMs: z.number().int().nonnegative().nullable(),
    ageMs: z.number().int().nonnegative().nullable(),
    lastReason: rejectReasonSchema.nullable(),
    walletDataFresh: z.boolean().optional(),
    spendingReady: z.boolean().optional(),
    commonTip: z.boolean().nullable().optional(),
    classificationState: z.enum(['bootstrapping', 'active', 'advancing', 'reconciling', 'blocked', 'unavailable']).nullable().optional(),
    reorgState: z.enum(['clear', 'verifying', 'reconciling', 'manual_intervention', 'unknown']).nullable().optional(),
    readinessReasons: z.array(productionReadOnlyReasonSchema).optional(),
  })
  .strict();
export type GatewayStatusView = z.infer<typeof gatewayStatusViewSchema>;

export function deriveGatewayView(
  cached: CachedGatewayStatus | null,
  lastFailure: GatewayRejectReason | null,
  nowMs: number,
): GatewayStatusView {
  if (cached === null) {
    return {
      state: 'unreachable',
      network: null,
      mode: null,
      missingProtections: [],
      tipHeight: null,
      verifiedAtMs: null,
      ageMs: null,
      lastReason: lastFailure,
      walletDataFresh: false,
      spendingReady: false,
      commonTip: null,
      classificationState: null,
      reorgState: null,
    };
  }

  const ageMs = Math.max(0, nowMs - cached.verifiedAtMs);
  const freshness = evaluateFreshness(cached.status, nowMs, cached.verifiedAtMs);
  const derivation = deriveSafetyMode(cached.status.capabilities, cached.status.eligibleSafetyModes);
  const readiness = cached.status.protocolVersion === 2 ? cached.status.readiness : null;

  // Badge precedence: unreachable → read_only → stale → degraded → connected.
  // A shelf-life-expired cache with a failing fetch behind it means we cannot
  // reach the gateway; the same expiry with no recorded failure is merely
  // stale data.
  const expired = ageMs > STATUS_STALE_AFTER_MS;
  const state: GatewayBadgeState =
    expired && lastFailure !== null
      ? 'unreachable'
      : freshness.walletDataFresh === true && freshness.spendingReady === false
        ? 'read_only'
        : derivation.readOnly
          ? 'read_only'
          : expired || !freshness.spendEligible
          ? 'stale'
          : derivation.mode === 'standard_ordinals_safety'
            ? 'degraded'
            : 'connected';

  return {
    state,
    network: cached.status.network,
    mode: derivation.mode,
    missingProtections: derivation.missingFullProtections,
    tipHeight: cached.status.coreTip.height,
    verifiedAtMs: cached.verifiedAtMs,
    ageMs,
    lastReason: lastFailure,
    walletDataFresh: freshness.walletDataFresh,
    spendingReady: freshness.spendingReady,
    commonTip: freshness.commonTip,
    classificationState: readiness?.classificationState ?? null,
    reorgState: readiness?.reorgState ?? null,
    ...(readiness === null ? {} : { readinessReasons: readiness.reasons }),
  };
}

const NORMAL_CONVERGENCE_REASONS = new Set([
  'classification_inactive',
  'classification_revision_mismatch',
  'classification_tip_mismatch',
  'classification_advancing',
  'core_tip_changed',
  'spending_endpoints_unavailable',
  'tip_mismatch',
]);

/** A normal block/index transition that is safe to present as brief syncing. */
export function isGatewaySyncing(view: GatewayStatusView): boolean {
  if (view.walletDataFresh !== false) return false;
  if (view.state === 'unreachable') return false;
  if (view.lastReason === 'conflicting_sources') return false;
  if (
    view.reorgState !== undefined &&
    view.reorgState !== null &&
    view.reorgState !== 'clear'
  ) {
    return false;
  }
  if (view.readinessReasons !== undefined) {
    // Production deliberately clears capabilities while a new block converges,
    // which projects as read_only even though the signed reason set identifies
    // routine index work. Require a non-empty, exhaustively allowlisted v2 set:
    // an unknown, empty, or genuinely unavailable read-only response must stay
    // prominent and never borrow the quiet syncing presentation.
    return (
      view.readinessReasons.length > 0 &&
      view.readinessReasons.every((reason) => NORMAL_CONVERGENCE_REASONS.has(reason))
    );
  }
  // A legacy read-only response has no signed reason set with which to prove
  // routine convergence, so fail closed in presentation as well as authority.
  if (view.state === 'read_only') return false;
  // Legacy status views do not carry readiness reasons. Retain their narrower
  // state-based fallback without weakening any spending gate.
  return (
    view.commonTip === false ||
    view.classificationState === 'advancing' ||
    view.classificationState === 'reconciling'
  );
}
