/**
 * §18.4 freshness rules as pure domain logic.
 *
 * Spending requires: all indexes at the same common confirmed tip, a mempool
 * heartbeat no older than 30 s (inclusive), and the classification revision
 * still active. Evaluated at read time against a caller-supplied clock so a
 * cached status object can go stale without being rewritten.
 */
import type { StatusCapabilities, Tip } from './contract';

/** Inclusive: a heartbeat exactly this old is still fresh. */
export const MEMPOOL_HEARTBEAT_MAX_AGE_MS = 30_000;

export interface FreshnessReport {
  /** Core, history, ord, and index tips all identify the same block. */
  commonTip: boolean;
  /** Mempool overlay heartbeat within the (inclusive) 30 s bound. */
  heartbeatFresh: boolean;
  /** The revision this data was classified under is still the active one. */
  revisionActive: boolean;
  /** Read routes are coherent and explicitly ready for the current protocol. */
  walletDataFresh?: boolean;
  /** Gateway advertises every spending dependency, including fees and broadcast. */
  spendingReady?: boolean;
  /** Conjunction of the above — M6 adds per-UTXO revision checks on top. */
  spendEligible: boolean;
}

function sameTip(a: Tip, b: Tip): boolean {
  return a.height === b.height && a.hash === b.hash;
}

export function evaluateFreshness(
  status: StatusCapabilities,
  nowMs: number,
  verifiedAtMs = Date.parse(status.serverTime),
): FreshnessReport {
  const commonTip =
    sameTip(status.coreTip, status.indexTip) &&
    sameTip(status.coreTip, status.historyTip) &&
    sameTip(status.coreTip, status.ordTip);

  // Compare the two signed server timestamps first, then age that observation
  // with locally elapsed time. Comparing a remote timestamp directly to the
  // local wall clock makes a healthy response flicker stale under ordinary
  // millisecond-scale host/browser clock skew.
  const heartbeatAgeAtVerification =
    Date.parse(status.serverTime) - Date.parse(status.mempoolObservedAt);
  const elapsedSinceVerification = Math.max(0, nowMs - verifiedAtMs);
  const heartbeatAge = heartbeatAgeAtVerification + elapsedSinceVerification;
  // A heartbeat ahead of the signed server time is inconsistent data.
  const heartbeatFresh =
    Number.isFinite(heartbeatAgeAtVerification) &&
    Number.isFinite(elapsedSinceVerification) &&
    heartbeatAgeAtVerification >= 0 &&
    heartbeatAge >= 0 &&
    heartbeatAge <= MEMPOOL_HEARTBEAT_MAX_AGE_MS;

  const revisionActive = status.classificationRevision === status.activeRevision;
  const baseFresh = commonTip && heartbeatFresh && revisionActive;
  const walletDataFresh = baseFresh && (status.protocolVersion === 1 || status.readiness.walletDataReady);
  const spendingReady = status.protocolVersion === 1 || status.readiness.spendingReady;

  return {
    commonTip,
    heartbeatFresh,
    revisionActive,
    walletDataFresh,
    spendingReady,
    spendEligible: walletDataFresh && spendingReady,
  };
}

/**
 * The M6 per-UTXO layer on top of evaluateFreshness: a stored classification
 * is only usable for spending while its revision is still the gateway's
 * active one (§11.2 condition 2, §18.4).
 */
export function isUtxoRevisionFresh(status: StatusCapabilities, classificationRevision: string): boolean {
  return classificationRevision === status.activeRevision;
}
