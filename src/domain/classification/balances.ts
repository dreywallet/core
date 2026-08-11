/**
 * Home balance fold (spec §10.2): Available now vs Protected sats, with
 * §12.2 reserved lane BTC and pending amounts kept out of both. Available is
 * strictly the sum of §11.2-eligible UTXOs — nothing may imply Protected (or
 * reserved, or frozen) sats are spendable BTC.
 */
import { evaluateEligibility, type EligibilityContext } from './eligibility';
import { laneState } from './lanes';
import { displayClass, type WalletUtxo } from './types';

export interface BalanceSummary {
  /** Sum of §11.2-eligible UTXO values. */
  availableSats: bigint;
  /** Protected asset classes + §12.1 wrong-lane protected UTXOs. */
  protectedSats: bigint;
  /** §12.2 plain BTC reserved in the ordinals lane. */
  reservedSats: bigint;
  /** Incoming unconfirmed (not wallet-created change). */
  pendingSats: bigint;
  /** Pending value with inscription identities proven by signed sat flow. */
  pendingOrdinalSats: bigint;
  /** Clean but user-frozen or dust-quarantined value. */
  frozenSats: bigint;
  /** Clean, confirmed, but stale/locked/uneconomic — not spendable right now. */
  unavailableCleanSats: bigint;
  /** Protected value with a detected asset class. */
  assetProtectedSats: bigint;
  /** Protected value whose classification is not yet authoritative. */
  awaitingClassificationSats: bigint;
  /** Clean value explicitly frozen by the user. */
  userFrozenSats: bigint;
  /** Clean value automatically set aside by the script dust policy. */
  dustQuarantinedSats: bigint;
  collectiblesCount: number;
  pendingOrdinalCount: number;
  wrongLaneCount: number;
}

const PROTECTED_DISPLAY = new Set(['inscribed', 'rare_sat', 'runic_or_unsupported', 'mixed', 'unknown']);

/**
 * Every UTXO lands in exactly one bucket, so the buckets partition the total
 * value (property-tested). Incoming unconfirmed value is always presented as
 * pending while classification catches up; it remains ineligible for every
 * spend path. Confirmed protected/wrong-lane facts then take precedence over
 * reserved lane BTC > frozen > eligible.
 */
export function summarizeBalances(
  utxos: readonly WalletUtxo[],
  ctx: EligibilityContext,
): BalanceSummary {
  const summary: BalanceSummary = {
    availableSats: 0n,
    protectedSats: 0n,
    reservedSats: 0n,
    pendingSats: 0n,
    pendingOrdinalSats: 0n,
    frozenSats: 0n,
    unavailableCleanSats: 0n,
    assetProtectedSats: 0n,
    awaitingClassificationSats: 0n,
    userFrozenSats: 0n,
    dustQuarantinedSats: 0n,
    collectiblesCount: 0,
    pendingOrdinalCount: 0,
    wrongLaneCount: 0,
  };

  for (const utxo of utxos) {
    const display = displayClass(utxo);
    const lane = laneState(utxo);
    const inscriptionCount = utxo.facts?.inscriptions.length ?? 0;
    if (utxo.height !== null && utxo.facts?.confidence === 'authoritative' && inscriptionCount > 0) {
      summary.collectiblesCount += inscriptionCount;
    }
    if (lane !== 'normal') summary.wrongLaneCount += lane === 'protected_wrong_address' ? 1 : 0;

    if (utxo.height === null && !utxo.walletCreatedChange) {
      summary.pendingSats += utxo.valueSats;
      if (inscriptionCount > 0) {
        summary.pendingOrdinalSats += utxo.valueSats;
        summary.pendingOrdinalCount += inscriptionCount;
      }
    } else if (PROTECTED_DISPLAY.has(utxo.facts?.primaryClass ?? 'unknown')) {
      summary.protectedSats += utxo.valueSats;
      if ((utxo.facts?.primaryClass ?? 'unknown') === 'unknown') {
        summary.awaitingClassificationSats += utxo.valueSats;
      } else {
        summary.assetProtectedSats += utxo.valueSats;
      }
    } else if (lane === 'reserved_ordinal_lane_btc') {
      summary.reservedSats += utxo.valueSats;
    } else if (display === 'user_frozen' || display === 'dust_quarantined') {
      summary.frozenSats += utxo.valueSats;
      if (display === 'user_frozen') summary.userFrozenSats += utxo.valueSats;
      else summary.dustQuarantinedSats += utxo.valueSats;
    } else if (evaluateEligibility(utxo, ctx).eligible) {
      summary.availableSats += utxo.valueSats;
    } else {
      summary.unavailableCleanSats += utxo.valueSats;
    }
  }

  return summary;
}
