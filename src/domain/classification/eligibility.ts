/**
 * THE single §11.2 eligibility predicate.
 *
 * Every ordinary send, fee input, RBF, CPFP, consolidation, Send Max,
 * marketplace funding input, and dApp funding input MUST call
 * evaluateEligibility and nothing else. No UI toggle, expert mode, manual
 * coin selection, or site request may override a protected or unknown
 * classification (§11.2) — accordingly, this module exports no bypass.
 */
import type { FreshnessReport } from '../gateway/freshness';
import { isAuthoritativeCardinalClean } from '../gateway/contract';
import { outpointKey, type WalletUtxo } from './types';

export type IneligibleReason =
  | 'not_cardinal_clean'
  | 'classification_stale'
  | 'user_frozen'
  | 'dust_quarantined'
  | 'unconfirmed_not_wallet_change'
  | 'plan_locked'
  | 'uneconomic';

export interface EligibilityContext {
  /** From evaluateFreshness over the current verified status (§18.4). */
  freshness: FreshnessReport;
  /** The gateway's currently active classification revision. */
  activeRevision: string;
  /** Outpoints ("txid:vout") locked by pending plans. Empty until M7. */
  lockedOutpoints: ReadonlySet<string>;
  /** Marginal fee to spend this input at the plan's fee rate (M6 read views use 0n). */
  marginalFeeSatsFor: (utxo: WalletUtxo) => bigint;
}

export interface EligibilityResult {
  eligible: boolean;
  reasons: IneligibleReason[];
}

/**
 * §11.2, all seven conditions, in spec order:
 *  1. class is cardinal_clean;
 *  2. backend classification fresh under §18 (status spend-eligible AND this
 *     UTXO classified against the active revision);
 *  3. not user-frozen;
 *  4. not suspicious dust;
 *  5. confirmed, or wallet-created unconfirmed change;
 *  6. not locked by another pending plan;
 *  7. positive effective value after marginal fee.
 */
export function evaluateEligibility(
  utxo: WalletUtxo,
  ctx: EligibilityContext,
): EligibilityResult {
  const reasons: IneligibleReason[] = [];

  if (!isAuthoritativeCardinalClean(utxo.facts)) reasons.push('not_cardinal_clean');

  const revisionFresh =
    utxo.facts !== null && utxo.facts.classificationRevision === ctx.activeRevision;
  if (!ctx.freshness.spendEligible || !revisionFresh) reasons.push('classification_stale');

  if (utxo.flags.userFrozen) reasons.push('user_frozen');
  if (utxo.flags.dustQuarantined) reasons.push('dust_quarantined');
  if (utxo.height === null && !utxo.walletCreatedChange) {
    reasons.push('unconfirmed_not_wallet_change');
  }
  if (ctx.lockedOutpoints.has(outpointKey(utxo.outpoint))) reasons.push('plan_locked');
  if (utxo.valueSats - ctx.marginalFeeSatsFor(utxo) <= 0n) reasons.push('uneconomic');

  return { eligible: reasons.length === 0, reasons };
}
