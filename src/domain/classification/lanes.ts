/**
 * Wrong-lane detection states (spec §12) — detection only in M6; rescue and
 * sweep construction land with M7 transactions.
 */
import type { WalletUtxo } from './types';

export type LaneState =
  /** Asset class matches the lane's purpose. */
  | 'normal'
  /**
   * §12.1: a detected protected asset at a payment-lane address. Frozen
   * before ever appearing in Available now; surfaces as "Protected in
   * the wrong address".
   */
  | 'protected_wrong_address'
  /**
   * §12.2: plain BTC at an ordinal-lane address. Reserved (kept for postage,
   * never counted in Available now) until swept.
   */
  | 'reserved_ordinal_lane_btc';

const PROTECTED_CLASSES = new Set(['inscribed', 'rare_sat', 'runic_or_unsupported', 'mixed']);

export function laneState(utxo: WalletUtxo): LaneState {
  const primary = utxo.facts?.primaryClass ?? 'unknown';
  if (utxo.lane === 'payment') {
    // 'unknown' at a payment address is not a wrong-lane detection — it is
    // merely unclassified (already spend-blocked by §11.2). Claiming
    // "Protected in the wrong address" for it would assert a detection that
    // never happened.
    return PROTECTED_CLASSES.has(primary) ? 'protected_wrong_address' : 'normal';
  }
  // Ordinals lane: protected classes are where they belong; clean BTC is
  // reserved. Unknown/unclassified stays 'normal' here — it is already
  // spend-blocked by the §11.2 predicate, and inventing a wrong-lane warning
  // for it would misstate what we know.
  return primary === 'cardinal_clean' ? 'reserved_ordinal_lane_btc' : 'normal';
}
