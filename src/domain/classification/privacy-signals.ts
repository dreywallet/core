/**
 * Local privacy signals for the §14.4 UTXO manager.
 *
 * Every signal here is derived from data the wallet already holds and can
 * prove: its own UTXO set, the plans of transactions it built itself, and the
 * user's own §14.4 labels. Nothing is asked of the gateway, and no third-party
 * attribution, exchange tagging, or chain-surveillance verdict is imported
 * (§6.2 forbids querying an independent indexer; §1 makes classification a
 * security boundary rather than a presentation feature).
 *
 * Signals are DERIVED, NEVER STORED — the same treatment displayClass gets in
 * types.ts, and for the same reason: a stored verdict goes stale silently.
 *
 * They are advisory. They add no IneligibleReason, gate nothing, and grant no
 * bypass; §11.2 eligibility is unaffected by anything in this module.
 *
 * Deliberately absent: any numeric score, percentage, or letter grade. A
 * per-UTXO number invites score-maximizing over threat-model thinking, and
 * §2.1 orders the audience everyday-holders-first.
 *
 * STAGED, NOT WIRED. Only walletPrivacyNotes is currently rendered. The
 * per-UTXO signals below are deliberately not surfaced in v1: under §8.1's
 * pinned receive address `shared_address` fires on nearly every payment output
 * (saying what the wallet-wide note already says), `dust_attack` restates the
 * §11.2 dust_quarantined reason the row already shows, and the two merge
 * signals describe linkage that already happened and cannot be undone. A
 * warning a user cannot act on is anxiety, not information. They become
 * meaningful once a rotating external-address mode exists, so they are kept
 * here under test rather than rewritten later from memory.
 *
 * Pure domain module: no browser APIs, no network, bigint sats internally.
 */
import { outpointKey, type WalletOutpoint, type WalletUtxo } from './types';

/**
 * Per-UTXO signals, each differentiating: a signal that fires on every row
 * carries no information. Wallet-wide facts belong in WalletPrivacyNote.
 */
export type UtxoPrivacySignal =
  /** §11.1 suspicious unsolicited dust — a probe to link this wallet's coins. */
  | 'dust_attack'
  /** Another current output sits on the same address, publicly linking them. */
  | 'shared_address'
  /** Wallet change from a transaction that spent several inputs at once. */
  | 'merged_origin'
  /** Those merged inputs carried differing §14.4 labels. */
  | 'mixed_label_origin';

/** Wallet-wide facts, reported once rather than on every row. */
export type WalletPrivacyNote =
  /** §8.1: v1 pins the external address to chain 0 / index 0. */
  | 'stable_receive_address';

export interface PrivacySignalContext {
  /** Current wallet outputs per address slot — see addressSlotKey. */
  utxosPerAddress: ReadonlyMap<string, number>;
  /**
   * Input outpoints of transactions this wallet built, keyed by the creating
   * txid. Only wallet-created transactions appear: the wallet cannot see the
   * inputs of a transaction someone else made (SnapshotHistoryEntry carries no
   * input/output sets), so merge signals are reported only where provable.
   */
  walletTransactionInputs: ReadonlyMap<string, readonly WalletOutpoint[]>;
  /**
   * labelGroupKey per outpoint key. Retained across spends so a change output
   * can still report the labels of the inputs that funded it.
   */
  labelGroupByOutpoint: ReadonlyMap<string, string>;
}

/** Identifies one derived address; two UTXOs sharing it share an address. */
export function addressSlotKey(utxo: WalletUtxo): string {
  return `${utxo.account}:${utxo.lane}:${utxo.chain}:${utxo.addressIndex}`;
}

export function countUtxosPerAddress(utxos: readonly WalletUtxo[]): Map<string, number> {
  const counts = new Map<string, number>();
  for (const utxo of utxos) {
    const key = addressSlotKey(utxo);
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  return counts;
}

/**
 * Signals for one UTXO, in a fixed order so the list renders stably.
 *
 * Each condition understates rather than overstates. shared_address counts only
 * outputs still unspent, so an address that received twice and had one output
 * spent stays quiet; merge signals require a transaction this wallet built.
 * An advisory surface that cries wolf is worse than one that stays quiet.
 */
export function utxoPrivacySignals(
  utxo: WalletUtxo,
  ctx: PrivacySignalContext,
): UtxoPrivacySignal[] {
  const signals: UtxoPrivacySignal[] = [];

  if (utxo.flags.dustQuarantined) signals.push('dust_attack');

  if ((ctx.utxosPerAddress.get(addressSlotKey(utxo)) ?? 0) > 1) {
    signals.push('shared_address');
  }

  const inputs = utxo.walletCreatedChange
    ? ctx.walletTransactionInputs.get(utxo.outpoint.txid)
    : undefined;
  if (inputs !== undefined && inputs.length > 1) {
    signals.push('merged_origin');

    const groups = new Set<string>();
    for (const input of inputs) {
      const group = ctx.labelGroupByOutpoint.get(outpointKey(input));
      if (group !== undefined) groups.add(group);
    }
    if (groups.size > 1) signals.push('mixed_label_origin');
  }

  return signals;
}

/**
 * Wallet-wide notes. Reported once in the UTXO manager header rather than
 * per row: under §8.1's stable external address the reuse note would otherwise
 * fire on nearly every payment output, which is both true and useless.
 */
export function walletPrivacyNotes(input: {
  externalAddressRotates: boolean;
}): WalletPrivacyNote[] {
  return input.externalAddressRotates ? [] : ['stable_receive_address'];
}
