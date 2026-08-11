/**
 * Suspicious-dust quarantine heuristic (spec §11.1 dust_quarantined, §11.2
 * condition 4).
 *
 * The spec leaves "suspicious dust" undefined. Keep the automatic quarantine
 * tied to Bitcoin's standard script-specific dust limit rather than an
 * arbitrary round-number payment threshold. Wallet-created change and the
 * account's first funding remain exempt.
 */
import type { WalletUtxo } from './types';
import { scriptDustSats } from '../transactions/fees';

export function isSuspiciousDust(utxo: WalletUtxo, isAccountFirstFunding: boolean): boolean {
  return (
    utxo.valueSats < scriptDustSats(utxo.scriptPubKey) &&
    !utxo.walletCreatedChange &&
    !isAccountFirstFunding
  );
}
