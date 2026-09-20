/**
 * Derive bounded local change evidence from the durable outgoing journal.
 *
 * This is intentionally narrower than a transaction parser: the journal's
 * validated plan is the source of output role/script/value, while the stored
 * txid is the only transaction identity accepted here. The scan engine still
 * requires an exact gateway outpoint match and independently checks funding,
 * chain and burned-change bounds before any claim can affect eligibility.
 */
import type { Network } from '../domain/keys/derivation';
import { hashPlan } from '../domain/transactions/plan';
import type { StoredTransaction } from './cache-schemas';
import {
  MAX_LOCAL_CHANGE_CLAIMS,
  type LocalChangeClaim,
  type LocalChangeClaimRole,
} from './scan-engine';

const ACCEPTED_JOURNAL_STATUSES = new Set<StoredTransaction['status']>([
  'accepted', 'already_known', 'confirmed',
]);

export interface LocalTransactionJournalEntry {
  /** Exact encrypted-cache key under the `transactions` namespace. */
  cacheKey: string;
  transaction: StoredTransaction;
}

function journalPriority(status: StoredTransaction['status']): number {
  return status === 'confirmed' ? 1 : 0;
}

function claimRole(role: string): LocalChangeClaimRole | null {
  if (role === 'payment_change') return 'payment_change';
  // Postage is an asset-bearing output, so it is deliberately represented as
  // non-promotable ordinal change rather than being mistaken for clean BTC.
  if (role === 'ordinal_change' || role === 'postage') return 'ordinal_change';
  return null;
}

/**
 * Build scan claims from current, accepted journal plans.
 *
 * `null` means the local evidence is ambiguous or malformed and callers must
 * pass no claims for this scan. Legacy plans, rejected/conflicted records and
 * recipient outputs are ignored because they do not establish safe change
 * provenance. A current plan must bind its journal txid/planId/kind/network;
 * `planHash` is required as the immutable-plan marker even though the hash is
 * not recomputed here (plan validation owns that invariant).
 */
export function deriveLocalChangeClaims(
  entries: readonly LocalTransactionJournalEntry[],
  network: Network,
): LocalChangeClaim[] | null {
  // Journal history is unbounded. Keep the scan input bounded while giving
  // live mempool rows precedence over old confirmed rows, then newest rows
  // precedence within each class. Rows outside this window are deliberately
  // omitted: they receive no local claim and therefore remain degraded rather
  // than invalidating current claims or becoming spendable by assumption.
  const candidates = entries
    .filter(({ transaction }) => ACCEPTED_JOURNAL_STATUSES.has(transaction.status))
    .sort((a, b) => journalPriority(a.transaction.status) - journalPriority(b.transaction.status) ||
      b.transaction.createdAt - a.transaction.createdAt ||
      a.transaction.txid.localeCompare(b.transaction.txid))
    .slice(0, MAX_LOCAL_CHANGE_CLAIMS);
  const claims: LocalChangeClaim[] = [];
  const seenOutpoints = new Set<string>();
  for (const { cacheKey, transaction } of candidates) {
    const plan = transaction.plan;
    if (plan.version !== 4) continue;
    if (cacheKey !== transaction.txid || transaction.planId !== plan.planId ||
        transaction.kind !== plan.kind || plan.network !== network ||
        typeof plan.planHash !== 'string' || hashPlan(plan) !== plan.planHash) {
      return null;
    }

    for (const [vout, output] of plan.outputs.entries()) {
      const role = claimRole(output.role);
      if (role === null) continue;
      // A claim without a wallet-derived internal address cannot establish
      // the chain-1/burned-prefix provenance required by scan-engine.ts.
      if (output.derivation === undefined || output.derivation.chain !== 1 ||
          output.derivation.account !== plan.account ||
          (role === 'payment_change' && output.derivation.lane !== 'payment') ||
          (role === 'ordinal_change' && output.derivation.lane !== 'ordinals')) {
        return null;
      }
      const key = `${transaction.txid}:${vout}`;
      if (seenOutpoints.has(key)) return null;
      seenOutpoints.add(key);
      claims.push({
        txid: transaction.txid,
        vout,
        valueSats: output.valueSats,
        scriptPubKey: output.scriptPubKey,
        role,
      });
      if (claims.length === MAX_LOCAL_CHANGE_CLAIMS) return claims;
    }
  }
  return claims;
}
