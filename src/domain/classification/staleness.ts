/**
 * §11.4 data-gating states.
 *
 * While classification is stale or conflicting, receive and cached read-only
 * views remain available but every spend-shaped action is blocked. The UI
 * must distinguish backend unavailable, index lag, reorg reconciliation, and
 * conflicting source data — hence a discriminated state, not a boolean.
 */
import { z } from 'zod';
import { isGatewaySyncing, type GatewayStatusView } from '../gateway/status-view';

export const dataGatingStateSchema = z.enum([
  'fresh',
  'backend_unreachable',
  'backend_read_only',
  'index_lag',
  'reorg_reconciliation',
  'conflicting_sources',
]);
export type DataGatingState = z.infer<typeof dataGatingStateSchema>;

/** §11.4's blocked list; M6 read surfaces show it, M7 flows enforce it. */
export const BLOCKED_WHILE_STALE = [
  'native_send',
  'native_batch_send',
  'dapp_signature',
  'rbf',
  'cpfp',
  'consolidation',
  'rescue_sweep',
  'signed_psbt_finalize',
] as const;
export type BlockedAction = (typeof BLOCKED_WHILE_STALE)[number];

export interface DataGating {
  state: DataGatingState;
  /** Empty exactly when state is 'fresh'. */
  blockedActions: readonly BlockedAction[];
}

/**
 * Derive the gating state from the read-time gateway view plus scan-recorded
 * conflicts.
 *
 * `hasConflictingSources` is set by the scan engine when a snapshot/classify
 * pair disagreed on revision even after a refetch; it outranks lag because it
 * is positive evidence of inconsistency, not mere latency. Tip divergence
 * without conflict reads as reorg reconciliation when heights disagree only
 * by hash, index lag otherwise. `cachedRevisionStale` — the last scan's
 * classification revision no longer being the gateway's active one — also
 * reads as index lag even while the gateway itself is healthy: our cached
 * facts lag the index and every spend-shaped action must gate until a rescan
 * (§11.4, §18.4).
 */
export function deriveDataGating(
  view: GatewayStatusView,
  input: {
    hasConflictingSources: boolean;
    tipsDivergeByHashOnly: boolean;
    cachedRevisionStale: boolean;
  },
): DataGating {
  const gate = (state: DataGatingState): DataGating => ({
    state,
    blockedActions: state === 'fresh' ? [] : BLOCKED_WHILE_STALE,
  });

  if (input.hasConflictingSources) return gate('conflicting_sources');
  if (view.state === 'unreachable') return gate('backend_unreachable');
  if (view.reorgState === 'verifying' || view.reorgState === 'reconciling' || view.reorgState === 'manual_intervention') {
    return gate('reorg_reconciliation');
  }
  if (isGatewaySyncing(view)) {
    return gate(input.tipsDivergeByHashOnly ? 'reorg_reconciliation' : 'index_lag');
  }
  if (view.state === 'read_only') return gate('backend_read_only');
  if (view.classificationState === 'advancing') return gate('index_lag');
  if (view.state === 'stale') {
    return gate(input.tipsDivergeByHashOnly ? 'reorg_reconciliation' : 'index_lag');
  }
  if (input.cachedRevisionStale) return gate('index_lag');
  return gate('fresh');
}
