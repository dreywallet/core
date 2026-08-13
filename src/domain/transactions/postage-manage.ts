import { parseCanonicalSatpoint } from '../ordinals/satpoint';
import type { BoundOrdinalBatchSelection } from './ordinal-transfer';

export type OrdinalPostageTarget =
  | { type: 'common_546' }
  | { type: 'compatible_10000' }
  | { type: 'minimum_standard' }
  | { type: 'keep_current' }
  | { type: 'custom'; customSats: string };

export interface OrdinalPostageSourceRequest {
  selection: BoundOrdinalBatchSelection;
  valueSats: bigint;
  classificationRevision: string;
  inscriptionIds: readonly string[];
  ordinalOutputDustSats: bigint;
  paymentChangeDustSats: bigint;
}

export interface OrdinalPostageSourcePlan {
  selection: BoundOrdinalBatchSelection;
  currentPostageSats: bigint;
  retainedPostageSats: bigint;
  returnedBtcSats: bigint;
  requiredTopUpSats: bigint;
}

export interface OrdinalPostagePlan {
  sources: OrdinalPostageSourcePlan[];
  returnedBtcSats: bigint;
  requiredTopUpSats: bigint;
  requiredTopUpSourceIndex: number | null;
}

export function summarizeOrdinalPostageRecovery(
  items: readonly { currentPostageSats: bigint; retainedPostageSats: bigint }[],
  feeSats: bigint,
): { recoveredSats: bigint; netRecoveredSats: bigint } {
  if (feeSats < 0n || items.some((item) => item.currentPostageSats < 0n || item.retainedPostageSats < 0n)) {
    throw new Error('invalid postage recovery summary');
  }
  const recoveredSats = items.reduce((sum, item) => sum +
    (item.currentPostageSats > item.retainedPostageSats
      ? item.currentPostageSats - item.retainedPostageSats
      : 0n), 0n);
  return {
    recoveredSats,
    netRecoveredSats: recoveredSats > feeSats ? recoveredSats - feeSats : 0n,
  };
}

export type OrdinalPostagePlanFailure =
  | 'invalid_selection'
  | 'ineligible_source'
  | 'stale_classification'
  | 'invalid_target'
  | 'multiple_top_ups';

export class OrdinalPostagePlanError extends Error {
  override readonly name = 'OrdinalPostagePlanError';
  constructor(readonly reason: OrdinalPostagePlanFailure, message: string) { super(message); }
}

export function resolveOrdinalPostageTarget(
  target: OrdinalPostageTarget,
  currentSats: bigint,
  dustSats: bigint,
): bigint {
  if (currentSats <= 0n || dustSats <= 0n) {
    throw new OrdinalPostagePlanError('invalid_target', 'invalid postage target context');
  }
  if (target.type === 'keep_current') return currentSats;
  if (target.type === 'minimum_standard') return dustSats;
  if (target.type === 'common_546') return dustSats > 546n ? dustSats : 546n;
  if (target.type === 'compatible_10000') return 10_000n;
  if (!/^(?:0|[1-9][0-9]*)$/u.test(target.customSats)) {
    throw new OrdinalPostagePlanError('invalid_target', 'custom postage is not canonical');
  }
  const custom = BigInt(target.customSats);
  if (custom < dustSats || custom > 10_000n) {
    throw new OrdinalPostagePlanError('invalid_target', 'custom postage is outside the standard range');
  }
  return custom;
}

/**
 * Plan source-local FIFO segments. Each protected source is exactly one offset-zero
 * inscription; only one source may require clean trailing funding and it is placed last.
 */
export function planOrdinalPostageManage(
  requests: readonly OrdinalPostageSourceRequest[],
  target: OrdinalPostageTarget,
): OrdinalPostagePlan {
  if (requests.length < 1 || requests.length > 16) {
    throw new OrdinalPostagePlanError('invalid_selection', 'postage management requires 1 to 16 sources');
  }
  const ids = new Set<string>();
  const outpoints = new Set<string>();
  const planned = requests.map((request): OrdinalPostageSourcePlan => {
    const parsed = parseCanonicalSatpoint(request.selection.satpoint);
    const outpointKey = `${request.selection.outpoint.txid}:${request.selection.outpoint.vout}`;
    if (!parsed || parsed.txid !== request.selection.outpoint.txid ||
        parsed.vout !== request.selection.outpoint.vout || parsed.offset !== 0n ||
        ids.has(request.selection.inscriptionId) || outpoints.has(outpointKey)) {
      throw new OrdinalPostagePlanError('invalid_selection', 'postage selection is ambiguous');
    }
    ids.add(request.selection.inscriptionId);
    outpoints.add(outpointKey);
    if (request.selection.classificationRevision !== request.classificationRevision) {
      throw new OrdinalPostagePlanError('stale_classification', 'postage source classification changed');
    }
    if (request.valueSats <= 0n || request.inscriptionIds.length !== 1 ||
        request.inscriptionIds[0] !== request.selection.inscriptionId ||
        request.ordinalOutputDustSats <= 0n || request.paymentChangeDustSats <= 0n) {
      throw new OrdinalPostagePlanError('ineligible_source', 'postage source is not a single offset-zero inscription');
    }
    let retained = resolveOrdinalPostageTarget(target, request.valueSats, request.ordinalOutputDustSats);
    let returned = request.valueSats > retained ? request.valueSats - retained : 0n;
    if (returned > 0n && returned < request.paymentChangeDustSats) {
      retained += returned;
      returned = 0n;
    }
    return {
      selection: { ...request.selection, outpoint: { ...request.selection.outpoint } },
      currentPostageSats: request.valueSats,
      retainedPostageSats: retained,
      returnedBtcSats: returned,
      requiredTopUpSats: retained > request.valueSats ? retained - request.valueSats : 0n,
    };
  });
  const topUps = planned.filter((source) => source.requiredTopUpSats > 0n);
  if (topUps.length > 1) {
    throw new OrdinalPostagePlanError('multiple_top_ups', 'more than one postage source requires clean top-up');
  }
  const order = (a: OrdinalPostageSourcePlan, b: OrdinalPostageSourcePlan): number =>
    a.selection.outpoint.txid.localeCompare(b.selection.outpoint.txid) ||
    a.selection.outpoint.vout - b.selection.outpoint.vout;
  const sources = planned.filter((source) => source.requiredTopUpSats === 0n).sort(order);
  if (topUps[0]) sources.push(topUps[0]);
  return {
    sources,
    returnedBtcSats: sources.reduce((sum, source) => sum + source.returnedBtcSats, 0n),
    requiredTopUpSats: sources.reduce((sum, source) => sum + source.requiredTopUpSats, 0n),
    requiredTopUpSourceIndex: topUps.length === 0 ? null : sources.length - 1,
  };
}
