import { parseCanonicalSatpoint } from '../ordinals/satpoint';

export interface OrdinalInscriptionLocation {
  inscriptionId: string;
  satpoint: string;
}

export interface OrdinalInscriptionGroup {
  key: string;
  offset: bigint;
  target: boolean;
  items: Array<{ inscriptionId: string; offset: bigint; target: boolean }>;
}

export interface OrdinalPartitionRequest {
  inscriptionId: string;
  inputOffset: bigint;
  minimumOutputSats: bigint;
  preferredOutputSats?: bigint;
  target: boolean;
}

export interface OrdinalPartition {
  inscriptionId: string;
  inputOffset: bigint;
  outputOffset: bigint;
  valueSats: bigint;
  target: boolean;
}

export interface BoundOrdinalBatchSelection {
  inscriptionId: string;
  outpoint: { txid: string; vout: number };
  satpoint: string;
  classificationRevision: string;
}

export interface OrdinalBatchSourceRequest {
  txid: string;
  vout: number;
  valueSats: bigint;
  classificationRevision: string;
  inscriptions: readonly OrdinalInscriptionLocation[];
  selections: readonly BoundOrdinalBatchSelection[];
  recipientMinimumOutputSats: bigint;
  preferredPostageSats: bigint;
  sourceChangeMinimumSats: bigint;
}

export interface OrdinalBatchGroupPlan {
  key: string;
  inscriptionIds: string[];
  inputOffset: bigint;
  outputOffset: bigint;
  valueSats: bigint;
  sourceOutputIndex: number;
}

export type OrdinalBatchSourceOutputPlan =
  | { role: 'postage'; valueSats: bigint; groupKey: string }
  | { role: 'payment_change'; valueSats: bigint };

export interface OrdinalBatchSourcePlan {
  txid: string;
  vout: number;
  valueSats: bigint;
  groups: OrdinalBatchGroupPlan[];
  outputs: OrdinalBatchSourceOutputPlan[];
  returnedBtcSats: bigint;
  requiredTopUpSats: bigint;
}

export interface OrdinalBatchSatFlowPlan {
  sources: OrdinalBatchSourcePlan[];
  inscriptionCount: number;
  groupCount: number;
  requiredTopUpSourceIndex: number | null;
}

export type OrdinalBatchPlanFailure =
  | 'invalid_selection'
  | 'incomplete_source'
  | 'stale_classification'
  | 'unprovable_satpoint'
  | 'unsafe_partition'
  | 'multiple_top_ups';

export class OrdinalBatchPlanError extends Error {
  override readonly name = 'OrdinalBatchPlanError';

  constructor(
    readonly reason: OrdinalBatchPlanFailure,
    message: string,
    readonly outpoint?: { txid: string; vout: number },
  ) {
    super(message);
  }
}

/** Canonical immutable order bound into a batch intent and activity record. */
export function canonicalOrdinalBatchSelections(
  selections: readonly BoundOrdinalBatchSelection[],
): BoundOrdinalBatchSelection[] {
  const ids = new Set<string>();
  const bound = selections.map((selection) => {
    const parsed = parseCanonicalSatpoint(selection.satpoint);
    if (!/^[0-9a-f]{64}i(?:0|[1-9][0-9]*)$/u.test(selection.inscriptionId) ||
        !parsed || parsed.txid !== selection.outpoint.txid || parsed.vout !== selection.outpoint.vout ||
        selection.classificationRevision.length === 0 || ids.has(selection.inscriptionId)) {
      throw new OrdinalBatchPlanError('invalid_selection', 'batch selection binding is invalid');
    }
    ids.add(selection.inscriptionId);
    return { selection: { ...selection, outpoint: { ...selection.outpoint } }, offset: parsed.offset };
  });
  return bound.sort((a, b) =>
    a.selection.outpoint.txid.localeCompare(b.selection.outpoint.txid) ||
    a.selection.outpoint.vout - b.selection.outpoint.vout ||
    (a.offset < b.offset ? -1 : a.offset > b.offset ? 1 :
      a.selection.inscriptionId.localeCompare(b.selection.inscriptionId)))
    .map(({ selection }) => selection);
}

export type OrdinalInscriptionGroupFailure =
  | 'unprovable_satpoint'
  | 'ambiguous_set'
  | 'co_located';

export class OrdinalInscriptionGroupError extends Error {
  override readonly name = 'OrdinalInscriptionGroupError';

  constructor(
    readonly reason: OrdinalInscriptionGroupFailure,
    message: string,
  ) {
    super(message);
  }
}

/**
 * Preserve a small inscription's existing postage, cap larger postage at the
 * wallet preference, and add clean trailing funding only when dust requires it.
 */
export function automaticOrdinalPostage(
  inputValueSats: bigint,
  preferredPostageSats: bigint,
  dustSats: bigint,
): bigint {
  if (inputValueSats <= 0n || preferredPostageSats <= 0n || dustSats <= 0n) {
    throw new Error('invalid automatic ordinal postage');
  }
  const preservedOrPreferred = inputValueSats < preferredPostageSats
    ? inputValueSats
    : preferredPostageSats;
  return preservedOrPreferred > dustSats ? preservedOrPreferred : dustSats;
}

/** Parse and group every inscription in one exact current outpoint. */
export function groupOrdinalInscriptions(input: {
  txid: string;
  vout: number;
  valueSats: bigint;
  targetInscriptionId: string;
  inscriptions: readonly OrdinalInscriptionLocation[];
}): OrdinalInscriptionGroup[] {
  const located = input.inscriptions.map((inscription) => {
    const parsed = parseCanonicalSatpoint(inscription.satpoint);
    if (
      !parsed ||
      parsed.txid !== input.txid ||
      parsed.vout !== input.vout ||
      parsed.offset >= input.valueSats
    ) {
      throw new OrdinalInscriptionGroupError(
        'unprovable_satpoint',
        'unprovable inscription satpoint',
      );
    }
    return {
      inscriptionId: inscription.inscriptionId,
      offset: parsed.offset,
      target: inscription.inscriptionId === input.targetInscriptionId,
    };
  });
  if (
    located.filter((item) => item.target).length !== 1 ||
    new Set(located.map((item) => item.inscriptionId)).size !== located.length
  ) {
    throw new OrdinalInscriptionGroupError('ambiguous_set', 'ambiguous inscription set');
  }

  const byOffset = new Map<string, typeof located>();
  for (const item of located) {
    const key = item.offset.toString();
    const group = byOffset.get(key) ?? [];
    group.push(item);
    byOffset.set(key, group);
  }
  return [...byOffset.values()].map((items) => {
    const sorted = [...items].sort((a, b) => a.inscriptionId.localeCompare(b.inscriptionId));
    const target = sorted.some((item) => item.target);
    if (target && sorted.length !== 1) {
      throw new OrdinalInscriptionGroupError(
        'co_located',
        'target inscription is co-located with another id',
      );
    }
    return {
      key: sorted[0]!.inscriptionId,
      offset: sorted[0]!.offset,
      target,
      items: sorted,
    };
  });
}

/**
 * Partition one input's FIFO sat stream into one non-dust output per protected
 * inscription group. Preferred sizes are used when protected boundaries permit
 * them and otherwise fall back to the hard minimum. Earliest-safe boundaries
 * maximize value available to later groups.
 * The final output may be extended with cardinal-clean sats appended after the
 * protected input, which cannot change any protected sat's FIFO destination.
 */
export function partitionOrdinalSatFlow(
  inputValueSats: bigint,
  requests: readonly OrdinalPartitionRequest[],
): OrdinalPartition[] {
  if (
    inputValueSats <= 0n ||
    requests.length === 0 ||
    requests.filter((item) => item.target).length !== 1
  ) {
    throw new Error('invalid ordinal partition request');
  }
  const sorted = [...requests].sort((a, b) =>
    a.inputOffset === b.inputOffset
      ? a.inscriptionId.localeCompare(b.inscriptionId)
      : a.inputOffset < b.inputOffset ? -1 : 1);
  const ids = new Set<string>();
  for (let index = 0; index < sorted.length; index += 1) {
    const item = sorted[index]!;
    if (
      ids.has(item.inscriptionId) ||
      item.inputOffset < 0n ||
      item.inputOffset >= inputValueSats ||
      item.minimumOutputSats <= 0n ||
      (item.preferredOutputSats !== undefined &&
        item.preferredOutputSats < item.minimumOutputSats) ||
      (index > 0 && sorted[index - 1]!.inputOffset === item.inputOffset)
    ) {
      throw new Error('inscriptions cannot be partitioned safely');
    }
    ids.add(item.inscriptionId);
  }
  const result: OrdinalPartition[] = [];
  let start = 0n;
  for (let index = 0; index < sorted.length; index += 1) {
    const item = sorted[index]!;
    const preferredSized = start + (item.preferredOutputSats ?? item.minimumOutputSats);
    const minimumSized = start + item.minimumOutputSats;
    let end = inputValueSats > minimumSized ? inputValueSats : minimumSized;
    if (index + 1 < sorted.length) {
      const earliestAfterInscription = item.inputOffset + 1n;
      end = earliestAfterInscription > preferredSized ? earliestAfterInscription : preferredSized;
      if (end > sorted[index + 1]!.inputOffset) {
        end = earliestAfterInscription > minimumSized ? earliestAfterInscription : minimumSized;
        if (end > sorted[index + 1]!.inputOffset) {
          throw new Error('inscriptions cannot be partitioned safely');
        }
      }
    }
    if (end - start < item.minimumOutputSats || item.inputOffset < start || item.inputOffset >= end) {
      throw new Error('inscriptions cannot be partitioned safely');
    }
    result.push({
      inscriptionId: item.inscriptionId,
      inputOffset: item.inputOffset,
      outputOffset: item.inputOffset - start,
      valueSats: end - start,
      target: item.target,
    });
    start = end;
  }
  return result;
}

/**
 * Plan all protected source segments for an atomic one-recipient transfer.
 * Every source is self-balancing, except one optional top-up source which is
 * placed last so appended clean inputs cannot shift a later protected sat.
 */
export function planOrdinalBatchSatFlow(
  requests: readonly OrdinalBatchSourceRequest[],
): OrdinalBatchSatFlowPlan {
  const selections = canonicalOrdinalBatchSelections(requests.flatMap((request) => request.selections));
  const selectionIds = new Set(selections.map((selection) => selection.inscriptionId));
  if (
    requests.length === 0 || selections.length === 0 || selections.length > 16 ||
    selectionIds.size !== selections.length
  ) {
    throw new OrdinalBatchPlanError('invalid_selection', 'batch selection must contain 1 to 16 unique inscriptions');
  }
  const requestKeys = new Set<string>();
  const planned = requests.map((request): OrdinalBatchSourcePlan => {
    const source = { txid: request.txid, vout: request.vout };
    const sourceKey = `${request.txid}:${request.vout}`;
    if (
      requestKeys.has(sourceKey) || request.valueSats <= 0n ||
      request.recipientMinimumOutputSats <= 0n ||
      request.preferredPostageSats < request.recipientMinimumOutputSats ||
      request.sourceChangeMinimumSats <= 0n
    ) {
      throw new OrdinalBatchPlanError('invalid_selection', 'batch source is invalid', source);
    }
    requestKeys.add(sourceKey);
    if (request.selections.some((selection) =>
      selection.outpoint.txid !== request.txid || selection.outpoint.vout !== request.vout)) {
      throw new OrdinalBatchPlanError('invalid_selection', 'selection is bound to another source', source);
    }
    if (request.selections.some((selection) =>
      selection.classificationRevision !== request.classificationRevision)) {
      throw new OrdinalBatchPlanError('stale_classification', 'selection classification changed', source);
    }
    const selectedById = new Map(request.selections.map((selection) => [selection.inscriptionId, selection]));
    const factsById = new Map(request.inscriptions.map((inscription) => [inscription.inscriptionId, inscription]));
    if (
      selectedById.size !== request.selections.length ||
      factsById.size !== request.inscriptions.length ||
      selectedById.size !== factsById.size ||
      [...factsById.keys()].some((id) => !selectedById.has(id))
    ) {
      throw new OrdinalBatchPlanError(
        'incomplete_source',
        'every inscription in a selected source must be included',
        source,
      );
    }
    const byOffset = new Map<string, Array<{ inscriptionId: string; offset: bigint }>>();
    for (const [inscriptionId, fact] of factsById) {
      const selected = selectedById.get(inscriptionId)!;
      if (selected.satpoint !== fact.satpoint) {
        throw new OrdinalBatchPlanError('unprovable_satpoint', 'selected inscription location changed', source);
      }
      const parsed = parseCanonicalSatpoint(fact.satpoint);
      if (!parsed || parsed.txid !== request.txid || parsed.vout !== request.vout ||
          parsed.offset >= request.valueSats) {
        throw new OrdinalBatchPlanError('unprovable_satpoint', 'unprovable inscription satpoint', source);
      }
      const key = parsed.offset.toString();
      const group = byOffset.get(key) ?? [];
      group.push({ inscriptionId, offset: parsed.offset });
      byOffset.set(key, group);
    }
    const groups = [...byOffset.values()]
      .map((items) => ({
        key: [...items].sort((a, b) => a.inscriptionId.localeCompare(b.inscriptionId))[0]!.inscriptionId,
        inscriptionIds: items.map((item) => item.inscriptionId).sort((a, b) => a.localeCompare(b)),
        inputOffset: items[0]!.offset,
      }))
      .sort((a, b) => a.inputOffset === b.inputOffset
        ? a.key.localeCompare(b.key)
        : a.inputOffset < b.inputOffset ? -1 : 1);
    if (groups.length === 0) {
      throw new OrdinalBatchPlanError('invalid_selection', 'batch source has no inscriptions', source);
    }
    const partitions: OrdinalBatchGroupPlan[] = [];
    const outputs: OrdinalBatchSourceOutputPlan[] = [];
    let cursor = 0n;
    for (let index = 0; index < groups.length; index += 1) {
      const group = groups[index]!;
      const gap = group.inputOffset - cursor;
      if (gap >= request.sourceChangeMinimumSats) {
        outputs.push({ role: 'payment_change', valueSats: gap });
        cursor = group.inputOffset;
      }
      const minimumEnd = cursor + request.recipientMinimumOutputSats;
      const preferredEnd = cursor + request.preferredPostageSats;
      const containingEnd = group.inputOffset + 1n;
      let end = preferredEnd > containingEnd ? preferredEnd : containingEnd;
      const next = groups[index + 1];
      if (next && end > next.inputOffset) {
        end = minimumEnd > containingEnd ? minimumEnd : containingEnd;
      }
      if (next && end > next.inputOffset) {
        throw new OrdinalBatchPlanError(
          'unsafe_partition',
          'inscription groups cannot be partitioned into standard outputs',
          source,
        );
      }
      if (group.inputOffset < cursor || group.inputOffset >= end || end - cursor < request.recipientMinimumOutputSats) {
        throw new OrdinalBatchPlanError('unsafe_partition', 'inscription group boundary is unsafe', source);
      }
      const sourceOutputIndex = outputs.length;
      outputs.push({ role: 'postage', valueSats: end - cursor, groupKey: group.key });
      partitions.push({
        key: group.key,
        inscriptionIds: group.inscriptionIds,
        inputOffset: group.inputOffset,
        outputOffset: group.inputOffset - cursor,
        valueSats: end - cursor,
        sourceOutputIndex,
      });
      cursor = end;
    }
    const tail = request.valueSats - cursor;
    if (tail >= request.sourceChangeMinimumSats) {
      outputs.push({ role: 'payment_change', valueSats: tail });
      cursor += tail;
    } else if (tail > 0n) {
      const lastOutput = outputs.at(-1);
      const lastPartition = partitions.at(-1);
      if (lastOutput?.role !== 'postage' || !lastPartition) {
        throw new OrdinalBatchPlanError('unsafe_partition', 'cardinal tail cannot be routed safely', source);
      }
      lastOutput.valueSats += tail;
      lastPartition.valueSats += tail;
      cursor += tail;
    }
    const outputTotal = outputs.reduce((sum, output) => sum + output.valueSats, 0n);
    const returnedBtcSats = outputs
      .filter((output) => output.role === 'payment_change')
      .reduce((sum, output) => sum + output.valueSats, 0n);
    return {
      ...source,
      valueSats: request.valueSats,
      groups: partitions,
      outputs,
      returnedBtcSats,
      requiredTopUpSats: outputTotal > request.valueSats
        ? outputTotal - request.valueSats
        : 0n,
    };
  });
  const topUps = planned.filter((source) => source.requiredTopUpSats > 0n);
  if (topUps.length > 1) {
    throw new OrdinalBatchPlanError(
      'multiple_top_ups',
      'more than one inscription source requires clean postage top-up',
    );
  }
  const byOutpoint = (a: OrdinalBatchSourcePlan, b: OrdinalBatchSourcePlan): number =>
    a.txid.localeCompare(b.txid) || a.vout - b.vout;
  const ordered = planned.filter((source) => source.requiredTopUpSats === 0n).sort(byOutpoint);
  if (topUps[0]) ordered.push(topUps[0]);
  return {
    sources: ordered,
    inscriptionCount: selections.length,
    groupCount: ordered.reduce((sum, source) => sum + source.groups.length, 0),
    requiredTopUpSourceIndex: topUps.length === 0 ? null : ordered.length - 1,
  };
}
