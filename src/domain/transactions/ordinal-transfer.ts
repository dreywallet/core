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
