import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import {
  automaticOrdinalPostage,
  groupOrdinalInscriptions,
  OrdinalInscriptionGroupError,
  partitionOrdinalSatFlow,
  planOrdinalBatchSatFlow,
} from '../../src/domain/transactions/ordinal-transfer';
import { parseCanonicalSatpoint } from '../../src/domain/ordinals/satpoint';

const TXID = 'ab'.repeat(32);
const ids = Array.from({ length: 6 }, (_, index) => `${index.toString(16).padStart(64, '0')}i0`);

describe('M9X ordinal transfer partitioning', () => {
  it('parses only canonical satpoints with protocol-sized numeric fields', () => {
    expect(parseCanonicalSatpoint(`${TXID}:4294967295:18446744073709551615`)).toEqual({
      txid: TXID,
      vout: 0xffffffff,
      offset: 0xffffffffffffffffn,
    });
    expect(parseCanonicalSatpoint(`${TXID}:4294967296:7`)).toBeNull();
    expect(parseCanonicalSatpoint(`${TXID}:0:18446744073709551616`)).toBeNull();
    expect(parseCanonicalSatpoint(`${TXID}:0:100000000000000000000`)).toBeNull();
  });

  it.each([
    ['first sat', 0n],
    ['middle sat', 25_000n],
    ['last sat', 49_999n],
    ['output boundary', 10_000n],
    ['fee-tail boundary', 39_999n],
  ])('preserves a target at the %s', (_name, targetOffset) => {
    const partitions = partitionOrdinalSatFlow(50_000n, [{
      inscriptionId: ids[0]!,
      inputOffset: targetOffset,
      minimumOutputSats: 10_000n,
      target: true,
    }]);
    expect(partitions).toEqual([{
      inscriptionId: ids[0],
      inputOffset: targetOffset,
      outputOffset: targetOffset,
      valueSats: 50_000n,
      target: true,
    }]);

    expect(partitionOrdinalSatFlow(20_000n, [
      {
        inscriptionId: ids[0]!,
        inputOffset: 0n,
        minimumOutputSats: 330n,
        preferredOutputSats: 10_000n,
        target: true,
      },
      {
        inscriptionId: ids[1]!,
        inputOffset: 546n,
        minimumOutputSats: 330n,
        target: false,
      },
    ])[0]).toMatchObject({ valueSats: 330n, target: true });
  });

  it('preserves small postage and tops up only when dust requires it', () => {
    expect(automaticOrdinalPostage(546n, 10_000n, 330n)).toBe(546n);
    expect(automaticOrdinalPostage(20_000n, 10_000n, 330n)).toBe(10_000n);
    expect(automaticOrdinalPostage(200n, 10_000n, 330n)).toBe(330n);

    const partitions = partitionOrdinalSatFlow(200n, [{
      inscriptionId: ids[0]!,
      inputOffset: 0n,
      minimumOutputSats: 330n,
      target: true,
    }]);
    expect(partitions).toEqual([{
      inscriptionId: ids[0],
      inputOffset: 0n,
      outputOffset: 0n,
      valueSats: 330n,
      target: true,
    }]);
  });

  it('keeps distinct retained groups in FIFO order with their absolute sat positions', () => {
    const partitions = partitionOrdinalSatFlow(60_000n, [
      { inscriptionId: ids[2]!, inputOffset: 35_000n, minimumOutputSats: 10_000n, target: false },
      { inscriptionId: ids[0]!, inputOffset: 2_000n, minimumOutputSats: 10_000n, target: false },
      { inscriptionId: ids[1]!, inputOffset: 20_000n, minimumOutputSats: 10_000n, target: true },
    ]);
    expect(partitions.map((item) => item.inscriptionId)).toEqual([ids[0], ids[1], ids[2]]);
    let outputStart = 0n;
    for (const partition of partitions) {
      expect(outputStart + partition.outputOffset).toBe(partition.inputOffset);
      outputStart += partition.valueSats;
    }
    expect(outputStart).toBe(60_000n);
  });

  it('rejects a co-located target but preserves a co-located retained group', () => {
    expect(() => groupOrdinalInscriptions({
      txid: TXID,
      vout: 1,
      valueSats: 50_000n,
      targetInscriptionId: ids[0]!,
      inscriptions: [
        { inscriptionId: ids[0]!, satpoint: `${TXID}:1:7` },
        { inscriptionId: ids[1]!, satpoint: `${TXID}:1:7` },
      ],
    })).toThrow(/co-located/u);

    const groups = groupOrdinalInscriptions({
      txid: TXID,
      vout: 1,
      valueSats: 50_000n,
      targetInscriptionId: ids[2]!,
      inscriptions: [
        { inscriptionId: ids[0]!, satpoint: `${TXID}:1:7` },
        { inscriptionId: ids[1]!, satpoint: `${TXID}:1:7` },
        { inscriptionId: ids[2]!, satpoint: `${TXID}:1:20000` },
      ],
    });
    expect(groups.find((group) => !group.target)?.items.map((item) => item.inscriptionId))
      .toEqual([ids[0], ids[1]]);
  });

  it('fails closed for wrong outpoints, missing targets, duplicate IDs, and invalid offsets', () => {
    const base = {
      txid: TXID,
      vout: 0,
      valueSats: 20_000n,
      targetInscriptionId: ids[0]!,
    };
    expect(() => groupOrdinalInscriptions({
      ...base,
      inscriptions: [{ inscriptionId: ids[0]!, satpoint: `${TXID}:1:0` }],
    })).toThrow(/satpoint/u);
    expect(() => groupOrdinalInscriptions({
      ...base,
      inscriptions: [{ inscriptionId: ids[1]!, satpoint: `${TXID}:0:0` }],
    })).toThrow(/ambiguous/u);
    expect(() => groupOrdinalInscriptions({
      ...base,
      inscriptions: [
        { inscriptionId: ids[0]!, satpoint: `${TXID}:0:0` },
        { inscriptionId: ids[0]!, satpoint: `${TXID}:0:1` },
      ],
    })).toThrow(/ambiguous/u);
    expect(() => groupOrdinalInscriptions({
      ...base,
      inscriptions: [{ inscriptionId: ids[0]!, satpoint: `${TXID}:0:20000` }],
    })).toThrow(/satpoint/u);
  });

  // The former split/BigInt parser accepted satpoints the analyzer later rejected
  // as effect mismatches: BigInt('') is 0n, Number('') is 0, and BigInt tolerates
  // hex and surrounding whitespace. Reject them here, where the error is legible.
  it.each([
    ['empty offset', `${TXID}:0:`],
    ['empty vout', `${TXID}::0`],
    ['hex offset', `${TXID}:0:0x10`],
    ['padded offset', `${TXID}:0:007`],
    ['padded vout', `${TXID}:00:0`],
    ['whitespace offset', `${TXID}:0: 5 `],
    ['signed offset', `${TXID}:0:-0`],
    ['uppercase txid', `${TXID.toUpperCase()}:0:0`],
    ['missing offset field', `${TXID}:0`],
    ['extra field', `${TXID}:0:0:0`],
  ])('rejects a non-canonical satpoint (%s)', (_name, satpoint) => {
    try {
      groupOrdinalInscriptions({
        txid: TXID,
        vout: 0,
        valueSats: 20_000n,
        targetInscriptionId: ids[0]!,
        inscriptions: [{ inscriptionId: ids[0]!, satpoint }],
      });
      throw new Error('expected malformed satpoint to fail');
    } catch (error) {
      expect(error).toBeInstanceOf(OrdinalInscriptionGroupError);
      expect(error).toMatchObject({ reason: 'unprovable_satpoint' });
    }
  });

  it('preserves randomized FIFO sat positions and all input value', () => {
    fc.assert(fc.property(
      fc.array(fc.integer({ min: 10_000, max: 30_000 }), { minLength: 1, maxLength: 6 }),
      fc.nat(),
      (gaps, targetSeed) => {
        let cursor = 0n;
        const requests = gaps.map((gap, index) => {
          const inputOffset = cursor + BigInt(Math.floor(gap / 2));
          cursor += BigInt(gap);
          return {
            inscriptionId: ids[index]!,
            inputOffset,
            minimumOutputSats: 1_000n,
            target: index === targetSeed % gaps.length,
          };
        });
        const inputValueSats = cursor + 10_000n;
        const partitions = partitionOrdinalSatFlow(inputValueSats, requests);
        let outputStart = 0n;
        for (const partition of partitions) {
          expect(partition.valueSats).toBeGreaterThanOrEqual(1_000n);
          expect(outputStart + partition.outputOffset).toBe(partition.inputOffset);
          outputStart += partition.valueSats;
        }
        expect(outputStart).toBe(inputValueSats);
      },
    ), { numRuns: 250 });
  });
});

describe('ordinal batch sat-flow planning', () => {
  const source = (input: {
    txid?: string;
    vout?: number;
    valueSats?: bigint;
    offsets: readonly bigint[];
    coLocated?: boolean;
    idOffset?: number;
  }) => {
    const txid = input.txid ?? TXID;
    const vout = input.vout ?? 0;
    const entries = input.offsets.flatMap((offset, index) => {
      const first = { inscriptionId: ids[index + (input.idOffset ?? 0)]!, satpoint: `${txid}:${vout}:${offset}` };
      return input.coLocated && index === 0
        ? [first, { inscriptionId: ids[5]!, satpoint: first.satpoint }]
        : [first];
    });
    return {
      txid,
      vout,
      valueSats: input.valueSats ?? 100_000n,
      classificationRevision: 'rev-1',
      inscriptions: entries,
      selections: entries.map((entry) => ({
        ...entry,
        outpoint: { txid, vout },
        classificationRevision: 'rev-1',
      })),
      recipientMinimumOutputSats: 330n,
      preferredPostageSats: 10_000n,
      sourceChangeMinimumSats: 600n,
    };
  };

  it('returns cardinal prefixes and tails locally while keeping 10,000-sat postage', () => {
    const plan = planOrdinalBatchSatFlow([source({ offsets: [50_000n] })]);
    expect(plan.sources[0]?.outputs).toEqual([
      { role: 'payment_change', valueSats: 50_000n },
      { role: 'postage', valueSats: 10_000n, groupKey: ids[0] },
      { role: 'payment_change', valueSats: 40_000n },
    ]);
    expect(plan.sources[0]?.groups[0]).toMatchObject({
      inputOffset: 50_000n,
      outputOffset: 0n,
      valueSats: 10_000n,
      sourceOutputIndex: 1,
    });
    expect(plan.sources[0]?.returnedBtcSats).toBe(90_000n);
  });

  it('keeps co-located IDs in one atomic output', () => {
    const plan = planOrdinalBatchSatFlow([source({ offsets: [5_000n], coLocated: true })]);
    expect(plan.inscriptionCount).toBe(2);
    expect(plan.groupCount).toBe(1);
    expect(plan.sources[0]?.groups[0]?.inscriptionIds).toEqual([ids[0], ids[5]]);
  });

  it('orders protected sources deterministically and places one top-up last', () => {
    const noTopUp = source({ txid: 'bb'.repeat(32), vout: 1, offsets: [0n], idOffset: 1 });
    const topUp = source({ txid: 'aa'.repeat(32), vout: 0, valueSats: 200n, offsets: [0n] });
    topUp.preferredPostageSats = 330n;
    const plan = planOrdinalBatchSatFlow([topUp, noTopUp]);
    expect(plan.sources.map((item) => item.txid)).toEqual([noTopUp.txid, topUp.txid]);
    expect(plan.requiredTopUpSourceIndex).toBe(1);
    expect(plan.sources[1]?.requiredTopUpSats).toBe(130n);
  });

  it('fails closed for incomplete sources, stale bindings, and multiple top-ups', () => {
    const incomplete = source({ offsets: [0n, 20_000n] });
    incomplete.selections.pop();
    expect(() => planOrdinalBatchSatFlow([incomplete]))
      .toThrow(expect.objectContaining({ reason: 'incomplete_source' }));
    const stale = source({ offsets: [0n] });
    stale.selections[0]!.classificationRevision = 'rev-old';
    expect(() => planOrdinalBatchSatFlow([stale]))
      .toThrow(expect.objectContaining({ reason: 'stale_classification' }));
    expect(() => planOrdinalBatchSatFlow([
      source({ txid: 'aa'.repeat(32), valueSats: 200n, offsets: [0n] }),
      source({ txid: 'bb'.repeat(32), valueSats: 200n, offsets: [0n], idOffset: 1 }),
    ])).toThrowError(/more than one/u);
  });

  it('preserves every selected source prefix under randomized permutations', () => {
    fc.assert(fc.property(
      fc.array(fc.integer({ min: 330, max: 18_000 }), { minLength: 1, maxLength: 5 }),
      fc.integer({ min: 0, max: 10_000 }),
      (rawOffsets, permutationSeed) => {
        let offset = 0n;
        const offsets = rawOffsets.map((gap) => {
          const current = offset;
          offset += BigInt(gap);
          return current;
        });
        const request = source({ offsets });
        const shuffled = [...request.selections].sort((a, b) =>
          (a.inscriptionId.charCodeAt(0) + permutationSeed) % 7 -
          (b.inscriptionId.charCodeAt(0) + permutationSeed) % 7);
        const plan = planOrdinalBatchSatFlow([{ ...request, selections: shuffled }]);
        const planned = plan.sources[0]!;
        expect(planned.outputs.reduce((sum, output) => sum + output.valueSats, 0n))
          .toBe(planned.valueSats + planned.requiredTopUpSats);
        const outputStarts: bigint[] = [];
        let cursor = 0n;
        for (const output of planned.outputs) {
          outputStarts.push(cursor);
          cursor += output.valueSats;
        }
        for (const group of planned.groups) {
          expect(outputStarts[group.sourceOutputIndex]! + group.outputOffset).toBe(group.inputOffset);
        }
      },
    ), { numRuns: 250 });
  });
});
