import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import {
  automaticOrdinalPostage,
  groupOrdinalInscriptions,
  OrdinalInscriptionGroupError,
  partitionOrdinalSatFlow,
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
