import { describe, expect, it } from 'vitest';
import {
  OrdinalPostagePlanError,
  planOrdinalPostageManage,
  resolveOrdinalPostageTarget,
  summarizeOrdinalPostageRecovery,
} from '../../src/domain/transactions/postage-manage';

const txid = (letter: string) => letter.repeat(64);
const source = (letter: string, valueSats: bigint) => ({
  selection: { inscriptionId: `${txid(letter)}i0`, outpoint: { txid: txid(letter), vout: 0 },
    satpoint: `${txid(letter)}:0:0`, classificationRevision: 'rev-1' },
  valueSats, classificationRevision: 'rev-1', inscriptionIds: [`${txid(letter)}i0`],
  ordinalOutputDustSats: 330n, paymentChangeDustSats: 294n,
});

describe('ordinal postage management primitives', () => {
  it('resolves safe targets and retains an uneconomic tail', () => {
    expect(resolveOrdinalPostageTarget({ type: 'common_546' }, 20_000n, 330n)).toBe(546n);
    expect(resolveOrdinalPostageTarget({ type: 'minimum_standard' }, 20_000n, 330n)).toBe(330n);
    expect(resolveOrdinalPostageTarget({ type: 'compatible_10000' }, 500n, 330n)).toBe(10_000n);
    const planned = planOrdinalPostageManage([source('a', 700n)], { type: 'common_546' });
    expect(planned.sources[0]).toMatchObject({ retainedPostageSats: 700n, returnedBtcSats: 0n });
  });

  it('recovers source-local tails and permits only one top-up source', () => {
    const recovered = planOrdinalPostageManage([source('b', 20_000n), source('a', 15_000n)],
      { type: 'common_546' });
    expect(recovered.sources.map((item) => item.selection.outpoint.txid))
      .toEqual([txid('a'), txid('b')]);
    expect(recovered.returnedBtcSats).toBe(33_908n);
    expect(() => planOrdinalPostageManage([source('a', 500n), source('b', 500n)],
      { type: 'compatible_10000' })).toThrow(OrdinalPostagePlanError);
  });

  it('requires one authoritative, offset-zero inscription per source binding', () => {
    expect(() => planOrdinalPostageManage([{ ...source('a', 10_000n),
      selection: { ...source('a', 10_000n).selection, satpoint: `${txid('a')}:0:1` } }],
    { type: 'common_546' })).toThrow(/ambiguous/u);
    expect(() => resolveOrdinalPostageTarget({ type: 'custom', customSats: '329' }, 1_000n, 330n))
      .toThrow(/outside/u);
  });

  it('excludes unrelated clean funding change from recovered and net amounts', () => {
    const summary = summarizeOrdinalPostageRecovery([
      { currentPostageSats: 50_000n, retainedPostageSats: 546n },
    ], 1_000n);
    expect(summary).toEqual({ recoveredSats: 49_454n, netRecoveredSats: 48_454n });
  });
});
