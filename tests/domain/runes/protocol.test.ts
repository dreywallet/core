import { describe, expect, it } from 'vitest';
import fc from 'fast-check';
import { assertRuneDivisibility, formatRuneQuantity, parseRuneAtomic, parseRuneId, parseRuneQuantity, RUNE_U128_MAX } from '../../../src/domain/runes/amounts';
import { decodeRunestone, encodeRunestone, evaluateRuneAllocations, RuneResourceLimitError } from '../../../src/domain/runes/protocol';

const pay = Uint8Array.of(0x51);
const ret = Uint8Array.of(0x6a);
const supply = [{ id: '840000:1', amount: 101n }];
// Raw independent vector builder: tests malformed fields the transfer encoder never emits.
function raw(values: readonly bigint[]): Uint8Array {
  const bytes: number[] = [];
  for (let value of values) {
    do { const byte = Number(value % 128n); value /= 128n; bytes.push(byte + (value ? 128 : 0)); } while (value);
  }
  return Uint8Array.from([0x6a, 0x5d, 76, bytes.length, ...bytes]);
}
const parse = (values: readonly bigint[], count = 3) => decodeRunestone([raw(values), ...Array.from({ length: count - 1 }, () => pay)]);

describe('exact Rune quantities and identity', () => {
  it('enforces canonical IDs and protocol ranges', () => {
    expect(parseRuneId('18446744073709551615:4294967295')).toEqual({ block: (1n << 64n) - 1n, tx: 4294967295 });
    for (const id of ['01:0', '1:00', '-1:0', '1: 0', '0:1', '18446744073709551616:0', '1:4294967296', '1e3:0']) expect(() => parseRuneId(id)).toThrow();
    expect(parseRuneId('0:0')).toEqual({ block: 0n, tx: 0 });
  });
  it('validates u128 without a floating point conversion', () => {
    expect(parseRuneAtomic(RUNE_U128_MAX.toString())).toBe(RUNE_U128_MAX);
    for (const amount of ['-1', '+1', '00', ' 1', '1e3', '1.0', (RUNE_U128_MAX + 1n).toString()]) expect(() => parseRuneAtomic(amount)).toThrow();
    for (const div of [-1, 39, 1.5, NaN]) expect(() => assertRuneDivisibility(div)).toThrow();
  });
  it('round trips exact EN/ES quantities at every supported precision', () => {
    fc.assert(fc.property(fc.bigInt({ min: 0n, max: RUNE_U128_MAX }), fc.integer({ min: 0, max: 38 }), fc.constantFrom('en', 'es', 'es-MX'), (amount, div, locale) => {
      expect(parseRuneQuantity(formatRuneQuantity(amount, div, locale), div, locale)).toBe(amount);
    }), { seed: 2701, numRuns: 1000 });
  });
  it('rejects ambiguous or rounded quantity input', () => {
    expect(parseRuneQuantity('9007199254740993.12', 2)).toBe(900719925474099312n);
    expect(parseRuneQuantity('9007199254740993,12', 2, 'es')).toBe(900719925474099312n);
    expect(formatRuneQuantity(1n, 38)).toBe('0.' + '0'.repeat(37) + '1');
    for (const text of ['1,000', '1.', '.1', '-1', '1e2', '1.001', '01', ' 1', '1 ']) expect(() => parseRuneQuantity(text, 2)).toThrow();
    expect(() => parseRuneQuantity('1.2', 2, 'es')).toThrow();
    expect(() => parseRuneQuantity(RUNE_U128_MAX.toString(), 1)).toThrow();
  });
});

describe('ord 0.27.1 runestone semantics', () => {
  it('encodes a stable transfer vector with sorted delta IDs', () => {
    const script = encodeRunestone({ pointer: 2, edicts: [{ id: '3:4', amount: 5n, output: 1 }, { id: '1:2', amount: 6n, output: 2 }] }, 3);
    expect([...script]).toEqual([106, 93, 11, 22, 2, 0, 1, 2, 6, 2, 2, 4, 5, 1]);
    expect(decodeRunestone([script, pay, pay])).toEqual({ kind: 'runestone', pointer: 2, edicts: [{ id: '1:2', amount: 6n, output: 2 }, { id: '3:4', amount: 5n, output: 1 }] });
    expect([...encodeRunestone({ edicts: [] }, 1)]).toEqual([106, 93]);
  });
  it('recognizes only literal magic opcodes and uses the first candidate', () => {
    expect(decodeRunestone([Uint8Array.of(106, 1, 13), pay])).toEqual({ kind: 'absent' });
    expect(decodeRunestone([Uint8Array.of(106, 93, 81), raw([])])).toEqual({ kind: 'cenotaph', flaw: 'opcode' });
    expect(decodeRunestone([raw([]), Uint8Array.of(106, 93, 81)])).toEqual({ kind: 'runestone', edicts: [] });
    expect(decodeRunestone([Uint8Array.of(106, 93, 2, 1)])).toEqual({ kind: 'cenotaph', flaw: 'invalid_script' });
    expect(decodeRunestone([Uint8Array.of(106, 93, 78, 255, 255, 255, 255)])).toEqual({ kind: 'cenotaph', flaw: 'invalid_script' });
  });
  it('concatenates data pushes and accepts non-minimal varints', () => {
    expect(decodeRunestone([Uint8Array.of(106, 93, 1, 128, 1, 0)])).toEqual({ kind: 'runestone', edicts: [] });
    expect(decodeRunestone([Uint8Array.of(106, 93, 1, 128)])).toEqual({ kind: 'cenotaph', flaw: 'varint' });
    expect(decodeRunestone([Uint8Array.from([106, 93, 19, ...Array(18).fill(128), 4])])).toEqual({ kind: 'cenotaph', flaw: 'varint' });
  });
  it.each([
    [[22n, 3n], 'unrecognized_even_tag'], [[22n, 1n, 22n, 1n], 'unrecognized_even_tag'],
    [[24n, 0n], 'unrecognized_even_tag'], [[2n, 8n], 'unrecognized_flag'],
    [[2n, 2n], 'unrecognized_flag'], [[1n], 'truncated_field'],
    [[0n, 1n], 'trailing_integers'], [[0n, 0n, 1n, 1n, 1n], 'edict_rune_id'],
    [[0n, 1n, 1n, 1n, 4n], 'edict_output'], [[20n, 1n], 'unrecognized_even_tag'],
    [[2n, 3n, 6n, RUNE_U128_MAX, 8n, 1n, 10n, 1n], 'supply_overflow'],
  ] as const)('detects malformed field/body vector %#', (values, flaw) => {
    expect(parse(values)).toMatchObject({ kind: 'cenotaph', flaw });
  });
  it('ignores odd fields but consumes exact valid mint/etch fields', () => {
    expect(parse([127n, 123n, 1n, 255n])).toEqual({ kind: 'runestone', edicts: [] });
    expect(parse([20n, 1n, 20n, 2n])).toEqual({ kind: 'runestone', edicts: [], mint: '1:2' });
    expect(parse([2n, 7n, 1n, 38n, 6n, 10n, 8n, 2n, 10n, 3n])).toMatchObject({ kind: 'runestone', etching: { terms: true, turbo: true } });
    expect(() => evaluateRuneAllocations([raw([20n, 1n, 20n, 2n]), pay], supply)).toThrow('Mint/etch');
    expect(() => evaluateRuneAllocations([raw([2n, 1n]), pay], supply)).toThrow('Mint/etch');
  });
  it('moves absent-runestone balances to the first non-OP_RETURN output', () => {
    expect(evaluateRuneAllocations([ret, pay, pay], supply).outputs[1]!.get('840000:1')).toBe(101n);
    expect(evaluateRuneAllocations([ret], supply).burned.get('840000:1')).toBe(101n);
  });
  it('allocates partial sends, explicit residual change and zero-as-all', () => {
    const stone = encodeRunestone({ pointer: 2, edicts: [{ id: '840000:1', amount: 40n, output: 1 }] }, 3);
    const result = evaluateRuneAllocations([stone, pay, pay], supply);
    expect(result.outputs.map(m => m.get('840000:1') ?? 0n)).toEqual([0n, 40n, 61n]);
    expect(result.burned.size).toBe(0);
    for (const amount of [0n, 101n, RUNE_U128_MAX]) {
      const all = encodeRunestone({ edicts: [{ id: '840000:1', amount, output: 2 }] }, 3);
      expect(evaluateRuneAllocations([all, pay, pay], supply).outputs[2]!.get('840000:1')).toBe(101n);
    }
  });
  it('distributes evenly with early-output remainder, or a fixed amount each', () => {
    for (const [amount, expected] of [[0n, [51n, 50n]], [40n, [61n, 40n]], [70n, [70n, 31n]]] as const) {
      const stone = encodeRunestone({ edicts: [{ id: '840000:1', amount, output: 3 }] }, 3);
      const result = evaluateRuneAllocations([stone, pay, pay], supply);
      expect(result.outputs.slice(1).map(m => m.get('840000:1'))).toEqual(expected);
    }
  });
  it('burns OP_RETURN allocations, explicit return pointers and cenotaphs', () => {
    for (const stone of [raw([22n, 0n]), raw([0n, 840000n, 1n, 0n, 0n]), raw([126n, 0n])]) {
      const result = evaluateRuneAllocations([stone, pay], supply);
      expect(result.burned.get('840000:1')).toBe(101n);
      expect(result.outputs.every(m => !m.size)).toBe(true);
    }
  });
  it('bounds resources separately from protocol flaws', () => {
    expect(() => decodeRunestone(Array.from({ length: 4097 }, () => pay))).toThrow(RuneResourceLimitError);
    expect(() => decodeRunestone([Uint8Array.from([106, 93, 77, 1, 64, ...Array(16385).fill(0)])])).toThrow(RuneResourceLimitError);
    expect(() => evaluateRuneAllocations([pay], [{ id: '1:0', amount: RUNE_U128_MAX }, { id: '1:0', amount: 1n }])).toThrow();
  });
  it('preserves every input atomic unit across seeded transfers and burns', () => {
    fc.assert(fc.property(fc.bigInt({ min: 0n, max: RUNE_U128_MAX }), fc.bigInt({ min: 0n, max: RUNE_U128_MAX }), fc.integer({ min: 0, max: 3 }), fc.integer({ min: 0, max: 2 }), (balance, amount, output, pointer) => {
      const stone = encodeRunestone({ pointer, edicts: [{ id: '1:0', amount, output }] }, 3);
      const result = evaluateRuneAllocations([stone, pay, pay], [{ id: '1:0', amount: balance }, { id: '2:0', amount: 37n }]);
      for (const [id, total] of [['1:0', balance], ['2:0', 37n]] as const) {
        expect(result.outputs.reduce((sum, m) => sum + (m.get(id) ?? 0n), result.burned.get(id) ?? 0n)).toBe(total);
      }
    }), { seed: 2701, numRuns: 1000 });
  });
});

import ordVectors from './ord-0.27.1-vectors.json';
describe('actual pinned ord 0.27.1 differential vectors', () => {
  it('matches the reference binary on malformed, transfer, and etching vectors', () => {
    for (const vector of ordVectors.cases) {
      const actual = decodeRunestone(vector.scripts.map(script => Uint8Array.from(script)));
      if (actual.kind === 'runestone') {
        expect({ kind: actual.kind, edicts: actual.edicts.map(edict => ({ ...edict, amount: edict.amount.toString() })),
          pointer: actual.pointer ?? null, mint: actual.mint ?? null, etching: actual.etching !== undefined }).toEqual(vector.expected);
      } else if (actual.kind === 'cenotaph') {
        const flaw = actual.flaw.split('_').map(part => part[0]!.toUpperCase() + part.slice(1)).join('');
        expect({ kind: actual.kind, flaw: `Some(${flaw})` }).toEqual(vector.expected);
      } else expect(actual).toEqual(vector.expected);
    }
    // A changed interpretation must fail even when the reference corpus exists.
    expect(ordVectors.cases.some(vector => vector.expected.kind === 'cenotaph')).toBe(true);
    expect(decodeRunestone([Uint8Array.of(106, 93, 81)]).kind).not.toBe('runestone');
  });
});
