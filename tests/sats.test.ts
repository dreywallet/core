import { describe, expect, it } from 'vitest';
import { formatSats, parseSats } from '../src/domain/sats';

describe('integer sats', () => {
  it('round-trips decimal strings', () => {
    for (const s of ['0', '1', '546', '10000', '2100000000000000']) {
      expect(formatSats(parseSats(s))).toBe(s);
    }
  });

  it('rejects floats, negatives, leading zeros, and non-decimal input', () => {
    for (const s of ['1.5', '-1', '01', '', ' 1', '1e3', '0x10', '1_000']) {
      expect(() => parseSats(s)).toThrow(RangeError);
    }
  });

  it('rejects amounts above total supply', () => {
    expect(() => parseSats('2100000000000001')).toThrow(RangeError);
  });
});
