import { describe, expect, it } from 'vitest';
import { formatUsdFromSats, usdCentsForSats } from '../../src/domain/fiat';

describe('fiat display conversion', () => {
  it('uses integer half-up rounding at the final cent', () => {
    expect(usdCentsForSats(205_556n, '10000000')).toBe(20_556n);
    expect(formatUsdFromSats(205_556n, '10000000', 'en')).toBe('$205.56');
  });

  it('handles zero, sub-cent values, and very large balances without float overflow', () => {
    expect(formatUsdFromSats(0n, '6565000', 'en')).toBe('$0.00');
    expect(formatUsdFromSats(1n, '6565000', 'en')).toBe('<$0.01');
    expect(formatUsdFromSats(2_100_000_000_000_000n, '10000000000', 'en'))
      .toBe('$2,100,000,000,000,000.00');
  });

  it('rejects negative sats and malformed price strings', () => {
    expect(() => usdCentsForSats(-1n, '6565000')).toThrow();
    expect(() => usdCentsForSats(1n, '65.65')).toThrow();
  });
});
