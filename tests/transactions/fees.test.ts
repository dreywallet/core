import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { Address, NETWORK, OutScript } from '@scure/btc-signer';
import { feeQuoteResponseSchema } from '../../src/domain/gateway/contract';
import { bytesToHex } from '../../src/domain/vault/encoding';
import {
  CustomFeeRateError,
  FEE_QUOTE_MAX_AGE_MS,
  FEE_QUOTE_MAX_FUTURE_SKEW_MS,
  estimateVsize,
  feeForVsize,
  formatFeeRateSatPerVb,
  inputVbytes,
  parseCustomFeeRate,
  payableScriptKind,
  scriptDustSats,
  scriptKind,
  sequenceForInput,
  validateAutomaticQuote,
} from '../../src/domain/transactions/fees';

const fixturePath = join(import.meta.dirname, '..', 'fixtures', 'gateway', 'fees.signed.json');
const fixture = feeQuoteResponseSchema.parse(JSON.parse(readFileSync(fixturePath, 'utf8')));
const now = Date.parse('2026-07-23T00:00:00.000Z');

describe('exact custom fee rates', () => {
  it.each([
    ['1', 1_000n, '1'],
    ['1.25', 1_250n, '1.25'],
    ['1.001', 1_001n, '1.001'],
    ['12.340', 12_340n, '12.34'],
    ['10000.000', 10_000_000n, '10000'],
  ] as const)('parses %s without floating-point arithmetic', (text, rate, normalized) => {
    expect(parseCustomFeeRate(text)).toEqual({
      normalizedSatPerVb: normalized,
      satPerKvB: rate,
    });
    expect(formatFeeRateSatPerVb(rate)).toBe(normalized);
  });

  it('uses the exact sat/kvB rate in deterministic fee ceilings', () => {
    expect(feeForVsize(141n, parseCustomFeeRate('1.25').satPerKvB)).toBe(177n);
    expect(feeForVsize(141n, parseCustomFeeRate('1.001').satPerKvB)).toBe(142n);
  });

  it.each([
    ['', 'syntax'], [' 1.25', 'syntax'], ['1.25 ', 'syntax'], ['01.25', 'syntax'],
    ['+1.25', 'syntax'], ['-1.25', 'syntax'], ['1,25', 'syntax'], ['1e3', 'syntax'],
    ['1.', 'syntax'], ['.5', 'syntax'], ['1.0000', 'precision'], ['0.999', 'below_minimum'],
    ['10000.001', 'above_maximum'],
  ] as const)('rejects %s as %s', (text, code) => {
    try {
      parseCustomFeeRate(text);
      throw new Error('expected custom fee parser to reject');
    } catch (error) {
      expect(error).toBeInstanceOf(CustomFeeRateError);
      expect((error as CustomFeeRateError).code).toBe(code);
    }
  });

  it('rejects oversized pasted input before bigint conversion', () => {
    expect(() => parseCustomFeeRate('1'.repeat(33))).toThrow(CustomFeeRateError);
  });
});

function quote(sampledAtMs: number, expiresAtMs = now + FEE_QUOTE_MAX_AGE_MS) {
  return {
    ...fixture,
    sampledAt: new Date(sampledAtMs).toISOString(),
    expiresAt: new Date(expiresAtMs).toISOString(),
    ageSeconds: Math.max(0, Math.floor((now - sampledAtMs) / 1_000)),
  };
}

describe('signed fee quote tier safety', () => {
  it('accepts a live effective rate below the same-tier historical estimate', () => {
    const parsed = feeQuoteResponseSchema.parse({
      ...fixture,
      floorSatPerKvB: 200,
      tiers: [
        { ...fixture.tiers[0], rawSatPerKvB: 4_000, effectiveSatPerKvB: 1_500 },
        { ...fixture.tiers[1], rawSatPerKvB: 2_000, effectiveSatPerKvB: 1_000 },
        { ...fixture.tiers[2], rawSatPerKvB: 800, effectiveSatPerKvB: 500 },
      ],
    });
    expect(parsed.tiers.map((tier) => tier.effectiveSatPerKvB)).toEqual([1_500, 1_000, 500]);
  });

  it('still rejects a tier below the signed node floor', () => {
    expect(feeQuoteResponseSchema.safeParse({
      ...fixture,
      floorSatPerKvB: 1_000,
      tiers: [
        fixture.tiers[0],
        fixture.tiers[1],
        { ...fixture.tiers[2], effectiveSatPerKvB: 999 },
      ],
    }).success).toBe(false);
  });

  it('still rejects non-monotonic effective tiers', () => {
    expect(feeQuoteResponseSchema.safeParse({
      ...fixture,
      tiers: [
        { ...fixture.tiers[0], effectiveSatPerKvB: 1_500 },
        { ...fixture.tiers[1], effectiveSatPerKvB: 2_000 },
        fixture.tiers[2],
      ],
    }).success).toBe(false);
  });
});

describe('automatic fee quote freshness', () => {
  it('accepts normal sub-second client/server clock skew', () => {
    expect(() => validateAutomaticQuote(quote(now + 1_000), now)).not.toThrow();
  });

  it('rejects quotes beyond the bounded future-skew allowance', () => {
    expect(() => validateAutomaticQuote(
      quote(now + FEE_QUOTE_MAX_FUTURE_SKEW_MS + 1),
      now,
    )).toThrow('fee quote stale');
  });

  it('rejects quotes that are too old or expired', () => {
    expect(() => validateAutomaticQuote(quote(now - FEE_QUOTE_MAX_AGE_MS - 1), now))
      .toThrow('fee quote stale');
    expect(() => validateAutomaticQuote(quote(now, now - 1), now)).toThrow('fee quote unsafe');
  });

  it('rejects a quote whose expiry cannot be parsed', () => {
    // Date.parse yields NaN and `nowMs > NaN` is false, so an unguarded expiry
    // comparison would let the quote through unexpired.
    expect(() => validateAutomaticQuote({ ...quote(now), expiresAt: 'not-a-date' }, now))
      .toThrow('fee quote unsafe');
  });

  it('uses final sequences for every Ordinals movement action', () => {
    expect(sequenceForInput('ordinal_transfer')).toBe(0xffffffff);
    expect(sequenceForInput('rescue')).toBe(0xffffffff);
    expect(sequenceForInput('ordinal_sweep')).toBe(0xffffffff);
  });
});

/** Every address type @scure/btc-signer will decode, so the wallet can pay all of them. */
const PAYABLE = {
  p2pkh: '1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2',
  p2sh: '3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy',
  p2wpkh: 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4',
  p2wsh: 'bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3',
  p2tr: 'bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr',
} as const;

function scriptFor(address: string): string {
  return bytesToHex(OutScript.encode(Address(NETWORK).decode(address)));
}

describe('payable recipient scripts', () => {
  it('pays every address type the decoder accepts, at Bitcoin Core dust floors', () => {
    // Core's floor is 3x (serialized output + bytes to spend it), which is why a
    // legacy recipient needs roughly twice a bech32 one.
    const expected = { p2pkh: 546n, p2sh: 540n, p2wpkh: 294n, p2wsh: 330n, p2tr: 330n };
    for (const [kind, address] of Object.entries(PAYABLE)) {
      const script = scriptFor(address);
      expect(payableScriptKind(script)).toBe(kind);
      expect(scriptDustSats(script)).toBe(expected[kind as keyof typeof expected]);
    }
  });

  it('sizes a legacy output from its own script, not a segwit assumption', () => {
    // estimateVsize measures outputs generically, so paying a legacy recipient
    // costs the extra bytes it actually occupies rather than being rejected.
    const input = scriptFor(PAYABLE.p2wpkh);
    expect(estimateVsize([input], [scriptFor(PAYABLE.p2pkh)]))
      .toBeGreaterThan(estimateVsize([input], [scriptFor(PAYABLE.p2wpkh)]));
  });

  it('still refuses to treat a non-segwit script as spendable', () => {
    // Inputs are a different question: the wallet derives only P2WPKH and P2TR,
    // so nothing may size or set a sighash policy for a script it cannot sign.
    expect(() => scriptKind(scriptFor(PAYABLE.p2sh))).toThrow('unsupported script type');
    expect(() => scriptKind(scriptFor(PAYABLE.p2pkh))).toThrow('unsupported script type');
    expect(() => inputVbytes(scriptFor(PAYABLE.p2sh))).toThrow('unsupported script type');
  });

  it('rejects a script that is not a payable template', () => {
    expect(() => payableScriptKind('6a0548656c6c6f')).toThrow('unsupported script type');
    expect(() => payableScriptKind('')).toThrow('unsupported script type');
    // Right opcodes, wrong payload length.
    expect(() => payableScriptKind(`a914${'ab'.repeat(19)}87`)).toThrow('unsupported script type');
  });
});
