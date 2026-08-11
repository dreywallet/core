// spec.md §10.5 / §24.1: all Bitcoin amounts are integer sats; arithmetic never
// uses floating point. Amounts crossing the API boundary are decimal strings.

export type Sats = bigint;

const MAX_SATS = 21_000_000n * 100_000_000n;
const DECIMAL_STRING = /^(0|[1-9][0-9]*)$/;

export function parseSats(decimal: string): Sats {
  if (!DECIMAL_STRING.test(decimal)) {
    throw new RangeError(`invalid sats amount: ${JSON.stringify(decimal)}`);
  }
  const value = BigInt(decimal);
  if (value > MAX_SATS) {
    throw new RangeError(`sats amount exceeds total supply: ${decimal}`);
  }
  return value;
}

export function formatSats(value: Sats): string {
  if (value < 0n || value > MAX_SATS) {
    throw new RangeError(`sats amount out of range: ${value}`);
  }
  return value.toString(10);
}

const SATS_PER_BTC = 100_000_000n;
const BTC_DECIMAL = /^(0|[1-9][0-9]*)(?:\.([0-9]{1,8}))?$/;

/** BTC decimal string ("0.00012" — trailing zeros trimmed), integer-only math. */
export function satsToBtcDecimal(value: Sats): string {
  if (value < 0n || value > MAX_SATS) {
    throw new RangeError(`sats amount out of range: ${value}`);
  }
  const whole = value / SATS_PER_BTC;
  const frac = (value % SATS_PER_BTC).toString(10).padStart(8, '0').replace(/0+$/u, '');
  return frac === '' ? whole.toString(10) : `${whole.toString(10)}.${frac}`;
}

/** Parses a BTC decimal string (≤8 fractional digits) to integer sats. */
export function btcDecimalToSats(decimal: string): Sats {
  const match = BTC_DECIMAL.exec(decimal);
  if (!match?.[1]) {
    throw new RangeError(`invalid BTC amount: ${JSON.stringify(decimal)}`);
  }
  const frac = match[2] ?? '';
  const value = BigInt(match[1]) * SATS_PER_BTC + BigInt(frac.padEnd(8, '0'));
  if (value > MAX_SATS) {
    throw new RangeError(`BTC amount exceeds total supply: ${decimal}`);
  }
  return value;
}
