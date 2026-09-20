/** Atomic quantities never pass through Number. Locale handling is intentionally EN/ES. */
export const RUNE_U128_MAX = (1n << 128n) - 1n;
export const RUNE_U64_MAX = (1n << 64n) - 1n;
export const RUNE_U32_MAX = 0xffff_ffff;

export interface RuneId { readonly block: bigint; readonly tx: number }

export function parseRuneId(value: string): RuneId {
  if (value.length > 31 || !/^(0|[1-9][0-9]*):(0|[1-9][0-9]*)$/.test(value)) {
    throw new Error('Invalid canonical Rune ID');
  }
  const [blockText, txText] = value.split(':');
  const block = BigInt(blockText!);
  const tx = BigInt(txText!);
  if (block > RUNE_U64_MAX || tx > BigInt(RUNE_U32_MAX) || (block === 0n && tx !== 0n)) {
    throw new Error('Rune ID out of range');
  }
  return { block, tx: Number(tx) };
}

export function parseRuneAtomic(value: string): bigint {
  if (value.length > 39 || !/^(0|[1-9][0-9]*)$/.test(value)) throw new Error('Invalid atomic Rune quantity');
  return assertRuneAtomic(BigInt(value));
}

export function assertRuneAtomic(value: bigint): bigint {
  if (typeof value !== 'bigint' || value < 0n || value > RUNE_U128_MAX) throw new Error('Rune quantity out of u128 range');
  return value;
}

export function assertRuneDivisibility(value: number): number {
  if (!Number.isInteger(value) || value < 0 || value > 38) throw new Error('Invalid Rune divisibility');
  return value;
}

function separator(locale: string): string {
  if (/^es(?:-|$)/i.test(locale)) return ',';
  if (/^en(?:-|$)/i.test(locale)) return '.';
  throw new Error('Unsupported Rune quantity locale');
}

/** No grouping, exponent, sign, whitespace, or alternate decimal separator is accepted. */
export function parseRuneQuantity(value: string, divisibility: number, locale = 'en'): bigint {
  assertRuneDivisibility(divisibility);
  const decimal = separator(locale);
  if (value.length > 79) throw new Error('Rune quantity too long');
  const parts = value.split(decimal);
  const whole = parts[0]!;
  const fraction = parts[1] ?? '';
  if (parts.length > 2 || !/^(0|[1-9][0-9]*)$/.test(whole)
    || (parts.length === 2 && !/^[0-9]+$/.test(fraction)) || fraction.length > divisibility) {
    throw new Error('Invalid Rune quantity or precision');
  }
  return assertRuneAtomic(BigInt(whole + fraction.padEnd(divisibility, '0')));
}

/** Exact, ungrouped display; trimming trailing fractional zeros never rounds. */
export function formatRuneQuantity(value: bigint | string, divisibility: number, locale = 'en'): string {
  const amount = typeof value === 'string' ? parseRuneAtomic(value) : assertRuneAtomic(value);
  assertRuneDivisibility(divisibility);
  const decimal = separator(locale);
  if (divisibility === 0) return amount.toString();
  const digits = amount.toString().padStart(divisibility + 1, '0');
  const fraction = digits.slice(-divisibility).replace(/0+$/, '');
  return digits.slice(0, -divisibility) + (fraction ? decimal + fraction : '');
}
