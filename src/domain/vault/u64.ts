import { z } from 'zod';

const CANONICAL_DECIMAL = /^(?:0|[1-9][0-9]*)$/u;
const U64_MAX_DECIMAL = '18446744073709551615';

function isCanonicalU64(value: string): boolean {
  if (!CANONICAL_DECIMAL.test(value)) return false;
  return value.length < U64_MAX_DECIMAL.length ||
    (value.length === U64_MAX_DECIMAL.length && value <= U64_MAX_DECIMAL);
}

/** Canonical unsigned 64-bit decimal without a throwing numeric refinement. */
export const decimalU64Schema = z.string().refine(
  isCanonicalU64,
  'unsigned 64-bit decimal required',
);
