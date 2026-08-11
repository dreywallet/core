export const CANONICAL_SATPOINT_PATTERN =
  /^([0-9a-f]{64}):(0|[1-9][0-9]{0,9}):(0|[1-9][0-9]{0,19})$/u;

const MAX_SATPOINT_OFFSET = 0xffffffffffffffffn;

export interface ParsedSatpoint {
  txid: string;
  vout: number;
  offset: bigint;
}

/**
 * Parse the one canonical satpoint representation accepted by gateway
 * contracts, transaction planning, and transaction analysis.
 */
export function parseCanonicalSatpoint(satpoint: string): ParsedSatpoint | null {
  const parsed = CANONICAL_SATPOINT_PATTERN.exec(satpoint);
  if (!parsed) return null;
  const vout = Number(parsed[2]);
  const offset = BigInt(parsed[3]!);
  // Bitcoin output indexes are unsigned 32-bit values.
  // Ord represents satpoint offsets as unsigned 64-bit values.
  if (vout > 0xffffffff || offset > MAX_SATPOINT_OFFSET) return null;
  return {
    txid: parsed[1]!,
    vout,
    offset,
  };
}
