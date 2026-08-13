export const CANONICAL_SATPOINT_PATTERN =
  /^([0-9a-f]{64}):(0|[1-9][0-9]{0,9}):(0|[1-9][0-9]{0,19})$/u;

const MAX_SATPOINT_OFFSET = 0xffffffffffffffffn;

export interface ParsedSatpoint {
  txid: string;
  vout: number;
  offset: bigint;
}

export interface InscriptionAtSatpoint {
  inscriptionId: string;
  satpoint: string;
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

/**
 * Pick the inscription whose sat lands first in the output. Invalid satpoints
 * sort after valid ones, with the inscription id providing a stable tie-break.
 * This is presentation-only: it never selects transaction inputs or assets.
 */
export function primaryInscriptionForPreview<T extends InscriptionAtSatpoint>(
  inscriptions: readonly T[],
): T | null {
  let selected: T | null = null;
  let selectedOffset: bigint | null = null;
  for (const inscription of inscriptions) {
    const offset = parseCanonicalSatpoint(inscription.satpoint)?.offset ?? null;
    if (selected === null ||
        (offset !== null && (selectedOffset === null || offset < selectedOffset)) ||
        (offset === selectedOffset && inscription.inscriptionId < selected.inscriptionId)) {
      selected = inscription;
      selectedOffset = offset;
    }
  }
  return selected;
}
