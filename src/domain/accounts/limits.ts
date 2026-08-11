import { assertBip32Index, BIP32_MAX_INDEX } from '../keys/derivation';

/** Standard accounts occupy the complete non-hardened BIP32 child-index space. */
export const MAX_ACCOUNT_INDEX = BIP32_MAX_INDEX;

/**
 * Recovery derives a bounded public-key batch at a time. Re-running discovery
 * continues after the highest contiguous discovered account, so this is a
 * per-scan work bound rather than an account-count limit.
 */
export const ACCOUNT_DISCOVERY_BATCH_SIZE = 100;

export function normalizeAccountIndexes(indexes: Iterable<number>): number[] {
  const unique = new Set<number>();
  for (const index of indexes) {
    assertBip32Index(index, 'account index');
    unique.add(index);
  }
  unique.add(0);
  return [...unique].sort((left, right) => left - right);
}

export function nextAccountIndex(indexes: Iterable<number>): number | null {
  const accounts = normalizeAccountIndexes(indexes);
  const highest = accounts.at(-1) ?? 0;
  return highest === MAX_ACCOUNT_INDEX ? null : highest + 1;
}
