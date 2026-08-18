import { assertBip32Index, BIP32_MAX_INDEX } from '../keys/derivation';

/** Standard accounts occupy the complete non-hardened BIP32 child-index space. */
export const MAX_ACCOUNT_INDEX = BIP32_MAX_INDEX;

/**
 * Drey's bounded extension to BIP44 account discovery. Recovery checks this
 * many consecutive accounts without confirmed history before it stops.
 */
export const ACCOUNT_GAP_LIMIT = 5;

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

export type StandardAccountAddState =
  | {
      kind: 'available';
      nextAccount: number;
      trailingEmptyAccounts: number;
      limit: typeof ACCOUNT_GAP_LIMIT;
      requiresAcknowledgement: boolean;
    }
  | {
      kind: 'empty_limit';
      firstEmptyAccount: number;
      lastEmptyAccount: number;
      limit: typeof ACCOUNT_GAP_LIMIT;
    }
  | { kind: 'index_exhausted'; limit: typeof ACCOUNT_GAP_LIMIT };

/** Worker- and mobile-shared authority for the next standard-account action. */
export function standardAccountAddState(
  indexes: Iterable<number>,
  confirmedAccounts: Iterable<number>,
  gapAcknowledged: boolean,
): StandardAccountAddState {
  const accounts = normalizeAccountIndexes(indexes);
  const highest = accounts.at(-1) ?? 0;
  const nextAccount = nextAccountIndex(accounts);
  if (nextAccount === null) return { kind: 'index_exhausted', limit: ACCOUNT_GAP_LIMIT };

  const registered = new Set(accounts);
  let highestConfirmed = -1;
  for (const account of confirmedAccounts) {
    assertBip32Index(account, 'confirmed account index');
    if (registered.has(account)) highestConfirmed = Math.max(highestConfirmed, account);
  }
  const trailingEmptyAccounts = highest - highestConfirmed;
  if (trailingEmptyAccounts >= ACCOUNT_GAP_LIMIT) {
    return {
      kind: 'empty_limit',
      firstEmptyAccount: highest - ACCOUNT_GAP_LIMIT + 1,
      lastEmptyAccount: highest,
      limit: ACCOUNT_GAP_LIMIT,
    };
  }
  return {
    kind: 'available',
    nextAccount,
    trailingEmptyAccounts,
    limit: ACCOUNT_GAP_LIMIT,
    requiresAcknowledgement: trailingEmptyAccounts > 0 && !gapAcknowledged,
  };
}
