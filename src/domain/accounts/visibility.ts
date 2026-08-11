import { normalizeAccountIndexes } from './limits';

/** Hidden accounts remain registered so discovery and recovery are unchanged. */
export function normalizeHiddenStandardAccounts(
  standardAccounts: Iterable<number>,
  hiddenAccounts: Iterable<number>,
): number[] {
  const standard = new Set(normalizeAccountIndexes(standardAccounts));
  const hidden = [...new Set(hiddenAccounts)].sort((left, right) => left - right);
  for (const account of hidden) {
    if (!Number.isInteger(account) || account < 0 || !standard.has(account)) {
      throw new RangeError('hidden account must be a registered standard account');
    }
  }
  if (hidden.length >= standard.size) {
    throw new RangeError('at least one standard account must remain visible');
  }
  return hidden;
}

export function visibleStandardAccounts(
  standardAccounts: Iterable<number>,
  hiddenAccounts: Iterable<number>,
): number[] {
  const standard = normalizeAccountIndexes(standardAccounts);
  const hidden = new Set(normalizeHiddenStandardAccounts(standard, hiddenAccounts));
  return standard.filter((account) => !hidden.has(account));
}

/** New activity makes a hidden account visible again. */
export function restoreOccupiedStandardAccounts(
  hiddenAccounts: Iterable<number>,
  occupiedAccounts: Iterable<number>,
): number[] {
  const occupied = new Set(occupiedAccounts);
  return [...new Set(hiddenAccounts)]
    .filter((account) => !occupied.has(account))
    .sort((left, right) => left - right);
}
