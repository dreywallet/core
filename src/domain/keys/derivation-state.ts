/**
 * Per-account derivation state (spec §8.1).
 *
 * Change indexes are burned at reservation time — the moment an index is
 * handed out for an attempted transaction it is unusable forever, even if the
 * transaction never broadcasts. Because reservation is the only way an index
 * is ever issued, the burned set is always exactly [0, nextChangeIndex): the
 * counter alone encodes it, so no burned-index list is stored. A future
 * rotating-external-address mode is a new externalMode variant (and, if it
 * ever needs sparse burning, its own versioned structure) — not a format
 * migration; in v1 stable mode the external address is always index 0.
 */
import { assertBip32Index, BIP32_MAX_INDEX, type AddressKind, type Network } from './derivation';

/** Counter-only sentinel after every non-hardened child index has been burned. */
export const BIP32_INDEX_EXHAUSTED = BIP32_MAX_INDEX + 1;

export interface AccountDerivationStateV1 {
  version: 1;
  network: Network;
  kind: AddressKind;
  accountIndex: number;
  externalMode: 'stable';
  nextExternalIndex: number;
  nextChangeIndex: number; // monotonic; every index below it is burned
}

export function initialDerivationState(
  kind: AddressKind,
  network: Network,
  accountIndex: number,
): AccountDerivationStateV1 {
  assertBip32Index(accountIndex, 'account index');
  return {
    version: 1,
    network,
    kind,
    accountIndex,
    externalMode: 'stable',
    nextExternalIndex: 0,
    nextChangeIndex: 0,
  };
}

/**
 * Reserve the next change index for an attempted transaction. The returned
 * state has the counter advanced (burning the index); the caller must persist
 * it before using the index in a transaction.
 */
export function reserveChangeIndex(state: AccountDerivationStateV1): {
  state: AccountDerivationStateV1;
  index: number;
} {
  if (!Number.isSafeInteger(state.nextChangeIndex) || state.nextChangeIndex < 0) {
    throw new Error(`invalid next change index: ${state.nextChangeIndex}`);
  }
  if (state.nextChangeIndex >= BIP32_INDEX_EXHAUSTED) {
    throw new Error('BIP32 change index space exhausted');
  }
  const index = state.nextChangeIndex;
  return { index, state: { ...state, nextChangeIndex: index + 1 } };
}

export function isChangeIndexBurned(state: AccountDerivationStateV1, index: number): boolean {
  assertBip32Index(index, 'address index');
  return index < state.nextChangeIndex;
}
