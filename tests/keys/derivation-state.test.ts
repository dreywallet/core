/**
 * spec §8.1: change indexes are monotonic and are never reused after they have
 * appeared in an attempted transaction, even when the attempt fails. Burning
 * happens at reservation, and since reservation is the only issuance path the
 * burned set is exactly [0, nextChangeIndex) — encoded by the counter alone.
 */
import { describe, expect, it } from 'vitest';
import {
  BIP32_INDEX_EXHAUSTED,
  initialDerivationState,
  isChangeIndexBurned,
  reserveChangeIndex,
  type AccountDerivationStateV1,
} from '../../src/domain/keys/derivation-state';
import { BIP32_MAX_INDEX } from '../../src/domain/keys/derivation';

describe('initialDerivationState', () => {
  it('starts at zero with rotating-ready fields present', () => {
    const state = initialDerivationState('payment', 'mainnet', 0);
    expect(state).toEqual({
      version: 1,
      network: 'mainnet',
      kind: 'payment',
      accountIndex: 0,
      externalMode: 'stable',
      nextExternalIndex: 0,
      nextChangeIndex: 0,
    });
  });

  it('rejects invalid account indexes', () => {
    expect(() => initialDerivationState('payment', 'mainnet', -1)).toThrow();
    expect(() => initialDerivationState('payment', 'mainnet', 1.5)).toThrow();
    expect(() => initialDerivationState('payment', 'mainnet', BIP32_INDEX_EXHAUSTED)).toThrow();
  });
});

describe('reserveChangeIndex', () => {
  it('is monotonic and burns at reservation time without mutating the input', () => {
    const state = initialDerivationState('payment', 'mainnet', 0);
    const first = reserveChangeIndex(state);
    expect(first.index).toBe(0);
    expect(isChangeIndexBurned(first.state, 0)).toBe(true);
    expect(isChangeIndexBurned(state, 0)).toBe(false); // input not mutated
    expect(state.nextChangeIndex).toBe(0);

    const second = reserveChangeIndex(first.state);
    expect(second.index).toBe(1);
    expect(second.state.nextChangeIndex).toBe(2);
  });

  it('never reissues an index across many attempt/failure cycles', () => {
    let state = initialDerivationState('ordinals', 'signet', 2);
    const seen = new Set<number>();
    for (let i = 0; i < 1000; i++) {
      const { state: next, index } = reserveChangeIndex(state);
      expect(seen.has(index)).toBe(false);
      seen.add(index);
      // A failed broadcast changes nothing: the index was burned at
      // reservation and the counter only ever advances.
      state = next;
      expect(isChangeIndexBurned(state, index)).toBe(true);
    }
    expect(state.nextChangeIndex).toBe(1000);
  });

  it('burned-ness is exactly the counter invariant', () => {
    let state = initialDerivationState('payment', 'mainnet', 0);
    for (let i = 0; i < 10; i++) state = reserveChangeIndex(state).state;
    for (let i = 0; i < 10; i++) expect(isChangeIndexBurned(state, i)).toBe(true);
    expect(isChangeIndexBurned(state, 10)).toBe(false);
    expect(isChangeIndexBurned(state, 999)).toBe(false);
  });

  it('survives a JSON round trip unchanged', () => {
    let state = initialDerivationState('payment', 'mainnet', 0);
    for (let i = 0; i < 5; i++) state = reserveChangeIndex(state).state;
    const revived = JSON.parse(JSON.stringify(state)) as AccountDerivationStateV1;
    expect(revived).toEqual(state);
    expect(reserveChangeIndex(revived).index).toBe(5);
  });

  it('reserves the last non-hardened child once, then reports exhaustion', () => {
    const state = {
      ...initialDerivationState('payment', 'mainnet', 0),
      nextChangeIndex: BIP32_MAX_INDEX,
    };
    const last = reserveChangeIndex(state);
    expect(last.index).toBe(BIP32_MAX_INDEX);
    expect(last.state.nextChangeIndex).toBe(BIP32_INDEX_EXHAUSTED);
    expect(isChangeIndexBurned(last.state, BIP32_MAX_INDEX)).toBe(true);
    expect(() => reserveChangeIndex(last.state)).toThrow(/exhausted/u);
  });

  it('rejects malformed counters instead of advancing them', () => {
    const state = initialDerivationState('payment', 'mainnet', 0);
    expect(() => reserveChangeIndex({ ...state, nextChangeIndex: -1 })).toThrow();
    expect(() => reserveChangeIndex({ ...state, nextChangeIndex: 1.5 })).toThrow();
    expect(() => reserveChangeIndex({ ...state, nextChangeIndex: Number.NaN })).toThrow();
  });
});
