import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { summarizeBalances } from '../../src/domain/classification/balances';
import { laneState } from '../../src/domain/classification/lanes';
import type { WalletUtxo } from '../../src/domain/classification/types';
import { contextArb, FRESH_CONTEXT, utxoArb } from './arbitraries';

describe('balance summary (§10.2)', () => {
  it('buckets partition total value exactly', () => {
    fc.assert(
      fc.property(fc.array(utxoArb, { maxLength: 30 }), contextArb, (utxos, ctx) => {
        const total = utxos.reduce((sum, u) => sum + u.valueSats, 0n);
        const s = summarizeBalances(utxos, ctx);
        expect(
          s.availableSats +
            s.protectedSats +
            s.reservedSats +
            s.pendingSats +
            s.frozenSats +
            s.unavailableCleanSats,
        ).toBe(total);
      }),
    );
  });

  it('available never counts protected, reserved, frozen, or pending value', () => {
    fc.assert(
      fc.property(fc.array(utxoArb, { maxLength: 30 }), contextArb, (utxos, ctx) => {
        const s = summarizeBalances(utxos, ctx);
        const eligibleOnly = utxos.filter(
          (u) =>
            u.facts?.primaryClass === 'cardinal_clean' &&
            laneState(u) === 'normal' &&
            !u.flags.userFrozen &&
            !u.flags.dustQuarantined &&
            !(u.height === null && !u.walletCreatedChange),
        );
        const upperBound = eligibleOnly.reduce((sum, u) => sum + u.valueSats, 0n);
        expect(s.availableSats <= upperBound).toBe(true);
      }),
    );
  });

  it('shows an unconfirmed degraded output as pending, never protected or available', () => {
    const pending: WalletUtxo = {
      outpoint: { txid: 'a'.repeat(64), vout: 0 },
      valueSats: 1_000n,
      scriptPubKey: `0014${'1'.repeat(40)}`,
      account: 0,
      lane: 'payment',
      chain: 0,
      addressIndex: 0,
      height: null,
      walletCreatedChange: false,
      facts: {
        primaryClass: 'unknown',
        inscriptions: [],
        satRanges: null,
        unsupportedAssetDetected: false,
        confidence: 'degraded',
        classifiedTip: { height: 100, hash: 'b'.repeat(64) },
        classificationRevision: 'rev-0001',
      },
      flags: { userFrozen: false, dustQuarantined: false },
    };
    expect(summarizeBalances([pending], FRESH_CONTEXT)).toMatchObject({
      pendingSats: 1_000n,
      pendingOrdinalSats: 0n,
      pendingOrdinalCount: 0,
      protectedSats: 0n,
      availableSats: 0n,
    });
  });

  it('separates a signed pending inscription hint without counting it as gallery inventory', () => {
    const pending: WalletUtxo = {
      outpoint: { txid: 'a'.repeat(64), vout: 0 },
      valueSats: 546n,
      scriptPubKey: `5120${'1'.repeat(64)}`,
      account: 0,
      lane: 'ordinals',
      chain: 0,
      addressIndex: 0,
      height: null,
      walletCreatedChange: false,
      facts: {
        primaryClass: 'unknown',
        inscriptions: [{
          inscriptionId: `${'b'.repeat(64)}i0`,
          number: 67_368_437,
          satpoint: `${'a'.repeat(64)}:0:0`,
        }],
        satRanges: null,
        unsupportedAssetDetected: false,
        confidence: 'degraded',
        classifiedTip: { height: 100, hash: 'c'.repeat(64) },
        classificationRevision: 'rev-0001',
      },
      flags: { userFrozen: false, dustQuarantined: false },
    };

    expect(summarizeBalances([pending], FRESH_CONTEXT)).toMatchObject({
      pendingSats: 546n,
      pendingOrdinalSats: 546n,
      pendingOrdinalCount: 1,
      collectiblesCount: 0,
      protectedSats: 0n,
      availableSats: 0n,
    });
  });

  it('wrong-lane protected UTXOs count into protectedSats and wrongLaneCount', () => {
    fc.assert(
      fc.property(fc.array(utxoArb, { maxLength: 30 }), contextArb, (utxos, ctx) => {
        const s = summarizeBalances(utxos, ctx);
        const wrongLane = utxos.filter((u) => laneState(u) === 'protected_wrong_address');
        expect(s.wrongLaneCount).toBe(wrongLane.length);
      }),
    );
  });

  it('provides an exact visible breakdown of protected and frozen value', () => {
    const base: WalletUtxo = {
      outpoint: { txid: 'c'.repeat(64), vout: 0 },
      valueSats: 10_000n,
      scriptPubKey: `0014${'1'.repeat(40)}`,
      account: 0,
      lane: 'payment',
      chain: 0,
      addressIndex: 0,
      height: 100,
      walletCreatedChange: false,
      facts: {
        primaryClass: 'cardinal_clean',
        inscriptions: [],
        satRanges: [],
        unsupportedAssetDetected: false,
        confidence: 'authoritative',
        classifiedTip: { height: 100, hash: 'd'.repeat(64) },
        classificationRevision: 'rev-0001',
      },
      flags: { userFrozen: false, dustQuarantined: false },
    };
    const summary = summarizeBalances([
      { ...base, valueSats: 1_000n, facts: null },
      {
        ...base,
        outpoint: { ...base.outpoint, vout: 1 },
        valueSats: 2_000n,
        facts: {
          ...base.facts!,
          primaryClass: 'inscribed',
          inscriptions: [{ inscriptionId: `${'e'.repeat(64)}i0`, satpoint: `${'c'.repeat(64)}:1:0` }],
        },
      },
      {
        ...base,
        outpoint: { ...base.outpoint, vout: 2 },
        valueSats: 3_000n,
        flags: { userFrozen: true, dustQuarantined: false },
      },
      {
        ...base,
        outpoint: { ...base.outpoint, vout: 3 },
        valueSats: 293n,
        flags: { userFrozen: false, dustQuarantined: true },
      },
    ], FRESH_CONTEXT);
    expect(summary).toMatchObject({
      protectedSats: 3_000n,
      frozenSats: 3_293n,
      assetProtectedSats: 2_000n,
      awaitingClassificationSats: 1_000n,
      userFrozenSats: 3_000n,
      dustQuarantinedSats: 293n,
    });
  });

  it('reserved lane BTC is clean ordinals-lane value, never available', () => {
    fc.assert(
      fc.property(fc.array(utxoArb, { maxLength: 30 }), contextArb, (utxos, ctx) => {
        const s = summarizeBalances(utxos, ctx);
        const reserved = utxos
          .filter((u) =>
            laneState(u) === 'reserved_ordinal_lane_btc' &&
            !(u.height === null && !u.walletCreatedChange))
          .reduce((sum, u) => sum + u.valueSats, 0n);
        expect(s.reservedSats).toBe(reserved);
      }),
    );
  });
});
