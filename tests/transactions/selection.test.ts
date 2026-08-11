import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import type { WalletUtxo } from '../../src/domain/classification/types';
import { estimateVsize, feeForVsize, sequenceForInput } from '../../src/domain/transactions/fees';
import { selectCoins } from '../../src/domain/transactions/selection';

const P2WPKH = `0014${'1'.repeat(40)}`;
const ACCOUNT_ID = `acct_signet_${'a'.repeat(64)}`;
const freshness = { commonTip: true, heartbeatFresh: true, revisionActive: true, spendEligible: true };
const eligibility = { freshness, activeRevision: 'rev-1', lockedOutpoints: new Set<string>() };

function coin(nibble: string, valueSats: bigint, overrides: Partial<WalletUtxo> = {}): WalletUtxo {
  return {
    outpoint: { txid: nibble.repeat(64), vout: 0 }, valueSats, scriptPubKey: P2WPKH,
    accountId: ACCOUNT_ID, account: 0, lane: 'payment', chain: 0, addressIndex: 0, height: 1,
    walletCreatedChange: false,
    facts: { primaryClass: 'cardinal_clean', inscriptions: [], satRanges: null,
      unsupportedAssetDetected: false, confidence: 'authoritative',
      classifiedTip: { height: 10, hash: 'f'.repeat(64) }, classificationRevision: 'rev-1' },
    flags: { userFrozen: false, dustQuarantined: false }, ...overrides,
  };
}

function request(utxos: WalletUtxo[]) {
  return { utxos, eligibility, accountId: ACCOUNT_ID, account: 0, feeRate: 2_000n, targetSats: 20_000n,
    recipientScripts: [P2WPKH], changeScript: P2WPKH, sendMax: false };
}

describe('M7 deterministic coin selection', () => {
  it('routes all candidates through eligibility and rejects excluded manual inputs', () => {
    const frozen = coin('a', 100_000n, { flags: { userFrozen: true, dustQuarantined: false } });
    expect(() => selectCoins({ ...request([frozen]), selectedOutpoints: new Set([`${'a'.repeat(64)}:0`]) })).toThrow(/ineligible/u);
  });

  it('never mixes public accounts that share the same BIP32 account index', () => {
    const foreignId = `acct_signet_${'b'.repeat(64)}`;
    const local = coin('a', 30_000n);
    const foreign = coin('b', 100_000n, { accountId: foreignId });
    const selected = selectCoins(request([foreign, local]));
    expect(selected.inputs).toEqual([local]);
    expect(() => selectCoins({
      ...request([foreign]),
      selectedOutpoints: new Set([`${'b'.repeat(64)}:0`]),
    })).toThrow('manual selection');
  });

  it('Send Max spends only eligible inputs and has no change', () => {
    const eligible = coin('a', 50_000n);
    const protectedCoin = coin('b', 80_000n, { facts: { ...coin('b', 1n).facts!, primaryClass: 'inscribed' } });
    const selected = selectCoins({ ...request([eligible, protectedCoin]), targetSats: 0n, sendMax: true });
    expect(selected.inputs.map((input) => input.outpoint.txid)).toEqual([eligible.outpoint.txid]);
    expect(selected.changeSats).toBe(0n);
    expect(selected.recipientSats + selected.feeSats).toBe(eligible.valueSats);
  });

  it('is independent of candidate order', () => {
    const coins = [coin('a', 11_000n), coin('b', 15_000n), coin('c', 35_000n)];
    const expected = selectCoins(request(coins)).inputs.map((input) => input.outpoint.txid);
    fc.assert(fc.property(fc.shuffledSubarray(coins, { minLength: coins.length, maxLength: coins.length }), (shuffled) => {
      expect(selectCoins(request(shuffled)).inputs.map((input) => input.outpoint.txid)).toEqual(expected);
    }));
  });

  it('keeps owned change above the script-specific economic threshold', () => {
    const selected = selectCoins(request([coin('a', 30_000n)]));
    expect(selected.changeSats).toBeGreaterThan(294n);
  });

  it('uses exact bigint fee arithmetic above Number.MAX_SAFE_INTEGER', () => {
    const vsize = BigInt(Number.MAX_SAFE_INTEGER) + 123n;
    expect(feeForVsize(vsize, 10_000n)).toBe(vsize * 10n);
  });

  it('handles exact balance and dust without creating a dust change output', () => {
    const exact = selectCoins(request([coin('a', 20_220n)]));
    expect(exact).toMatchObject({ recipientSats: 20_000n, changeSats: 0n, feeSats: 220n, vsize: 110n });

    const dust = selectCoins(request([coin('a', 20_513n)]));
    expect(dust.changeSats).toBe(0n);
    expect(dust.feeSats).toBe(513n);

    const economic = selectCoins(request([coin('a', 20_577n)]));
    expect(economic.changeSats).toBe(295n);
    expect(economic.feeSats).toBe(282n);
  });

  it('uses CompactSize-aware conservative bounds for 1, 100, and 500 inputs', () => {
    expect(estimateVsize([P2WPKH], [P2WPKH])).toBe(110n);
    expect(estimateVsize(Array.from({ length: 100 }, () => P2WPKH), [P2WPKH])).toBe(6_842n);
    expect(estimateVsize(Array.from({ length: 500 }, () => P2WPKH), [P2WPKH])).toBe(34_044n);
  });

  it('prefers not to merge label groups when the cost is identical (§14.1)', () => {
    // Three equal coins, so every pair carries identical waste. Group-wise,
    // only (b,c) stays inside one group — and it is NOT the pair deterministic
    // outpoint order would otherwise pick, so the assertion is meaningful.
    const coins = [coin('a', 12_000n), coin('b', 12_000n), coin('c', 12_000n)];
    const req = { ...request(coins), targetSats: 15_000n };

    const unlabeled = selectCoins(req).inputs.map((input) => input.outpoint.txid);
    expect(unlabeled).toEqual(['a'.repeat(64), 'b'.repeat(64)]);

    const labelGroupByOutpoint = new Map([
      [`${'a'.repeat(64)}:0`, 'savings|'],
      [`${'b'.repeat(64)}:0`, 'exchange_withdrawal|'],
      [`${'c'.repeat(64)}:0`, 'exchange_withdrawal|'],
    ]);
    const labeled = selectCoins({ ...req, labelGroupByOutpoint });
    expect(labeled.inputs.map((input) => input.outpoint.txid))
      .toEqual(['b'.repeat(64), 'c'.repeat(64)]);
    // Same cost — the preference only ever reorders economically tied options.
    expect(labeled.feeSats + labeled.changeSats).toBe(selectCoins(req).feeSats + selectCoins(req).changeSats);
  });

  it('never lets the label preference cost the user sats (§14.1)', () => {
    // The cheap option merges two groups; the single-group option wastes 8k
    // more. Waste is compared first, so the cheap merging option must win.
    const coins = [coin('a', 8_000n), coin('b', 8_000n), coin('c', 24_000n)];
    const labelGroupByOutpoint = new Map([
      [`${'a'.repeat(64)}:0`, 'savings|'],
      [`${'b'.repeat(64)}:0`, 'exchange_withdrawal|'],
      [`${'c'.repeat(64)}:0`, 'savings|'],
    ]);
    const selected = selectCoins({
      ...request(coins), targetSats: 15_000n, labelGroupByOutpoint,
    });
    expect(selected.inputs.map((input) => input.outpoint.txid))
      .toEqual(['a'.repeat(64), 'b'.repeat(64)]);
  });

  it('leaves selection untouched when nothing is labeled', () => {
    const coins = [coin('a', 11_000n), coin('b', 15_000n), coin('c', 35_000n)];
    const expected = selectCoins(request(coins));
    const withEmptyMap = selectCoins({
      ...request(coins), labelGroupByOutpoint: new Map<string, string>(),
    });
    expect(withEmptyMap).toEqual(expected);
  });

  it('stays order-independent with labels applied', () => {
    const coins = [coin('a', 12_000n), coin('b', 12_000n), coin('c', 12_000n)];
    const labelGroupByOutpoint = new Map([
      [`${'a'.repeat(64)}:0`, 'savings|'],
      [`${'b'.repeat(64)}:0`, 'exchange_withdrawal|'],
      [`${'c'.repeat(64)}:0`, 'exchange_withdrawal|'],
    ]);
    const req = { ...request(coins), targetSats: 15_000n, labelGroupByOutpoint };
    const expected = selectCoins(req).inputs.map((input) => input.outpoint.txid);
    fc.assert(fc.property(
      fc.shuffledSubarray(coins, { minLength: coins.length, maxLength: coins.length }),
      (shuffled) => {
        expect(selectCoins({ ...req, utxos: shuffled }).inputs.map((i) => i.outpoint.txid))
          .toEqual(expected);
      },
    ));
  });

  it('never lets a label group make an ineligible input spendable', () => {
    const frozen = coin('a', 100_000n, { flags: { userFrozen: true, dustQuarantined: false } });
    const clean = coin('b', 100_000n);
    const labelGroupByOutpoint = new Map([[`${'a'.repeat(64)}:0`, 'savings|']]);
    const selected = selectCoins({ ...request([frozen, clean]), labelGroupByOutpoint });
    expect(selected.inputs.map((input) => input.outpoint.txid)).toEqual(['b'.repeat(64)]);
  });

  it('propagates RBF sequences while rescue and sweep remain non-replaceable', () => {
    expect(sequenceForInput('rbf', 0xfffffffc)).toBe(0xfffffffc);
    expect(sequenceForInput('rbf', 0xffffffff)).toBe(0xffffffff);
    expect(sequenceForInput('rbf')).toBe(0xfffffffd);
    expect(sequenceForInput('native_send')).toBe(0xfffffffd);
    expect(sequenceForInput('rescue')).toBe(0xffffffff);
    expect(sequenceForInput('ordinal_sweep')).toBe(0xffffffff);
  });
});
