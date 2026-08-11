import { describe, expect, it } from 'vitest';
import { labelGroupKey } from '../../src/domain/classification/labels';
import {
  addressSlotKey,
  countUtxosPerAddress,
  utxoPrivacySignals,
  walletPrivacyNotes,
  type PrivacySignalContext,
} from '../../src/domain/classification/privacy-signals';
import type { WalletOutpoint, WalletUtxo } from '../../src/domain/classification/types';

const P2WPKH = `0014${'1'.repeat(40)}`;

function coin(nibble: string, overrides: Partial<WalletUtxo> = {}): WalletUtxo {
  return {
    outpoint: { txid: nibble.repeat(64), vout: 0 },
    valueSats: 50_000n,
    scriptPubKey: P2WPKH,
    account: 0,
    lane: 'payment',
    chain: 0,
    addressIndex: 0,
    height: 1,
    walletCreatedChange: false,
    facts: {
      primaryClass: 'cardinal_clean',
      inscriptions: [],
      satRanges: null,
      unsupportedAssetDetected: false,
      confidence: 'authoritative',
      classifiedTip: { height: 10, hash: 'f'.repeat(64) },
      classificationRevision: 'rev-1',
    },
    flags: { userFrozen: false, dustQuarantined: false },
    ...overrides,
  };
}

function outpoint(nibble: string, vout = 0): WalletOutpoint {
  return { txid: nibble.repeat(64), vout };
}

function context(overrides: Partial<PrivacySignalContext> = {}): PrivacySignalContext {
  return {
    utxosPerAddress: new Map(),
    walletTransactionInputs: new Map(),
    labelGroupByOutpoint: new Map(),
    ...overrides,
  };
}

describe('local privacy signals (§14.4)', () => {
  it('reports suspicious dust as a linkability probe', () => {
    const dust = coin('a', { flags: { userFrozen: false, dustQuarantined: true } });
    expect(utxoPrivacySignals(dust, context())).toEqual(['dust_attack']);
    expect(utxoPrivacySignals(coin('a'), context())).toEqual([]);
  });

  it('flags an address only once it demonstrably holds more than one output', () => {
    const first = coin('a');
    const second = coin('b');
    const alone = countUtxosPerAddress([first]);
    expect(utxoPrivacySignals(first, context({ utxosPerAddress: alone }))).toEqual([]);

    const shared = countUtxosPerAddress([first, second]);
    expect(utxoPrivacySignals(first, context({ utxosPerAddress: shared })))
      .toEqual(['shared_address']);
  });

  it('keeps distinct address slots apart', () => {
    const payment = coin('a');
    const change = coin('b', { chain: 1, addressIndex: 4 });
    expect(addressSlotKey(payment)).not.toBe(addressSlotKey(change));
    const counts = countUtxosPerAddress([payment, change]);
    expect(utxoPrivacySignals(payment, context({ utxosPerAddress: counts }))).toEqual([]);
  });

  it('reports a merge only for wallet change from a multi-input wallet transaction', () => {
    const inputs = new Map([[
      'c'.repeat(64), [outpoint('a'), outpoint('b')],
    ]]);
    const change = coin('c', { walletCreatedChange: true });
    expect(utxoPrivacySignals(change, context({ walletTransactionInputs: inputs })))
      .toEqual(['merged_origin']);

    // Same transaction, but the output is not wallet-created change.
    const received = coin('c');
    expect(utxoPrivacySignals(received, context({ walletTransactionInputs: inputs })))
      .toEqual([]);

    // A single-input transaction merges nothing.
    const single = new Map([['c'.repeat(64), [outpoint('a')]]]);
    expect(utxoPrivacySignals(change, context({ walletTransactionInputs: single })))
      .toEqual([]);
  });

  it('stays quiet about transactions this wallet did not build', () => {
    const change = coin('c', { walletCreatedChange: true });
    expect(utxoPrivacySignals(change, context())).toEqual([]);
  });

  it('escalates to a mixed-label merge only when the inputs spanned groups', () => {
    const walletTransactionInputs = new Map([[
      'c'.repeat(64), [outpoint('a'), outpoint('b')],
    ]]);
    const change = coin('c', { walletCreatedChange: true });

    const sameGroup = new Map([
      [`${'a'.repeat(64)}:0`, 'exchange_withdrawal|'],
      [`${'b'.repeat(64)}:0`, 'exchange_withdrawal|'],
    ]);
    expect(utxoPrivacySignals(change, context({ walletTransactionInputs, labelGroupByOutpoint: sameGroup })))
      .toEqual(['merged_origin']);

    const crossGroup = new Map([
      [`${'a'.repeat(64)}:0`, 'exchange_withdrawal|'],
      [`${'b'.repeat(64)}:0`, 'savings|'],
    ]);
    expect(utxoPrivacySignals(change, context({ walletTransactionInputs, labelGroupByOutpoint: crossGroup })))
      .toEqual(['merged_origin', 'mixed_label_origin']);
  });

  it('emits signals in a stable order', () => {
    const walletTransactionInputs = new Map([[
      'c'.repeat(64), [outpoint('a'), outpoint('b')],
    ]]);
    const labelGroupByOutpoint = new Map([
      [`${'a'.repeat(64)}:0`, 'savings|'],
      [`${'b'.repeat(64)}:0`, 'purchase|'],
    ]);
    const change = coin('c', {
      walletCreatedChange: true,
      flags: { userFrozen: false, dustQuarantined: true },
    });
    const counts = countUtxosPerAddress([change, coin('d')]);
    expect(utxoPrivacySignals(change, {
      utxosPerAddress: counts, walletTransactionInputs, labelGroupByOutpoint,
    })).toEqual(['dust_attack', 'shared_address', 'merged_origin', 'mixed_label_origin']);
  });

  it('reports the §8.1 stable receive address once, wallet-wide', () => {
    expect(walletPrivacyNotes({ externalAddressRotates: false }))
      .toEqual(['stable_receive_address']);
    expect(walletPrivacyNotes({ externalAddressRotates: true })).toEqual([]);
  });
});

describe('label grouping (§14.1)', () => {
  it('separates two exchanges that share a preset', () => {
    const kraken = labelGroupKey({ preset: 'exchange_withdrawal', text: 'Kraken' });
    const strike = labelGroupKey({ preset: 'exchange_withdrawal', text: 'Strike' });
    expect(kraken).not.toBe(strike);
  });

  it('folds case and surrounding whitespace so a group does not split by accident', () => {
    expect(labelGroupKey({ preset: null, text: ' Kraken ' }))
      .toBe(labelGroupKey({ preset: null, text: 'kraken' }));
  });

  it('keeps a bare preset distinct from the same preset with a note', () => {
    expect(labelGroupKey({ preset: 'savings', text: null }))
      .not.toBe(labelGroupKey({ preset: 'savings', text: 'cold' }));
  });
});
