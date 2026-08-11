import fc from 'fast-check';
import { Address, TEST_NETWORK } from '@scure/btc-signer';
import { describe, expect, it } from 'vitest';
import type { WalletUtxo } from '../../src/domain/classification/types';
import {
  buildNativeSendCandidate,
  resolvePayableAddress,
  type NativeSendCandidateRequest,
  type NativeSendChangeOutput,
  type ResolvedPayableAddress,
} from '../../src/domain/transactions/native-send';
import type { PlanDerivation } from '../../src/domain/transactions/plan';

const P2WPKH = `0014${'1'.repeat(40)}`;
const ACCOUNT_ID = `acct_signet_${'a'.repeat(64)}`;
const freshness = { commonTip: true, heartbeatFresh: true, revisionActive: true, spendEligible: true };
const eligibility = { freshness, activeRevision: 'rev-1', lockedOutpoints: new Set<string>() };
const recipientAddress = Address(TEST_NETWORK).encode({ type: 'wpkh', hash: new Uint8Array(20).fill(7) });
const recipientOutcome = resolvePayableAddress(recipientAddress, 'signet');
const RECIPIENT: ResolvedPayableAddress = recipientOutcome.ok
  ? recipientOutcome.value
  : (() => { throw new Error('fixture recipient did not resolve'); })();

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

function derivationFor(utxo: WalletUtxo): PlanDerivation {
  return {
    accountId: utxo.accountId, account: utxo.account, lane: utxo.lane,
    chain: utxo.chain, index: utxo.addressIndex,
    path: `m/84'/1'/${utxo.account}'/${utxo.chain}/${utxo.addressIndex}`,
    publicKeyHex: `02${'1'.repeat(64)}`,
  };
}

const changeOutput: NativeSendChangeOutput = {
  address: Address(TEST_NETWORK).encode({ type: 'wpkh', hash: new Uint8Array(20).fill(8) }),
  scriptPubKey: `0014${'2'.repeat(40)}`,
  role: 'payment_change',
  derivation: {
    accountId: ACCOUNT_ID, account: 0, lane: 'payment', chain: 1, index: 4,
    path: "m/84'/1'/0'/1/4", publicKeyHex: `02${'2'.repeat(64)}`,
  },
};

function request(
  utxos: readonly WalletUtxo[],
  overrides: Partial<NativeSendCandidateRequest> = {},
): NativeSendCandidateRequest {
  return {
    recipient: RECIPIENT,
    amountSats: 20_000n,
    sendMax: false,
    accountId: ACCOUNT_ID,
    account: 0,
    utxos,
    eligibility,
    feeRate: 2_000n,
    changeOutput,
    deriveInput: derivationFor,
    ...overrides,
  };
}

function expectCandidate(outcome: ReturnType<typeof buildNativeSendCandidate>) {
  expect(outcome.ok).toBe(true);
  if (!outcome.ok) throw new Error(`unexpected candidate failure: ${outcome.reason}`);
  return outcome.candidate;
}

describe('M2m payable address resolution', () => {
  const PAYABLE = {
    p2pkh: '1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2',
    p2sh: '3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy',
    p2wpkh: 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4',
    p2wsh: 'bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3',
    p2tr: 'bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr',
  } as const;

  it('resolves all five established payable types and preserves the original address', () => {
    for (const [kind, address] of Object.entries(PAYABLE)) {
      const result = resolvePayableAddress(address, 'mainnet');
      expect(result).toMatchObject({ ok: true, value: { address, scriptKind: kind } });
    }
  });

  it('distinguishes wrong-network and malformed addresses from future witness output types', () => {
    expect(resolvePayableAddress(recipientAddress, 'mainnet'))
      .toEqual({ ok: false, reason: 'invalid_address' });
    expect(resolvePayableAddress('not-an-address', 'mainnet'))
      .toEqual({ ok: false, reason: 'invalid_address' });
    expect(resolvePayableAddress('bc1QW508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4', 'mainnet'))
      .toEqual({ ok: false, reason: 'invalid_address' });
    expect(resolvePayableAddress('BC1SW50QGDZ25J', 'mainnet'))
      .toEqual({ ok: false, reason: 'unsupported_output_type' });
  });
});

describe('M2m native-send candidate construction', () => {
  it('constructs the exact fixed-amount shape, RBF sequence and economic change', () => {
    const candidate = expectCandidate(buildNativeSendCandidate(request([coin('a', 30_000n)])));
    expect(candidate).toMatchObject({
      accountId: ACCOUNT_ID, account: 0, feeSats: 282n, vsize: 141n,
      protectedSatFlow: [], rbf: true,
      parentTxid: null, replacesTxid: null,
    });
    expect(candidate.inputs).toEqual([expect.objectContaining({
      txid: 'a'.repeat(64), sequence: 0xfffffffd, sighash: 1, ownership: 'wallet',
    })]);
    expect(candidate.outputs).toEqual([
      { address: recipientAddress, scriptPubKey: RECIPIENT.scriptPubKey,
        valueSats: 20_000n, role: 'recipient' },
      { ...changeOutput, valueSats: 9_718n },
    ]);
  });

  it('preserves exact/no-change and strict economic-threshold boundaries', () => {
    const exact = expectCandidate(buildNativeSendCandidate(request([coin('a', 20_220n)])));
    expect(exact.outputs).toHaveLength(1);
    expect(exact).toMatchObject({ feeSats: 220n, vsize: 110n });

    const atThreshold = expectCandidate(buildNativeSendCandidate(request([coin('a', 20_576n)])));
    expect(atThreshold.outputs).toHaveLength(1);
    expect(atThreshold.feeSats).toBe(576n);

    const aboveThreshold = expectCandidate(buildNativeSendCandidate(request([coin('a', 20_577n)])));
    expect(aboveThreshold.outputs[1]?.valueSats).toBe(295n);
    expect(aboveThreshold.feeSats).toBe(282n);
  });

  it('returns dust at floor-1 and succeeds at the exact recipient floor', () => {
    expect(buildNativeSendCandidate(request([coin('a', 10_000n)], { amountSats: 293n })))
      .toEqual({ ok: false, reason: 'dust' });
    const floor = expectCandidate(buildNativeSendCandidate(
      request([coin('a', 10_000n)], { amountSats: 294n }),
    ));
    expect(floor.outputs[0]?.valueSats).toBe(294n);
  });

  it('keeps insufficient funds distinct from manual-selection mismatch', () => {
    expect(buildNativeSendCandidate(request([])))
      .toEqual({ ok: false, reason: 'insufficient_eligible_funds' });
    expect(buildNativeSendCandidate(request([coin('a', 100_000n)], {
      selectedOutpoints: new Set([`${'b'.repeat(64)}:0`]),
    }))).toEqual({ ok: false, reason: 'manual_selection_mismatch' });
    expect(buildNativeSendCandidate(request([coin('a', 1_000n)], {
      selectedOutpoints: new Set([`${'a'.repeat(64)}:0`]),
    }))).toEqual({ ok: false, reason: 'insufficient_eligible_funds' });
  });

  it('Send Max spends only eligible ordinary payment inputs and emits no change', () => {
    const protectedCoin = coin('b', 80_000n, {
      facts: { ...coin('b', 1n).facts!, primaryClass: 'inscribed' },
    });
    const candidate = expectCandidate(buildNativeSendCandidate(request(
      [coin('a', 50_000n), protectedCoin],
      { amountSats: 0n, sendMax: true },
    )));
    expect(candidate.inputs.map((input) => input.txid)).toEqual(['a'.repeat(64)]);
    expect(candidate.outputs).toHaveLength(1);
    expect(candidate.outputs[0]?.valueSats).toBe(49_780n);
  });

  it('excludes frozen, quarantined, stale, locked, incoming-unconfirmed and uneconomic inputs', () => {
    const cases: WalletUtxo[] = [
      coin('a', 50_000n, { flags: { userFrozen: true, dustQuarantined: false } }),
      coin('b', 50_000n, { flags: { userFrozen: false, dustQuarantined: true } }),
      coin('c', 50_000n, { facts: { ...coin('c', 1n).facts!, classificationRevision: 'old' } }),
      coin('d', 50_000n, { height: null, walletCreatedChange: false }),
      coin('e', 100n),
    ];
    for (const excluded of cases) {
      const lockedOutpoints = excluded.outpoint.txid === 'c'.repeat(64)
        ? new Set<string>()
        : eligibility.lockedOutpoints;
      expect(buildNativeSendCandidate(request([excluded], {
        eligibility: { ...eligibility, lockedOutpoints },
      }))).toEqual({ ok: false, reason: 'insufficient_eligible_funds' });
    }
    const locked = coin('f', 50_000n);
    expect(buildNativeSendCandidate(request([locked], {
      eligibility: { ...eligibility, lockedOutpoints: new Set([`${locked.outpoint.txid}:0`]) },
    }))).toEqual({ ok: false, reason: 'insufficient_eligible_funds' });
  });

  it('preserves label-group tie-breaking and remains independent of UTXO order', () => {
    const coins = [coin('a', 12_000n), coin('b', 12_000n), coin('c', 12_000n)];
    const labels = new Map([
      [`${'a'.repeat(64)}:0`, 'savings|'],
      [`${'b'.repeat(64)}:0`, 'exchange|'],
      [`${'c'.repeat(64)}:0`, 'exchange|'],
    ]);
    const expected = ['b'.repeat(64), 'c'.repeat(64)];
    fc.assert(fc.property(
      fc.shuffledSubarray(coins, { minLength: 3, maxLength: 3 }),
      (shuffled) => {
        const candidate = expectCandidate(buildNativeSendCandidate(request(shuffled, {
          amountSats: 15_000n, labelGroupByOutpoint: labels,
        })));
        expect(candidate.inputs.map((input) => input.txid)).toEqual(expected);
      },
    ));
  });

  it('derives only selected inputs and does not remap ownership failures', () => {
    const seen: string[] = [];
    const candidate = expectCandidate(buildNativeSendCandidate(request(
      [coin('a', 21_000n), coin('b', 90_000n)],
      { deriveInput: (utxo) => { seen.push(utxo.outpoint.txid); return derivationFor(utxo); } },
    )));
    expect(seen).toEqual(candidate.inputs.map((input) => input.txid));

    expect(() => buildNativeSendCandidate(request([coin('a', 30_000n)], {
      deriveInput: () => { throw new Error('ownership mismatch'); },
    }))).toThrow('ownership mismatch');
  });

  it('rejects forged non-payment change metadata as an invariant failure', () => {
    for (const forged of [
      { ...changeOutput, role: 'recipient' },
      { ...changeOutput, derivation: { ...changeOutput.derivation, lane: 'ordinals' } },
      { ...changeOutput, derivation: { ...changeOutput.derivation, chain: 0 } },
      { ...changeOutput, derivation: { ...changeOutput.derivation, account: 1 } },
      { ...changeOutput, scriptPubKey: `5120${'3'.repeat(64)}` },
    ]) {
      expect(() => buildNativeSendCandidate(request([coin('a', 30_000n)], {
        changeOutput: forged as NativeSendChangeOutput,
      }))).toThrow('invalid native-send payment change output');
    }
  });

  it('preserves explicit empty and duplicate manual Set behavior', () => {
    expect(buildNativeSendCandidate(request([coin('a', 30_000n)], {
      selectedOutpoints: new Set(),
    }))).toEqual({ ok: false, reason: 'insufficient_eligible_funds' });
    const duplicateCollapsed = expectCandidate(buildNativeSendCandidate(request([coin('a', 30_000n)], {
      selectedOutpoints: new Set([`${'a'.repeat(64)}:0`, `${'a'.repeat(64)}:0`]),
    })));
    expect(duplicateCollapsed.inputs).toHaveLength(1);
  });

  it('keeps the caller-supplied resolved recipient string byte-for-byte', () => {
    const upper = resolvePayableAddress('BC1SW50QGDZ25J', 'mainnet');
    expect(upper).toEqual({ ok: false, reason: 'unsupported_output_type' });
    const resolved: ResolvedPayableAddress = { ...RECIPIENT, address: recipientAddress.toUpperCase() };
    const candidate = expectCandidate(buildNativeSendCandidate(request([coin('a', 30_000n)], {
      recipient: resolved,
    })));
    expect(candidate.outputs[0]?.address).toBe(recipientAddress.toUpperCase());
  });
});
