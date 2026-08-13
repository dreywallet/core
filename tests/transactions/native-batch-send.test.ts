import { Address, TEST_NETWORK } from '@scure/btc-signer';
import { describe, expect, it } from 'vitest';
import type { WalletUtxo } from '../../src/domain/classification/types';
import {
  buildNativeBatchSendCandidate,
  resolvePayableAddress,
  type NativeSendChangeOutput,
} from '../../src/domain/transactions/native-send';
import type { PlanDerivation } from '../../src/domain/transactions/plan';

const ACCOUNT_ID = `acct_signet_${'a'.repeat(64)}`;
const P2WPKH = `0014${'1'.repeat(40)}`;
const facts = { primaryClass: 'cardinal_clean' as const, inscriptions: [], satRanges: null,
  unsupportedAssetDetected: false, confidence: 'authoritative' as const,
  classifiedTip: { height: 10, hash: 'f'.repeat(64) }, classificationRevision: 'rev-1' };
const coin: WalletUtxo = {
  outpoint: { txid: 'a'.repeat(64), vout: 0 }, valueSats: 100_000n, scriptPubKey: P2WPKH,
  accountId: ACCOUNT_ID, account: 0, lane: 'payment', chain: 0, addressIndex: 0, height: 1,
  walletCreatedChange: false, facts, flags: { userFrozen: false, dustQuarantined: false },
};
const changeOutput: NativeSendChangeOutput = {
  address: Address(TEST_NETWORK).encode({ type: 'wpkh', hash: new Uint8Array(20).fill(8) }),
  scriptPubKey: `0014${'2'.repeat(40)}`, role: 'payment_change',
  derivation: { accountId: ACCOUNT_ID, account: 0, lane: 'payment', chain: 1, index: 0,
    path: "m/84'/1'/0'/1/0", publicKeyHex: `02${'2'.repeat(64)}` },
};
const deriveInput = (utxo: WalletUtxo): PlanDerivation => ({
  accountId: utxo.accountId, account: 0, lane: 'payment', chain: 0, index: 0,
  path: "m/84'/1'/0'/0/0", publicKeyHex: `02${'1'.repeat(64)}`,
});
const resolved = (fill: number) => {
  const result = resolvePayableAddress(
    Address(TEST_NETWORK).encode({ type: 'wpkh', hash: new Uint8Array(20).fill(fill) }), 'signet',
  );
  if (!result.ok) throw new Error('fixture address failed');
  return result.value;
};

describe('native batch send', () => {
  const base = {
    accountId: ACCOUNT_ID, account: 0, utxos: [coin],
    eligibility: { freshness: { commonTip: true, heartbeatFresh: true, revisionActive: true, spendEligible: true },
      activeRevision: 'rev-1', lockedOutpoints: new Set<string>() },
    feeRate: 2_000n, changeOutput, deriveInput,
  };

  it('preserves ordered recipients and uses one atomic selection', () => {
    const outcome = buildNativeBatchSendCandidate({ ...base, recipients: [
      { recipient: resolved(3), amountSats: 10_000n },
      { recipient: resolved(4), amountSats: 20_000n },
    ] });
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) throw new Error(outcome.reason);
    expect(outcome.candidate.outputs.slice(0, 2).map((output) => output.valueSats))
      .toEqual([10_000n, 20_000n]);
    expect(outcome.candidate.inputs).toHaveLength(1);
    expect(outcome.candidate.rbf).toBe(true);
  });

  it('fails closed on duplicates, dust, and recipient-count limits', () => {
    const recipient = resolved(3);
    expect(buildNativeBatchSendCandidate({ ...base, recipients: [
      { recipient, amountSats: 1_000n }, { recipient, amountSats: 2_000n },
    ] })).toEqual({ ok: false, reason: 'duplicate_recipient' });
    expect(buildNativeBatchSendCandidate({ ...base, recipients: [
      { recipient: resolved(3), amountSats: 293n }, { recipient: resolved(4), amountSats: 2_000n },
    ] })).toEqual({ ok: false, reason: 'dust' });
    expect(buildNativeBatchSendCandidate({ ...base, recipients: [] }))
      .toEqual({ ok: false, reason: 'invalid_recipient_count' });
  });
});
