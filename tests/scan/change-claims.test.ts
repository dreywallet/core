import { beforeAll, describe, expect, it } from 'vitest';
import { hashPlan } from '../../src/domain/transactions/plan';
import type { StoredTransaction } from '../../src/scan/cache-schemas';
import { deriveLocalChangeClaims } from '../../src/scan/change-claims';
import { installTestCryptoProvider } from '../helpers/install-crypto-provider';

beforeAll(installTestCryptoProvider);

const TXID = 'a'.repeat(64);
const SCRIPT = '0014' + 'b'.repeat(40);

function journal(overrides: Record<string, unknown> = {}): StoredTransaction {
  const planId = 'plan-1';
  const kind = 'native_send';
  const transaction = {
    planId,
    kind,
    txid: TXID,
    createdAt: 1,
    amountSats: 1n,
    feeSats: 1n,
    status: 'accepted',
    detail: null,
    parentTxid: null,
    replacesTxid: null,
    plan: {
      version: 4,
      planId,
      kind,
      network: 'signet',
      account: 0,
      planHash: 'c'.repeat(64),
      outputs: [
        { role: 'recipient', valueSats: 1n, scriptPubKey: SCRIPT, address: 'recipient' },
        {
          role: 'payment_change', valueSats: 2n, scriptPubKey: SCRIPT,
          address: 'change', derivation: { account: 0, lane: 'payment', chain: 1, index: 2 },
        },
        {
          role: 'ordinal_change', valueSats: 3n, scriptPubKey: SCRIPT,
          address: 'ordinal-change', derivation: { account: 0, lane: 'ordinals', chain: 1, index: 3 },
        },
        {
          role: 'postage', valueSats: 4n, scriptPubKey: SCRIPT,
          address: 'postage', derivation: { account: 0, lane: 'ordinals', chain: 1, index: 4 },
        },
      ],
    },
    ...overrides,
  } as unknown as StoredTransaction;
  transaction.plan.planHash = hashPlan(transaction.plan);
  return transaction;
}

function claims(transactions: readonly StoredTransaction[]) {
  return deriveLocalChangeClaims(
    transactions.map((transaction) => ({ cacheKey: transaction.txid, transaction })),
    'signet',
  );
}

describe('deriveLocalChangeClaims', () => {
  it('derives only current accepted change outputs and never recipients', () => {
    expect(claims([journal()])).toEqual([
      { txid: TXID, vout: 1, valueSats: 2n, scriptPubKey: SCRIPT, role: 'payment_change' },
      { txid: TXID, vout: 2, valueSats: 3n, scriptPubKey: SCRIPT, role: 'ordinal_change' },
      { txid: TXID, vout: 3, valueSats: 4n, scriptPubKey: SCRIPT, role: 'ordinal_change' },
    ]);
  });

  it('ignores non-current or non-accepted records', () => {
    expect(claims([
      journal({ status: 'rejected' }),
      journal({ status: 'conflicted' }),
      journal({ plan: { ...journal().plan, version: 3 } }),
    ])).toEqual([]);
  });

  it.each(['planId', 'kind', 'network'] as const)(
    'fails closed for a mismatched stored %s binding', (label) => {
    const override = label === 'planId'
      ? { planId: 'different' }
      : label === 'kind'
        ? { kind: 'cpfp' }
        : { plan: { ...journal().plan, network: 'mainnet' } };
    expect(claims([journal(override)])).toBeNull();
    },
  );

  it('fails closed for ambiguous duplicate transaction outputs', () => {
    expect(claims([journal(), journal()])).toBeNull();
  });

  it('bounds lifetime journal history, preferring live rows and newest rows', () => {
    const many = Array.from({ length: 129 }, (_, index) => journal({
      txid: index.toString(16).padStart(64, '0'),
      createdAt: 10_000 + index,
      status: 'confirmed',
      plan: {
        ...journal().plan,
        outputs: [
          {
            role: 'payment_change', valueSats: 2n, scriptPubKey: SCRIPT, address: 'change',
            derivation: { account: 0, lane: 'payment', chain: 1, index: 2 },
          },
        ],
      },
    }));
    const liveTxid = 'f'.repeat(64);
    const derived = claims([
      ...many,
      journal({ txid: liveTxid, createdAt: 1, status: 'accepted', plan: {
        ...journal().plan,
        outputs: [{
          role: 'payment_change', valueSats: 2n, scriptPubKey: SCRIPT, address: 'change',
          derivation: { account: 0, lane: 'payment', chain: 1, index: 2 },
        }],
      } }),
    ]);
    expect(derived).toHaveLength(128);
    expect(derived?.[0]?.txid).toBe(liveTxid);
    // The oldest confirmed row is outside the bounded window and therefore
    // gets no claim instead of invalidating the newer evidence.
    expect(derived?.some((claim) => claim.txid === '0'.repeat(64))).toBe(false);
  });

  it('fails closed when a change output is not an internal chain-1 derivation', () => {
    expect(claims([journal({
      plan: {
        ...journal().plan,
        outputs: [{
          role: 'payment_change', valueSats: 2n, scriptPubKey: SCRIPT, address: 'change',
          derivation: { account: 0, lane: 'payment', chain: 0, index: 2 },
        }],
      },
    })])).toBeNull();
  });

  it('fails closed when the plan hash or encrypted-cache key is changed', () => {
    const mutated = journal();
    mutated.plan.outputs[1]!.valueSats += 1n;
    expect(claims([mutated])).toBeNull();

    const transaction = journal();
    expect(deriveLocalChangeClaims([
      { cacheKey: 'f'.repeat(64), transaction },
    ], 'signet')).toBeNull();
  });
});
