import { beforeAll, describe, expect, it } from 'vitest';
import { SigHash, Transaction } from '@scure/btc-signer';
import { publicAccountFromSeed } from '../../src/domain/accounts/public-account';
import { deriveAccountNode, deriveAddress } from '../../src/domain/keys/derivation';
import { mnemonicToSeed } from '../../src/domain/keys/mnemonic';
import { scriptPubKeyHex } from '../../src/domain/keys/script-hash';
import type { UtxoClassification } from '../../src/domain/gateway/contract';
import {
  assertProviderPsbtBatchPlan,
  createProviderPsbtBatchPlan,
  providerPsbtUnsignedTxid,
  signProviderPsbtBatchPlan,
} from '../../src/domain/transactions/provider-psbt-batch';
import { createProviderPsbtPlan, signProviderPsbtPlan } from '../../src/domain/transactions/provider-psbt';
import { base64ToBytes, bytesToBase64, hexToBytes } from '../../src/domain/vault/encoding';
import { installTestCryptoProvider } from '../helpers/install-crypto-provider';

beforeAll(() => installTestCryptoProvider());

const NOW = 1_800_000_000_000;
const seed = mnemonicToSeed('abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about');
const publicAccount = publicAccountFromSeed(seed, 'signet', 0);
const account = deriveAccountNode(seed, 'payment', 'signet', 0);
const wallet = deriveAddress(account, 'payment', 'signet', 0, 0);
const recipient = deriveAddress(account, 'payment', 'signet', 0, 1);
account.wipePrivateData();
const source = {
  backend: 'https://gateway.example', instanceId: 'gateway-1', classificationRevision: 'rev-1',
  coreTip: { height: 100, hash: 'aa'.repeat(32) }, indexTip: { height: 100, hash: 'aa'.repeat(32) },
  feeQuoteTimestamp: null, mempoolState: null,
};
const binding = {
  origin: 'https://app.example', tabId: 1, frameId: 0,
  documentId: '123e4567-e89b-42d3-a456-426614174000',
  requestNonce: '123e4567-e89b-42d3-a456-426614174001',
  providerMethod: 'signMultipleTransactions' as const,
};

function plan(input: {
  txid: string;
  planId: string;
  amount?: bigint;
  bindingOverride?: Partial<typeof binding>;
  metadataTag?: number;
  network?: 'mainnet' | 'signet' | 'regtest';
  sessionId?: string;
  accountNumber?: number;
}) {
  const amount = input.amount ?? 50_000n;
  const network = input.network ?? 'signet';
  const accountNumber = input.accountNumber ?? 0;
  const useFixtureAccount = network === 'signet' && accountNumber === 0;
  const planAccount = useFixtureAccount ? account : deriveAccountNode(seed, 'payment', network, accountNumber);
  const planWallet = useFixtureAccount ? wallet : deriveAddress(planAccount, 'payment', network, 0, 0);
  const planRecipient = useFixtureAccount ? recipient : deriveAddress(planAccount, 'payment', network, 0, 1);
  const accountId = useFixtureAccount
    ? publicAccount.accountId
    : publicAccountFromSeed(seed, network, accountNumber).accountId;
  const planWalletScript = scriptPubKeyHex(planWallet.publicKeyHex, 'payment', network);
  const planRecipientScript = scriptPubKeyHex(planRecipient.publicKeyHex, 'payment', network);
  if (!useFixtureAccount) planAccount.wipePrivateData();
  const tx = new Transaction({ lowR: true });
  tx.addInput({
    txid: input.txid,
    index: 0,
    sequence: 0xfffffffd,
    sighashType: SigHash.ALL,
    witnessUtxo: { script: hexToBytes(planWalletScript), amount },
    ...(input.metadataTag === undefined ? {} : {
      proprietary: [[new Uint8Array([0x64, 0x72, 0x65, 0x79, input.metadataTag]), new Uint8Array([1])]],
    }),
  });
  tx.addOutput({ script: hexToBytes(planRecipientScript), amount: amount - 2_000n });
  const classification: UtxoClassification = {
    txid: input.txid,
    vout: 0,
    valueSats: amount.toString(),
    scriptPubKey: planWalletScript,
    confirmations: 10,
    primaryClass: 'cardinal_clean',
    inscriptions: [],
    satRanges: null,
    unsupportedAssetDetected: false,
    confidence: 'authoritative',
    classifiedTip: source.coreTip,
    classificationRevision: source.classificationRevision,
  };
  return createProviderPsbtPlan({
    psbtBase64: bytesToBase64(tx.toPSBT()),
    binding: { ...binding, ...input.bindingOverride },
    network,
    vaultId: 'vault-1',
    sessionId: input.sessionId ?? 'session-1',
    accountId,
    account: accountNumber,
    classifications: [classification],
    walletInputs: [{
      outpoint: `${input.txid}:0`,
      derivation: {
        accountId,
        account: accountNumber,
        lane: 'payment',
        chain: 0,
        index: 0,
        path: planWallet.path,
        publicKeyHex: planWallet.publicKeyHex,
      },
    }],
    walletOutputs: [],
    source,
    broadcast: false,
    selectedInputIndexes: [0],
    planId: input.planId,
    now: NOW,
  });
}

function create(items = [
  { plan: plan({ txid: '11'.repeat(32), planId: 'plan-1' }) },
  { plan: plan({ txid: '22'.repeat(32), planId: 'plan-2', amount: 60_000n }) },
]) {
  return createProviderPsbtBatchPlan({ items, planId: 'batch-1', now: NOW, approvalGeneration: 7 });
}

describe('independent provider PSBT batches', () => {
  it('binds aggregate limits and returns signed results in exact request order', async () => {
    const batch = create();
    expect(batch.items).toHaveLength(2);
    expect(batch.aggregate).toMatchObject({ inputs: 2, outputs: 2, feeExposureSats: 4_000n });
    expect(batch.requiresAdvanced).toBe(true);
    const signed = await signProviderPsbtBatchPlan({
      plan: batch,
      seed,
      now: NOW + 1,
      random: (length) => new Uint8Array(length).fill(7),
      yieldControl: async () => undefined,
    });
    const singles = batch.items.map((item) => signProviderPsbtPlan({
      plan: item.plan,
      seed,
      requestedInputIndexes: item.requestedInputIndexes,
      random: (length) => new Uint8Array(length).fill(7),
    }).psbtBase64);
    expect(signed.map((item) => item.psbtBase64)).toEqual(singles);
    expect(signed[0]!.psbtBase64).not.toBe(signed[1]!.psbtBase64);
  });

  it('signs an independent deterministic regtest-network batch without a network service', async () => {
    const batch = create([
      { plan: plan({ txid: '21'.repeat(32), planId: 'regtest-1', network: 'regtest' }) },
      { plan: plan({ txid: '23'.repeat(32), planId: 'regtest-2', network: 'regtest' }) },
    ]);
    expect(batch.network).toBe('regtest');
    const signed = await signProviderPsbtBatchPlan({
      plan: batch,
      seed,
      now: NOW + 1,
      random: (length) => new Uint8Array(length).fill(3),
      yieldControl: async () => undefined,
    });
    expect(signed).toHaveLength(2);
    expect(signed.every((item) =>
      Transaction.fromPSBT(base64ToBytes(item.psbtBase64))
        .getInput(0).partialSig?.length === 1)).toBe(true);
  });

  it('binds selection addresses, indexes, sighashes, order, analysis and approval generation', () => {
    const first = plan({ txid: '31'.repeat(32), planId: 'plan-a' });
    const second = plan({ txid: '32'.repeat(32), planId: 'plan-b' });
    const batch = createProviderPsbtBatchPlan({
      items: [first, second].map((item) => ({
        plan: item,
        inputsToSign: [{ address: wallet.address, signingIndexes: [0], sigHash: 1 }],
      })),
      planId: 'batch-selection',
      now: NOW,
      approvalGeneration: 12,
    });
    expect(() => assertProviderPsbtBatchPlan({ ...batch, approvalGeneration: 13 })).toThrow(/mutated/u);
    expect(() => assertProviderPsbtBatchPlan({ ...batch, items: [...batch.items].reverse() })).toThrow(/mutated/u);
    const changed = structuredClone(batch);
    changed.items[0]!.requestedInputIndexes = [1];
    expect(() => assertProviderPsbtBatchPlan(changed)).toThrow();
    const changedAnalysis = structuredClone(batch);
    changedAnalysis.items[0]!.plan.analysis.outputs[0]!.valueSats += 1n;
    expect(() => assertProviderPsbtBatchPlan(changedAnalysis)).toThrow(/mutated/u);
    expect(() => createProviderPsbtBatchPlan({
      items: [{
        plan: first,
        inputsToSign: [{ address: wallet.address, signingIndexes: [0], sigHash: 129 }],
      }],
      planId: 'bad-sighash', now: NOW, approvalGeneration: 1,
    })).toThrow(/sighash/u);
  });

  it('rejects duplicate PSBTs, conflicting inputs and prospective internal graphs', () => {
    const first = plan({ txid: '41'.repeat(32), planId: 'plan-first' });
    expect(() => createProviderPsbtBatchPlan({
      items: [{ plan: first }, { plan: first }], planId: 'duplicates', now: NOW, approvalGeneration: 1,
    })).toThrow(/duplicate/u);
    const conflicting = plan({ txid: '41'.repeat(32), planId: 'plan-conflict', amount: 55_000n });
    expect(() => createProviderPsbtBatchPlan({
      items: [{ plan: first }, { plan: conflicting }], planId: 'conflict', now: NOW, approvalGeneration: 1,
    })).toThrow(/repeated/u);
    const metadataVariant = plan({
      txid: '41'.repeat(32), planId: 'plan-metadata-variant', metadataTag: 1,
    });
    expect(() => createProviderPsbtBatchPlan({
      items: [{ plan: first }, { plan: metadataVariant }],
      planId: 'duplicate-transaction', now: NOW, approvalGeneration: 1,
    })).toThrow(/duplicate unsigned transaction/u);

    const firstTxid = providerPsbtUnsignedTxid(first);
    const dependent = plan({ txid: firstTxid, planId: 'plan-dependent' });
    expect(() => createProviderPsbtBatchPlan({
      items: [{ plan: first }, { plan: dependent }], planId: 'linked-forward', now: NOW, approvalGeneration: 1,
    })).toThrow(/internally linked/u);
    expect(() => createProviderPsbtBatchPlan({
      items: [{ plan: dependent }, { plan: first }], planId: 'linked-reverse', now: NOW, approvalGeneration: 1,
    })).toThrow(/internally linked/u);
  });

  it('rejects mixed authorities and expiry and never returns a partial result', async () => {
    const first = plan({ txid: '51'.repeat(32), planId: 'plan-first' });
    const otherOrigin = plan({
      txid: '52'.repeat(32), planId: 'plan-other', bindingOverride: { origin: 'https://other.example' },
    });
    expect(() => createProviderPsbtBatchPlan({
      items: [{ plan: first }, { plan: otherOrigin }], planId: 'mixed', now: NOW, approvalGeneration: 1,
    })).toThrow(/context/u);
    for (const different of [
      plan({ txid: '53'.repeat(32), planId: 'other-network', network: 'mainnet' }),
      plan({ txid: '54'.repeat(32), planId: 'other-session', sessionId: 'session-2' }),
      plan({ txid: '55'.repeat(32), planId: 'other-account', accountNumber: 1 }),
    ]) {
      expect(() => createProviderPsbtBatchPlan({
        items: [{ plan: first }, { plan: different }], planId: 'mixed', now: NOW, approvalGeneration: 1,
      })).toThrow(/context/u);
    }
    const batch = create();
    await expect(signProviderPsbtBatchPlan({
      plan: batch,
      seed,
      now: batch.expiresAt,
      random: (length) => new Uint8Array(length),
      yieldControl: async () => undefined,
    })).rejects.toThrow(/expired/u);
    let guardCalls = 0;
    let returned = false;
    try {
      await signProviderPsbtBatchPlan({
        plan: batch,
        seed,
        now: NOW + 1,
        random: (length) => new Uint8Array(length),
        yieldControl: async () => undefined,
        guard: () => {
          guardCalls += 1;
          if (guardCalls === 2) throw new Error('stale approval');
        },
      });
      returned = true;
    } catch (error) {
      expect(error).toMatchObject({ message: 'stale approval' });
    }
    expect(returned).toBe(false);
    expect(guardCalls).toBe(2);
  });

  it('processes a queued lifecycle invalidation before returning any batch result', async () => {
    const batch = create();
    let stale = false;
    let returned = false;
    const invalidation = setTimeout(() => { stale = true; }, 0);
    try {
      await signProviderPsbtBatchPlan({
        plan: batch,
        seed,
        now: NOW + 1,
        random: (length) => new Uint8Array(length),
        yieldControl: () => new Promise((resolve) => setTimeout(resolve, 0)),
        guard: () => {
          if (stale) throw new Error('queued lifecycle invalidation');
        },
      });
      returned = true;
    } catch (error) {
      expect(error).toMatchObject({ message: 'queued lifecycle invalidation' });
    } finally {
      clearTimeout(invalidation);
    }
    expect(returned).toBe(false);
  });
});
