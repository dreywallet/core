import fc from 'fast-check';
import { beforeAll, describe, expect, it } from 'vitest';
import { NETWORK, SigHash, Transaction, p2wpkh } from '@scure/btc-signer';
import { installTestCryptoProvider } from '../helpers/install-crypto-provider';
import { bytesToBase64, bytesToHex, hexToBytes } from '../../src/domain/vault/encoding';
import { createProviderPsbtPlan } from '../../src/domain/transactions/provider-psbt';
import {
  approveCommunityVaultSale,
  assertCommunityVaultSalePlan,
  assertCommunityVaultSalePreflight,
  combineCommunityVaultSalePsbts,
  communityVaultSalePayouts,
  constructCommunityVaultSalePsbt,
  createCommunityVaultSalePlan,
  finalizeCommunityVaultSalePsbt,
  validateCommunityVaultSalePsbt,
  verifyFinalizedCommunityVaultSale,
} from '../../src/domain/community-vault/sale';
import { reviewCommunityVaultSaleProviderRequest } from '../../src/domain/community-vault/sale-provider';
import type { CommunityVaultSalePlanV1, CommunityVaultSalePreflightV1 } from '../../src/domain/community-vault/sale-contracts';
import { deterministicAux, fixturePolicy, fixtureRoot } from './helpers';

beforeAll(() => installTestCryptoProvider());

const CREATED = '1800000000000';
const EXPIRES = '1800003600000';

function payment(index: number) {
  const root = fixtureRoot(index);
  const child = root.deriveChild(0);
  if (!child.publicKey) throw new Error('sale fixture key unavailable');
  const output = p2wpkh(child.publicKey, NETWORK);
  return { root, child, address: output.address, scriptPubKeyHex: bytesToHex(output.script) };
}

function saleFixture(grossOfferSats = '100000') {
  const { policy, roots } = fixturePolicy();
  const buyerFunding = payment(400);
  const buyerDestination = payment(401);
  const buyerChange = payment(402);
  const fee = 2_000n;
  const change = 1_000n;
  const plan = createCommunityVaultSalePlan({
    policy,
    vaultOutpoint: { txid: 'ee'.repeat(32), vout: 2 },
    offerId: 'aa'.repeat(32),
    buyerId: 'buyer-fixture',
    nonceHex: 'bb'.repeat(32),
    createdAtMs: CREATED,
    expiresAtMs: EXPIRES,
    vaultValueSats: '10000',
    inscriptionInputOffsetSats: '0',
    postageSats: '546',
    grossOfferSats,
    settlementFeeSats: fee.toString(),
    buyerDestinationAddress: buyerDestination.address,
    buyerDestinationScriptPubKeyHex: buyerDestination.scriptPubKeyHex,
    buyerInputs: [{
      txid: 'cc'.repeat(32),
      vout: 1,
      valueSats: (BigInt(grossOfferSats) + fee + change).toString(),
      scriptPubKeyHex: buyerFunding.scriptPubKeyHex,
      sequence: 0xffff_fffd,
      scriptKind: 'p2wpkh',
      sighashType: SigHash.ALL,
    }],
    buyerChange: { valueSats: change.toString(), scriptPubKeyHex: buyerChange.scriptPubKeyHex },
  });
  return { policy, roots, plan, buyerFunding };
}

function fundedBuyerPsbt(fixture: ReturnType<typeof saleFixture>): string {
  const tx = Transaction.fromPSBT(
    hexToBytes(constructCommunityVaultSalePsbt(fixture.policy, fixture.plan)),
    { PSBTVersion: 0, lowR: true },
  );
  if (!fixture.buyerFunding.child.privateKey) throw new Error('sale fixture private key unavailable');
  tx.signIdx(fixture.buyerFunding.child.privateKey, 1, [SigHash.ALL]);
  tx.finalizeIdx(1);
  const psbtHex = bytesToHex(tx.toPSBT(0));
  validateCommunityVaultSalePsbt(fixture.policy, fixture.plan, psbtHex);
  return psbtHex;
}

function preflight(plan: CommunityVaultSalePlanV1): CommunityVaultSalePreflightV1 {
  return {
    version: 1,
    network: 'mainnet',
    source: 'ord',
    verifiedAtMs: (BigInt(CREATED) + 10_000n).toString(),
    blockHeight: 910_000,
    blockHash: 'dd'.repeat(32),
    inputs: plan.spendPlan.inputs.map((input, index) => ({
      inputIndex: index,
      txid: input.txid,
      vout: input.vout,
      valueSats: input.valueSats,
      scriptPubKeyHex: input.scriptPubKeyHex,
      unspent: true,
      inscriptionIds: index === 0 ? [plan.inscriptionId] : [],
      runeIds: [],
    })),
  };
}

describe('Community Vault exact-funded sale payouts', () => {
  it('sums exactly and applies fractional remainder before cap-table order', () => {
    const { policy } = fixturePolicy();
    const payouts = communityVaultSalePayouts(policy, '100003');
    expect(payouts.reduce((total, payout) => total + BigInt(payout.valueSats), 0n)).toBe(100_003n);
    expect(payouts.slice(0, 3).map((payout) => payout.valueSats)).toEqual(['20001', '20001', '20001']);
    expect(payouts[6]!.valueSats).toBe('20000');

    fc.assert(fc.property(fc.integer({ min: 33_000, max: 10_000_000 }), (gross) => {
      const rows = communityVaultSalePayouts(policy, gross.toString());
      expect(rows.reduce((total, row) => total + BigInt(row.valueSats), 0n)).toBe(BigInt(gross));
    }), { numRuns: 10 });
  }, 10_000);

  it('rejects a gross offer that creates any dust owner payout', () => {
    expect(() => saleFixture('10000')).toThrow(/dust/u);
  });
});

describe('Community Vault exact-funded sale transaction', () => {
  it('requires finalized buyer funding, then rejects 68 and succeeds with 69 unit signatures', () => {
    const fixture = saleFixture();
    const unsigned = constructCommunityVaultSalePsbt(fixture.policy, fixture.plan);
    expect(() => validateCommunityVaultSalePsbt(fixture.policy, fixture.plan, unsigned)).toThrow(/exactly funded/u);
    let psbtHex = fundedBuyerPsbt(fixture);
    const random = deterministicAux();
    for (let index = 0; index < 4; index += 1) {
      psbtHex = approveCommunityVaultSale({
        policy: fixture.policy,
        plan: fixture.plan,
        psbtHex,
        ownerId: `owner-${index}`,
        signerRoot: fixture.roots[index]!,
        nowMs: (BigInt(CREATED) + 20_000n).toString(),
        random,
      }).psbtHex;
    }
    expect(() => finalizeCommunityVaultSalePsbt(fixture.policy, fixture.plan, psbtHex)).toThrow(/at least 69/u);
    psbtHex = approveCommunityVaultSale({
      policy: fixture.policy,
      plan: fixture.plan,
      psbtHex,
      ownerId: 'owner-4',
      signerRoot: fixture.roots[4]!,
      nowMs: (BigInt(CREATED) + 20_000n).toString(),
      random,
    }).psbtHex;
    const finalized = finalizeCommunityVaultSalePsbt(fixture.policy, fixture.plan, psbtHex);
    expect(finalized.signedUnits).toHaveLength(69);
    expect(verifyFinalizedCommunityVaultSale({
      policy: fixture.policy,
      plan: fixture.plan,
      transactionHex: finalized.transactionHex,
    })).toEqual(finalized);
  }, 20_000);

  it('accepts an owner approval that crosses the threshold without bloating the final witness', () => {
    const fixture = saleFixture();
    let psbtHex = fundedBuyerPsbt(fixture);
    const random = deterministicAux();
    for (let index = 0; index < 6; index += 1) {
      psbtHex = approveCommunityVaultSale({
        policy: fixture.policy,
        plan: fixture.plan,
        psbtHex,
        ownerId: `owner-${index}`,
        signerRoot: fixture.roots[index]!,
        nowMs: (BigInt(CREATED) + 20_000n).toString(),
        random,
      }).psbtHex;
    }
    expect(validateCommunityVaultSalePsbt(fixture.policy, fixture.plan, psbtHex).signedUnits).toHaveLength(80);
    const finalized = finalizeCommunityVaultSalePsbt(fixture.policy, fixture.plan, psbtHex);
    expect(finalized.signedUnits).toHaveLength(69);
    expect(finalized.weight).toBeLessThanOrEqual(400_000);
  }, 20_000);

  it('makes the buyer pay fee on top and pays dissenting owners identically', () => {
    const { policy, plan } = saleFixture();
    expect(plan.buyerPaysFee).toBe(true);
    expect(plan.grossOfferSats).toBe('100000');
    expect(plan.settlementFeeSats).toBe('2000');
    expect(plan.buyerTotalSats).toBe('102000');
    expect(plan.ownerPayouts.reduce((total, payout) => total + BigInt(payout.valueSats), 0n)).toBe(100_000n);
    const nonSigner = plan.ownerPayouts.find((payout) => payout.ownerId === 'owner-6')!;
    expect(nonSigner.valueSats).toBe('20000');
    expect(nonSigner.payoutScriptPubKeyHex).toBe(policy.owners[6]!.payoutScriptPubKeyHex);
  });

  it('rejects payout, destination, fee, expiry, and unexplained-output mutation', () => {
    const { policy, plan } = saleFixture();
    const mutated = (change: (copy: CommunityVaultSalePlanV1) => void) => {
      const copy = structuredClone(plan);
      change(copy);
      return () => assertCommunityVaultSalePlan(policy, copy);
    };
    expect(mutated((copy) => { copy.ownerPayouts[0]!.valueSats = '19999'; })).toThrow(/payout/u);
    expect(mutated((copy) => { copy.buyerDestinationScriptPubKeyHex = policy.owners[0]!.payoutScriptPubKeyHex; }))
      .toThrow(/destination/u);
    expect(mutated((copy) => { copy.buyerTotalSats = '101999'; })).toThrow(/total/u);
    expect(mutated((copy) => { copy.expiresAtMs = copy.createdAtMs; })).toThrow(/expiry/u);
    expect(mutated((copy) => {
      copy.spendPlan.outputs.push({ valueSats: '1', scriptPubKeyHex: policy.owners[0]!.payoutScriptPubKeyHex });
    })).toThrow();
  });

  it('requires fresh unspent asset-clean preflight evidence', () => {
    const { policy, plan } = saleFixture();
    assertCommunityVaultSalePreflight({
      policy,
      plan,
      preflight: preflight(plan),
      nowMs: (BigInt(CREATED) + 20_000n).toString(),
    });
    const conflict = preflight(plan);
    conflict.inputs[1]!.unspent = false;
    expect(() => assertCommunityVaultSalePreflight({
      policy, plan, preflight: conflict, nowMs: (BigInt(CREATED) + 20_000n).toString(),
    })).toThrow(/differs/u);
    const rune = preflight(plan);
    rune.inputs[1]!.runeIds.push('RUNE:1');
    expect(() => assertCommunityVaultSalePreflight({
      policy, plan, preflight: rune, nowMs: (BigInt(CREATED) + 20_000n).toString(),
    })).toThrow(/another asset/u);
    const stale = preflight(plan);
    expect(() => assertCommunityVaultSalePreflight({
      policy, plan, preflight: stale, nowMs: (BigInt(stale.verifiedAtMs) + 120_001n).toString(),
    })).toThrow(/stale/u);
  });

  it('binds a provider approval to one exact owner and the vault input', () => {
    const fixture = saleFixture();
    const base = fundedBuyerPsbt(fixture);
    const context = {
      version: 1 as const,
      ownerId: 'owner-0',
      policy: fixture.policy,
      plan: fixture.plan,
      preflight: preflight(fixture.plan),
    };
    const review = reviewCommunityVaultSaleProviderRequest({
      context,
      psbtHex: base,
      selectedInputIndexes: [0],
      nowMs: (BigInt(CREATED) + 20_000n).toString(),
    });
    expect(review.units).toEqual(fixture.policy.owners[0]!.units);
    expect(review.ownerPayoutSats).toBe(fixture.plan.ownerPayouts[0]!.valueSats);
    expect(review.grossOfferSats).toBe(fixture.plan.grossOfferSats);
    expect(() => reviewCommunityVaultSaleProviderRequest({
      context,
      psbtHex: base,
      selectedInputIndexes: [1],
      nowMs: (BigInt(CREATED) + 20_000n).toString(),
    })).toThrow(/vault input/u);

    const source = {
      backend: 'https://gateway.example',
      instanceId: 'gateway-1',
      classificationRevision: 'sale-rev-1',
      coreTip: { height: 910_000, hash: 'dd'.repeat(32) },
      indexTip: { height: 910_000, hash: 'dd'.repeat(32) },
      feeQuoteTimestamp: null,
      mempoolState: null,
    };
    const providerPlan = createProviderPsbtPlan({
      psbtBase64: bytesToBase64(hexToBytes(base)),
      binding: {
        origin: 'https://omb.wiki',
        tabId: 1,
        frameId: 0,
        documentId: 'sale-document',
        requestNonce: 'sale-request',
        providerMethod: 'signPsbt',
      },
      network: 'mainnet',
      vaultId: 'spending-vault',
      sessionId: 'sale-session',
      accountId: `acct_mainnet_${'ff'.repeat(32)}`,
      account: 0,
      classifications: fixture.plan.spendPlan.inputs.map((item, index) => ({
        txid: item.txid,
        vout: item.vout,
        valueSats: item.valueSats,
        scriptPubKey: item.scriptPubKeyHex,
        confirmations: 10,
        primaryClass: index === 0 ? 'inscribed' as const : 'cardinal_clean' as const,
        inscriptions: index === 0
          ? [{ inscriptionId: fixture.plan.inscriptionId, satpoint: `${item.txid}:${item.vout}:0` }]
          : [],
        satRanges: null,
        unsupportedAssetDetected: false,
        confidence: 'authoritative' as const,
        classifiedTip: source.coreTip,
        classificationRevision: source.classificationRevision,
      })),
      walletInputs: [],
      source,
      broadcast: false,
      planId: 'sale-provider-plan',
      now: Number(BigInt(CREATED) + 20_000n),
      selectedInputIndexes: [0],
      communityVaultSale: review,
      protectedSatFlow: [{
        inputIndex: 0,
        inputOffset: 0n,
        outputIndex: 0,
        outputOffset: 0n,
        inscriptionId: fixture.plan.inscriptionId,
      }],
    });
    expect(providerPlan.kind).toBe('community_vault_sale');
    expect(providerPlan.inputs[0]!.ownership).toBe('external');
    expect(providerPlan.selectedInputIndexes).toEqual([0]);
  });

  it('combines independent owner packages deterministically and rejects duplicate units', () => {
    const fixture = saleFixture();
    const base = fundedBuyerPsbt(fixture);
    const random = deterministicAux();
    const packages = fixture.policy.owners.slice(0, 5).map((owner, index) =>
      approveCommunityVaultSale({
        policy: fixture.policy,
        plan: fixture.plan,
        psbtHex: base,
        ownerId: owner.ownerId,
        signerRoot: fixture.roots[index]!,
        nowMs: (BigInt(CREATED) + 20_000n).toString(),
        random,
      }).psbtHex);
    const forward = combineCommunityVaultSalePsbts({
      policy: fixture.policy,
      plan: fixture.plan,
      psbtHexes: packages,
    });
    const reverse = combineCommunityVaultSalePsbts({
      policy: fixture.policy,
      plan: fixture.plan,
      psbtHexes: [...packages].reverse(),
    });
    expect(forward.signedUnits).toHaveLength(69);
    expect(reverse.signedUnits).toEqual(forward.signedUnits);
    expect(finalizeCommunityVaultSalePsbt(fixture.policy, fixture.plan, forward.psbtHex).signedUnits)
      .toHaveLength(69);
    expect(() => combineCommunityVaultSalePsbts({
      policy: fixture.policy,
      plan: fixture.plan,
      psbtHexes: [packages[0]!, packages[0]!],
    })).toThrow(/duplicate/u);
  }, 20_000);
});
