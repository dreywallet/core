import { beforeAll, describe, expect, it } from 'vitest';
import { NETWORK, SigHash, Transaction, p2wpkh } from '@scure/btc-signer';

import { signBip322Simple } from '../../src/domain/transactions/bip322';
import { bytesToHex, hexToBytes } from '../../src/domain/vault/encoding';
import { createCommunityVaultPolicy } from '../../src/domain/community-vault/policy';
import {
  approveCommunityVaultPositionTransfer,
  assertCommunityVaultPositionTransferPlan,
  assertCommunityVaultPositionTransferPreflight,
  communityVaultPositionTransferSellerAuthorization,
  communityVaultPositionTransferSellerMessage,
  constructCommunityVaultPositionTransferPsbt,
  createCommunityVaultPositionTransferPlan,
  createCommunityVaultPositionTransferPolicy,
  finalizeCommunityVaultPositionTransferPsbt,
  validateCommunityVaultPositionTransferPsbt,
} from '../../src/domain/community-vault/position-transfer';
import {
  reviewCommunityVaultPositionTransferBuyerProviderRequest,
  reviewCommunityVaultPositionTransferOwnerProviderRequest,
} from '../../src/domain/community-vault/position-transfer-provider';
import type {
  CommunityVaultPositionTransferPlanV1,
  CommunityVaultPositionTransferPreflightV1,
} from '../../src/domain/community-vault/position-transfer-contracts';
import { installTestCryptoProvider } from '../helpers/install-crypto-provider';
import { deterministicAux, fixturePolicy, fixtureRoot } from './helpers';

beforeAll(() => installTestCryptoProvider());

const CREATED = '1800000000000';
const EXPIRES = '1800003600000';

function transferFixture(options: { eligibility?: 'anyone' | 'omb-holders-only' } = {}) {
  const { policy: basePolicy, roots } = fixturePolicy();
  const policy = options.eligibility ? createCommunityVaultPolicy({
    version: 1,
    policyVersion: 1,
    network: 'mainnet',
    campaignId: basePolicy.campaignId,
    inscriptionId: basePolicy.inscriptionId,
    currentOutpoint: basePolicy.currentOutpoint,
    mode: basePolicy.mode,
    eligibility: options.eligibility,
    creatorOwnerId: basePolicy.creatorOwnerId,
    termsVersion: basePolicy.termsVersion,
    capTableVersion: basePolicy.capTableVersion,
    owners: basePolicy.owners,
  }) : basePolicy;
  const buyerRoot = fixtureRoot(500);
  const buyerPaymentKey = buyerRoot.deriveChild(1_000);
  if (!buyerPaymentKey.publicKey) throw new Error('position buyer payment key unavailable');
  const buyerPayment = p2wpkh(buyerPaymentKey.publicKey, NETWORK);
  const buyer = {
    ownerId: 'position-buyer',
    identityCommitmentHex: '55'.repeat(32),
    payoutAddress: buyerPayment.address,
    payoutScriptPubKeyHex: bytesToHex(buyerPayment.script),
    campaignRoot: {
      version: 1 as const,
      masterFingerprintHex: buyerRoot.fingerprint.toString(16).padStart(8, '0'),
      originPath: 'm' as const,
      campaignXpub: buyerRoot.publicExtendedKey,
    },
    qualifyingInscriptionNumber: options.eligibility ? 12345 : null,
  };
  const vaultOutpoint = { txid: 'aa'.repeat(32), vout: 2 };
  const nextPolicy = createCommunityVaultPositionTransferPolicy({
    currentPolicy: policy,
    sellerOwnerId: 'owner-1',
    buyer,
    currentVaultOutpoint: vaultOutpoint,
  });
  const unsignedAuthorization = communityVaultPositionTransferSellerAuthorization({
    transferId: 'private-position-1',
    currentPolicy: policy,
    nextPolicy,
    currentVaultOutpoint: vaultOutpoint,
    sellerOwnerId: 'owner-1',
    buyer,
    sellerPriceSats: '100000',
    expiresAtMs: EXPIRES,
    nonceHex: '66'.repeat(32),
  });
  const sellerPayoutKey = roots[1]!.deriveChild(1_001);
  if (!sellerPayoutKey.privateKey) throw new Error('position seller payout key unavailable');
  const signature = signBip322Simple({
    message: communityVaultPositionTransferSellerMessage(unsignedAuthorization),
    privateKey: sellerPayoutKey.privateKey,
    addressKind: 'payment',
    random: deterministicAux(),
  });
  sellerPayoutKey.wipePrivateData();
  const plan = createCommunityVaultPositionTransferPlan({
    currentPolicy: policy,
    nextPolicy,
    transferId: 'private-position-1',
    vaultOutpoint,
    vaultValueSats: '10000',
    inscriptionInputOffsetSats: '0',
    postageSats: '546',
    sellerOwnerId: 'owner-1',
    buyer,
    sellerPriceSats: '100000',
    settlementFeeSats: '2000',
    buyerInputs: [{
      txid: 'bb'.repeat(32),
      vout: 1,
      valueSats: '103000',
      scriptPubKeyHex: bytesToHex(buyerPayment.script),
      sequence: 0xffff_fffd,
      scriptKind: 'p2wpkh',
      sighashType: SigHash.ALL,
    }],
    buyerChange: { valueSats: '1000', scriptPubKeyHex: bytesToHex(buyerPayment.script) },
    createdAtMs: CREATED,
    expiresAtMs: EXPIRES,
    sellerAuthorization: { payload: unsignedAuthorization, signature },
  });
  return { policy, roots, buyerRoot, buyerPaymentKey, buyer, nextPolicy, plan };
}

function preflight(plan: CommunityVaultPositionTransferPlanV1): CommunityVaultPositionTransferPreflightV1 {
  return {
    version: 1,
    network: 'mainnet',
    source: 'ord',
    verifiedAtMs: (BigInt(CREATED) + 10_000n).toString(),
    blockHeight: 910_000,
    blockHash: 'cc'.repeat(32),
    inputs: plan.spendPlan.inputs.map((item, index) => ({
      inputIndex: index,
      txid: item.txid,
      vout: item.vout,
      valueSats: item.valueSats,
      scriptPubKeyHex: item.scriptPubKeyHex,
      unspent: true,
      inscriptionIds: index === 0 ? [plan.nextPolicy.inscriptionId] : [],
      runeIds: [],
    })),
  };
}

function buyerFundedPsbt(fixture: ReturnType<typeof transferFixture>): string {
  const tx = Transaction.fromPSBT(hexToBytes(
    constructCommunityVaultPositionTransferPsbt(fixture.policy, fixture.plan),
  ), { PSBTVersion: 0, lowR: true });
  if (!fixture.buyerPaymentKey.privateKey) throw new Error('position buyer funding key unavailable');
  tx.signIdx(fixture.buyerPaymentKey.privateKey, 1, [SigHash.ALL]);
  tx.finalizeIdx(1);
  const psbtHex = bytesToHex(tx.toPSBT(0));
  validateCommunityVaultPositionTransferPsbt({
    currentPolicy: fixture.policy,
    plan: fixture.plan,
    psbtHex,
  });
  return psbtHex;
}

describe('Community Vault private whole-position transfer', () => {
  it('rotates exactly the seller position and binds authorization to the buyer and next policy', () => {
    const fixture = transferFixture();
    expect(fixture.plan.transferredUnits).toEqual(fixture.policy.owners[1]!.units);
    expect(fixture.nextPolicy.owners[1]!.ownerId).toBe('position-buyer');
    expect(fixture.nextPolicy.owners[1]!.capTableOrder).toBe(1);
    expect(fixture.policy.units[20]!.publicKeyHex).not.toBe(fixture.nextPolicy.units[20]!.publicKeyHex);
    expect(fixture.nextPolicy.owners.filter((owner) => owner.ownerId === 'owner-1')).toHaveLength(0);

    const buyerMutation = structuredClone(fixture.plan);
    buyerMutation.buyer.ownerId = 'different-buyer';
    expect(() => assertCommunityVaultPositionTransferPlan(fixture.policy, buyerMutation)).toThrow();
    const policyMutation = structuredClone(fixture.plan);
    policyMutation.nextPolicy = fixture.policy;
    expect(() => assertCommunityVaultPositionTransferPlan(fixture.policy, policyMutation)).toThrow();
    const priceMutation = structuredClone(fixture.plan);
    priceMutation.sellerPriceSats = '99999';
    expect(() => assertCommunityVaultPositionTransferPlan(fixture.policy, priceMutation)).toThrow();
  });

  it('rejects creator transfers, existing-owner buyers, missing holder evidence, and long expiry', () => {
    const fixture = transferFixture();
    expect(() => createCommunityVaultPositionTransferPolicy({
      currentPolicy: fixture.policy,
      sellerOwnerId: fixture.policy.creatorOwnerId,
      buyer: fixture.buyer,
      currentVaultOutpoint: { txid: 'aa'.repeat(32), vout: 2 },
    })).toThrow(/creator position/u);
    expect(() => createCommunityVaultPositionTransferPolicy({
      currentPolicy: fixture.policy,
      sellerOwnerId: 'owner-1',
      buyer: { ...fixture.buyer, ownerId: 'owner-2' },
      currentVaultOutpoint: { txid: 'aa'.repeat(32), vout: 2 },
    })).toThrow(/already owns/u);

    const holder = transferFixture({ eligibility: 'omb-holders-only' });
    const missingEvidence = structuredClone(holder.plan);
    missingEvidence.buyer.qualifyingInscriptionNumber = null;
    expect(() => assertCommunityVaultPositionTransferPlan(holder.policy, missingEvidence)).toThrow();
    const longExpiry = structuredClone(fixture.plan);
    longExpiry.spendPlan.expiresAtMs = (BigInt(CREATED) + 86_400_001n).toString();
    expect(() => assertCommunityVaultPositionTransferPlan(fixture.policy, longExpiry)).toThrow();
  });

  it('gives the buyer only their funding inputs and owners only the vault input', () => {
    const fixture = transferFixture();
    const unsigned = constructCommunityVaultPositionTransferPsbt(fixture.policy, fixture.plan);
    const evidence = preflight(fixture.plan);
    const buyerReview = reviewCommunityVaultPositionTransferBuyerProviderRequest({
      context: { version: 1, currentPolicy: fixture.policy, plan: fixture.plan, preflight: evidence },
      psbtHex: unsigned,
      selectedInputIndexes: [1],
      nowMs: (BigInt(CREATED) + 20_000n).toString(),
    });
    expect(buyerReview).toMatchObject({
      role: 'buyer',
      units: fixture.plan.transferredUnits,
      sellerPriceSats: '100000',
      buyerTotalSats: '102000',
      selectedInputIndexes: [1],
    });
    expect(() => reviewCommunityVaultPositionTransferBuyerProviderRequest({
      context: { version: 1, currentPolicy: fixture.policy, plan: fixture.plan, preflight: evidence },
      psbtHex: unsigned,
      selectedInputIndexes: [0],
      nowMs: (BigInt(CREATED) + 20_000n).toString(),
    })).toThrow(/signing inputs/u);

    const funded = buyerFundedPsbt(fixture);
    const ownerReview = reviewCommunityVaultPositionTransferOwnerProviderRequest({
      context: {
        version: 1,
        ownerId: 'owner-0',
        currentPolicy: fixture.policy,
        plan: fixture.plan,
        preflight: evidence,
      },
      psbtHex: funded,
      selectedInputIndexes: [0],
      nowMs: (BigInt(CREATED) + 20_000n).toString(),
    });
    expect(ownerReview.role).toBe('owner');
    expect(ownerReview.selectedInputIndexes).toEqual([0]);
  });

  it('requires clean live inputs and finalized buyer funding', () => {
    const fixture = transferFixture();
    const evidence = preflight(fixture.plan);
    assertCommunityVaultPositionTransferPreflight({
      currentPolicy: fixture.policy,
      plan: fixture.plan,
      preflight: evidence,
      nowMs: (BigInt(CREATED) + 20_000n).toString(),
    });
    evidence.inputs[1]!.runeIds.push('RUNE:1');
    expect(() => assertCommunityVaultPositionTransferPreflight({
      currentPolicy: fixture.policy,
      plan: fixture.plan,
      preflight: evidence,
      nowMs: (BigInt(CREATED) + 20_000n).toString(),
    })).toThrow(/contains an asset/u);
    const unsigned = constructCommunityVaultPositionTransferPsbt(fixture.policy, fixture.plan);
    expect(() => validateCommunityVaultPositionTransferPsbt({
      currentPolicy: fixture.policy,
      plan: fixture.plan,
      psbtHex: unsigned,
    })).toThrow(/exactly funded/u);
  });

  it('cannot finalize at 68 units and succeeds atomically at 69', () => {
    const fixture = transferFixture();
    let psbtHex = buyerFundedPsbt(fixture);
    const random = deterministicAux();
    for (let index = 0; index < 4; index += 1) {
      psbtHex = approveCommunityVaultPositionTransfer({
        currentPolicy: fixture.policy,
        plan: fixture.plan,
        psbtHex,
        ownerId: `owner-${index}`,
        signerRoot: fixture.roots[index]!,
        nowMs: (BigInt(CREATED) + 20_000n).toString(),
        random,
      }).psbtHex;
    }
    expect(() => finalizeCommunityVaultPositionTransferPsbt(
      fixture.policy,
      fixture.plan,
      psbtHex,
    )).toThrow(/at least 69/u);
    psbtHex = approveCommunityVaultPositionTransfer({
      currentPolicy: fixture.policy,
      plan: fixture.plan,
      psbtHex,
      ownerId: 'owner-4',
      signerRoot: fixture.roots[4]!,
      nowMs: (BigInt(CREATED) + 20_000n).toString(),
      random,
    }).psbtHex;
    const finalized = finalizeCommunityVaultPositionTransferPsbt(
      fixture.policy,
      fixture.plan,
      psbtHex,
    );
    expect(finalized.signedUnits).toHaveLength(69);
    expect(finalized.txid).toMatch(/^[0-9a-f]{64}$/u);
  }, 20_000);
});
