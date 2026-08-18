import { beforeAll, describe, expect, it } from 'vitest';
import { NETWORK, SigHash, Transaction, p2wpkh } from '@scure/btc-signer';
import { installTestCryptoProvider } from '../helpers/install-crypto-provider';
import { bytesToHex, hexToBytes } from '../../src/domain/vault/encoding';
import {
  communityVaultAcquisitionUnitAmounts,
  constructCommunityVaultAcquisitionPsbt,
  createCommunityVaultListedAcquisitionPlan,
} from '../../src/domain/community-vault/acquisition';
import {
  reviewCommunityVaultAcquisitionProviderRequest,
} from '../../src/domain/community-vault/acquisition-provider';
import type {
  CommunityVaultAcquisitionInputV1,
  CommunityVaultAcquisitionPreflightV1,
} from '../../src/domain/community-vault/acquisition-contracts';
import { fixturePolicy, fixtureRoot } from './helpers';

beforeAll(() => installTestCryptoProvider());

const CREATED = 1_800_000_000_000n;

function payment(index: number) {
  const child = fixtureRoot(index).deriveChild(0);
  if (!child.publicKey) throw new Error('fixture payment key unavailable');
  return bytesToHex(p2wpkh(child.publicKey, NETWORK).script);
}

function fixture() {
  const { policy } = fixturePolicy();
  const assetScript = payment(700);
  const sellerScript = payment(701);
  const assetCost = 100_000n;
  const fee = 2_000n;
  const unitAsset = communityVaultAcquisitionUnitAmounts(assetCost.toString()).map(BigInt);
  const unitFee = communityVaultAcquisitionUnitAmounts(fee.toString()).map(BigInt);
  const fundingScripts = policy.owners.map((_owner, index) => payment(710 + index));
  const fundingInputs: CommunityVaultAcquisitionInputV1[] = policy.owners.map((owner, index) => {
    const due = owner.units.reduce((total, unit) => total + unitAsset[unit]! + unitFee[unit]!, 0n);
    return {
      txid: (800 + index).toString(16).padStart(64, '0'),
      vout: 0,
      valueSats: (due + 1_000n).toString(),
      scriptPubKeyHex: fundingScripts[index]!,
      sequence: 0xffff_fffd,
      scriptKind: 'p2wpkh',
      role: 'owner-funding',
      ownerId: owner.ownerId,
      sighashType: SigHash.ALL,
    };
  });
  const plan = createCommunityVaultListedAcquisitionPlan({
    policy,
    planId: 'provider-fixture',
    createdAtMs: CREATED.toString(),
    expiresAtMs: (CREATED + 60_000n).toString(),
    inputs: [{
      txid: policy.currentOutpoint.txid,
      vout: policy.currentOutpoint.vout,
      valueSats: '10000',
      scriptPubKeyHex: assetScript,
      sequence: 0xffff_fffd,
      scriptKind: 'p2wpkh',
      role: 'inscription',
      ownerId: null,
      sighashType: SigHash.ALL,
    }, ...fundingInputs],
    outputs: [
      { valueSats: '10000', scriptPubKeyHex: policy.scriptPubKeyHex, role: 'vault', ownerId: null, recipientId: null },
      { valueSats: assetCost.toString(), scriptPubKeyHex: sellerScript, role: 'seller-payment', ownerId: null, recipientId: 'seller' },
      ...policy.owners.map((owner, index) => ({
        valueSats: '1000',
        scriptPubKeyHex: fundingScripts[index]!,
        role: 'owner-change' as const,
        ownerId: owner.ownerId,
        recipientId: null,
      })),
    ],
    assetInputIndex: 0,
    vaultOutputIndex: 0,
    inscriptionInputOffsetSats: '0',
    inscriptionOutputOffsetSats: '0',
    postageSats: '546',
    settlementFeeSats: fee.toString(),
    listedTerms: {
      marketplaceId: 'satflow',
      listingId: 'provider-listing',
      listingFingerprintHex: 'ab'.repeat(32),
      observedAtMs: (CREATED - 1_000n).toString(),
      listingExpiresAtMs: (CREATED + 60_000n).toString(),
      sellerPaymentSats: assetCost.toString(),
      sellerPayoutScriptPubKeyHex: sellerScript,
      maximumLandedCostSats: (assetCost + fee).toString(),
    },
  });
  const preflight: CommunityVaultAcquisitionPreflightV1 = {
    version: 1,
    network: 'mainnet',
    source: 'ord',
    verifiedAtMs: (CREATED + 1_000n).toString(),
    blockHeight: 900_000,
    blockHash: 'cd'.repeat(32),
    inputs: plan.inputs.map((candidate, inputIndex) => ({
      inputIndex,
      txid: candidate.txid,
      vout: candidate.vout,
      valueSats: candidate.valueSats,
      scriptPubKeyHex: candidate.scriptPubKeyHex,
      unspent: true,
      inscriptionIds: inputIndex === 0 ? [policy.inscriptionId] : [],
      runeIds: [],
    })),
    listing: {
      marketplaceId: 'satflow',
      listingId: 'provider-listing',
      listingFingerprintHex: 'ab'.repeat(32),
      active: true,
      observedAtMs: CREATED.toString(),
    },
  };
  return { policy, plan, preflight, psbtHex: constructCommunityVaultAcquisitionPsbt(policy, plan) };
}

describe('Community Vault acquisition provider binding', () => {
  it('binds one owner to every and only their acquisition inputs', () => {
    const { policy, plan, preflight, psbtHex } = fixture();
    const owner = policy.owners[0]!;
    const review = reviewCommunityVaultAcquisitionProviderRequest({
      context: { version: 1, ownerId: owner.ownerId, policy, plan, preflight },
      psbtHex,
      selectedInputIndexes: [1],
      nowMs: (CREATED + 2_000n).toString(),
    });
    expect(review.units).toEqual(owner.units);
    expect(review.cashDueSats).toBe(plan.ownerObligations[0]!.cashDueSats);
    expect(review.vaultAddress).toBe(policy.address);
    expect(() => reviewCommunityVaultAcquisitionProviderRequest({
      context: { version: 1, ownerId: owner.ownerId, policy, plan, preflight },
      psbtHex,
      selectedInputIndexes: [1, 2],
      nowMs: (CREATED + 2_000n).toString(),
    })).toThrow(/differ/u);
  });

  it('rejects an already signed owner input and stale evidence', () => {
    const { policy, plan, preflight, psbtHex } = fixture();
    const owner = policy.owners[0]!;
    const tx = Transaction.fromPSBT(hexToBytes(psbtHex), { PSBTVersion: 0 });
    const key = fixtureRoot(710).deriveChild(0);
    if (!key.privateKey) throw new Error('fixture signing key unavailable');
    tx.signIdx(key.privateKey, 1, [SigHash.ALL]);
    tx.finalizeIdx(1);
    expect(() => reviewCommunityVaultAcquisitionProviderRequest({
      context: { version: 1, ownerId: owner.ownerId, policy, plan, preflight },
      psbtHex: bytesToHex(tx.toPSBT(0)),
      selectedInputIndexes: [1],
      nowMs: (CREATED + 2_000n).toString(),
    })).toThrow(/already signed/u);
    expect(() => reviewCommunityVaultAcquisitionProviderRequest({
      context: { version: 1, ownerId: owner.ownerId, policy, plan, preflight },
      psbtHex,
      selectedInputIndexes: [1],
      nowMs: (CREATED + 122_000n).toString(),
    })).toThrow(/stale/u);
  });
});
