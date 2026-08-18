import fc from 'fast-check';
import { beforeAll, describe, expect, it } from 'vitest';
import { NETWORK, SigHash, Transaction, p2wpkh } from '@scure/btc-signer';
import { installTestCryptoProvider } from '../helpers/install-crypto-provider';
import { bytesToHex, hexToBytes } from '../../src/domain/vault/encoding';
import {
  assertCommunityVaultAcquisitionPlan,
  assertCommunityVaultAcquisitionPreflight,
  communityVaultAcquisitionUnitAmounts,
  combineCommunityVaultAcquisitionPsbts,
  constructCommunityVaultAcquisitionPsbt,
  createCommunityVaultFrontedAcquisitionPlan,
  createCommunityVaultListedAcquisitionPlan,
  finalizeCommunityVaultAcquisitionPsbt,
  validateCommunityVaultAcquisitionPsbt,
  verifyFinalizedCommunityVaultAcquisition,
} from '../../src/domain/community-vault/acquisition';
import type {
  CommunityVaultAcquisitionInputV1,
  CommunityVaultAcquisitionOutputV1,
  CommunityVaultAcquisitionPlanV1,
  CommunityVaultAcquisitionPreflightV1,
} from '../../src/domain/community-vault/acquisition-contracts';
import type { CommunityVaultPolicyV1 } from '../../src/domain/community-vault/contracts';
import { fixturePolicy, fixtureRoot } from './helpers';

beforeAll(() => installTestCryptoProvider());

const CREATED = '1800000000000';
const EXPIRES = '1800003600000';
const CHANGE = 1_000n;

function payment(index: number) {
  const root = fixtureRoot(index);
  const child = root.deriveChild(0);
  if (!child.publicKey) throw new Error('fixture payment key unavailable');
  const result = p2wpkh(child.publicKey, NETWORK);
  return { root, child, scriptPubKeyHex: bytesToHex(result.script) };
}

function ownerShares(policy: CommunityVaultPolicyV1, amount: bigint): Map<string, bigint> {
  const units = communityVaultAcquisitionUnitAmounts(amount.toString()).map(BigInt);
  return new Map(policy.owners.map((owner) => [
    owner.ownerId,
    owner.units.reduce((total, unit) => total + units[unit]!, 0n),
  ]));
}

function funding(
  policy: CommunityVaultPolicyV1,
  dues: Map<string, bigint>,
): { inputs: CommunityVaultAcquisitionInputV1[]; outputs: CommunityVaultAcquisitionOutputV1[]; keys: ReturnType<typeof payment>[] } {
  const keys = policy.owners.map((_owner, index) => payment(310 + index));
  return {
    keys,
    inputs: policy.owners.map((owner, index) => ({
      txid: (310 + index).toString(16).padStart(64, '0'),
      vout: index,
      valueSats: (dues.get(owner.ownerId)! + CHANGE).toString(),
      scriptPubKeyHex: keys[index]!.scriptPubKeyHex,
      sequence: 0xffff_fffd,
      scriptKind: 'p2wpkh',
      role: 'owner-funding',
      ownerId: owner.ownerId,
      sighashType: SigHash.ALL,
    })),
    outputs: policy.owners.map((owner, index) => ({
      valueSats: CHANGE.toString(),
      scriptPubKeyHex: keys[index]!.scriptPubKeyHex,
      role: 'owner-change',
      ownerId: owner.ownerId,
      recipientId: null,
    })),
  };
}

function assetInput(policy: CommunityVaultPolicyV1) {
  const key = payment(300);
  return {
    key,
    input: {
      txid: policy.currentOutpoint.txid,
      vout: policy.currentOutpoint.vout,
      valueSats: '10000',
      scriptPubKeyHex: key.scriptPubKeyHex,
      sequence: 0xffff_fffd,
      scriptKind: 'p2wpkh' as const,
      role: 'inscription' as const,
      ownerId: null,
      sighashType: SigHash.ALL,
    },
  };
}

function listedFixture(): {
  policy: CommunityVaultPolicyV1;
  plan: CommunityVaultAcquisitionPlanV1;
  keys: ReturnType<typeof payment>[];
} {
  const { policy } = fixturePolicy();
  const asset = assetInput(policy);
  const seller = payment(301);
  const marketplace = payment(302);
  const assetCost = 102_000n;
  const fee = 2_000n;
  const assetShares = ownerShares(policy, assetCost);
  const feeShares = ownerShares(policy, fee);
  const dues = new Map(policy.owners.map((owner) => [
    owner.ownerId,
    assetShares.get(owner.ownerId)! + feeShares.get(owner.ownerId)!,
  ]));
  const paid = funding(policy, dues);
  const outputs: CommunityVaultAcquisitionOutputV1[] = [
    { valueSats: '10000', scriptPubKeyHex: policy.scriptPubKeyHex, role: 'vault', ownerId: null, recipientId: null },
    { valueSats: '100000', scriptPubKeyHex: seller.scriptPubKeyHex, role: 'seller-payment', ownerId: null, recipientId: 'seller' },
    { valueSats: '2000', scriptPubKeyHex: marketplace.scriptPubKeyHex, role: 'marketplace-fee', ownerId: null, recipientId: 'satflow' },
    ...paid.outputs,
  ];
  const plan = createCommunityVaultListedAcquisitionPlan({
    policy,
    planId: 'listed-fixture-1',
    createdAtMs: CREATED,
    expiresAtMs: EXPIRES,
    inputs: [asset.input, ...paid.inputs],
    outputs,
    assetInputIndex: 0,
    vaultOutputIndex: 0,
    inscriptionInputOffsetSats: '0',
    inscriptionOutputOffsetSats: '0',
    postageSats: '546',
    settlementFeeSats: fee.toString(),
    listedTerms: {
      marketplaceId: 'satflow',
      listingId: 'listing-fixture-1',
      listingFingerprintHex: 'ab'.repeat(32),
      observedAtMs: (BigInt(CREATED) - 1_000n).toString(),
      listingExpiresAtMs: EXPIRES,
      sellerPaymentSats: '100000',
      sellerPayoutScriptPubKeyHex: seller.scriptPubKeyHex,
      maximumLandedCostSats: '105000',
    },
  });
  return { policy, plan, keys: [asset.key, ...paid.keys] };
}

function frontedFixture(): {
  policy: CommunityVaultPolicyV1;
  plan: CommunityVaultAcquisitionPlanV1;
  keys: ReturnType<typeof payment>[];
} {
  const { policy } = fixturePolicy();
  const asset = assetInput(policy);
  const creatorAssetInput: CommunityVaultAcquisitionInputV1 = {
    ...asset.input,
    ownerId: policy.creatorOwnerId,
  };
  const creator = payment(303);
  const assetCost = 200_000n;
  const fee = 2_000n;
  const assetShares = ownerShares(policy, assetCost);
  const feeShares = ownerShares(policy, fee);
  const dues = new Map(policy.owners.map((owner) => [
    owner.ownerId,
    feeShares.get(owner.ownerId)! + (owner.ownerId === policy.creatorOwnerId ? 0n : assetShares.get(owner.ownerId)!),
  ]));
  const paid = funding(policy, dues);
  const reimbursement = [...assetShares.entries()]
    .filter(([ownerId]) => ownerId !== policy.creatorOwnerId)
    .reduce((total, [, value]) => total + value, 0n);
  const plan = createCommunityVaultFrontedAcquisitionPlan({
    policy,
    planId: 'fronted-fixture-1',
    createdAtMs: CREATED,
    expiresAtMs: EXPIRES,
    inputs: [creatorAssetInput, ...paid.inputs],
    outputs: [
      { valueSats: '10000', scriptPubKeyHex: policy.scriptPubKeyHex, role: 'vault', ownerId: null, recipientId: null },
      {
        valueSats: reimbursement.toString(),
        scriptPubKeyHex: creator.scriptPubKeyHex,
        role: 'creator-reimbursement',
        ownerId: null,
        recipientId: policy.creatorOwnerId,
      },
      ...paid.outputs,
    ],
    assetInputIndex: 0,
    vaultOutputIndex: 0,
    inscriptionInputOffsetSats: '0',
    inscriptionOutputOffsetSats: '0',
    postageSats: '546',
    settlementFeeSats: fee.toString(),
    frontedTerms: {
      purchaseTxid: policy.currentOutpoint.txid,
      purchaseConfirmedAtMs: (BigInt(CREATED) - 3_600_000n).toString(),
      campaignOpenedAtMs: (BigInt(CREATED) - 1_000n).toString(),
      sellerPriceSats: '190000',
      marketplaceFeeSats: '5000',
      purchaseMinerFeeSats: '4000',
      requiredPostageSats: '2000',
      rebatesSats: '500',
      refundsSats: '500',
      verifiedLandedCostSats: assetCost.toString(),
    },
  });
  return { policy, plan, keys: [asset.key, ...paid.keys] };
}

function preflight(plan: CommunityVaultAcquisitionPlanV1): CommunityVaultAcquisitionPreflightV1 {
  return {
    version: 1,
    network: 'mainnet',
    source: 'ord',
    verifiedAtMs: (BigInt(CREATED) + 10_000n).toString(),
    blockHeight: 910_000,
    blockHash: 'cd'.repeat(32),
    inputs: plan.inputs.map((input, index) => ({
      inputIndex: index,
      txid: input.txid,
      vout: input.vout,
      valueSats: input.valueSats,
      scriptPubKeyHex: input.scriptPubKeyHex,
      unspent: true,
      inscriptionIds: index === plan.assetInputIndex ? [plan.inscriptionId] : [],
      runeIds: [],
    })),
    listing: plan.listedTerms ? {
      marketplaceId: plan.listedTerms.marketplaceId,
      listingId: plan.listedTerms.listingId,
      listingFingerprintHex: plan.listedTerms.listingFingerprintHex,
      active: true,
      observedAtMs: CREATED,
    } : null,
  };
}

function finalizeFixture(
  policy: CommunityVaultPolicyV1,
  plan: CommunityVaultAcquisitionPlanV1,
  keys: ReturnType<typeof payment>[],
): string {
  const tx = Transaction.fromPSBT(hexToBytes(constructCommunityVaultAcquisitionPsbt(policy, plan)), {
    PSBTVersion: 0,
    lowR: true,
  });
  keys.forEach((key, index) => {
    if (!key.child.privateKey) throw new Error('fixture signing key unavailable');
    tx.signIdx(key.child.privateKey, index, [SigHash.ALL]);
    tx.finalizeIdx(index);
  });
  const finalizedPsbt = bytesToHex(tx.toPSBT(0));
  expect(validateCommunityVaultAcquisitionPsbt(policy, plan, finalizedPsbt).finalizedInputIndexes)
    .toEqual(plan.inputs.map((_input, index) => index));
  return bytesToHex(tx.extract());
}

describe('Community Vault acquisition allocation', () => {
  it('allocates every sat exactly by numbered unit with at most one sat variance', () => {
    fc.assert(fc.property(fc.bigInt({ min: 0n, max: 21_000_000_0000_0000n }), (total) => {
      const allocations = communityVaultAcquisitionUnitAmounts(total.toString()).map(BigInt);
      expect(allocations.reduce((sum, value) => sum + value, 0n)).toBe(total);
      expect(allocations[0]! - allocations[99]!).toBeLessThanOrEqual(1n);
    }));
  });
});

describe('Community Vault listed acquisition profile', () => {
  it('builds, preflights, fully signs, decodes, and verifies a mainnet-format purchase', () => {
    const { policy, plan, keys } = listedFixture();
    expect(plan.totalEconomicCostSats).toBe('104000');
    expect(plan.ownerObligations.every((owner) =>
      BigInt(owner.cashDueSats) === BigInt(owner.assetCostShareSats) + BigInt(owner.settlementFeeShareSats)))
      .toBe(true);
    assertCommunityVaultAcquisitionPreflight({
      policy,
      plan,
      preflight: preflight(plan),
      nowMs: (BigInt(CREATED) + 20_000n).toString(),
    });
    const final = verifyFinalizedCommunityVaultAcquisition({
      policy,
      plan,
      transactionHex: finalizeFixture(policy, plan, keys),
    });
    expect(final.feeSats).toBe('2000');
    expect(final.weight).toBeLessThanOrEqual(400_000);
    expect(final.txid).toMatch(/^[0-9a-f]{64}$/u);
  });

  it('rejects listing mutation, stale/spent evidence, extra assets, and excessive landed cost', () => {
    const { policy, plan } = listedFixture();
    const mutate = (change: (copy: CommunityVaultAcquisitionPlanV1) => void) => {
      const copy = structuredClone(plan);
      change(copy);
      return () => assertCommunityVaultAcquisitionPlan(policy, copy);
    };
    expect(mutate((copy) => { copy.listedTerms!.listingFingerprintHex = 'ef'.repeat(32); })).toThrow(/digest/u);
    expect(mutate((copy) => { copy.listedTerms!.maximumLandedCostSats = '103999'; })).toThrow(/maximum/u);
    expect(mutate((copy) => { copy.outputs[1]!.valueSats = '99999'; })).toThrow();

    const stale = preflight(plan);
    expect(() => assertCommunityVaultAcquisitionPreflight({
      policy, plan, preflight: stale, nowMs: (BigInt(stale.verifiedAtMs) + 120_001n).toString(),
    })).toThrow(/stale/u);
    const spent = preflight(plan);
    spent.inputs[1]!.unspent = false;
    expect(() => assertCommunityVaultAcquisitionPreflight({
      policy, plan, preflight: spent, nowMs: (BigInt(CREATED) + 20_000n).toString(),
    })).toThrow(/differs/u);
    const extra = preflight(plan);
    extra.inputs[1]!.inscriptionIds.push(`${'ee'.repeat(32)}i0`);
    expect(() => assertCommunityVaultAcquisitionPreflight({
      policy, plan, preflight: extra, nowMs: (BigInt(CREATED) + 20_000n).toString(),
    })).toThrow(/unexpected inscriptions/u);
  });

  it('rejects output reordering, foreign PSBT fields, and signature mutation', () => {
    const { policy, plan, keys } = listedFixture();
    const changed = structuredClone(plan);
    [changed.outputs[0], changed.outputs[1]] = [changed.outputs[1]!, changed.outputs[0]!];
    expect(() => assertCommunityVaultAcquisitionPlan(policy, changed)).toThrow();

    const psbt = constructCommunityVaultAcquisitionPsbt(policy, plan);
    const tx = Transaction.fromPSBT(hexToBytes(psbt), { PSBTVersion: 0, allowUnknown: true });
    tx.updateInput(1, {
      unknown: [[{ type: 0xfc, key: Uint8Array.of(1) }, Uint8Array.of(2)]],
    } as unknown as Parameters<Transaction['updateInput']>[1], true);
    expect(() => validateCommunityVaultAcquisitionPsbt(
      policy, plan, bytesToHex(tx.toPSBT(0)),
    )).toThrow(/unapproved|differs/u);
    const signed = finalizeFixture(policy, plan, keys);
    const raw = Transaction.fromRaw(hexToBytes(signed));
    const signature = raw.getInput(1).finalScriptWitness![0]!;
    const signatureHex = bytesToHex(signature);
    const mutated = signed.replace(signatureHex, `${signatureHex.startsWith('00') ? '01' : '00'}${signatureHex.slice(2)}`);
    expect(() => verifyFinalizedCommunityVaultAcquisition({ policy, plan, transactionHex: mutated })).toThrow();
  });

  it('combines independent owner approvals and finalizes without broadcasting', () => {
    const { policy, plan, keys } = listedFixture();
    const unsigned = constructCommunityVaultAcquisitionPsbt(policy, plan);
    const packages = keys.map((key, index) => {
      const tx = Transaction.fromPSBT(hexToBytes(unsigned), { PSBTVersion: 0, lowR: true });
      if (!key.child.privateKey) throw new Error('fixture signing key unavailable');
      tx.signIdx(key.child.privateKey, index, [SigHash.ALL]);
      tx.finalizeIdx(index);
      return bytesToHex(tx.toPSBT(0));
    });
    expect(() => finalizeCommunityVaultAcquisitionPsbt({
      policy,
      plan,
      psbtHex: combineCommunityVaultAcquisitionPsbts({
        policy,
        plan,
        psbtHexes: packages.slice(0, -1),
      }).psbtHex,
    })).toThrow(/not signed/u);
    const forward = combineCommunityVaultAcquisitionPsbts({ policy, plan, psbtHexes: packages });
    const reverse = combineCommunityVaultAcquisitionPsbts({ policy, plan, psbtHexes: [...packages].reverse() });
    expect(reverse).toEqual(forward);
    const final = finalizeCommunityVaultAcquisitionPsbt({ policy, plan, psbtHex: forward.psbtHex });
    expect(final.transactionHex).toMatch(/^[0-9a-f]+$/u);
    expect(final.feeSats).toBe(plan.settlementFeeSats);
    expect(() => combineCommunityVaultAcquisitionPsbts({
      policy,
      plan,
      psbtHexes: [packages[0]!, packages[0]!],
    })).toThrow(/duplicate/u);
  });
});

describe('Community Vault creator-fronted acquisition profile', () => {
  it('charges every owner a pro-rata settlement fee and reimburses no creator-owned asset share', () => {
    const { policy, plan, keys } = frontedFixture();
    const creator = plan.ownerObligations.find((owner) => owner.ownerId === policy.creatorOwnerId)!;
    expect(creator.assetCostShareSats).toBe('40000');
    expect(creator.settlementFeeShareSats).toBe('400');
    expect(creator.cashDueSats).toBe('400');
    expect(plan.frontedTerms!.creatorReimbursementSats).toBe('160000');
    expect(plan.outputs.find((output) => output.role === 'creator-reimbursement')!.valueSats).toBe('160000');
    assertCommunityVaultAcquisitionPreflight({
      policy,
      plan,
      preflight: preflight(plan),
      nowMs: (BigInt(CREATED) + 20_000n).toString(),
    });
    expect(verifyFinalizedCommunityVaultAcquisition({
      policy,
      plan,
      transactionHex: finalizeFixture(policy, plan, keys),
    }).feeSats).toBe('2000');
  });

  it('rejects campaigns opened after 24 hours and duplicated creator reimbursement', () => {
    const { policy, plan } = frontedFixture();
    const late = structuredClone(plan);
    late.frontedTerms!.campaignOpenedAtMs =
      (BigInt(late.frontedTerms!.purchaseConfirmedAtMs) + 86_400_001n).toString();
    expect(() => assertCommunityVaultAcquisitionPlan(policy, late)).toThrow(/24-hour/u);

    const duplicate = structuredClone(plan);
    duplicate.outputs[1]!.valueSats = '160001';
    expect(() => assertCommunityVaultAcquisitionPlan(policy, duplicate)).toThrow();
  });
});
