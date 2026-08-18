/** Strict transaction profiles for Community Vault v1 acquisitions. */
import { schnorr, secp256k1 } from '@noble/curves/secp256k1';
import { SigHash, Transaction } from '@scure/btc-signer';
import { hash160 } from '@scure/btc-signer/utils';
import { getCryptoProvider } from '../vault/crypto-provider';
import { bytesToHex, hexToBytes, utf8ToBytes } from '../vault/encoding';
import {
  COMMUNITY_VAULT_FRONTED_OPEN_WINDOW_MS,
  COMMUNITY_VAULT_MAX_PREFLIGHT_AGE_MS,
  communityVaultAcquisitionPlanSchema,
  communityVaultAcquisitionPreflightSchema,
  type CommunityVaultAcquisitionInputV1,
  type CommunityVaultAcquisitionOutputV1,
  type CommunityVaultAcquisitionPlanV1,
  type CommunityVaultAcquisitionPreflightV1,
  type CommunityVaultFrontedAcquisitionDraftV1,
  type CommunityVaultListedAcquisitionDraftV1,
  type CommunityVaultOwnerObligationV1,
} from './acquisition-contracts';
import type { CommunityVaultPolicyV1 } from './contracts';
import { assertCommunityVaultPolicy } from './policy';

const ACQUISITION_DOMAIN = 'drey-community-vault-acquisition-v1';
const MAX_PSBT_BYTES = 2_000_000;
const MAX_STANDARD_TRANSACTION_WEIGHT = 400_000;
const SIGHASH_SINGLE_ANYONECANPAY = SigHash.SINGLE_ANYONECANPAY;

export interface CommunityVaultAcquisitionPsbtValidationV1 {
  version: 1;
  psbtHex: string;
  psbtHash: string;
  finalizedInputIndexes: number[];
}

export interface FinalizedCommunityVaultAcquisitionV1 {
  version: 1;
  transactionHex: string;
  txid: string;
  wtxid: string;
  weight: number;
  vsize: number;
  feeSats: string;
  feeRateSatPerKvB: string;
}

export interface CombinedCommunityVaultAcquisitionPsbtV1
  extends CommunityVaultAcquisitionPsbtValidationV1 {
  version: 1;
}

export interface FinalizedCommunityVaultAcquisitionPsbtV1
  extends FinalizedCommunityVaultAcquisitionV1 {
  psbtHex: string;
  psbtHash: string;
}

function canonical(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonical);
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value as Record<string, unknown>)
      .filter(([key]) => key !== 'planDigest')
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, child]) => [key, canonical(child)]));
  }
  return value;
}

function hashDomain(domain: string, value: Uint8Array): string {
  const prefix = utf8ToBytes(domain);
  const input = new Uint8Array(prefix.length + 1 + value.length);
  input.set(prefix);
  input[prefix.length] = 0;
  input.set(value, prefix.length + 1);
  return bytesToHex(getCryptoProvider().sha256(input));
}

function planDigest(plan: Omit<CommunityVaultAcquisitionPlanV1, 'planDigest'> | CommunityVaultAcquisitionPlanV1): string {
  return hashDomain(ACQUISITION_DOMAIN, utf8ToBytes(JSON.stringify(canonical(plan))));
}

function sum(values: readonly string[]): bigint {
  return values.reduce((total, value) => total + BigInt(value), 0n);
}

function buildUnsignedTransaction(
  inputs: readonly CommunityVaultAcquisitionInputV1[],
  outputs: readonly CommunityVaultAcquisitionOutputV1[],
): string {
  const tx = new Transaction({ PSBTVersion: 0, version: 2, lockTime: 0 });
  for (const input of inputs) tx.addInput({ txid: input.txid, index: input.vout, sequence: input.sequence });
  for (const output of outputs) {
    tx.addOutput({ script: hexToBytes(output.scriptPubKeyHex), amount: BigInt(output.valueSats) });
  }
  return bytesToHex(tx.unsignedTx);
}

function allocateUnitShares(policy: CommunityVaultPolicyV1, amount: bigint): Map<string, bigint> {
  const perUnit = amount / 100n;
  const remainder = Number(amount % 100n);
  return new Map(policy.owners.map((owner) => [owner.ownerId, owner.units.reduce((ownerTotal, unit) =>
    ownerTotal + perUnit + (unit < remainder ? 1n : 0n), 0n)]));
}

/** Deterministic numbered-unit allocation used for both purchase cost and settlement fees. */
export function communityVaultAcquisitionUnitAmounts(totalSats: string): string[] {
  const total = BigInt(totalSats);
  if (total < 0n || total > 0xffff_ffff_ffff_ffffn) throw new RangeError('invalid Community Vault allocation total');
  const base = total / 100n;
  const remainder = Number(total % 100n);
  return Array.from({ length: 100 }, (_unused, unit) => (base + (unit < remainder ? 1n : 0n)).toString());
}

function ownerFundingTotals(
  policy: CommunityVaultPolicyV1,
  inputs: readonly CommunityVaultAcquisitionInputV1[],
  outputs: readonly CommunityVaultAcquisitionOutputV1[],
): Map<string, { inputs: bigint; change: bigint }> {
  const totals = new Map(policy.owners.map((owner) => [owner.ownerId, { inputs: 0n, change: 0n }]));
  for (const input of inputs) {
    if (input.role !== 'owner-funding' || input.ownerId === null) continue;
    const value = totals.get(input.ownerId);
    if (!value) throw new Error('acquisition funding owner is absent from the frozen cap table');
    value.inputs += BigInt(input.valueSats);
  }
  for (const output of outputs) {
    if (output.role !== 'owner-change' || output.ownerId === null) continue;
    const value = totals.get(output.ownerId);
    if (!value) throw new Error('acquisition change owner is absent from the frozen cap table');
    value.change += BigInt(output.valueSats);
  }
  return totals;
}

function ownerObligations(
  policy: CommunityVaultPolicyV1,
  source: 'listed' | 'creator-fronted',
  assetCostSats: bigint,
  settlementFeeSats: bigint,
  inputs: readonly CommunityVaultAcquisitionInputV1[],
  outputs: readonly CommunityVaultAcquisitionOutputV1[],
): CommunityVaultOwnerObligationV1[] {
  const assetShares = allocateUnitShares(policy, assetCostSats);
  const feeShares = allocateUnitShares(policy, settlementFeeSats);
  const funding = ownerFundingTotals(policy, inputs, outputs);
  return [...policy.owners]
    .sort((left, right) => left.capTableOrder - right.capTableOrder)
    .map((owner) => {
      const assetShare = assetShares.get(owner.ownerId)!;
      const feeShare = feeShares.get(owner.ownerId)!;
      const cashDue = source === 'creator-fronted' && owner.ownerId === policy.creatorOwnerId
        ? feeShare : assetShare + feeShare;
      const actual = funding.get(owner.ownerId)!;
      return {
        ownerId: owner.ownerId,
        capTableOrder: owner.capTableOrder,
        units: [...owner.units],
        assetCostShareSats: assetShare.toString(),
        settlementFeeShareSats: feeShare.toString(),
        cashDueSats: cashDue.toString(),
        fundingInputSats: actual.inputs.toString(),
        changeSats: actual.change.toString(),
      };
    });
}

function assertInputShape(plan: CommunityVaultAcquisitionPlanV1, policy: CommunityVaultPolicyV1): void {
  const outpoints = new Set<string>();
  let assetInputs = 0;
  for (let index = 0; index < plan.inputs.length; index += 1) {
    const input = plan.inputs[index]!;
    const outpoint = `${input.txid}:${input.vout}`;
    if (outpoints.has(outpoint)) throw new Error('Community Vault acquisition contains a duplicate input');
    outpoints.add(outpoint);
    const expectedKind = /^0014[0-9a-f]{40}$/u.test(input.scriptPubKeyHex) ? 'p2wpkh'
      : /^5120[0-9a-f]{64}$/u.test(input.scriptPubKeyHex) ? 'p2tr' : null;
    if (expectedKind !== input.scriptKind || BigInt(input.valueSats) <= 0n) {
      throw new Error(`Community Vault acquisition input ${index} has an unsupported script or value`);
    }
    if (input.role === 'inscription') {
      assetInputs += 1;
      if (index !== plan.assetInputIndex) throw new Error('Community Vault inscription input index differs from plan');
      if (plan.source === 'creator-fronted' && input.ownerId !== policy.creatorOwnerId) {
        throw new Error('creator-fronted inscription input must belong to the creator');
      }
      if (plan.source === 'listed' && input.ownerId !== null) {
        throw new Error('listed inscription input must remain external to the cap table');
      }
      const allowed = plan.source === 'listed'
        ? [SigHash.DEFAULT, SigHash.ALL, SIGHASH_SINGLE_ANYONECANPAY]
        : [SigHash.DEFAULT, SigHash.ALL];
      if (!allowed.includes(input.sighashType)) throw new Error('unsafe inscription-input sighash');
    } else {
      if (input.ownerId === null || !policy.owners.some((owner) => owner.ownerId === input.ownerId)) {
        throw new Error('owner funding input is not bound to a cap-table owner');
      }
      const expectedSighash = input.scriptKind === 'p2wpkh' ? SigHash.ALL : SigHash.DEFAULT;
      if (input.sighashType !== expectedSighash) {
        throw new Error('owner funding input does not commit to the complete acquisition');
      }
    }
  }
  if (assetInputs !== 1) throw new Error('Community Vault acquisition requires one exact inscription input');
}

function assertOutputShape(plan: CommunityVaultAcquisitionPlanV1, policy: CommunityVaultPolicyV1): void {
  let vaultOutputs = 0;
  const changeOwners = new Set<string>();
  for (let index = 0; index < plan.outputs.length; index += 1) {
    const output = plan.outputs[index]!;
    if (BigInt(output.valueSats) <= 0n) throw new Error('Community Vault acquisition output must be positive');
    if (output.role === 'vault') {
      vaultOutputs += 1;
      if (index !== plan.vaultOutputIndex || output.scriptPubKeyHex !== policy.scriptPubKeyHex ||
          output.ownerId !== null || output.recipientId !== null) {
        throw new Error('Community Vault acquisition vault output differs from frozen policy');
      }
    } else if (output.role === 'owner-change') {
      if (output.ownerId === null || output.recipientId !== null || changeOwners.has(output.ownerId) ||
          !policy.owners.some((owner) => owner.ownerId === output.ownerId)) {
        throw new Error('Community Vault acquisition owner change is invalid or duplicated');
      }
      changeOwners.add(output.ownerId);
    } else if (output.ownerId !== null || output.recipientId === null) {
      throw new Error('Community Vault acquisition external output attribution is invalid');
    }
  }
  if (vaultOutputs !== 1) throw new Error('Community Vault acquisition requires one exact vault output');
  const allowed = plan.source === 'listed'
    ? new Set(['vault', 'seller-payment', 'marketplace-fee', 'owner-change'])
    : new Set(['vault', 'creator-reimbursement', 'owner-change']);
  if (plan.outputs.some((output) => !allowed.has(output.role))) {
    throw new Error('Community Vault acquisition contains an unexplained output');
  }
}

function assertOrdinalRoute(plan: CommunityVaultAcquisitionPlanV1): void {
  const input = plan.inputs[plan.assetInputIndex];
  const output = plan.outputs[plan.vaultOutputIndex];
  if (!input || !output || BigInt(plan.inscriptionInputOffsetSats) >= BigInt(input.valueSats)) {
    throw new Error('Community Vault acquisition inscription source is invalid');
  }
  const absoluteInputOffset = sum(plan.inputs.slice(0, plan.assetInputIndex).map((item) => item.valueSats)) +
    BigInt(plan.inscriptionInputOffsetSats);
  const outputStart = sum(plan.outputs.slice(0, plan.vaultOutputIndex).map((item) => item.valueSats));
  const expectedOutputOffset = absoluteInputOffset - outputStart;
  if (expectedOutputOffset < 0n || expectedOutputOffset >= BigInt(output.valueSats) ||
      expectedOutputOffset.toString() !== plan.inscriptionOutputOffsetSats ||
      BigInt(output.valueSats) - expectedOutputOffset < BigInt(plan.postageSats)) {
    throw new Error('Community Vault acquisition does not preserve the exact inscribed sat and postage');
  }
}

function assertEconomics(plan: CommunityVaultAcquisitionPlanV1, policy: CommunityVaultPolicyV1): void {
  const inputTotal = sum(plan.inputs.map((input) => input.valueSats));
  const outputTotal = sum(plan.outputs.map((output) => output.valueSats));
  if (inputTotal <= outputTotal || inputTotal - outputTotal !== BigInt(plan.settlementFeeSats)) {
    throw new Error('Community Vault acquisition settlement fee is inconsistent');
  }
  if (BigInt(plan.totalEconomicCostSats) !== BigInt(plan.assetCostSats) + BigInt(plan.settlementFeeSats)) {
    throw new Error('Community Vault acquisition total cost is inconsistent');
  }
  const expected = ownerObligations(
    policy, plan.source, BigInt(plan.assetCostSats), BigInt(plan.settlementFeeSats), plan.inputs, plan.outputs,
  );
  if (JSON.stringify(expected) !== JSON.stringify(plan.ownerObligations)) {
    throw new Error('Community Vault acquisition owner obligations differ from numbered-unit allocation');
  }
  for (const obligation of plan.ownerObligations) {
    if (BigInt(obligation.fundingInputSats) - BigInt(obligation.changeSats) !== BigInt(obligation.cashDueSats)) {
      throw new Error(`Community Vault acquisition funding differs from ${obligation.ownerId} total due`);
    }
  }

  if (plan.source === 'listed') {
    if (!plan.listedTerms || plan.frontedTerms) throw new Error('listed acquisition terms are missing or mixed');
    const sellerOutputs = plan.outputs.filter((output) => output.role === 'seller-payment');
    if (sellerOutputs.length !== 1 || sellerOutputs[0]!.valueSats !== plan.listedTerms.sellerPaymentSats ||
        sellerOutputs[0]!.scriptPubKeyHex !== plan.listedTerms.sellerPayoutScriptPubKeyHex) {
      throw new Error('listed acquisition seller payment differs from listing');
    }
    const assetCost = sum(plan.outputs
      .filter((output) => output.role === 'seller-payment' || output.role === 'marketplace-fee')
      .map((output) => output.valueSats));
    if (assetCost.toString() !== plan.assetCostSats ||
        BigInt(plan.totalEconomicCostSats) > BigInt(plan.listedTerms.maximumLandedCostSats) ||
        BigInt(plan.createdAtMs) < BigInt(plan.listedTerms.observedAtMs) ||
        BigInt(plan.expiresAtMs) > BigInt(plan.listedTerms.listingExpiresAtMs)) {
      throw new Error('listed acquisition price, maximum, or freshness differs from frozen listing');
    }
  } else {
    if (!plan.frontedTerms || plan.listedTerms) throw new Error('creator-fronted acquisition terms are missing or mixed');
    const terms = plan.frontedTerms;
    const gross = BigInt(terms.sellerPriceSats) + BigInt(terms.marketplaceFeeSats) +
      BigInt(terms.purchaseMinerFeeSats) + BigInt(terms.requiredPostageSats);
    const reductions = BigInt(terms.rebatesSats) + BigInt(terms.refundsSats);
    if (reductions > gross || gross - reductions !== BigInt(terms.verifiedLandedCostSats) ||
        terms.verifiedLandedCostSats !== plan.assetCostSats ||
        plan.inputs[plan.assetInputIndex]!.txid !== terms.purchaseTxid ||
        BigInt(terms.campaignOpenedAtMs) < BigInt(terms.purchaseConfirmedAtMs) ||
        BigInt(terms.campaignOpenedAtMs) - BigInt(terms.purchaseConfirmedAtMs) >
          BigInt(COMMUNITY_VAULT_FRONTED_OPEN_WINDOW_MS)) {
      throw new Error('creator-fronted landed cost or 24-hour freshness is invalid');
    }
    const reimbursementOutputs = plan.outputs.filter((output) => output.role === 'creator-reimbursement');
    const nonCreatorShares = sum(plan.ownerObligations
      .filter((owner) => owner.ownerId !== policy.creatorOwnerId)
      .map((owner) => owner.assetCostShareSats));
    if (reimbursementOutputs.length !== 1 || reimbursementOutputs[0]!.recipientId !== policy.creatorOwnerId ||
        BigInt(reimbursementOutputs[0]!.valueSats) !== nonCreatorShares ||
        BigInt(terms.creatorReimbursementSats) !== nonCreatorShares) {
      throw new Error('creator-fronted reimbursement duplicates or omits an ownership share');
    }
  }
}

export function assertCommunityVaultAcquisitionPlan(
  policy: CommunityVaultPolicyV1,
  raw: CommunityVaultAcquisitionPlanV1,
): void {
  assertCommunityVaultPolicy(policy);
  const plan = communityVaultAcquisitionPlanSchema.parse(raw);
  if (plan.policyId !== policy.policyId || plan.capTableHash !== policy.capTableHash ||
      plan.capTableVersion !== policy.capTableVersion || plan.campaignId !== policy.campaignId ||
      plan.inscriptionId !== policy.inscriptionId || plan.network !== policy.network) {
    throw new Error('Community Vault acquisition policy binding mismatch');
  }
  if (BigInt(plan.createdAtMs) >= BigInt(plan.expiresAtMs)) throw new Error('Community Vault acquisition expiry is invalid');
  if (plan.assetInputIndex >= plan.inputs.length || plan.vaultOutputIndex >= plan.outputs.length) {
    throw new Error('Community Vault acquisition index is out of range');
  }
  const assetInput = plan.inputs[plan.assetInputIndex]!;
  if (assetInput.txid !== policy.currentOutpoint.txid || assetInput.vout !== policy.currentOutpoint.vout) {
    throw new Error('Community Vault acquisition does not spend the frozen inscription outpoint');
  }
  if (buildUnsignedTransaction(plan.inputs, plan.outputs) !== plan.unsignedTransactionHex) {
    throw new Error('Community Vault acquisition unsigned transaction differs from plan');
  }
  assertInputShape(plan, policy);
  assertOutputShape(plan, policy);
  assertOrdinalRoute(plan);
  assertEconomics(plan, policy);
  if (planDigest(plan) !== plan.planDigest) throw new Error('Community Vault acquisition digest mismatch');
}

function createPlan(
  source: 'listed' | 'creator-fronted',
  draft: CommunityVaultListedAcquisitionDraftV1 | CommunityVaultFrontedAcquisitionDraftV1,
  assetCostSats: bigint,
  listedTerms: CommunityVaultAcquisitionPlanV1['listedTerms'],
  frontedTerms: CommunityVaultAcquisitionPlanV1['frontedTerms'],
): CommunityVaultAcquisitionPlanV1 {
  assertCommunityVaultPolicy(draft.policy);
  const settlementFee = BigInt(draft.settlementFeeSats);
  const unsignedTransactionHex = buildUnsignedTransaction(draft.inputs, draft.outputs);
  const withoutDigest: Omit<CommunityVaultAcquisitionPlanV1, 'planDigest'> = {
    version: 1,
    profileVersion: 1,
    policyVersion: 1,
    network: 'mainnet',
    source,
    campaignId: draft.policy.campaignId,
    policyId: draft.policy.policyId,
    capTableHash: draft.policy.capTableHash,
    capTableVersion: draft.policy.capTableVersion,
    inscriptionId: draft.policy.inscriptionId,
    planId: draft.planId,
    createdAtMs: draft.createdAtMs,
    expiresAtMs: draft.expiresAtMs,
    assetInputIndex: draft.assetInputIndex,
    vaultOutputIndex: draft.vaultOutputIndex,
    inscriptionInputOffsetSats: draft.inscriptionInputOffsetSats,
    inscriptionOutputOffsetSats: draft.inscriptionOutputOffsetSats,
    postageSats: draft.postageSats,
    assetCostSats: assetCostSats.toString(),
    settlementFeeSats: settlementFee.toString(),
    totalEconomicCostSats: (assetCostSats + settlementFee).toString(),
    inputs: draft.inputs,
    outputs: draft.outputs,
    ownerObligations: ownerObligations(
      draft.policy, source, assetCostSats, settlementFee, draft.inputs, draft.outputs,
    ),
    listedTerms,
    frontedTerms,
    unsignedTransactionHex,
  };
  const plan = communityVaultAcquisitionPlanSchema.parse({ ...withoutDigest, planDigest: planDigest(withoutDigest) });
  assertCommunityVaultAcquisitionPlan(draft.policy, plan);
  return plan;
}

export function createCommunityVaultListedAcquisitionPlan(
  draft: CommunityVaultListedAcquisitionDraftV1,
): CommunityVaultAcquisitionPlanV1 {
  const assetCost = sum(draft.outputs
    .filter((output) => output.role === 'seller-payment' || output.role === 'marketplace-fee')
    .map((output) => output.valueSats));
  return createPlan('listed', draft, assetCost, draft.listedTerms, null);
}

export function createCommunityVaultFrontedAcquisitionPlan(
  draft: CommunityVaultFrontedAcquisitionDraftV1,
): CommunityVaultAcquisitionPlanV1 {
  const terms = draft.frontedTerms;
  const gross = BigInt(terms.sellerPriceSats) + BigInt(terms.marketplaceFeeSats) +
    BigInt(terms.purchaseMinerFeeSats) + BigInt(terms.requiredPostageSats);
  const reductions = BigInt(terms.rebatesSats) + BigInt(terms.refundsSats);
  if (reductions > gross) throw new Error('creator-fronted rebates and refunds exceed verified costs');
  const assetCost = gross - reductions;
  const assetShares = allocateUnitShares(draft.policy, assetCost);
  const creatorReimbursement = [...assetShares.entries()]
    .filter(([ownerId]) => ownerId !== draft.policy.creatorOwnerId)
    .reduce((total, [, value]) => total + value, 0n);
  return createPlan('creator-fronted', draft, assetCost, null, {
    ...terms,
    creatorReimbursementSats: creatorReimbursement.toString(),
  });
}

export function assertCommunityVaultAcquisitionPreflight(input: {
  policy: CommunityVaultPolicyV1;
  plan: CommunityVaultAcquisitionPlanV1;
  preflight: CommunityVaultAcquisitionPreflightV1;
  nowMs: string;
  maximumAgeMs?: number;
}): void {
  assertCommunityVaultAcquisitionPlan(input.policy, input.plan);
  const evidence = communityVaultAcquisitionPreflightSchema.parse(input.preflight);
  const now = BigInt(input.nowMs);
  const maximumAge = BigInt(input.maximumAgeMs ?? COMMUNITY_VAULT_MAX_PREFLIGHT_AGE_MS);
  if (now < BigInt(evidence.verifiedAtMs) || now - BigInt(evidence.verifiedAtMs) > maximumAge ||
      now > BigInt(input.plan.expiresAtMs)) {
    throw new Error('Community Vault acquisition preflight is stale or expired');
  }
  if (evidence.inputs.length !== input.plan.inputs.length) {
    throw new Error('Community Vault acquisition preflight input count differs');
  }
  for (let index = 0; index < input.plan.inputs.length; index += 1) {
    const planned = input.plan.inputs[index]!;
    const observed = evidence.inputs[index]!;
    if (observed.inputIndex !== index || observed.txid !== planned.txid || observed.vout !== planned.vout ||
        observed.valueSats !== planned.valueSats || observed.scriptPubKeyHex !== planned.scriptPubKeyHex ||
        !observed.unspent || observed.runeIds.length !== 0) {
      throw new Error(`Community Vault acquisition preflight input ${index} differs or contains runes`);
    }
    const expectedInscriptions = index === input.plan.assetInputIndex ? [input.plan.inscriptionId] : [];
    if (JSON.stringify(observed.inscriptionIds) !== JSON.stringify(expectedInscriptions)) {
      throw new Error(`Community Vault acquisition preflight input ${index} has unexpected inscriptions`);
    }
  }
  if (input.plan.source === 'listed') {
    const terms = input.plan.listedTerms!;
    if (!evidence.listing || !evidence.listing.active || evidence.listing.marketplaceId !== terms.marketplaceId ||
        evidence.listing.listingId !== terms.listingId ||
        evidence.listing.listingFingerprintHex !== terms.listingFingerprintHex ||
        BigInt(evidence.listing.observedAtMs) < BigInt(terms.observedAtMs)) {
      throw new Error('Community Vault listed acquisition preflight differs from frozen listing');
    }
  } else if (evidence.listing !== null) {
    throw new Error('creator-fronted acquisition must not depend on listing evidence');
  }
}

type PsbtKeyValue = { key: Uint8Array; value: Uint8Array };

function readCompactSize(bytes: Uint8Array, cursor: { offset: number }): number {
  if (cursor.offset >= bytes.length) throw new Error('truncated acquisition PSBT compact size');
  const prefix = bytes[cursor.offset++]!;
  if (prefix < 0xfd) return prefix;
  const width = prefix === 0xfd ? 2 : prefix === 0xfe ? 4 : 8;
  if (cursor.offset + width > bytes.length) throw new Error('truncated acquisition PSBT compact size');
  const view = new DataView(bytes.buffer, bytes.byteOffset + cursor.offset, width);
  const value = width === 2 ? BigInt(view.getUint16(0, true))
    : width === 4 ? BigInt(view.getUint32(0, true)) : view.getBigUint64(0, true);
  cursor.offset += width;
  if ((width === 2 && value < 0xfdn) || (width === 4 && value <= 0xffffn) ||
      (width === 8 && value <= 0xffff_ffffn) || value > BigInt(MAX_PSBT_BYTES)) {
    throw new Error('non-canonical or excessive acquisition PSBT compact size');
  }
  return Number(value);
}

function readMap(bytes: Uint8Array, cursor: { offset: number }): PsbtKeyValue[] {
  const result: PsbtKeyValue[] = [];
  const keys = new Set<string>();
  while (true) {
    const keyLength = readCompactSize(bytes, cursor);
    if (keyLength === 0) return result;
    if (cursor.offset + keyLength > bytes.length) throw new Error('truncated acquisition PSBT key');
    const key = bytes.slice(cursor.offset, cursor.offset + keyLength);
    cursor.offset += keyLength;
    const keyHex = bytesToHex(key);
    if (keys.has(keyHex)) throw new Error('duplicate acquisition PSBT map key');
    keys.add(keyHex);
    const valueLength = readCompactSize(bytes, cursor);
    if (cursor.offset + valueLength > bytes.length) throw new Error('truncated acquisition PSBT value');
    result.push({ key, value: bytes.slice(cursor.offset, cursor.offset + valueLength) });
    cursor.offset += valueLength;
  }
}

function assertRawPsbtProfile(bytes: Uint8Array, plan: CommunityVaultAcquisitionPlanV1): void {
  if (bytes.length < 5 || bytesToHex(bytes.slice(0, 5)) !== '70736274ff') throw new Error('invalid acquisition PSBT framing');
  const cursor = { offset: 5 };
  const maps = Array.from({ length: 1 + plan.inputs.length + plan.outputs.length }, () => readMap(bytes, cursor));
  if (cursor.offset !== bytes.length) throw new Error('trailing acquisition PSBT maps');
  const global = maps[0]!;
  if (global.length !== 1 || bytesToHex(global[0]!.key) !== '00' ||
      bytesToHex(global[0]!.value) !== plan.unsignedTransactionHex) {
    throw new Error('acquisition PSBT global map differs from exact PSBTv0 transaction');
  }
  const allowedInputs = new Set([0x01, 0x02, 0x03, 0x06, 0x07, 0x08, 0x13, 0x16, 0x17]);
  for (let index = 0; index < plan.inputs.length; index += 1) {
    const map = maps[index + 1]!;
    const finalWitnessCount = map.filter(({ key }) => key[0] === 0x08).length;
    const sighashCount = map.filter(({ key }) => key[0] === 0x03).length;
    if (map.some(({ key }) => key.length < 1 || !allowedInputs.has(key[0]!)) ||
        map.filter(({ key }) => key[0] === 0x01).length !== 1 ||
        finalWitnessCount > 1 || (sighashCount !== 1 && !(sighashCount === 0 && finalWitnessCount === 1))) {
      throw new Error(`acquisition input ${index} contains an unapproved PSBT field`);
    }
  }
  for (let index = 0; index < plan.outputs.length; index += 1) {
    if (maps[1 + plan.inputs.length + index]!.length !== 0) {
      throw new Error(`acquisition output ${index} contains unexpected PSBT metadata`);
    }
  }
}

export function constructCommunityVaultAcquisitionPsbt(
  policy: CommunityVaultPolicyV1,
  plan: CommunityVaultAcquisitionPlanV1,
): string {
  assertCommunityVaultAcquisitionPlan(policy, plan);
  const tx = new Transaction({ PSBTVersion: 0, version: 2, lockTime: 0 });
  for (const input of plan.inputs) {
    tx.addInput({
      txid: input.txid,
      index: input.vout,
      sequence: input.sequence,
      witnessUtxo: { script: hexToBytes(input.scriptPubKeyHex), amount: BigInt(input.valueSats) },
      sighashType: input.sighashType,
    });
  }
  for (const output of plan.outputs) {
    tx.addOutput({ script: hexToBytes(output.scriptPubKeyHex), amount: BigInt(output.valueSats) });
  }
  const psbtHex = bytesToHex(tx.toPSBT(0));
  validateCommunityVaultAcquisitionPsbt(policy, plan, psbtHex);
  return psbtHex;
}

export function validateCommunityVaultAcquisitionPsbt(
  policy: CommunityVaultPolicyV1,
  plan: CommunityVaultAcquisitionPlanV1,
  psbtHex: string,
): CommunityVaultAcquisitionPsbtValidationV1 {
  assertCommunityVaultAcquisitionPlan(policy, plan);
  const bytes = hexToBytes(psbtHex);
  if (bytes.length > MAX_PSBT_BYTES) throw new Error('Community Vault acquisition PSBT exceeds size limit');
  const tx = Transaction.fromPSBT(bytes, { PSBTVersion: 0, lowR: true });
  if (tx.inputsLength !== plan.inputs.length || tx.outputsLength !== plan.outputs.length ||
      bytesToHex(tx.unsignedTx) !== plan.unsignedTransactionHex) {
    throw new Error('Community Vault acquisition PSBT transaction differs from plan');
  }
  assertRawPsbtProfile(bytes, plan);
  const finalizedInputIndexes: number[] = [];
  for (let index = 0; index < plan.inputs.length; index += 1) {
    const expected = plan.inputs[index]!;
    const actual = tx.getInput(index);
    const hasFinalWitness = (actual.finalScriptWitness?.length ?? 0) > 0;
    if (!actual.txid || bytesToHex(actual.txid) !== expected.txid || actual.index !== expected.vout ||
        actual.sequence !== expected.sequence || actual.witnessUtxo?.amount !== BigInt(expected.valueSats) ||
        !actual.witnessUtxo.script || bytesToHex(actual.witnessUtxo.script) !== expected.scriptPubKeyHex ||
        (actual.sighashType !== expected.sighashType && !(hasFinalWitness && actual.sighashType === undefined)) ||
        (actual.unknown?.length ?? 0) > 0 ||
        (actual.proprietary?.length ?? 0) > 0 || (actual.tapLeafScript?.length ?? 0) > 0 ||
        (actual.tapScriptSig?.length ?? 0) > 0) {
      throw new Error(`Community Vault acquisition PSBT input ${index} differs or contains a hidden path`);
    }
    const hasFinalScriptSig = (actual.finalScriptSig?.length ?? 0) > 0;
    if (hasFinalScriptSig && hasFinalWitness) throw new Error('acquisition input has conflicting final scripts');
    if (hasFinalWitness) {
      verifyInputSignature(tx, plan, index);
      finalizedInputIndexes.push(index);
    } else {
      verifyPartialInputSignature(tx, plan, index);
    }
  }
  for (let index = 0; index < plan.outputs.length; index += 1) {
    const expected = plan.outputs[index]!;
    const actual = tx.getOutput(index);
    if (!actual.script || bytesToHex(actual.script) !== expected.scriptPubKeyHex ||
        actual.amount !== BigInt(expected.valueSats) || (actual.unknown?.length ?? 0) > 0 ||
        (actual.proprietary?.length ?? 0) > 0) {
      throw new Error(`Community Vault acquisition PSBT output ${index} differs from plan`);
    }
  }
  return {
    version: 1,
    psbtHex,
    psbtHash: bytesToHex(getCryptoProvider().sha256(bytes)),
    finalizedInputIndexes,
  };
}

/**
 * Deterministically combines independently signed acquisition PSBTs. Every
 * candidate is validated against the frozen policy and exact transaction
 * before any signature material is admitted.
 */
export function combineCommunityVaultAcquisitionPsbts(input: {
  policy: CommunityVaultPolicyV1;
  plan: CommunityVaultAcquisitionPlanV1;
  psbtHexes: string[];
}): CombinedCommunityVaultAcquisitionPsbtV1 {
  if (input.psbtHexes.length === 0 || input.psbtHexes.length > input.plan.inputs.length) {
    throw new Error('Community Vault acquisition requires one unique PSBT per signer');
  }
  const candidates = input.psbtHexes.map((psbtHex) => ({
    psbtHex,
    validation: validateCommunityVaultAcquisitionPsbt(input.policy, input.plan, psbtHex),
  })).sort((left, right) => left.validation.psbtHash.localeCompare(right.validation.psbtHash));
  if (new Set(candidates.map(({ validation }) => validation.psbtHash)).size !== candidates.length) {
    throw new Error('duplicate Community Vault acquisition PSBT cannot be combined');
  }
  const claimedInputs = new Set<number>();
  for (const candidate of candidates) {
    if (candidate.validation.finalizedInputIndexes.length === 0) {
      throw new Error('Community Vault acquisition signer added no finalized input');
    }
    for (const index of candidate.validation.finalizedInputIndexes) {
      if (claimedInputs.has(index)) {
        throw new Error('Community Vault acquisition input was signed by more than one package');
      }
      claimedInputs.add(index);
    }
  }
  const combined = Transaction.fromPSBT(
    hexToBytes(constructCommunityVaultAcquisitionPsbt(input.policy, input.plan)),
    { PSBTVersion: 0, lowR: true },
  );
  for (const candidate of candidates) {
    combined.combine(Transaction.fromPSBT(hexToBytes(candidate.psbtHex), { PSBTVersion: 0, lowR: true }));
  }
  return validateCommunityVaultAcquisitionPsbt(
    input.policy,
    input.plan,
    bytesToHex(combined.toPSBT(0)),
  );
}

/** Finalizes every ordinary acquisition input and returns a verified raw transaction without broadcasting it. */
export function finalizeCommunityVaultAcquisitionPsbt(input: {
  policy: CommunityVaultPolicyV1;
  plan: CommunityVaultAcquisitionPlanV1;
  psbtHex: string;
}): FinalizedCommunityVaultAcquisitionPsbtV1 {
  validateCommunityVaultAcquisitionPsbt(input.policy, input.plan, input.psbtHex);
  const tx = Transaction.fromPSBT(hexToBytes(input.psbtHex), { PSBTVersion: 0, lowR: true });
  for (let index = 0; index < input.plan.inputs.length; index += 1) {
    if ((tx.getInput(index).finalScriptWitness?.length ?? 0) === 0) {
      try {
        tx.finalizeIdx(index);
      } catch {
        throw new Error(`Community Vault acquisition input ${index} is not signed`);
      }
    }
  }
  const psbtHex = bytesToHex(tx.toPSBT(0));
  const validation = validateCommunityVaultAcquisitionPsbt(input.policy, input.plan, psbtHex);
  if (validation.finalizedInputIndexes.length !== input.plan.inputs.length) {
    throw new Error('Community Vault acquisition is not fully signed');
  }
  const finalized = verifyFinalizedCommunityVaultAcquisition({
    policy: input.policy,
    plan: input.plan,
    transactionHex: bytesToHex(tx.extract()),
  });
  return { ...finalized, psbtHex, psbtHash: validation.psbtHash };
}

function verifyPartialInputSignature(
  tx: Transaction,
  plan: CommunityVaultAcquisitionPlanV1,
  index: number,
): void {
  const expected = plan.inputs[index]!;
  const actual = tx.getInput(index);
  if (expected.scriptKind === 'p2wpkh') {
    if ((actual.tapKeySig?.length ?? 0) > 0 || (actual.partialSig?.length ?? 0) > 1) {
      throw new Error(`acquisition input ${index} contains conflicting partial signatures`);
    }
    const signed = actual.partialSig?.[0];
    if (!signed) return;
    const [publicKey, signature] = signed;
    const keyHash = expected.scriptPubKeyHex.slice(4);
    const message = tx.preimageWitnessV0(
      index,
      hexToBytes(`76a914${keyHash}88ac`),
      expected.sighashType,
      BigInt(expected.valueSats),
    );
    if (signature.at(-1) !== expected.sighashType || bytesToHex(hash160(publicKey)) !== keyHash ||
        !secp256k1.verify(signature.slice(0, -1), message, publicKey, {
          format: 'der', prehash: false, lowS: true,
        })) {
      throw new Error(`invalid acquisition partial signature at input ${index}`);
    }
    return;
  }
  if ((actual.partialSig?.length ?? 0) > 0) {
    throw new Error(`acquisition input ${index} contains a non-Taproot partial signature`);
  }
  const signature = actual.tapKeySig;
  if (!signature) return;
  const sighash = signature.length === 64 ? SigHash.DEFAULT : signature.length === 65 ? signature[64]! : -1;
  if (sighash !== expected.sighashType) throw new Error(`acquisition Taproot sighash differs at input ${index}`);
  const message = tx.preimageWitnessV1(
    index,
    plan.inputs.map((input) => hexToBytes(input.scriptPubKeyHex)),
    sighash,
    plan.inputs.map((input) => BigInt(input.valueSats)),
  );
  if (!schnorr.verify(signature.slice(0, 64), message, hexToBytes(expected.scriptPubKeyHex).slice(2))) {
    throw new Error(`invalid acquisition partial signature at input ${index}`);
  }
}

function verifyInputSignature(tx: Transaction, plan: CommunityVaultAcquisitionPlanV1, index: number): void {
  const expected = plan.inputs[index]!;
  const witness = tx.getInput(index).finalScriptWitness ?? [];
  if (expected.scriptKind === 'p2wpkh') {
    const signature = witness[0];
    const publicKey = witness[1];
    if (witness.length !== 2 || !signature || signature.length < 2 || !publicKey ||
        signature.at(-1) !== expected.sighashType) {
      throw new Error(`invalid acquisition P2WPKH witness at input ${index}`);
    }
    const keyHash = expected.scriptPubKeyHex.slice(4);
    const scriptCode = hexToBytes(`76a914${keyHash}88ac`);
    const message = tx.preimageWitnessV0(index, scriptCode, expected.sighashType, BigInt(expected.valueSats));
    if (bytesToHex(hash160(publicKey)) !== keyHash ||
        !secp256k1.verify(signature.slice(0, -1), message, publicKey, {
          format: 'der', prehash: false, lowS: true,
        })) {
      throw new Error(`invalid acquisition P2WPKH signature at input ${index}`);
    }
    return;
  }
  const signature = witness[0];
  if (witness.length !== 1 || !signature || (signature.length !== 64 && signature.length !== 65)) {
    throw new Error(`unsupported acquisition Taproot witness at input ${index}`);
  }
  const sighash = signature.length === 64 ? SigHash.DEFAULT : signature[64]!;
  if (sighash !== expected.sighashType) throw new Error(`acquisition Taproot sighash differs at input ${index}`);
  const message = tx.preimageWitnessV1(
    index,
    plan.inputs.map((input) => hexToBytes(input.scriptPubKeyHex)),
    sighash,
    plan.inputs.map((input) => BigInt(input.valueSats)),
  );
  if (!schnorr.verify(signature.slice(0, 64), message, hexToBytes(expected.scriptPubKeyHex).slice(2))) {
    throw new Error(`invalid acquisition Taproot signature at input ${index}`);
  }
}

export function verifyFinalizedCommunityVaultAcquisition(input: {
  policy: CommunityVaultPolicyV1;
  plan: CommunityVaultAcquisitionPlanV1;
  transactionHex: string;
}): FinalizedCommunityVaultAcquisitionV1 {
  assertCommunityVaultAcquisitionPlan(input.policy, input.plan);
  const tx = Transaction.fromRaw(hexToBytes(input.transactionHex));
  if (tx.inputsLength !== input.plan.inputs.length || tx.outputsLength !== input.plan.outputs.length ||
      bytesToHex(tx.unsignedTx) !== input.plan.unsignedTransactionHex) {
    throw new Error('finalized Community Vault acquisition differs from approved plan');
  }
  for (let index = 0; index < input.plan.inputs.length; index += 1) verifyInputSignature(tx, input.plan, index);
  if (tx.weight > MAX_STANDARD_TRANSACTION_WEIGHT) throw new Error('finalized acquisition exceeds standard weight');
  const raw = hexToBytes(input.transactionHex);
  const digest = getCryptoProvider().sha256(getCryptoProvider().sha256(raw));
  const fee = BigInt(input.plan.settlementFeeSats);
  return {
    version: 1,
    transactionHex: input.transactionHex,
    txid: tx.id,
    wtxid: bytesToHex(Uint8Array.from(digest).reverse()),
    weight: tx.weight,
    vsize: tx.vsize,
    feeSats: fee.toString(),
    feeRateSatPerKvB: ((fee * 1_000n + BigInt(tx.vsize) - 1n) / BigInt(tx.vsize)).toString(),
  };
}
