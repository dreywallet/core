/** Atomic, private, whole-position Community Vault transfer profile. */
import type { HDKey } from '@scure/bip32';
import { Address, NETWORK, OutScript, Transaction } from '@scure/btc-signer';

import { scriptDustSats } from '../transactions/fees';
import { verifyBip322Simple } from '../transactions/bip322';
import { getCryptoProvider } from '../vault/crypto-provider';
import { bytesToHex, hexToBytes, utf8ToBytes } from '../vault/encoding';
import {
  assertCommunityVaultBuyerInput,
  communityVaultBuyerSpendInput,
  verifyCommunityVaultBuyerInput,
} from './buyer-funding';
import type { CommunityVaultOwnerInputV1, CommunityVaultPolicyV1 } from './contracts';
import { assertCommunityVaultPolicy, createCommunityVaultPolicy } from './policy';
import {
  approveCommunityVaultSpend,
  combineCommunityVaultPsbts,
  constructCommunityVaultPsbt,
  createCommunityVaultSpendPlan,
  finalizeCommunityVaultPsbt,
  validateCommunityVaultPsbt,
  verifyFinalizedCommunityVaultTransaction,
  type CommunityVaultOwnerApprovalResultV1,
  type CommunityVaultPsbtValidation,
  type FinalizedCommunityVaultTransactionV1,
} from './psbt';
import {
  COMMUNITY_VAULT_POSITION_TRANSFER_MAX_LIFETIME_MS,
  COMMUNITY_VAULT_POSITION_TRANSFER_MAX_PREFLIGHT_AGE_MS,
  communityVaultPositionTransferPlanSchema,
  communityVaultPositionTransferPreflightSchema,
  communityVaultPositionTransferSellerAuthorizationSchema,
  type CommunityVaultPositionTransferBuyerV1,
  type CommunityVaultPositionTransferDraftV1,
  type CommunityVaultPositionTransferPlanV1,
  type CommunityVaultPositionTransferPreflightV1,
  type CommunityVaultPositionTransferSellerAuthorizationV1,
} from './position-transfer-contracts';

const TRANSFER_DOMAIN = 'drey-community-vault-position-transfer-v1';
const SELLER_MESSAGE_PREFIX = 'Drey Community Vault Position Transfer';

function canonical(value: unknown, omitted: ReadonlySet<string> = new Set()): unknown {
  if (Array.isArray(value)) return value.map((item) => canonical(item, omitted));
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value as Record<string, unknown>)
      .filter(([key]) => !omitted.has(key))
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, child]) => [key, canonical(child, omitted)]));
  }
  return value;
}

function domainHash(value: unknown, omitted?: ReadonlySet<string>): string {
  const prefix = utf8ToBytes(TRANSFER_DOMAIN);
  const body = utf8ToBytes(JSON.stringify(canonical(value, omitted)));
  const bytes = new Uint8Array(prefix.length + 1 + body.length);
  bytes.set(prefix);
  bytes[prefix.length] = 0;
  bytes.set(body, prefix.length + 1);
  return bytesToHex(getCryptoProvider().sha256(bytes));
}

function scriptForAddress(address: string): string {
  return bytesToHex(OutScript.encode(Address(NETWORK).decode(address)));
}

function cloneOwner(owner: CommunityVaultOwnerInputV1): CommunityVaultOwnerInputV1 {
  return { ...owner, campaignRoot: { ...owner.campaignRoot }, units: [...owner.units] };
}

function replacementOwner(
  buyer: CommunityVaultPositionTransferBuyerV1,
  seller: CommunityVaultOwnerInputV1,
): CommunityVaultOwnerInputV1 {
  return {
    ownerId: buyer.ownerId,
    capTableOrder: seller.capTableOrder,
    identityCommitmentHex: buyer.identityCommitmentHex,
    payoutAddress: buyer.payoutAddress,
    payoutScriptPubKeyHex: buyer.payoutScriptPubKeyHex,
    campaignRoot: { ...buyer.campaignRoot },
    units: [...seller.units],
  };
}

export function createCommunityVaultPositionTransferPolicy(input: {
  currentPolicy: CommunityVaultPolicyV1;
  sellerOwnerId: string;
  buyer: CommunityVaultPositionTransferBuyerV1;
  currentVaultOutpoint: { txid: string; vout: number };
}): CommunityVaultPolicyV1 {
  assertCommunityVaultPolicy(input.currentPolicy);
  const seller = input.currentPolicy.owners.find((owner) => owner.ownerId === input.sellerOwnerId);
  if (!seller) throw new Error('Community Vault position seller is absent from the cap table');
  if (seller.ownerId === input.currentPolicy.creatorOwnerId) {
    throw new Error('Community Vault v1 does not transfer the creator position');
  }
  if (input.currentPolicy.owners.some((owner) => owner.ownerId === input.buyer.ownerId)) {
    throw new Error('Community Vault position buyer already owns a position');
  }
  if (scriptForAddress(input.buyer.payoutAddress) !== input.buyer.payoutScriptPubKeyHex) {
    throw new Error('Community Vault position buyer payout address and script differ');
  }
  return createCommunityVaultPolicy({
    version: 1,
    policyVersion: 1,
    network: 'mainnet',
    campaignId: input.currentPolicy.campaignId,
    inscriptionId: input.currentPolicy.inscriptionId,
    currentOutpoint: { ...input.currentVaultOutpoint },
    mode: input.currentPolicy.mode,
    eligibility: input.currentPolicy.eligibility,
    creatorOwnerId: input.currentPolicy.creatorOwnerId,
    termsVersion: input.currentPolicy.termsVersion,
    capTableVersion: input.currentPolicy.capTableVersion + 1,
    owners: input.currentPolicy.owners.map((owner) => owner.ownerId === seller.ownerId
      ? replacementOwner(input.buyer, seller) : cloneOwner(owner)),
  });
}

export function communityVaultPositionTransferSellerAuthorization(input: {
  transferId: string;
  currentPolicy: CommunityVaultPolicyV1;
  nextPolicy: CommunityVaultPolicyV1;
  currentVaultOutpoint: { txid: string; vout: number };
  sellerOwnerId: string;
  buyer: CommunityVaultPositionTransferBuyerV1;
  sellerPriceSats: string;
  expiresAtMs: string;
  nonceHex: string;
}): CommunityVaultPositionTransferSellerAuthorizationV1 {
  const seller = input.currentPolicy.owners.find((owner) => owner.ownerId === input.sellerOwnerId);
  if (!seller) throw new Error('Community Vault position seller is absent from the cap table');
  return communityVaultPositionTransferSellerAuthorizationSchema.parse({
    protocol: 'drey-community-vault-position-transfer',
    version: 1,
    network: 'mainnet',
    action: 'authorize-whole-position-transfer',
    transferId: input.transferId,
    campaignId: input.currentPolicy.campaignId,
    currentPolicyId: input.currentPolicy.policyId,
    currentCapTableHash: input.currentPolicy.capTableHash,
    currentCapTableVersion: input.currentPolicy.capTableVersion,
    currentVaultOutpoint: `${input.currentVaultOutpoint.txid}:${input.currentVaultOutpoint.vout}`,
    nextPolicyId: input.nextPolicy.policyId,
    nextCapTableHash: input.nextPolicy.capTableHash,
    nextCapTableVersion: input.nextPolicy.capTableVersion,
    sellerOwnerId: seller.ownerId,
    buyerOwnerId: input.buyer.ownerId,
    buyerIdentityCommitmentHex: input.buyer.identityCommitmentHex,
    buyerCampaignXpub: input.buyer.campaignRoot.campaignXpub,
    buyerPayoutAddress: input.buyer.payoutAddress,
    qualifyingInscriptionNumber: input.buyer.qualifyingInscriptionNumber,
    units: [...seller.units],
    sellerPriceSats: input.sellerPriceSats,
    expiresAtMs: input.expiresAtMs,
    nonceHex: input.nonceHex,
  });
}

export function communityVaultPositionTransferSellerMessage(
  payload: CommunityVaultPositionTransferSellerAuthorizationV1,
): string {
  return `${SELLER_MESSAGE_PREFIX}\n${JSON.stringify(payload)}`;
}

function assertPolicyTransition(
  current: CommunityVaultPolicyV1,
  next: CommunityVaultPolicyV1,
  sellerOwnerId: string,
  buyer: CommunityVaultPositionTransferBuyerV1,
  currentVaultOutpoint: { txid: string; vout: number },
): CommunityVaultOwnerInputV1 {
  const expected = createCommunityVaultPositionTransferPolicy({
    currentPolicy: current,
    sellerOwnerId,
    buyer,
    currentVaultOutpoint,
  });
  if (JSON.stringify(next) !== JSON.stringify(expected)) {
    throw new Error('Community Vault next policy is not the exact whole-position replacement');
  }
  const seller = current.owners.find((owner) => owner.ownerId === sellerOwnerId)!;
  for (const unit of seller.units) {
    if (current.units[unit]!.publicKeyHex === next.units[unit]!.publicKeyHex) {
      throw new Error('Community Vault transferred unit key did not rotate');
    }
  }
  return seller;
}

export function createCommunityVaultPositionTransferPlan(
  draft: CommunityVaultPositionTransferDraftV1,
): CommunityVaultPositionTransferPlanV1 {
  const seller = assertPolicyTransition(
    draft.currentPolicy,
    draft.nextPolicy,
    draft.sellerOwnerId,
    draft.buyer,
    draft.vaultOutpoint,
  );
  const createdAt = BigInt(draft.createdAtMs);
  const expiresAt = BigInt(draft.expiresAtMs);
  if (expiresAt <= createdAt || expiresAt - createdAt > BigInt(COMMUNITY_VAULT_POSITION_TRANSFER_MAX_LIFETIME_MS)) {
    throw new Error('Community Vault private position transfer must expire within 24 hours');
  }
  if (draft.currentPolicy.eligibility === 'omb-holders-only' && draft.buyer.qualifyingInscriptionNumber === null) {
    throw new Error('Community Vault position buyer requires verified holder evidence');
  }
  const expectedAuthorization = communityVaultPositionTransferSellerAuthorization({
    transferId: draft.transferId,
    currentPolicy: draft.currentPolicy,
    nextPolicy: draft.nextPolicy,
    currentVaultOutpoint: draft.vaultOutpoint,
    sellerOwnerId: draft.sellerOwnerId,
    buyer: draft.buyer,
    sellerPriceSats: draft.sellerPriceSats,
    expiresAtMs: draft.expiresAtMs,
    nonceHex: draft.sellerAuthorization.payload.nonceHex,
  });
  if (JSON.stringify(draft.sellerAuthorization.payload) !== JSON.stringify(expectedAuthorization) ||
      !verifyBip322Simple(
        communityVaultPositionTransferSellerMessage(expectedAuthorization),
        seller.payoutAddress,
        'mainnet',
        draft.sellerAuthorization.signature,
      )) {
    throw new Error('Community Vault seller authorization is invalid or differs from the transfer');
  }

  draft.buyerInputs.forEach(assertCommunityVaultBuyerInput);
  if (draft.buyerInputs.some((item) => item.scriptPubKeyHex !== draft.buyer.payoutScriptPubKeyHex)) {
    throw new Error('Community Vault buyer funding does not belong to the verified buyer payout address');
  }
  const outpoints = new Set([`${draft.vaultOutpoint.txid}:${draft.vaultOutpoint.vout}`]);
  for (const item of draft.buyerInputs) {
    const outpoint = `${item.txid}:${item.vout}`;
    if (outpoints.has(outpoint)) throw new Error('Community Vault position transfer input is duplicated');
    outpoints.add(outpoint);
  }

  const vaultValue = BigInt(draft.vaultValueSats);
  const price = BigInt(draft.sellerPriceSats);
  const fee = BigInt(draft.settlementFeeSats);
  if (vaultValue <= 0n || price <= 0n || fee <= 0n) {
    throw new Error('Community Vault position transfer values must be positive');
  }
  if (price < scriptDustSats(seller.payoutScriptPubKeyHex)) {
    throw new Error('Community Vault position seller payment is dust');
  }
  const buyerInputTotal = draft.buyerInputs.reduce((sum, input) => sum + BigInt(input.valueSats), 0n);
  const change = draft.buyerChange ? BigInt(draft.buyerChange.valueSats) : 0n;
  if (draft.buyerChange && (draft.buyerChange.scriptPubKeyHex !== draft.buyer.payoutScriptPubKeyHex ||
      change < scriptDustSats(draft.buyerChange.scriptPubKeyHex))) {
    throw new Error('Community Vault buyer change differs from the verified buyer or is dust');
  }
  if (buyerInputTotal - change !== price + fee) {
    throw new Error('Community Vault buyer funding must exactly cover seller payment and fee');
  }
  const outputs = [
    { valueSats: vaultValue.toString(), scriptPubKeyHex: draft.nextPolicy.scriptPubKeyHex },
    { valueSats: price.toString(), scriptPubKeyHex: seller.payoutScriptPubKeyHex },
    ...(draft.buyerChange ? [{
      valueSats: draft.buyerChange.valueSats,
      scriptPubKeyHex: draft.buyerChange.scriptPubKeyHex,
    }] : []),
  ];
  const spendPlan = createCommunityVaultSpendPlan({
    version: 1,
    policyVersion: 1,
    network: 'mainnet',
    policyId: draft.currentPolicy.policyId,
    capTableHash: draft.currentPolicy.capTableHash,
    capTableVersion: draft.currentPolicy.capTableVersion,
    planId: draft.transferId,
    kind: 'rotation',
    createdAtMs: draft.createdAtMs,
    expiresAtMs: draft.expiresAtMs,
    inputs: [{
      txid: draft.vaultOutpoint.txid,
      vout: draft.vaultOutpoint.vout,
      valueSats: vaultValue.toString(),
      scriptPubKeyHex: draft.currentPolicy.scriptPubKeyHex,
      sequence: 0xffff_fffd,
    }, ...draft.buyerInputs.map(communityVaultBuyerSpendInput)],
    vaultInputIndex: 0,
    outputs,
    feeSats: fee.toString(),
    ordinalRoute: {
      inscriptionId: draft.currentPolicy.inscriptionId,
      inputIndex: 0,
      inputOffsetSats: draft.inscriptionInputOffsetSats,
      outputIndex: 0,
      outputOffsetSats: draft.inscriptionInputOffsetSats,
      postageSats: draft.postageSats,
    },
  });
  const withoutDigest: Omit<CommunityVaultPositionTransferPlanV1, 'transferDigest'> = {
    version: 1,
    profileVersion: 1,
    policyVersion: 1,
    network: 'mainnet',
    transferId: draft.transferId,
    currentPolicyId: draft.currentPolicy.policyId,
    currentCapTableHash: draft.currentPolicy.capTableHash,
    currentCapTableVersion: draft.currentPolicy.capTableVersion,
    nextPolicy: draft.nextPolicy,
    sellerOwnerId: draft.sellerOwnerId,
    buyer: draft.buyer,
    transferredUnits: [...seller.units],
    sellerPriceSats: price.toString(),
    settlementFeeSats: fee.toString(),
    buyerTotalSats: (price + fee).toString(),
    buyerInputs: draft.buyerInputs,
    buyerChange: draft.buyerChange ? { ...draft.buyerChange, outputIndex: 2 } : null,
    sellerAuthorization: draft.sellerAuthorization,
    spendPlan,
  };
  const plan = communityVaultPositionTransferPlanSchema.parse({
    ...withoutDigest,
    transferDigest: domainHash(withoutDigest),
  });
  assertCommunityVaultPositionTransferPlan(draft.currentPolicy, plan);
  return plan;
}

export function assertCommunityVaultPositionTransferPlan(
  currentPolicy: CommunityVaultPolicyV1,
  raw: CommunityVaultPositionTransferPlanV1,
): void {
  assertCommunityVaultPolicy(currentPolicy);
  const plan = communityVaultPositionTransferPlanSchema.parse(raw);
  const currentOutpoint = plan.spendPlan.inputs[0];
  if (!currentOutpoint) throw new Error('Community Vault position transfer vault input is missing');
  const seller = assertPolicyTransition(currentPolicy, plan.nextPolicy, plan.sellerOwnerId, plan.buyer, {
    txid: currentOutpoint.txid,
    vout: currentOutpoint.vout,
  });
  if (plan.currentPolicyId !== currentPolicy.policyId ||
      plan.currentCapTableHash !== currentPolicy.capTableHash ||
      plan.currentCapTableVersion !== currentPolicy.capTableVersion ||
      plan.spendPlan.policyId !== currentPolicy.policyId ||
      plan.spendPlan.kind !== 'rotation' || plan.spendPlan.planId !== plan.transferId ||
      plan.spendPlan.vaultInputIndex !== 0 || plan.spendPlan.ordinalRoute.outputIndex !== 0 ||
      plan.spendPlan.outputs[0]?.scriptPubKeyHex !== plan.nextPolicy.scriptPubKeyHex ||
      plan.spendPlan.outputs[0]?.valueSats !== currentOutpoint.valueSats ||
      plan.spendPlan.outputs[1]?.scriptPubKeyHex !== seller.payoutScriptPubKeyHex ||
      plan.spendPlan.outputs[1]?.valueSats !== plan.sellerPriceSats) {
    throw new Error('Community Vault position transfer policy, route, or seller payout differs');
  }
  if (JSON.stringify(plan.transferredUnits) !== JSON.stringify(seller.units) ||
      plan.buyerTotalSats !== (BigInt(plan.sellerPriceSats) + BigInt(plan.settlementFeeSats)).toString() ||
      plan.settlementFeeSats !== plan.spendPlan.feeSats ||
      plan.buyerInputs.length !== plan.spendPlan.inputs.length - 1 ||
      plan.spendPlan.outputs.length !== 2 + (plan.buyerChange ? 1 : 0)) {
    throw new Error('Community Vault position transfer units or economics differ');
  }
  plan.buyerInputs.forEach((buyerInput, offset) => {
    assertCommunityVaultBuyerInput(buyerInput);
    if (JSON.stringify(plan.spendPlan.inputs[offset + 1]) !==
        JSON.stringify(communityVaultBuyerSpendInput(buyerInput))) {
      throw new Error('Community Vault position transfer buyer input differs');
    }
  });
  if (plan.buyerChange) {
    const output = plan.spendPlan.outputs[plan.buyerChange.outputIndex];
    if (!output || output.valueSats !== plan.buyerChange.valueSats ||
        output.scriptPubKeyHex !== plan.buyerChange.scriptPubKeyHex) {
      throw new Error('Community Vault position transfer buyer change differs');
    }
  }
  const expectedAuthorization = communityVaultPositionTransferSellerAuthorization({
    transferId: plan.transferId,
    currentPolicy,
    nextPolicy: plan.nextPolicy,
    currentVaultOutpoint: { txid: currentOutpoint.txid, vout: currentOutpoint.vout },
    sellerOwnerId: plan.sellerOwnerId,
    buyer: plan.buyer,
    sellerPriceSats: plan.sellerPriceSats,
    expiresAtMs: plan.spendPlan.expiresAtMs,
    nonceHex: plan.sellerAuthorization.payload.nonceHex,
  });
  if (JSON.stringify(plan.sellerAuthorization.payload) !== JSON.stringify(expectedAuthorization) ||
      !verifyBip322Simple(
        communityVaultPositionTransferSellerMessage(expectedAuthorization),
        seller.payoutAddress,
        'mainnet',
        plan.sellerAuthorization.signature,
      )) {
    throw new Error('Community Vault seller authorization differs or is invalid');
  }
  if (BigInt(plan.spendPlan.expiresAtMs) - BigInt(plan.spendPlan.createdAtMs) >
      BigInt(COMMUNITY_VAULT_POSITION_TRANSFER_MAX_LIFETIME_MS) ||
      domainHash(plan, new Set(['transferDigest'])) !== plan.transferDigest) {
    throw new Error('Community Vault position transfer expiry or digest differs');
  }
}

export function assertCommunityVaultPositionTransferPreflight(input: {
  currentPolicy: CommunityVaultPolicyV1;
  plan: CommunityVaultPositionTransferPlanV1;
  preflight: CommunityVaultPositionTransferPreflightV1;
  nowMs: string;
}): void {
  assertCommunityVaultPositionTransferPlan(input.currentPolicy, input.plan);
  const evidence = communityVaultPositionTransferPreflightSchema.parse(input.preflight);
  const now = BigInt(input.nowMs);
  if (now < BigInt(evidence.verifiedAtMs) ||
      now - BigInt(evidence.verifiedAtMs) > BigInt(COMMUNITY_VAULT_POSITION_TRANSFER_MAX_PREFLIGHT_AGE_MS) ||
      now >= BigInt(input.plan.spendPlan.expiresAtMs) ||
      evidence.inputs.length !== input.plan.spendPlan.inputs.length) {
    throw new Error('Community Vault position transfer preflight is stale, expired, or incomplete');
  }
  input.plan.spendPlan.inputs.forEach((planned, index) => {
    const observed = evidence.inputs[index]!;
    if (observed.inputIndex !== index || observed.txid !== planned.txid || observed.vout !== planned.vout ||
        observed.valueSats !== planned.valueSats || observed.scriptPubKeyHex !== planned.scriptPubKeyHex ||
        !observed.unspent || observed.runeIds.length !== 0 ||
        JSON.stringify(observed.inscriptionIds) !==
          JSON.stringify(index === 0 ? [input.currentPolicy.inscriptionId] : [])) {
      throw new Error(`Community Vault position transfer preflight input ${index} differs or contains an asset`);
    }
  });
}

export function constructCommunityVaultPositionTransferPsbt(
  currentPolicy: CommunityVaultPolicyV1,
  plan: CommunityVaultPositionTransferPlanV1,
): string {
  assertCommunityVaultPositionTransferPlan(currentPolicy, plan);
  const tx = Transaction.fromPSBT(hexToBytes(constructCommunityVaultPsbt(currentPolicy, plan.spendPlan)), {
    PSBTVersion: 0,
    lowR: true,
  });
  plan.buyerInputs.forEach((input, offset) => {
    tx.updateInput(offset + 1, { sighashType: input.sighashType }, true);
  });
  return bytesToHex(tx.toPSBT(0));
}

export function validateCommunityVaultPositionTransferPsbt(input: {
  currentPolicy: CommunityVaultPolicyV1;
  plan: CommunityVaultPositionTransferPlanV1;
  psbtHex: string;
  requireBuyerFunding?: boolean;
}): CommunityVaultPsbtValidation {
  assertCommunityVaultPositionTransferPlan(input.currentPolicy, input.plan);
  const validation = validateCommunityVaultPsbt(input.currentPolicy, input.plan.spendPlan, input.psbtHex);
  if (input.requireBuyerFunding ?? true) {
    const tx = Transaction.fromPSBT(hexToBytes(input.psbtHex), { PSBTVersion: 0, lowR: true });
    input.plan.buyerInputs.forEach((buyerInput, offset) => verifyCommunityVaultBuyerInput({
      tx,
      buyerInput,
      inputIndex: offset + 1,
      spendInputs: input.plan.spendPlan.inputs,
    }));
  }
  return validation;
}

export function approveCommunityVaultPositionTransfer(input: {
  currentPolicy: CommunityVaultPolicyV1;
  plan: CommunityVaultPositionTransferPlanV1;
  psbtHex: string;
  ownerId: string;
  signerRoot: HDKey;
  nowMs: string;
  random: (length: number) => Uint8Array;
}): CommunityVaultOwnerApprovalResultV1 {
  validateCommunityVaultPositionTransferPsbt({ ...input, requireBuyerFunding: true });
  const approved = approveCommunityVaultSpend({
    policy: input.currentPolicy,
    plan: input.plan.spendPlan,
    psbtHex: input.psbtHex,
    ownerId: input.ownerId,
    signerRoot: input.signerRoot,
    nowMs: input.nowMs,
    random: input.random,
  });
  validateCommunityVaultPositionTransferPsbt({
    currentPolicy: input.currentPolicy,
    plan: input.plan,
    psbtHex: approved.psbtHex,
  });
  return approved;
}

export function combineCommunityVaultPositionTransferPsbts(input: {
  currentPolicy: CommunityVaultPolicyV1;
  plan: CommunityVaultPositionTransferPlanV1;
  psbtHexes: readonly string[];
}): CommunityVaultPsbtValidation {
  const seen = new Set<number>();
  for (const psbtHex of input.psbtHexes) {
    const validation = validateCommunityVaultPositionTransferPsbt({ ...input, psbtHex });
    for (const unit of validation.signedUnits) {
      if (seen.has(unit)) throw new Error(`duplicate Community Vault position signature for unit ${unit}`);
      seen.add(unit);
    }
  }
  const combined = combineCommunityVaultPsbts(input.currentPolicy, input.plan.spendPlan, input.psbtHexes);
  return validateCommunityVaultPositionTransferPsbt({ ...input, psbtHex: combined.psbtHex });
}

export function verifyFinalizedCommunityVaultPositionTransfer(input: {
  currentPolicy: CommunityVaultPolicyV1;
  plan: CommunityVaultPositionTransferPlanV1;
  transactionHex: string;
}): FinalizedCommunityVaultTransactionV1 {
  assertCommunityVaultPositionTransferPlan(input.currentPolicy, input.plan);
  const finalized = verifyFinalizedCommunityVaultTransaction({
    policy: input.currentPolicy,
    plan: input.plan.spendPlan,
    transactionHex: input.transactionHex,
  });
  const tx = Transaction.fromRaw(hexToBytes(input.transactionHex));
  input.plan.buyerInputs.forEach((buyerInput, offset) => verifyCommunityVaultBuyerInput({
    tx,
    buyerInput,
    inputIndex: offset + 1,
    spendInputs: input.plan.spendPlan.inputs,
  }));
  return finalized;
}

export function finalizeCommunityVaultPositionTransferPsbt(
  currentPolicy: CommunityVaultPolicyV1,
  plan: CommunityVaultPositionTransferPlanV1,
  psbtHex: string,
): FinalizedCommunityVaultTransactionV1 {
  validateCommunityVaultPositionTransferPsbt({ currentPolicy, plan, psbtHex });
  const finalized = finalizeCommunityVaultPsbt(currentPolicy, plan.spendPlan, psbtHex);
  return verifyFinalizedCommunityVaultPositionTransfer({
    currentPolicy,
    plan,
    transactionHex: finalized.transactionHex,
  });
}
