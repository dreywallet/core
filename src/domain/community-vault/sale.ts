/** Exact-funded, direct-payout Community Vault v1 sale profile. */
import { schnorr, secp256k1 } from '@noble/curves/secp256k1';
import type { HDKey } from '@scure/bip32';
import { Address, NETWORK, OutScript, SigHash, Transaction } from '@scure/btc-signer';
import { hash160 } from '@scure/btc-signer/utils';
import { scriptDustSats } from '../transactions/fees';
import { getCryptoProvider } from '../vault/crypto-provider';
import { bytesToHex, hexToBytes, utf8ToBytes } from '../vault/encoding';
import type { CommunityVaultPolicyV1 } from './contracts';
import { assertCommunityVaultPolicy } from './policy';
import {
  approveCommunityVaultSpend,
  assertCommunityVaultSpendPlan,
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
  COMMUNITY_VAULT_SALE_MAX_PREFLIGHT_AGE_MS,
  communityVaultSalePlanSchema,
  communityVaultSalePreflightSchema,
  type CommunityVaultSaleBuyerInputV1,
  type CommunityVaultSaleDraftV1,
  type CommunityVaultSaleOwnerPayoutV1,
  type CommunityVaultSalePlanV1,
  type CommunityVaultSalePreflightV1,
} from './sale-contracts';

const PAYOUT_DOMAIN = 'drey-community-vault-sale-payout-snapshot-v1';
const OFFER_DOMAIN = 'drey-community-vault-sale-offer-v1';

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

function domainHash(domain: string, value: unknown, omitted?: ReadonlySet<string>): string {
  const prefix = utf8ToBytes(domain);
  const body = utf8ToBytes(JSON.stringify(canonical(value, omitted)));
  const input = new Uint8Array(prefix.length + 1 + body.length);
  input.set(prefix);
  input[prefix.length] = 0;
  input.set(body, prefix.length + 1);
  return bytesToHex(getCryptoProvider().sha256(input));
}

function sum(values: readonly string[]): bigint {
  return values.reduce((total, value) => total + BigInt(value), 0n);
}

function scriptForAddress(address: string): string {
  return bytesToHex(OutScript.encode(Address(NETWORK).decode(address)));
}

/** Aggregate units first, then use fractional remainder and cap-table order. */
export function communityVaultSalePayouts(
  policy: CommunityVaultPolicyV1,
  grossOfferSats: string,
): Omit<CommunityVaultSaleOwnerPayoutV1, 'outputIndex'>[] {
  assertCommunityVaultPolicy(policy);
  const gross = BigInt(grossOfferSats);
  if (gross <= 0n || gross > 0xffff_ffff_ffff_ffffn) throw new RangeError('invalid Community Vault sale offer');
  const ranked = policy.owners.map((owner) => {
    const numerator = gross * BigInt(owner.units.length);
    return { owner, value: numerator / 100n, remainder: numerator % 100n };
  });
  let remaining = gross - ranked.reduce((total, item) => total + item.value, 0n);
  const remainderOrder = [...ranked].sort((left, right) => {
    if (left.remainder !== right.remainder) return left.remainder > right.remainder ? -1 : 1;
    return left.owner.capTableOrder - right.owner.capTableOrder;
  });
  for (let index = 0; index < remainderOrder.length && remaining > 0n; index += 1) {
    remainderOrder[index]!.value += 1n;
    remaining -= 1n;
  }
  if (remaining !== 0n) throw new Error('Community Vault sale payout remainder could not be allocated');
  return ranked
    .sort((left, right) => left.owner.capTableOrder - right.owner.capTableOrder)
    .map(({ owner, value }) => ({
      ownerId: owner.ownerId,
      capTableOrder: owner.capTableOrder,
      units: owner.units.length,
      payoutAddress: owner.payoutAddress,
      payoutScriptPubKeyHex: owner.payoutScriptPubKeyHex,
      valueSats: value.toString(),
    }));
}

function payoutSnapshotHash(policy: CommunityVaultPolicyV1): string {
  return domainHash(PAYOUT_DOMAIN, policy.owners
    .map((owner) => ({
      ownerId: owner.ownerId,
      capTableOrder: owner.capTableOrder,
      units: [...owner.units],
      payoutAddress: owner.payoutAddress,
      payoutScriptPubKeyHex: owner.payoutScriptPubKeyHex,
    }))
    .sort((left, right) => left.capTableOrder - right.capTableOrder));
}

function assertBuyerInput(input: CommunityVaultSaleBuyerInputV1): void {
  const kind = /^0014[0-9a-f]{40}$/u.test(input.scriptPubKeyHex) ? 'p2wpkh'
    : /^5120[0-9a-f]{64}$/u.test(input.scriptPubKeyHex) ? 'p2tr' : null;
  if (kind !== input.scriptKind || BigInt(input.valueSats) <= 0n ||
      (kind === 'p2wpkh' ? input.sighashType !== SigHash.ALL : input.sighashType !== SigHash.DEFAULT)) {
    throw new Error('Community Vault buyer input is not clean whole-transaction funding');
  }
}

function buyerSpendInput(input: CommunityVaultSaleBuyerInputV1) {
  return {
    txid: input.txid,
    vout: input.vout,
    valueSats: input.valueSats,
    scriptPubKeyHex: input.scriptPubKeyHex,
    sequence: input.sequence,
  };
}

export function createCommunityVaultSalePlan(draft: CommunityVaultSaleDraftV1): CommunityVaultSalePlanV1 {
  assertCommunityVaultPolicy(draft.policy);
  if (scriptForAddress(draft.buyerDestinationAddress) !== draft.buyerDestinationScriptPubKeyHex) {
    throw new Error('Community Vault buyer destination address and script differ');
  }
  draft.buyerInputs.forEach(assertBuyerInput);
  const seen = new Set<string>();
  for (const input of draft.buyerInputs) {
    const outpoint = `${input.txid}:${input.vout}`;
    if (seen.has(outpoint) || outpoint === `${draft.policy.currentOutpoint.txid}:${draft.policy.currentOutpoint.vout}`) {
      throw new Error('Community Vault sale buyer input is duplicated');
    }
    seen.add(outpoint);
  }

  const gross = BigInt(draft.grossOfferSats);
  const fee = BigInt(draft.settlementFeeSats);
  if (gross <= 0n || fee <= 0n) throw new Error('Community Vault sale offer and fee must be positive');
  const payoutRows = communityVaultSalePayouts(draft.policy, draft.grossOfferSats);
  const ownerPayouts: CommunityVaultSaleOwnerPayoutV1[] = payoutRows.map((payout, index) => ({
    ...payout,
    outputIndex: index + 1,
  }));
  for (const payout of ownerPayouts) {
    if (BigInt(payout.valueSats) < scriptDustSats(payout.payoutScriptPubKeyHex)) {
      throw new Error(`Community Vault sale payout for ${payout.ownerId} is dust`);
    }
  }
  if (draft.buyerChange && BigInt(draft.buyerChange.valueSats) < scriptDustSats(draft.buyerChange.scriptPubKeyHex)) {
    throw new Error('Community Vault sale buyer change is dust');
  }

  const buyerInputTotal = sum(draft.buyerInputs.map((input) => input.valueSats));
  const buyerChangeValue = draft.buyerChange ? BigInt(draft.buyerChange.valueSats) : 0n;
  const buyerTotal = gross + fee;
  if (buyerInputTotal - buyerChangeValue !== buyerTotal) {
    throw new Error('Community Vault sale buyer funding does not equal offer plus network fee');
  }

  const outputs = [
    { valueSats: draft.vaultValueSats, scriptPubKeyHex: draft.buyerDestinationScriptPubKeyHex },
    ...ownerPayouts.map((payout) => ({
      valueSats: payout.valueSats,
      scriptPubKeyHex: payout.payoutScriptPubKeyHex,
    })),
    ...(draft.buyerChange ? [{
      valueSats: draft.buyerChange.valueSats,
      scriptPubKeyHex: draft.buyerChange.scriptPubKeyHex,
    }] : []),
  ];
  const inputs = [{
    txid: draft.policy.currentOutpoint.txid,
    vout: draft.policy.currentOutpoint.vout,
    valueSats: draft.vaultValueSats,
    scriptPubKeyHex: draft.policy.scriptPubKeyHex,
    sequence: 0xffff_fffd,
  }, ...draft.buyerInputs.map(buyerSpendInput)];
  const spendPlan = createCommunityVaultSpendPlan({
    version: 1,
    policyVersion: 1,
    network: 'mainnet',
    policyId: draft.policy.policyId,
    capTableHash: draft.policy.capTableHash,
    capTableVersion: draft.policy.capTableVersion,
    planId: `sale-${draft.offerId}`,
    kind: 'sale',
    createdAtMs: draft.createdAtMs,
    expiresAtMs: draft.expiresAtMs,
    inputs,
    vaultInputIndex: 0,
    outputs,
    feeSats: draft.settlementFeeSats,
    ordinalRoute: {
      inscriptionId: draft.policy.inscriptionId,
      inputIndex: 0,
      inputOffsetSats: draft.inscriptionInputOffsetSats,
      outputIndex: 0,
      outputOffsetSats: draft.inscriptionInputOffsetSats,
      postageSats: draft.postageSats,
    },
  });
  const changeOutputIndex = draft.buyerChange ? outputs.length - 1 : null;
  const withoutDigest: Omit<CommunityVaultSalePlanV1, 'offerDigest'> = {
    version: 1,
    profileVersion: 1,
    policyVersion: 1,
    network: 'mainnet',
    campaignId: draft.policy.campaignId,
    policyId: draft.policy.policyId,
    capTableHash: draft.policy.capTableHash,
    capTableVersion: draft.policy.capTableVersion,
    inscriptionId: draft.policy.inscriptionId,
    offerId: draft.offerId,
    buyerId: draft.buyerId,
    nonceHex: draft.nonceHex,
    createdAtMs: draft.createdAtMs,
    expiresAtMs: draft.expiresAtMs,
    grossOfferSats: gross.toString(),
    buyerPaysFee: true,
    settlementFeeSats: fee.toString(),
    buyerTotalSats: buyerTotal.toString(),
    buyerDestinationAddress: draft.buyerDestinationAddress,
    buyerDestinationScriptPubKeyHex: draft.buyerDestinationScriptPubKeyHex,
    buyerInputs: draft.buyerInputs,
    buyerChange: draft.buyerChange && changeOutputIndex !== null ? {
      ...draft.buyerChange,
      outputIndex: changeOutputIndex,
    } : null,
    ownerPayouts,
    payoutSnapshotHash: payoutSnapshotHash(draft.policy),
    spendPlan,
  };
  const plan = communityVaultSalePlanSchema.parse({
    ...withoutDigest,
    offerDigest: domainHash(OFFER_DOMAIN, withoutDigest),
  });
  assertCommunityVaultSalePlan(draft.policy, plan);
  return plan;
}

export function assertCommunityVaultSalePlan(policy: CommunityVaultPolicyV1, raw: CommunityVaultSalePlanV1): void {
  assertCommunityVaultPolicy(policy);
  const plan = communityVaultSalePlanSchema.parse(raw);
  assertCommunityVaultSpendPlan(plan.spendPlan);
  if (plan.policyId !== policy.policyId || plan.capTableHash !== policy.capTableHash ||
      plan.capTableVersion !== policy.capTableVersion || plan.campaignId !== policy.campaignId ||
      plan.inscriptionId !== policy.inscriptionId || plan.spendPlan.kind !== 'sale' ||
      plan.spendPlan.planId !== `sale-${plan.offerId}` || plan.spendPlan.policyId !== plan.policyId ||
      plan.spendPlan.capTableHash !== plan.capTableHash ||
      plan.spendPlan.capTableVersion !== plan.capTableVersion) {
    throw new Error('Community Vault sale policy or offer binding mismatch');
  }
  if (BigInt(plan.createdAtMs) >= BigInt(plan.expiresAtMs) ||
      plan.createdAtMs !== plan.spendPlan.createdAtMs || plan.expiresAtMs !== plan.spendPlan.expiresAtMs) {
    throw new Error('Community Vault sale expiry differs from spend plan');
  }
  if (plan.buyerTotalSats !== (BigInt(plan.grossOfferSats) + BigInt(plan.settlementFeeSats)).toString() ||
      plan.settlementFeeSats !== plan.spendPlan.feeSats) {
    throw new Error('Community Vault sale buyer total or fee is inconsistent');
  }
  if (scriptForAddress(plan.buyerDestinationAddress) !== plan.buyerDestinationScriptPubKeyHex) {
    throw new Error('Community Vault sale buyer destination differs');
  }
  const expectedPayouts = communityVaultSalePayouts(policy, plan.grossOfferSats)
    .map((payout, index) => ({ ...payout, outputIndex: index + 1 }));
  if (JSON.stringify(expectedPayouts) !== JSON.stringify(plan.ownerPayouts) ||
      sum(plan.ownerPayouts.map((payout) => payout.valueSats)) !== BigInt(plan.grossOfferSats) ||
      plan.payoutSnapshotHash !== payoutSnapshotHash(policy)) {
    throw new Error('Community Vault sale direct payout vector differs from frozen cap table');
  }
  plan.ownerPayouts.forEach((payout) => {
    if (BigInt(payout.valueSats) < scriptDustSats(payout.payoutScriptPubKeyHex)) {
      throw new Error(`Community Vault sale payout for ${payout.ownerId} is dust`);
    }
    const output = plan.spendPlan.outputs[payout.outputIndex];
    if (!output || output.valueSats !== payout.valueSats || output.scriptPubKeyHex !== payout.payoutScriptPubKeyHex) {
      throw new Error('Community Vault sale payout output differs from exact vector');
    }
  });
  const assetOutput = plan.spendPlan.outputs[0];
  const vaultInput = plan.spendPlan.inputs[0];
  if (!assetOutput || !vaultInput || vaultInput.txid !== policy.currentOutpoint.txid ||
      vaultInput.vout !== policy.currentOutpoint.vout || vaultInput.scriptPubKeyHex !== policy.scriptPubKeyHex ||
      assetOutput.valueSats !== vaultInput.valueSats ||
      assetOutput.scriptPubKeyHex !== plan.buyerDestinationScriptPubKeyHex ||
      plan.spendPlan.vaultInputIndex !== 0 || plan.spendPlan.ordinalRoute.inputIndex !== 0 ||
      plan.spendPlan.ordinalRoute.outputIndex !== 0) {
    throw new Error('Community Vault sale asset input or buyer output differs');
  }
  if (plan.buyerInputs.length !== plan.spendPlan.inputs.length - 1) {
    throw new Error('Community Vault sale buyer input count differs');
  }
  plan.buyerInputs.forEach((input, offset) => {
    assertBuyerInput(input);
    const spendInput = plan.spendPlan.inputs[offset + 1];
    if (JSON.stringify(spendInput) !== JSON.stringify(buyerSpendInput(input))) {
      throw new Error('Community Vault sale buyer input differs from spend plan');
    }
  });
  const changeIndex = 1 + plan.ownerPayouts.length;
  if (plan.buyerChange) {
    const output = plan.spendPlan.outputs[changeIndex];
    if (plan.buyerChange.outputIndex !== changeIndex || !output || output.valueSats !== plan.buyerChange.valueSats ||
        output.scriptPubKeyHex !== plan.buyerChange.scriptPubKeyHex ||
        BigInt(plan.buyerChange.valueSats) < scriptDustSats(plan.buyerChange.scriptPubKeyHex)) {
      throw new Error('Community Vault sale buyer change differs or is dust');
    }
  }
  if (plan.spendPlan.outputs.length !== changeIndex + (plan.buyerChange ? 1 : 0)) {
    throw new Error('Community Vault sale contains an unexplained output');
  }
  const buyerInputTotal = sum(plan.buyerInputs.map((input) => input.valueSats));
  const change = plan.buyerChange ? BigInt(plan.buyerChange.valueSats) : 0n;
  if (buyerInputTotal - change !== BigInt(plan.buyerTotalSats)) {
    throw new Error('Community Vault buyer funding does not cover offer plus fee exactly');
  }
  if (domainHash(OFFER_DOMAIN, plan, new Set(['offerDigest'])) !== plan.offerDigest) {
    throw new Error('Community Vault sale offer digest mismatch');
  }
}

export function assertCommunityVaultSalePreflight(input: {
  policy: CommunityVaultPolicyV1;
  plan: CommunityVaultSalePlanV1;
  preflight: CommunityVaultSalePreflightV1;
  nowMs: string;
  maximumAgeMs?: number;
}): void {
  assertCommunityVaultSalePlan(input.policy, input.plan);
  const evidence = communityVaultSalePreflightSchema.parse(input.preflight);
  const now = BigInt(input.nowMs);
  const maxAge = BigInt(input.maximumAgeMs ?? COMMUNITY_VAULT_SALE_MAX_PREFLIGHT_AGE_MS);
  if (now < BigInt(evidence.verifiedAtMs) || now - BigInt(evidence.verifiedAtMs) > maxAge ||
      now > BigInt(input.plan.expiresAtMs) || evidence.inputs.length !== input.plan.spendPlan.inputs.length) {
    throw new Error('Community Vault sale preflight is stale, expired, or incomplete');
  }
  input.plan.spendPlan.inputs.forEach((planned, index) => {
    const observed = evidence.inputs[index]!;
    if (observed.inputIndex !== index || observed.txid !== planned.txid || observed.vout !== planned.vout ||
        observed.valueSats !== planned.valueSats || observed.scriptPubKeyHex !== planned.scriptPubKeyHex ||
        !observed.unspent || observed.runeIds.length !== 0 ||
        JSON.stringify(observed.inscriptionIds) !== JSON.stringify(index === 0 ? [input.plan.inscriptionId] : [])) {
      throw new Error(`Community Vault sale preflight input ${index} differs or contains another asset`);
    }
  });
}

export function constructCommunityVaultSalePsbt(
  policy: CommunityVaultPolicyV1,
  plan: CommunityVaultSalePlanV1,
): string {
  assertCommunityVaultSalePlan(policy, plan);
  const tx = Transaction.fromPSBT(hexToBytes(constructCommunityVaultPsbt(policy, plan.spendPlan)), {
    PSBTVersion: 0,
    lowR: true,
  });
  plan.buyerInputs.forEach((buyerInput, offset) => {
    tx.updateInput(offset + 1, { sighashType: buyerInput.sighashType }, true);
  });
  return bytesToHex(tx.toPSBT(0));
}

function verifyBuyerInput(tx: Transaction, plan: CommunityVaultSalePlanV1, offset: number): void {
  const index = offset + 1;
  const expected = plan.buyerInputs[offset]!;
  const witness = tx.getInput(index).finalScriptWitness ?? [];
  if (expected.scriptKind === 'p2wpkh') {
    const signature = witness[0];
    const publicKey = witness[1];
    const keyHash = expected.scriptPubKeyHex.slice(4);
    if (witness.length !== 2 || !signature || signature.length < 2 || !publicKey ||
        signature.at(-1) !== expected.sighashType || bytesToHex(hash160(publicKey)) !== keyHash) {
      throw new Error(`Community Vault buyer input ${index} is not exactly funded`);
    }
    const message = tx.preimageWitnessV0(
      index, hexToBytes(`76a914${keyHash}88ac`), expected.sighashType, BigInt(expected.valueSats),
    );
    if (!secp256k1.verify(signature.slice(0, -1), message, publicKey, {
      format: 'der', prehash: false, lowS: true,
    })) throw new Error(`Community Vault buyer input ${index} signature is invalid`);
    return;
  }
  const signature = witness[0];
  if (witness.length !== 1 || !signature || (signature.length !== 64 && signature.length !== 65)) {
    throw new Error(`Community Vault buyer input ${index} is not exactly funded`);
  }
  const sighash = signature.length === 64 ? SigHash.DEFAULT : signature[64]!;
  if (sighash !== expected.sighashType) throw new Error(`Community Vault buyer input ${index} sighash differs`);
  const message = tx.preimageWitnessV1(
    index,
    plan.spendPlan.inputs.map((item) => hexToBytes(item.scriptPubKeyHex)),
    sighash,
    plan.spendPlan.inputs.map((item) => BigInt(item.valueSats)),
  );
  if (!schnorr.verify(signature.slice(0, 64), message, hexToBytes(expected.scriptPubKeyHex).slice(2))) {
    throw new Error(`Community Vault buyer input ${index} signature is invalid`);
  }
}

export function validateCommunityVaultSalePsbt(
  policy: CommunityVaultPolicyV1,
  plan: CommunityVaultSalePlanV1,
  psbtHex: string,
): CommunityVaultPsbtValidation {
  assertCommunityVaultSalePlan(policy, plan);
  const validation = validateCommunityVaultPsbt(policy, plan.spendPlan, psbtHex);
  const tx = Transaction.fromPSBT(hexToBytes(psbtHex), { PSBTVersion: 0, lowR: true });
  plan.buyerInputs.forEach((_input, offset) => verifyBuyerInput(tx, plan, offset));
  return validation;
}

export function approveCommunityVaultSale(input: {
  policy: CommunityVaultPolicyV1;
  plan: CommunityVaultSalePlanV1;
  psbtHex: string;
  ownerId: string;
  signerRoot: HDKey;
  nowMs: string;
  random: (length: number) => Uint8Array;
}): CommunityVaultOwnerApprovalResultV1 {
  validateCommunityVaultSalePsbt(input.policy, input.plan, input.psbtHex);
  const approved = approveCommunityVaultSpend({
    policy: input.policy,
    plan: input.plan.spendPlan,
    psbtHex: input.psbtHex,
    ownerId: input.ownerId,
    signerRoot: input.signerRoot,
    nowMs: input.nowMs,
    random: input.random,
  });
  validateCommunityVaultSalePsbt(input.policy, input.plan, approved.psbtHex);
  return approved;
}

export function verifyFinalizedCommunityVaultSale(input: {
  policy: CommunityVaultPolicyV1;
  plan: CommunityVaultSalePlanV1;
  transactionHex: string;
}): FinalizedCommunityVaultTransactionV1 {
  assertCommunityVaultSalePlan(input.policy, input.plan);
  const finalized = verifyFinalizedCommunityVaultTransaction({
    policy: input.policy,
    plan: input.plan.spendPlan,
    transactionHex: input.transactionHex,
  });
  const tx = Transaction.fromRaw(hexToBytes(input.transactionHex));
  input.plan.buyerInputs.forEach((_buyerInput, offset) => verifyBuyerInput(tx, input.plan, offset));
  return finalized;
}

export function finalizeCommunityVaultSalePsbt(
  policy: CommunityVaultPolicyV1,
  plan: CommunityVaultSalePlanV1,
  psbtHex: string,
): FinalizedCommunityVaultTransactionV1 {
  validateCommunityVaultSalePsbt(policy, plan, psbtHex);
  const finalized = finalizeCommunityVaultPsbt(policy, plan.spendPlan, psbtHex);
  return verifyFinalizedCommunityVaultSale({ policy, plan, transactionHex: finalized.transactionHex });
}
