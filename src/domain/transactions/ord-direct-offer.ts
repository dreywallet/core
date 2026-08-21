import { Transaction } from '@scure/btc-signer';
import { sha256 } from '@scure/btc-signer/utils';
import { z } from 'zod';
import { bitcoinNetwork, type Network } from '../keys/derivation';
import { base64ToBytes, bytesToBase64, bytesToHex } from '../vault/encoding';
import type { PlanInput, PlanOutput } from './plan';

export const ORD_DIRECT_OFFER_TEMPLATE_ID = 'ord_direct_offer_v1' as const;
/** Production stays unavailable until official ord fixtures and signet interop are reviewed. */
export const ORD_DIRECT_OFFERS_PRODUCTION_ENABLED = false as const;
export const ORD_DIRECT_OFFER_MAX_PSBT_BYTES = 1_500_000;

export const ordDirectOfferRecordSchema = z.object({
  version: z.literal(1),
  templateId: z.literal(ORD_DIRECT_OFFER_TEMPLATE_ID),
  offerId: z.string().regex(/^[0-9a-f]{64}$/u),
  role: z.enum(['buyer', 'seller']),
  inscriptionId: z.string().regex(/^[0-9a-f]{64}i(?:0|[1-9][0-9]*)$/u),
  amountSats: z.string().regex(/^[1-9][0-9]*$/u),
  unsignedTransactionId: z.string().regex(/^[0-9a-f]{64}$/u),
  fundingOutpoints: z.array(z.object({
    txid: z.string().regex(/^[0-9a-f]{64}$/u), vout: z.number().int().nonnegative(),
  }).strict()).min(1),
  createdAt: z.number().int().nonnegative(),
  status: z.enum(['ready', 'cancel_pending', 'accepted', 'cancelled', 'invalidated']),
}).strict();
export type OrdDirectOfferRecordV1 = z.infer<typeof ordDirectOfferRecordSchema>;

export interface OrdDirectOfferAcceptanceExpectation {
  network: Network;
  inscriptionId: string;
  sellerOutpoint: { txid: string; vout: number };
  sellerPrevout: { valueSats: bigint; scriptPubKey: string };
  sellerPayoutAddress: string;
  amountSats: bigint;
  inscriptionDestinationAddress: string;
}

export const ordDirectOfferCreateRequestSchema = z.object({
  version: z.literal(1),
  templateId: z.literal(ORD_DIRECT_OFFER_TEMPLATE_ID),
  inscriptionId: z.string().regex(/^[0-9a-f]{64}i(?:0|[1-9][0-9]*)$/u),
  sellerOutpoint: z.object({ txid: z.string().regex(/^[0-9a-f]{64}$/u), vout: z.number().int().nonnegative() }).strict(),
  sellerPrevoutValueSats: z.string().regex(/^[1-9][0-9]*$/u),
  sellerPrevoutScriptPubKey: z.string().regex(/^(?:[0-9a-f]{2})+$/u),
  sellerPayoutAddress: z.string().min(1).max(128),
  buyerDestinationAddress: z.string().min(1).max(128),
  amountSats: z.string().regex(/^[1-9][0-9]*$/u),
  fundingOutpoints: z.array(z.object({
    txid: z.string().regex(/^[0-9a-f]{64}$/u), vout: z.number().int().nonnegative(),
  }).strict()).min(1),
}).strict();
export type OrdDirectOfferCreateRequestV1 = z.infer<typeof ordDirectOfferCreateRequestSchema>;

export const ordDirectOfferAcceptRequestSchema = z.object({
  version: z.literal(1), templateId: z.literal(ORD_DIRECT_OFFER_TEMPLATE_ID),
  offerId: z.string().regex(/^[0-9a-f]{64}$/u), psbtBase64: z.string().min(1).max(2_000_000),
}).strict();
export type OrdDirectOfferAcceptRequestV1 = z.infer<typeof ordDirectOfferAcceptRequestSchema>;

export const ordDirectOfferCancelRequestSchema = z.object({
  version: z.literal(1), templateId: z.literal(ORD_DIRECT_OFFER_TEMPLATE_ID),
  offerId: z.string().regex(/^[0-9a-f]{64}$/u),
  fundingOutpoints: z.array(z.object({
    txid: z.string().regex(/^[0-9a-f]{64}$/u), vout: z.number().int().nonnegative(),
  }).strict()).min(1),
}).strict();
export type OrdDirectOfferCancelRequestV1 = z.infer<typeof ordDirectOfferCancelRequestSchema>;

export interface ValidatedOrdDirectOfferV1 {
  templateId: typeof ORD_DIRECT_OFFER_TEMPLATE_ID;
  canonicalPsbtBase64: string;
  offerId: string;
  unsignedTransactionId: string;
  sellerInputIndex: 0;
  inscriptionOutputIndex: 0;
  sellerOutputIndex: 1;
  buyerFundingOutpoints: Array<{ txid: string; vout: number }>;
  feeSats: bigint;
}

export function buildOrdDirectOfferTemplate(input: {
  sellerOutpoint: { txid: string; vout: number };
  sellerPrevout: { valueSats: bigint; scriptPubKey: string };
  inscriptionDestination: { address: string; scriptPubKey: string };
  sellerPayout: { address: string; scriptPubKey: string };
  amountSats: bigint;
  buyerFundingInputs: readonly PlanInput[];
  buyerChangeOutputs: readonly PlanOutput[];
}): { psbtBase64: string; buyerInputIndexes: number[]; feeSats: bigint } {
  assertOrdDirectOffersProductionEnabled();
  if (input.amountSats <= 0n || input.sellerPrevout.valueSats <= 0n || input.buyerFundingInputs.length === 0 ||
      !/^[0-9a-f]{64}$/u.test(input.sellerOutpoint.txid) ||
      !/^(?:[0-9a-f]{2})+$/u.test(input.sellerPrevout.scriptPubKey) ||
      input.buyerFundingInputs.some((item) => item.derivation?.lane !== 'payment' || item.sighash !== 1 ||
        item.ownership === 'external' || item.classification.primaryClass !== 'cardinal_clean' ||
        item.classification.confidence !== 'authoritative' || item.classification.unsupportedAssetDetected ||
        item.classification.inscriptions.length !== 0) ||
      input.buyerChangeOutputs.some((output) => output.role !== 'payment_change' ||
        output.derivation?.lane !== 'payment')) {
    throw new Error('invalid direct-offer construction request');
  }
  const tx = new Transaction({ lowR: true, version: 2, lockTime: 0 });
  tx.addInput({
    txid: input.sellerOutpoint.txid,
    index: input.sellerOutpoint.vout,
    sequence: 0xffff_fffd,
    witnessUtxo: { amount: input.sellerPrevout.valueSats, script: hexBytes(input.sellerPrevout.scriptPubKey) },
  });
  for (const funding of input.buyerFundingInputs) {
    tx.addInput({
      txid: funding.txid, index: funding.vout, sequence: funding.sequence,
      witnessUtxo: { amount: funding.valueSats, script: hexBytes(funding.scriptPubKey) },
    });
  }
  tx.addOutput({ script: hexBytes(input.inscriptionDestination.scriptPubKey), amount: input.sellerPrevout.valueSats });
  tx.addOutput({
    script: hexBytes(input.sellerPayout.scriptPubKey),
    amount: input.sellerPrevout.valueSats + input.amountSats,
  });
  for (const output of input.buyerChangeOutputs) {
    tx.addOutput({ script: hexBytes(output.scriptPubKey), amount: output.valueSats });
  }
  const inputTotal = input.sellerPrevout.valueSats +
    input.buyerFundingInputs.reduce((sum, item) => sum + item.valueSats, 0n);
  const outputTotal = input.sellerPrevout.valueSats * 2n + input.amountSats +
    input.buyerChangeOutputs.reduce((sum, item) => sum + item.valueSats, 0n);
  const feeSats = inputTotal - outputTotal;
  if (feeSats <= 0n) throw new Error('direct-offer fee is not positive');
  return {
    psbtBase64: bytesToBase64(tx.toPSBT()),
    buyerInputIndexes: input.buyerFundingInputs.map((_item, index) => index + 1),
    feeSats,
  };
}

function hexBytes(hex: string): Uint8Array {
  if (!/^(?:[0-9a-f]{2})+$/u.test(hex)) throw new Error('invalid hex');
  const result = new Uint8Array(hex.length / 2);
  for (let index = 0; index < result.length; index += 1) {
    result[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  }
  return result;
}

function outputAddress(tx: Transaction, index: number, network: Network): string | null {
  try {
    return tx.getOutputAddress(index, bitcoinNetwork(network)) ?? null;
  } catch {
    return null;
  }
}

function digestHex(bytes: Uint8Array): string {
  return bytesToHex(sha256(bytes));
}

function unsignedTransactionId(tx: Transaction): string {
  return bytesToHex(Uint8Array.from(sha256(sha256(tx.unsignedTx))).reverse());
}

/** Strict seller-side parser for the ord 0.29 direct-offer acceptance shape. */
export function validateOrdDirectOfferForAcceptance(
  psbtBase64: string,
  expected: OrdDirectOfferAcceptanceExpectation,
): ValidatedOrdDirectOfferV1 {
  assertOrdDirectOffersProductionEnabled();
  if (!/^[0-9a-f]{64}i(?:0|[1-9][0-9]*)$/u.test(expected.inscriptionId) ||
      expected.amountSats <= 0n || !/^(?:[0-9a-f]{2})+$/u.test(expected.sellerPrevout.scriptPubKey)) {
    throw new Error('invalid direct-offer expectation');
  }
  const bytes = base64ToBytes(psbtBase64);
  if (bytes.length > ORD_DIRECT_OFFER_MAX_PSBT_BYTES || bytesToBase64(bytes) !== psbtBase64) {
    throw new Error('direct-offer PSBT is absent, oversized, or non-canonical');
  }
  const tx = Transaction.fromPSBT(bytes, { lowR: true });
  if (tx.inputsLength < 2 || tx.outputsLength < 2) throw new Error('direct offer has an invalid shape');
  const seller = tx.getInput(0);
  if (!seller.txid || seller.index === undefined ||
      bytesToHex(seller.txid) !== expected.sellerOutpoint.txid || seller.index !== expected.sellerOutpoint.vout ||
      seller.witnessUtxo?.amount !== expected.sellerPrevout.valueSats ||
      !seller.witnessUtxo.script || bytesToHex(seller.witnessUtxo.script) !== expected.sellerPrevout.scriptPubKey ||
      seller.sighashType !== undefined || (seller.partialSig?.length ?? 0) > 0 ||
      (seller.tapKeySig?.length ?? 0) > 0 || (seller.tapScriptSig?.length ?? 0) > 0 ||
      (seller.finalScriptSig?.length ?? 0) > 0 || (seller.finalScriptWitness?.length ?? 0) > 0) {
    throw new Error('direct-offer seller input differs from the reviewed inscription source');
  }
  const inscriptionOutput = tx.getOutput(0);
  if (inscriptionOutput.amount !== expected.sellerPrevout.valueSats ||
      outputAddress(tx, 0, expected.network) !== expected.inscriptionDestinationAddress) {
    throw new Error('direct-offer inscription destination or postage differs from the reviewed offer');
  }
  const sellerOutputs = Array.from({ length: tx.outputsLength }, (_unused, index) => index)
    .filter((index) => outputAddress(tx, index, expected.network) === expected.sellerPayoutAddress);
  const sellerOutputTotal = sellerOutputs.reduce((sum, index) => sum + (tx.getOutput(index).amount ?? 0n), 0n);
  if (sellerOutputs.length !== 1 || sellerOutputs[0] !== 1 ||
      sellerOutputTotal - expected.sellerPrevout.valueSats !== expected.amountSats) {
    throw new Error('direct-offer seller net proceeds differ from the reviewed amount');
  }
  const seen = new Set<string>();
  const buyerFundingOutpoints: Array<{ txid: string; vout: number }> = [];
  let inputTotal = expected.sellerPrevout.valueSats;
  for (let index = 1; index < tx.inputsLength; index += 1) {
    const input = tx.getInput(index);
    const hasFinalScriptSig = (input.finalScriptSig?.length ?? 0) > 0;
    const hasFinalScriptWitness = (input.finalScriptWitness?.length ?? 0) > 0;
    if (!input.txid || input.index === undefined || !input.witnessUtxo ||
        input.sighashType !== undefined || (input.partialSig?.length ?? 0) > 0 ||
        (input.tapKeySig?.length ?? 0) > 0 || (input.tapScriptSig?.length ?? 0) > 0 ||
        hasFinalScriptSig === hasFinalScriptWitness) {
      throw new Error('direct-offer buyer funding input is absent or unsigned');
    }
    const outpoint = `${bytesToHex(input.txid)}:${input.index}`;
    if (seen.has(outpoint) || outpoint === `${expected.sellerOutpoint.txid}:${expected.sellerOutpoint.vout}`) {
      throw new Error('direct-offer input is duplicated');
    }
    seen.add(outpoint);
    buyerFundingOutpoints.push({ txid: bytesToHex(input.txid), vout: input.index });
    inputTotal += input.witnessUtxo.amount;
  }
  const outputTotal = Array.from({ length: tx.outputsLength }, (_unused, index) =>
    tx.getOutput(index).amount ?? 0n).reduce((sum, amount) => sum + amount, 0n);
  const feeSats = inputTotal - outputTotal;
  if (feeSats <= 0n) throw new Error('direct-offer fee is not positive');
  return {
    templateId: ORD_DIRECT_OFFER_TEMPLATE_ID,
    canonicalPsbtBase64: psbtBase64,
    offerId: digestHex(bytes),
    unsignedTransactionId: unsignedTransactionId(tx),
    sellerInputIndex: 0,
    inscriptionOutputIndex: 0,
    sellerOutputIndex: 1,
    buyerFundingOutpoints,
    feeSats,
  };
}

export function createOrdDirectOfferRecord(input: {
  role: 'buyer' | 'seller';
  inscriptionId: string;
  amountSats: bigint;
  unsignedTransactionId: string;
  fundingOutpoints: Array<{ txid: string; vout: number }>;
  createdAt: number;
  offerId: string;
}): OrdDirectOfferRecordV1 {
  return ordDirectOfferRecordSchema.parse({
    version: 1, templateId: ORD_DIRECT_OFFER_TEMPLATE_ID, offerId: input.offerId,
    role: input.role, inscriptionId: input.inscriptionId, amountSats: input.amountSats.toString(),
    unsignedTransactionId: input.unsignedTransactionId, fundingOutpoints: input.fundingOutpoints,
    createdAt: input.createdAt, status: 'ready',
  });
}

export function beginOrdDirectOfferCancellation(
  record: OrdDirectOfferRecordV1,
  fundingOutpoints: readonly { txid: string; vout: number }[],
): OrdDirectOfferRecordV1 {
  if (record.role !== 'buyer' || record.status !== 'ready') throw new Error('offer cannot be cancelled from this state');
  const expected = new Set(record.fundingOutpoints.map((item) => `${item.txid}:${item.vout}`));
  if (fundingOutpoints.length !== expected.size ||
      fundingOutpoints.some((item) => !expected.has(`${item.txid}:${item.vout}`))) {
    throw new Error('offer cancellation must spend every reserved funding input');
  }
  return { ...record, status: 'cancel_pending' };
}

export function reconcileOrdDirectOffer(input: {
  record: OrdDirectOfferRecordV1;
  acceptedTransactionObserved: boolean;
  conflictingFundingSpendObserved: boolean;
}): OrdDirectOfferRecordV1 {
  if (input.acceptedTransactionObserved && input.conflictingFundingSpendObserved) {
    return { ...input.record, status: 'invalidated' };
  }
  if (input.acceptedTransactionObserved) return { ...input.record, status: 'accepted' };
  if (input.conflictingFundingSpendObserved) return { ...input.record, status: 'cancelled' };
  return input.record;
}

export function assertOrdDirectOfferFundingAvailable(
  activeRecords: readonly OrdDirectOfferRecordV1[],
  proposedOutpoints: readonly { txid: string; vout: number }[],
): void {
  const reserved = new Set(activeRecords
    .filter((record) => record.status === 'ready' || record.status === 'cancel_pending')
    .flatMap((record) => record.fundingOutpoints.map((item) => `${item.txid}:${item.vout}`)));
  if (proposedOutpoints.some((item) => reserved.has(`${item.txid}:${item.vout}`))) {
    throw new Error('funding input is already reserved by an active offer');
  }
}

export function assertOrdDirectOffersProductionEnabled(): void {
  if (!ORD_DIRECT_OFFERS_PRODUCTION_ENABLED) {
    throw new Error('direct inscription offers are disabled pending reviewed ord fixtures and signet interoperability');
  }
}
