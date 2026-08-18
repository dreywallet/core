import { NETWORK, SigHash, TEST_NETWORK, Transaction } from '@scure/btc-signer';
import type { Network } from '../keys/derivation';
import { base64ToBytes, bytesToHex } from '../vault/encoding';
import type { PlanInput, PlanOutput, ProtectedSatFlow } from '../transactions/plan';
import type { MarketplaceContext } from './types';
import { assertProviderPsbtItemCounts } from '../transactions/provider-psbt-limits';

export interface MarketplaceCommitmentAnalysis {
  mode: 'exact' | 'partial';
  selectedInputIndexes: number[];
  guaranteedOutputIndexes: number[] | 'all';
  guaranteedProceedsSats: bigint;
  walletFeeExposureSats: bigint;
  uncommittedDimensions: Array<'external_inputs' | 'non_corresponding_outputs'>;
}

function outputAddress(tx: Transaction, index: number, network: Network): string | null {
  const output = tx.getOutput(index);
  if (!output.script) return null;
  try {
    return tx.getOutputAddress(index, network === 'mainnet' ? NETWORK : TEST_NETWORK) ?? null;
  } catch {
    return null;
  }
}

export function analyzeMarketplaceCommitment(input: {
  psbtBase64: string;
  network: Network;
  context: MarketplaceContext;
  selectedInputIndexes: number[];
}): MarketplaceCommitmentAnalysis {
  const tx = Transaction.fromPSBT(base64ToBytes(input.psbtBase64), { lowR: true });
  assertProviderPsbtItemCounts(tx);
  const selected = [...new Set(input.selectedInputIndexes)].sort((a, b) => a - b);
  if (selected.length === 0 || selected.some((index) => index < 0 || index >= tx.inputsLength)) {
    throw new Error('marketplace signer indexes are missing or invalid');
  }
  let guaranteedProceedsSats = 0n;
  let walletFeeExposureSats = 0n;
  let allInputsCommitted = false;
  let allOutputsCommitted = false;
  const guaranteed = new Set<number>();
  const payoutOutputs = new Set<number>();
  for (const index of selected) {
    const item = tx.getInput(index);
    const sighash = item.sighashType ?? (item.witnessUtxo?.script?.length === 22 ? SigHash.ALL : SigHash.DEFAULT);
    if (!item.witnessUtxo) throw new Error('selected marketplace input has no prevout');
    if (sighash === SigHash.SINGLE_ANYONECANPAY) {
      const output = tx.getOutput(index);
      if (!output || output.amount === undefined) throw new Error('SINGLE has no corresponding output');
      guaranteed.add(index);
      payoutOutputs.add(index);
      if (item.witnessUtxo.amount > output.amount) walletFeeExposureSats += item.witnessUtxo.amount - output.amount;
      if (input.context.economics?.payoutAddress &&
          outputAddress(tx, index, input.network) !== input.context.economics.payoutAddress) {
        throw new Error('seller payout address differs from approved economics');
      }
    } else if (sighash === SigHash.ALL_ANYONECANPAY) {
      allOutputsCommitted = true;
      for (let outputIndex = 0; outputIndex < tx.outputsLength; outputIndex += 1) guaranteed.add(outputIndex);
    } else if (sighash === SigHash.DEFAULT || sighash === SigHash.ALL) {
      allInputsCommitted = true;
      allOutputsCommitted = true;
      for (let outputIndex = 0; outputIndex < tx.outputsLength; outputIndex += 1) guaranteed.add(outputIndex);
    } else {
      throw new Error('unsupported marketplace sighash');
    }
  }
  if (allOutputsCommitted && input.context.economics?.payoutAddress) {
    for (let index = 0; index < tx.outputsLength; index += 1) {
      if (outputAddress(tx, index, input.network) === input.context.economics.payoutAddress) {
        payoutOutputs.add(index);
      }
    }
  }
  for (const index of payoutOutputs) guaranteedProceedsSats += tx.getOutput(index).amount ?? 0n;
  const expectedProceeds = input.context.economics?.sellerProceedsSats;
  if (expectedProceeds !== undefined && guaranteedProceedsSats < BigInt(expectedProceeds)) {
    throw new Error('seller proceeds are below the approved amount');
  }
  const uncommittedDimensions: MarketplaceCommitmentAnalysis['uncommittedDimensions'] = [];
  if (!allInputsCommitted) uncommittedDimensions.push('external_inputs');
  if (!allOutputsCommitted) uncommittedDimensions.push('non_corresponding_outputs');
  return {
    mode: uncommittedDimensions.length === 0 ? 'exact' : 'partial',
    selectedInputIndexes: selected,
    guaranteedOutputIndexes: guaranteed.size === tx.outputsLength ? 'all' : [...guaranteed].sort((a, b) => a - b),
    guaranteedProceedsSats,
    walletFeeExposureSats,
    uncommittedDimensions,
  };
}

export function assertMarketplaceWalletInputs(input: {
  planInputs: readonly PlanInput[];
  selectedInputIndexes: readonly number[];
  context: MarketplaceContext;
}): void {
  const selected = new Set(input.selectedInputIndexes);
  for (let index = 0; index < input.planInputs.length; index += 1) {
    const planInput = input.planInputs[index]!;
    if (planInput.ownership === 'wallet' && !selected.has(index)) {
      throw new Error('marketplace request contains an unapproved wallet input');
    }
  }
  if (input.context.selectedInputIndexes) {
    const expected = [...input.context.selectedInputIndexes].sort((a, b) => a - b);
    const actual = [...selected].sort((a, b) => a - b);
    if (expected.length !== actual.length || expected.some((index, position) => index !== actual[position])) {
      throw new Error('marketplace signing indexes differ from approved context');
    }
  }
  const inscriptionId = input.context.identifiers?.inscriptionId;
  const purchase = input.context.role === 'buyer' &&
    ['buy', 'secure_buy', 'accept_counter'].includes(input.context.action) &&
    input.context.stage !== 'payment-prep';
  if (inscriptionId && purchase && !input.planInputs.some((item) =>
    item.ownership === 'external' &&
    item.classification.inscriptions.some((inscription) => inscription.inscriptionId === inscriptionId))) {
    throw new Error('marketplace purchase inscription is not on an external input');
  }
  if (inscriptionId && !purchase && input.context.stage !== 'payment-prep' &&
      !input.selectedInputIndexes.some((index) =>
        input.planInputs[index]?.classification.inscriptions.some((item) => item.inscriptionId === inscriptionId))) {
    throw new Error('marketplace inscription identity does not match current classification');
  }
}

export function assertMarketplaceBuyerPlan(input: {
  planInputs: readonly PlanInput[];
  outputs: readonly PlanOutput[];
  protectedSatFlow: readonly ProtectedSatFlow[];
  selectedInputIndexes: readonly number[];
  feeSats: bigint;
  context: MarketplaceContext;
}): void {
  if (input.context.role !== 'buyer' ||
      !['buy', 'secure_buy', 'accept_counter'].includes(input.context.action) ||
      !input.context.templateVersion.startsWith('omb-wiki-')) return;
  const expectedDebit = input.context.economics?.buyerDebitSats;
  if (!expectedDebit) throw new Error('marketplace buyer debit binding is missing');
  const selectedScripts = new Set(input.selectedInputIndexes.map((index) =>
    input.planInputs[index]?.scriptPubKey).filter((script): script is string => script !== undefined));
  const selectedValue = input.selectedInputIndexes.reduce((sum, index) =>
    sum + (input.planInputs[index]?.valueSats ?? 0n), 0n);
  const returnedValue = input.outputs.reduce((sum, output) =>
    selectedScripts.has(output.scriptPubKey) ? sum + output.valueSats : sum, 0n);
  if (selectedValue - returnedValue !== BigInt(expectedDebit) ||
      input.context.economics?.totalSats !== expectedDebit) {
    throw new Error('marketplace buyer debit differs from the analyzed plan');
  }

  if (input.context.stage === 'payment-prep') {
    if (input.planInputs.some((item) => item.ownership !== 'wallet') ||
        input.selectedInputIndexes.some((index) =>
          input.planInputs[index]?.derivation?.lane !== 'payment' ||
          input.planInputs[index]?.classification.inscriptions.length !== 0 ||
          input.planInputs[index]?.classification.unsupportedAssetDetected ||
          input.planInputs[index]?.classification.satRanges !== null) ||
        input.outputs.some((output) => !output.derivation)) {
      throw new Error('marketplace payment preparation contains non-payment assets or external value');
    }
    const totalIn = input.planInputs.reduce((sum, item) => sum + item.valueSats, 0n);
    if (input.feeSats <= 0n || input.feeSats > 100_000n || input.feeSats * 10n > totalIn) {
      throw new Error('marketplace payment preparation fee is outside the bounded policy');
    }
    return;
  }

  const inscriptionId = input.context.identifiers?.inscriptionId;
  const destination = input.context.economics?.assetDestination;
  const flows = input.protectedSatFlow.filter((flow) => flow.inscriptionId === inscriptionId);
  if (!inscriptionId || !destination || flows.length !== 1) {
    throw new Error('marketplace purchase does not have one exact protected inscription flow');
  }
  const flow = flows[0]!;
  const source = input.planInputs[flow.inputIndex];
  const target = input.outputs[flow.outputIndex];
  if (source?.ownership !== 'external' || target?.address !== destination ||
      target.derivation?.lane !== 'ordinals') {
    throw new Error('marketplace purchase inscription does not land at the active Ordinals destination');
  }
}

export function unsignedMarketplaceFingerprint(psbtBase64: string): string {
  const tx = Transaction.fromPSBT(base64ToBytes(psbtBase64), { lowR: true });
  assertProviderPsbtItemCounts(tx);
  return bytesToHex(tx.toPSBT());
}
