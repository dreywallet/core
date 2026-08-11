import { NETWORK, SigHash, TEST_NETWORK, Transaction } from '@scure/btc-signer';
import type { Network } from '../keys/derivation';
import { base64ToBytes, bytesToHex } from '../vault/encoding';
import type { PlanInput } from '../transactions/plan';
import type { MarketplaceContext } from './types';

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
  const inscriptionId = input.context.identifiers?.inscriptionId;
  if (inscriptionId && !input.selectedInputIndexes.some((index) =>
    input.planInputs[index]?.classification.inscriptions.some((item) => item.inscriptionId === inscriptionId))) {
    throw new Error('marketplace inscription identity does not match current classification');
  }
}

export function unsignedMarketplaceFingerprint(psbtBase64: string): string {
  const tx = Transaction.fromPSBT(base64ToBytes(psbtBase64), { lowR: true });
  return bytesToHex(tx.toPSBT());
}
