import { bech32m } from '@scure/base';
import { Address, NETWORK, OutScript, TEST_NETWORK } from '@scure/btc-signer';
import type { WalletUtxo } from '../classification/types';
import type { EligibilityContext } from '../classification/eligibility';
import type { Network } from '../keys/derivation';
import {
  payableScriptKind,
  scriptDustSats,
  scriptKind,
  sequenceForInput,
  type PayableScriptKind,
} from './fees';
import { inputFromUtxo, type PlanDerivation, type PlanInput, type PlanOutput } from './plan';
import {
  CoinSelectionError,
  selectCoins,
  type CoinSelectionFailure,
} from './selection';

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

export interface ResolvedPayableAddress {
  address: string;
  scriptPubKey: string;
  scriptKind: PayableScriptKind;
}

export type PayableAddressOutcome =
  | { ok: true; value: ResolvedPayableAddress }
  | { ok: false; reason: 'invalid_address' | 'unsupported_output_type' };

export interface NativeSendChangeOutput {
  address: string;
  scriptPubKey: string;
  role: 'payment_change';
  derivation: PlanDerivation & { lane: 'payment'; chain: 1 };
}

/**
 * Recognize a consensus-valid, correct-network future witness address after
 * the pinned signer refuses to project it into a known OutScript. This keeps
 * invalid/wrong-network input distinct from a valid output type the wallet
 * deliberately does not support.
 */
function isUnsupportedWitnessAddress(address: string, network: Network): boolean {
  const expectedPrefix = network === 'mainnet' ? NETWORK.bech32 : TEST_NETWORK.bech32;
  try {
    const decoded = bech32m.decode(address as `${string}1${string}`, 90);
    if (decoded.prefix.toLowerCase() !== expectedPrefix || decoded.words.length < 2) return false;
    const [version, ...programWords] = decoded.words;
    if (version === undefined || version < 1 || version > 16) return false;
    const program = bech32m.fromWords(programWords);
    if (program.length < 2 || program.length > 40) return false;
    // A 32-byte v1 program is the supported P2TR shape. If the signer rejected
    // it (for example, an invalid output key), it is invalid rather than a
    // future output type.
    return version !== 1 || program.length !== 32;
  } catch {
    return false;
  }
}

/** Address -> exact payable script, with fail-closed typed domain outcomes. */
export function resolvePayableAddress(address: string, network: Network): PayableAddressOutcome {
  let scriptPubKey: string;
  try {
    const codec = Address(network === 'mainnet' ? NETWORK : TEST_NETWORK);
    scriptPubKey = bytesToHex(OutScript.encode(codec.decode(address)));
  } catch {
    return {
      ok: false,
      reason: isUnsupportedWitnessAddress(address, network)
        ? 'unsupported_output_type'
        : 'invalid_address',
    };
  }
  try {
    return {
      ok: true,
      value: { address, scriptPubKey, scriptKind: payableScriptKind(scriptPubKey) },
    };
  } catch {
    return { ok: false, reason: 'unsupported_output_type' };
  }
}

export interface NativeSendCandidateRequest {
  recipient: ResolvedPayableAddress;
  amountSats: bigint;
  sendMax: boolean;
  accountId: string;
  account: number;
  utxos: readonly WalletUtxo[];
  eligibility: Omit<EligibilityContext, 'marginalFeeSatsFor'>;
  feeRate: bigint;
  changeOutput: NativeSendChangeOutput;
  deriveInput: (utxo: WalletUtxo) => PlanDerivation;
  selectedOutpoints?: ReadonlySet<string>;
  labelGroupByOutpoint?: ReadonlyMap<string, string>;
}

export interface NativeSendCandidate {
  accountId: string;
  account: number;
  inputs: PlanInput[];
  outputs: PlanOutput[];
  feeSats: bigint;
  vsize: bigint;
  protectedSatFlow: [];
  rbf: true;
  parentTxid: null;
  replacesTxid: null;
}

export type NativeSendCandidateFailure =
  | CoinSelectionFailure
  | 'dust';

export type NativeSendCandidateOutcome =
  | { ok: true; candidate: NativeSendCandidate }
  | { ok: false; reason: NativeSendCandidateFailure };

/**
 * Pure ordinary-send construction. Reservation, key access, storage and RPC
 * mapping remain consumer responsibilities; every wallet semantic is shared.
 */
export function buildNativeSendCandidate(
  request: NativeSendCandidateRequest,
): NativeSendCandidateOutcome {
  if (request.changeOutput.role !== 'payment_change' ||
      request.changeOutput.derivation.accountId !== request.accountId ||
      request.changeOutput.derivation.account !== request.account ||
      request.changeOutput.derivation.lane !== 'payment' ||
      request.changeOutput.derivation.chain !== 1 ||
      scriptKind(request.changeOutput.scriptPubKey) !== 'p2wpkh') {
    throw new Error('invalid native-send payment change output');
  }
  let selection;
  try {
    selection = selectCoins({
      utxos: request.utxos,
      eligibility: request.eligibility,
      accountId: request.accountId,
      account: request.account,
      feeRate: request.feeRate,
      targetSats: request.amountSats,
      recipientScripts: [request.recipient.scriptPubKey],
      changeScript: request.changeOutput.scriptPubKey,
      sendMax: request.sendMax,
      ...(request.selectedOutpoints ? { selectedOutpoints: request.selectedOutpoints } : {}),
      ...(request.labelGroupByOutpoint
        ? { labelGroupByOutpoint: request.labelGroupByOutpoint }
        : {}),
    });
  } catch (error) {
    if (error instanceof CoinSelectionError) return { ok: false, reason: error.reason };
    throw error;
  }

  // Preserve the extension's established operation order: selected input
  // ownership is resolved before the recipient dust result is returned.
  const inputs = selection.inputs.map((utxo) => inputFromUtxo(
    utxo,
    request.deriveInput(utxo),
    sequenceForInput('native_send'),
  ));
  const outputs: PlanOutput[] = [{
    address: request.recipient.address,
    scriptPubKey: request.recipient.scriptPubKey,
    valueSats: selection.recipientSats,
    role: 'recipient',
  }];
  if (selection.recipientSats < scriptDustSats(request.recipient.scriptPubKey)) {
    return { ok: false, reason: 'dust' };
  }
  if (selection.changeSats > 0n) {
    outputs.push({
      address: request.changeOutput.address,
      scriptPubKey: request.changeOutput.scriptPubKey,
      valueSats: selection.changeSats,
      role: 'payment_change',
      derivation: request.changeOutput.derivation,
    });
  }
  return {
    ok: true,
    candidate: {
      accountId: request.accountId,
      account: request.account,
      inputs,
      outputs,
      feeSats: selection.feeSats,
      vsize: selection.vsize,
      protectedSatFlow: [],
      rbf: true,
      parentTxid: null,
      replacesTxid: null,
    },
  };
}
