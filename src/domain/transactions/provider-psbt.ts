import { p2tr, p2wpkh, RawTx, SigHash, Transaction } from '@scure/btc-signer';
import { schnorr, secp256k1 } from '@noble/curves/secp256k1';
import type { UtxoClassification } from '../gateway/contract';
import { bitcoinNetwork, deriveAccountNode, type Network } from '../keys/derivation';
import { scriptPubKeyHex } from '../keys/script-hash';
import { base64ToBytes, bytesToBase64, bytesToHex } from '../vault/encoding';
import { getCryptoProvider } from '../vault/crypto-provider';
import { analyzePsbtHex, analyzeRawTransactionHex, decodeSighash, type TransactionAnalysis } from './analysis';
import { estimateVsize, payableScriptKind, scriptKind } from './fees';
import type { PlanDerivation, PlanInput, PlanOutput, TransactionPlan } from './plan';
import type { InscriptionPreviewSet, StoredInscriptionPreviewSet } from './inscription-previews';
import { approvalInscriptionItems, cloneInscriptionPreviewSet, storedPreviewSet } from './inscription-previews';
import { canonicalTaprootSignatureSighash } from './taproot-signature';
import type { MarketplaceContext, MarketplaceResolution } from '../marketplaces/types';
import { publicAccountFromSeed } from '../accounts/public-account';
import {
  analyzeMarketplaceCommitment,
  assertMarketplaceBuyerPlan,
  assertMarketplaceWalletInputs,
  type MarketplaceCommitmentAnalysis,
} from '../marketplaces/commitment';
import { templateForResolution } from '../marketplaces/resolver';
import { verifyOrdnetSaleKeyPath, verifyOrdnetSaleScriptPath } from '../marketplaces/ordnet-script-path';
import {
  assertProviderPsbtItemCounts,
  PROVIDER_MAX_PSBT_INPUT_SELECTIONS,
  PROVIDER_MAX_PSBT_INPUTS,
} from './provider-psbt-limits';
import type { ProviderPsbtInputClassificationProvenanceV1 } from './provider-psbt-group-prepare';
import {
  assertProviderPsbtGroupPlan,
  type ProviderPsbtGroupPlanV1,
  type SignedProviderPsbtGroupV1,
} from './provider-psbt-group-plan';
import type { CommunityVaultAcquisitionProviderReviewV1 } from '../community-vault/acquisition-provider';
import type {
  CommunityVaultSaleBuyerProviderReviewV1,
  CommunityVaultSaleProviderReviewV1,
} from '../community-vault/sale-provider';
import type {
  CommunityVaultPositionTransferProviderReviewV1,
} from '../community-vault/position-transfer-provider';
import {
  createProviderPsbtApprovalExplanation,
  type ProviderPsbtApprovalExplanationV1,
  type ProviderPsbtInputScriptType,
  type ProviderPsbtOutputScriptType,
} from './provider-psbt-approval';
export {
  partitionOrdinalSatFlow,
  type OrdinalPartition,
  type OrdinalPartitionRequest,
} from './ordinal-transfer';

export interface ProviderAuthorityBinding {
  origin: string;
  tabId: number;
  frameId: number;
  documentId: string;
  requestNonce: string;
  providerMethod: 'signPsbt' | 'signMultipleTransactions' | 'sendTransfer' | 'ord_sendInscriptions';
}

export type ProviderPsbtSighash = 0 | 1 | 3 | 129 | 131;

export interface ProviderPsbtInput extends Omit<PlanInput, 'sighash'> {
  sighash: ProviderPsbtSighash;
  scriptType: ProviderPsbtInputScriptType;
}

export interface ProviderPsbtOutput extends Omit<PlanOutput, 'address' | 'role'> {
  address: string | null;
  role: PlanOutput['role'] | 'data' | 'unknown';
  scriptType: ProviderPsbtOutputScriptType;
}

export type ProviderPsbtPolicyErrorCode =
  | 'missing_prevout'
  | 'invalid_sighash'
  | 'sighash_none'
  | 'single_missing_output'
  | 'unsupported_wallet_script'
  | 'unknown_output_script'
  | 'sign_input_address_mismatch'
  | 'unsafe_protected_asset'
  | 'generic_listing_multiple_signatures'
  | 'unsafe_fee_exposure';

export class ProviderPsbtPolicyError extends Error {
  constructor(readonly code: ProviderPsbtPolicyErrorCode, message: string) {
    super(message);
    this.name = 'ProviderPsbtPolicyError';
  }
}

export interface ProviderPsbtPlanV5 {
  version: 5;
  planId: string;
  createdAt: number;
  expiresAt: number;
  network: Network;
  vaultId: string;
  sessionId: string;
  /** Stable public-account identity; numeric account is BIP32 metadata only. */
  accountId: string;
  account: number;
  kind: 'provider_psbt' | 'provider_transfer' | 'provider_ordinal_transfer' | 'marketplace_psbt' |
    'community_vault_acquisition' | 'community_vault_sale';
  provider: ProviderAuthorityBinding;
  psbtVersion: 0 | 2;
  broadcast: boolean;
  requiresAdvanced: boolean;
  /** Exact input indexes approved for this provider request. */
  selectedInputIndexes?: number[];
  /** §21.1 generic listing: origin-independent flexible sale proven from the PSBT. */
  genericListing?: {
    selectedInputIndexes: number[];
    commitment: MarketplaceCommitmentAnalysis;
  };
  inputs: ProviderPsbtInput[];
  outputs: ProviderPsbtOutput[];
  source: TransactionPlan['source'];
  feeSats: bigint;
  /** Exact, non-broadcast zero-fee signing request surfaced for explicit review. */
  deferredZeroFee: boolean;
  vsize: bigint | null;
  feeRateSatPerKvB: bigint | null;
  rbf: boolean;
  protectedSatFlow: TransactionPlan['protectedSatFlow'];
  psbtHex: string;
  psbtHash: string;
  analysis: TransactionAnalysis;
  analysisHash: string;
  approvalExplanation: ProviderPsbtApprovalExplanationV1 | null;
  transactionCommitmentHash: string;
  inscriptionPreviews: StoredInscriptionPreviewSet | null;
  planHash: string;
  /** Present only when prospective inputs were derived from a validated group graph. */
  linkedGroup?: {
    groupId: string;
    nodeId: string;
    preparationHash: string;
    inputProvenance: ProviderPsbtInputClassificationProvenanceV1[];
  };
  marketplace?: {
    context: MarketplaceContext;
    resolution: MarketplaceResolution;
    selectedInputIndexes: number[];
    commitment: MarketplaceCommitmentAnalysis;
    allowTaprootScriptPath: boolean;
    allowTaprootTreeKeyPath: boolean;
  };
  communityVaultAcquisition?: CommunityVaultAcquisitionProviderReviewV1;
  communityVaultSale?: CommunityVaultSaleProviderReviewV1;
  communityVaultSaleBuyer?: CommunityVaultSaleBuyerProviderReviewV1;
  communityVaultPositionTransfer?: CommunityVaultPositionTransferProviderReviewV1;
}

/** Compatibility names for call sites; only version 5 is constructible. */
export type ProviderPsbtPlanV3 = ProviderPsbtPlanV5;
export type ProviderPsbtPlanV4 = ProviderPsbtPlanV5;

const liveProviderPreviews = new WeakMap<ProviderPsbtPlanV5, InscriptionPreviewSet>();

export interface WalletPsbtInput {
  outpoint: string;
  derivation: PlanDerivation;
}

export interface ProviderSignInputBinding {
  address: string;
  inputIndexes: number[];
}

export interface ProviderPsbtInputSelection {
  address: string;
  signingIndexes: number[];
  sigHash?: ProviderPsbtSighash | undefined;
}

function inferExternalInscriptionFlows(
  inputs: readonly ProviderPsbtInput[],
  outputs: readonly ProviderPsbtOutput[],
): TransactionPlan['protectedSatFlow'] {
  const flows: TransactionPlan['protectedSatFlow'] = [];
  for (let inputIndex = 0; inputIndex < inputs.length; inputIndex += 1) {
    const input = inputs[inputIndex]!;
    if (input.ownership !== 'external' || input.classification.inscriptions.length === 0 ||
        input.classification.unsupportedAssetDetected || input.classification.satRanges !== null) continue;
    for (const inscription of input.classification.inscriptions) {
      const match = /^([0-9a-f]{64}):(\d+):(\d+)$/u.exec(inscription.satpoint);
      if (!match || match[1] !== input.txid || Number(match[2]) !== input.vout) continue;
      const inputOffset = BigInt(match[3]!);
      if (inputOffset < 0n || inputOffset >= input.valueSats) continue;
      const absolutePosition = inputs.slice(0, inputIndex)
        .reduce((sum, item) => sum + item.valueSats, 0n) + inputOffset;
      let outputStart = 0n;
      for (let outputIndex = 0; outputIndex < outputs.length; outputIndex += 1) {
        const output = outputs[outputIndex]!;
        const outputEnd = outputStart + output.valueSats;
        if (absolutePosition >= outputStart && absolutePosition < outputEnd &&
            output.derivation?.lane === 'ordinals') {
          flows.push({
            inputIndex,
            inputOffset,
            outputIndex,
            outputOffset: absolutePosition - outputStart,
            inscriptionId: inscription.inscriptionId,
          });
          break;
        }
        outputStart = outputEnd;
      }
    }
  }
  return flows;
}

function inferMarketplaceInscriptionFlows(
  inputs: readonly ProviderPsbtInput[],
  outputs: readonly ProviderPsbtOutput[],
): TransactionPlan['protectedSatFlow'] {
  const flows: TransactionPlan['protectedSatFlow'] = [];
  let inputStart = 0n;
  for (let inputIndex = 0; inputIndex < inputs.length; inputIndex += 1) {
    const input = inputs[inputIndex]!;
    for (const inscription of input.classification.inscriptions) {
      const match = /^([0-9a-f]{64}):(\d+):(\d+)$/u.exec(inscription.satpoint);
      if (!match || match[1] !== input.txid || Number(match[2]) !== input.vout) continue;
      const inputOffset = BigInt(match[3]!);
      if (inputOffset < 0n || inputOffset >= input.valueSats) continue;
      const absolutePosition = inputStart + inputOffset;
      let outputStart = 0n;
      for (let outputIndex = 0; outputIndex < outputs.length; outputIndex += 1) {
        const output = outputs[outputIndex]!;
        if (absolutePosition >= outputStart && absolutePosition < outputStart + output.valueSats) {
          flows.push({
            inputIndex,
            inputOffset,
            outputIndex,
            outputOffset: absolutePosition - outputStart,
            inscriptionId: inscription.inscriptionId,
          });
          break;
        }
        outputStart += output.valueSats;
      }
    }
    inputStart += input.valueSats;
  }
  return flows;
}

/**
 * Partition one input's FIFO sat stream into one non-dust output per protected
 * inscription. Earliest-safe boundaries preserve the maximum value for later
 * inscriptions; if they fail, no other boundary placement can succeed.
 */
export function providerPsbtOutpoints(psbtBase64: string): Array<{ txid: string; vout: number }> {
  const bytes = base64ToBytes(psbtBase64);
  if (bytesToBase64(bytes) !== psbtBase64) throw new Error('non-canonical PSBT base64');
  const tx = Transaction.fromPSBT(bytes, { allowUnknownInputs: true, allowUnknownOutputs: true });
  assertProviderPsbtItemCounts(tx);
  const outpoints: Array<{ txid: string; vout: number }> = [];
  for (let index = 0; index < tx.inputsLength; index += 1) {
    const item = tx.getInput(index);
    if (!item.txid || item.index === undefined) throw new Error('PSBT input outpoint missing');
    outpoints.push({ txid: bytesToHex(item.txid), vout: item.index });
  }
  return outpoints;
}

function hexToBytes(hex: string): Uint8Array {
  if (!/^(?:[0-9a-f]{2})+$/u.test(hex)) throw new Error('invalid hex');
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i += 1) bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return bytes;
}

function policyError(code: ProviderPsbtPolicyErrorCode, message: string): never {
  throw new ProviderPsbtPolicyError(code, message);
}

function providerInputScriptType(scriptPubKey: string): ProviderPsbtInputScriptType {
  try {
    return payableScriptKind(scriptPubKey);
  } catch {
    return 'unknown';
  }
}

function providerOutputScriptType(
  scriptPubKey: string,
  valueSats: bigint,
): ProviderPsbtOutputScriptType {
  if (/^6a(?:[0-9a-f]{2})*$/u.test(scriptPubKey) && scriptPubKey.length <= 166) {
    if (valueSats !== 0n) policyError('unknown_output_script', 'OP_RETURN output must have zero value');
    return 'op_return';
  }
  try {
    return payableScriptKind(scriptPubKey);
  } catch {
    return policyError('unknown_output_script', 'provider output locking script cannot be explained safely');
  }
}

function derivationAddress(derivation: PlanDerivation, network: Network): string {
  const publicKey = hexToBytes(derivation.publicKeyHex);
  const encoded = derivation.lane === 'payment'
    ? p2wpkh(publicKey, bitcoinNetwork(network)).address
    : p2tr(publicKey.slice(1), undefined, bitcoinNetwork(network)).address;
  if (!encoded) throw new Error('provider signing address encoding failed');
  return encoded;
}

function assertSignInputBindings(
  inputs: readonly ProviderPsbtInput[],
  selectedInputIndexes: readonly number[],
  network: Network,
  bindings: readonly ProviderSignInputBinding[] | undefined,
): void {
  if (bindings === undefined) return;
  const flattened = bindings.flatMap((binding) => binding.inputIndexes);
  const unique = new Set(flattened);
  const expected = [...selectedInputIndexes].sort((a, b) => a - b);
  const actual = [...unique].sort((a, b) => a - b);
  if (flattened.length !== unique.size || expected.length !== actual.length ||
      expected.some((index, position) => index !== actual[position])) {
    policyError('sign_input_address_mismatch', 'signInputs indexes differ from the selected wallet inputs');
  }
  for (const binding of bindings) {
    for (const index of binding.inputIndexes) {
      const derivation = inputs[index]?.derivation;
      if (!derivation || derivationAddress(derivation, network) !== binding.address) {
        policyError('sign_input_address_mismatch', `signInputs address does not own input ${index}`);
      }
    }
  }
}

export function validateProviderSignInputBindings(
  plan: ProviderPsbtPlanV5,
  bindings: readonly ProviderSignInputBinding[],
): void {
  assertProviderPsbtPlan(plan);
  assertSignInputBindings(plan.inputs, plan.selectedInputIndexes ?? [], plan.network, bindings);
}

/** Bind callback-level address, index, and sighash declarations to one prepared plan. */
export function resolveProviderPsbtInputSelections(
  plan: ProviderPsbtPlanV5,
  inputsToSign?: readonly ProviderPsbtInputSelection[],
): number[] {
  assertProviderPsbtPlan(plan);
  if (inputsToSign !== undefined) {
    if (inputsToSign.length === 0 || inputsToSign.length > PROVIDER_MAX_PSBT_INPUT_SELECTIONS ||
        inputsToSign.some((selection) => selection.signingIndexes.length === 0 ||
          selection.signingIndexes.length > PROVIDER_MAX_PSBT_INPUTS) ||
        new Set(inputsToSign.map((selection) => selection.address)).size !== inputsToSign.length) {
      throw new Error('provider signing declarations are invalid or duplicated');
    }
  }
  const approved = plan.selectedInputIndexes ?? plan.marketplace?.selectedInputIndexes ??
    plan.inputs.map((item, index) => item.ownership === 'wallet' ? index : -1).filter((index) => index >= 0);
  const selected = inputsToSign === undefined
    ? [...approved]
    : inputsToSign.flatMap((entry) => entry.signingIndexes);
  const unique = new Set(selected);
  if (selected.length === 0 || unique.size !== selected.length) {
    throw new Error('provider signing indexes must be nonempty and unique');
  }
  const expected = [...approved].sort((a, b) => a - b);
  const actual = [...unique].sort((a, b) => a - b);
  if (expected.length !== actual.length || expected.some((index, position) => index !== actual[position])) {
    throw new Error('provider signing indexes differ from prepared plan');
  }
  for (const declaration of inputsToSign ?? []) {
    for (const index of declaration.signingIndexes) {
      const planned = plan.inputs[index];
      if (!planned || (declaration.sigHash !== undefined && planned.sighash !== declaration.sigHash)) {
        throw new Error('provider sighash declaration differs from prepared plan');
      }
    }
  }
  if (inputsToSign !== undefined) {
    assertSignInputBindings(plan.inputs, approved, plan.network, inputsToSign.map((selection) => ({
      address: selection.address,
      inputIndexes: selection.signingIndexes,
    })));
  }
  return selected;
}

function hash(value: string | Uint8Array): string {
  const bytes = typeof value === 'string' ? new TextEncoder().encode(value) : value;
  return bytesToHex(getCryptoProvider().sha256(bytes));
}

function canonical(value: unknown): unknown {
  if (typeof value === 'bigint') return value.toString();
  if (value instanceof Uint8Array) return bytesToHex(value);
  if (Array.isArray(value)) return value.map(canonical);
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .filter(([key]) => key !== 'planHash' && key !== 'bytesBase64')
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([key, child]) => [key, canonical(child)]),
    );
  }
  return value;
}

function providerTransactionCommitmentHash(plan: object): string {
  const {
    planHash: _planHash,
    transactionCommitmentHash: _transactionCommitmentHash,
    inscriptionPreviews: _inscriptionPreviews,
    approvalExplanation: _approvalExplanation,
    ...transaction
  } = plan as ProviderPsbtPlanV3;
  void _planHash;
  void _transactionCommitmentHash;
  void _inscriptionPreviews;
  void _approvalExplanation;
  return hash(JSON.stringify(canonical(transaction)));
}

function withoutSignatureFields(value: Record<string, unknown>): Record<string, unknown> {
  const {
    partialSig: _partialSig,
    tapKeySig: _tapKeySig,
    tapScriptSig: _tapScriptSig,
    finalScriptSig: _finalScriptSig,
    finalScriptWitness: _finalScriptWitness,
    ...unsigned
  } = value;
  void _partialSig;
  void _tapKeySig;
  void _tapScriptSig;
  void _finalScriptSig;
  void _finalScriptWitness;
  return unsigned;
}

function assertSignatureOnlyMutation(
  before: Transaction,
  after: Transaction,
  selected: readonly number[],
): void {
  const beforeGlobal = (before as unknown as { global: unknown }).global;
  const afterGlobal = (after as unknown as { global: unknown }).global;
  if (JSON.stringify(canonical(beforeGlobal)) !== JSON.stringify(canonical(afterGlobal))) {
    throw new Error('signed provider PSBT global metadata changed');
  }
  if (before.inputsLength !== after.inputsLength || before.outputsLength !== after.outputsLength) {
    throw new Error('signed provider PSBT shape changed');
  }
  for (let index = 0; index < before.inputsLength; index += 1) {
    const a = JSON.stringify(canonical(withoutSignatureFields(before.getInput(index) as Record<string, unknown>)));
    const b = JSON.stringify(canonical(withoutSignatureFields(after.getInput(index) as Record<string, unknown>)));
    if (a !== b) throw new Error('signed provider PSBT metadata changed');
    if (!selected.includes(index) &&
        JSON.stringify(canonical(before.getInput(index))) !== JSON.stringify(canonical(after.getInput(index)))) {
      throw new Error('unselected provider input changed');
    }
  }
  for (let index = 0; index < before.outputsLength; index += 1) {
    if (JSON.stringify(canonical(before.getOutput(index))) !== JSON.stringify(canonical(after.getOutput(index)))) {
      throw new Error('signed provider PSBT output metadata changed');
    }
  }
}

function sourceFacts(classification: UtxoClassification) {
  return {
    primaryClass: classification.primaryClass,
    inscriptions: classification.inscriptions,
    satRanges: classification.satRanges,
    unsupportedAssetDetected: classification.unsupportedAssetDetected,
    confidence: classification.confidence,
    classifiedTip: classification.classifiedTip,
    classificationRevision: classification.classificationRevision,
  };
}

function previousOutput(tx: Transaction, index: number): { valueSats: bigint; scriptPubKey: string } {
  const input = tx.getInput(index);
  let witness = input.witnessUtxo;
  if (input.nonWitnessUtxo) {
    const previous = Transaction.fromRaw(RawTx.encode(input.nonWitnessUtxo));
    if (!input.txid || previous.id !== bytesToHex(input.txid)) throw new Error('non-witness transaction id mismatch');
    const output = input.index === undefined ? undefined : previous.getOutput(input.index);
    if (!output?.script || output.amount === undefined) throw new Error('non-witness prevout missing');
    const decoded = { valueSats: output.amount, scriptPubKey: bytesToHex(output.script) };
    if (witness && (witness.amount !== decoded.valueSats || bytesToHex(witness.script) !== decoded.scriptPubKey)) {
      throw new Error('witness and non-witness prevouts disagree');
    }
    witness = { amount: decoded.valueSats, script: output.script };
  }
  if (!witness) policyError('missing_prevout', 'PSBT input is missing its previous output');
  return { valueSats: witness.amount, scriptPubKey: bytesToHex(witness.script) };
}

function outputAddress(tx: Transaction, index: number, network: Network): string | null {
  try {
    return tx.getOutputAddress(index, bitcoinNetwork(network)) ?? null;
  } catch {
    return null;
  }
}

export function createProviderPsbtPlan(input: {
  psbtBase64: string;
  binding: ProviderAuthorityBinding;
  network: Network;
  vaultId: string;
  sessionId: string;
  accountId: string;
  account: number;
  classifications: UtxoClassification[];
  walletInputs: WalletPsbtInput[];
  source: TransactionPlan['source'];
  broadcast: boolean;
  planId: string;
  now: number;
  kind?: ProviderPsbtPlanV3['kind'];
  walletOutputs?: Array<{ scriptPubKey: string; output: PlanOutput }>;
  protectedSatFlow?: TransactionPlan['protectedSatFlow'];
  requiresAdvanced?: boolean;
  expiresAt?: number;
  selectedInputIndexes?: number[];
  signInputBindings?: ProviderSignInputBinding[];
  communityVaultAcquisition?: CommunityVaultAcquisitionProviderReviewV1;
  communityVaultSale?: CommunityVaultSaleProviderReviewV1;
  communityVaultSaleBuyer?: CommunityVaultSaleBuyerProviderReviewV1;
  communityVaultPositionTransfer?: CommunityVaultPositionTransferProviderReviewV1;
  marketplace?: {
    context: MarketplaceContext;
    resolution: MarketplaceResolution;
    selectedInputIndexes?: number[];
  };
  linkedGroup?: {
    groupId: string;
    nodeId: string;
    preparationHash: string;
    inputProvenance: ProviderPsbtInputClassificationProvenanceV1[];
  };
}): ProviderPsbtPlanV5 {
  const specialContexts = [
    input.marketplace,
    input.communityVaultAcquisition,
    input.communityVaultSale,
    input.communityVaultSaleBuyer,
    input.communityVaultPositionTransfer,
  ]
    .filter((candidate) => candidate !== undefined);
  if (specialContexts.length > 1) {
    throw new Error('marketplace and Community Vault plans are mutually exclusive');
  }
  if ((input.communityVaultAcquisition || input.communityVaultSale || input.communityVaultSaleBuyer ||
      input.communityVaultPositionTransfer) &&
      (input.network !== 'mainnet' || input.broadcast)) {
    throw new Error('Community Vault signing is mainnet-only and never broadcasts');
  }
  if (!new RegExp(`^acct_${input.network}_[0-9a-f]{64}$`, 'u').test(input.accountId)) {
    throw new Error('provider public account identity differs from network');
  }
  if (input.linkedGroup && (input.binding.providerMethod !== 'signMultipleTransactions' ||
      !input.linkedGroup.groupId || input.linkedGroup.groupId.length > 128 ||
      !input.linkedGroup.nodeId || input.linkedGroup.nodeId.length > 128 ||
      !/^[0-9a-f]{64}$/u.test(input.linkedGroup.preparationHash))) {
    throw new Error('linked provider plan identity is invalid');
  }
  const decoded = base64ToBytes(input.psbtBase64);
  if (bytesToBase64(decoded) !== input.psbtBase64) throw new Error('non-canonical PSBT base64');
  const tx = Transaction.fromPSBT(decoded, {
    lowR: true,
    allowUnknownInputs: true,
    allowUnknownOutputs: true,
  });
  const rawPsbtVersion = tx.opts.PSBTVersion;
  if (rawPsbtVersion !== 0 && rawPsbtVersion !== 2) throw new Error('unsupported PSBT version');
  const psbtVersion: 0 | 2 = rawPsbtVersion;
  assertProviderPsbtItemCounts(tx);
  if (tx.inputsLength === 0 || tx.outputsLength === 0) throw new Error('empty PSBT');
  const byOutpoint = new Map(input.classifications.map((item) => [`${item.txid}:${item.vout}`, item]));
  if (byOutpoint.size !== input.classifications.length) throw new Error('duplicate gateway classification');
  if (input.linkedGroup && input.linkedGroup.inputProvenance.length !== tx.inputsLength) {
    throw new Error('linked provider input provenance partition is incomplete');
  }
  const wallet = new Map(input.walletInputs.map((item) => [item.outpoint, item.derivation]));
  if ([...wallet.values()].some((derivation) =>
    derivation.accountId !== input.accountId || derivation.account !== input.account)) {
    throw new Error('provider wallet input public account identity mismatch');
  }
  if (input.walletOutputs?.some(({ output }) => {
    const derivation = output.derivation;
    const change = output.role === 'payment_change' || output.role === 'ordinal_change';
    return (change && derivation === undefined) ||
      (derivation !== undefined &&
        (derivation.accountId !== input.accountId || derivation.account !== input.account));
  })) {
    throw new Error('provider wallet output public account identity mismatch');
  }
  const marketplaceTemplate = input.marketplace ? templateForResolution(input.marketplace.resolution) : null;
  const marketplaceRule = marketplaceTemplate?.steps.find((rule) => rule.step === input.marketplace!.context.step) ??
    (marketplaceTemplate?.stepCount === 'context' ? marketplaceTemplate.steps[0] : undefined);
  const selectedMarketplaceIndexes = input.marketplace?.selectedInputIndexes === undefined
    ? []
    : [...new Set(input.marketplace.selectedInputIndexes)].sort((a, b) => a - b);
  const requestedIndexes = input.marketplace
    ? selectedMarketplaceIndexes
    : input.selectedInputIndexes === undefined
      ? undefined
      : [...new Set(input.selectedInputIndexes)].sort((a, b) => a - b);
  if (input.communityVaultAcquisition &&
      JSON.stringify(requestedIndexes ?? []) !==
        JSON.stringify(input.communityVaultAcquisition.selectedInputIndexes)) {
    throw new Error('Community Vault acquisition signer indexes changed');
  }
  if (input.communityVaultSale &&
      JSON.stringify(requestedIndexes ?? []) !==
        JSON.stringify(input.communityVaultSale.selectedInputIndexes)) {
    throw new Error('Community Vault sale signer indexes changed');
  }
  if (input.communityVaultSaleBuyer &&
      JSON.stringify(requestedIndexes ?? []) !==
        JSON.stringify(input.communityVaultSaleBuyer.selectedInputIndexes)) {
    throw new Error('Community Vault buyer signer indexes changed');
  }
  if (input.communityVaultPositionTransfer &&
      JSON.stringify(requestedIndexes ?? []) !==
        JSON.stringify(input.communityVaultPositionTransfer.selectedInputIndexes)) {
    throw new Error('Community Vault position-transfer signer indexes changed');
  }
  if (input.marketplace && (!marketplaceTemplate || !marketplaceRule || input.marketplace.resolution.status !== 'recognized')) {
    throw new Error('marketplace template resolution changed');
  }
  if (input.marketplace && marketplaceTemplate && (
    !marketplaceTemplate.origins.includes(input.binding.origin) ||
    !marketplaceTemplate.networks.includes(input.network) ||
    marketplaceTemplate.marketplaceId !== input.marketplace.context.marketplaceId ||
    marketplaceTemplate.templateVersion !== input.marketplace.context.templateVersion ||
    marketplaceTemplate.action !== input.marketplace.context.action ||
    marketplaceTemplate.role !== input.marketplace.context.role ||
    marketplaceTemplate.assetKind !== input.marketplace.context.assetKind
  )) throw new Error('marketplace authority or context differs from the pinned template');
  if (input.marketplace && input.broadcast !== (input.marketplace.context.broadcaster === 'wallet')) {
    throw new Error('marketplace broadcaster differs from the provider broadcast request');
  }
  const marketplaceCommitment = input.marketplace
    ? analyzeMarketplaceCommitment({
        psbtBase64: input.psbtBase64,
        network: input.network,
        context: input.marketplace.context,
        selectedInputIndexes: selectedMarketplaceIndexes,
      })
    : null;
  const planInputs: ProviderPsbtInput[] = [];
  const consumedOutpoints = new Set<string>();
  for (let index = 0; index < tx.inputsLength; index += 1) {
    const actual = tx.getInput(index);
    if (!actual.txid || actual.index === undefined) throw new Error('PSBT input outpoint missing');
    const txid = bytesToHex(actual.txid);
    const outpoint = `${txid}:${actual.index}`;
    if (consumedOutpoints.has(outpoint)) throw new Error('duplicate PSBT input');
    consumedOutpoints.add(outpoint);
    const classification = byOutpoint.get(outpoint);
    if (!classification) throw new Error('gateway did not classify every input');
    if (classification.confidence !== 'authoritative' ||
        classification.classificationRevision !== input.source.classificationRevision ||
        classification.classifiedTip.height !== input.source.coreTip.height ||
        classification.classifiedTip.hash !== input.source.coreTip.hash) {
      throw new Error('gateway classification is not current and authoritative');
    }
    const previous = previousOutput(tx, index);
    if (
      classification.valueSats !== previous.valueSats.toString() ||
      classification.scriptPubKey !== previous.scriptPubKey
    ) throw new Error('signed classification differs from PSBT prevout');
    const derivation = wallet.get(outpoint) ?? null;
    const linkedProvenance = input.linkedGroup?.inputProvenance[index];
    const linkedControl = linkedProvenance?.kind === 'linked_output'
      ? linkedProvenance.walletControl : undefined;
    if (derivation) {
      if (actual.tapLeafScript?.length) {
        const marketplaceAllowed = input.marketplace && marketplaceTemplate?.marketplaceId === 'ordnet' &&
          marketplaceRule?.allowTaprootScriptPath;
        if ((!marketplaceAllowed && linkedControl !== 'ordnet_sale_script_path') ||
            derivation.lane !== 'ordinals') throw new Error('Taproot script-path signing is unsupported');
        verifyOrdnetSaleScriptPath(tx, index, derivation.publicKeyHex.slice(2));
      } else if (scriptPubKeyHex(derivation.publicKeyHex, derivation.lane, input.network) !== previous.scriptPubKey) {
        const marketplaceAllowed = input.marketplace && marketplaceTemplate?.marketplaceId === 'ordnet' &&
          marketplaceRule?.allowTaprootTreeKeyPath;
        if ((!marketplaceAllowed && linkedControl !== 'ordnet_sale_key_path') || derivation.lane !== 'ordinals') {
          throw new Error('wallet ownership proof mismatch');
        }
        verifyOrdnetSaleKeyPath(tx, index, derivation.publicKeyHex.slice(2));
      }
    }
    const inputScriptType = providerInputScriptType(previous.scriptPubKey);
    if (derivation && inputScriptType !== 'p2wpkh' && inputScriptType !== 'p2tr') {
      policyError('unsupported_wallet_script', 'wallet-owned provider input uses an unsupported script path');
    }
    const sighash = actual.sighashType ?? (inputScriptType === 'p2tr' ? SigHash.DEFAULT : SigHash.ALL);
    const decodedSighash = decodeSighash(sighash, index, tx.outputsLength);
    if (!decodedSighash.validEncoding) {
      policyError('invalid_sighash', `input ${index} uses an invalid or reserved sighash encoding`);
    }
    const selectedForSigning = requestedIndexes?.includes(index) ?? Boolean(derivation);
    if (selectedForSigning && derivation) {
      if (decodedSighash.outputMode === 'none') {
        policyError('sighash_none', `input ${index} does not commit to a destination`);
      }
      if (decodedSighash.outputMode === 'single' && decodedSighash.committedOutputIndexes.length === 0) {
        policyError('single_missing_output', `input ${index} uses SINGLE without a corresponding output`);
      }
      const ordinaryAllowed = inputScriptType === 'p2wpkh'
        ? [SigHash.ALL, SigHash.SINGLE, SigHash.ALL_ANYONECANPAY, SigHash.SINGLE_ANYONECANPAY]
        : [SigHash.DEFAULT, SigHash.ALL, SigHash.SINGLE, SigHash.ALL_ANYONECANPAY,
            SigHash.SINGLE_ANYONECANPAY];
      const allowedSighashes = input.marketplace
        ? selectedMarketplaceIndexes.includes(index) ? marketplaceRule!.allowedSighashes : ordinaryAllowed
        : ordinaryAllowed;
      if (!allowedSighashes.includes(sighash)) {
        policyError('invalid_sighash', `input ${index} uses a sighash unsupported by its wallet script`);
      }
    }
    if (actual.tapLeafScript?.length && derivation && !marketplaceRule?.allowTaprootScriptPath &&
        linkedControl !== 'ordnet_sale_script_path') {
      throw new Error('Taproot script-path signing is unsupported');
    }
    planInputs.push({
      txid,
      vout: actual.index,
      valueSats: previous.valueSats,
      scriptPubKey: previous.scriptPubKey,
      sequence: actual.sequence ?? 0xffffffff,
      sighash: sighash as ProviderPsbtSighash,
      scriptType: inputScriptType,
      ownership: derivation ? 'wallet' : 'external',
      derivation,
      classification: sourceFacts(classification),
    });
  }
  const outputs: ProviderPsbtOutput[] = [];
  for (let index = 0; index < tx.outputsLength; index += 1) {
    const output = tx.getOutput(index);
    if (!output.script || output.amount === undefined) throw new Error('PSBT output missing');
    const scriptPubKey = bytesToHex(output.script);
    const outputScriptType = providerOutputScriptType(scriptPubKey, output.amount);
    const decodedAddress = outputScriptType === 'op_return' ? null : outputAddress(tx, index, input.network);
    if (outputScriptType !== 'op_return' && decodedAddress === null) {
      policyError('unknown_output_script', `output ${index} address cannot be decoded`);
    }
    const owned = input.walletOutputs?.find((item) => item.scriptPubKey === scriptPubKey)?.output;
    outputs.push(owned
      ? { ...owned, valueSats: output.amount, scriptPubKey, scriptType: outputScriptType }
      : {
          valueSats: output.amount,
          scriptPubKey,
          scriptType: outputScriptType,
          address: decodedAddress,
          role: outputScriptType === 'op_return' ? 'data' : 'recipient',
        });
  }
  if (input.marketplace) {
    assertMarketplaceWalletInputs({
      planInputs,
      selectedInputIndexes: selectedMarketplaceIndexes,
      context: input.marketplace.context,
    });
  }
  const selectedInputIndexes = requestedIndexes ?? planInputs
    .map((item, index) => item.ownership === 'wallet' ? index : -1)
    .filter((index) => index >= 0);
  const communitySaleIndexes = new Set([
    ...(input.communityVaultSale?.selectedInputIndexes ?? []),
    ...(input.communityVaultPositionTransfer?.role === 'owner'
      ? input.communityVaultPositionTransfer.selectedInputIndexes : []),
  ]);
  if (selectedInputIndexes.length === 0 || selectedInputIndexes.some((index) =>
    !planInputs[index] || (planInputs[index]!.ownership !== 'wallet' && !communitySaleIndexes.has(index)))) {
    throw new Error('requested input is not owned by the active account');
  }
  assertSignInputBindings(planInputs, selectedInputIndexes, input.network, input.signInputBindings);
  // §21.1 generic listing: without a recognized marketplace template, a wallet
  // input may carry a flexible sighash only when every wallet guarantee is
  // proven from the PSBT itself. The ordinary contextless path remains exactly
  // one signature. A prepared linked ord.net alternative may contain multiple
  // signatures only when Core already proved every selected internal outpoint
  // uses the pinned sale tree: script-path SINGLE|ANYONECANPAY for settlement,
  // or key-path ALL|ANYONECANPAY for recovery. Those provisional plans cannot
  // be signed outside a group, and the group validator must still prove the
  // unique settlement/recovery alternative before any signature is released.
  const flexibleIndexes = selectedInputIndexes.filter((index) =>
    planInputs[index]!.sighash === SigHash.SINGLE ||
    planInputs[index]!.sighash === SigHash.ALL_ANYONECANPAY ||
    planInputs[index]!.sighash === SigHash.SINGLE_ANYONECANPAY);
  const genericFlexibleIndexes = input.marketplace ? [] : flexibleIndexes.filter((index) =>
    planInputs[index]!.classification.inscriptions.length > 0);
  const linkedOrdSettlement = input.marketplace === undefined && input.linkedGroup !== undefined &&
    selectedInputIndexes.length > 0 && selectedInputIndexes.every((index) =>
      planInputs[index]?.sighash === SigHash.SINGLE_ANYONECANPAY &&
      input.linkedGroup!.inputProvenance[index]?.kind === 'linked_output' &&
      input.linkedGroup!.inputProvenance[index].walletControl === 'ordnet_sale_script_path');
  const linkedOrdRecovery = input.marketplace === undefined && input.linkedGroup !== undefined &&
    selectedInputIndexes.length > 0 && selectedInputIndexes.every((index) =>
      planInputs[index]?.sighash === SigHash.ALL_ANYONECANPAY &&
      input.linkedGroup!.inputProvenance[index]?.kind === 'linked_output' &&
      input.linkedGroup!.inputProvenance[index].walletControl === 'ordnet_sale_key_path');
  const linkedOrdAlternativeLeg = linkedOrdSettlement || linkedOrdRecovery;
  let genericCommitment: MarketplaceCommitmentAnalysis | null = null;
  if (genericFlexibleIndexes.length > 0) {
    if (input.broadcast) {
      throw new Error('generic listing may not request wallet broadcast');
    }
    if (!linkedOrdAlternativeLeg &&
        (genericFlexibleIndexes.length !== 1 || selectedInputIndexes.length !== 1)) {
      policyError(
        'generic_listing_multiple_signatures',
        'generic flexible inscription signing requires exactly one selected wallet signature',
      );
    }
    if (genericFlexibleIndexes.length !== selectedInputIndexes.length) {
      throw new Error('generic listing may not mix flexible and deterministic wallet signatures');
    }
    for (let index = 0; index < planInputs.length; index += 1) {
      if (planInputs[index]!.ownership === 'wallet' && !selectedInputIndexes.includes(index)) {
        throw new Error('generic listing contains an unapproved wallet input');
      }
    }
    for (const index of genericFlexibleIndexes) {
      const item = planInputs[index]!;
      if (item.classification.unsupportedAssetDetected || item.classification.satRanges !== null) {
        policyError('unsafe_protected_asset', 'generic listing may not spend unsupported-asset or rare-sat inputs');
      }
      if (item.sighash === SigHash.SINGLE || item.sighash === SigHash.SINGLE_ANYONECANPAY) {
        const corresponding = outputs[index];
        if (!corresponding?.derivation) {
          policyError('unsafe_protected_asset', 'generic listing payout must return to the active account');
        }
        if (corresponding.valueSats < item.valueSats) {
          policyError('unsafe_protected_asset', 'generic listing payout is below the listed input value');
        }
      }
    }
    const walletInSats = selectedInputIndexes.reduce((sum, index) => sum + planInputs[index]!.valueSats, 0n);
    const walletOutSats = outputs.reduce((sum, output) => output.derivation ? sum + output.valueSats : sum, 0n);
    if (!linkedOrdRecovery && walletOutSats < walletInSats) {
      policyError('unsafe_fee_exposure', 'generic listing does not guarantee the wallet value it spends');
    }
    if (linkedOrdRecovery && (outputs.length === 0 || outputs.some((output) => !output.derivation) ||
        walletOutSats >= walletInSats)) {
      policyError('unsafe_fee_exposure', 'linked recovery must return every output to the wallet less a positive fee');
    }
    genericCommitment = analyzeMarketplaceCommitment({
      psbtBase64: input.psbtBase64,
      network: input.network,
      context: {
        version: 1,
        marketplaceId: 'generic',
        templateVersion: 'generic',
        action: 'list',
        role: 'seller',
        assetKind: 'inscription',
        workflowId: input.planId,
        step: 1,
        stepCount: 1,
        broadcaster: 'site',
      },
      selectedInputIndexes: [...selectedInputIndexes],
    });
    if (linkedOrdRecovery) {
      // Every input and output in this provisional recovery leg is proven to
      // belong to the wallet, so its bounded positive debit is exactly its fee
      // even though ANYONECANPAY leaves room for later external inputs.
      genericCommitment.walletFeeExposureSats = walletInSats - walletOutSats;
    }
  }
  const flexibleCommitment = marketplaceCommitment ?? genericCommitment;
  const protectedSatFlow = input.protectedSatFlow ?? (input.marketplace || genericCommitment
    ? inferMarketplaceInscriptionFlows(planInputs, outputs)
    : inferExternalInscriptionFlows(planInputs, outputs));
  for (const index of genericFlexibleIndexes) {
    // A pinned linked settlement intentionally sells the inscription while
    // committing its corresponding payout. Its all-wallet recovery sibling,
    // proven by the group validator, is the asset-preservation branch.
    if (linkedOrdSettlement) continue;
    const protectedFlows = protectedSatFlow.filter((flow) => flow.inputIndex === index);
    if (protectedFlows.length === 0) {
      policyError('unsafe_protected_asset', 'generic listing protected asset destination is not provable');
    }
    const commitment = decodeSighash(planInputs[index]!.sighash, index, outputs.length).committedOutputIndexes;
    if (protectedFlows.some((flow) =>
      commitment !== 'all' && !commitment.includes(flow.outputIndex))) {
      policyError('unsafe_protected_asset', 'generic listing signature does not preserve the protected asset destination');
    }
  }
  const totalIn = planInputs.reduce((sum, item) => sum + item.valueSats, 0n);
  const totalOut = outputs.reduce((sum, item) => sum + item.valueSats, 0n);
  // Only a partial commitment may legitimately show outputs above inputs: the
  // counterparty's inputs are still missing. A zero-fee exact request is safe to
  // review only when every wallet input is selected, every selected signature
  // commits the complete transaction, the wallet will not broadcast it, and no
  // marketplace-flexible commitment is involved. This is deliberately generic:
  // it does not claim to recognize any marketplace business semantics.
  const selectedSet = new Set(selectedInputIndexes);
  const deferredZeroFee = flexibleCommitment === null && totalIn === totalOut && !input.broadcast &&
    (input.binding.providerMethod === 'signPsbt' ||
      input.binding.providerMethod === 'signMultipleTransactions') && selectedInputIndexes.length > 0 &&
    planInputs.every((planned, index) => planned.ownership !== 'wallet' || selectedSet.has(index)) &&
    selectedInputIndexes.every((index) => {
      const planned = planInputs[index];
      return planned?.ownership === 'wallet' && (planned.sighash === SigHash.DEFAULT || planned.sighash === SigHash.ALL);
    });
  if (flexibleCommitment?.mode !== 'partial' && (totalIn < totalOut ||
      (totalIn === totalOut && !deferredZeroFee))) {
    throw new Error('PSBT fee is not positive');
  }
  const feeSats = flexibleCommitment?.mode === 'partial'
    ? flexibleCommitment.walletFeeExposureSats
    : totalIn - totalOut;
  if (input.marketplace) {
    assertMarketplaceBuyerPlan({
      planInputs,
      outputs,
      protectedSatFlow,
      selectedInputIndexes: selectedMarketplaceIndexes,
      feeSats,
      context: input.marketplace.context,
    });
  }
  let vsize: bigint | null = null;
  try {
    vsize = estimateVsize(planInputs.map((item) => item.scriptPubKey), outputs.map((item) => item.scriptPubKey));
  } catch {
    vsize = null;
  }
  const feeRateSatPerKvB = vsize === null ? null : (feeSats * 1000n + vsize - 1n) / vsize;
  const psbt = decoded;
  const psbtHex = bytesToHex(psbt);
  const analysisResult = analyzePsbtHex(psbtHex, {
    network: input.network,
    account: input.account,
    kind: input.marketplace ? 'marketplace_psbt' :
      input.communityVaultAcquisition ? 'community_vault_acquisition' :
        input.communityVaultSale || input.communityVaultSaleBuyer || input.communityVaultPositionTransfer
          ? 'community_vault_sale' :
        input.kind ?? 'provider_psbt',
    source: input.source,
    inputs: planInputs,
    outputs,
    protectedSatFlow,
    feeSats,
    vsize,
    feeRateSatPerKvB,
    rbf: planInputs.some((item) => item.sequence < 0xfffffffe),
    providerPolicy: {
      selectedInputIndexes,
      allowedSighashesByInput: Object.fromEntries(selectedInputIndexes.map((index) =>
        [index, [planInputs[index]!.sighash]])),
      allowTaprootScriptPathInputIndexes: selectedInputIndexes.filter((index) =>
        input.linkedGroup?.inputProvenance[index]?.kind === 'linked_output' &&
        input.linkedGroup.inputProvenance[index].walletControl === 'ordnet_sale_script_path'),
      allowTaprootTreeKeyPathInputIndexes: selectedInputIndexes.filter((index) =>
        input.linkedGroup?.inputProvenance[index]?.kind === 'linked_output' &&
        input.linkedGroup.inputProvenance[index].walletControl === 'ordnet_sale_key_path'),
      // This is provisional only: linked plans cannot be signed alone, and the
      // group validator proves every contextless protected inscription has a
      // committed recovery branch before releasing any signature.
      permittedProtectedInputIndexes: input.linkedGroup ? selectedInputIndexes : [],
      deferredZeroFee,
    },
    ...(marketplaceCommitment ? { marketplace: {
      allowedSighashesByInput: Object.fromEntries(selectedMarketplaceIndexes.map((index) =>
        [index, marketplaceRule!.allowedSighashes])),
      allowTaprootScriptPathInputIndexes: marketplaceRule!.allowTaprootScriptPath
        ? selectedMarketplaceIndexes : [],
      allowTaprootTreeKeyPathInputIndexes: marketplaceRule!.allowTaprootTreeKeyPath
        ? selectedMarketplaceIndexes : [],
      permittedProtectedInputIndexes: selectedMarketplaceIndexes,
      commitment: marketplaceCommitment,
    } } : genericCommitment ? { marketplace: {
      // The generic listing pins each input to exactly the sighash the page
      // declared and validated above; no script path is ever permitted.
      allowedSighashesByInput: Object.fromEntries(genericFlexibleIndexes.map((index) =>
        [index, [planInputs[index]!.sighash]])),
      allowTaprootScriptPathInputIndexes: [],
      allowTaprootTreeKeyPathInputIndexes: [],
      permittedProtectedInputIndexes: genericFlexibleIndexes,
      commitment: genericCommitment,
    } } : {}),
  });
  if (!analysisResult.ok || analysisResult.analysis.hardViolations.length > 0) {
    throw new Error(`provider PSBT violates transaction safety policy${
      analysisResult.ok ? `: ${analysisResult.analysis.hardViolations.map((item) =>
        `${item.code}@${item.inputIndex ?? '-'}:${item.outputIndex ?? '-'}`).join(',')}` : ''
    }`);
  }
  if (input.broadcast && (vsize === null || planInputs.some((item) =>
    item.scriptType !== 'p2wpkh' && item.scriptType !== 'p2tr'))) {
    policyError('unsupported_wallet_script', 'wallet broadcast requires fully verifiable P2WPKH or P2TR inputs');
  }
  if (!input.marketplace && (input.kind ?? 'provider_psbt') === 'provider_psbt' && analysisResult.analysis.warnings.some(
    (warning) => warning.code === 'high_absolute_fee' || warning.code === 'high_relative_fee',
  )) {
    // Advanced signing may acknowledge an unknown deterministic business
    // template, but it never overrides the material-fee invariant (§16.3).
    throw new Error('provider PSBT has a non-overridable fee anomaly');
  }
  const communityPlan = Boolean(input.communityVaultAcquisition || input.communityVaultSale ||
    input.communityVaultSaleBuyer || input.communityVaultPositionTransfer);
  const approvalExplanation = communityPlan ? null : createProviderPsbtApprovalExplanation({
    selectedInputIndexes,
    inputs: planInputs,
    outputs,
    protectedSatFlow,
    inscriptionEffects: analysisResult.analysis.assetEffects.inscriptions,
    analysisWarnings: analysisResult.analysis.warnings,
    feeRateSatPerKvB,
    rbf: planInputs.some((item) => item.sequence < 0xfffffffe),
    broadcast: input.broadcast,
    ...(input.marketplace ? { marketplaceAction: input.marketplace.context.action } : {}),
    genericListing: genericCommitment !== null,
    ...((marketplaceCommitment ?? genericCommitment)?.guaranteedProceedsSats === undefined ? {} : {
      guaranteedProceedsSats: (marketplaceCommitment ?? genericCommitment)!.guaranteedProceedsSats,
    }),
  });
  const withoutHash = {
    version: 5 as const,
    planId: input.planId,
    createdAt: input.now,
    expiresAt: Math.min(input.now + 5 * 60_000, input.expiresAt ?? Number.MAX_SAFE_INTEGER),
    network: input.network,
    vaultId: input.vaultId,
    sessionId: input.sessionId,
    accountId: input.accountId,
    account: input.account,
    kind: input.marketplace ? 'marketplace_psbt' as const :
      input.communityVaultAcquisition ? 'community_vault_acquisition' as const :
        input.communityVaultSale || input.communityVaultSaleBuyer || input.communityVaultPositionTransfer
          ? 'community_vault_sale' as const :
        input.kind ?? 'provider_psbt',
    provider: input.binding,
    psbtVersion,
    broadcast: input.broadcast,
    requiresAdvanced: false,
    selectedInputIndexes,
    ...(genericCommitment ? { genericListing: {
      selectedInputIndexes: [...selectedInputIndexes],
      commitment: genericCommitment,
    } } : {}),
    inputs: planInputs,
    outputs,
    source: input.source,
    feeSats,
    deferredZeroFee,
    vsize,
    feeRateSatPerKvB,
    rbf: planInputs.some((item) => item.sequence < 0xfffffffe),
    protectedSatFlow,
    psbtHex,
    psbtHash: hash(psbt),
    analysis: analysisResult.analysis,
    analysisHash: analysisResult.analysisHash,
    approvalExplanation,
    ...(input.marketplace && marketplaceCommitment ? { marketplace: {
      context: input.marketplace.context,
      resolution: input.marketplace.resolution,
      selectedInputIndexes: selectedMarketplaceIndexes,
      commitment: marketplaceCommitment,
      allowTaprootScriptPath: marketplaceRule!.allowTaprootScriptPath,
      allowTaprootTreeKeyPath: marketplaceRule!.allowTaprootTreeKeyPath,
    } } : {}),
    ...(input.communityVaultAcquisition ? {
      communityVaultAcquisition: input.communityVaultAcquisition,
    } : {}),
    ...(input.communityVaultSale ? {
      communityVaultSale: input.communityVaultSale,
    } : {}),
    ...(input.communityVaultSaleBuyer ? {
      communityVaultSaleBuyer: input.communityVaultSaleBuyer,
    } : {}),
    ...(input.communityVaultPositionTransfer ? {
      communityVaultPositionTransfer: input.communityVaultPositionTransfer,
    } : {}),
    ...(input.linkedGroup ? { linkedGroup: {
      ...input.linkedGroup,
      inputProvenance: input.linkedGroup.inputProvenance.map((item) => ({ ...item })),
    } } : {}),
  };
  const transactionCommitmentHash = providerTransactionCommitmentHash(withoutHash);
  const inscriptionPreviews: StoredInscriptionPreviewSet | null =
    analysisResult.analysis.assetEffects.inscriptions.length === 0
      ? {
          transactionCommitmentHash,
          analysisHash: analysisResult.analysisHash,
          psbtHash: withoutHash.psbtHash,
          effectSetHash: analysisResult.analysis.assetEffects.effectSetHash,
          classificationRevision: input.source.classificationRevision,
          verifiedAtMs: input.now,
          items: [],
        }
      : null;
  const bound = { ...withoutHash, transactionCommitmentHash, inscriptionPreviews };
  return { ...bound, planHash: hash(JSON.stringify(canonical(bound))) };
}

export function bindProviderPsbtPlanPreviews(
  plan: ProviderPsbtPlanV3,
  previews: InscriptionPreviewSet,
): ProviderPsbtPlanV3 {
  if (providerTransactionCommitmentHash(plan) !== plan.transactionCommitmentHash ||
      previews.transactionCommitmentHash !== plan.transactionCommitmentHash ||
      previews.analysisHash !== plan.analysisHash || previews.psbtHash !== plan.psbtHash ||
      previews.effectSetHash !== plan.analysis.assetEffects.effectSetHash ||
      previews.classificationRevision !== plan.source.classificationRevision ||
      previews.items.length !== plan.analysis.assetEffects.inscriptions.length) {
    throw new Error('provider inscription previews differ from transaction plan');
  }
  approvalInscriptionItems(plan.analysis, previews);
  const descriptors = storedPreviewSet(previews);
  const withoutHash = { ...plan, inscriptionPreviews: descriptors };
  const rebound = {
    ...withoutHash,
    planHash: hash(JSON.stringify(canonical(withoutHash))),
  };
  liveProviderPreviews.set(rebound, cloneInscriptionPreviewSet(previews));
  return rebound;
}

export function providerPsbtPlanPreviews(plan: ProviderPsbtPlanV3): InscriptionPreviewSet {
  const previews = liveProviderPreviews.get(plan);
  if (!previews) {
    if (plan.inscriptionPreviews && plan.inscriptionPreviews.items.every(
      (item) => item.preview.disposition === 'placeholder',
    )) {
      return {
        ...plan.inscriptionPreviews,
        items: plan.inscriptionPreviews.items.map((item) => {
          if (item.preview.disposition !== 'placeholder') {
            throw new Error('provider raster bytes unavailable');
          }
          return {
            metadata: { ...item.metadata, outpoint: { ...item.metadata.outpoint } },
            preview: { ...item.preview, bytesBase64: null },
          };
        }),
      };
    }
    throw new Error('provider inscription preview bytes unavailable');
  }
  return cloneInscriptionPreviewSet(previews);
}

export function reattachProviderPsbtPlanPreviews(
  plan: ProviderPsbtPlanV3,
  previews: InscriptionPreviewSet,
): void {
  assertProviderPsbtPlan(plan);
  const stored = storedPreviewSet(previews);
  if (!plan.inscriptionPreviews ||
      JSON.stringify({ ...stored, verifiedAtMs: plan.inscriptionPreviews.verifiedAtMs }) !==
        JSON.stringify(plan.inscriptionPreviews)) {
    throw new Error('provider inscription preview provenance changed');
  }
  liveProviderPreviews.set(plan, cloneInscriptionPreviewSet(previews));
}

function signProviderPsbtPlanInternal(input: {
  plan: ProviderPsbtPlanV3;
  seed: Uint8Array;
  requestedInputIndexes?: number[];
  random: (length: number) => Uint8Array;
}, linkedGroup: ProviderPsbtPlanV3['linkedGroup'] | null): { psbtBase64: string; transactionHex?: string } {
  assertProviderPsbtPlan(input.plan);
  if (input.plan.linkedGroup && (!linkedGroup ||
      input.plan.linkedGroup.groupId !== linkedGroup.groupId ||
      input.plan.linkedGroup.nodeId !== linkedGroup.nodeId ||
      input.plan.linkedGroup.preparationHash !== linkedGroup.preparationHash)) {
    throw new Error('linked provider plan may only be signed by its validated group');
  }
  if (input.plan.genericListing && input.plan.broadcast) {
    throw new Error('generic listing may not request wallet broadcast');
  }
  if (publicAccountFromSeed(input.seed, input.plan.network, input.plan.account).accountId !==
      input.plan.accountId) {
    throw new Error('provider signer public account does not match transaction plan');
  }
  const approvedIndexes = input.plan.selectedInputIndexes ?? input.plan.marketplace?.selectedInputIndexes ??
    input.plan.inputs.map((item, index) => item.ownership === 'wallet' ? index : -1).filter((index) => index >= 0);
  const selected = input.requestedInputIndexes === undefined
    ? [...approvedIndexes]
    : [...new Set(input.requestedInputIndexes)];
  const expected = [...approvedIndexes].sort((a, b) => a - b);
  const actualSelected = [...selected].sort((a, b) => a - b);
  if (expected.length !== actualSelected.length || expected.some((index, position) => index !== actualSelected[position])) {
    throw new Error('provider signer indexes changed after approval');
  }
  const txOptions = { lowR: true, allowUnknownInputs: true, allowUnknownOutputs: true } as const;
  const tx = Transaction.fromPSBT(hexToBytes(input.plan.psbtHex), txOptions);
  const beforeSigning = Transaction.fromPSBT(hexToBytes(input.plan.psbtHex), txOptions);
  assertProviderPsbtItemCounts(tx);
  for (const index of selected) {
    const planned = input.plan.inputs[index];
    if (!planned || planned.ownership !== 'wallet' || !planned.derivation || planned.derivation.account !== input.plan.account) {
      throw new Error('requested input is not owned by the active account');
    }
    const derivation = planned.derivation;
    if (derivation.accountId !== input.plan.accountId) {
      throw new Error('provider input public account identity differs from plan');
    }
    const account = deriveAccountNode(input.seed, derivation.lane, input.plan.network, derivation.account);
    const chain = account.deriveChild(derivation.chain);
    const key = chain.deriveChild(derivation.index);
    try {
      if (!key.privateKey || !key.publicKey || bytesToHex(key.publicKey) !== derivation.publicKeyHex) {
        throw new Error('derived provider key mismatch');
      }
      const original = tx.getInput(index);
      const scriptPathInternalKey = original.tapLeafScript?.length ? original.tapInternalKey : undefined;
      if (scriptPathInternalKey) {
        // @scure otherwise creates both a tweaked key-path signature and the
        // requested script-path signature. This is the explicit equivalent of
        // disableTweakSigner; metadata is restored before serialization.
        tx.updateInput(
          index,
          { tapInternalKey: undefined } as unknown as Parameters<Transaction['updateInput']>[1],
          true,
        );
      }
      tx.signIdx(
        key.privateKey,
        index,
        [planned.sighash as SigHash],
        planned.derivation.lane === 'ordinals' ? input.random(32) : undefined,
      );
      if (scriptPathInternalKey) {
        tx.updateInput(
          index,
          { tapInternalKey: scriptPathInternalKey, tapKeySig: undefined } as unknown as
            Parameters<Transaction['updateInput']>[1],
          true,
        );
      }
    } finally {
      key.privateKey?.fill(0);
      key.wipePrivateData();
      chain.wipePrivateData();
      account.wipePrivateData();
    }
  }
  verifyProviderPartialSignatures(tx, input.plan, selected);
  assertSignatureOnlyMutation(beforeSigning, tx, selected);
  const signed = tx.toPSBT();
  const reparsed = analyzePsbtHex(bytesToHex(signed), {
    network: input.plan.network,
    account: input.plan.account,
    kind: input.plan.kind,
    source: input.plan.source,
    inputs: input.plan.inputs,
    outputs: input.plan.outputs,
    protectedSatFlow: input.plan.protectedSatFlow,
    feeSats: input.plan.feeSats,
    vsize: input.plan.vsize,
    feeRateSatPerKvB: input.plan.feeRateSatPerKvB,
    rbf: input.plan.rbf,
    providerPolicy: {
      selectedInputIndexes: selected,
      allowedSighashesByInput: Object.fromEntries(selected.map((index) =>
        [index, [input.plan.inputs[index]!.sighash]])),
      allowTaprootScriptPathInputIndexes: selected.filter((index) =>
        input.plan.linkedGroup?.inputProvenance[index]?.kind === 'linked_output' &&
        input.plan.linkedGroup.inputProvenance[index].walletControl === 'ordnet_sale_script_path'),
      allowTaprootTreeKeyPathInputIndexes: selected.filter((index) =>
        input.plan.linkedGroup?.inputProvenance[index]?.kind === 'linked_output' &&
        input.plan.linkedGroup.inputProvenance[index].walletControl === 'ordnet_sale_key_path'),
      permittedProtectedInputIndexes: input.plan.linkedGroup ? selected : [],
      deferredZeroFee: input.plan.deferredZeroFee,
    },
    ...(input.plan.marketplace ? { marketplace: {
      allowedSighashesByInput: Object.fromEntries(input.plan.marketplace.selectedInputIndexes.map((index) =>
        [index, [input.plan.inputs[index]!.sighash]])),
      allowTaprootScriptPathInputIndexes: input.plan.marketplace.allowTaprootScriptPath
        ? input.plan.marketplace.selectedInputIndexes : [],
      allowTaprootTreeKeyPathInputIndexes: input.plan.marketplace.allowTaprootTreeKeyPath
        ? input.plan.marketplace.selectedInputIndexes : [],
      permittedProtectedInputIndexes: input.plan.marketplace.selectedInputIndexes,
      commitment: input.plan.marketplace.commitment,
    } } : input.plan.genericListing ? { marketplace: {
      allowedSighashesByInput: Object.fromEntries(input.plan.genericListing.selectedInputIndexes.map((index) =>
        [index, [input.plan.inputs[index]!.sighash]])),
      allowTaprootScriptPathInputIndexes: [],
      allowTaprootTreeKeyPathInputIndexes: [],
      permittedProtectedInputIndexes: input.plan.genericListing.selectedInputIndexes,
      commitment: input.plan.genericListing.commitment,
    } } : {}),
  });
  if (!reparsed.ok || reparsed.analysisHash !== input.plan.analysisHash || reparsed.analysis.hardViolations.length > 0) {
    throw new Error('signed provider PSBT differs from approved analysis');
  }
  if (!input.plan.broadcast) return { psbtBase64: bytesToBase64(signed) };
  tx.finalize();
  const transactionHex = bytesToHex(tx.extract());
  validateProviderTransactionHex(input.plan, transactionHex);
  return { psbtBase64: bytesToBase64(signed), transactionHex };
}

export function signProviderPsbtPlan(input: {
  plan: ProviderPsbtPlanV3;
  seed: Uint8Array;
  requestedInputIndexes?: number[];
  random: (length: number) => Uint8Array;
}): { psbtBase64: string; transactionHex?: string } {
  if (input.plan.linkedGroup) {
    throw new Error('linked provider plan may only be signed by its validated group');
  }
  return signProviderPsbtPlanInternal(input, null);
}

/**
 * Sign a complete validated group without exposing any per-item signature.
 * The full graph is revalidated before signing and again before release.
 */
export async function signValidatedProviderPsbtGroupAtomically(input: {
  plan: ProviderPsbtGroupPlanV1;
  seed: Uint8Array;
  now: () => number;
  random: (length: number) => Uint8Array;
  guard?: () => void;
  yieldControl: () => Promise<void>;
}): Promise<SignedProviderPsbtGroupV1> {
  assertProviderPsbtGroupPlan(input.plan);
  const assertActive = (): void => {
    const now = input.now();
    if (!Number.isSafeInteger(now) || now < 0 || now >= input.plan.expiresAt) {
      throw new Error('provider group plan expired');
    }
  };
  assertActive();
  const byNodeId = new Map(input.plan.items.map((item) => [item.nodeId, item]));
  const signed = new Map<string, string>();
  for (const nodeId of input.plan.topology.topologicalNodeIds) {
    await input.yieldControl();
    assertActive();
    input.guard?.();
    const item = byNodeId.get(nodeId);
    if (!item) throw new Error('provider group topology differs from item order');
    const result = signProviderPsbtPlanInternal({
      plan: item.plan,
      seed: input.seed,
      requestedInputIndexes: item.requestedInputIndexes,
      random: input.random,
    }, item.plan.linkedGroup ?? null);
    if (result.transactionHex !== undefined) throw new Error('provider group may not broadcast');
    signed.set(nodeId, result.psbtBase64);
  }
  await input.yieldControl();
  assertActive();
  input.guard?.();
  assertProviderPsbtGroupPlan(input.plan);
  return {
    version: 1,
    groupHash: input.plan.groupHash,
    results: input.plan.items.map((item) => {
      const psbtBase64 = signed.get(item.nodeId);
      if (!psbtBase64) throw new Error('provider group signing did not complete atomically');
      return { nodeId: item.nodeId, psbtBase64 };
    }),
  };
}

export function assertProviderPsbtPlan(plan: ProviderPsbtPlanV3): void {
  if (!plan || plan.version !== 5 || !plan.inscriptionPreviews ||
      !new RegExp(`^acct_${plan.network}_[0-9a-f]{64}$`, 'u').test(plan.accountId) ||
      plan.inputs.some((input) => input.ownership === 'wallet' &&
        (input.derivation?.accountId !== plan.accountId || input.derivation.account !== plan.account)) ||
      plan.outputs.some((output) => output.derivation !== undefined &&
        (output.derivation.accountId !== plan.accountId || output.derivation.account !== plan.account)) ||
      !['provider_psbt', 'provider_transfer', 'provider_ordinal_transfer', 'marketplace_psbt',
        'community_vault_acquisition', 'community_vault_sale'].includes(plan.kind) ||
      !Array.isArray(plan.inputs) || !Array.isArray(plan.outputs) ||
      (plan.psbtVersion !== 0 && plan.psbtVersion !== 2) ||
      (plan.approvalExplanation === null &&
        !['community_vault_acquisition', 'community_vault_sale'].includes(plan.kind)) ||
      (plan.selectedInputIndexes !== undefined &&
        (!Array.isArray(plan.selectedInputIndexes) || plan.selectedInputIndexes.length === 0)) ||
      (plan.linkedGroup !== undefined && (plan.broadcast ||
        plan.provider.providerMethod !== 'signMultipleTransactions' ||
        !plan.linkedGroup.groupId || !plan.linkedGroup.nodeId ||
        !/^[0-9a-f]{64}$/u.test(plan.linkedGroup.preparationHash) ||
        plan.linkedGroup.inputProvenance.length !== plan.inputs.length)) ||
      providerTransactionCommitmentHash(plan) !== plan.transactionCommitmentHash ||
      plan.inscriptionPreviews.transactionCommitmentHash !== plan.transactionCommitmentHash ||
      plan.inscriptionPreviews.analysisHash !== plan.analysisHash ||
      plan.inscriptionPreviews.psbtHash !== plan.psbtHash ||
      plan.inscriptionPreviews.effectSetHash !== plan.analysis.assetEffects.effectSetHash ||
      plan.inscriptionPreviews.items.length !== plan.analysis.assetEffects.inscriptions.length ||
      hash(JSON.stringify(canonical(plan))) !== plan.planHash) {
    throw new Error('provider plan mutated');
  }
}

export function validateProviderTransactionHex(plan: ProviderPsbtPlanV3, transactionHex: string): string {
  assertProviderPsbtPlan(plan);
  const analyzed = analyzeRawTransactionHex(transactionHex, {
    network: plan.network, account: plan.account, kind: plan.kind, source: plan.source,
    inputs: plan.inputs, outputs: plan.outputs, protectedSatFlow: plan.protectedSatFlow, feeSats: plan.feeSats,
    vsize: plan.vsize, feeRateSatPerKvB: plan.feeRateSatPerKvB, rbf: plan.rbf,
    providerPolicy: {
      selectedInputIndexes: plan.selectedInputIndexes ?? [],
      allowedSighashesByInput: Object.fromEntries((plan.selectedInputIndexes ?? []).map((index) =>
        [index, [plan.inputs[index]!.sighash]])),
      deferredZeroFee: plan.deferredZeroFee,
    },
    ...(plan.marketplace ? { marketplace: {
      allowedSighashesByInput: Object.fromEntries(plan.marketplace.selectedInputIndexes.map((index) =>
        [index, [plan.inputs[index]!.sighash]])),
      allowTaprootScriptPathInputIndexes: plan.marketplace.allowTaprootScriptPath
        ? plan.marketplace.selectedInputIndexes : [],
      allowTaprootTreeKeyPathInputIndexes: plan.marketplace.allowTaprootTreeKeyPath
        ? plan.marketplace.selectedInputIndexes : [],
      permittedProtectedInputIndexes: plan.marketplace.selectedInputIndexes,
      commitment: plan.marketplace.commitment,
    } } : {}),
  });
  if (!analyzed.ok || analyzed.analysisHash !== plan.analysisHash || analyzed.analysis.hardViolations.length > 0) {
    throw new Error('provider transaction differs from approved analysis');
  }
  const tx = Transaction.fromRaw(hexToBytes(transactionHex));
  if (tx.inputsLength !== plan.inputs.length || tx.outputsLength !== plan.outputs.length) {
    throw new Error('provider transaction shape changed');
  }
  if (plan.vsize === null || BigInt(tx.vsize) > plan.vsize) {
    throw new Error('provider transaction exceeds approved vsize bound');
  }
  const scripts = plan.inputs.map((item) => hexToBytes(item.scriptPubKey));
  const amounts = plan.inputs.map((item) => item.valueSats);
  for (let index = 0; index < plan.inputs.length; index += 1) {
    const expected = plan.inputs[index]!;
    const witness = tx.getInput(index).finalScriptWitness ?? [];
    if (scriptKind(expected.scriptPubKey) === 'p2wpkh') {
      const signature = witness[0];
      const publicKey = witness[1];
      if (!signature || !publicKey || signature.at(-1) !== expected.sighash) {
        throw new Error('invalid provider P2WPKH witness');
      }
      const keyHash = expected.scriptPubKey.slice(4);
      const preimage = tx.preimageWitnessV0(
        index,
        hexToBytes(`76a914${keyHash}88ac`),
        expected.sighash,
        expected.valueSats,
      );
      if (scriptPubKeyHex(bytesToHex(publicKey), 'payment', plan.network) !== expected.scriptPubKey ||
          !secp256k1.verify(signature.slice(0, -1), preimage, publicKey, {
            format: 'der', prehash: false, lowS: true,
          })) throw new Error('invalid provider P2WPKH signature');
    } else {
      if (witness.length !== 1) throw new Error('unsupported provider Taproot witness');
      const signature = witness[0];
      if (!signature) throw new Error('invalid provider Taproot signature');
      const sighash = canonicalTaprootSignatureSighash(signature);
      if (sighash === null) throw new Error('invalid provider Taproot signature');
      if (sighash !== expected.sighash) throw new Error('provider Taproot witness sighash differs from plan');
      const preimage = tx.preimageWitnessV1(index, scripts, sighash, amounts);
      if (!schnorr.verify(signature.slice(0, 64), preimage, hexToBytes(expected.scriptPubKey).slice(2))) {
        throw new Error('invalid provider Taproot signature');
      }
    }
  }
  return tx.id;
}

function verifyProviderPartialSignatures(tx: Transaction, plan: ProviderPsbtPlanV3, indexes: number[]): void {
  const scripts = plan.inputs.map((item) => hexToBytes(item.scriptPubKey));
  const amounts = plan.inputs.map((item) => item.valueSats);
  for (const index of indexes) {
    const planned = plan.inputs[index]!;
    const actual = tx.getInput(index);
    if (!planned.derivation) throw new Error('missing signing derivation');
    if (planned.derivation.lane === 'payment') {
      const signed = actual.partialSig?.find(([pubkey]) => bytesToHex(pubkey) === planned.derivation!.publicKeyHex);
      if (!signed || signed[1].at(-1) !== planned.sighash) throw new Error('missing P2WPKH partial signature');
      const keyHash = planned.scriptPubKey.slice(4);
      const preimage = tx.preimageWitnessV0(
        index,
        hexToBytes(`76a914${keyHash}88ac`),
        planned.sighash,
        planned.valueSats,
      );
      if (!secp256k1.verify(signed[1].slice(0, -1), preimage, signed[0], {
        format: 'der', prehash: false, lowS: true,
      })) throw new Error('invalid P2WPKH partial signature');
    } else {
      if (actual.tapLeafScript?.length) {
        if (actual.tapLeafScript.length !== 1) throw new Error('unexpected Taproot leaf count');
        const scriptWithVersion = actual.tapLeafScript[0]![1];
        const script = scriptWithVersion.slice(0, -1);
        const version = scriptWithVersion.at(-1)!;
        const sellerKey = hexToBytes(planned.derivation.publicKeyHex).slice(1);
        const signed = actual.tapScriptSig?.find(([key]) => bytesToHex(key.pubKey) === bytesToHex(sellerKey));
        const sighash = signed ? canonicalTaprootSignatureSighash(signed[1]) : null;
        if (!signed || sighash === null || sighash !== planned.sighash) {
          throw new Error('missing Taproot script-path partial signature');
        }
        const preimage = tx.preimageWitnessV1(index, scripts, planned.sighash, amounts, undefined, script, version);
        if (!schnorr.verify(signed[1].slice(0, 64), preimage, sellerKey)) {
          throw new Error('invalid Taproot script-path partial signature');
        }
        continue;
      }
      const signature = actual.tapKeySig;
      if (!signature) throw new Error('missing Taproot signature');
      const sighash = canonicalTaprootSignatureSighash(signature);
      if (sighash === null) throw new Error('missing Taproot signature');
      if (sighash !== planned.sighash) throw new Error('Taproot sighash differs from plan');
      const preimage = tx.preimageWitnessV1(index, scripts, sighash, amounts);
      if (!schnorr.verify(signature.slice(0, 64), preimage, hexToBytes(planned.scriptPubKey).slice(2))) {
        throw new Error('invalid Taproot signature');
      }
    }
  }
}
