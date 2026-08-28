import { z } from 'zod';
import { decodeSighash, type TransactionWarningCode } from './analysis';
import type { PlanDerivation, ProtectedSatFlow } from './plan';

export type ProviderPsbtPresentation = 'standard' | 'flexible';
export type ProviderPsbtIntent =
  | 'send_btc'
  | 'move_inscription'
  | 'list_inscription'
  | 'marketplace_action'
  | 'custom_transaction';
export type ProviderPsbtCommitmentState = 'fixed' | 'changeable' | 'unavailable';
export type ProviderPsbtOutputScriptType =
  | 'p2pkh'
  | 'p2sh'
  | 'p2wpkh'
  | 'p2wsh'
  | 'p2tr'
  | 'op_return';
export type ProviderPsbtInputScriptType = ProviderPsbtOutputScriptType | 'unknown';
export type ProviderPsbtWarningCode =
  | TransactionWarningCode
  | 'inputs_changeable'
  | 'outputs_changeable'
  | 'fee_changeable'
  | 'fee_rate_unavailable'
  | 'mixed_sighashes'
  | 'protected_asset';

export interface ProviderPsbtSighashExplanationV1 {
  inputIndex: number;
  raw: number;
  name: 'DEFAULT' | 'ALL' | 'ALL|ANYONECANPAY' | 'SINGLE' | 'SINGLE|ANYONECANPAY';
  inputSet: 'fixed' | 'changeable';
  outputs: 'all' | 'corresponding';
  correspondingOutputIndex: number | null;
  fee: 'fixed' | 'changeable';
}

export interface ProviderPsbtApprovalOutputV1 {
  index: number;
  valueSats: string;
  scriptPubKey: string;
  scriptType: ProviderPsbtOutputScriptType;
  address: string | null;
  ownership: 'wallet' | 'external';
  role: 'recipient' | 'payment_change' | 'ordinal_change' | 'postage' | 'data' | 'unknown';
  commitment: 'fixed' | 'changeable';
  guaranteed: boolean;
}

export interface ProviderPsbtAssetMovementV1 {
  inscriptionId: string;
  inputIndex: number;
  outputIndex: number;
  movement: 'received' | 'sent' | 'retained';
  destinationAddress: string | null;
  guaranteed: boolean;
}

/**
 * Portable, plan-hashed provider approval meaning. Platforms render this
 * value; they never independently infer transaction guarantees.
 */
export interface ProviderPsbtApprovalExplanationV1 {
  version: 1;
  presentation: ProviderPsbtPresentation;
  intent: ProviderPsbtIntent;
  currentWalletInputSats: string;
  currentWalletOutputSats: string;
  guaranteedWalletReturnSats: string;
  guaranteedProceedsSats: string;
  maximumWalletDebitSats: string;
  commitments: {
    inputs: 'fixed' | 'changeable';
    outputs: 'fixed' | 'changeable';
    fee: 'fixed' | 'changeable';
    feeRate: 'fixed' | 'unavailable';
  };
  sighashes: ProviderPsbtSighashExplanationV1[];
  outputs: ProviderPsbtApprovalOutputV1[];
  rbf: 'replaceable' | 'final';
  broadcastOwner: 'site' | 'wallet';
  assetMovements: ProviderPsbtAssetMovementV1[];
  warningCodes: ProviderPsbtWarningCode[];
  blockReasonCodes: [];
}

const satsSchema = z.string().regex(/^(0|[1-9][0-9]*)$/u);

/** Runtime boundary shared by every approval surface. */
export const providerPsbtApprovalExplanationSchema: z.ZodType<ProviderPsbtApprovalExplanationV1> =
  z.object({
    version: z.literal(1),
    presentation: z.enum(['standard', 'flexible']),
    intent: z.enum([
      'send_btc',
      'move_inscription',
      'list_inscription',
      'marketplace_action',
      'custom_transaction',
    ]),
    currentWalletInputSats: satsSchema,
    currentWalletOutputSats: satsSchema,
    guaranteedWalletReturnSats: satsSchema,
    guaranteedProceedsSats: satsSchema,
    maximumWalletDebitSats: satsSchema,
    commitments: z.object({
      inputs: z.enum(['fixed', 'changeable']),
      outputs: z.enum(['fixed', 'changeable']),
      fee: z.enum(['fixed', 'changeable']),
      feeRate: z.enum(['fixed', 'unavailable']),
    }).strict(),
    sighashes: z.array(z.object({
      inputIndex: z.number().int().nonnegative(),
      raw: z.union([z.literal(0), z.literal(1), z.literal(3), z.literal(129), z.literal(131)]),
      name: z.enum(['DEFAULT', 'ALL', 'ALL|ANYONECANPAY', 'SINGLE', 'SINGLE|ANYONECANPAY']),
      inputSet: z.enum(['fixed', 'changeable']),
      outputs: z.enum(['all', 'corresponding']),
      correspondingOutputIndex: z.number().int().nonnegative().nullable(),
      fee: z.enum(['fixed', 'changeable']),
    }).strict()).min(1).max(128),
    outputs: z.array(z.object({
      index: z.number().int().nonnegative(),
      valueSats: satsSchema,
      scriptPubKey: z.string().regex(/^(?:[0-9a-f]{2})+$/u),
      scriptType: z.enum(['p2pkh', 'p2sh', 'p2wpkh', 'p2wsh', 'p2tr', 'op_return']),
      address: z.string().nullable(),
      ownership: z.enum(['wallet', 'external']),
      role: z.enum(['recipient', 'payment_change', 'ordinal_change', 'postage', 'data', 'unknown']),
      commitment: z.enum(['fixed', 'changeable']),
      guaranteed: z.boolean(),
    }).strict()).min(1).max(128),
    rbf: z.enum(['replaceable', 'final']),
    broadcastOwner: z.enum(['site', 'wallet']),
    assetMovements: z.array(z.object({
      inscriptionId: z.string().min(1),
      inputIndex: z.number().int().nonnegative(),
      outputIndex: z.number().int().nonnegative(),
      movement: z.enum(['received', 'sent', 'retained']),
      destinationAddress: z.string().nullable(),
      guaranteed: z.boolean(),
    }).strict()).max(128),
    warningCodes: z.array(z.enum([
      'high_absolute_fee',
      'high_relative_fee',
      'fee_above_target',
      'inputs_changeable',
      'outputs_changeable',
      'fee_changeable',
      'fee_rate_unavailable',
      'mixed_sighashes',
      'protected_asset',
    ])).max(16),
    blockReasonCodes: z.tuple([]),
  }).strict().superRefine((value, context) => {
    if (value.outputs.some((output, index) => output.index !== index ||
        output.guaranteed !== (output.commitment === 'fixed'))) {
      context.addIssue({ code: z.ZodIssueCode.custom, message: 'PSBT output guarantees are inconsistent' });
    }
    const allOutputsFixed = value.sighashes.every((sighash) => sighash.outputs === 'all');
    if ((value.commitments.outputs === 'fixed') !== allOutputsFixed ||
        (value.presentation === 'standard') !==
          (value.commitments.inputs === 'fixed' && value.commitments.outputs === 'fixed')) {
      context.addIssue({ code: z.ZodIssueCode.custom, message: 'PSBT commitment summary is inconsistent' });
    }
    const names = new Map<number, string>([
      [0, 'DEFAULT'], [1, 'ALL'], [3, 'SINGLE'],
      [129, 'ALL|ANYONECANPAY'], [131, 'SINGLE|ANYONECANPAY'],
    ]);
    if (value.sighashes.some((sighash) => names.get(sighash.raw) !== sighash.name)) {
      context.addIssue({ code: z.ZodIssueCode.custom, message: 'PSBT sighash meaning is inconsistent' });
    }
  });

export interface ProviderPsbtApprovalInput {
  selectedInputIndexes: readonly number[];
  inputs: readonly {
    valueSats: bigint;
    ownership?: 'wallet' | 'external' | undefined;
    derivation: PlanDerivation | null;
    sighash: number;
    classification: { inscriptions: readonly { inscriptionId: string }[] };
  }[];
  outputs: readonly {
    valueSats: bigint;
    scriptPubKey: string;
    scriptType: ProviderPsbtOutputScriptType;
    address: string | null;
    role: ProviderPsbtApprovalOutputV1['role'];
    derivation?: PlanDerivation | undefined;
  }[];
  protectedSatFlow: readonly ProtectedSatFlow[];
  inscriptionEffects: readonly {
    inscriptionId: string;
    inputIndex: number;
    outputIndex: number;
    movement: 'received' | 'sent' | 'retained';
  }[];
  analysisWarnings: readonly { code: TransactionWarningCode }[];
  feeRateSatPerKvB: bigint | null;
  rbf: boolean;
  broadcast: boolean;
  marketplaceAction?: string | undefined;
  genericListing: boolean;
  guaranteedProceedsSats?: bigint | undefined;
}

function sighashName(raw: number): ProviderPsbtSighashExplanationV1['name'] {
  if (raw === 0) return 'DEFAULT';
  if (raw === 1) return 'ALL';
  if (raw === 3) return 'SINGLE';
  if (raw === 0x81) return 'ALL|ANYONECANPAY';
  if (raw === 0x83) return 'SINGLE|ANYONECANPAY';
  throw new Error('unsupported provider sighash explanation');
}

function intent(input: ProviderPsbtApprovalInput): ProviderPsbtIntent {
  if (input.genericListing || input.marketplaceAction === 'list') return 'list_inscription';
  if (input.marketplaceAction !== undefined) return 'marketplace_action';
  if (input.inscriptionEffects.some((effect) => effect.movement === 'sent')) return 'move_inscription';
  if (input.outputs.some((output) => output.role === 'recipient' && output.valueSats > 0n)) return 'send_btc';
  return 'custom_transaction';
}

function uniqueWarnings(values: readonly ProviderPsbtWarningCode[]): ProviderPsbtWarningCode[] {
  return [...new Set(values)];
}

/**
 * Compute guarantees across every selected signature. A site may return only
 * one signature to a future transaction, so an output is displayed as
 * guaranteed only when every returned signature commits to it.
 */
export function createProviderPsbtApprovalExplanation(
  input: ProviderPsbtApprovalInput,
): ProviderPsbtApprovalExplanationV1 {
  if (input.selectedInputIndexes.length === 0) throw new Error('provider approval has no selected inputs');
  const selected = input.selectedInputIndexes.map((index) => {
    const planInput = input.inputs[index];
    if (!planInput || planInput.ownership !== 'wallet') {
      throw new Error('provider approval selected input is not wallet-owned');
    }
    const decoded = decodeSighash(planInput.sighash, index, input.outputs.length);
    if (!decoded.validEncoding || decoded.outputMode === 'none' ||
        (decoded.outputMode === 'single' && decoded.committedOutputIndexes.length === 0)) {
      throw new Error('provider approval contains an unsafe sighash');
    }
    return { index, input: planInput, decoded };
  });
  const guaranteedOutputIndexes = input.outputs
    .map((_output, outputIndex) => selected.every(({ decoded }) =>
      decoded.committedOutputIndexes === 'all' || decoded.committedOutputIndexes.includes(outputIndex))
      ? outputIndex : -1)
    .filter((index) => index >= 0);
  const guaranteedSet = new Set(guaranteedOutputIndexes);
  const inputsFixed = selected.every(({ decoded }) => !decoded.anyoneCanPay);
  // SINGLE commits the corresponding current output, but it never fixes the
  // complete output set: other outputs can be added, removed, or replaced.
  const outputsFixed = selected.every(({ decoded }) => decoded.committedOutputIndexes === 'all');
  const feeFixed = inputsFixed && outputsFixed;
  const currentWalletInputSats = input.inputs.reduce((sum, planInput) =>
    planInput.ownership === 'wallet' ? sum + planInput.valueSats : sum, 0n);
  const currentWalletOutputSats = input.outputs.reduce((sum, output) =>
    output.derivation ? sum + output.valueSats : sum, 0n);
  const guaranteedWalletReturnSats = input.outputs.reduce((sum, output, index) =>
    output.derivation && guaranteedSet.has(index) ? sum + output.valueSats : sum, 0n);
  const maximumWalletDebitSats = currentWalletInputSats > guaranteedWalletReturnSats
    ? currentWalletInputSats - guaranteedWalletReturnSats : 0n;
  const sighashes = selected.map(({ index, input: planInput, decoded }) => ({
    inputIndex: index,
    raw: planInput.sighash,
    name: sighashName(planInput.sighash),
    inputSet: decoded.anyoneCanPay ? 'changeable' as const : 'fixed' as const,
    outputs: decoded.outputMode === 'single' ? 'corresponding' as const : 'all' as const,
    correspondingOutputIndex: decoded.outputMode === 'single' ? index : null,
    fee: decoded.anyoneCanPay || decoded.outputMode === 'single' ? 'changeable' as const : 'fixed' as const,
  }));
  const outputs: ProviderPsbtApprovalOutputV1[] = input.outputs.map((output, index) => ({
    index,
    valueSats: output.valueSats.toString(),
    scriptPubKey: output.scriptPubKey,
    scriptType: output.scriptType,
    address: output.address,
    ownership: output.derivation ? 'wallet' : 'external',
    role: output.role,
    commitment: guaranteedSet.has(index) ? 'fixed' : 'changeable',
    guaranteed: guaranteedSet.has(index),
  }));
  const assetMovements = input.inscriptionEffects.map((effect) => ({
    inscriptionId: effect.inscriptionId,
    inputIndex: effect.inputIndex,
    outputIndex: effect.outputIndex,
    movement: effect.movement,
    destinationAddress: input.outputs[effect.outputIndex]?.address ?? null,
    guaranteed: guaranteedSet.has(effect.outputIndex),
  }));
  const warningCodes: ProviderPsbtWarningCode[] = input.analysisWarnings.map((warning) => warning.code);
  if (!inputsFixed) warningCodes.push('inputs_changeable');
  if (!outputsFixed) warningCodes.push('outputs_changeable');
  if (!feeFixed) warningCodes.push('fee_changeable');
  if (input.feeRateSatPerKvB === null) warningCodes.push('fee_rate_unavailable');
  if (new Set(sighashes.map((item) => item.raw)).size > 1) warningCodes.push('mixed_sighashes');
  if (assetMovements.length > 0) warningCodes.push('protected_asset');
  return {
    version: 1,
    presentation: inputsFixed && outputsFixed ? 'standard' : 'flexible',
    intent: intent(input),
    currentWalletInputSats: currentWalletInputSats.toString(),
    currentWalletOutputSats: currentWalletOutputSats.toString(),
    guaranteedWalletReturnSats: guaranteedWalletReturnSats.toString(),
    guaranteedProceedsSats: (input.guaranteedProceedsSats ??
      (input.genericListing ? guaranteedWalletReturnSats : 0n)).toString(),
    maximumWalletDebitSats: maximumWalletDebitSats.toString(),
    commitments: {
      inputs: inputsFixed ? 'fixed' : 'changeable',
      outputs: outputsFixed ? 'fixed' : 'changeable',
      fee: feeFixed ? 'fixed' : 'changeable',
      feeRate: input.feeRateSatPerKvB === null ? 'unavailable' : 'fixed',
    },
    sighashes,
    outputs,
    rbf: input.rbf ? 'replaceable' : 'final',
    broadcastOwner: input.broadcast ? 'wallet' : 'site',
    assetMovements,
    warningCodes: uniqueWarnings(warningCodes),
    blockReasonCodes: [],
  };
}
