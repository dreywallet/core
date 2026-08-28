import { Transaction } from '@scure/btc-signer';
import { bytesToBase64, bytesToHex, hexToBytes } from '../vault/encoding';
import { getCryptoProvider } from '../vault/crypto-provider';
import {
  assertProviderPsbtPlan,
  resolveProviderPsbtInputSelections,
  signProviderPsbtPlan,
  type ProviderAuthorityBinding,
  type ProviderPsbtInputSelection,
  type ProviderPsbtPlanV3,
} from './provider-psbt';
import {
  PROVIDER_MAX_PSBT_BATCH_BASE64_CHARS,
  PROVIDER_MAX_PSBT_BATCH_INPUTS,
  PROVIDER_MAX_PSBT_BATCH_ITEMS,
  PROVIDER_MAX_PSBT_OUTPUTS,
} from './provider-psbt-limits';

export type ProviderBatchInputSelection = ProviderPsbtInputSelection;

export interface ProviderPsbtBatchItemV1 {
  plan: ProviderPsbtPlanV3;
  /** Exact Sats Connect declarations, in request order. */
  inputsToSign?: ProviderBatchInputSelection[];
  requestedInputIndexes: number[];
}

export interface ProviderPsbtBatchPlanV1 {
  version: 1;
  planId: string;
  createdAt: number;
  expiresAt: number;
  network: ProviderPsbtPlanV3['network'];
  vaultId: string;
  sessionId: string;
  accountId: string;
  account: number;
  provider: ProviderAuthorityBinding & { providerMethod: 'signMultipleTransactions' };
  approvalGeneration: number;
  requiresAdvanced: boolean;
  items: ProviderPsbtBatchItemV1[];
  aggregate: {
    encodedPsbtChars: number;
    inputs: number;
    outputs: number;
    walletInputSats: bigint;
    walletOutputSats: bigint;
    feeExposureSats: bigint;
  };
  batchHash: string;
}

function hash(value: unknown): string {
  return bytesToHex(getCryptoProvider().sha256(new TextEncoder().encode(JSON.stringify(value, (_key, child) =>
    typeof child === 'bigint' ? child.toString() : child))));
}

function sameAuthority(a: ProviderAuthorityBinding, b: ProviderAuthorityBinding): boolean {
  return a.origin === b.origin && a.tabId === b.tabId && a.frameId === b.frameId &&
    a.documentId === b.documentId && a.requestNonce === b.requestNonce &&
    a.providerMethod === b.providerMethod;
}

export function providerPsbtUnsignedTxid(plan: ProviderPsbtPlanV3): string {
  const unsigned = Transaction.fromPSBT(hexToBytes(plan.psbtHex), { lowR: true }).unsignedTx;
  const first = getCryptoProvider().sha256(unsigned);
  return bytesToHex(getCryptoProvider().sha256(first).reverse());
}

function selectedIndexes(
  plan: ProviderPsbtPlanV3,
  inputsToSign?: readonly ProviderBatchInputSelection[],
): number[] {
  return resolveProviderPsbtInputSelections(plan, inputsToSign);
}

function batchProjection(plan: Omit<ProviderPsbtBatchPlanV1, 'batchHash'>): unknown {
  return {
    version: plan.version,
    planId: plan.planId,
    createdAt: plan.createdAt,
    expiresAt: plan.expiresAt,
    network: plan.network,
    vaultId: plan.vaultId,
    sessionId: plan.sessionId,
    accountId: plan.accountId,
    account: plan.account,
    provider: plan.provider,
    approvalGeneration: plan.approvalGeneration,
    requiresAdvanced: plan.requiresAdvanced,
    aggregate: plan.aggregate,
    items: plan.items.map((item, index) => ({
      index,
      planHash: item.plan.planHash,
      psbtHash: item.plan.psbtHash,
      analysisHash: item.plan.analysisHash,
      transactionCommitmentHash: item.plan.transactionCommitmentHash,
      requestedInputIndexes: item.requestedInputIndexes,
      ...(item.inputsToSign === undefined ? {} : { inputsToSign: item.inputsToSign }),
    })),
  };
}

function validateItems(items: readonly ProviderPsbtBatchItemV1[]): ProviderPsbtBatchPlanV1['aggregate'] {
  if (items.length === 0 || items.length > PROVIDER_MAX_PSBT_BATCH_ITEMS) {
    throw new Error(`PSBT batch must contain 1-${PROVIDER_MAX_PSBT_BATCH_ITEMS} items`);
  }
  const psbtHashes = new Set<string>();
  const planIds = new Set<string>();
  const outpoints = new Set<string>();
  const transactionIds = new Set<string>();
  let encodedPsbtChars = 0;
  let inputs = 0;
  let outputs = 0;
  let walletInputSats = 0n;
  let walletOutputSats = 0n;
  let feeExposureSats = 0n;
  for (const item of items) {
    assertProviderPsbtPlan(item.plan);
    if (item.plan.broadcast || item.plan.provider.providerMethod !== 'signMultipleTransactions' ||
        item.plan.marketplace || item.plan.communityVaultAcquisition || item.plan.communityVaultSale ||
        item.plan.communityVaultSaleBuyer || item.plan.communityVaultPositionTransfer) {
      throw new Error('batch items must be generic, non-broadcast provider PSBTs');
    }
    if (psbtHashes.has(item.plan.psbtHash) || planIds.has(item.plan.planId)) {
      throw new Error('duplicate PSBT batch item');
    }
    psbtHashes.add(item.plan.psbtHash);
    planIds.add(item.plan.planId);
    const expectedIndexes = selectedIndexes(item.plan, item.inputsToSign);
    if (expectedIndexes.length !== item.requestedInputIndexes.length ||
        expectedIndexes.some((index, position) => index !== item.requestedInputIndexes[position])) {
      throw new Error('batch signing indexes differ from prepared selection');
    }
    const transactionId = providerPsbtUnsignedTxid(item.plan);
    if (transactionIds.has(transactionId)) {
      throw new Error('duplicate unsigned transaction in PSBT batch');
    }
    transactionIds.add(transactionId);
    encodedPsbtChars += bytesToBase64(hexToBytes(item.plan.psbtHex)).length;
    inputs += item.plan.inputs.length;
    outputs += item.plan.outputs.length;
    walletInputSats += item.plan.inputs.reduce((sum, input) =>
      input.ownership === 'wallet' ? sum + input.valueSats : sum, 0n);
    walletOutputSats += item.plan.outputs.reduce((sum, output) =>
      output.derivation ? sum + output.valueSats : sum, 0n);
    feeExposureSats += item.plan.feeSats;
    for (const input of item.plan.inputs) {
      const outpoint = `${input.txid}:${input.vout}`;
      if (outpoints.has(outpoint)) throw new Error('batch input outpoint is repeated');
      outpoints.add(outpoint);
    }
  }
  for (const item of items) {
    for (const input of item.plan.inputs) {
      if (transactionIds.has(input.txid)) throw new Error('batch contains an internally linked transaction');
    }
  }
  if (encodedPsbtChars > PROVIDER_MAX_PSBT_BATCH_BASE64_CHARS ||
      inputs > PROVIDER_MAX_PSBT_BATCH_INPUTS || outputs > PROVIDER_MAX_PSBT_OUTPUTS) {
    throw new Error('PSBT batch exceeds aggregate resource limits');
  }
  return { encodedPsbtChars, inputs, outputs, walletInputSats, walletOutputSats, feeExposureSats };
}

export function createProviderPsbtBatchPlan(input: {
  items: Array<{ plan: ProviderPsbtPlanV3; inputsToSign?: ProviderBatchInputSelection[] }>;
  planId: string;
  now: number;
  approvalGeneration: number;
}): ProviderPsbtBatchPlanV1 {
  const items = input.items.map((item) => ({
    ...item,
    requestedInputIndexes: selectedIndexes(item.plan, item.inputsToSign),
  }));
  const aggregate = validateItems(items);
  const first = items[0]!.plan;
  for (const { plan } of items.slice(1)) {
    if (plan.network !== first.network || plan.vaultId !== first.vaultId ||
        plan.sessionId !== first.sessionId || plan.accountId !== first.accountId ||
        plan.account !== first.account || !sameAuthority(plan.provider, first.provider)) {
      throw new Error('batch provider context differs between items');
    }
  }
  const withoutHash: Omit<ProviderPsbtBatchPlanV1, 'batchHash'> = {
    version: 1,
    planId: input.planId,
    createdAt: input.now,
    expiresAt: Math.min(...items.map((item) => item.plan.expiresAt)),
    network: first.network,
    vaultId: first.vaultId,
    sessionId: first.sessionId,
    accountId: first.accountId,
    account: first.account,
    provider: first.provider as ProviderPsbtBatchPlanV1['provider'],
    approvalGeneration: input.approvalGeneration,
    requiresAdvanced: items.some((item) => item.plan.requiresAdvanced),
    items,
    aggregate,
  };
  return { ...withoutHash, batchHash: hash(batchProjection(withoutHash)) };
}

export function assertProviderPsbtBatchPlan(plan: ProviderPsbtBatchPlanV1): void {
  if (!plan || plan.version !== 1 || !Number.isSafeInteger(plan.approvalGeneration) ||
      plan.approvalGeneration < 0 || plan.provider.providerMethod !== 'signMultipleTransactions') {
    throw new Error('provider batch plan mutated');
  }
  const aggregate = validateItems(plan.items);
  const first = plan.items[0]!.plan;
  if (plan.network !== first.network || plan.vaultId !== first.vaultId ||
      plan.sessionId !== first.sessionId || plan.accountId !== first.accountId ||
      plan.account !== first.account || !sameAuthority(plan.provider, first.provider) ||
      plan.expiresAt !== Math.min(...plan.items.map((item) => item.plan.expiresAt)) ||
      plan.requiresAdvanced !== plan.items.some((item) => item.plan.requiresAdvanced) ||
      JSON.stringify(aggregate, (_key, child) => typeof child === 'bigint' ? child.toString() : child) !==
        JSON.stringify(plan.aggregate, (_key, child) => typeof child === 'bigint' ? child.toString() : child) ||
      plan.items.some((item) => item.plan.network !== plan.network || item.plan.vaultId !== plan.vaultId ||
        item.plan.sessionId !== plan.sessionId || item.plan.accountId !== plan.accountId ||
        item.plan.account !== plan.account || !sameAuthority(item.plan.provider, plan.provider))) {
    throw new Error('provider batch plan mutated');
  }
  if (hash(batchProjection(plan)) !== plan.batchHash) throw new Error('provider batch plan mutated');
}

export async function signProviderPsbtBatchPlan(input: {
  plan: ProviderPsbtBatchPlanV1;
  seed: Uint8Array;
  now: number;
  random: (length: number) => Uint8Array;
  guard?: () => void;
  /** Lets the host process queued lock, disconnect, and approval-cancellation events. */
  yieldControl: () => Promise<void>;
}): Promise<Array<{ psbtBase64: string }>> {
  assertProviderPsbtBatchPlan(input.plan);
  if (input.now >= input.plan.expiresAt) throw new Error('provider batch plan expired');
  // No result escapes until every independent item has passed the same signer.
  const results: Array<{ psbtBase64: string }> = [];
  for (const item of input.plan.items) {
    await input.yieldControl();
    input.guard?.();
    const signed = signProviderPsbtPlan({
      plan: item.plan,
      seed: input.seed,
      requestedInputIndexes: item.requestedInputIndexes,
      random: input.random,
    });
    results.push({ psbtBase64: signed.psbtBase64 });
  }
  await input.yieldControl();
  input.guard?.();
  return results;
}
