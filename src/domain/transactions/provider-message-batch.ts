import { publicAccountFromSeed } from '../accounts/public-account';
import { deriveAccountNode, deriveAddress, type AddressKind, type Network } from '../keys/derivation';
import { bytesToHex } from '../vault/encoding';
import { getCryptoProvider } from '../vault/crypto-provider';
import {
  bip322MessageHash,
  signBip322Simple,
  validateBip322Message,
  verifyBip322Simple,
} from './bip322';
import {
  PROVIDER_MAX_SIGN_MESSAGES,
  PROVIDER_MAX_SIGN_MESSAGE_BATCH_BYTES,
} from './provider-message-batch-limits';

export const PROVIDER_MESSAGE_BATCH_TTL_MS = 5 * 60_000;

export interface ProviderMessageBatchItemV1 {
  index: number;
  address: string;
  addressKind: AddressKind;
  message: string;
  messageBytes: number;
  messageHash: string;
  requestedProtocol: 'BIP322' | null;
  protocol: 'BIP322';
}

export interface ProviderMessageBatchPlanV1 {
  version: 1;
  planId: string;
  createdAt: number;
  expiresAt: number;
  network: Network;
  vaultId: string;
  sessionId: string;
  accountId: string;
  account: number;
  provider: {
    origin: string;
    tabId: number;
    frameId: number;
    documentId: string;
    requestNonce: string;
    providerMethod: 'signMultipleMessages';
  };
  approvalGeneration: number;
  totalMessageBytes: number;
  items: ProviderMessageBatchItemV1[];
  batchHash: string;
}

export interface ProviderSignedMessage {
  signature: string;
  message: string;
  messageHash: string;
  address: string;
  protocol: 'BIP322';
}

function hash(value: unknown): string {
  return bytesToHex(getCryptoProvider().sha256(
    new TextEncoder().encode(JSON.stringify(value)),
  ));
}

function projection(plan: Omit<ProviderMessageBatchPlanV1, 'batchHash'>): unknown {
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
    totalMessageBytes: plan.totalMessageBytes,
    items: plan.items,
  };
}

function validateItems(items: readonly ProviderMessageBatchItemV1[]): number {
  if (items.length === 0 || items.length > PROVIDER_MAX_SIGN_MESSAGES) {
    throw new Error(`message batch must contain 1-${PROVIDER_MAX_SIGN_MESSAGES} items`);
  }
  const seen = new Set<string>();
  let totalMessageBytes = 0;
  for (let index = 0; index < items.length; index += 1) {
    const item = items[index]!;
    const bytes = validateBip322Message(item.message);
    const expectedHash = bytesToHex(bip322MessageHash(bytes));
    if (item.index !== index || (item.addressKind !== 'payment' && item.addressKind !== 'ordinals') ||
        item.messageBytes !== bytes.length || item.messageHash !== expectedHash ||
        item.protocol !== 'BIP322' ||
        (item.addressKind === 'payment' && item.requestedProtocol !== 'BIP322') ||
        (item.requestedProtocol !== null && item.requestedProtocol !== 'BIP322')) {
      throw new Error('provider message batch item mutated');
    }
    const duplicateKey = `${item.address.length}:${item.address}:${bytes.length}:${item.message}`;
    if (seen.has(duplicateKey)) throw new Error('provider message batch contains a duplicate');
    seen.add(duplicateKey);
    totalMessageBytes += bytes.length;
  }
  if (totalMessageBytes > PROVIDER_MAX_SIGN_MESSAGE_BATCH_BYTES) {
    throw new Error('provider message batch exceeds aggregate byte limit');
  }
  return totalMessageBytes;
}

export function createProviderMessageBatchPlan(input: {
  requests: Array<{ address: string; message: string; protocol?: 'BIP322' }>;
  activeAddresses: Record<AddressKind, string>;
  planId: string;
  now: number;
  network: Network;
  vaultId: string;
  sessionId: string;
  accountId: string;
  account: number;
  provider: ProviderMessageBatchPlanV1['provider'];
  approvalGeneration: number;
}): ProviderMessageBatchPlanV1 {
  if (input.requests.length === 0 || input.requests.length > PROVIDER_MAX_SIGN_MESSAGES) {
    throw new Error(`message batch must contain 1-${PROVIDER_MAX_SIGN_MESSAGES} items`);
  }
  const items = input.requests.map((request, index): ProviderMessageBatchItemV1 => {
    const addressKind = request.address === input.activeAddresses.payment
      ? 'payment'
      : request.address === input.activeAddresses.ordinals
        ? 'ordinals'
        : null;
    if (addressKind === null) throw new Error('message signing address is not in the active account');
    // Sats Connect documents omitted protocol as ECDSA for P2WPKH. Drey is
    // BIP322-only, so payment-lane batches must request that protocol exactly.
    if (addressKind === 'payment' && request.protocol === undefined) {
      throw new Error('payment message signing must explicitly request BIP322');
    }
    const bytes = validateBip322Message(request.message);
    return {
      index,
      address: request.address,
      addressKind,
      message: request.message,
      messageBytes: bytes.length,
      messageHash: bytesToHex(bip322MessageHash(bytes)),
      requestedProtocol: request.protocol ?? null,
      protocol: 'BIP322',
    };
  });
  const totalMessageBytes = validateItems(items);
  const withoutHash: Omit<ProviderMessageBatchPlanV1, 'batchHash'> = {
    version: 1,
    planId: input.planId,
    createdAt: input.now,
    expiresAt: input.now + PROVIDER_MESSAGE_BATCH_TTL_MS,
    network: input.network,
    vaultId: input.vaultId,
    sessionId: input.sessionId,
    accountId: input.accountId,
    account: input.account,
    provider: input.provider,
    approvalGeneration: input.approvalGeneration,
    totalMessageBytes,
    items,
  };
  return { ...withoutHash, batchHash: hash(projection(withoutHash)) };
}

export function assertProviderMessageBatchPlan(plan: ProviderMessageBatchPlanV1): void {
  if (!plan || plan.version !== 1 || !Number.isSafeInteger(plan.approvalGeneration) ||
      plan.approvalGeneration < 0 || plan.provider.providerMethod !== 'signMultipleMessages' ||
      !Number.isSafeInteger(plan.createdAt) || plan.createdAt < 0 ||
      !Number.isSafeInteger(plan.expiresAt) ||
      plan.expiresAt !== plan.createdAt + PROVIDER_MESSAGE_BATCH_TTL_MS ||
      validateItems(plan.items) !== plan.totalMessageBytes ||
      hash(projection(plan)) !== plan.batchHash) {
    throw new Error('provider message batch plan mutated');
  }
}

/** Sign exactly one committed item. The host owns batch ordering and atomic delivery. */
export function signProviderMessageBatchItem(input: {
  plan: ProviderMessageBatchPlanV1;
  itemIndex: number;
  seed: Uint8Array;
  now: number;
  random: (length: number) => Uint8Array;
}): ProviderSignedMessage {
  assertProviderMessageBatchPlan(input.plan);
  if (input.now >= input.plan.expiresAt) throw new Error('provider message batch plan expired');
  const item = input.plan.items[input.itemIndex];
  if (!item || item.index !== input.itemIndex) throw new Error('provider message batch index changed');
  if (publicAccountFromSeed(input.seed, input.plan.network, input.plan.account).accountId !==
      input.plan.accountId) {
    throw new Error('message signing account changed');
  }
  const accountNode = deriveAccountNode(input.seed, item.addressKind, input.plan.network, input.plan.account);
  let chain: ReturnType<typeof accountNode.deriveChild> | undefined;
  let key: ReturnType<typeof accountNode.deriveChild> | undefined;
  try {
    chain = accountNode.deriveChild(0);
    key = chain.deriveChild(0);
    if (!key.privateKey) throw new Error('message signing key unavailable');
    const address = deriveAddress(accountNode, item.addressKind, input.plan.network, 0, 0).address;
    if (address !== item.address) throw new Error('message signing address changed');
    const signature = signBip322Simple({
      message: item.message,
      privateKey: key.privateKey,
      addressKind: item.addressKind,
      random: input.random,
    });
    if (!verifyBip322Simple(item.message, item.address, input.plan.network, signature)) {
      throw new Error('BIP322 post-sign verification failed');
    }
    return {
      signature,
      message: item.message,
      messageHash: item.messageHash,
      address: item.address,
      protocol: 'BIP322',
    };
  } finally {
    key?.privateKey?.fill(0);
    key?.wipePrivateData();
    chain?.wipePrivateData();
    accountNode.wipePrivateData();
  }
}

export function assertProviderMessageBatchResults(
  plan: ProviderMessageBatchPlanV1,
  results: readonly ProviderSignedMessage[],
): void {
  assertProviderMessageBatchPlan(plan);
  if (results.length !== plan.items.length) throw new Error('provider message batch result is incomplete');
  for (let index = 0; index < results.length; index += 1) {
    const result = results[index]!;
    const item = plan.items[index]!;
    if (result.message !== item.message || result.messageHash !== item.messageHash ||
        result.address !== item.address || result.protocol !== 'BIP322' ||
        !verifyBip322Simple(item.message, item.address, plan.network, result.signature)) {
      throw new Error('provider message batch result changed');
    }
  }
}
