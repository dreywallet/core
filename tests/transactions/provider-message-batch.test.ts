import { beforeAll, describe, expect, it } from 'vitest';
import { publicAccountFromSeed } from '../../src/domain/accounts/public-account';
import { deriveAccountNode, deriveAddress } from '../../src/domain/keys/derivation';
import { mnemonicToSeed } from '../../src/domain/keys/mnemonic';
import {
  assertProviderMessageBatchPlan,
  assertProviderMessageBatchResults,
  createProviderMessageBatchPlan,
  signProviderMessageBatchItem,
} from '../../src/domain/transactions/provider-message-batch';
import {
  PROVIDER_MAX_SIGN_MESSAGES,
  PROVIDER_MAX_SIGN_MESSAGE_BATCH_BYTES,
} from '../../src/domain/transactions/provider-message-batch-limits';
import { verifyBip322Simple } from '../../src/domain/transactions/bip322';
import { installTestCryptoProvider } from '../helpers/install-crypto-provider';

beforeAll(() => installTestCryptoProvider());

const NOW = 1_800_000_000_000;
const seed = mnemonicToSeed(
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
);
const publicAccount = publicAccountFromSeed(seed, 'signet', 0);
const paymentNode = deriveAccountNode(seed, 'payment', 'signet', 0);
const ordinalNode = deriveAccountNode(seed, 'ordinals', 'signet', 0);
const payment = deriveAddress(paymentNode, 'payment', 'signet', 0, 0).address;
const ordinals = deriveAddress(ordinalNode, 'ordinals', 'signet', 0, 0).address;
paymentNode.wipePrivateData();
ordinalNode.wipePrivateData();

const binding = {
  origin: 'https://app.example',
  tabId: 1,
  frameId: 0,
  documentId: '123e4567-e89b-42d3-a456-426614174000',
  requestNonce: '123e4567-e89b-42d3-a456-426614174001',
  providerMethod: 'signMultipleMessages' as const,
};

function create(overrides: Partial<Parameters<typeof createProviderMessageBatchPlan>[0]> = {}) {
  return createProviderMessageBatchPlan({
    requests: [
      { address: payment, message: 'payment challenge', protocol: 'BIP322' },
      { address: ordinals, message: 'ordinal challenge' },
    ],
    activeAddresses: { payment, ordinals },
    planId: 'message-batch-1',
    now: NOW,
    network: 'signet',
    vaultId: 'vault-1',
    sessionId: 'session-1',
    accountId: publicAccount.accountId,
    account: 0,
    provider: binding,
    approvalGeneration: 7,
    ...overrides,
  });
}

describe('provider message batch plan', () => {
  it('binds exact ordered messages, addresses, protocols, authority, and account context', () => {
    const plan = create();
    expect(() => assertProviderMessageBatchPlan(plan)).not.toThrow();
    expect(plan.items).toMatchObject([
      {
        index: 0, address: payment, addressKind: 'payment', message: 'payment challenge',
        requestedProtocol: 'BIP322', protocol: 'BIP322',
      },
      {
        index: 1, address: ordinals, addressKind: 'ordinals', message: 'ordinal challenge',
        requestedProtocol: null, protocol: 'BIP322',
      },
    ]);
    expect(plan.batchHash).toMatch(/^[0-9a-f]{64}$/u);

    for (const mutate of [
      (candidate: typeof plan) => { candidate.items.reverse(); },
      (candidate: typeof plan) => { candidate.items[0]!.message = 'changed'; },
      (candidate: typeof plan) => { candidate.provider.origin = 'https://other.example'; },
      (candidate: typeof plan) => { candidate.provider.documentId = 'changed-document'; },
      (candidate: typeof plan) => { candidate.provider.requestNonce = 'changed-nonce'; },
      (candidate: typeof plan) => { candidate.sessionId = 'session-2'; },
      (candidate: typeof plan) => { candidate.accountId = 'changed'; },
      (candidate: typeof plan) => { candidate.account += 1; },
      (candidate: typeof plan) => { candidate.network = 'mainnet'; },
      (candidate: typeof plan) => { candidate.approvalGeneration += 1; },
    ]) {
      const candidate = structuredClone(plan);
      mutate(candidate);
      expect(() => assertProviderMessageBatchPlan(candidate)).toThrow(/mutated/u);
    }
  });

  it('requires explicit BIP322 for payment while preserving the official Taproot default', () => {
    expect(() => create({ requests: [{ address: payment, message: 'payment challenge' }] }))
      .toThrow(/explicitly request BIP322/u);
    expect(() => create({ requests: [{ address: ordinals, message: 'ordinal challenge' }] }))
      .not.toThrow();
    expect(() => create({ requests: [{ address: 'tb1qforeignaddress', message: 'x', protocol: 'BIP322' }] }))
      .toThrow(/active account/u);
  });

  it('rejects duplicate pairs and resource-limit mutations before signing', () => {
    expect(() => create({
      requests: [
        { address: payment, message: 'same', protocol: 'BIP322' },
        { address: payment, message: 'same', protocol: 'BIP322' },
      ],
    })).toThrow(/duplicate/u);
    const plan = create();
    plan.totalMessageBytes += 1;
    expect(() => assertProviderMessageBatchPlan(plan)).toThrow(/mutated/u);

    expect(() => create({ requests: Array.from(
      { length: PROVIDER_MAX_SIGN_MESSAGES + 1 },
      (_, index) => ({ address: ordinals, message: `challenge ${index}` }),
    ) })).toThrow(/1-10 items/u);
    const sizedMessage = (length: number, index: number): string =>
      `${String.fromCharCode(65 + index)}${'a'.repeat(length - 1)}`;
    const exact = Array.from({ length: PROVIDER_MAX_SIGN_MESSAGES }, (_, index) => ({
      address: ordinals,
      message: sizedMessage(index === PROVIDER_MAX_SIGN_MESSAGES - 1 ? 3_284 : 3_276, index),
    }));
    expect(exact.reduce((total, item) => total + new TextEncoder().encode(item.message).length, 0))
      .toBe(PROVIDER_MAX_SIGN_MESSAGE_BATCH_BYTES);
    expect(() => create({ requests: exact })).not.toThrow();
    exact[exact.length - 1]!.message += 'x';
    expect(() => create({ requests: exact })).toThrow(/aggregate byte limit/u);
  });

  it('signs and verifies every item in order and rejects incomplete or reordered delivery', () => {
    const plan = create();
    const results = plan.items.map((item) => signProviderMessageBatchItem({
      plan,
      itemIndex: item.index,
      seed,
      now: NOW + 1,
      random: (length) => new Uint8Array(length),
    }));
    expect(results.map((result) => result.message)).toEqual([
      'payment challenge', 'ordinal challenge',
    ]);
    expect(results.every((result) => verifyBip322Simple(
      result.message, result.address, 'signet', result.signature,
    ))).toBe(true);
    expect(() => assertProviderMessageBatchResults(plan, results)).not.toThrow();
    expect(() => assertProviderMessageBatchResults(plan, results.slice(0, 1)))
      .toThrow(/incomplete/u);
    expect(() => assertProviderMessageBatchResults(plan, results.toReversed()))
      .toThrow(/changed/u);
    for (const mutate of [
      (candidate: typeof results) => { candidate[0]!.signature = 'smpbad'; },
      (candidate: typeof results) => { candidate[0]!.message = 'changed'; },
      (candidate: typeof results) => { candidate[0]!.messageHash = '00'.repeat(32); },
      (candidate: typeof results) => { candidate[0]!.address = ordinals; },
      (candidate: typeof results) => {
        (candidate[0] as { protocol: string }).protocol = 'ECDSA';
      },
    ]) {
      const candidate = structuredClone(results);
      mutate(candidate);
      expect(() => assertProviderMessageBatchResults(plan, candidate)).toThrow(/changed/u);
    }
    expect(() => signProviderMessageBatchItem({
      plan, itemIndex: 0, seed, now: plan.expiresAt,
      random: (length) => new Uint8Array(length),
    })).toThrow(/expired/u);
  });

  it('allows one address to sign distinct messages and both addresses to sign the same message', () => {
    const plan = create({ requests: [
      { address: payment, message: 'first', protocol: 'BIP322' },
      { address: payment, message: 'second', protocol: 'BIP322' },
      { address: payment, message: 'shared', protocol: 'BIP322' },
      { address: ordinals, message: 'shared' },
    ] });
    expect(plan.items.map((item) => [item.addressKind, item.message])).toEqual([
      ['payment', 'first'], ['payment', 'second'], ['payment', 'shared'], ['ordinals', 'shared'],
    ]);
  });

  it('rejects a seed that does not match the committed stable account identity', () => {
    const wrongSeed = mnemonicToSeed(
      'legal winner thank year wave sausage worth useful legal winner thank yellow',
    );
    try {
      expect(() => signProviderMessageBatchItem({
        plan: create(), itemIndex: 0, seed: wrongSeed, now: NOW + 1,
        random: (length) => new Uint8Array(length),
      })).toThrow(/account changed/u);
    } finally {
      wrongSeed.fill(0);
    }
  });
});
