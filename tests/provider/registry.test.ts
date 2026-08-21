import { describe, expect, it } from 'vitest';
import {
  normalizeProviderConnectionRequest,
  PROVIDER_MAX_SIGN_INPUTS,
  PROVIDER_METHODS,
  PROVIDER_OPERATIONS,
} from '../../src/provider/registry';

describe('provider operation registry', () => {
  it('contains exactly the spec-authorized Bitcoin/WBIP surface', () => {
    expect([...PROVIDER_METHODS].sort()).toEqual(
      [
        'getInfo',
        'drey_openCommunityVault',
        'wallet_connect',
        'wallet_disconnect',
        'wallet_renouncePermissions',
        'wallet_getCurrentPermissions',
        'wallet_requestPermissions',
        'wallet_getAccount',
        'wallet_getNetwork',
        'getAddresses',
        'getAccounts',
        'getBalance',
        'signMessage',
        'signPsbt',
        'sendTransfer',
        'ord_getInscriptions',
        'ord_sendInscriptions',
      ].sort(),
    );
    expect(PROVIDER_OPERATIONS).not.toHaveProperty('pushTx');
    expect(PROVIDER_OPERATIONS).not.toHaveProperty('pushPsbt');
    expect(PROVIDER_OPERATIONS).not.toHaveProperty('runes_transfer');
    expect(PROVIDER_OPERATIONS).not.toHaveProperty('stx_transferStx');
  });

  it('versions every op and applies connection/unlock/fresh-approval policy', () => {
    for (const spec of Object.values(PROVIDER_OPERATIONS)) expect(spec.version).toBe(1);
    for (const method of ['signMessage', 'signPsbt', 'sendTransfer', 'ord_sendInscriptions'] as const) {
      expect(PROVIDER_OPERATIONS[method]).toMatchObject({
        requiresConnection: true,
        requiresUnlock: true,
        requiresFreshApproval: true,
      });
    }
    for (const method of ['wallet_getAccount', 'getAddresses', 'getBalance', 'ord_getInscriptions'] as const) {
      expect(PROVIDER_OPERATIONS[method]).toMatchObject({
        requiresConnection: true,
        requiresUnlock: true,
        requiresFreshApproval: false,
      });
    }
    expect(PROVIDER_OPERATIONS.wallet_connect).toMatchObject({
      requiresConnection: false,
      requiresUnlock: true,
      requiresFreshApproval: true,
    });
  });

  it('advertises optional provider capabilities without using the product version as a protocol gate', () => {
    const getInfo = PROVIDER_OPERATIONS.getInfo.response;
    const base = {
      version: '0.11.2',
      platform: 'web',
      methods: ['getInfo', 'signPsbt'],
      supports: ['WBIP001', 'WBIP004'],
    };
    expect(getInfo.safeParse(base).success).toBe(true);
    expect(getInfo.safeParse({ ...base, capabilities: ['community-vault-v1'] }).success).toBe(true);
    expect(getInfo.safeParse({
      ...base,
      capabilities: [
        'community-vault-v1',
        'community-vault-offers-v1',
        'community-vault-position-transfer-v1',
      ],
    }).success).toBe(true);
    expect(getInfo.safeParse({ ...base, capabilities: ['unknown-capability'] }).success).toBe(false);
  });

  it('bounds the Community Vault setup handoff to public identifiers', () => {
    const setup = PROVIDER_OPERATIONS.drey_openCommunityVault;
    expect(setup).toMatchObject({
      requiresConnection: true,
      requiresUnlock: false,
      requiresFreshApproval: false,
      dataCategories: [],
    });
    expect(setup.request.safeParse({ campaignId: 'cp_123', ownerId: 'owner_123' }).success).toBe(true);
    expect(setup.request.safeParse({ campaignId: '../bad', ownerId: 'owner_123' }).success).toBe(false);
    expect(setup.request.safeParse({ campaignId: 'cp_123', ownerId: 'owner_123', secret: 'no' }).success).toBe(false);
  });

  it('accepts only BIP322 messages and keeps PSBT broadcast inside the approved signPsbt method', () => {
    const message = PROVIDER_OPERATIONS.signMessage.request;
    expect(message.safeParse({ address: 'tb1q00000000', message: 'hello', protocol: 'BIP322' }).success).toBe(true);
    expect(message.safeParse({ address: 'tb1q00000000', message: 'hello', protocol: 'ECDSA' }).success).toBe(false);
    expect(message.safeParse({ address: 'tb1q00000000', message: 'nul\0byte', protocol: 'BIP322' }).success).toBe(false);
    expect(message.safeParse({ address: 'tb1q00000000', message: 'a'.repeat(4097), protocol: 'BIP322' }).success).toBe(false);

    const psbt = PROVIDER_OPERATIONS.signPsbt.request;
    expect(psbt.safeParse({ psbt: 'cHNidP8=', broadcast: false }).success).toBe(true);
    expect(psbt.safeParse({ psbt: 'cHNidP8=', broadcast: true }).success).toBe(true);
    expect(psbt.safeParse({ psbt: 'cHNidP8=', rawTransaction: '00' }).success).toBe(false);
    expect(psbt.safeParse({
      psbt: 'cHNidP8=',
      marketplaceContext: {
        version: 1, marketplaceId: 'future_market', templateVersion: 'v1', action: 'list',
        role: 'seller', assetKind: 'inscription', workflowId: 'future-1', step: 1,
        stepCount: 1, broadcaster: 'site',
      },
    }).success).toBe(true);
  });

  it('bounds signPsbt input selections to the supported PSBT input ceiling', () => {
    const psbt = PROVIDER_OPERATIONS.signPsbt.request;
    const indexes = Array.from({ length: PROVIDER_MAX_SIGN_INPUTS }, (_, index) => index);
    expect(psbt.safeParse({
      psbt: 'cHNidP8=',
      signInputs: { tb1q00000000: indexes },
    }).success).toBe(true);
    expect(psbt.safeParse({
      psbt: 'cHNidP8=',
      signInputs: { tb1q00000000: [...indexes, PROVIDER_MAX_SIGN_INPUTS] },
    }).success).toBe(false);
    expect(psbt.safeParse({
      psbt: 'cHNidP8=',
      signInputs: {
        tb1q00000000: indexes.slice(0, PROVIDER_MAX_SIGN_INPUTS / 2),
        tb1p00000000: indexes.slice(PROVIDER_MAX_SIGN_INPUTS / 2).concat(0),
      },
    }).success).toBe(false);
    expect(psbt.safeParse({
      psbt: 'cHNidP8=',
      signInputs: { tb1q00000000: [PROVIDER_MAX_SIGN_INPUTS] },
    }).success).toBe(false);
    expect(psbt.safeParse({ psbt: 'cHNidP8=', signInputs: {} }).success).toBe(false);
  });

  it('allows exactly one inscription transfer and only Bitcoin address purposes', () => {
    const send = PROVIDER_OPERATIONS.ord_sendInscriptions.request;
    const transfer = { address: 'tb1p00000000', inscriptionId: `${'a'.repeat(64)}i0` };
    expect(send.safeParse({ transfers: [transfer] }).success).toBe(true);
    expect(send.safeParse({ transfers: [transfer, transfer] }).success).toBe(false);

    const addresses = PROVIDER_OPERATIONS.getAddresses.request;
    expect(addresses.safeParse({ purposes: ['payment', 'ordinals'] }).success).toBe(true);
    expect(addresses.safeParse({ purposes: ['payment', 'stacks'] }).success).toBe(false);
  });

  it('accepts WBIP permission requests while keeping Drey categories worker-derived', () => {
    const request = PROVIDER_OPERATIONS.wallet_requestPermissions.request;
    expect(
      request.safeParse([
        { type: 'account', resourceId: 'account-0', actions: { read: true } },
        { type: 'wallet', resourceId: 'wallet', actions: { readNetwork: true } },
      ]).success,
    ).toBe(true);
    expect(
      request.safeParse([{ type: 'account', resourceId: 'account-0', actions: { sign: true } }]).success,
    ).toBe(false);
  });

  it('normalizes the same approve-all connection scope for every platform', () => {
    expect(normalizeProviderConnectionRequest(undefined)).toEqual({
      categories: ['account_identity', 'addresses', 'network'],
      purposes: ['ordinals', 'payment'],
    });
    expect(normalizeProviderConnectionRequest({
      addresses: ['payment'],
      permissions: [{
        type: 'account',
        resourceId: 'account-0',
        actions: { read: true },
        dataCategories: ['balance'],
      }],
    })).toEqual({
      categories: ['account_identity', 'addresses', 'balance', 'network'],
      purposes: ['payment'],
    });
  });
});
