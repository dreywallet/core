import { describe, expect, it } from 'vitest';
import {
  ordnetMarketplaceProviderCapabilities,
  normalizeProviderConnectionRequest,
  PROVIDER_MAX_SIGN_MESSAGES,
  PROVIDER_MAX_SIGN_MESSAGE_BATCH_BYTES,
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
        'wallet_getWalletType',
        'getAddresses',
        'getAccounts',
        'getBalance',
        'signMessage',
        'signMultipleMessages',
        'signPsbt',
        'signMultipleTransactions',
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
    for (const method of ['signMessage', 'signMultipleMessages', 'signPsbt', 'signMultipleTransactions', 'sendTransfer',
      'ord_sendInscriptions'] as const) {
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
    expect(PROVIDER_OPERATIONS.wallet_getWalletType).toMatchObject({
      requiresConnection: false,
      requiresUnlock: false,
      requiresFreshApproval: false,
      dataCategories: [],
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
    expect(ordnetMarketplaceProviderCapabilities()).toEqual([
      'marketplace-ordnet-list-v1',
      'marketplace-ordnet-foundry-presale-v1',
    ]);
    expect(getInfo.safeParse({
      ...base,
      capabilities: [
        'community-vault-v1',
        'community-vault-offers-v1',
        'community-vault-position-transfer-v1',
        ...ordnetMarketplaceProviderCapabilities(),
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
    expect(psbt.safeParse({
      psbt: 'cHNidP8=',
      inputsToSign: [{ address: 'tb1q00000000', signingIndexes: [0], sigHash: 1 }],
    }).success).toBe(true);
    expect(psbt.safeParse({
      psbt: 'cHNidP8=',
      signInputs: { tb1q00000000: [0] },
      inputsToSign: [{ address: 'tb1q00000000', signingIndexes: [0], sigHash: 1 }],
    }).success).toBe(false);
    expect(psbt.safeParse({
      psbt: 'cHNidP8=',
      inputsToSign: [
        { address: 'tb1q00000000', signingIndexes: [0], sigHash: 1 },
        { address: 'tb1p00000000', signingIndexes: [0], sigHash: 1 },
      ],
    }).success).toBe(false);
  });

  it('implements a bounded BIP322-only official multiple-message contract', () => {
    const request = PROVIDER_OPERATIONS.signMultipleMessages.request;
    const payment = { address: 'tb1q00000000', message: 'payment challenge', protocol: 'BIP322' };
    const ordinal = { address: 'tb1p00000000', message: 'ordinal challenge' };
    expect(request.safeParse([payment, ordinal]).success).toBe(true);
    expect(request.safeParse([]).success).toBe(false);
    expect(request.safeParse(Array.from({ length: PROVIDER_MAX_SIGN_MESSAGES + 1 }, (_, index) => ({
      ...ordinal,
      message: `challenge ${index}`,
    }))).success).toBe(false);
    expect(request.safeParse([{ ...payment, protocol: 'ECDSA' }]).success).toBe(false);
    expect(request.safeParse([{ ...payment, message: 'hidden\0control' }]).success).toBe(false);
    expect(request.safeParse([{ ...payment, extra: true }]).success).toBe(false);
    expect(request.safeParse([payment, payment]).success).toBe(false);
    expect(request.safeParse(Array.from({ length: PROVIDER_MAX_SIGN_MESSAGES }, (_, index) => ({
      ...ordinal,
      message: `${index}:${'a'.repeat(Math.floor(PROVIDER_MAX_SIGN_MESSAGE_BATCH_BYTES /
        PROVIDER_MAX_SIGN_MESSAGES))}`,
    }))).success).toBe(false);

    const response = PROVIDER_OPERATIONS.signMultipleMessages.response;
    const results = [
      {
        signature: 'smp-payment', message: payment.message, messageHash: '11'.repeat(32),
        address: payment.address, protocol: 'BIP322',
      },
      {
        signature: 'smp-ordinal', message: ordinal.message, messageHash: '22'.repeat(32),
        address: ordinal.address, protocol: 'BIP322',
      },
    ];
    expect(response.safeParse(results).success).toBe(true);
    expect(response.safeParse(results.toReversed()).success).toBe(true);
    expect(response.safeParse([{ ...results[0], protocol: 'ECDSA' }]).success).toBe(false);
    expect(response.safeParse([]).success).toBe(false);
  });

  it('implements the bounded official Sats Connect multi-transaction payload and result shapes', () => {
    const request = PROVIDER_OPERATIONS.signMultipleTransactions.request;
    const item = {
      psbtBase64: 'cHNidP8=',
      inputsToSign: [{ address: 'tb1q00000000', signingIndexes: [0], sigHash: 1 }],
    };
    expect(request.safeParse({
      network: { type: 'Signet' }, message: 'Sign transactions', psbts: [item],
    }).success).toBe(true);
    expect(request.safeParse({
      network: { type: 'Signet' }, message: '', psbts: [item],
    }).success).toBe(true);
    expect(request.safeParse({
      network: { type: 'Mainnet', address: 'bc1q00000000' }, message: 'Sign transactions',
      psbts: Array.from({ length: 41 }, () => ({ psbtBase64: 'cHNidP8=' })),
    }).success).toBe(true);
    expect(request.safeParse({ network: { type: 'Signet' }, message: 'x', psbts: [] }).success).toBe(false);
    expect(request.safeParse({
      network: { type: 'Signet' }, message: 'x',
      psbts: Array.from({ length: 42 }, () => ({ psbtBase64: 'cHNidP8=' })),
    }).success).toBe(false);
    expect(request.safeParse({
      network: { type: 'Signet' }, message: 'x', psbts: [{ ...item, broadcast: true }],
    }).success).toBe(false);
    const selectedItem = (count: number) => ({
      psbtBase64: 'cHNidP8=',
      inputsToSign: [{
        address: 'tb1q00000000',
        signingIndexes: Array.from({ length: count }, (_value, index) => index),
        sigHash: 1,
      }],
    });
    expect(request.safeParse({
      network: { type: 'Signet' }, message: 'x',
      psbts: [selectedItem(200), selectedItem(200), selectedItem(100)],
    }).success).toBe(true);
    expect(request.safeParse({
      network: { type: 'Signet' }, message: 'x',
      psbts: [selectedItem(200), selectedItem(200), selectedItem(101)],
    }).success).toBe(false);
    expect(request.safeParse({
      network: { type: 'Signet' }, message: 'x', psbts: [{
        ...item,
        inputsToSign: [{ address: 'tb1q00000000', signingIndexes: [0], sigHash: 3 }],
      }],
    }).success).toBe(false);
    expect(PROVIDER_OPERATIONS.signMultipleTransactions.response.safeParse([
      { psbtBase64: 'cHNidP8=', txId: '11'.repeat(32) },
    ]).success).toBe(true);
    expect(PROVIDER_OPERATIONS.signMultipleTransactions.response.safeParse([
      { psbt: 'cHNidP8=' },
    ]).success).toBe(false);
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
