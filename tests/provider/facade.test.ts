import { describe, expect, it, vi } from 'vitest';
import {
  createDreyProvider,
  parseSatsConnectBatchToken,
  type ProviderTransport,
} from '../../src/provider/facade';
import { DreyProviderError, providerError } from '../../src/provider/errors';

function transport(request: ProviderTransport['request']): ProviderTransport {
  return {
    request,
    addListener: vi.fn(),
    removeListener: vi.fn(),
    destroy: vi.fn(),
  };
}

describe('platform-neutral provider facade', () => {
  it('preserves the shared method surface and JSON-RPC result shape', async () => {
    const request = vi.fn(async () => ({ id: 'request-1', result: { version: '0.10.0' } }));
    const provider = createDreyProvider(transport(request));
    expect(provider.methods).toContain('wallet_connect');
    await expect(provider.request('getInfo', null)).resolves.toEqual({
      jsonrpc: '2.0', id: 'request-1', result: { version: '0.10.0' },
    });
  });

  it('strictly unwraps the official unsecured batch token before structured dispatch', async () => {
    const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
    const payload = {
      network: { type: 'Signet' },
      message: 'Sign transactions',
      psbts: [{ psbtBase64: 'cHNidP8=' }],
    } as const;
    const token = `${encode({ typ: 'JWT', alg: 'none' })}.${encode(payload)}.`;
    expect(parseSatsConnectBatchToken(token)).toEqual(payload);
    const request = vi.fn(async () => ({ id: 'request-1', result: [{ psbtBase64: 'cHNidP8=' }] }));
    const provider = createDreyProvider(transport(request));
    await expect(provider.signMultipleTransactions(token)).resolves.toEqual([{ psbtBase64: 'cHNidP8=' }]);
    expect(request).toHaveBeenCalledWith('signMultipleTransactions', payload);
    const shortProvider = createDreyProvider(transport(async () => ({
      id: 'request-2', result: [{ psbtBase64: 'cHNidP8=' }],
    })));
    const twoItemPayload = { ...payload, psbts: [...payload.psbts, ...payload.psbts] };
    const twoItemToken = `${encode({ typ: 'JWT', alg: 'none' })}.${encode(twoItemPayload)}.`;
    await expect(shortProvider.signMultipleTransactions(twoItemToken)).rejects.toThrow('Internal error');
    for (const invalid of [
      `${encode({ typ: 'JWT', alg: 'HS256' })}.${encode(payload)}.`,
      `${encode({ typ: 'JWT', alg: 'none', kid: 'x' })}.${encode(payload)}.`,
      `${encode({ typ: 'JWT', alg: 'none' })}.${encode({ ...payload, broadcast: true })}.`,
      `${encode({ typ: 'JWT', alg: 'none' })}.${encode(payload)}.signature`,
      'not-a-token',
    ]) {
      expect(() => parseSatsConnectBatchToken(invalid)).toThrow('Invalid params');
    }
  });

  it('projects stable provider errors without leaking transport exceptions', async () => {
    const expected = providerError('ERR_USER_REJECTED');
    const rejected = createDreyProvider(transport(async () => {
      throw new DreyProviderError(expected);
    }));
    await expect(rejected.request('wallet_connect', null)).resolves.toEqual({
      jsonrpc: '2.0', id: null, error: expected,
    });
    const failed = createDreyProvider(transport(async () => { throw new Error('secret'); }));
    await expect(failed.request('getInfo', null)).resolves.toEqual({
      jsonrpc: '2.0', id: null, error: { code: -32603, message: 'Internal error' },
    });
  });
});
