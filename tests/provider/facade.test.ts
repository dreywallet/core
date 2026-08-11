import { describe, expect, it, vi } from 'vitest';
import { createDreyProvider, type ProviderTransport } from '../../src/provider/facade';
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
