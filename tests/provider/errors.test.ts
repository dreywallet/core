import { describe, expect, it } from 'vitest';
import { ProviderErrorCode, providerError, providerJsonRpcErrorSchema } from '../../src/provider/errors';

describe('provider JSON-RPC errors', () => {
  it('maps every stable provider code without exposing internal details', () => {
    for (const code of ProviderErrorCode.options) {
      const error = providerError(code);
      expect(providerJsonRpcErrorSchema.safeParse(error).success).toBe(true);
      expect(error.data).toEqual({ dreyCode: code });
      expect(error.message).not.toContain('Error:');
    }
  });

  it('uses WBIP-compatible codes for rejection, unsupported methods, and access denial', () => {
    expect(providerError('ERR_USER_REJECTED').code).toBe(-32000);
    expect(providerError('ERR_UNSUPPORTED_METHOD').code).toBe(-32601);
    expect(providerError('ERR_NOT_CONNECTED').code).toBe(-32002);
    expect(providerError('ERR_NO_ACCOUNT').code).toBe(-32002);
    expect(providerError('ERR_PHISHING_BLOCKED')).toMatchObject({
      code: -32002, data: { dreyCode: 'ERR_PHISHING_BLOCKED' },
    });
    expect(providerError('ERR_DATA_STALE')).toMatchObject({
      code: -32009, data: { dreyCode: 'ERR_DATA_STALE' },
    });
    expect(providerError('ERR_BROADCAST_OUTCOME_UNKNOWN')).toMatchObject({
      code: -32010, data: { dreyCode: 'ERR_BROADCAST_OUTCOME_UNKNOWN' },
    });
  });
});
