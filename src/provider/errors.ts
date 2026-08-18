/** Stable provider errors and their Sats Connect/WBIP JSON-RPC projection. */
import { z } from 'zod';

export const ProviderErrorCode = z.enum([
  'ERR_NOT_CONNECTED',
  'ERR_NO_ACCOUNT',
  'ERR_LOCKED',
  'ERR_PHISHING_BLOCKED',
  'ERR_UNSUPPORTED_METHOD',
  'ERR_UNSUPPORTED_BY_ACCOUNT',
  'ERR_USER_REJECTED',
  'ERR_REQUEST_EXPIRED',
  'ERR_STALE_CONTEXT',
  'ERR_QUEUE_FULL',
  'ERR_UNSUPPORTED_MARKETPLACE',
  'ERR_UNSUPPORTED_TEMPLATE',
  'ERR_MARKETPLACE_STATE_CHANGED',
  'ERR_DATA_STALE',
  'ERR_BROADCAST_OUTCOME_UNKNOWN',
]);
export type ProviderErrorCode = z.infer<typeof ProviderErrorCode>;

const ERROR_DETAILS: Record<ProviderErrorCode, { code: number; message: string }> = {
  ERR_USER_REJECTED: { code: -32000, message: 'User rejected the request' },
  ERR_UNSUPPORTED_METHOD: { code: -32601, message: 'Method is not supported' },
  ERR_UNSUPPORTED_BY_ACCOUNT: { code: -32001, message: 'Method is not supported by this account' },
  ERR_NOT_CONNECTED: { code: -32002, message: 'Site is not connected' },
  ERR_NO_ACCOUNT: { code: -32002, message: 'No approved account is available' },
  ERR_LOCKED: { code: -32002, message: 'Wallet is locked' },
  ERR_PHISHING_BLOCKED: { code: -32002, message: 'Site is blocked for safety' },
  ERR_REQUEST_EXPIRED: { code: -32003, message: 'Request expired' },
  ERR_STALE_CONTEXT: { code: -32004, message: 'Request context is stale' },
  ERR_QUEUE_FULL: { code: -32005, message: 'Approval queue is full' },
  ERR_UNSUPPORTED_MARKETPLACE: { code: -32006, message: 'Marketplace is not supported for this request' },
  ERR_UNSUPPORTED_TEMPLATE: { code: -32007, message: 'Marketplace transaction template is not supported' },
  ERR_MARKETPLACE_STATE_CHANGED: { code: -32008, message: 'Marketplace request state changed' },
  ERR_DATA_STALE: { code: -32009, message: 'Wallet data is not current' },
  ERR_BROADCAST_OUTCOME_UNKNOWN: { code: -32010, message: 'Broadcast outcome is unknown' },
};

export const providerJsonRpcErrorSchema = z
  .object({
    code: z.number().int(),
    message: z.string().min(1),
    data: z.object({ dreyCode: ProviderErrorCode }).strict(),
  })
  .strict();
export type ProviderJsonRpcError = z.infer<typeof providerJsonRpcErrorSchema>;

export function providerError(code: ProviderErrorCode): ProviderJsonRpcError {
  return { ...ERROR_DETAILS[code], data: { dreyCode: code } };
}

export const INVALID_REQUEST_ERROR = Object.freeze({ code: -32600, message: 'Invalid request' });
export const METHOD_NOT_FOUND_ERROR = Object.freeze({ code: -32601, message: 'Method not found' });
export const INVALID_PARAMS_ERROR = Object.freeze({ code: -32602, message: 'Invalid params' });
export const INTERNAL_ERROR = Object.freeze({ code: -32603, message: 'Internal error' });

export const bridgeJsonRpcErrorSchema = z.union([
  providerJsonRpcErrorSchema,
  z.object({ code: z.literal(-32600), message: z.literal('Invalid request') }).strict(),
  z.object({ code: z.literal(-32601), message: z.literal('Method not found') }).strict(),
  z.object({ code: z.literal(-32602), message: z.literal('Invalid params') }).strict(),
  z.object({ code: z.literal(-32603), message: z.literal('Internal error') }).strict(),
]);
export type BridgeJsonRpcError = z.infer<typeof bridgeJsonRpcErrorSchema>;

export class DreyProviderError extends Error {
  readonly code: number;
  readonly data?: { dreyCode: ProviderErrorCode };

  constructor(error: BridgeJsonRpcError) {
    super(error.message);
    this.name = 'DreyProviderError';
    this.code = error.code;
    if ('data' in error) this.data = error.data;
  }
}
