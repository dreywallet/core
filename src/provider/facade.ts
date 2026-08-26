/** Platform-neutral, data-free page provider facade. */
import {
  PROVIDER_BRIDGE_VERSION,
  type ProviderEventName,
  type PageProviderEvent,
} from './bridge-schemas';
import {
  DreyProviderError,
  INTERNAL_ERROR,
  type BridgeJsonRpcError,
} from './errors';
import {
  PROVIDER_METHODS,
  signMultipleTransactionsParamsSchema,
  signMultipleTransactionsResultSchema,
  type ProviderMethod,
  type ProviderRequest,
  type ProviderResult,
  type SignMultipleTransactionsParams,
} from './registry';
import { base64ToBytes, bytesToBase64 } from '../domain/vault/encoding';

type ProviderEvent = PageProviderEvent['data'];
export type ProviderEventData<E extends ProviderEventName> = Extract<ProviderEvent, { type: E }>;
export type ProviderEventListener<E extends ProviderEventName> = (data: ProviderEventData<E>) => void;

export interface ProviderTransportResult {
  id: string;
  result: unknown;
}

export interface ProviderTransport {
  request(method: string, params?: unknown): Promise<ProviderTransportResult>;
  addListener<E extends ProviderEventName>(event: E, listener: ProviderEventListener<E>): void;
  removeListener<E extends ProviderEventName>(event: E, listener: ProviderEventListener<E>): void;
  destroy(): void;
}

export interface DreyProvider {
  readonly isDrey: true;
  readonly protocolVersion: 1;
  readonly methods: readonly ProviderMethod[];
  request<M extends ProviderMethod>(
    method: M,
    params: ProviderRequest<M>,
  ): Promise<DreyRpcResponse<ProviderResult<M>>>;
  request(method: string, params?: unknown): Promise<DreyRpcResponse<unknown>>;
  /** Callback-era Sats Connect compatibility. The unsecured token is data, never authority. */
  signMultipleTransactions(token: string): Promise<ProviderResult<'signMultipleTransactions'>>;
  addListener<E extends ProviderEventName>(
    listener: { eventName: E; cb: ProviderEventListener<E> },
  ): () => void;
}

const MAX_LEGACY_BATCH_TOKEN_CHARS = 2_100_000;

function decodeBase64UrlJson(segment: string, maxBytes: number): unknown {
  if (segment.length === 0 || !/^[A-Za-z0-9_-]+$/u.test(segment)) {
    throw new DreyProviderError({ code: -32602, message: 'Invalid params' });
  }
  const standard = segment.replace(/-/gu, '+').replace(/_/gu, '/');
  const padded = `${standard}${'='.repeat((4 - standard.length % 4) % 4)}`;
  let bytes: Uint8Array;
  try {
    bytes = base64ToBytes(padded);
  } catch {
    throw new DreyProviderError({ code: -32602, message: 'Invalid params' });
  }
  const canonical = bytesToBase64(bytes).replace(/=/gu, '').replace(/\+/gu, '-').replace(/\//gu, '_');
  if (canonical !== segment || bytes.length > maxBytes) {
    throw new DreyProviderError({ code: -32602, message: 'Invalid params' });
  }
  try {
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } catch {
    throw new DreyProviderError({ code: -32602, message: 'Invalid params' });
  }
}

/** Decode only the exact `alg:none` envelope emitted by Sats Connect's legacy helper. */
export function parseSatsConnectBatchToken(token: string): SignMultipleTransactionsParams {
  if (typeof token !== 'string' || token.length > MAX_LEGACY_BATCH_TOKEN_CHARS) {
    throw new DreyProviderError({ code: -32602, message: 'Invalid params' });
  }
  const segments = token.split('.');
  if (segments.length !== 3 || segments[2] !== '') {
    throw new DreyProviderError({ code: -32602, message: 'Invalid params' });
  }
  const header = decodeBase64UrlJson(segments[0]!, 256);
  if (header === null || typeof header !== 'object' || Array.isArray(header) ||
      Object.keys(header).length !== 2 ||
      (header as Record<string, unknown>)['typ'] !== 'JWT' ||
      (header as Record<string, unknown>)['alg'] !== 'none') {
    throw new DreyProviderError({ code: -32602, message: 'Invalid params' });
  }
  const parsed = signMultipleTransactionsParamsSchema.safeParse(
    decodeBase64UrlJson(segments[1]!, 1_600_000),
  );
  if (!parsed.success) throw new DreyProviderError({ code: -32602, message: 'Invalid params' });
  return parsed.data;
}

export interface DreyRpcSuccess<Result> {
  jsonrpc: '2.0';
  id: string;
  result: Result;
}

export interface DreyRpcFailure {
  jsonrpc: '2.0';
  id: string | null;
  error: BridgeJsonRpcError;
}

export type DreyRpcResponse<Result> = DreyRpcSuccess<Result> | DreyRpcFailure;

export function createDreyProvider(transport: ProviderTransport): DreyProvider {
  const request = async (method: string, params?: unknown): Promise<DreyRpcResponse<unknown>> => {
    try {
      const response = await transport.request(method, params);
      return { jsonrpc: '2.0', id: response.id, result: response.result };
    } catch (reason) {
      const error: BridgeJsonRpcError = reason instanceof DreyProviderError
        ? {
            code: reason.code,
            message: reason.message,
            ...(reason.data ? { data: reason.data } : {}),
          } as BridgeJsonRpcError
        : INTERNAL_ERROR;
      return { jsonrpc: '2.0', id: null, error };
    }
  };
  const signMultipleTransactions = async (
    token: string,
  ): Promise<ProviderResult<'signMultipleTransactions'>> => {
    const payload = parseSatsConnectBatchToken(token);
    const response = await transport.request('signMultipleTransactions', payload);
    const parsed = signMultipleTransactionsResultSchema.safeParse(response.result);
    if (!parsed.success || parsed.data.length !== payload.psbts.length) {
      throw new DreyProviderError(INTERNAL_ERROR);
    }
    return parsed.data;
  };
  return Object.freeze({
    isDrey: true as const,
    protocolVersion: PROVIDER_BRIDGE_VERSION,
    methods: PROVIDER_METHODS,
    request,
    signMultipleTransactions,
    addListener: <E extends ProviderEventName>(
      listener: { eventName: E; cb: ProviderEventListener<E> },
    ): (() => void) => {
      transport.addListener(listener.eventName, listener.cb);
      return () => transport.removeListener(listener.eventName, listener.cb);
    },
  }) as DreyProvider;
}
