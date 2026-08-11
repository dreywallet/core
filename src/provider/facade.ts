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
  type ProviderMethod,
  type ProviderRequest,
  type ProviderResult,
} from './registry';

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
  addListener<E extends ProviderEventName>(
    listener: { eventName: E; cb: ProviderEventListener<E> },
  ): () => void;
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
  return Object.freeze({
    isDrey: true as const,
    protocolVersion: PROVIDER_BRIDGE_VERSION,
    methods: PROVIDER_METHODS,
    request,
    addListener: <E extends ProviderEventName>(
      listener: { eventName: E; cb: ProviderEventListener<E> },
    ): (() => void) => {
      transport.addListener(listener.eventName, listener.cb);
      return () => transport.removeListener(listener.eventName, listener.cb);
    },
  }) as DreyProvider;
}
