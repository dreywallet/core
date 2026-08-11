/**
 * Strict MAIN-world <-> isolated-world <-> worker bridge wire contracts.
 *
 * Schemas and constants only — platform-free. The DOM/port attachment logic
 * (attachIsolatedBridge and friends) lives with each consumer: the page
 * request ID is correlation only, the isolated bridge generates the request
 * nonce seen by the worker, and the platform's native sender identity remains
 * the sole authority.
 */
import { z } from 'zod';
import { bridgeJsonRpcErrorSchema } from './errors';
import { providerAddressSchema, providerNetworkResultSchema } from './registry';

export const PROVIDER_BRIDGE_VERSION = 1 as const;
export const PROVIDER_PORT_NAME = 'drey-provider-v1' as const;
export const PROVIDER_REQUEST_TIMEOUT_MS = 5 * 60_000;

export const bridgeRequestIdSchema = z.string().uuid();
const methodSchema = z.string().min(1).max(128);

export const pageProviderRequestSchema = z
  .object({
    type: z.literal('drey:provider:request'),
    protocolVersion: z.literal(PROVIDER_BRIDGE_VERSION),
    requestId: bridgeRequestIdSchema,
    method: methodSchema,
    params: z.unknown().optional(),
  })
  .strict();
export type PageProviderRequest = z.infer<typeof pageProviderRequestSchema>;

export const pageProviderResponseSchema = z.discriminatedUnion('ok', [
  z
    .object({
      type: z.literal('drey:provider:response'),
      protocolVersion: z.literal(PROVIDER_BRIDGE_VERSION),
      requestId: bridgeRequestIdSchema,
      ok: z.literal(true),
      result: z.unknown(),
    })
    .strict(),
  z
    .object({
      type: z.literal('drey:provider:response'),
      protocolVersion: z.literal(PROVIDER_BRIDGE_VERSION),
      requestId: bridgeRequestIdSchema,
      ok: z.literal(false),
      error: bridgeJsonRpcErrorSchema,
    })
    .strict(),
]);
export type PageProviderResponse = z.infer<typeof pageProviderResponseSchema>;

const accountChangeEventSchema = z
  .object({
    type: z.literal('drey:provider:event'),
    protocolVersion: z.literal(PROVIDER_BRIDGE_VERSION),
    event: z.literal('accountChange'),
    data: z
      .object({
        type: z.literal('accountChange'),
        addresses: z.array(providerAddressSchema).max(2).optional(),
      })
      .strict(),
  })
  .strict();
const networkChangeEventSchema = z
  .object({
    type: z.literal('drey:provider:event'),
    protocolVersion: z.literal(PROVIDER_BRIDGE_VERSION),
    event: z.literal('networkChange'),
    data: providerNetworkResultSchema.extend({
      type: z.literal('networkChange'),
      addresses: z.array(providerAddressSchema).max(2).optional(),
    }).strict(),
  })
  .strict();
const disconnectEventSchema = z
  .object({
    type: z.literal('drey:provider:event'),
    protocolVersion: z.literal(PROVIDER_BRIDGE_VERSION),
    event: z.literal('disconnect'),
    data: z.object({ type: z.literal('disconnect') }).strict(),
  })
  .strict();
export const pageProviderEventSchema = z.discriminatedUnion('event', [
  accountChangeEventSchema,
  networkChangeEventSchema,
  disconnectEventSchema,
]);
export type PageProviderEvent = z.infer<typeof pageProviderEventSchema>;
export type ProviderEventName = PageProviderEvent['event'];

export const runtimeProviderRequestSchema = z
  .object({
    type: z.literal('drey:provider:request'),
    protocolVersion: z.literal(PROVIDER_BRIDGE_VERSION),
    requestNonce: bridgeRequestIdSchema,
    method: methodSchema,
    params: z.unknown().optional(),
  })
  .strict();
export type RuntimeProviderRequest = z.infer<typeof runtimeProviderRequestSchema>;

export const runtimeProviderResponseSchema = z.discriminatedUnion('ok', [
  z
    .object({
      type: z.literal('drey:provider:response'),
      protocolVersion: z.literal(PROVIDER_BRIDGE_VERSION),
      requestNonce: bridgeRequestIdSchema,
      ok: z.literal(true),
      result: z.unknown(),
    })
    .strict(),
  z
    .object({
      type: z.literal('drey:provider:response'),
      protocolVersion: z.literal(PROVIDER_BRIDGE_VERSION),
      requestNonce: bridgeRequestIdSchema,
      ok: z.literal(false),
      error: bridgeJsonRpcErrorSchema,
    })
    .strict(),
]);
export type RuntimeProviderResponse = z.infer<typeof runtimeProviderResponseSchema>;

export const runtimeProviderEventSchema = pageProviderEventSchema;
