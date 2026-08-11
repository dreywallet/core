/**
 * Versioned, deny-by-default provider operation registry (spec §20.2).
 *
 * This registry is deliberately separate from trusted extension-page RPC.
 * Only the Bitcoin/Sats Connect/WBIP subset named by the specification is
 * registered. Request and response schemas are strict so neither page input
 * nor a worker response can silently grow an unsanctioned field.
 */
import { z } from 'zod';
import { validateBip322Message } from '../domain/transactions/bip322';
import { marketplaceContextSchema } from '../domain/marketplaces/types';

export const PROVIDER_OPERATION_VERSION = 1 as const;
/** Matches the worker's existing maximum supported PSBT input count. */
export const PROVIDER_MAX_SIGN_INPUTS = 200;

export const providerNetworkSchema = z.enum(['Mainnet', 'Signet']);
export type ProviderNetwork = z.infer<typeof providerNetworkSchema>;

export const providerNetworkResultSchema = z
  .object({
    bitcoin: z.object({ name: providerNetworkSchema }).strict(),
    stacks: z.object({ name: z.enum(['mainnet', 'testnet']) }).strict(),
    spark: z.object({ name: z.enum(['mainnet', 'regtest']) }).strict(),
  })
  .strict();
export type ProviderNetworkResult = z.infer<typeof providerNetworkResultSchema>;

export function providerNetworkResult(network: ProviderNetwork): ProviderNetworkResult {
  return network === 'Mainnet'
    ? {
        bitcoin: { name: 'Mainnet' },
        stacks: { name: 'mainnet' },
        spark: { name: 'mainnet' },
      }
    : {
        bitcoin: { name: 'Signet' },
        stacks: { name: 'testnet' },
        spark: { name: 'regtest' },
      };
}

export const addressPurposeSchema = z.enum(['payment', 'ordinals']);
export type AddressPurpose = z.infer<typeof addressPurposeSchema>;

export const dataCategorySchema = z.enum([
  'account_identity',
  'network',
  'addresses',
  'balance',
  'inscriptions',
]);
export type DataCategory = z.infer<typeof dataCategorySchema>;

const emptyParamsSchema = z.union([z.undefined(), z.null(), z.object({}).strict()]);
const decimalSatsSchema = z.string().regex(/^(0|[1-9][0-9]*)$/u);
const txidSchema = z.string().regex(/^[0-9a-f]{64}$/u);
const publicKeySchema = z.string().regex(/^(?:[0-9a-f]{66}|[0-9a-f]{64})$/u);
const addressSchema = z.string().min(8).max(128);
const base64PsbtSchema = z
  .string()
  .min(1)
  .max(1_500_000)
  .regex(/^[A-Za-z0-9+/]+={0,2}$/u);

export const providerAddressSchema = z
  .object({
    address: addressSchema,
    publicKey: publicKeySchema,
    purpose: addressPurposeSchema,
    addressType: z.enum(['p2wpkh', 'p2tr']),
    walletType: z.literal('software'),
  })
  .strict();
export type ProviderAddress = z.infer<typeof providerAddressSchema>;

const accountResultSchema = z
  .object({
    id: z.string().min(1).max(128),
    addresses: z.array(providerAddressSchema).max(2),
    walletType: z.literal('software'),
    network: providerNetworkResultSchema,
  })
  .strict();

export const providerPermissionRequestSchema = z.discriminatedUnion('type', [
  z
    .object({
      type: z.literal('account'),
      // Display/request hint only. The worker derives the actual account.
      resourceId: z.string().min(1).max(128),
      actions: z.object({ read: z.literal(true) }).strict(),
      dataCategories: z
        .array(z.enum(['account', 'addresses', 'balance', 'inscriptions']))
        .min(1)
        .max(4)
        .optional(),
    })
    .strict(),
  z
    .object({
      type: z.literal('wallet'),
      resourceId: z.literal('wallet'),
      actions: z.object({ readNetwork: z.literal(true) }).strict(),
      dataCategories: z.tuple([z.literal('network')]).optional(),
    })
    .strict(),
]);

export type ProviderPermissionRequest = z.infer<typeof providerPermissionRequestSchema>;

export const providerPermissionGrantSchema = z.discriminatedUnion('type', [
  z
    .object({
      type: z.literal('account'),
      resourceId: z.string().min(1).max(128),
      clientId: z.string().url(),
      actions: z.object({ read: z.literal(true) }).strict(),
      dataCategories: z
        .array(z.enum(['account', 'addresses', 'balance', 'inscriptions']))
        .min(1)
        .max(4),
    })
    .strict(),
  z
    .object({
      type: z.literal('wallet'),
      resourceId: z.literal('wallet'),
      clientId: z.string().url(),
      actions: z.object({ readNetwork: z.literal(true) }).strict(),
      dataCategories: z.tuple([z.literal('network')]),
    })
    .strict(),
]);

export type ProviderPermissionGrant = z.infer<typeof providerPermissionGrantSchema>;

export const providerConnectParamsSchema = z.union([
  z.undefined(),
  z.null(),
  z
    .object({
      permissions: z.array(providerPermissionRequestSchema).max(2).optional(),
      addresses: z.array(addressPurposeSchema).min(1).max(2).optional(),
      message: z.string().max(80).optional(),
      network: providerNetworkSchema.optional(),
    })
    .strict(),
]);

export type ProviderConnectParams = z.input<typeof providerConnectParamsSchema>;

export interface NormalizedProviderConnectionRequest {
  categories: DataCategory[];
  purposes: AddressPurpose[];
}

/** Canonical approve-all connection scope shared by every provider surface. */
export function normalizeProviderConnectionRequest(
  input: ProviderConnectParams,
): NormalizedProviderConnectionRequest {
  const value = providerConnectParamsSchema.parse(input);
  const purposes = value?.addresses
    ? [...new Set(value.addresses)].sort()
    : ['ordinals', 'payment'] as AddressPurpose[];
  const requested = value?.permissions?.flatMap((item) => item.dataCategories ??
    (item.type === 'account'
      ? ['account', 'addresses', 'balance', 'inscriptions'] as const
      : ['network'] as const)) ?? [];
  const categories = [
    'account_identity' as const,
    'network' as const,
    ...(purposes.length > 0 ? ['addresses' as const] : []),
    ...requested.map((category): DataCategory =>
      category === 'account' ? 'account_identity' : category),
  ];
  return {
    categories: [...new Set(categories)].sort(),
    purposes,
  };
}

const connectResultSchema = accountResultSchema;

const getAddressesParamsSchema = z
  .object({
    purposes: z.array(addressPurposeSchema).min(1).max(2),
    message: z.string().max(80).optional(),
  })
  .strict();

const getAddressesResultSchema = z
  .object({ addresses: z.array(providerAddressSchema).max(2), network: providerNetworkResultSchema })
  .strict();

const getAccountsResultSchema = z.array(providerAddressSchema).max(2);

const getBalanceResultSchema = z
  .object({ confirmed: decimalSatsSchema, unconfirmed: decimalSatsSchema, total: decimalSatsSchema })
  .strict();

const signMessageParamsSchema = z
  .object({
    address: addressSchema,
    message: z.string().superRefine((message, context) => {
      try {
        validateBip322Message(message);
      } catch {
        context.addIssue({ code: z.ZodIssueCode.custom, message: 'invalid BIP322 message' });
      }
    }),
    // Drey implements only strict BIP322 simple; ECDSA is intentionally absent.
    protocol: z.literal('BIP322').optional(),
    marketplaceContext: marketplaceContextSchema.optional(),
  })
  .strict();

const signMessageResultSchema = z
  .object({
    signature: z.string().min(1),
    messageHash: z.string().regex(/^[0-9a-f]{64}$/u),
    address: addressSchema,
    protocol: z.literal('BIP322'),
  })
  .strict();

const signInputsSchema = z
  .record(
    addressSchema,
    z
      .array(z.number().int().nonnegative().max(PROVIDER_MAX_SIGN_INPUTS - 1))
      .min(1)
      .max(PROVIDER_MAX_SIGN_INPUTS),
  )
  .superRefine((value, context) => {
    let total = 0;
    for (const indexes of Object.values(value)) {
      total += indexes.length;
      if (total > PROVIDER_MAX_SIGN_INPUTS) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          message: `signInputs may select at most ${PROVIDER_MAX_SIGN_INPUTS} inputs`,
        });
        return;
      }
    }
    if (total === 0) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'signInputs must select at least one input',
      });
    }
  });

const signPsbtParamsSchema = z
  .object({
    psbt: base64PsbtSchema,
    signInputs: signInputsSchema.optional(),
    broadcast: z.boolean().optional(),
    marketplaceContext: marketplaceContextSchema.optional(),
  })
  .strict();

const signPsbtResultSchema = z
  .object({
    psbt: base64PsbtSchema,
    txid: txidSchema.optional(),
  })
  .strict();

const transferRecipientSchema = z
  .object({ address: addressSchema, amount: z.number().int().positive().max(Number.MAX_SAFE_INTEGER) })
  .strict();
const sendTransferParamsSchema = z.object({ recipients: z.array(transferRecipientSchema).min(1).max(100) }).strict();

const inscriptionSchema = z
  .object({
    inscriptionId: z.string().min(1).max(256),
    inscriptionNumber: z.string().regex(/^-?(0|[1-9][0-9]*)$/u).optional(),
    satpoint: z.string().min(1).max(256),
    address: addressSchema,
    output: z.string().min(66).max(80),
    valueSats: decimalSatsSchema,
  })
  .strict();

const getInscriptionsParamsSchema = z
  .object({ offset: z.number().int().nonnegative(), limit: z.number().int().positive().max(100) })
  .strict();
const getInscriptionsResultSchema = z
  .object({
    total: z.number().int().nonnegative(),
    limit: z.number().int().positive().max(100),
    offset: z.number().int().nonnegative(),
    inscriptions: z.array(inscriptionSchema).max(100),
  })
  .strict();

const sendInscriptionsParamsSchema = z
  .object({
    // M8 authorizes exactly one transfer. Marketplace batches/templates are M9.
    transfers: z
      .tuple([
        z.object({ address: addressSchema, inscriptionId: z.string().min(1).max(256) }).strict(),
      ]),
  })
  .strict();

const getInfoResultSchema = z
  .object({
    version: z.string().regex(/^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/u),
    platform: z.enum(['web', 'mobile']),
    methods: z.array(z.string().min(1).max(128)),
    supports: z.tuple([z.literal('WBIP001'), z.literal('WBIP004')]),
  })
  .strict();

export interface ProviderOperationSpec {
  version: typeof PROVIDER_OPERATION_VERSION;
  request: z.ZodTypeAny;
  response: z.ZodTypeAny;
  requiresConnection: boolean;
  requiresUnlock: boolean;
  requiresFreshApproval: boolean;
  dataCategories: readonly DataCategory[];
}

const op = (
  request: z.ZodTypeAny,
  response: z.ZodTypeAny,
  policy: Omit<ProviderOperationSpec, 'version' | 'request' | 'response'>,
): ProviderOperationSpec => ({ version: PROVIDER_OPERATION_VERSION, request, response, ...policy });

const READ_ACCOUNT = {
  requiresConnection: true,
  requiresUnlock: true,
  requiresFreshApproval: false,
} as const;
const SIGN_OR_SEND = {
  requiresConnection: true,
  requiresUnlock: true,
  requiresFreshApproval: true,
} as const;

export const PROVIDER_OPERATIONS = {
  getInfo: op(emptyParamsSchema, getInfoResultSchema, {
    requiresConnection: false,
    requiresUnlock: false,
    requiresFreshApproval: false,
    dataCategories: [],
  }),
  wallet_connect: op(providerConnectParamsSchema, connectResultSchema, {
    requiresConnection: false,
    requiresUnlock: true,
    requiresFreshApproval: true,
    dataCategories: ['account_identity', 'network', 'addresses'],
  }),
  wallet_disconnect: op(emptyParamsSchema, z.null(), {
    requiresConnection: false,
    requiresUnlock: false,
    requiresFreshApproval: false,
    dataCategories: [],
  }),
  wallet_renouncePermissions: op(emptyParamsSchema, z.null(), {
    requiresConnection: false,
    requiresUnlock: false,
    requiresFreshApproval: false,
    dataCategories: [],
  }),
  wallet_getCurrentPermissions: op(emptyParamsSchema, z.array(providerPermissionGrantSchema).max(2), {
    requiresConnection: false,
    requiresUnlock: false,
    requiresFreshApproval: false,
    dataCategories: [],
  }),
  wallet_requestPermissions: op(z.array(providerPermissionRequestSchema).min(1).max(2), z.array(providerPermissionGrantSchema).max(2), {
    requiresConnection: false,
    requiresUnlock: true,
    requiresFreshApproval: true,
    dataCategories: [],
  }),
  wallet_getAccount: op(emptyParamsSchema, accountResultSchema, {
    ...READ_ACCOUNT,
    dataCategories: ['account_identity', 'network', 'addresses'],
  }),
  wallet_getNetwork: op(emptyParamsSchema, providerNetworkResultSchema, {
    ...READ_ACCOUNT,
    dataCategories: ['network'],
  }),
  getAddresses: op(getAddressesParamsSchema, getAddressesResultSchema, {
    ...READ_ACCOUNT,
    dataCategories: ['addresses', 'network'],
  }),
  getAccounts: op(getAddressesParamsSchema, getAccountsResultSchema, {
    ...READ_ACCOUNT,
    dataCategories: ['addresses'],
  }),
  getBalance: op(emptyParamsSchema, getBalanceResultSchema, {
    ...READ_ACCOUNT,
    dataCategories: ['balance'],
  }),
  signMessage: op(signMessageParamsSchema, signMessageResultSchema, {
    ...SIGN_OR_SEND,
    dataCategories: ['account_identity'],
  }),
  signPsbt: op(signPsbtParamsSchema, signPsbtResultSchema, {
    ...SIGN_OR_SEND,
    dataCategories: ['account_identity'],
  }),
  sendTransfer: op(sendTransferParamsSchema, z.object({ txid: txidSchema }).strict(), {
    ...SIGN_OR_SEND,
    dataCategories: ['account_identity', 'balance'],
  }),
  ord_getInscriptions: op(getInscriptionsParamsSchema, getInscriptionsResultSchema, {
    ...READ_ACCOUNT,
    dataCategories: ['inscriptions'],
  }),
  ord_sendInscriptions: op(sendInscriptionsParamsSchema, z.object({ txid: txidSchema }).strict(), {
    ...SIGN_OR_SEND,
    dataCategories: ['account_identity', 'inscriptions'],
  }),
} satisfies Record<string, ProviderOperationSpec>;

export type ProviderMethod = keyof typeof PROVIDER_OPERATIONS;
type ProviderSchemas = typeof PROVIDER_OPERATIONS;
export type ProviderRequest<M extends ProviderMethod> = z.input<ProviderSchemas[M]['request']>;
export type ProviderResult<M extends ProviderMethod> = z.output<ProviderSchemas[M]['response']>;

export const PROVIDER_METHODS = Object.freeze(Object.keys(PROVIDER_OPERATIONS) as ProviderMethod[]);

export function isProviderMethod(method: string): method is ProviderMethod {
  return Object.prototype.hasOwnProperty.call(PROVIDER_OPERATIONS, method);
}
