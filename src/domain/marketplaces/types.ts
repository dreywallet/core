import { z } from 'zod';

export const marketplaceIdSchema = z.enum(['satflow', 'ordnet']);
export type MarketplaceId = z.infer<typeof marketplaceIdSchema>;

export const marketplaceActionSchema = z.enum([
  'authenticate',
  'cancel',
  'list',
  'bulk_list',
  'buy',
  'secure_buy',
  'offer',
  'accept_offer',
  'counter_offer',
  'accept_counter',
  'collection_offer',
  'trait_offer',
  'transfer',
  'extract',
  'recover',
]);
export type MarketplaceAction = z.infer<typeof marketplaceActionSchema>;

export const marketplaceRoleSchema = z.enum(['buyer', 'seller']);
export type MarketplaceRole = z.infer<typeof marketplaceRoleSchema>;

export const marketplaceAssetKindSchema = z.enum(['inscription', 'collection', 'trait']);
export type MarketplaceAssetKind = z.infer<typeof marketplaceAssetKindSchema>;

const decimalSatsSchema = z.string().regex(/^(0|[1-9][0-9]*)$/u);
const identifierSchema = z.string().min(1).max(256);

export const marketplaceContextSchema = z.object({
  version: z.number().int().positive().max(65_535),
  // Untrusted hint may name a marketplace introduced after this release. It
  // remains inert unless exact origin/template resolution maps it to a known ID.
  marketplaceId: z.string().regex(/^[a-z0-9][a-z0-9_-]*$/u).max(64),
  templateVersion: z.string().min(1).max(64),
  action: marketplaceActionSchema,
  role: marketplaceRoleSchema,
  assetKind: marketplaceAssetKindSchema,
  workflowId: z.string().min(1).max(128),
  step: z.number().int().positive().max(32),
  stepCount: z.number().int().positive().max(32),
  identifiers: z.object({
    listingId: identifierSchema.optional(),
    orderId: identifierSchema.optional(),
    offerId: identifierSchema.optional(),
    inscriptionId: identifierSchema.optional(),
    preflightHandle: identifierSchema.optional(),
  }).strict().optional(),
  economics: z.object({
    priceSats: decimalSatsSchema.optional(),
    totalSats: decimalSatsSchema.optional(),
    sellerProceedsSats: decimalSatsSchema.optional(),
    marketplaceFeeSats: decimalSatsSchema.optional(),
    royaltySats: decimalSatsSchema.optional(),
    minerFeeSats: decimalSatsSchema.optional(),
    payoutAddress: z.string().min(8).max(128).optional(),
    assetDestination: z.string().min(8).max(128).optional(),
  }).strict().optional(),
  revision: z.string().min(1).max(128).optional(),
  // Preflight-promised transaction ids (ord.net Trading API 1.0.0): the page
  // echoes these at submit; binding them lets a changed preflight force a
  // fresh approval instead of silently re-signing against new state.
  expectedTxids: z.array(z.string().regex(/^[0-9a-f]{64}$/u)).min(1).max(21).optional(),
  expiresAt: z.number().int().positive().optional(),
  broadcaster: z.enum(['site', 'wallet']),
}).strict().superRefine((value, ctx) => {
  if (value.step > value.stepCount) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['step'], message: 'step exceeds stepCount' });
  }
});

export type MarketplaceContext = z.infer<typeof marketplaceContextSchema>;

export type MarketplaceResolutionStatus =
  | 'recognized'
  | 'unknown_marketplace'
  | 'known_marketplace_unknown_version'
  | 'known_template_mismatch'
  | 'unsupported_action';

export interface MarketplaceResolution {
  status: MarketplaceResolutionStatus;
  marketplaceId: MarketplaceId | null;
  displayName: string | null;
  templateId: string | null;
  templateVersion: string | null;
  flexible: boolean;
  reason: string;
}
