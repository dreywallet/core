import type { Network } from '../keys/derivation';
import type {
  MarketplaceAction,
  MarketplaceAssetKind,
  MarketplaceId,
  MarketplaceRole,
} from './types';

export const MARKETPLACE_REGISTRY_VERSION = 1 as const;

export interface MarketplaceStepRule {
  step: number;
  allowedSighashes: readonly number[];
  allowTaprootScriptPath: boolean;
  requiresCorrespondingOutput: boolean;
  mutationEnvelope: 'signature_fields_only';
}

export interface MarketplaceTemplate {
  registryVersion: typeof MARKETPLACE_REGISTRY_VERSION;
  marketplaceId: MarketplaceId;
  displayName: string;
  templateId: string;
  templateVersion: string;
  origins: readonly string[];
  action: MarketplaceAction;
  role: MarketplaceRole;
  assetKind: MarketplaceAssetKind;
  networks: readonly Network[];
  broadcaster: 'site' | 'wallet' | 'context';
  stepCount: number | 'context';
  steps: readonly MarketplaceStepRule[];
  sourceVersion: string;
  fixtureManifestDigest: string;
  freshnessMs: number;
  maxPsbtBytes: number;
  activation: 'fixture_only' | 'enabled';
}

const SATFLOW_ORIGINS = ['https://satflow.com', 'https://www.satflow.com'] as const;
const ORDNET_ORIGINS = ['https://ord.net', 'https://www.ord.net'] as const;
const OMB_WIKI_ORIGIN = ['https://ordinalmaxibiz.wiki'] as const;
const FIXTURE_DIGEST = 'cc85aecdb59b05de459d4e115a6705796e0c9b5f1731853c8cf5b894d2cfd5d7';
const FIVE_MINUTES = 5 * 60_000;

function step(
  index: number,
  allowedSighashes: readonly number[],
  allowTaprootScriptPath = false,
): MarketplaceStepRule {
  return {
    step: index,
    allowedSighashes,
    allowTaprootScriptPath,
    requiresCorrespondingOutput: allowedSighashes.includes(0x83),
    mutationEnvelope: 'signature_fields_only',
  };
}

function template(input: Omit<MarketplaceTemplate, 'registryVersion' | 'fixtureManifestDigest' |
  'freshnessMs' | 'maxPsbtBytes' | 'activation'> &
  Partial<Pick<MarketplaceTemplate, 'activation'>>): MarketplaceTemplate {
  return {
    registryVersion: MARKETPLACE_REGISTRY_VERSION,
    fixtureManifestDigest: FIXTURE_DIGEST,
    freshnessMs: FIVE_MINUTES,
    maxPsbtBytes: 1_500_000,
    // Enabling a template is a security-policy release and must be
    // accompanied by reviewed vendor fixtures. ord.net single-inscription
    // templates were enabled 2026-08-10 against the published Trading API
    // 1.0.0 OpenAPI contract; Satflow and the ord.net collection/trait
    // funding-parent design remain fixture-backed pending vendor evidence.
    activation: 'fixture_only',
    ...input,
  };
}

/**
 * Compile-time signing policy. Source/API versions are evidence labels, not a
 * remotely controlled capability switch. Only an extension release can change
 * this table.
 */
export const MARKETPLACE_TEMPLATES: readonly MarketplaceTemplate[] = Object.freeze([
  template({ marketplaceId: 'satflow', displayName: 'Satflow', templateId: 'satflow-auth',
    templateVersion: 'drey-1', origins: SATFLOW_ORIGINS, action: 'authenticate', role: 'buyer',
    assetKind: 'inscription', networks: ['mainnet'], broadcaster: 'site', stepCount: 1,
    steps: [], sourceVersion: '1.1.4-prod' }),
  template({ marketplaceId: 'satflow', displayName: 'Satflow', templateId: 'satflow-cancel-listing',
    templateVersion: 'drey-1', origins: SATFLOW_ORIGINS, action: 'cancel', role: 'seller',
    assetKind: 'inscription', networks: ['mainnet'], broadcaster: 'site', stepCount: 1,
    steps: [], sourceVersion: '1.1.4-prod' }),
  template({ marketplaceId: 'satflow', displayName: 'Satflow', templateId: 'satflow-list-ordinal',
    templateVersion: 'drey-1', origins: SATFLOW_ORIGINS, action: 'list', role: 'seller',
    assetKind: 'inscription', networks: ['mainnet'], broadcaster: 'site', stepCount: 2,
    steps: [step(1, [0x83]), step(2, [0x81])], sourceVersion: '1.1.4-prod' }),
  template({ marketplaceId: 'satflow', displayName: 'Satflow', templateId: 'satflow-bulk-list-ordinal',
    templateVersion: 'drey-1', origins: SATFLOW_ORIGINS, action: 'bulk_list', role: 'seller',
    assetKind: 'inscription', networks: ['mainnet'], broadcaster: 'site', stepCount: 'context',
    steps: [step(1, [0x83]), step(2, [0x81])], sourceVersion: '1.1.4-prod' }),
  template({ marketplaceId: 'satflow', displayName: 'Satflow', templateId: 'satflow-buy-ordinal',
    templateVersion: 'drey-1', origins: SATFLOW_ORIGINS, action: 'buy', role: 'buyer',
    assetKind: 'inscription', networks: ['mainnet'], broadcaster: 'site', stepCount: 'context',
    steps: [step(1, [0, 1])], sourceVersion: '1.1.4-prod' }),
  template({ marketplaceId: 'satflow', displayName: 'Satflow', templateId: 'satflow-secure-buy-ordinal',
    templateVersion: 'drey-1', origins: SATFLOW_ORIGINS, action: 'secure_buy', role: 'buyer',
    assetKind: 'inscription', networks: ['mainnet'], broadcaster: 'site', stepCount: 'context',
    steps: [step(1, [0, 1]), step(2, [0, 1]), step(3, [0, 1])], sourceVersion: '1.1.4-prod' }),
  template({ marketplaceId: 'satflow', displayName: 'Satflow', templateId: 'satflow-offer',
    templateVersion: 'drey-1', origins: SATFLOW_ORIGINS, action: 'offer', role: 'buyer',
    assetKind: 'inscription', networks: ['mainnet'], broadcaster: 'site', stepCount: 1,
    steps: [step(1, [0, 1])], sourceVersion: '1.1.4-prod' }),
  template({ marketplaceId: 'satflow', displayName: 'OMB Wiki · Satflow',
    templateId: 'omb-wiki-satflow-secure-buy', templateVersion: 'omb-wiki-satflow-secure-buy-v1',
    origins: OMB_WIKI_ORIGIN, action: 'secure_buy', role: 'buyer', assetKind: 'inscription',
    networks: ['mainnet'], broadcaster: 'site', stepCount: 'context',
    steps: [step(1, [0, 1]), step(2, [0, 1])], sourceVersion: 'omb-wiki-contract-v1',
    activation: 'enabled' }),

  // ord.net Trading API 1.0.0 (developers.ord.net OpenAPI, accessed
  // 2026-08-10). Single-inscription trading flows are enabled; batch listing
  // preflights (2..20 items) are not represented and fail closed.
  template({ marketplaceId: 'ordnet', displayName: 'ord.net', templateId: 'ordnet-auth',
    templateVersion: 'drey-1', origins: ORDNET_ORIGINS, action: 'authenticate', role: 'buyer',
    assetKind: 'inscription', networks: ['mainnet'], broadcaster: 'site', stepCount: 1,
    steps: [], sourceVersion: 'trading-api-1.0.0', activation: 'enabled' }),
  // Listing PSBT steps: escrow transfer (DEFAULT), settlement leg
  // (SINGLE|ANYONECANPAY over the pinned 2-of-2 script path), batch recovery
  // (ALL). The recovery PSBT covers the whole preflight batch; only
  // single-listing preflights map onto this three-step template.
  template({ marketplaceId: 'ordnet', displayName: 'ord.net', templateId: 'ordnet-list',
    templateVersion: 'drey-1', origins: ORDNET_ORIGINS, action: 'list', role: 'seller',
    assetKind: 'inscription', networks: ['mainnet'], broadcaster: 'site', stepCount: 3,
    steps: [step(1, [0]), step(2, [0x83], true), step(3, [1])],
    sourceVersion: 'trading-api-1.0.0', activation: 'enabled' }),
  template({ marketplaceId: 'ordnet', displayName: 'ord.net', templateId: 'ordnet-buy',
    templateVersion: 'drey-1', origins: ORDNET_ORIGINS, action: 'buy', role: 'buyer',
    assetKind: 'inscription', networks: ['mainnet'], broadcaster: 'site', stepCount: 1,
    steps: [step(1, [0, 1])], sourceVersion: 'trading-api-1.0.0', activation: 'enabled' }),
  template({ marketplaceId: 'ordnet', displayName: 'OMB Wiki · ord.net',
    templateId: 'omb-wiki-ordnet-buy', templateVersion: 'omb-wiki-ordnet-buy-v1',
    origins: OMB_WIKI_ORIGIN, action: 'buy', role: 'buyer', assetKind: 'inscription',
    networks: ['mainnet'], broadcaster: 'site', stepCount: 1,
    steps: [step(1, [0, 1])], sourceVersion: 'omb-wiki-contract-v1', activation: 'enabled' }),
  template({ marketplaceId: 'ordnet', displayName: 'ord.net', templateId: 'ordnet-offer',
    templateVersion: 'drey-1', origins: ORDNET_ORIGINS, action: 'offer', role: 'buyer',
    assetKind: 'inscription', networks: ['mainnet'], broadcaster: 'site', stepCount: 1,
    steps: [step(1, [0, 1])], sourceVersion: 'trading-api-1.0.0', activation: 'enabled' }),
  // Counter steps: inscription transfer (DEFAULT), settlement and recovery
  // (both ALL|ANYONECANPAY), per the published counteroffer sighash table.
  template({ marketplaceId: 'ordnet', displayName: 'ord.net', templateId: 'ordnet-counter',
    templateVersion: 'drey-1', origins: ORDNET_ORIGINS, action: 'counter_offer', role: 'seller',
    assetKind: 'inscription', networks: ['mainnet'], broadcaster: 'site', stepCount: 3,
    steps: [step(1, [0]), step(2, [0x81]), step(3, [0x81])],
    sourceVersion: 'trading-api-1.0.0', activation: 'enabled' }),
  // Seller acceptance signs the settlement leg SINGLE|ANYONECANPAY; a second
  // payout step, when present, is deterministic.
  template({ marketplaceId: 'ordnet', displayName: 'ord.net', templateId: 'ordnet-accept-offer',
    templateVersion: 'drey-1', origins: ORDNET_ORIGINS, action: 'accept_offer', role: 'seller',
    assetKind: 'inscription', networks: ['mainnet'], broadcaster: 'site', stepCount: 'context',
    steps: [step(1, [0x83]), step(2, [0, 1])],
    sourceVersion: 'trading-api-1.0.0', activation: 'enabled' }),
  // Buyer counter acceptance signs deterministic funding and settlement steps.
  template({ marketplaceId: 'ordnet', displayName: 'ord.net', templateId: 'ordnet-accept-counter',
    templateVersion: 'drey-1', origins: ORDNET_ORIGINS, action: 'accept_counter', role: 'buyer',
    assetKind: 'inscription', networks: ['mainnet'], broadcaster: 'site', stepCount: 2,
    steps: [step(1, [0, 1]), step(2, [0, 1])],
    sourceVersion: 'trading-api-1.0.0', activation: 'enabled' }),
  // The v2 collection/trait funding-parent design (four-key fill gate, zero-fee
  // TRUC parents, enclave co-signer) is fixture-backed only until it is
  // independently reviewed against live behavior.
  template({ marketplaceId: 'ordnet', displayName: 'ord.net', templateId: 'ordnet-collection-offer-v2',
    templateVersion: 'drey-1', origins: ORDNET_ORIGINS, action: 'collection_offer', role: 'buyer',
    assetKind: 'collection', networks: ['mainnet'], broadcaster: 'site', stepCount: 'context',
    steps: [step(1, [0, 1])], sourceVersion: 'trading-api-1.0.0/ordnet-offer-v2' }),
  template({ marketplaceId: 'ordnet', displayName: 'ord.net', templateId: 'ordnet-trait-offer-v2',
    templateVersion: 'drey-1', origins: ORDNET_ORIGINS, action: 'trait_offer', role: 'buyer',
    assetKind: 'trait', networks: ['mainnet'], broadcaster: 'site', stepCount: 'context',
    steps: [step(1, [0, 1])], sourceVersion: 'trading-api-1.0.0/ordnet-offer-v2' }),
]);

export function assertMarketplaceRegistryIntegrity(
  registry: readonly MarketplaceTemplate[] = MARKETPLACE_TEMPLATES,
): void {
  const keys = new Set<string>();
  for (const entry of registry) {
    if (entry.origins.length === 0 || entry.steps.some((rule, index) => rule.step !== index + 1)) {
      throw new Error(`invalid marketplace template ${entry.templateId}`);
    }
    for (const origin of entry.origins) {
      const parsed = new URL(origin);
      if (parsed.protocol !== 'https:' || parsed.origin !== origin || parsed.pathname !== '/' ||
          origin.includes('*')) throw new Error(`unsafe marketplace origin ${origin}`);
      const key = [origin, entry.marketplaceId, entry.templateVersion, entry.action, entry.role,
        entry.assetKind, entry.networks.join(',')].join('|');
      if (keys.has(key)) throw new Error(`overlapping marketplace template ${key}`);
      keys.add(key);
    }
    for (const rule of entry.steps) {
      if (rule.allowedSighashes.length === 0 || rule.allowedSighashes.some((value) =>
        ![0, 1, 0x81, 0x83].includes(value))) throw new Error(`unsafe sighash policy ${entry.templateId}`);
    }
    if (entry.activation !== 'fixture_only' && entry.activation !== 'enabled') {
      throw new Error(`invalid marketplace activation ${entry.templateId}`);
    }
    // Reviewed activation scope (2026-08-10): only ord.net single-inscription
    // trading is enabled. Widening this scope is itself a policy release.
    const reviewedOmbBuyer = entry.origins.length === 1 &&
      entry.origins[0] === OMB_WIKI_ORIGIN[0] && entry.role === 'buyer' &&
      entry.assetKind === 'inscription' && entry.broadcaster === 'site' &&
      ((entry.marketplaceId === 'ordnet' && entry.action === 'buy') ||
        (entry.marketplaceId === 'satflow' && entry.action === 'secure_buy'));
    if (entry.activation === 'enabled' && !reviewedOmbBuyer &&
        (entry.marketplaceId !== 'ordnet' || entry.assetKind !== 'inscription')) {
      throw new Error(`marketplace activation outside the reviewed scope ${entry.templateId}`);
    }
  }
}

export function marketplaceForOrigin(origin: string): MarketplaceId | null {
  return MARKETPLACE_TEMPLATES.find((entry) => entry.origins.includes(origin))?.marketplaceId ?? null;
}

export function marketplacesForOrigin(origin: string): MarketplaceId[] {
  return [...new Set(MARKETPLACE_TEMPLATES.filter((entry) => entry.origins.includes(origin))
    .map((entry) => entry.marketplaceId))];
}
