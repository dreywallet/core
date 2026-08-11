import type { MarketplaceContext } from './types';

export interface MarketplaceContractCheck {
  ok: boolean;
  reason: string;
}

const ok = (): MarketplaceContractCheck => ({ ok: true, reason: 'context contract matched' });
const fail = (reason: string): MarketplaceContractCheck => ({ ok: false, reason });

/** Strict wallet-facing subset; fields not established by fixtures stay unsupported. */
export function validateMarketplaceContextContract(context: MarketplaceContext): MarketplaceContractCheck {
  const ids = context.identifiers;
  const economics = context.economics;
  if (context.expiresAt !== undefined && !Number.isSafeInteger(context.expiresAt)) {
    return fail('marketplace expiry is invalid');
  }
  if (context.marketplaceId === 'satflow') {
    if (context.action === 'cancel') {
      if (!ids?.orderId || !ids.inscriptionId || !context.revision || context.expiresAt === undefined) {
        return fail('Satflow cancellation is missing order, inscription, challenge revision, or expiry binding');
      }
      return ok();
    }
    if (context.action === 'list' || context.action === 'bulk_list' || context.action === 'accept_offer') {
      if (!ids?.inscriptionId || !economics?.sellerProceedsSats || !economics.payoutAddress) {
        return fail('Satflow seller contract is missing inscription, proceeds, or payout binding');
      }
    }
    if (context.action === 'buy' || context.action === 'secure_buy') {
      if (!ids?.inscriptionId || !economics?.totalSats || !economics.assetDestination) {
        return fail('Satflow purchase contract is missing inscription, total, or destination binding');
      }
    }
    return ok();
  }
  if (context.marketplaceId === 'ordnet') {
    // Trading API 1.0.0 replaced the preflight revision with server-issued
    // handles (anchor/purchase-anchor UUIDs, preflight tokens) and
    // expected-txid echoes. Every write must bind at least one of them so a
    // changed preflight invalidates the request instead of re-signing.
    if (context.action !== 'authenticate' && !ids?.preflightHandle && !context.expectedTxids) {
      return fail('ord.net write is missing its preflight handle or expected-txid binding');
    }
    if (context.action === 'list' && !ids?.preflightHandle) {
      return fail('ord.net listing is missing its anchor UTXO handle');
    }
    if (context.action === 'buy' || context.action === 'counter_offer') {
      if (!ids?.preflightHandle || !context.expectedTxids) {
        return fail('ord.net purchase/counter is missing its anchor handle or expected settlement binding');
      }
    }
    if (context.action === 'list' || context.action === 'accept_offer' || context.action === 'counter_offer') {
      if (!ids?.inscriptionId || !economics?.sellerProceedsSats || !economics.payoutAddress) {
        return fail('ord.net seller contract is missing inscription, proceeds, or payout binding');
      }
    }
    if (context.action === 'accept_offer' || context.action === 'accept_counter') {
      if (!ids?.offerId || !context.expectedTxids) {
        return fail('ord.net offer acceptance is missing its offer or expected settlement binding');
      }
    }
    if (context.action === 'buy' || context.action === 'accept_counter') {
      if (!economics?.totalSats || !economics.assetDestination) {
        return fail('ord.net purchase contract is missing total or owned destination binding');
      }
    }
    if ((context.action === 'collection_offer' || context.action === 'trait_offer') &&
        (!ids?.preflightHandle || !context.expectedTxids || context.assetKind === 'inscription')) {
      return fail('ord.net criteria offer is missing its preflight token, funding txid, or criteria binding');
    }
    return ok();
  }
  return fail('marketplace ID is not compiled into this extension release');
}

export function assertOrdnetSubmitBinding(input: {
  preflightHandle: string;
  originalHandle: string;
  originalFieldsHash: string;
  submittedFieldsHash: string;
  httpStatus?: number;
}): void {
  if (input.httpStatus === 409) throw new Error('ERR_MARKETPLACE_STATE_CHANGED');
  if (input.preflightHandle !== input.originalHandle || input.originalFieldsHash !== input.submittedFieldsHash) {
    throw new Error('ERR_MARKETPLACE_STATE_CHANGED');
  }
}

export function assertSequentialMarketplaceStep(input: {
  previousStep: number;
  nextStep: number;
  previousSignedHash: string;
  suppliedPriorSignedHash: string;
}): void {
  if (input.nextStep !== input.previousStep + 1 ||
      input.previousSignedHash !== input.suppliedPriorSignedHash) {
    throw new Error('ERR_MARKETPLACE_STATE_CHANGED');
  }
}
