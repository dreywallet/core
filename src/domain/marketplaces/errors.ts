import type { ProviderErrorCode } from '../../provider/errors';

export class MarketplaceProviderError extends Error {
  readonly providerCode: Extract<ProviderErrorCode,
    'ERR_UNSUPPORTED_MARKETPLACE' | 'ERR_UNSUPPORTED_TEMPLATE' | 'ERR_MARKETPLACE_STATE_CHANGED'>;

  constructor(providerCode: MarketplaceProviderError['providerCode'], message: string) {
    super(message);
    this.name = 'MarketplaceProviderError';
    this.providerCode = providerCode;
  }
}

