import { describe, expect, it } from 'vitest';
import { deriveAccountCapabilities } from '../../src/domain/accounts/capabilities';

describe('derived account capabilities', () => {
  it('reports only capabilities implemented by the unlocked software seed vault', () => {
    expect(deriveAccountCapabilities({
      unlocked: true, vaultType: 'seed', network: 'signet', transport: 'software',
    })).toEqual({
      signMethod: 'software', canView: true, canDeriveAddresses: true,
      canPlanTransactions: true, canSignTransactions: true, canSignMessages: true,
      canBroadcast: true, canExposeToProviders: true, canUseMarketplaces: true,
      canBuildUnsignedPsbt: true, canSignPsbt: true,
      canSignBip322: true, canRevealSeed: true, canExportPublicAccount: true,
      canVerifyAddress: false,
    });
  });

  it('enables public watch-only behavior while refusing every private-key operation', () => {
    expect(deriveAccountCapabilities({
      unlocked: true, vaultType: 'watch_only', network: 'mainnet', transport: 'offline',
    })).toEqual({
      signMethod: 'none', canView: true, canDeriveAddresses: true,
      canPlanTransactions: true, canSignTransactions: false, canSignMessages: false,
      canBroadcast: false, canExposeToProviders: false, canUseMarketplaces: false,
      canBuildUnsignedPsbt: true, canSignPsbt: false, canSignBip322: false,
      canRevealSeed: false, canExportPublicAccount: true, canVerifyAddress: false,
    });
  });

  it('does not advertise deferred Ledger or offline signing transports', () => {
    expect(deriveAccountCapabilities({
      unlocked: true, vaultType: 'ledger', network: 'mainnet', transport: 'ledger',
    }).signMethod).toBe('none');
  });

  it('hides even public capabilities while locked', () => {
    expect(deriveAccountCapabilities({
      unlocked: false, vaultType: 'watch_only', network: 'signet', transport: 'offline',
    }).canView).toBe(false);
  });
});
