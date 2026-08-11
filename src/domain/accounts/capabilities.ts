import type { Network } from '../keys/derivation';

export type SignMethod = 'software' | 'ledger' | 'external' | 'none';

/**
 * Derived, never-persisted account feature matrix (spec §9.1).  Capability
 * values describe features that are actually wired today; future transports
 * must extend this derivation instead of scattering account-kind checks.
 */
export interface AccountCapabilities {
  signMethod: SignMethod;
  canView: boolean;
  canDeriveAddresses: boolean;
  canPlanTransactions: boolean;
  canSignTransactions: boolean;
  canSignMessages: boolean;
  canBroadcast: boolean;
  canExposeToProviders: boolean;
  canUseMarketplaces: boolean;
  canBuildUnsignedPsbt: boolean;
  canSignPsbt: boolean;
  canSignBip322: boolean;
  canRevealSeed: boolean;
  canExportPublicAccount: boolean;
  canVerifyAddress: boolean;
}

export interface AccountCapabilityContext {
  unlocked: boolean;
  vaultType: 'seed' | 'ledger' | 'watch_only';
  network: Network;
  transport: 'software' | 'ledger' | 'offline';
}

/** Persisted signing attachment is separate from the public account definition. */
export type ActiveSigningSource =
  | { kind: 'software' }
  | { kind: 'none' };

export interface PublicAccountCapabilityContext {
  unlocked: boolean;
  network: Network;
  signingSource: ActiveSigningSource;
}

const NONE: AccountCapabilities = Object.freeze({
  signMethod: 'none',
  canView: false,
  canDeriveAddresses: false,
  canPlanTransactions: false,
  canSignTransactions: false,
  canSignMessages: false,
  canBroadcast: false,
  canExposeToProviders: false,
  canUseMarketplaces: false,
  canBuildUnsignedPsbt: false,
  canSignPsbt: false,
  canSignBip322: false,
  canRevealSeed: false,
  canExportPublicAccount: false,
  canVerifyAddress: false,
});

export function derivePublicAccountCapabilities(
  context: PublicAccountCapabilityContext,
): AccountCapabilities {
  if (!context.unlocked) return NONE;
  if (context.signingSource.kind === 'none') {
    return Object.freeze({
      signMethod: 'none',
      canView: true,
      canDeriveAddresses: true,
      canPlanTransactions: true,
      canSignTransactions: false,
      canSignMessages: false,
      canBroadcast: false,
      canExposeToProviders: false,
      canUseMarketplaces: false,
      canBuildUnsignedPsbt: true,
      canSignPsbt: false,
      canSignBip322: false,
      canRevealSeed: false,
      canExportPublicAccount: true,
      canVerifyAddress: false,
    });
  }
  // `network` is intentionally part of the derivation input even though both
  // currently supported networks have the same software feature set.
  void context.network;
  return Object.freeze({
    signMethod: 'software',
    canView: true,
    canDeriveAddresses: true,
    canPlanTransactions: true,
    canSignTransactions: true,
    canSignMessages: true,
    canBroadcast: true,
    canExposeToProviders: true,
    canUseMarketplaces: true,
    canBuildUnsignedPsbt: true,
    canSignPsbt: true,
    canSignBip322: true,
    canRevealSeed: true,
    canExportPublicAccount: true,
    canVerifyAddress: false,
  });
}

/** Compatibility adapter for the original vault/transport-oriented call sites. */
export function deriveAccountCapabilities(context: AccountCapabilityContext): AccountCapabilities {
  const software = context.vaultType === 'seed' && context.transport === 'software';
  const watchOnly = context.vaultType === 'watch_only';
  if (!software && !watchOnly) return NONE;
  return derivePublicAccountCapabilities({
    unlocked: context.unlocked,
    network: context.network,
    signingSource: software ? { kind: 'software' } : { kind: 'none' },
  });
}
