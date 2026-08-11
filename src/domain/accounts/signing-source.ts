import { z } from 'zod';
import {
  publicAccountFromSeed,
  publicAccountDefinitionSchema,
  publicAccountsMatch,
  type PublicAccountDefinitionV1,
} from './public-account';
import type { Network } from '../keys/derivation';

/**
 * Current signing attachments. Ledger and offline PSBT transports intentionally
 * do not appear until they have real implementations; adding either extends
 * this versioned boundary without changing the public account definition.
 */
export type AccountSigningSourceV1 =
  | { version: 1; kind: 'software'; vaultId: string }
  | { version: 1; kind: 'none' };

export const accountSigningSourceSchema: z.ZodType<AccountSigningSourceV1> = z.discriminatedUnion(
  'kind',
  [
    z.object({ version: z.literal(1), kind: z.literal('software'), vaultId: z.string().min(1) }).strict(),
    z.object({ version: z.literal(1), kind: z.literal('none') }).strict(),
  ],
);

/**
 * Shared proof boundary for a future signer attachment. A signer-derived
 * public account must match every descriptor, origin, fingerprint, xpub,
 * network, account index, and deterministic account ID exactly.
 */
export function assertSignerMatchesPublicAccount(
  watched: PublicAccountDefinitionV1,
  signerDerived: PublicAccountDefinitionV1,
): void {
  publicAccountDefinitionSchema.parse(watched);
  publicAccountDefinitionSchema.parse(signerDerived);
  if (!publicAccountsMatch(watched, signerDerived)) {
    throw new Error('signer public account does not match watched account');
  }
}

/**
 * Deterministic legacy migration: project an existing software seed account
 * into the new public definition plus a separate signer binding. The caller
 * encrypts those two records independently and only then removes legacy
 * numeric-identity metadata.
 */
export function migrateLegacySoftwareAccountV1(
  seed: Uint8Array,
  network: Network,
  accountIndex: number,
  vaultId: string,
): {
  definition: PublicAccountDefinitionV1;
  binding: { version: 1; accountId: string; signingSource: AccountSigningSourceV1 };
} {
  if (vaultId.length === 0) throw new Error('software vault required');
  const definition = publicAccountFromSeed(seed, network, accountIndex);
  return {
    definition,
    binding: {
      version: 1,
      accountId: definition.accountId,
      signingSource: { version: 1, kind: 'software', vaultId },
    },
  };
}
