import { z } from 'zod';
import { restoreMnemonic } from '../keys/mnemonic';
import { hexToBytes } from './encoding';

export const recoveryWordCountSchema = z.union([
  z.literal(12), z.literal(15), z.literal(18), z.literal(21), z.literal(24),
]);
export type RecoveryWordCount = z.infer<typeof recoveryWordCountSchema>;

const knownBackupMetadata = {
  version: z.literal(1),
  usageGatePassed: z.boolean(),
  wordCount: recoveryWordCountSchema,
  usesPassphrase: z.boolean(),
  lastSpotCheckAt: z.number().int().nonnegative().nullable(),
  lastFullRecoveryCheckAt: z.number().int().nonnegative().nullable(),
} as const;

export const backupMetadataSchema = z.discriminatedUnion('origin', [
  z.object({ origin: z.literal('generated'), ...knownBackupMetadata }).strict(),
  z.object({ origin: z.literal('imported'), ...knownBackupMetadata }).strict(),
  z.object({
    origin: z.literal('legacy_unknown'),
    version: z.literal(1),
    usageGatePassed: z.boolean(),
    wordCount: recoveryWordCountSchema.nullable(),
    usesPassphrase: z.boolean().nullable(),
    lastSpotCheckAt: z.number().int().nonnegative().nullable(),
    lastFullRecoveryCheckAt: z.number().int().nonnegative().nullable(),
  }).strict(),
]);
export type BackupMetadataV1 = z.infer<typeof backupMetadataSchema>;

export function createBackupMetadata(input: {
  origin: 'generated' | 'imported';
  usageGatePassed?: boolean;
  wordCount: RecoveryWordCount;
  usesPassphrase: boolean;
}): BackupMetadataV1 {
  return backupMetadataSchema.parse({
    version: 1,
    origin: input.origin,
    usageGatePassed: input.usageGatePassed ?? false,
    wordCount: input.wordCount,
    usesPassphrase: input.usesPassphrase,
    lastSpotCheckAt: null,
    lastFullRecoveryCheckAt: null,
  });
}

/** Preserve a legacy usage gate without inventing how or when the wallet was backed up. */
export function migrateLegacyBackupMetadata(
  backupVerified: boolean,
  observed?: { wordCount: RecoveryWordCount; usesPassphrase: boolean },
): BackupMetadataV1 {
  return {
    version: 1,
    origin: 'legacy_unknown',
    usageGatePassed: backupVerified,
    wordCount: observed?.wordCount ?? null,
    usesPassphrase: observed?.usesPassphrase ?? null,
    lastSpotCheckAt: null,
    lastFullRecoveryCheckAt: null,
  };
}

export function recordBackupSpotCheck(metadata: BackupMetadataV1, completedAt: number): BackupMetadataV1 {
  return backupMetadataSchema.parse({
    ...metadata,
    usageGatePassed: true,
    lastSpotCheckAt: completedAt,
  });
}

export function recordFullRecoveryCheck(metadata: BackupMetadataV1, completedAt: number): BackupMetadataV1 {
  return backupMetadataSchema.parse({ ...metadata, lastFullRecoveryCheckAt: completedAt });
}

/**
 * Aggregate, local rehearsal check. No mismatch detail is returned, so this
 * cannot become a word-by-word oracle. The derived seed is wiped on every path.
 */
export function verifyFullRecoveryRehearsal(input: {
  mnemonic: string;
  passphrase?: string;
  expectedSeedHex: string;
}): boolean {
  if (!/^[0-9a-f]{128}$/u.test(input.expectedSeedHex)) throw new Error('invalid expected seed');
  const expected = hexToBytes(input.expectedSeedHex);
  let candidate: Uint8Array | undefined;
  try {
    try {
      candidate = restoreMnemonic(input.mnemonic, input.passphrase).seed;
    } catch {
      return false;
    }
    if (candidate.length !== expected.length) return false;
    let difference = 0;
    for (let index = 0; index < expected.length; index += 1) {
      difference |= expected[index]! ^ candidate[index]!;
    }
    return difference === 0;
  } finally {
    expected.fill(0);
    candidate?.fill(0);
  }
}
