import { describe, expect, it } from 'vitest';
import { mnemonicToSeed } from '../../src/domain/keys/mnemonic';
import { bytesToHex } from '../../src/domain/vault/encoding';
import {
  createBackupMetadata,
  migrateLegacyBackupMetadata,
  recordBackupSpotCheck,
  verifyFullRecoveryRehearsal,
} from '../../src/domain/vault/backup-metadata';

const WORDS = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

describe('backup metadata and full recovery rehearsal', () => {
  it('keeps legacy provenance unknown while preserving the usage gate', () => {
    expect(migrateLegacyBackupMetadata(true)).toEqual({
      version: 1, origin: 'legacy_unknown', usageGatePassed: true, wordCount: null,
      usesPassphrase: null, lastSpotCheckAt: null, lastFullRecoveryCheckAt: null,
    });
    const generated = createBackupMetadata({ origin: 'generated', wordCount: 12, usesPassphrase: false });
    expect(recordBackupSpotCheck(generated, 123)).toMatchObject({ usageGatePassed: true, lastSpotCheckAt: 123 });
  });

  it('returns only aggregate success for phrase and passphrase checks', () => {
    const expectedSeedHex = bytesToHex(mnemonicToSeed(WORDS, 'secret'));
    expect(verifyFullRecoveryRehearsal({ mnemonic: WORDS, passphrase: 'secret', expectedSeedHex })).toBe(true);
    expect(verifyFullRecoveryRehearsal({ mnemonic: WORDS, passphrase: 'wrong', expectedSeedHex })).toBe(false);
    expect(verifyFullRecoveryRehearsal({ mnemonic: 'wrong', expectedSeedHex })).toBe(false);
  });
});
