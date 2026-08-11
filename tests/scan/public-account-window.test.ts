import { beforeAll, describe, expect, it } from 'vitest';
import {
  derivePublicAccountAddress,
  publicAccountFromSeed,
} from '../../src/domain/accounts/public-account';
import { scriptHashFromScriptPubKey } from '../../src/domain/keys/script-hash';
import {
  buildAccountKeyRing,
  buildPublicAccountKeyRing,
  windowScriptHashes,
} from '../../src/scan/address-window';
import { buildPublicAccountScanUnits, unitKey } from '../../src/scan/scan-state';
import { installTestCryptoProvider } from '../helpers/install-crypto-provider';

const SEED = Uint8Array.from({ length: 32 }, (_, index) => 255 - index);

beforeAll(() => installTestCryptoProvider());

describe('descriptor-backed scan windows', () => {
  it('feeds both lanes and indexes beyond the gap limit into the normal scan port', () => {
    const definition = publicAccountFromSeed(SEED, 'signet', 0);
    const units = buildPublicAccountScanUnits(definition);
    const ring = buildPublicAccountKeyRing([definition], 'signet', units);

    expect(units.map(unitKey)).toEqual([
      `pub:${definition.accountId}:payment`,
      `pub:${definition.accountId}:ordinals`,
    ]);
    for (const unit of units) {
      const rows = windowScriptHashes(ring, unit, 0, 0, 22);
      expect(rows).toHaveLength(22);
      for (const index of [0, 1, 21]) {
        const expected = derivePublicAccountAddress(definition, unit.lane, 0, index);
        expect(rows[index]).toEqual({
          chain: 0,
          index,
          scriptHash: scriptHashFromScriptPubKey(expected.scriptPubKeyHex),
          scriptPubKey: expected.scriptPubKeyHex,
        });
      }
      expect(ring.descriptor.get(unitKey(unit))?.privateKey).toBeNull();
    }
  });

  it('fails closed when a scan unit claims another public account identity', () => {
    const definition = publicAccountFromSeed(SEED, 'mainnet', 0);
    const units = buildPublicAccountScanUnits(definition);
    expect(() => buildPublicAccountKeyRing([definition], 'mainnet', [
      { ...units[0]!, accountId: `acct_mainnet_${'a'.repeat(64)}` },
    ])).toThrow('does not match');
  });

  it('keeps software and imported accounts distinct when both use BIP32 account zero', () => {
    const software = publicAccountFromSeed(SEED, 'signet', 0);
    const importedSeed = Uint8Array.from({ length: 32 }, (_, index) => index + 1);
    const imported = publicAccountFromSeed(importedSeed, 'signet', 0);
    const softwareUnits = buildPublicAccountScanUnits(software, 'standard');
    const importedUnits = buildPublicAccountScanUnits(imported);

    expect(software.derivationAccountIndex).toBe(imported.derivationAccountIndex);
    expect(software.accountId).not.toBe(imported.accountId);
    expect(new Set([...softwareUnits, ...importedUnits].map(unitKey))).toHaveLength(4);

    const softwareRing = buildAccountKeyRing(SEED, 'signet', softwareUnits);
    const importedRing = buildPublicAccountKeyRing([imported], 'signet', importedUnits);
    expect(windowScriptHashes(softwareRing, softwareUnits[0]!, 0, 0, 1)[0]?.scriptPubKey)
      .not.toBe(windowScriptHashes(importedRing, importedUnits[0]!, 0, 0, 1)[0]?.scriptPubKey);
  });
});
