/**
 * §8.2 manifest verification: every entry's derivation math is pinned against
 * the INDEPENDENT public test vectors published in BIP49, BIP84, and BIP86
 * themselves (all three use the same well-known mnemonic). The Xverse
 * account-mapping quirk (address index at account 0) is exercised via the
 * index-1 vectors. Remaining human gate: spot-check against a real Xverse
 * install before the manifest is treated as final.
 */
import { describe, expect, it } from 'vitest';
import { HDKey } from '@scure/bip32';
import { mnemonicToSeedSync } from '@scure/bip39';
import {
  deriveLegacyAddress,
  legacyAccountPath,
  xverseManifest,
  XVERSE_MANIFEST_MAINNET,
  XVERSE_MANIFEST_SIGNET,
} from '../../src/domain/keys/legacy-manifests';

const MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const seed = mnemonicToSeedSync(MNEMONIC);

function entry(id: string) {
  const found = XVERSE_MANIFEST_MAINNET.entries.find((e) => e.id === id);
  if (!found) throw new Error(`missing manifest entry ${id}`);
  return found;
}

function accountNode(id: string, network: 'mainnet' | 'signet') {
  return HDKey.fromMasterSeed(seed).derive(legacyAccountPath(entry(id), network));
}

describe('Xverse legacy-path manifest (§8.2)', () => {
  it('identifies source version, network, address type, account mapping, and Ledger policy', () => {
    for (const manifest of [XVERSE_MANIFEST_MAINNET, XVERSE_MANIFEST_SIGNET]) {
      expect(manifest.sourceVersion).toContain('2026-07-21');
      expect(manifest.entries).toHaveLength(3);
      for (const e of manifest.entries) {
        expect(e.accountMapping).toBe('address-index-at-account-0');
        expect(e.ledgerPolicy).toContain('standard hardened account increments');
      }
    }
    expect(xverseManifest('signet')).toBe(XVERSE_MANIFEST_SIGNET);
  });

  it('nested SegWit payment matches the BIP49 spec test vector (testnet encoding)', () => {
    // BIP49 publishes its vector for testnet; signet shares the encoding.
    const info = deriveLegacyAddress(
      accountNode('xverse-nested-payment', 'signet'),
      entry('xverse-nested-payment'),
      'signet',
      0,
      0,
    );
    expect(info.address).toBe('2Mww8dCYPUpKHofjgcXcBCEGmniw9CoaiD2');
    expect(info.path).toBe("m/49'/1'/0'/0/0");
  });

  it('native SegWit payment matches the BIP84 spec test vectors, incl. the address-index mapping', () => {
    const node = accountNode('xverse-native-payment', 'mainnet');
    const e = entry('xverse-native-payment');
    // First receive address.
    expect(deriveLegacyAddress(node, e, 'mainnet', 0, 0).address).toBe(
      'bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu',
    );
    // BIP84's second-receive vector doubles as Xverse "Account 2"
    // (address-index-at-account-0 mapping ⇒ m/84'/0'/0'/0/1).
    const second = deriveLegacyAddress(node, e, 'mainnet', 0, 1);
    expect(second.address).toBe('bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g');
    expect(second.path).toBe("m/84'/0'/0'/0/1");
    // Change chain (BIP84 vector).
    expect(deriveLegacyAddress(node, e, 'mainnet', 1, 0).address).toBe(
      'bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el',
    );
  });

  it('ordinals matches the BIP86 spec test vectors, incl. the address-index mapping', () => {
    const node = accountNode('xverse-ordinals', 'mainnet');
    const e = entry('xverse-ordinals');
    expect(deriveLegacyAddress(node, e, 'mainnet', 0, 0).address).toBe(
      'bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr',
    );
    // BIP86 second-receive vector = Xverse ordinals "Account 2".
    expect(deriveLegacyAddress(node, e, 'mainnet', 0, 1).address).toBe(
      'bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh',
    );
    // BIP86 change vector.
    expect(deriveLegacyAddress(node, e, 'mainnet', 1, 0).address).toBe(
      'bc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqwruhk7',
    );
  });

  it('produces scriptPubKeys consistent with the address type', () => {
    const nested = deriveLegacyAddress(
      accountNode('xverse-nested-payment', 'mainnet'),
      entry('xverse-nested-payment'),
      'mainnet',
      0,
      0,
    );
    expect(nested.scriptPubKeyHex.startsWith('a914')).toBe(true); // OP_HASH160 push20
    expect(nested.scriptPubKeyHex.endsWith('87')).toBe(true); // OP_EQUAL

    const native = deriveLegacyAddress(
      accountNode('xverse-native-payment', 'mainnet'),
      entry('xverse-native-payment'),
      'mainnet',
      0,
      0,
    );
    expect(native.scriptPubKeyHex.startsWith('0014')).toBe(true);

    const taproot = deriveLegacyAddress(
      accountNode('xverse-ordinals', 'mainnet'),
      entry('xverse-ordinals'),
      'mainnet',
      0,
      0,
    );
    expect(taproot.scriptPubKeyHex.startsWith('5120')).toBe(true);
  });
});
