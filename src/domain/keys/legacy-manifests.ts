/**
 * Xverse legacy-path manifest (spec §8.2) — compatibility DATA, not copied
 * wallet logic (§4: Xverse source is behavioral research only).
 *
 * Pinned 2026-07-21 from independently verified public behavior:
 * - Xverse support article "Understanding Derivation Paths and Xverse Wallet
 *   Compatibility" (id 28787677710989): payment paths m/49'/0'/0'/0/N
 *   (nested SegWit) and m/84'/0'/0'/0/N (native SegWit after the 2024
 *   account migration), ordinals m/86'/0'/0'/0/N.
 * - Magic Eden help article "Understanding Merged Xverse Accounts": Xverse
 *   derives additional SOFTWARE accounts by incrementing the ADDRESS INDEX at
 *   hardened account 0 (account N ⇒ .../0'/0/N), not the hardened account
 *   index.
 * - Xverse "Account Migration Guide" (xverse.app/blog): the nested→native
 *   SegWit generation change; both generations remain discoverable.
 * - Xverse Ledger accounts use STANDARD hardened account increments
 *   (support article on Ledger + Ledger Live conflicts) — recorded in
 *   ledgerPolicy, consumed by M10, ignored by software-seed discovery.
 *
 * Derivation math per purpose is pinned by the BIP49/84/86 spec test vectors
 * in tests/keys/legacy-manifests.test.ts (all three BIPs publish vectors for
 * the same well-known mnemonic).
 *
 * VERIFICATION GATE (§8.2): the account-mapping behavior additionally requires
 * a spot-check of 2–3 derived addresses against a throwaway real Xverse
 * install before this manifest is treated as final.
 */
import { NETWORK, TEST_NETWORK, p2sh, p2tr, p2wpkh } from '@scure/btc-signer';
import type { HDKey } from '@scure/bip32';
import { assertBip32Index, type AddressKind, type Network } from './derivation';

export type LegacyAddressType = 'p2sh-p2wpkh' | 'p2wpkh' | 'p2tr';

export interface LegacyPathEntry {
  /** Stable id, used in scan-unit labels and cache keys. */
  id: string;
  addressType: LegacyAddressType;
  purpose: 49 | 84 | 86;
  /** Which Drey lane funds discovered here migrate toward (§8.3). */
  lane: AddressKind;
  /**
   * 'address-index-at-account-0': legacy wallet account N lives at
   * m/purpose'/coin'/0'/0/N (the Xverse software quirk). Discovery iterates N
   * with the normal gap limit.
   */
  accountMapping: 'address-index-at-account-0';
  /** M10 (Ledger) policy note; software discovery ignores it. */
  ledgerPolicy: string | null;
}

export interface LegacyPathManifest {
  id: 'xverse';
  /** Source version/date the behavior was pinned from. */
  sourceVersion: string;
  network: Network;
  entries: LegacyPathEntry[];
}

const XVERSE_ENTRIES: LegacyPathEntry[] = [
  {
    id: 'xverse-nested-payment',
    addressType: 'p2sh-p2wpkh',
    purpose: 49,
    lane: 'payment',
    accountMapping: 'address-index-at-account-0',
    ledgerPolicy: 'ledger accounts use standard hardened account increments (m/49\'/coin\'/N\')',
  },
  {
    id: 'xverse-native-payment',
    addressType: 'p2wpkh',
    purpose: 84,
    lane: 'payment',
    accountMapping: 'address-index-at-account-0',
    ledgerPolicy: 'ledger accounts use standard hardened account increments (m/84\'/coin\'/N\')',
  },
  {
    id: 'xverse-ordinals',
    addressType: 'p2tr',
    purpose: 86,
    lane: 'ordinals',
    accountMapping: 'address-index-at-account-0',
    ledgerPolicy: 'ledger accounts use standard hardened account increments (m/86\'/coin\'/N\')',
  },
];

const SOURCE_VERSION = 'public-behavior-2026-07-21 (support#28787677710989, magiceden#8847421, migration-guide)';

export const XVERSE_MANIFEST_MAINNET: LegacyPathManifest = {
  id: 'xverse',
  sourceVersion: SOURCE_VERSION,
  network: 'mainnet',
  entries: XVERSE_ENTRIES,
};

export const XVERSE_MANIFEST_SIGNET: LegacyPathManifest = {
  id: 'xverse',
  sourceVersion: SOURCE_VERSION,
  network: 'signet',
  entries: XVERSE_ENTRIES,
};

export function xverseManifest(network: Network): LegacyPathManifest {
  return network === 'mainnet' ? XVERSE_MANIFEST_MAINNET : XVERSE_MANIFEST_SIGNET;
}

const COIN_TYPE: Record<Network, number> = { mainnet: 0, signet: 1 };

/** m/purpose'/coin'/0' — the single hardened account legacy discovery scans. */
export function legacyAccountPath(entry: LegacyPathEntry, network: Network): string {
  return `m/${entry.purpose}'/${COIN_TYPE[network]}'/0'`;
}

export interface LegacyAddressInfo {
  address: string;
  path: string;
  publicKeyHex: string;
  scriptPubKeyHex: string;
}

/**
 * Derive legacy address `index` on `chain` under an account-level node for
 * `entry` (node must be the depth-3 key for legacyAccountPath). Legacy wallet
 * "account N" is chain 0, index N per the pinned accountMapping.
 */
export function deriveLegacyAddress(
  node: HDKey,
  entry: LegacyPathEntry,
  network: Network,
  chain: 0 | 1,
  index: number,
): LegacyAddressInfo {
  assertBip32Index(index, 'legacy address index');
  if (node.depth !== 3) throw new Error(`expected depth-3 account node, got depth ${node.depth}`);
  const key = node.deriveChild(chain).deriveChild(index);
  const publicKey = key.publicKey;
  if (!publicKey) throw new Error('derived node has no public key');
  const net = network === 'mainnet' ? NETWORK : TEST_NETWORK;
  const payment =
    entry.addressType === 'p2sh-p2wpkh'
      ? p2sh(p2wpkh(publicKey, net), net)
      : entry.addressType === 'p2wpkh'
        ? p2wpkh(publicKey, net)
        : p2tr(publicKey.slice(1), undefined, net);
  if (!payment.address || !payment.script) throw new Error('legacy address encoding failed');
  return {
    address: payment.address,
    path: `${legacyAccountPath(entry, network)}/${chain}/${index}`,
    publicKeyHex: bytesToHex(publicKey),
    scriptPubKeyHex: bytesToHex(payment.script),
  };
}

function bytesToHex(bytes: Uint8Array): string {
  let out = '';
  for (const b of bytes) out += b.toString(16).padStart(2, '0');
  return out;
}
