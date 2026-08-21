/**
 * BIP84/BIP86 account and address derivation (spec §8.1).
 *
 * Mainnet coin type 0; signet and regtest use test coin type 1. Regtest shares
 * the test-network key versions but has its own bech32 hrp ("bcrt").
 */
import { HDKey } from '@scure/bip32';
import { NETWORK, TEST_NETWORK, p2tr, p2wpkh } from '@scure/btc-signer';

export type Network = 'mainnet' | 'signet' | 'regtest';
export type AddressKind = 'payment' | 'ordinals';

const PURPOSE: Record<AddressKind, number> = { payment: 84, ordinals: 86 };
const COIN_TYPE: Record<Network, number> = { mainnet: 0, signet: 1, regtest: 1 };
export const REGTEST_NETWORK = { ...TEST_NETWORK, bech32: 'bcrt' };

export function bitcoinNetwork(network: Network): typeof NETWORK {
  return network === 'mainnet' ? NETWORK : network === 'signet' ? TEST_NETWORK : REGTEST_NETWORK;
}

/** Largest non-hardened BIP32 child/account index. */
export const BIP32_MAX_INDEX = 0x7fffffff;

export function assertBip32Index(index: number, label: string): void {
  if (!Number.isSafeInteger(index) || index < 0 || index > BIP32_MAX_INDEX) {
    throw new Error(`invalid ${label}: ${index}`);
  }
}

export interface AddressInfo {
  address: string;
  path: string;
  publicKeyHex: string;
}

export function accountPath(kind: AddressKind, network: Network, account: number): string {
  assertBip32Index(account, 'account index');
  return `m/${PURPOSE[kind]}'/${COIN_TYPE[network]}'/${account}'`;
}

export function deriveAccountNode(
  seed: Uint8Array,
  kind: AddressKind,
  network: Network,
  account: number,
): HDKey {
  const root = HDKey.fromMasterSeed(seed);
  try {
    return root.derive(accountPath(kind, network, account));
  } finally {
    root.wipePrivateData();
  }
}

export function deriveAddress(
  node: HDKey,
  kind: AddressKind,
  network: Network,
  chain: 0 | 1,
  index: number,
): AddressInfo {
  assertBip32Index(index, 'address index');
  // The returned path is reconstructed from the node's own metadata, so the
  // node must actually be a hardened account-level key (m/purpose'/coin'/a',
  // depth 3) — anything else would pair a real address with a false path.
  if (node.depth !== 3 || node.index < 0x80000000) {
    throw new Error(
      `expected a hardened account-level node (depth 3), got depth ${node.depth} index ${node.index}`,
    );
  }
  const key = node.deriveChild(chain).deriveChild(index);
  const publicKey = key.publicKey;
  if (!publicKey) throw new Error('derived node has no public key');
  const net = bitcoinNetwork(network);
  const address =
    kind === 'payment'
      ? p2wpkh(publicKey, net).address
      : p2tr(publicKey.slice(1), undefined, net).address;
  if (!address) throw new Error('address encoding failed');
  const accountIndex = node.index - 0x80000000;
  return {
    address,
    path: `${accountPath(kind, network, accountIndex)}/${chain}/${index}`,
    publicKeyHex: bytesToHex(publicKey),
  };
}

/** The stable external receive address for an account: chain 0, index 0 (spec §8.1). */
export function stableExternalAddress(
  seed: Uint8Array,
  kind: AddressKind,
  network: Network,
  account: number,
): AddressInfo {
  return deriveAddress(deriveAccountNode(seed, kind, network, account), kind, network, 0, 0);
}

function bytesToHex(bytes: Uint8Array): string {
  let out = '';
  for (const b of bytes) out += b.toString(16).padStart(2, '0');
  return out;
}
