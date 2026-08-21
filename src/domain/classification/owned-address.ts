/**
 * Presentation-only ownership metadata for locally proven wallet UTXOs.
 *
 * Drey v1 issues one stable external address (chain 0, index 0) per account.
 * External indexes above zero can therefore only have been recovered from a
 * compatible wallet. Keeping the external mode explicit prevents a future
 * rotating-address mode from silently inheriting that classification.
 */
import { Address, OutScript } from '@scure/btc-signer';
import { bitcoinNetwork, type Network } from '../keys/derivation';
import { bytesToHex, hexToBytes } from '../vault/encoding';
import type { WalletUtxo } from './types';

export type ExternalAddressMode = 'stable';
export type OwnedAddressRole = 'primary' | 'recovered' | 'change';

export interface OwnedAddress {
  address: string;
  lane: WalletUtxo['lane'];
  role: OwnedAddressRole;
}

export interface RecoveredAddressCount {
  accountId: string;
  account: number;
  payment: number;
  ordinals: number;
}

export function ownedAddressRole(
  utxo: Pick<WalletUtxo, 'chain' | 'addressIndex'>,
  externalMode: ExternalAddressMode,
): OwnedAddressRole {
  if (utxo.chain === 1) return 'change';
  if (utxo.addressIndex === 0) return 'primary';
  switch (externalMode) {
    case 'stable':
      return 'recovered';
  }
}

/**
 * Encode the cached script rather than re-deriving from the seed. A round trip
 * binds the displayed address back to the exact script whose ownership the
 * scanner proved; an unsupported or inconsistent script is not displayable.
 */
export function ownedAddressFromUtxo(
  utxo: Pick<WalletUtxo, 'scriptPubKey' | 'lane' | 'chain' | 'addressIndex'>,
  network: Network,
  externalMode: ExternalAddressMode = 'stable',
): OwnedAddress {
  const codec = Address(bitcoinNetwork(network));
  const script = OutScript.decode(hexToBytes(utxo.scriptPubKey));
  const address = codec.encode(script);
  const roundTrip = bytesToHex(OutScript.encode(codec.decode(address)));
  if (roundTrip !== utxo.scriptPubKey) {
    throw new Error('owned address does not round-trip to its cached script');
  }
  return {
    address,
    lane: utxo.lane,
    role: ownedAddressRole(utxo, externalMode),
  };
}

/**
 * Reuse script/address encoding for every UTXO held at the same script. The
 * cheap lane/role comparison still runs for each UTXO so contradictory cached
 * derivation metadata cannot borrow the first entry's ownership claim.
 */
export function createOwnedAddressResolver(
  network: Network,
  externalMode: ExternalAddressMode = 'stable',
): (
  utxo: Pick<WalletUtxo, 'scriptPubKey' | 'lane' | 'chain' | 'addressIndex'>,
) => OwnedAddress {
  const byScript = new Map<string, OwnedAddress>();
  return (utxo) => {
    const role = ownedAddressRole(utxo, externalMode);
    const cached = byScript.get(utxo.scriptPubKey);
    if (cached) {
      if (cached.lane !== utxo.lane || cached.role !== role) {
        throw new Error('owned script has inconsistent cached derivation metadata');
      }
      return cached;
    }
    const ownership = ownedAddressFromUtxo(utxo, network, externalMode);
    byScript.set(utxo.scriptPubKey, ownership);
    return ownership;
  };
}

/**
 * Distinct current recovered scripts per stable public account and lane. Multiple
 * UTXOs or inscriptions at one address count once; empty accounts are omitted.
 */
export function summarizeRecoveredAddresses(
  utxos: readonly WalletUtxo[],
  externalMode: ExternalAddressMode = 'stable',
): RecoveredAddressCount[] {
  const scripts = new Map<string, {
    account: number;
    payment: Set<string>;
    ordinals: Set<string>;
  }>();
  for (const utxo of utxos) {
    if (ownedAddressRole(utxo, externalMode) !== 'recovered') continue;
    if (utxo.accountId === undefined) {
      throw new Error('recovered address lacks stable public account identity');
    }
    let account = scripts.get(utxo.accountId);
    if (!account) {
      account = { account: utxo.account, payment: new Set(), ordinals: new Set() };
      scripts.set(utxo.accountId, account);
    } else if (account.account !== utxo.account) {
      throw new Error('public account identity has inconsistent account index');
    }
    account[utxo.lane].add(utxo.scriptPubKey);
  }
  return [...scripts.entries()]
    .sort(([left], [right]) => left < right ? -1 : left === right ? 0 : 1)
    .map(([accountId, lanes]) => ({
      accountId,
      account: lanes.account,
      payment: lanes.payment.size,
      ordinals: lanes.ordinals.size,
    }));
}
