/**
 * Script-hash derivation for gateway lookups (spec §18.5).
 *
 * The /v1 contract's script hash is sha256(scriptPubKey) over the raw output
 * script bytes, natural output byte order, lowercase hex — deliberately NOT
 * the Electrum reversed-byte convention (gateway
 * docs/design/wallet-snapshot.md). Scripts are rebuilt from the public key
 * with the same @scure/btc-signer constructions derivation.ts uses for
 * addresses, so a script hash and its address can never disagree.
 *
 * Pure domain module: callers must have awaited initSodium() (the worker
 * composition root does this at startup).
 */
import { p2tr, p2wpkh } from '@scure/btc-signer';
import { getCryptoProvider } from '../vault/crypto-provider';
import { bitcoinNetwork, type AddressKind, type Network } from './derivation';

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0 || !/^[0-9a-f]*$/.test(hex)) {
    throw new Error('public key must be lowercase hex');
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function bytesToHex(bytes: Uint8Array): string {
  let out = '';
  for (const b of bytes) out += b.toString(16).padStart(2, '0');
  return out;
}

/** Raw output script (scriptPubKey) for a derived public key, lowercase hex. */
export function scriptPubKeyHex(publicKeyHex: string, kind: AddressKind, network: Network): string {
  const publicKey = hexToBytes(publicKeyHex);
  const net = bitcoinNetwork(network);
  const script =
    kind === 'payment'
      ? p2wpkh(publicKey, net).script
      : p2tr(publicKey.slice(1), undefined, net).script;
  if (!script) throw new Error('script derivation failed');
  return bytesToHex(script);
}

/** Contract script hash: sha256(scriptPubKey), natural byte order, lowercase hex. */
export function scriptHashFromScriptPubKey(scriptPubKeyHexValue: string): string {
  return bytesToHex(getCryptoProvider().sha256(hexToBytes(scriptPubKeyHexValue)));
}

export function scriptHashForPublicKey(
  publicKeyHex: string,
  kind: AddressKind,
  network: Network,
): string {
  return scriptHashFromScriptPubKey(scriptPubKeyHex(publicKeyHex, kind, network));
}
