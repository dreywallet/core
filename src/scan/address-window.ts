/**
 * Script-hash windows for scan units (spec §18.5).
 *
 * Key handling: the seed is touched exactly once per scan start — the service
 * derives every account-level node under withActiveDek, neuters them with
 * wipePrivateData(), and hands this module public-only HDKeys. The xpubs live
 * in worker memory for the scan's duration only, are never transmitted
 * (script hashes only leave the device), and are dropped on lock, cancel, or
 * completion. Re-deriving per window would multiply DEK exposure windows —
 * the recorded tradeoff goes the other way.
 */
import { HDKey } from '@scure/bip32';
import {
  accountPath,
  assertBip32Index,
  type AddressKind,
  type Network,
} from '../domain/keys/derivation';
import {
  deriveLegacyAddress,
  legacyAccountPath,
  xverseManifest,
  type LegacyPathEntry,
} from '../domain/keys/legacy-manifests';
import {
  scriptHashFromScriptPubKey,
  scriptPubKeyHex,
} from '../domain/keys/script-hash';
import { type ScanUnit, unitKey } from './scan-state';
import type { IndexedScriptHash } from './scan-engine';
import {
  publicAccountDefinitionSchema,
  publicAccountFromRoot,
  type PublicAccountDefinitionV1,
} from '../domain/accounts/public-account';
import { bip32Versions } from '../domain/keys/extended-key';

export interface AccountKeyRing {
  network: Network;
  /** `a{account}:{lane}` → neutered depth-3 account node. */
  standard: Map<string, HDKey>;
  /** descriptor unit key → neutered depth-3 account node. */
  descriptor: Map<string, HDKey>;
  /** legacy entry id → { node, entry }. */
  legacy: Map<string, { node: HDKey; entry: LegacyPathEntry }>;
}

/**
 * Derive and neuter every account node the scan plan needs. Call under
 * withActiveDek; the returned ring holds public-only keys.
 */
export function buildAccountKeyRing(
  seed: Uint8Array,
  network: Network,
  units: readonly ScanUnit[],
): AccountKeyRing {
  const master = HDKey.fromMasterSeed(seed, bip32Versions(network));
  const standard = new Map<string, HDKey>();
  const validatedIdentities = new Map<number, string>();
  const legacy = new Map<string, { node: HDKey; entry: LegacyPathEntry }>();
  try {
    for (const unit of units) {
      if (unit.source !== 'standard' || standard.has(unitKey(unit))) continue;
      if (unit.accountId !== undefined) {
        let expected = validatedIdentities.get(unit.account);
        if (expected === undefined) {
          expected = publicAccountFromRoot(master, network, unit.account).accountId;
          validatedIdentities.set(unit.account, expected);
        }
        if (unit.accountId !== expected) {
          throw new Error('standard scan unit public account identity mismatch');
        }
      }
      const node = master.derive(accountPath(unit.lane, network, unit.account));
      node.wipePrivateData();
      standard.set(unitKey(unit), node);
    }
    const requestedLegacy = new Set(units.flatMap((unit) =>
      unit.source === 'xverse' && unit.legacyEntryId ? [unit.legacyEntryId] : []));
    for (const entry of xverseManifest(network).entries) {
      if (!requestedLegacy.has(entry.id)) continue;
      const node = master.derive(legacyAccountPath(entry, network));
      node.wipePrivateData();
      legacy.set(entry.id, { node, entry });
    }
    return { network, standard, descriptor: new Map(), legacy };
  } finally {
    master.wipePrivateData();
  }
}

/** Build the same public-only scan ring from imported account definitions. */
export function buildPublicAccountKeyRing(
  definitions: readonly PublicAccountDefinitionV1[],
  network: Network,
  units: readonly ScanUnit[],
): AccountKeyRing {
  const byId = new Map(definitions.map((value) => {
    const definition = publicAccountDefinitionSchema.parse(value);
    if (definition.network !== network) throw new Error('public account ring network mismatch');
    return [definition.accountId, definition] as const;
  }));
  const descriptor = new Map<string, HDKey>();
  for (const unit of units) {
    if (unit.source !== 'descriptor') continue;
    const definition = byId.get(unit.accountId ?? '');
    if (!definition || definition.derivationAccountIndex !== unit.account) {
      throw new Error('descriptor scan unit does not match a public account definition');
    }
    const node = HDKey.fromExtendedKey(
      definition.lanes[unit.lane].origin.accountXpub,
      bip32Versions(network),
    );
    if (node.privateKey !== null) throw new Error('public account ring received private material');
    descriptor.set(unitKey(unit), node);
  }
  return { network, standard: new Map(), descriptor, legacy: new Map() };
}

/** Script hashes for `unit`'s `chain`, indexes [from, to). */
export function windowScriptHashes(
  ring: AccountKeyRing,
  unit: ScanUnit,
  chain: 0 | 1,
  from: number,
  to: number,
): IndexedScriptHash[] {
  const out: IndexedScriptHash[] = [];
  if (unit.source === 'standard' || unit.source === 'descriptor') {
    const key = unitKey(unit);
    const node = unit.source === 'standard' ? ring.standard.get(key) : ring.descriptor.get(key);
    if (!node) throw new Error(`no account key for ${key}`);
    for (let index = from; index < to; index += 1) {
      assertBip32Index(index, 'scan address index');
      out.push(publicScript(node, unit.lane, ring.network, chain, index));
    }
    return out;
  }
  const legacy = ring.legacy.get(unit.legacyEntryId ?? '');
  if (!legacy) throw new Error(`no legacy key for ${unit.legacyEntryId ?? '(missing id)'}`);
  for (let index = from; index < to; index += 1) {
    const info = deriveLegacyAddress(legacy.node, legacy.entry, ring.network, chain, index);
    out.push({
      chain,
      index,
      scriptHash: scriptHashFromScriptPubKey(info.scriptPubKeyHex),
      scriptPubKey: info.scriptPubKeyHex,
    });
  }
  return out;
}

function publicScript(
  node: HDKey,
  lane: AddressKind,
  network: Network,
  chain: 0 | 1,
  index: number,
): IndexedScriptHash {
  const key = node.deriveChild(chain).deriveChild(index);
  const publicKey = key.publicKey;
  if (!publicKey) throw new Error('derived node has no public key');
  let hex = '';
  for (const b of publicKey) hex += b.toString(16).padStart(2, '0');
  const scriptPubKey = scriptPubKeyHex(hex, lane, network);
  return {
    chain,
    index,
    scriptHash: scriptHashFromScriptPubKey(scriptPubKey),
    scriptPubKey,
  };
}
