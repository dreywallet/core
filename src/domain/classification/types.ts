/**
 * UTXO classification model (spec §11.1).
 *
 * Backend asset facts are stored SEPARATELY from user flags so that a user
 * freeze or dust quarantine never erases what the classifier said about the
 * sats (§11.1: "Protected facts MUST be stored separately from the primary
 * display class"). The display class is derived, never stored.
 *
 * Pure domain module: no browser APIs, no network, bigint sats internally.
 */
import type {
  InscriptionRef,
  PrimaryClass,
  SatRange,
  Tip,
} from '../gateway/contract';
import type { AddressKind } from '../keys/derivation';

export type { PrimaryClass } from '../gateway/contract';

/** What the backend classifier asserted, verbatim. User actions never mutate this. */
export interface AssetFacts {
  primaryClass: PrimaryClass;
  inscriptions: InscriptionRef[];
  satRanges: SatRange[] | null;
  unsupportedAssetDetected: boolean;
  detectedAssets?: import('../gateway/contract').DetectedAsset[] | undefined;
  detectedAssetCount?: number | undefined;
  assetIdentityComplete?: boolean | undefined;
  confidence: 'authoritative' | 'degraded';
  classifiedTip: Tip;
  classificationRevision: string;
}

/** Local user decisions, stored beside — never inside — the facts. */
export interface UserFlags {
  /** §14.4 hard exclusion, only meaningful on clean UTXOs. */
  userFrozen: boolean;
  /** §11.1 suspicious unsolicited dust, excluded from automatic use. */
  dustQuarantined: boolean;
}

export interface WalletOutpoint {
  txid: string;
  vout: number;
}

export interface WalletUtxo {
  outpoint: WalletOutpoint;
  valueSats: bigint;
  /** Exact previous-output script, verified equal across snapshot/classify. */
  scriptPubKey: string;
  /** Stable public-account identity. Absent only on legacy cache records. */
  accountId?: string | undefined;
  /** BIP32 origin account index; never used as the account's storage identity. */
  account: number;
  lane: AddressKind;
  chain: 0 | 1;
  addressIndex: number;
  /** null = unconfirmed. */
  height: number | null;
  /** Established per the §18.2 change signal + local internal-chain checks. */
  walletCreatedChange: boolean;
  /** null = never classified — displays and gates as 'unknown'. */
  facts: AssetFacts | null;
  flags: UserFlags;
}

export type DisplayClass = PrimaryClass | 'user_frozen' | 'dust_quarantined';

export function outpointKey(outpoint: WalletOutpoint): string {
  return `${outpoint.txid}:${outpoint.vout}`;
}

/**
 * §11.1 display class. user_frozen / dust_quarantined only ever overlay
 * cardinal_clean facts: a protected or unknown classification always shows
 * (and gates) as itself, whatever the local flags say.
 */
export function displayClass(utxo: WalletUtxo): DisplayClass {
  const primary = utxo.facts?.primaryClass ?? 'unknown';
  if (primary !== 'cardinal_clean') return primary;
  if (utxo.flags.userFrozen) return 'user_frozen';
  if (utxo.flags.dustQuarantined) return 'dust_quarantined';
  return primary;
}
