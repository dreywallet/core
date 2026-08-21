/**
 * Coordinator-neutral Full Sat Safety evidence for the independent Vault.
 *
 * Every online coordinator and every online signer uses these projections.
 * Gateway responses remain evidence rather than policy: missing, stale, or
 * conflicting data fails closed and never becomes `cardinal_clean` by default.
 */
import type { WalletUtxo } from '../classification/types';
import type { StatusCapabilities, Tip } from '../gateway/contract';
import type { Network } from '../keys/derivation';
import { getCryptoProvider } from './crypto-provider';
import { bytesToHex, hexToBytes } from './encoding';
import type { VaultUnsignedPlanV1 } from './multisig-contracts';
import {
  finalizeVaultInputAssetEvidence,
  VAULT_FULL_SAT_SAFETY_CAPABILITIES,
  type VaultAssetPolicyEvidenceV1,
  type VaultInputAssetEvidenceV1,
} from './multisig-asset-policy';


export const VAULT_EVIDENCE_TTL_MS = 10 * 60 * 1000;

export type VaultEvidenceRefusal =
  | 'gateway_unavailable'
  | 'capabilities_insufficient'
  | 'conflicting_source'
  | 'stale_evidence'
  | 'scan_incomplete';

export type VaultUtxoRefusal =
  | 'degraded'
  | 'classification_incomplete'
  | 'rare_sat'
  | 'unsupported_asset'
  | 'mixed_or_unknown'
  | 'user_frozen'
  | 'dust_quarantined'
  | 'unconfirmed';

export interface VaultEvidenceSourceV1 {
  network: Network;
  backendInstanceIdHash: string;
  classificationRevisionHash: string;
  coreTip: Tip;
  indexTip: Tip;
  historyTip: Tip;
  ordTip: Tip;
  observedAtMs: string;
  validUntilMs: string;
}

export interface VaultUtxoV1 {
  txid: string;
  vout: number;
  valueSats: string;
  scriptPubKeyHex: string;
  branch: 'receive' | 'change';
  derivationIndex: number;
  confirmations: number;
  walletCreatedUnconfirmedChange: boolean;
  primaryClass: VaultInputAssetEvidenceV1['primaryClass'];
  confidence: 'authoritative' | 'degraded';
  classificationComplete: boolean;
  satRangesComplete: boolean;
  inscriptions: Array<{ inscriptionId: string; offsetSats: string }>;
  rareSatDetected: boolean;
  unsupportedAssetDetected: boolean;
  userFrozen: boolean;
  dustQuarantined: boolean;
  refusal: VaultUtxoRefusal | null;
}

function domainHash(domain: string, value: string): string {
  const label = new TextEncoder().encode(domain);
  const body = new TextEncoder().encode(value);
  const framed = new Uint8Array(label.length + 1 + body.length);
  framed.set(label);
  framed[label.length] = 0;
  framed.set(body, label.length + 1);
  return bytesToHex(getCryptoProvider().sha256(framed));
}

export function vaultBackendInstanceIdHash(instanceId: string): string {
  return domainHash('drey-vault-backend-instance-v1', instanceId);
}

export function vaultClassificationRevisionHash(revision: string): string {
  return domainHash('drey-vault-classification-revision-v1', revision);
}

function sameTip(left: Tip, right: Tip): boolean {
  return left.height === right.height && left.hash === right.hash;
}

export function deriveVaultEvidenceSource(input: {
  network: Network;
  status: StatusCapabilities | null;
  scan: {
    instanceId: string;
    classificationRevision: string;
    coreTip: Tip;
    indexTip: Tip;
  } | null;
  nowMs: number;
}): { ok: true; source: VaultEvidenceSourceV1 } | { ok: false; refusal: VaultEvidenceRefusal } {
  const { status, scan } = input;
  if (status === null) return { ok: false, refusal: 'gateway_unavailable' };
  if (scan === null) return { ok: false, refusal: 'scan_incomplete' };

  const offered = new Set(status.capabilities);
  if (!VAULT_FULL_SAT_SAFETY_CAPABILITIES.every((capability) => offered.has(capability))) {
    return { ok: false, refusal: 'capabilities_insufficient' };
  }
  if (!status.eligibleSafetyModes.includes('full_sat_safety')) {
    return { ok: false, refusal: 'capabilities_insufficient' };
  }
  if (
    status.network !== input.network ||
    status.instanceId !== scan.instanceId ||
    status.classificationRevision !== scan.classificationRevision ||
    !sameTip(status.coreTip, scan.coreTip) ||
    !sameTip(status.indexTip, scan.indexTip) ||
    !sameTip(status.coreTip, status.indexTip) ||
    !sameTip(status.coreTip, status.historyTip) ||
    !sameTip(status.coreTip, status.ordTip)
  ) {
    return { ok: false, refusal: 'conflicting_source' };
  }

  return {
    ok: true,
    source: {
      network: input.network,
      backendInstanceIdHash: vaultBackendInstanceIdHash(status.instanceId),
      classificationRevisionHash: vaultClassificationRevisionHash(status.classificationRevision),
      coreTip: status.coreTip,
      indexTip: status.indexTip,
      historyTip: status.historyTip,
      ordTip: status.ordTip,
      observedAtMs: String(input.nowMs),
      validUntilMs: String(input.nowMs + VAULT_EVIDENCE_TTL_MS),
    },
  };
}

export function vaultEvidenceExpired(source: VaultEvidenceSourceV1, nowMs: number): boolean {
  return BigInt(String(nowMs)) > BigInt(source.validUntilMs);
}

function inscriptionOffsetSats(satpoint: string, txid: string, vout: number): string | null {
  const parts = satpoint.split(':');
  if (parts.length !== 3) return null;
  const [satTxid, satVout, offset] = parts;
  if (satTxid !== txid || satVout !== String(vout)) return null;
  if (!/^(?:0|[1-9][0-9]*)$/u.test(offset ?? '')) return null;
  return offset!;
}

function utxoRefusal(utxo: VaultUtxoV1): VaultUtxoRefusal | null {
  if (utxo.confidence !== 'authoritative') return 'degraded';
  if (!utxo.classificationComplete || !utxo.satRangesComplete) return 'classification_incomplete';
  if (utxo.unsupportedAssetDetected) return 'unsupported_asset';
  if (utxo.rareSatDetected) return 'rare_sat';
  if (!['cardinal_clean', 'inscribed'].includes(utxo.primaryClass)) return 'mixed_or_unknown';
  if (utxo.userFrozen) return 'user_frozen';
  if (utxo.dustQuarantined) return 'dust_quarantined';
  if (utxo.confirmations === 0 && !utxo.walletCreatedUnconfirmedChange) return 'unconfirmed';
  return null;
}

function unsignedPlanTxid(plan: VaultUnsignedPlanV1): string {
  const first = getCryptoProvider().sha256(hexToBytes(plan.unsignedTransactionHex));
  return bytesToHex(Uint8Array.from(getCryptoProvider().sha256(first)).reverse());
}

/**
 * Promote an independently scanned unconfirmed change output only when a
 * complete signer-local parent plan proves Drey created that exact outpoint.
 */
export function recognizeVaultCreatedUnconfirmedChange(
  utxo: VaultUtxoV1,
  previousPlan: VaultUnsignedPlanV1,
): VaultUtxoV1 {
  const output = previousPlan.outputs[utxo.vout];
  if (utxo.confirmations !== 0 || utxo.txid !== unsignedPlanTxid(previousPlan) ||
      output === undefined || output.purpose !== 'vault-change' || output.branch !== 'change' ||
      output.valueSats !== utxo.valueSats || output.scriptPubKeyHex !== utxo.scriptPubKeyHex ||
      output.derivationIndex !== utxo.derivationIndex || utxo.branch !== 'change') {
    return utxo;
  }
  const recognized = { ...utxo, walletCreatedUnconfirmedChange: true };
  return { ...recognized, refusal: utxoRefusal(recognized) };
}

export function projectVaultUtxo(
  utxo: WalletUtxo,
  source: VaultEvidenceSourceV1,
): VaultUtxoV1 | null {
  const facts = utxo.facts;
  if (!facts) return null;
  const confirmations = utxo.height === null ? 0 : source.coreTip.height - utxo.height + 1;
  if (confirmations < 0) return null;
  const inscriptions: VaultUtxoV1['inscriptions'] = [];
  for (const inscription of facts.inscriptions) {
    const offsetSats = inscriptionOffsetSats(
      inscription.satpoint,
      utxo.outpoint.txid,
      utxo.outpoint.vout,
    );
    if (offsetSats === null) return null;
    inscriptions.push({ inscriptionId: inscription.inscriptionId, offsetSats });
  }
  const projected: VaultUtxoV1 = {
    txid: utxo.outpoint.txid,
    vout: utxo.outpoint.vout,
    valueSats: utxo.valueSats.toString(),
    scriptPubKeyHex: utxo.scriptPubKey,
    branch: utxo.chain === 0 ? 'receive' : 'change',
    derivationIndex: utxo.addressIndex,
    confirmations,
    walletCreatedUnconfirmedChange: utxo.walletCreatedChange && confirmations === 0,
    primaryClass: facts.primaryClass,
    confidence: facts.confidence,
    classificationComplete: true,
    satRangesComplete: facts.satRanges !== null,
    inscriptions,
    rareSatDetected:
      facts.satRanges?.some((range) => range.rarity !== undefined && range.rarity !== 'common') ===
      true,
    unsupportedAssetDetected: facts.unsupportedAssetDetected,
    userFrozen: utxo.flags.userFrozen,
    dustQuarantined: utxo.flags.dustQuarantined,
    refusal: null,
  };
  return { ...projected, refusal: utxoRefusal(projected) };
}

export function finalizeVaultUtxoEvidence(
  utxo: VaultUtxoV1,
  source: VaultEvidenceSourceV1,
  inputIndex: number,
): VaultInputAssetEvidenceV1 {
  return finalizeVaultInputAssetEvidence({
    version: 1,
    network: source.network,
    inputIndex,
    txid: utxo.txid,
    vout: utxo.vout,
    valueSats: utxo.valueSats,
    scriptPubKeyHex: utxo.scriptPubKeyHex,
    primaryClass: utxo.primaryClass,
    confidence: utxo.confidence,
    confirmations: utxo.confirmations,
    walletCreatedUnconfirmedChange: utxo.walletCreatedUnconfirmedChange,
    userFrozen: utxo.userFrozen,
    dustQuarantined: utxo.dustQuarantined,
    classificationComplete: utxo.classificationComplete,
    satRangesComplete: utxo.satRangesComplete,
    inscriptions: utxo.inscriptions,
    rareSatDetected: utxo.rareSatDetected,
    unsupportedAssetDetected: utxo.unsupportedAssetDetected,
    classificationRevisionHash: source.classificationRevisionHash,
    classifiedTip: source.coreTip,
  });
}

export function buildVaultAssetPolicyEvidence(input: {
  source: VaultEvidenceSourceV1;
  policyId: string;
  planId: string;
  planDigest: string;
  utxos: readonly VaultUtxoV1[];
}): VaultAssetPolicyEvidenceV1 {
  return {
    version: 1,
    network: input.source.network,
    policyId: input.policyId,
    planId: input.planId,
    planDigest: input.planDigest,
    safetyMode: 'full_sat_safety',
    capabilities: [...VAULT_FULL_SAT_SAFETY_CAPABILITIES],
    backendInstanceIdHash: input.source.backendInstanceIdHash,
    classificationRevisionHash: input.source.classificationRevisionHash,
    coreTip: input.source.coreTip,
    indexTip: input.source.indexTip,
    historyTip: input.source.historyTip,
    ordTip: input.source.ordTip,
    observedAtMs: input.source.observedAtMs,
    validUntilMs: input.source.validUntilMs,
    inputs: input.utxos.map((utxo, index) =>
      finalizeVaultUtxoEvidence(utxo, input.source, index),
    ),
  };
}

export function summarizeVaultBalance(utxos: readonly VaultUtxoV1[]): {
  totalSats: string;
  movableSats: string;
  immovableSats: string;
  inscriptionCount: number;
} {
  let total = 0n;
  let movable = 0n;
  let inscriptionCount = 0;
  for (const utxo of utxos) {
    const value = BigInt(utxo.valueSats);
    total += value;
    if (utxo.refusal === null) movable += value;
    inscriptionCount += utxo.inscriptions.length;
  }
  return {
    totalSats: total.toString(),
    movableSats: movable.toString(),
    immovableSats: (total - movable).toString(),
    inscriptionCount,
  };
}
