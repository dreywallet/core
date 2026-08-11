/**
 * Per-unit scan execution (spec §8.2, §18.5): gap-limit window widening, one
 * snapshot request per (account, lane) round, per-account classify batches,
 * and the snapshot/classify revision-equality rule (one refetch on skew, then
 * the unit fails as conflicting sources — §11.4).
 *
 * Pure orchestration over injected ports: no chrome, no direct network, no
 * key material — the address port hands back script hashes only.
 */
import type {
  OutpointsClassifyRequest,
  OutpointsClassifyResponse,
  SnapshotHistoryEntry,
  UtxoClassification,
  WalletSnapshotRequest,
  WalletSnapshotResponse,
} from '../domain/gateway/contract';
import { CLASSIFY_MAX_OUTPOINTS, SNAPSHOT_MAX_SCRIPT_HASHES } from '../domain/gateway/contract';
import type { FetchSignedResult } from '../gateway-client';
import type { Network } from '../domain/keys/derivation';
import { isSuspiciousDust } from '../domain/classification/dust';
import type { AssetFacts, WalletUtxo } from '../domain/classification/types';
import { GAP_LIMIT, type ScanUnit } from './scan-state';

export interface IndexedScriptHash {
  chain: 0 | 1;
  index: number;
  scriptHash: string;
  /** Locally derived ownership proof; never accepted from the gateway. */
  scriptPubKey: string;
}

export interface ScanUnitPorts {
  network: Network;
  snapshot(req: WalletSnapshotRequest): Promise<FetchSignedResult<WalletSnapshotResponse>>;
  classify(req: OutpointsClassifyRequest): Promise<FetchSignedResult<OutpointsClassifyResponse>>;
  /** Script hashes for `unit`'s addresses on `chain`, indexes [from, to). */
  hashesFor(unit: ScanUnit, chain: 0 | 1, from: number, to: number): IndexedScriptHash[];
  shouldCancel(): boolean;
}

export interface ScanUnitOptions {
  /** Per-chain index bound for this pass (initial or extended, §8.2). */
  maxIndexPerChain: number;
  /** Burned change-index count for wallet-created-change detection (§11.2 c5). */
  burnedChangeCount: number;
}

export type ScanUnitFailure =
  | 'cancelled'
  | 'conflicting_sources'
  | 'gateway'; // any transport/verification failure — retried by the service

export interface ScanUnitResult {
  ok: boolean;
  failure?: ScanUnitFailure;
  utxos: WalletUtxo[];
  history: SnapshotHistoryEntry[];
  /** The envelope revision all responses agreed on (null when no data). */
  revision: string | null;
  /** §8.2: gap not satisfied at the pass bound — offer Extended scan. */
  boundaryPrompt: boolean;
}

interface WindowState {
  /** Exclusive end of the fetched range. */
  to: number;
  highestActive: number | null;
}

function emptyResult(failure?: ScanUnitFailure): ScanUnitResult {
  return {
    ok: failure === undefined,
    ...(failure !== undefined ? { failure } : {}),
    utxos: [],
    history: [],
    revision: null,
    boundaryPrompt: false,
  };
}

/** Widen while activity sits within the gap limit of the fetched end. */
function nextWindowEnd(state: WindowState, cap: number): number | null {
  if (state.highestActive === null) return null;
  const satisfiedAt = state.highestActive + 1 + GAP_LIMIT;
  if (satisfiedAt <= state.to) return null;
  return Math.min(satisfiedAt, cap);
}

export async function scanUnit(
  unit: ScanUnit,
  ports: ScanUnitPorts,
  options: ScanUnitOptions,
): Promise<ScanUnitResult> {
  // One full-unit retry when snapshot/classify revisions disagree (§11.4).
  for (let attempt = 0; attempt < 2; attempt += 1) {
    const outcome = await scanUnitOnce(unit, ports, options);
    if (outcome !== 'revision_skew') return outcome;
  }
  return emptyResult('conflicting_sources');
}

async function scanUnitOnce(
  unit: ScanUnit,
  ports: ScanUnitPorts,
  options: ScanUnitOptions,
): Promise<ScanUnitResult | 'revision_skew'> {
  const cap = options.maxIndexPerChain;
  const windows: Record<0 | 1, WindowState> = {
    0: { to: 0, highestActive: null },
    1: { to: 0, highestActive: null },
  };
  type WireUtxo = WalletSnapshotResponse['utxos'][number];
  const hashIndex = new Map<
    string,
    { chain: 0 | 1; index: number; scriptPubKey: string }
  >();
  const utxosByOutpoint = new Map<string, { wire: WireUtxo; chain: 0 | 1; index: number }>();
  const historyByTxid = new Map<string, SnapshotHistoryEntry>();
  let revision: string | null = null;
  let sourceIdentity: {
    instanceId: string;
    coreTip: { height: number; hash: string };
    indexTip: { height: number; hash: string };
  } | null = null;

  let nextTargets: Record<0 | 1, number> = { 0: Math.min(GAP_LIMIT, cap), 1: Math.min(GAP_LIMIT, cap) };

  while (nextTargets[0] > windows[0].to || nextTargets[1] > windows[1].to) {
    if (ports.shouldCancel()) return emptyResult('cancelled');

    const batch: IndexedScriptHash[] = [];
    for (const chain of [0, 1] as const) {
      if (nextTargets[chain] > windows[chain].to) {
        batch.push(...ports.hashesFor(unit, chain, windows[chain].to, nextTargets[chain]));
      }
    }
    // Respect the wire cap; anything beyond lands in the next round.
    const roundHashes = batch.slice(0, SNAPSHOT_MAX_SCRIPT_HASHES);
    for (const h of roundHashes) {
      const prior = hashIndex.get(h.scriptHash);
      if (
        prior &&
        (prior.chain !== h.chain || prior.index !== h.index || prior.scriptPubKey !== h.scriptPubKey)
      ) {
        return emptyResult('conflicting_sources');
      }
      hashIndex.set(h.scriptHash, {
        chain: h.chain,
        index: h.index,
        scriptPubKey: h.scriptPubKey,
      });
      windows[h.chain].to = Math.max(windows[h.chain].to, h.index + 1);
    }

    const response = await ports.snapshot({
      network: ports.network,
      scriptHashes: roundHashes.map((h) => h.scriptHash),
      ...(unit.lane === 'ordinals' ? { includeOrdinalFlow: true } : {}),
    });
    if (!response.ok) return emptyResult('gateway');
    const body = response.value;
    // Bind the signed body to THIS request: a signed-but-misrouted response
    // must not read as an empty account and satisfy the gap scan early.
    if (
      body.requestedScriptHashes.length !== roundHashes.length ||
      body.requestedScriptHashes.some((hash, i) => hash !== roundHashes[i]!.scriptHash)
    ) {
      return emptyResult('conflicting_sources');
    }
    if (revision === null) revision = body.classificationRevision;
    else if (revision !== body.classificationRevision) return 'revision_skew';
    if (sourceIdentity === null) {
      sourceIdentity = { instanceId: body.instanceId, coreTip: body.coreTip, indexTip: body.indexTip };
    } else if (
      sourceIdentity.instanceId !== body.instanceId ||
      sourceIdentity.coreTip.height !== body.coreTip.height ||
      sourceIdentity.coreTip.hash !== body.coreTip.hash ||
      sourceIdentity.indexTip.height !== body.indexTip.height ||
      sourceIdentity.indexTip.hash !== body.indexTip.hash
    ) return 'revision_skew';

    const roundHashIndex = new Map(roundHashes.map((entry) => [entry.scriptHash, entry]));
    for (const utxo of body.utxos) {
      const where = roundHashIndex.get(utxo.scriptHash);
      // Ownership is established locally from the derived script, not from a
      // gateway-supplied script hash. Foreign or mutated records poison the
      // whole unit instead of being ignored or cached as spendable.
      if (!where || utxo.scriptPubKey !== where.scriptPubKey) {
        return emptyResult('conflicting_sources');
      }
      const outpoint = `${utxo.txid}:${utxo.vout}`;
      if (utxosByOutpoint.has(outpoint)) return emptyResult('conflicting_sources');
      utxosByOutpoint.set(outpoint, { wire: utxo, ...where });
      const w = windows[where.chain];
      w.highestActive = Math.max(w.highestActive ?? -1, where.index);
    }
    for (const entry of body.history) {
      historyByTxid.set(entry.txid, entry);
      for (const scriptHash of [...entry.fundedScriptHashes, ...entry.spentScriptHashes]) {
        const where = roundHashIndex.get(scriptHash);
        if (!where) return emptyResult('conflicting_sources');
        const w = windows[where.chain];
        w.highestActive = Math.max(w.highestActive ?? -1, where.index);
      }
    }

    nextTargets = {
      0: nextWindowEnd(windows[0], cap) ?? windows[0].to,
      1: nextWindowEnd(windows[1], cap) ?? windows[1].to,
    };
  }

  // Gap unsatisfied at the cap on either chain → §8.2 Extended-scan prompt.
  const boundaryPrompt = ([0, 1] as const).some((chain) => {
    const w = windows[chain];
    return w.highestActive !== null && w.highestActive + 1 + GAP_LIMIT > cap;
  });

  // Classify every found outpoint in ≤200 chunks (per-account batch, §18.5).
  const outpoints = [...utxosByOutpoint.keys()].map((key) => {
    const [txid, vout] = key.split(':');
    return { txid: txid ?? '', vout: Number(vout) };
  });
  const classifications = new Map<string, UtxoClassification>();
  for (let i = 0; i < outpoints.length; i += CLASSIFY_MAX_OUTPOINTS) {
    if (ports.shouldCancel()) return emptyResult('cancelled');
    const chunk = outpoints.slice(i, i + CLASSIFY_MAX_OUTPOINTS);
    const response = await ports.classify({ network: ports.network, outpoints: chunk });
    if (!response.ok) return emptyResult('gateway');
    if (revision !== null && response.value.classificationRevision !== revision) {
      return 'revision_skew';
    }
    if (sourceIdentity === null || response.value.instanceId !== sourceIdentity.instanceId ||
        response.value.coreTip.height !== sourceIdentity.coreTip.height ||
        response.value.coreTip.hash !== sourceIdentity.coreTip.hash ||
        response.value.indexTip.height !== sourceIdentity.indexTip.height ||
        response.value.indexTip.hash !== sourceIdentity.indexTip.hash) return 'revision_skew';
    const requested = new Set(chunk.map((outpoint) => `${outpoint.txid}:${outpoint.vout}`));
    const returned = new Set<string>();
    for (const record of response.value.classifications) {
      const key = `${record.txid}:${record.vout}`;
      if (!requested.has(key) || returned.has(key)) return emptyResult('conflicting_sources');
      returned.add(key);
      if (record.classificationRevision !== response.value.classificationRevision ||
          record.classifiedTip.height !== sourceIdentity.coreTip.height ||
          record.classifiedTip.hash !== sourceIdentity.coreTip.hash) {
        return 'revision_skew';
      }
      classifications.set(key, record);
    }
    // A snapshot UTXO without an exact classification is not safe to cache.
    // Unknown, foreign, duplicate, overlapping, or omitted results are all a
    // positive source conflict.
    if (response.value.unknownOutpoints.length > 0) return emptyResult('conflicting_sources');
    if (returned.size !== requested.size) return emptyResult('conflicting_sources');
  }

  // Earliest confirmed funding = the account's first funding (dust heuristic).
  const firstFundingTxid = [...historyByTxid.values()]
    .filter((e) => e.height !== null)
    .sort((a, b) => (a.height ?? 0) - (b.height ?? 0))[0]?.txid;

  const utxos: WalletUtxo[] = [];
  for (const [key, { wire, chain, index }] of utxosByOutpoint) {
    const record = classifications.get(key);
    // A correctly signed but internally inconsistent snapshot/classification
    // pair is conflicting security data, never a spendable prevout.
    if (
      !record ||
      record.valueSats !== wire.valueSats ||
      record.scriptPubKey !== wire.scriptPubKey
    ) {
      return emptyResult('conflicting_sources');
    }
    // Mempool membership can change without advancing the block-backed
    // classification revision. If a transaction confirms between the signed
    // snapshot and classification requests, retry the whole unit so height,
    // confirmation count, and asset facts come from one coherent pass.
    const expectedConfirmations = wire.height === null
      ? 0
      : sourceIdentity === null
        ? -1
        : sourceIdentity.coreTip.height - wire.height + 1;
    if (
      (wire.height === null && record.confirmations !== 0) ||
      (wire.height !== null &&
        (expectedConfirmations < 1 || record.confirmations !== expectedConfirmations))
    ) {
      return 'revision_skew';
    }
    const facts: AssetFacts = {
      primaryClass: record.primaryClass,
      inscriptions: record.inscriptions,
      satRanges: record.satRanges,
      unsupportedAssetDetected: record.unsupportedAssetDetected,
      detectedAssets: record.detectedAssets ?? [],
      detectedAssetCount: record.detectedAssetCount ?? 0,
      assetIdentityComplete: record.assetIdentityComplete ?? false,
      confidence: record.confidence,
      classifiedTip: record.classifiedTip,
      classificationRevision: record.classificationRevision,
    };
    const walletCreatedChange =
      wire.fundingSpendsOnlyRequested && chain === 1 && index < options.burnedChangeCount;
    const utxo: WalletUtxo = {
      outpoint: { txid: wire.txid, vout: wire.vout },
      valueSats: BigInt(wire.valueSats),
      scriptPubKey: wire.scriptPubKey,
      ...(unit.accountId !== undefined ? { accountId: unit.accountId } : {}),
      account: unit.account,
      lane: unit.lane,
      chain,
      addressIndex: index,
      height: wire.height,
      walletCreatedChange,
      facts,
      flags: { userFrozen: false, dustQuarantined: false },
    };
    utxo.flags.dustQuarantined = isSuspiciousDust(utxo, wire.txid === firstFundingTxid);
    utxos.push(utxo);
  }

  return {
    ok: true,
    utxos,
    history: [...historyByTxid.values()],
    revision,
    boundaryPrompt,
  };
}
