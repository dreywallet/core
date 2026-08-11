import type { DetectedAsset, SnapshotHistoryEntry } from './gateway/contract';
import { sha256 } from '@scure/btc-signer/utils';
import {
  ACTIVITY_PAGE_SIZE,
  type ActivityPageCursor,
  type WalletActivityItem,
} from '../messaging/ops';
import type { ActivityEvidenceEntry, StoredTransaction } from '../scan/cache-schemas';

type RecentActivity = WalletActivityItem;
export type LaneAwareHistoryEntry = SnapshotHistoryEntry & {
  ordinalsAddressFunded?: boolean;
  ordinalsAddressSpent?: boolean;
};
export interface ReceivedInscriptionEvidence {
  txid: string;
  vout: number;
  inscriptionId: string;
  number: number | null;
  valueSats: bigint;
}

export interface ReceivedDetectedAssetEvidence {
  txid: string;
  vout: number;
  assets: readonly DetectedAsset[];
  identityCount: number;
  identityComplete: boolean;
}

/** Attach only identities observed directly on positive receiving outputs. */
export function annotateReceivedDetectedAssetActivity(
  activity: readonly RecentActivity[],
  evidence: readonly ReceivedDetectedAssetEvidence[],
): RecentActivity[] {
  const byTxid = new Map<string, ReceivedDetectedAssetEvidence[]>();
  for (const item of evidence) {
    const entries = byTxid.get(item.txid) ?? [];
    entries.push(item);
    byTxid.set(item.txid, entries);
  }
  return activity.map((entry) => {
    if (BigInt(entry.deltaSats) <= 0n) return entry;
    const candidates = byTxid.get(entry.txid);
    if (!candidates?.length) return entry;
    const identities = new Map<string, DetectedAsset>();
    let unknownIdentityCount = 0;
    let assetIdentityComplete = true;
    for (const candidate of candidates) {
      unknownIdentityCount += Math.max(0, candidate.identityCount - candidate.assets.length);
      assetIdentityComplete &&= candidate.identityComplete;
      for (const asset of candidate.assets) {
        const key = `${asset.protocol}:${asset.name}:${asset.divisibility}:${asset.symbol ?? ''}`;
        const prior = identities.get(key);
        identities.set(key, prior === undefined
          ? asset
          : { ...asset, amountAtoms: (BigInt(prior.amountAtoms) + BigInt(asset.amountAtoms)).toString() });
      }
    }
    const detectedAssetCount = identities.size + unknownIdentityCount;
    return {
      ...entry,
      detectedAssets: [...identities.values()]
        .sort((a, b) => a.name.localeCompare(b.name))
        .slice(0, 16),
      detectedAssetCount,
      assetIdentityComplete: assetIdentityComplete && unknownIdentityCount === 0 && identities.size <= 16,
    };
  });
}

function evidenceKey(entry: Pick<ActivityEvidenceEntry, 'inscriptionId' | 'outpoint' | 'offsetSats'>): string {
  return `${entry.inscriptionId}:${entry.outpoint.txid}:${entry.outpoint.vout}:${entry.offsetSats}`;
}

function locationKey(outpoint: { txid: string; vout: number }): string {
  return `${outpoint.txid}:${outpoint.vout}`;
}

/**
 * Propagate display identities in both directions through complete, signed
 * boundary evidence. An unavailable transaction contributes no edges.
 */
export function propagateActivityEvidence(
  history: readonly SnapshotHistoryEntry[],
  seeds: readonly ActivityEvidenceEntry[],
  limit = 4_096,
): ActivityEvidenceEntry[] {
  type Edge = Extract<NonNullable<SnapshotHistoryEntry['ordinalFlow']>, { kind: 'complete' }>['edges'][number];
  const bySource = new Map<string, Edge[]>();
  const byDestination = new Map<string, Edge[]>();
  for (const entry of history) {
    if (entry.ordinalFlow?.kind !== 'complete') continue;
    for (const edge of entry.ordinalFlow.edges) {
      const sources = bySource.get(locationKey(edge.source)) ?? [];
      sources.push(edge);
      bySource.set(locationKey(edge.source), sources);
      if (edge.destination !== null) {
        const destinations = byDestination.get(locationKey(edge.destination)) ?? [];
        destinations.push(edge);
        byDestination.set(locationKey(edge.destination), destinations);
      }
    }
  }
  const found = new Map<string, ActivityEvidenceEntry>();
  const queue: ActivityEvidenceEntry[] = [];
  for (const seed of [...seeds].sort((a, b) => b.observedAt - a.observedAt)) {
    const key = evidenceKey(seed);
    if (found.has(key) || found.size >= limit) continue;
    found.set(key, seed);
    queue.push(seed);
  }
  for (let index = 0; index < queue.length && found.size < limit; index += 1) {
    const current = queue[index]!;
    const add = (next: ActivityEvidenceEntry): void => {
      const key = evidenceKey(next);
      if (found.has(key) || found.size >= limit) return;
      found.set(key, next);
      queue.push(next);
    };
    for (const edge of bySource.get(locationKey(current.outpoint)) ?? []) {
      const start = BigInt(edge.source.offsetSats);
      const end = start + BigInt(edge.lengthSats);
      if (current.offsetSats < start || current.offsetSats >= end || edge.destination === null) continue;
      add({
        ...current,
        outpoint: { txid: edge.destination.txid, vout: edge.destination.vout },
        offsetSats: BigInt(edge.destination.offsetSats) + current.offsetSats - start,
      });
    }
    for (const edge of byDestination.get(locationKey(current.outpoint)) ?? []) {
      const destination = edge.destination;
      if (destination === null) continue;
      const start = BigInt(destination.offsetSats);
      const end = start + BigInt(edge.lengthSats);
      if (current.offsetSats < start || current.offsetSats >= end) continue;
      add({
        ...current,
        outpoint: { txid: edge.source.txid, vout: edge.source.vout },
        offsetSats: BigInt(edge.source.offsetSats) + current.offsetSats - start,
      });
    }
  }
  return [...found.values()]
    .sort((a, b) => b.observedAt - a.observedAt || evidenceKey(a).localeCompare(evidenceKey(b)))
    .slice(0, limit);
}

export function annotateOrdinalFlowActivity(
  activity: readonly RecentActivity[],
  history: readonly SnapshotHistoryEntry[],
  evidence: readonly ActivityEvidenceEntry[],
): RecentActivity[] {
  const historyByTxid = new Map(history.map((entry) => [entry.txid, entry]));
  const evidenceByOutpoint = new Map<string, ActivityEvidenceEntry[]>();
  for (const item of evidence) {
    const key = locationKey(item.outpoint);
    const entries = evidenceByOutpoint.get(key) ?? [];
    entries.push(item);
    evidenceByOutpoint.set(key, entries);
  }
  return activity.map((activityEntry) => {
    if (activityEntry.actionKind !== null && activityEntry.actionKind !== undefined) return activityEntry;
    const historyEntry = historyByTxid.get(activityEntry.txid);
    if (historyEntry?.ordinalFlow?.kind !== 'complete') return activityEntry;
    const deltaSats = BigInt(activityEntry.deltaSats);
    if (deltaSats === 0n) return activityEntry;
    const direction = deltaSats < 0n ? 'sent' : 'received';
    const identities = new Map<string, ActivityEvidenceEntry>();
    for (const edge of historyEntry.ordinalFlow.edges) {
      const directional = direction === 'sent'
        ? edge.sourceRequested && !edge.destinationRequested
        : !edge.sourceRequested && edge.destinationRequested;
      if (!directional) continue;
      const point = direction === 'sent' ? edge.source : edge.destination;
      if (point === null) continue;
      const start = BigInt(point.offsetSats);
      const end = start + BigInt(edge.lengthSats);
      for (const item of evidenceByOutpoint.get(locationKey(point)) ?? []) {
        if (item.offsetSats >= start && item.offsetSats < end) {
          identities.set(item.inscriptionId, item);
        }
      }
    }
    const ordered = [...identities.values()]
      .sort((a, b) => a.inscriptionId.localeCompare(b.inscriptionId));
    const first = ordered[0];
    if (first === undefined) return activityEntry;
    return {
      ...activityEntry,
      actionKind: direction === 'sent' ? 'ordinal_transfer' : 'ordinal_receive',
      inscriptionId: first.inscriptionId,
      inscriptionNumber: first.number,
      inscriptionCount: ordered.length,
      ...(direction === 'received'
        ? {
            receivedInscriptionCount: ordered.length,
            ordinalValueSats: activityEntry.deltaSats,
          }
        : {}),
    };
  });
}
type JournalTransaction = Pick<
  StoredTransaction,
  'txid' | 'createdAt' | 'amountSats' | 'feeSats' | 'replacesTxid'
> & {
  status: StoredTransaction['status'] | 'pending';
  kind?: StoredTransaction['kind'];
  plan?: StoredTransaction['plan'];
};
export type TransactionDisplayStatus =
  | StoredTransaction['status']
  | 'pending'
  | 'replaced';

export function ordinalActionInscriptionId(
  plan: StoredTransaction['plan'] | undefined,
): string | null {
  if (plan?.kind === 'ordinal_transfer' && plan.policy.intent.kind === 'ordinal_transfer') {
    return plan.policy.intent.inscriptionId;
  }
  if (plan?.kind === 'rescue') {
    return plan.protectedSatFlow[0]?.inscriptionId ?? null;
  }
  return null;
}

/** Gateway-scanned history is authoritative over the broadcast-time journal. */
export function reconcileTransactionStatus(
  journalStatus: TransactionDisplayStatus,
  confirmationState: SnapshotHistoryEntry['confirmationState'] | undefined,
): TransactionDisplayStatus {
  if (confirmationState === 'confirmed') return 'confirmed';
  if (confirmationState === 'conflicted') return 'conflicted';
  if (confirmationState === 'replaced') return 'replaced';
  if (confirmationState === 'mempool' && journalStatus === 'pending') return 'accepted';
  return journalStatus;
}

function journalState(
  transaction: JournalTransaction,
  replacedTxids: ReadonlySet<string>,
): RecentActivity['confirmationState'] | null {
  if (replacedTxids.has(transaction.txid)) return 'replaced';
  if (transaction.status === 'accepted' || transaction.status === 'already_known') return 'mempool';
  if (transaction.status === 'confirmed') return 'confirmed';
  if (transaction.status === 'conflicted') return 'conflicted';
  if (transaction.status === 'rejected') return 'rejected';
  if (transaction.status === 'pending') return 'indeterminate';
  return null;
}

function actionMetadata(transaction: JournalTransaction): Partial<Pick<
  RecentActivity,
  'actionKind' | 'addressDisplay' | 'bitcoinActionKind' | 'inscriptionId' |
  'inscriptionNumber' | 'returnedBtcSats'
>> {
  const actionKind =
    transaction.kind === 'ordinal_transfer' ||
    transaction.kind === 'rescue' ||
    transaction.kind === 'ordinal_sweep'
      ? transaction.kind
      : null;
  const bitcoinActionKind = transaction.kind === 'consolidation'
    ? 'self_transfer' as const
    : null;
  const recipientAddresses = transaction.plan?.outputs
    .filter((output) =>
      (output.role === 'recipient' || output.role === 'postage') &&
      output.derivation === undefined)
    .map((output) => output.address) ?? [];
  const uniqueRecipientAddresses = [...new Set(recipientAddresses)];
  const addressDisplay = uniqueRecipientAddresses.length === 1
    ? { kind: 'sent_to' as const, address: uniqueRecipientAddresses[0]! }
    : null;
  if (actionKind === null && bitcoinActionKind === null) {
    return addressDisplay === null ? {} : { addressDisplay };
  }
  const inscriptionId = ordinalActionInscriptionId(transaction.plan);
  const returnedBtcSats = actionKind === 'ordinal_sweep' && transaction.plan
    ? transaction.plan.outputs
        .filter((output) => output.role === 'payment_change')
        .reduce((sum, output) => sum + output.valueSats, 0n)
        .toString()
    : null;
  const inscriptionNumber = inscriptionId === null
    ? null
    : (transaction.plan?.version === 3 || transaction.plan?.version === 4
      ? transaction.plan.inscriptionPreviews.items.find(
          (item) => item.metadata.inscriptionId === inscriptionId,
        )?.metadata.number
      : null) ??
      transaction.plan?.inputs
        .flatMap((input) => input.classification.inscriptions)
        .find((inscription) => inscription.inscriptionId === inscriptionId)
        ?.number ??
      null;
  return {
    actionKind,
    addressDisplay,
    bitcoinActionKind,
    inscriptionId,
    inscriptionNumber,
    returnedBtcSats,
  };
}

function scannedBitcoinActionKind(
  entry: SnapshotHistoryEntry,
): RecentActivity['bitcoinActionKind'] | undefined {
  if (entry.feeSats === null ||
      entry.fundedScriptHashes.length === 0 ||
      entry.spentScriptHashes.length === 0) return undefined;
  const fee = BigInt(entry.feeSats);
  return fee > 0n && BigInt(entry.deltaSats) === -fee
    ? 'self_transfer'
    : undefined;
}

function scannedAddressContext(
  entry: LaneAwareHistoryEntry,
): RecentActivity['addressContext'] | undefined {
  const delta = BigInt(entry.deltaSats);
  if (delta > 0n && entry.ordinalsAddressFunded === true) return 'ordinals_received';
  if (delta < 0n && entry.ordinalsAddressSpent === true) return 'ordinals_sent';
  return undefined;
}

/**
 * Enrich positive scanned history with inscription evidence already verified
 * and retained by the worker. Evidence may come from a current classified UTXO
 * or a later outgoing plan that immutably records the original source outpoint.
 */
export function annotateReceivedInscriptionActivity(
  activity: readonly RecentActivity[],
  evidence: readonly ReceivedInscriptionEvidence[],
): RecentActivity[] {
  const byTxid = new Map<string, ReceivedInscriptionEvidence[]>();
  for (const item of evidence) {
    const entries = byTxid.get(item.txid) ?? [];
    entries.push(item);
    byTxid.set(item.txid, entries);
  }
  return activity.map((entry) => {
    if (entry.actionKind != null || BigInt(entry.deltaSats) <= 0n) return entry;
    const candidates = byTxid.get(entry.txid);
    if (!candidates || candidates.length === 0) return entry;
    const byInscriptionId = new Map(candidates.map((item) => [item.inscriptionId, item]));
    const inscriptions = [...byInscriptionId.values()]
      .sort((a, b) => a.inscriptionId.localeCompare(b.inscriptionId));
    const first = inscriptions[0];
    if (!first) return entry;
    const valueByOutpoint = new Map<string, bigint>();
    for (const item of inscriptions) {
      valueByOutpoint.set(`${item.txid}:${item.vout}`, item.valueSats);
    }
    const ordinalValueSats = [...valueByOutpoint.values()]
      .reduce((sum, value) => sum + value, 0n);
    return {
      ...entry,
      actionKind: 'ordinal_receive',
      inscriptionId: first.inscriptionId,
      inscriptionNumber: first.number,
      inscriptionCount: inscriptions.length,
      receivedInscriptionCount: inscriptions.length,
      ordinalValueSats: ordinalValueSats.toString(),
    };
  });
}

/**
 * Combine authoritative scanned history with the durable outgoing journal.
 * Scanned entries always win by txid; the journal fills the indexing gap
 * immediately after a successful broadcast.
 */
export function projectRecentActivity(
  history: readonly LaneAwareHistoryEntry[],
  transactions: readonly JournalTransaction[],
): RecentActivity[] {
  const scannedTxids = new Set(history.map((entry) => entry.txid));
  const replacedTxids = new Set(
    transactions
      .filter((transaction) => transaction.status !== 'rejected')
      .flatMap((transaction) => transaction.replacesTxid === null ? [] : [transaction.replacesTxid]),
  );

  const journal = transactions
    .filter((transaction) => !scannedTxids.has(transaction.txid))
    .map((transaction): RecentActivity | null => {
      const confirmationState = journalState(transaction, replacedTxids);
      if (confirmationState === null) return null;
      return {
        txid: transaction.txid,
        // Keep wallet-delta semantics consistent with scanned history. The UI
        // separates the recipient amount from this network fee for display.
        deltaSats: (-(transaction.amountSats + transaction.feeSats)).toString(),
        feeSats: transaction.feeSats.toString(),
        confirmationState,
        timestamp: new Date(transaction.createdAt).toISOString(),
        height: null,
        ...actionMetadata(transaction),
      };
    })
    .filter((entry): entry is RecentActivity => entry !== null);

  const transactionByTxid = new Map(transactions.map((transaction) => [transaction.txid, transaction]));
  const scanned = history.map((entry): RecentActivity => {
    const transaction = transactionByTxid.get(entry.txid);
    const metadata = transaction ? actionMetadata(transaction) : {};
    return {
      txid: entry.txid,
      deltaSats: entry.deltaSats,
      feeSats: entry.feeSats,
      confirmationState: entry.confirmationState,
      timestamp: entry.timestamp,
      height: entry.height,
      ...metadata,
      addressContext: scannedAddressContext(entry),
      transactionSource: entry.activitySource ?? null,
      bitcoinActionKind:
        metadata.actionKind === undefined
          ? metadata.bitcoinActionKind ?? scannedBitcoinActionKind(entry)
          : metadata.bitcoinActionKind,
    };
  });

  return [...journal, ...scanned]
    .sort((a, b) => {
      const aUnconfirmed = a.confirmationState === 'confirmed' ? 0 : 1;
      const bUnconfirmed = b.confirmationState === 'confirmed' ? 0 : 1;
      if (aUnconfirmed !== bUnconfirmed) return bUnconfirmed - aUnconfirmed;
      const time = Date.parse(b.timestamp ?? '') - Date.parse(a.timestamp ?? '');
      if (Number.isFinite(time) && time !== 0) return time;
      const height = (b.height ?? -1) - (a.height ?? -1);
      if (height !== 0) return height;
      return a.txid.localeCompare(b.txid);
    });
}

export function mergeRecentActivity(
  history: readonly LaneAwareHistoryEntry[],
  transactions: readonly JournalTransaction[],
  limit = 10,
): RecentActivity[] {
  return projectRecentActivity(history, transactions).slice(0, limit);
}

function bytesToHex(bytes: Uint8Array): string {
  let result = '';
  for (const byte of bytes) result += byte.toString(16).padStart(2, '0');
  return result;
}

/** Cosmetic pagination revision; it is consistency metadata, never authority. */
export function activityRevision(activity: readonly WalletActivityItem[]): string {
  const encoded = new TextEncoder().encode(JSON.stringify({ version: 1, activity }));
  return bytesToHex(sha256(encoded));
}

export function paginateActivity(
  activity: readonly WalletActivityItem[],
  cursor: ActivityPageCursor | null | undefined,
): {
  items: WalletActivityItem[];
  nextCursor: ActivityPageCursor | null;
  reset: boolean;
} {
  const revision = activityRevision(activity);
  const reset = cursor !== null && cursor !== undefined && cursor.revision !== revision;
  const offset = reset ? 0 : cursor?.offset ?? 0;
  const items = activity.slice(offset, offset + ACTIVITY_PAGE_SIZE);
  const nextOffset = offset + items.length;
  return {
    items,
    nextCursor: nextOffset < activity.length
      ? { version: 1, revision, offset: nextOffset }
      : null,
    reset,
  };
}
