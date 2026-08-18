/**
 * Scan-plan construction and progress states (spec §8.2) — pure logic, no
 * I/O. The engine (scan-engine.ts) executes units; the service owns the
 * queue, checkpoints, and cancellation.
 */
import type { AddressKind, Network } from '../domain/keys/derivation';
import {
  ACCOUNT_DISCOVERY_BATCH_SIZE,
  MAX_ACCOUNT_INDEX,
  normalizeAccountIndexes,
} from '../domain/accounts/limits';
import { xverseManifest } from '../domain/keys/legacy-manifests';
import type {
  AccountsMeta,
  RegisteredPublicAccount,
  ScanCheckpoint,
} from './cache-schemas';
import type { PublicAccountDefinitionV1 } from '../domain/accounts/public-account';

export const GAP_LIMIT = 20;
/** Initial bounded scan cap per chain; §8.2 Extended scan raises it. */
export const INITIAL_MAX_INDEX = 60;
/** Each Extended-scan continuation adds this many indexes per chain. */
export const EXTEND_STEP = 40;

export type ScanScope = 'discovery' | 'refresh';

export interface ScanUnit {
  source: 'standard' | 'descriptor' | 'xverse';
  /** standard: hardened account index. xverse: always 0 (address-index mapping). */
  account: number;
  /** Required for descriptor accounts and all newly created standard units. */
  accountId?: string | undefined;
  lane: AddressKind;
  legacyEntryId?: string | undefined;
}

export function unitKey(unit: ScanUnit): string {
  if (unit.accountId !== undefined) {
    if (unit.source === 'xverse') throw new Error('legacy scan unit cannot carry accountId');
    return `pub:${unit.accountId}:${unit.lane}`;
  }
  if (unit.source === 'descriptor') throw new Error('descriptor scan unit requires accountId');
  return unit.source === 'xverse'
    ? `xverse:${unit.legacyEntryId ?? 'unknown'}`
    : `a${unit.account}:${unit.lane}`;
}

/** Recover the locally derived address lane from an encrypted per-unit cache key. */
export function unitLaneFromKey(network: Network, key: string): AddressKind | null {
  const standard = /^a(?:0|[1-9][0-9]*):(payment|ordinals)$/u.exec(key);
  if (standard?.[1] === 'payment' || standard?.[1] === 'ordinals') {
    return standard[1];
  }
  const descriptor = new RegExp(
    `^pub:acct_${network}_[0-9a-f]{64}:(payment|ordinals)$`,
    'u',
  ).exec(key);
  if (descriptor?.[1] === 'payment' || descriptor?.[1] === 'ordinals') return descriptor[1];
  if (!key.startsWith('xverse:')) return null;
  const legacyEntryId = key.slice('xverse:'.length);
  return xverseManifest(network).entries.find((entry) => entry.id === legacyEntryId)?.lane ?? null;
}

/** Both public lanes for one imported descriptor account. */
export function buildPublicAccountScanUnits(
  definition: PublicAccountDefinitionV1,
  source: 'standard' | 'descriptor' = 'descriptor',
): ScanUnit[] {
  return (['payment', 'ordinals'] as const).map((lane) => ({
    source,
    accountId: definition.accountId,
    account: definition.derivationAccountIndex,
    lane,
  }));
}

/**
 * Xverse legacy units whose account-0 chains are byte-identical to a standard
 * account-0 unit (the m/84' payment and m/86' ordinals path coincidence):
 * their cache records duplicate the standard unit's rows exactly. Returns the
 * standard unit key that shadows `key`, or null when the unit's scripts are
 * genuinely distinct (m/49' nested SegWit).
 */
export function shadowedByStandardKey(network: Network, key: string): string | null {
  for (const entry of xverseManifest(network).entries) {
    if (key !== `xverse:${entry.id}`) continue;
    if (entry.purpose === 84 && entry.lane === 'payment') return 'a0:payment';
    if (entry.purpose === 86 && entry.lane === 'ordinals') return 'a0:ordinals';
  }
  return null;
}

/**
 * Explicit/known accounts plus one bounded sequential recovery batch, followed
 * by pinned Xverse legacy entries. Re-running discovery continues after the
 * highest contiguous known account, while the service still stops each pass
 * after the first completely unused account.
 */
export function buildScanUnits(
  network: Network,
  includeLegacy: boolean,
  knownAccounts: readonly number[] = [0],
  accountIds: ReadonlyMap<number, string> = new Map(),
): ScanUnit[] {
  const accountSet = new Set(normalizeAccountIndexes(knownAccounts));
  let highestContiguous = 0;
  while (accountSet.has(highestContiguous + 1)) highestContiguous += 1;
  for (let offset = 1; offset <= ACCOUNT_DISCOVERY_BATCH_SIZE; offset += 1) {
    const account = highestContiguous + offset;
    if (account > MAX_ACCOUNT_INDEX) break;
    accountSet.add(account);
  }
  const units: ScanUnit[] = [];
  for (const account of [...accountSet].sort((left, right) => left - right)) {
    for (const lane of ['payment', 'ordinals'] as const) {
      const accountId = accountIds.get(account);
      units.push({
        source: 'standard',
        account,
        lane,
        ...(accountId !== undefined ? { accountId } : {}),
      });
    }
  }
  if (includeLegacy) {
    for (const entry of xverseManifest(network).entries) {
      units.push({ source: 'xverse', account: 0, lane: entry.lane, legacyEntryId: entry.id });
    }
  }
  return units;
}

/**
 * Cheap live refresh: always cover both lanes for account 0 and the selected
 * account, then refresh only the exact lanes with known activity elsewhere.
 * A newly selected account is therefore probed completely without polling
 * every empty sibling lane on every timer tick.
 */
export function buildRefreshUnits(
  network: Network,
  activeUnits: readonly ScanUnit[],
  selectedAccount: number,
  standardAccounts: readonly number[] = [0],
  accountIds: ReadonlyMap<number, string> = new Map(),
  registeredAccounts: readonly RegisteredPublicAccount[] = [],
  selectedAccountId?: string,
): ScanUnit[] {
  if (!Number.isInteger(selectedAccount) || selectedAccount < 0 ||
      selectedAccount > MAX_ACCOUNT_INDEX) {
    throw new RangeError('selected account is outside the supported range');
  }
  const resolvedAccountIds = new Map(accountIds);
  if (selectedAccountId !== undefined) {
    const selected = registeredAccounts.find((account) => account.accountId === selectedAccountId);
    if (!selected) throw new Error('selected public account is not registered');
    if (selected.account !== selectedAccount) {
      throw new Error('selected public account metadata differs from account index');
    }
  }
  for (const registered of registeredAccounts) {
    if (registered.network !== network ||
        !registered.accountId.startsWith(`acct_${network}_`)) {
      throw new Error('registered public account network mismatch');
    }
    if (registered.source !== 'standard') continue;
    const prior = resolvedAccountIds.get(registered.account);
    if (prior !== undefined && prior !== registered.accountId) {
      throw new Error('multiple standard public identities claim one account index');
    }
    resolvedAccountIds.set(registered.account, registered.accountId);
  }
  for (const unit of activeUnits) {
    if (unit.source !== 'standard' || unit.accountId === undefined) continue;
    const prior = resolvedAccountIds.get(unit.account);
    if (prior !== undefined && prior !== unit.accountId) {
      throw new Error('multiple standard public identities claim one account index');
    }
    resolvedAccountIds.set(unit.account, unit.accountId);
  }
  const standard = new Map<string, ScanUnit>();
  const activeStandardAccounts = new Set(
    activeUnits
      .filter((unit) => unit.source === 'standard')
      .map((unit) => unit.account),
  );
  const completeAccounts = normalizeAccountIndexes([
    0,
    selectedAccount,
    ...standardAccounts.filter((account) => !activeStandardAccounts.has(account)),
  ]);
  for (const account of completeAccounts) {
    for (const lane of ['payment', 'ordinals'] as const) {
      const accountId = resolvedAccountIds.get(account);
      const unit: ScanUnit = {
        source: 'standard',
        account,
        lane,
        ...(accountId !== undefined ? { accountId } : {}),
      };
      standard.set(unitKey(unit), unit);
    }
  }
  for (const unit of activeUnits) {
    if (unit.source === 'standard' && unit.account <= MAX_ACCOUNT_INDEX) {
      const accountId = resolvedAccountIds.get(unit.account);
      const normalized = accountId === undefined ? unit : { ...unit, accountId };
      standard.set(unitKey(normalized), normalized);
    }
  }
  const units = [...standard.values()].sort((a, b) =>
    a.account - b.account || (a.lane === b.lane ? 0 : a.lane === 'payment' ? -1 : 1));
  const descriptorByKey = new Map<string, ScanUnit>();
  for (const registered of registeredAccounts) {
    if (registered.source !== 'descriptor') continue;
    for (const lane of ['payment', 'ordinals'] as const) {
      const unit: ScanUnit = {
        source: 'descriptor',
        accountId: registered.accountId,
        account: registered.account,
        lane,
      };
      descriptorByKey.set(unitKey(unit), unit);
    }
  }
  for (const unit of activeUnits) {
    if (unit.source !== 'descriptor') continue;
    const key = unitKey(unit);
    descriptorByKey.set(key, unit);
  }
  units.push(...[...descriptorByKey.values()].sort((left, right) => {
    const leftId = left.accountId ?? '';
    const rightId = right.accountId ?? '';
    if (leftId !== rightId) return leftId < rightId ? -1 : 1;
    return left.lane === right.lane ? 0 : left.lane === 'payment' ? -1 : 1;
  }));
  const legacyKeys = new Set<string>();
  for (const unit of activeUnits) {
    if (unit.source !== 'xverse' || !unit.legacyEntryId) continue;
    const key = unitKey(unit);
    if (shadowedByStandardKey(network, key) !== null || legacyKeys.has(key)) continue;
    legacyKeys.add(key);
    units.push(unit);
  }
  return units;
}

/**
 * Remove one descriptor account from durable scan lifecycle state. Consumers
 * use `removedAccountId` to purge its separately encrypted definition,
 * signer binding, UTXOs, history, plans (when terminal), and derivation cache.
 */
export function removeDescriptorAccountLifecycle(
  meta: AccountsMeta,
  checkpoint: ScanCheckpoint | null,
  accountId: string,
  fallbackAccountId: string | null,
): { meta: AccountsMeta; checkpoint: ScanCheckpoint | null; removedAccountId: string } {
  const removed = meta.registeredPublicAccounts.find((account) => account.accountId === accountId);
  if (!removed) throw new Error('public account is not registered');
  if (removed.source !== 'descriptor') throw new Error('software account removal is unsupported');
  const registeredPublicAccounts = meta.registeredPublicAccounts.filter(
    (account) => account.accountId !== accountId,
  );
  let activePublicAccountId = meta.activePublicAccountId;
  if (activePublicAccountId === accountId) {
    if (registeredPublicAccounts.length === 0) activePublicAccountId = null;
    else if (fallbackAccountId !== null &&
        registeredPublicAccounts.some((account) => account.accountId === fallbackAccountId)) {
      activePublicAccountId = fallbackAccountId;
    } else {
      throw new Error('valid fallback public account required');
    }
  }
  const keepUnit = (unit: ScanUnit) => unit.accountId !== accountId;
  const nextMeta: AccountsMeta = {
    ...meta,
    registeredPublicAccounts,
    activePublicAccountId,
    hiddenPublicAccountIds: meta.hiddenPublicAccountIds.filter((id) => id !== accountId),
    activeUnits: meta.activeUnits.filter(keepUnit),
    recoveredAddressCounts: meta.recoveredAddressCounts.filter(
      (count) => count.accountId !== accountId,
    ),
  };
  const nextCheckpoint = checkpoint === null ? null : {
    ...checkpoint,
    queue: checkpoint.queue.filter(keepUnit),
    done: checkpoint.done.filter(keepUnit),
    activeUnits: checkpoint.activeUnits.filter(keepUnit),
    confirmedUnits: checkpoint.confirmedUnits.filter(keepUnit),
    boundaryUnits: checkpoint.boundaryUnits.filter(keepUnit),
  };
  return { meta: nextMeta, checkpoint: nextCheckpoint, removedAccountId: accountId };
}

/**
 * Stop speculative discovery after an unused account without dropping accounts
 * the user explicitly created (including a still-empty trailing account).
 */
export function stopStandardDiscoveryAfter(
  queue: readonly ScanUnit[],
  account: number,
  standardAccounts: readonly number[] = [0],
): ScanUnit[] {
  const preserved = new Set(normalizeAccountIndexes(standardAccounts));
  return queue.filter((unit) =>
    unit.source !== 'standard' || unit.account <= account || preserved.has(unit.account));
}

/**
 * Recovery registers every standard account through a newly discovered active
 * index. Explicit pre-existing gaps are preserved rather than expanded.
 */
export function includeIntermediateDiscoveredAccounts(
  knownAccounts: readonly number[],
  discoveredActiveAccounts: readonly number[],
): number[] {
  const known = normalizeAccountIndexes(knownAccounts);
  const result = new Set(known);
  for (const active of normalizeAccountIndexes(discoveredActiveAccounts)) {
    if (result.has(active)) continue;
    let preceding = 0;
    for (const account of result) {
      if (account < active) preceding = Math.max(preceding, account);
    }
    if (active - preceding > ACCOUNT_DISCOVERY_BATCH_SIZE) {
      throw new RangeError('discovered standard-account gap exceeds one recovery batch');
    }
    for (let account = preceding + 1; account <= active; account += 1) result.add(account);
  }
  return [...result].sort((left, right) => left - right);
}

export type ScanPhase =
  | { kind: 'idle' }
  | {
      kind: 'running';
      scanId: string;
      unit: ScanUnit;
      unitsDone: number;
      unitsTotal: number;
    }
  | { kind: 'awaiting_extend'; scanId: string; boundaryUnits: ScanUnit[] }
  | { kind: 'completed'; scanId: string; finishedAt: number; historyPartial: boolean }
  | { kind: 'cancelled'; scanId: string; reason: 'user' | 'locked' }
  | { kind: 'failed'; scanId: string; reason: string }
  | { kind: 'interrupted'; checkpoint: ScanCheckpoint };

/** Wire-safe projection for the scan.status op (never carries keys/hashes). */
export interface ScanStatusView {
  kind: ScanPhase['kind'];
  scanId: string | null;
  unitsDone: number;
  unitsTotal: number;
  currentUnit: { source: ScanUnit['source']; accountId: string | null; account: number; lane: AddressKind } | null;
  boundaryUnits: { source: ScanUnit['source']; accountId: string | null; account: number; lane: AddressKind }[];
  failureReason: string | null;
  historyPartial: boolean;
}

export function scanStatusView(phase: ScanPhase, unitsTotal: number): ScanStatusView {
  const base: ScanStatusView = {
    kind: phase.kind,
    scanId: null,
    unitsDone: 0,
    unitsTotal,
    currentUnit: null,
    boundaryUnits: [],
    failureReason: null,
    historyPartial: false,
  };
  switch (phase.kind) {
    case 'idle':
      return base;
    case 'running':
      return {
        ...base,
        scanId: phase.scanId,
        unitsDone: phase.unitsDone,
        unitsTotal: phase.unitsTotal,
        currentUnit: {
          source: phase.unit.source,
          accountId: phase.unit.accountId ?? null,
          account: phase.unit.account,
          lane: phase.unit.lane,
        },
      };
    case 'awaiting_extend':
      return {
        ...base,
        scanId: phase.scanId,
        unitsDone: unitsTotal,
        boundaryUnits: phase.boundaryUnits.map((u) => ({
          source: u.source,
          accountId: u.accountId ?? null,
          account: u.account,
          lane: u.lane,
        })),
      };
    case 'completed':
      return {
        ...base,
        scanId: phase.scanId,
        unitsDone: unitsTotal,
        historyPartial: phase.historyPartial,
      };
    case 'cancelled':
      return { ...base, scanId: phase.scanId, failureReason: phase.reason };
    case 'failed':
      return { ...base, scanId: phase.scanId, failureReason: phase.reason };
    case 'interrupted':
      return {
        ...base,
        scanId: phase.checkpoint.scanId,
        unitsDone: phase.checkpoint.done.length,
        unitsTotal: phase.checkpoint.done.length + phase.checkpoint.queue.length,
        historyPartial: phase.checkpoint.historyPartial,
      };
  }
}
