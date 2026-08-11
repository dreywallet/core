import { describe, expect, it } from 'vitest';
import {
  buildRefreshUnits,
  buildScanUnits,
  removeDescriptorAccountLifecycle,
  stopStandardDiscoveryAfter,
  unitKey,
  unitLaneFromKey,
} from '../../src/scan/scan-state';
import {
  accountsMetaReadSchema,
  accountsMetaSchema,
  legacyRecoveredAddressCountsSchema,
  migrateLegacyAccountsMetaV04,
  migrateLegacyRecoveredAddressCounts,
  scanCheckpointSchema,
} from '../../src/scan/cache-schemas';
import {
  normalizeHiddenStandardAccounts,
  restoreOccupiedStandardAccounts,
  visibleStandardAccounts,
} from '../../src/domain/accounts/visibility';

describe('adaptive account scan planning', () => {
  it('migrates pre-registry encrypted metadata to account zero', () => {
    expect(accountsMetaSchema.parse({
      lastCompletedScanId: null,
      lastSyncedAt: null,
      revision: null,
      hasConflictingSources: false,
      activeUnits: [],
    })).toMatchObject({
      standardAccounts: [0],
      hiddenStandardAccounts: [],
      recoveredAddressCounts: [],
    });
  });

  it('keeps hidden accounts registered, sorted, recoverable, and never hides every account', () => {
    expect(normalizeHiddenStandardAccounts([0, 1, 2], [2, 1, 1])).toEqual([1, 2]);
    expect(visibleStandardAccounts([0, 1, 2], [1])).toEqual([0, 2]);
    expect(restoreOccupiedStandardAccounts([1, 2], [2])).toEqual([1]);
    expect(() => normalizeHiddenStandardAccounts([0, 1], [0, 1])).toThrow(/remain visible/u);
    expect(() => accountsMetaSchema.parse({
      lastCompletedScanId: null,
      lastSyncedAt: null,
      revision: null,
      hasConflictingSources: false,
      activeUnits: [],
      standardAccounts: [0, 1],
      hiddenStandardAccounts: [2],
      recoveredAddressCounts: [],
    })).toThrow(/registered standard account/u);
  });

  it('accepts only sorted, distinct, non-empty recovered-address summaries', () => {
    const accountA = `acct_signet_${'a'.repeat(64)}`;
    const accountB = `acct_signet_${'b'.repeat(64)}`;
    const base = {
      lastCompletedScanId: null,
      lastSyncedAt: null,
      revision: null,
      hasConflictingSources: false,
      activeUnits: [],
      registeredPublicAccounts: [
        { accountId: accountA, network: 'signet' as const, source: 'standard' as const,
          account: 0, name: 'Primary' },
        { accountId: accountB, network: 'signet' as const, source: 'descriptor' as const,
          account: 3, name: 'Watch' },
      ],
    };
    expect(accountsMetaSchema.parse({
      ...base,
      recoveredAddressCounts: [
        { accountId: accountA, account: 0, payment: 2, ordinals: 0 },
        { accountId: accountB, account: 3, payment: 0, ordinals: 1 },
      ],
    }).recoveredAddressCounts).toEqual([
      { accountId: accountA, account: 0, payment: 2, ordinals: 0 },
      { accountId: accountB, account: 3, payment: 0, ordinals: 1 },
    ]);
    expect(() => accountsMetaSchema.parse({
      ...base,
      recoveredAddressCounts: [
        { accountId: accountB, account: 3, payment: 1, ordinals: 0 },
        { accountId: accountA, account: 0, payment: 1, ordinals: 0 },
      ],
    })).toThrow();
    expect(() => accountsMetaSchema.parse({
      ...base,
      recoveredAddressCounts: [
        { accountId: accountA, account: 0, payment: 0, ordinals: 0 },
      ],
    })).toThrow();
    expect(() => accountsMetaSchema.parse({
      ...base,
      recoveredAddressCounts: [
        { accountId: accountA, account: 3, payment: 1, ordinals: 0 },
      ],
    })).toThrow('differs from registry');

    const legacy = legacyRecoveredAddressCountsSchema.parse([
      { account: 0, payment: 2, ordinals: 0 },
      { account: 3, payment: 0, ordinals: 1 },
    ]);
    expect(migrateLegacyRecoveredAddressCounts(
      legacy,
      (account) => account === 0 ? accountA : account === 3 ? accountB : null,
    )).toEqual([
      { accountId: accountA, account: 0, payment: 2, ordinals: 0 },
      { accountId: accountB, account: 3, payment: 0, ordinals: 1 },
    ]);
    expect(() => migrateLegacyRecoveredAddressCounts(legacy, () => null))
      .toThrow('cannot be resolved');
  });

  it('migrates a complete pre-v0.4 metadata plaintext through one stable-ID boundary', () => {
    const accountA = `acct_signet_${'a'.repeat(64)}`;
    const accountB = `acct_signet_${'b'.repeat(64)}`;
    const legacyPlaintext = {
      lastCompletedScanId: 'legacy-scan',
      lastSyncedAt: 10,
      revision: 'legacy-revision',
      hasConflictingSources: false,
      activeUnits: [
        { source: 'standard' as const, account: 0, lane: 'payment' as const },
        { source: 'standard' as const, account: 1, lane: 'ordinals' as const },
      ],
      standardAccounts: [0, 1],
      hiddenStandardAccounts: [1],
      recoveredAddressCounts: [
        { account: 0, payment: 2, ordinals: 0 },
        { account: 1, payment: 0, ordinals: 1 },
      ],
    };
    expect(accountsMetaReadSchema.parse(legacyPlaintext)).toEqual(legacyPlaintext);
    const registry = [
      { accountId: accountA, network: 'signet' as const, source: 'standard' as const,
        account: 0, name: 'Primary' },
      { accountId: accountB, network: 'signet' as const, source: 'standard' as const,
        account: 1, name: 'Account 2' },
    ];
    const migrated = migrateLegacyAccountsMetaV04(legacyPlaintext, registry, accountA);
    expect(accountsMetaSchema.parse(migrated)).toEqual(migrated);
    expect(migrated.activeUnits.map((unit) => unit.accountId)).toEqual([accountA, accountB]);
    expect(migrated.hiddenPublicAccountIds).toEqual([accountB]);
    expect(migrated.recoveredAddressCounts).toEqual([
      { accountId: accountA, account: 0, payment: 2, ordinals: 0 },
      { accountId: accountB, account: 1, payment: 0, ordinals: 1 },
    ]);
    expect(migrateLegacyAccountsMetaV04(migrated, registry, accountA)).toEqual(migrated);
    expect(() => migrateLegacyAccountsMetaV04(legacyPlaintext, registry.slice(0, 1), accountA))
      .toThrow('registry is incomplete');

    const emptyLegacyPlaintext = {
      ...legacyPlaintext,
      activeUnits: [],
      standardAccounts: [0],
      hiddenStandardAccounts: [],
      recoveredAddressCounts: [],
    };
    expect(accountsMetaReadSchema.parse(emptyLegacyPlaintext)).toEqual(emptyLegacyPlaintext);
    const migratedEmpty = migrateLegacyAccountsMetaV04(
      emptyLegacyPlaintext,
      registry.slice(0, 1),
      accountA,
    );
    expect(migratedEmpty.registeredPublicAccounts).toEqual(registry.slice(0, 1));
    expect(migratedEmpty.activePublicAccountId).toBe(accountA);
  });

  it('refreshes only account 0 for a typical one-account wallet', () => {
    expect(buildRefreshUnits('mainnet', [], 0).map(unitKey)).toEqual([
      'a0:payment',
      'a0:ordinals',
    ]);
  });

  it('retains an empty imported account across a completed-scan restart', () => {
    const accountId = `acct_signet_${'a'.repeat(64)}`;
    const softwareAccountId = `acct_signet_${'b'.repeat(64)}`;
    const registered = [
      { accountId: softwareAccountId, network: 'signet' as const,
        source: 'standard' as const, account: 0, name: 'Primary' },
      { accountId, network: 'signet' as const,
        source: 'descriptor' as const, account: 0, name: 'Watch account' },
    ];
    const persisted = accountsMetaSchema.parse({
      lastCompletedScanId: 'scan-1',
      lastSyncedAt: 10,
      revision: 'rev-1',
      hasConflictingSources: false,
      activeUnits: [],
      registeredPublicAccounts: registered,
      activePublicAccountId: accountId,
    });
    const refresh = buildRefreshUnits(
      'signet',
      persisted.activeUnits,
      0,
      persisted.standardAccounts,
      new Map(),
      persisted.registeredPublicAccounts,
      persisted.activePublicAccountId ?? undefined,
    );
    expect(refresh.filter((unit) => unit.source === 'descriptor').map(unitKey)).toEqual([
      `pub:${accountId}:payment`,
      `pub:${accountId}:ordinals`,
    ]);
    expect(refresh.filter((unit) => unit.source === 'standard').map(unitKey)).toEqual([
      `pub:${softwareAccountId}:payment`,
      `pub:${softwareAccountId}:ordinals`,
    ]);
  });

  it('normalizes legacy standard activity and fully removes an active descriptor account', () => {
    const accountId = `acct_signet_${'a'.repeat(64)}`;
    const softwareAccountId = `acct_signet_${'b'.repeat(64)}`;
    const registered = [
      { accountId: softwareAccountId, network: 'signet' as const,
        source: 'standard' as const, account: 0, name: 'Primary' },
      { accountId, network: 'signet' as const,
        source: 'descriptor' as const, account: 0, name: 'Watch account' },
    ];
    const watchPayment = {
      source: 'descriptor' as const, accountId, account: 0, lane: 'payment' as const,
    };
    const watchOrdinals = {
      source: 'descriptor' as const, accountId, account: 0, lane: 'ordinals' as const,
    };
    const persisted = accountsMetaSchema.parse({
      lastCompletedScanId: 'scan-2',
      lastSyncedAt: 20,
      revision: 'rev-2',
      hasConflictingSources: false,
      activeUnits: [
        { source: 'standard', account: 0, lane: 'payment' },
        { source: 'standard', account: 0, lane: 'ordinals' },
        watchPayment,
        watchOrdinals,
      ],
      registeredPublicAccounts: registered,
      activePublicAccountId: accountId,
      recoveredAddressCounts: [
        { accountId, account: 0, payment: 2, ordinals: 1 },
        { accountId: softwareAccountId, account: 0, payment: 1, ordinals: 0 },
      ],
    });
    const beforeRemoval = buildRefreshUnits(
      'signet',
      persisted.activeUnits,
      0,
      persisted.standardAccounts,
      new Map(),
      persisted.registeredPublicAccounts,
      persisted.activePublicAccountId ?? undefined,
    );
    expect(beforeRemoval.filter((unit) => unit.source === 'standard').map(unitKey)).toEqual([
      `pub:${softwareAccountId}:payment`,
      `pub:${softwareAccountId}:ordinals`,
    ]);
    expect(beforeRemoval.filter((unit) => unit.source === 'descriptor').map(unitKey)).toEqual([
      `pub:${accountId}:payment`,
      `pub:${accountId}:ordinals`,
    ]);

    const checkpoint = scanCheckpointSchema.parse({
      scanId: 'scan-2',
      scope: 'refresh',
      queue: [watchPayment],
      done: [watchOrdinals],
      activeUnits: [watchPayment, watchOrdinals],
      standardAccounts: [0],
      revision: 'rev-2',
      startedAt: 1,
      maxIndexPerChain: 60,
      boundaryUnits: [watchPayment],
      hadConflict: false,
    });
    const removed = removeDescriptorAccountLifecycle(
      persisted,
      checkpoint,
      accountId,
      softwareAccountId,
    );
    expect(removed.removedAccountId).toBe(accountId);
    expect(removed.meta.activePublicAccountId).toBe(softwareAccountId);
    expect(removed.meta.hiddenPublicAccountIds).toEqual([]);
    expect(removed.meta.registeredPublicAccounts).toEqual([registered[0]]);
    expect(removed.meta.recoveredAddressCounts).toEqual([
      { accountId: softwareAccountId, account: 0, payment: 1, ordinals: 0 },
    ]);
    for (const units of [
      removed.meta.activeUnits,
      removed.checkpoint?.queue,
      removed.checkpoint?.done,
      removed.checkpoint?.activeUnits,
      removed.checkpoint?.boundaryUnits,
    ]) {
      expect(units?.every((unit) => unit.accountId !== accountId)).toBe(true);
    }
    const validMeta = accountsMetaSchema.parse(removed.meta);
    expect(scanCheckpointSchema.parse(removed.checkpoint)).toBeDefined();
    const afterRestart = buildRefreshUnits(
      'signet',
      validMeta.activeUnits,
      0,
      validMeta.standardAccounts,
      new Map(),
      validMeta.registeredPublicAccounts,
      validMeta.activePublicAccountId ?? undefined,
    );
    expect(afterRestart.filter((unit) => unit.source === 'descriptor')).toEqual([]);
    expect(afterRestart.filter((unit) => unit.source === 'standard').map(unitKey)).toEqual([
      `pub:${softwareAccountId}:payment`,
      `pub:${softwareAccountId}:ordinals`,
    ]);
    expect(() => removeDescriptorAccountLifecycle(persisted, checkpoint,
      `acct_signet_${'c'.repeat(64)}`, softwareAccountId)).toThrow('not registered');
    expect(() => removeDescriptorAccountLifecycle(persisted, checkpoint,
      softwareAccountId, accountId)).toThrow('software account removal is unsupported');
  });

  it('rejects a registry identity whose prefix differs from its network', () => {
    expect(() => accountsMetaSchema.parse({
      lastCompletedScanId: null,
      lastSyncedAt: null,
      revision: null,
      hasConflictingSources: false,
      activeUnits: [],
      registeredPublicAccounts: [{
        accountId: `acct_mainnet_${'a'.repeat(64)}`,
        network: 'signet',
        source: 'descriptor',
        account: 0,
        name: 'Wrong network',
      }],
    })).toThrow('public account identity differs from registry network');
  });

  it('recovers standard and legacy address lanes from encrypted cache keys', () => {
    expect(unitLaneFromKey('mainnet', 'a19:ordinals')).toBe('ordinals');
    expect(unitLaneFromKey('mainnet', 'a0:payment')).toBe('payment');
    const legacy = buildScanUnits('mainnet', true).find((unit) => unit.source === 'xverse');
    expect(legacy).toBeDefined();
    expect(unitLaneFromKey('mainnet', unitKey(legacy!))).toBe(legacy!.lane);
    expect(unitLaneFromKey('mainnet', `pub:acct_signet_${'a'.repeat(64)}:payment`)).toBeNull();
    expect(unitLaneFromKey('mainnet', 'unknown')).toBeNull();
  });

  it('covers a selected or previously active twentieth account without polling empty middle accounts', () => {
    const units = buildRefreshUnits('mainnet', [
      { source: 'standard', account: 19, lane: 'payment' },
    ], 19);
    expect(units.map(unitKey)).toEqual([
      'a0:payment',
      'a0:ordinals',
      'a19:payment',
      'a19:ordinals',
    ]);
  });

  it('refreshes only the known-active lane for a non-selected account', () => {
    const units = buildRefreshUnits('mainnet', [
      { source: 'standard', account: 19, lane: 'payment' },
    ], 0);
    expect(units.map(unitKey)).toEqual([
      'a0:payment',
      'a0:ordinals',
      'a19:payment',
    ]);
  });

  it('stops standard discovery after an unused account while preserving legacy checks', () => {
    const queue = buildScanUnits('mainnet', true);
    const stopped = stopStandardDiscoveryAfter(queue, 1);
    expect(stopped.filter((unit) => unit.source === 'standard').map(unitKey)).toEqual([
      'a0:payment', 'a0:ordinals', 'a1:payment', 'a1:ordinals',
    ]);
    expect(stopped.filter((unit) => unit.source === 'xverse')).toHaveLength(3);
  });

  it('probes beyond twenty accounts and continues from the highest known account', () => {
    const standard = buildScanUnits('mainnet', false);
    expect(standard).toHaveLength(202);
    expect(standard.at(-1)).toEqual({ source: 'standard', account: 100, lane: 'ordinals' });

    const continued = buildScanUnits(
      'mainnet',
      false,
      Array.from({ length: 101 }, (_, account) => account),
    );
    expect(continued.at(-1)).toEqual({
      source: 'standard',
      account: 200,
      lane: 'ordinals',
    });
  });

  it('preserves an explicitly created empty account after an earlier unused account', () => {
    const queue = buildScanUnits('mainnet', false, [0, 3]);
    const stopped = stopStandardDiscoveryAfter(queue, 0, [0, 3]);
    expect(stopped.map(unitKey)).toEqual([
      'a0:payment',
      'a0:ordinals',
      'a3:payment',
      'a3:ordinals',
    ]);
  });
});
