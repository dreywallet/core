/**
 * Zod schemas for the encrypted wallet-cache plaintext (validated after
 * decrypt — a stale or foreign shape rejects instead of deserializing
 * garbage). Sats are bigint here; the cache codec round-trips them as tagged
 * decimal strings.
 */
import { z } from 'zod';
import { MAX_ACCOUNT_INDEX } from '../domain/accounts/limits';
import {
  hexIdSchema,
  feeQuoteResponseSchema,
  detectedAssetSchema,
  inscriptionRefSchema,
  inscriptionDisplayMetadataSchema,
  historyCoverageSchema,
  isAuthoritativeCardinalClean,
  primaryClassSchema,
  satRangeSchema,
  snapshotHistoryEntrySchema,
  statusCapabilitiesV2Schema,
  tipSchema,
  voutSchema,
} from '../domain/gateway/contract';
import { utxoLabelSchema } from '../domain/classification/labels';
import {
  legacyAnalyzedTransactionPlanSchema,
  legacyCurrentTransactionPlanSchema,
  legacyTransactionPlanSchema,
  transactionPlanSchema,
} from '../domain/transactions/plan';
export {
  marketplaceReservationSchema,
  marketplaceWorkflowSchema,
} from '../domain/marketplaces/workflow';

export const assetFactsSchema = z
  .object({
    primaryClass: primaryClassSchema,
    inscriptions: z.array(inscriptionRefSchema),
    satRanges: z.array(satRangeSchema).nullable(),
    unsupportedAssetDetected: z.boolean(),
    detectedAssets: z.array(detectedAssetSchema).max(16).default([]),
    detectedAssetCount: z.number().int().nonnegative().default(0),
    assetIdentityComplete: z.boolean().default(false),
    confidence: z.enum(['authoritative', 'degraded']),
    classifiedTip: tipSchema,
    classificationRevision: z.string().min(1),
  })
  .strict()
  .superRefine((facts, ctx) => {
    if (facts.primaryClass === 'cardinal_clean' && !isAuthoritativeCardinalClean(facts)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['primaryClass'],
        message: 'cardinal_clean classification contradicts protected asset facts',
      });
    }
  });

const storedUtxoShape = {
    outpoint: z.object({ txid: hexIdSchema, vout: voutSchema }).strict(),
    valueSats: z.bigint().nonnegative(),
    scriptPubKey: z.string().regex(/^[0-9a-f]+$/),
    account: z.number().int().nonnegative(),
    lane: z.enum(['payment', 'ordinals']),
    chain: z.union([z.literal(0), z.literal(1)]),
    addressIndex: z.number().int().nonnegative(),
    height: z.number().int().nonnegative().nullable(),
    walletCreatedChange: z.boolean(),
    facts: assetFactsSchema.nullable(),
    flags: z.object({ userFrozen: z.boolean(), dustQuarantined: z.boolean() }).strict(),
} as const;

/** Current writes always carry stable identity. */
export const storedUtxoSchema = z.object({
  ...storedUtxoShape,
  accountId: z.string().regex(/^acct_(?:mainnet|signet|regtest)_[0-9a-f]{64}$/u),
}).strict();
/** Read-only pre-v0.4 cache row; migrate before it can enter selection/planning. */
export const legacyStoredUtxoSchema = z.object(storedUtxoShape).strict();
export const storedUtxosSchema = z.array(z.union([storedUtxoSchema, legacyStoredUtxoSchema]));

export function migrateLegacyStoredUtxos(
  rows: z.infer<typeof storedUtxosSchema>,
  resolveAccountId: (row: z.infer<typeof legacyStoredUtxoSchema>) => string | null,
): z.infer<typeof storedUtxoSchema>[] {
  return rows.map((row) => {
    if ('accountId' in row) return storedUtxoSchema.parse(row);
    const accountId = resolveAccountId(row);
    if (accountId === null) throw new Error('legacy UTXO account identity cannot be resolved');
    return storedUtxoSchema.parse({ ...row, accountId });
  });
}

/** Legacy pre-v0.8.1 history record. */
export const storedHistorySchema = z.array(snapshotHistoryEntrySchema);
export const storedHistoryRecordSchema = z.object({
  version: z.literal(2),
  entries: storedHistorySchema,
  coverage: historyCoverageSchema,
}).strict();
/** Reads migrate legacy arrays without rewriting them during an unrelated view. */
export const storedHistoryReadSchema = z.union([
  storedHistoryRecordSchema,
  storedHistorySchema.transform((entries) => ({
    version: 2 as const,
    entries,
    coverage: { status: 'complete' as const, limitedScriptHashes: [] },
  })),
]);
export type StoredHistoryRecord = z.infer<typeof storedHistoryRecordSchema>;

export const ACTIVITY_EVIDENCE_MAX_IDENTITIES = 4_096;
export const activityEvidenceEntrySchema = z.object({
  inscriptionId: z.string().regex(/^[0-9a-f]{64}i[0-9]+$/),
  number: z.number().int().nullable(),
  outpoint: z.object({ txid: hexIdSchema, vout: voutSchema }).strict(),
  offsetSats: z.bigint().nonnegative(),
  observedAt: z.number().int().nonnegative(),
}).strict();
export const activityEvidenceRecordSchema = z.object({
  version: z.literal(1),
  entries: z.array(activityEvidenceEntrySchema).max(ACTIVITY_EVIDENCE_MAX_IDENTITIES),
}).strict();
export type ActivityEvidenceEntry = z.infer<typeof activityEvidenceEntrySchema>;
export type ActivityEvidenceRecord = z.infer<typeof activityEvidenceRecordSchema>;

export const scanUnitSchema = z
  .object({
    source: z.enum(['standard', 'descriptor', 'xverse']),
    account: z.number().int().nonnegative(),
    accountId: z.string().regex(/^acct_(?:mainnet|signet|regtest)_[0-9a-f]{64}$/u).optional(),
    lane: z.enum(['payment', 'ordinals']),
    legacyEntryId: z.string().min(1).optional(),
  })
  .strict()
  .superRefine((unit, context) => {
    if (unit.source === 'descriptor' && unit.accountId === undefined) {
      context.addIssue({ code: z.ZodIssueCode.custom, path: ['accountId'], message: 'descriptor unit requires accountId' });
    }
    if (unit.source === 'xverse' && unit.accountId !== undefined) {
      context.addIssue({ code: z.ZodIssueCode.custom, path: ['accountId'], message: 'legacy units cannot carry accountId' });
    }
  });

const standardAccountsSchema = z
  .array(z.number().int().min(0).max(MAX_ACCOUNT_INDEX))
  .min(1)
  .superRefine((accounts, context) => {
    if (accounts[0] !== 0) {
      context.addIssue({ code: z.ZodIssueCode.custom, message: 'account zero is required' });
    }
    for (let index = 1; index < accounts.length; index += 1) {
      if (accounts[index]! <= accounts[index - 1]!) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          message: 'standard accounts must be unique and sorted',
        });
        break;
      }
    }
  });

export const registeredPublicAccountSchema = z.object({
  accountId: z.string().regex(/^acct_(?:mainnet|signet|regtest)_[0-9a-f]{64}$/u),
  network: z.enum(['mainnet', 'signet', 'regtest']),
  source: z.enum(['standard', 'descriptor']),
  account: z.number().int().min(0).max(MAX_ACCOUNT_INDEX),
  name: z.string().min(1).max(80),
}).strict().superRefine((account, context) => {
  if (!account.accountId.startsWith(`acct_${account.network}_`)) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      path: ['accountId'],
      message: 'public account identity differs from registry network',
    });
  }
});
export type RegisteredPublicAccount = z.infer<typeof registeredPublicAccountSchema>;

const registeredPublicAccountsSchema = z.array(registeredPublicAccountSchema)
  .superRefine((accounts, context) => {
    const ids = new Set<string>();
    const standardIndexes = new Set<number>();
    for (const [index, account] of accounts.entries()) {
      if (ids.has(account.accountId)) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          path: [index, 'accountId'],
          message: 'duplicate public account',
        });
      }
      ids.add(account.accountId);
      if (account.source === 'standard') {
        if (standardIndexes.has(account.account)) {
          context.addIssue({
            code: z.ZodIssueCode.custom,
            path: [index, 'account'],
            message: 'duplicate software account index',
          });
        }
        standardIndexes.add(account.account);
      }
    }
  });

export const scanCheckpointSchema = z
  .object({
    scanId: z.string().min(1),
    /** Old checkpoints predate refresh scope and migrate to discovery. */
    scope: z.enum(['discovery', 'refresh']).default('discovery'),
    queue: z.array(scanUnitSchema),
    done: z.array(scanUnitSchema),
    /** Units that returned UTXOs or history during this scan. */
    activeUnits: z.array(scanUnitSchema).default([]),
    /** Units that returned confirmed UTXOs or confirmed transaction history. */
    confirmedUnits: z.array(scanUnitSchema).default([]),
    /** Consecutive completed standard accounts without confirmed activity. */
    emptyStandardAccountStreak: z.number().int().nonnegative().default(0),
    /** Explicitly created or previously discovered standard accounts. */
    standardAccounts: standardAccountsSchema.default([0]),
    /** Envelope revision every completed unit agreed on (null before first unit). */
    revision: z.string().nullable(),
    startedAt: z.number().int().nonnegative(),
    /** Per-chain index bound for the current (initial or extended) pass. */
    maxIndexPerChain: z.number().int().positive(),
    /** Units whose §8.2 boundary prompt is pending user opt-in. */
    boundaryUnits: z.array(scanUnitSchema),
    /**
     * A snapshot/classify pair disagreed on revision even after refetch
     * (§11.4). Durable so a resume after failure/restart cannot silently
     * clear the conflicting_sources gate.
     */
    hadConflict: z.boolean(),
    /** At least one completed unit returned bounded rather than full history. */
    historyPartial: z.boolean().default(false),
  })
  .strict();
export type ScanCheckpoint = z.infer<typeof scanCheckpointSchema>;

export const recoveredAddressCountSchema = z.object({
  accountId: z.string().regex(/^acct_(?:mainnet|signet|regtest)_[0-9a-f]{64}$/u),
  account: z.number().int().min(0).max(MAX_ACCOUNT_INDEX),
  payment: z.number().int().nonnegative(),
  ordinals: z.number().int().nonnegative(),
}).strict();

export const legacyRecoveredAddressCountSchema = z.object({
  account: z.number().int().min(0).max(MAX_ACCOUNT_INDEX),
  payment: z.number().int().nonnegative(),
  ordinals: z.number().int().nonnegative(),
}).strict();

const recoveredAddressCountsSchema = z
  .array(recoveredAddressCountSchema)
  .superRefine((counts, context) => {
    for (let index = 0; index < counts.length; index += 1) {
      const entry = counts[index]!;
      if (entry.payment === 0 && entry.ordinals === 0) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          path: [index],
          message: 'empty recovered-address counts must be omitted',
        });
      }
      if (index > 0 && entry.accountId <= counts[index - 1]!.accountId) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          path: [index, 'accountId'],
          message: 'recovered-address identities must be unique and sorted',
        });
      }
    }
  });

export const legacyRecoveredAddressCountsSchema = z
  .array(legacyRecoveredAddressCountSchema)
  .superRefine((counts, context) => {
    for (let index = 0; index < counts.length; index += 1) {
      const entry = counts[index]!;
      if (entry.payment === 0 && entry.ordinals === 0) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          path: [index],
          message: 'empty recovered-address counts must be omitted',
        });
      }
      if (index > 0 && entry.account <= counts[index - 1]!.account) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          path: [index, 'account'],
          message: 'legacy recovered-address accounts must be unique and sorted',
        });
      }
    }
  });

export function migrateLegacyRecoveredAddressCounts(
  counts: z.infer<typeof legacyRecoveredAddressCountsSchema>,
  resolveAccountId: (account: number) => string | null,
): z.infer<typeof recoveredAddressCountsSchema> {
  const migrated = counts.map((entry) => {
    const accountId = resolveAccountId(entry.account);
    if (accountId === null) {
      throw new Error('legacy recovered-address identity cannot be resolved');
    }
    return { ...entry, accountId };
  }).sort((left, right) => left.accountId < right.accountId ? -1 :
    left.accountId === right.accountId ? 0 : 1);
  return recoveredAddressCountsSchema.parse(migrated);
}

/** Exact pre-v0.4 metadata plaintext; parse before adding stable account identity. */
export const legacyAccountsMetaSchema = z.object({
  lastCompletedScanId: z.string().nullable(),
  lastSyncedAt: z.number().int().nonnegative().nullable(),
  revision: z.string().nullable(),
  hasConflictingSources: z.boolean(),
  activeUnits: z.array(scanUnitSchema).default([]),
  standardAccounts: standardAccountsSchema.default([0]),
  hiddenStandardAccounts: z
    .array(z.number().int().min(0).max(MAX_ACCOUNT_INDEX))
    .default([]),
  recoveredAddressCounts: legacyRecoveredAddressCountsSchema.default([]),
}).strict().superRefine((meta, context) => {
  const registered = new Set(meta.standardAccounts);
  for (let index = 0; index < meta.hiddenStandardAccounts.length; index += 1) {
    const account = meta.hiddenStandardAccounts[index]!;
    if (!registered.has(account)) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['hiddenStandardAccounts', index],
        message: 'hidden account must be a registered standard account',
      });
    }
    if (index > 0 && account <= meta.hiddenStandardAccounts[index - 1]!) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['hiddenStandardAccounts', index],
        message: 'hidden accounts must be unique and sorted',
      });
    }
  }
  if (meta.hiddenStandardAccounts.length >= meta.standardAccounts.length) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      path: ['hiddenStandardAccounts'],
      message: 'at least one standard account must remain visible',
    });
  }
});
export type LegacyAccountsMeta = z.infer<typeof legacyAccountsMetaSchema>;

export const accountsMetaSchema = z
  .object({
    lastCompletedScanId: z.string().nullable(),
    lastSyncedAt: z.number().int().nonnegative().nullable(),
    revision: z.string().nullable(),
    /** Set when a snapshot/classify pair disagreed even after refetch (§11.4). */
    hasConflictingSources: z.boolean(),
    /** Successful units worth polling; absent in pre-adaptive cache records. */
    activeUnits: z.array(scanUnitSchema).default([]),
    /** Units whose latest successful scan has incomplete display history. */
    partialHistoryUnits: z.array(scanUnitSchema).default([]),
    /** Explicitly created or recovery-discovered standard accounts. */
    standardAccounts: standardAccountsSchema.default([0]),
    /** Stable registry survives empty scans; definitions are encrypted separately. */
    registeredPublicAccounts: registeredPublicAccountsSchema.default([]),
    activePublicAccountId: z.string()
      .regex(/^acct_(?:mainnet|signet|regtest)_[0-9a-f]{64}$/u)
      .nullable()
      .default(null),
    hiddenPublicAccountIds: z.array(
      z.string().regex(/^acct_(?:mainnet|signet|regtest)_[0-9a-f]{64}$/u),
    ).default([]),
    /** Reversible presentation-only suppression; accounts remain scanned. */
    hiddenStandardAccounts: z
      .array(z.number().int().min(0).max(MAX_ACCOUNT_INDEX))
      .default([]),
    /** Distinct current recovered external scripts per account and lane. */
    recoveredAddressCounts: recoveredAddressCountsSchema.default([]),
    /** One-time acknowledgement of the cross-wallet empty-account tradeoff. */
    emptyAccountGapAcknowledged: z.boolean().default(false),
  })
  .strict()
  .superRefine((meta, context) => {
    if (meta.activePublicAccountId !== null &&
        !meta.registeredPublicAccounts.some((account) => account.accountId === meta.activePublicAccountId)) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['activePublicAccountId'],
        message: 'active public account must be registered',
      });
    }
    const registeredPublicIds = new Set(
      meta.registeredPublicAccounts.map((account) => account.accountId),
    );
    for (const [index, count] of meta.recoveredAddressCounts.entries()) {
      const registeredAccount = meta.registeredPublicAccounts.find(
        (account) => account.accountId === count.accountId,
      );
      if (!registeredAccount) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['recoveredAddressCounts', index, 'accountId'],
          message: 'recovered-address identity must be registered',
        });
      } else if (registeredAccount.account !== count.account) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['recoveredAddressCounts', index, 'account'],
          message: 'recovered-address account index differs from registry',
        });
      }
    }
    for (const [index, accountId] of meta.hiddenPublicAccountIds.entries()) {
      if (!registeredPublicIds.has(accountId)) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['hiddenPublicAccountIds', index],
          message: 'hidden public account must be registered',
        });
      }
      if (meta.hiddenPublicAccountIds.indexOf(accountId) !== index) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['hiddenPublicAccountIds', index],
          message: 'hidden public accounts must be unique',
        });
      }
    }
    if (meta.registeredPublicAccounts.length > 0 &&
        meta.hiddenPublicAccountIds.length >= meta.registeredPublicAccounts.length) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['hiddenPublicAccountIds'],
        message: 'at least one public account must remain visible',
      });
    }
    if (meta.activePublicAccountId !== null &&
        meta.hiddenPublicAccountIds.includes(meta.activePublicAccountId)) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['hiddenPublicAccountIds'],
        message: 'active public account cannot be hidden',
      });
    }
    const registered = new Set(meta.standardAccounts);
    for (let index = 0; index < meta.hiddenStandardAccounts.length; index += 1) {
      const account = meta.hiddenStandardAccounts[index]!;
      if (!registered.has(account)) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['hiddenStandardAccounts', index],
          message: 'hidden account must be a registered standard account',
        });
      }
      if (index > 0 && account <= meta.hiddenStandardAccounts[index - 1]!) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['hiddenStandardAccounts', index],
          message: 'hidden accounts must be unique and sorted',
        });
      }
    }
    if (meta.hiddenStandardAccounts.length >= meta.standardAccounts.length) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['hiddenStandardAccounts'],
        message: 'at least one standard account must remain visible',
      });
    }
  });
export type AccountsMeta = z.infer<typeof accountsMetaSchema>;

/** Read boundary accepts exact legacy or current plaintext; writes use current only. */
export const accountsMetaReadSchema = z.union([legacyAccountsMetaSchema, accountsMetaSchema]);

function carriesStableAccountIdentity(input: unknown): boolean {
  if (typeof input !== 'object' || input === null || Array.isArray(input)) return false;
  return Object.hasOwn(input, 'registeredPublicAccounts') ||
    Object.hasOwn(input, 'activePublicAccountId') ||
    Object.hasOwn(input, 'hiddenPublicAccountIds');
}

/**
 * Atomically migrate the complete pre-v0.4 plaintext after the platform derives
 * and seals one stable public definition for every registered software account.
 */
export function migrateLegacyAccountsMetaV04(
  input: unknown,
  registeredSoftwareAccounts: readonly RegisteredPublicAccount[],
  activePublicAccountId: string,
): AccountsMeta {
  if (carriesStableAccountIdentity(input)) return accountsMetaSchema.parse(input);
  const legacy = legacyAccountsMetaSchema.parse(input);
  const registered = registeredPublicAccountsSchema.parse(registeredSoftwareAccounts);
  if (registered.some((account) => account.source !== 'standard')) {
    throw new Error('legacy migration accepts only derived software accounts');
  }
  if (registered.length !== legacy.standardAccounts.length ||
      legacy.standardAccounts.some((account) =>
        !registered.some((candidate) => candidate.account === account))) {
    throw new Error('legacy software account registry is incomplete');
  }
  const byAccount = new Map(registered.map((account) => [account.account, account.accountId]));
  if (!registered.some((account) => account.accountId === activePublicAccountId)) {
    throw new Error('legacy active public account is not registered');
  }
  const activeUnits = legacy.activeUnits.map((unit) => {
    if (unit.source !== 'standard') return unit;
    const accountId = byAccount.get(unit.account);
    if (accountId === undefined) throw new Error('legacy active-unit identity cannot be resolved');
    return { ...unit, accountId };
  });
  const hiddenPublicAccountIds = legacy.hiddenStandardAccounts.map((account) => {
    const accountId = byAccount.get(account);
    if (accountId === undefined) throw new Error('legacy hidden-account identity cannot be resolved');
    return accountId;
  });
  return accountsMetaSchema.parse({
    ...legacy,
    activeUnits,
    registeredPublicAccounts: registered,
    activePublicAccountId,
    hiddenPublicAccountIds,
    recoveredAddressCounts: migrateLegacyRecoveredAddressCounts(
      legacy.recoveredAddressCounts,
      (account) => byAccount.get(account) ?? null,
    ),
  });
}

export const storedPlanSchema = z.union([
  transactionPlanSchema,
  legacyCurrentTransactionPlanSchema,
  legacyAnalyzedTransactionPlanSchema,
  legacyTransactionPlanSchema,
]);

const broadcastRecoveryBaseSchema = z
  .object({
    planId: z.string().min(1),
    transactionHex: z.string().regex(/^(?:[0-9a-f]{2})+$/),
    txid: hexIdSchema,
    wtxid: hexIdSchema,
    network: z.enum(['mainnet', 'signet', 'regtest']),
    backend: z.string().min(1),
    attempts: z.number().int().nonnegative(),
    nextRetryAt: z.number().int().nonnegative(),
    lastFailure: z.string().nullable(),
  });

export const broadcastRecoverySchema = z.union([
  broadcastRecoveryBaseSchema.extend({
    feeTarget: z.union([z.literal(2), z.literal(6), z.literal(12)]),
    feeQuote: feeQuoteResponseSchema,
  }).strict(),
  broadcastRecoveryBaseSchema.extend({
    customFeeRateSatPerKvB: z.number().int().positive().max(10_000_000),
    status: statusCapabilitiesV2Schema,
  }).strict(),
]);
export type BroadcastRecovery = z.infer<typeof broadcastRecoverySchema>;

export const providerBroadcastRecoverySchema = z.object({
  version: z.literal(1),
  plan: z.unknown(),
  transactionHex: z.string().regex(/^(?:[0-9a-f]{2})+$/),
  txid: hexIdSchema,
  wtxid: hexIdSchema,
  feeTarget: z.union([z.literal(2), z.literal(6), z.literal(12)]),
  feeQuote: feeQuoteResponseSchema,
  attempts: z.number().int().nonnegative(),
  nextRetryAt: z.number().int().nonnegative(),
  lastFailure: z.string().nullable(),
}).strict();
export type ProviderBroadcastRecovery = z.infer<typeof providerBroadcastRecoverySchema>;

export const storedTransactionSchema = z
  .object({
    planId: z.string().min(1),
    kind: z.enum([
      'native_send', 'native_batch_send', 'ordinal_transfer', 'ordinal_batch_transfer', 'ordinal_postage_manage', 'consolidation', 'rbf', 'cpfp', 'rescue', 'ordinal_sweep',
    ]),
    txid: hexIdSchema,
    createdAt: z.number().int().nonnegative(),
    amountSats: z.bigint().nonnegative(),
    feeSats: z.bigint().nonnegative(),
    status: z.enum(['accepted', 'already_known', 'confirmed', 'conflicted', 'rejected']),
    detail: z.string().nullable(),
    parentTxid: hexIdSchema.nullable(),
    replacesTxid: hexIdSchema.nullable(),
    plan: z.union([
      transactionPlanSchema,
      legacyCurrentTransactionPlanSchema,
      legacyAnalyzedTransactionPlanSchema,
      legacyTransactionPlanSchema,
    ]),
  })
  .strict();
export type StoredTransaction = z.infer<typeof storedTransactionSchema>;

export const galleryStateSchema = z.enum(['visible', 'hidden']);
const galleryItemFields = {
    inscriptionId: z.string().regex(/^[0-9a-f]{64}i(?:0|[1-9][0-9]*)$/),
    account: z.number().int().nonnegative(),
    firstSeenAt: z.number().int().nonnegative(),
    lastSeenAt: z.number().int().nonnegative(),
    metadata: z.object({
      number: z.number().int().nullable(),
      contentType: z.string().min(1).nullable(),
      contentLength: z.number().int().nonnegative().nullable(),
      satpoint: z.string().min(1),
      outpoint: z.object({ txid: hexIdSchema, vout: voutSchema }).strict(),
      confirmations: z.number().int().nonnegative(),
      parent: z.string().nullable(),
      delegate: z.string().nullable(),
      reinscription: z.boolean(),
      cursed: z.boolean(),
      classificationRevision: z.string().min(1),
    }).strict().nullable(),
    display: z.object({
      catalogRevision: z.string().regex(/^[0-9a-f]{40}$/),
      metadata: inscriptionDisplayMetadataSchema,
    }).strict().nullable().optional(),
};
const galleryItems = <StateSchema extends z.ZodTypeAny>(state: StateSchema) => z.array(z.object({
  ...galleryItemFields,
  state,
}).strict()).max(4096);
const currentGalleryRecordSchema = z.object({
  version: z.literal(2),
  items: galleryItems(galleryStateSchema),
}).strict();
const legacyGalleryRecordSchema = z.object({
  version: z.literal(1),
  items: galleryItems(z.enum(['received', 'kept', 'hidden', 'previous'])),
}).strict();

/** V1 organizational states migrate to the simpler visible/hidden model. */
export const galleryRecordSchema = z.union([
  currentGalleryRecordSchema,
  legacyGalleryRecordSchema,
]).transform((record) => record.version === 2 ? record : ({
  version: 2 as const,
  items: record.items.map((item) => ({
    ...item,
    state: item.state === 'hidden' ? 'hidden' as const : 'visible' as const,
  })),
}));
export type GalleryRecord = z.output<typeof galleryRecordSchema>;

export const UTXO_LABEL_MAX_ENTRIES = 4096;

const utxoLabelEntrySchema = z
  .object({
    outpoint: z.object({ txid: hexIdSchema, vout: voutSchema }).strict(),
    label: utxoLabelSchema,
    updatedAt: z.number().int().nonnegative(),
  })
  .strict();

/**
 * Labels live in their own record rather than inside the per-scan-unit utxos
 * records, for three reasons: they survive a rescan without carry-forward, one
 * outpoint cached under both the standard and legacy Xverse units cannot hold
 * two disagreeing labels, and entries for already-spent outpoints are retained
 * so a change output can still report the labels of the inputs that funded it.
 */
export const labelsRecordSchema = z
  .object({
    version: z.literal(1),
    entries: z.array(utxoLabelEntrySchema).max(UTXO_LABEL_MAX_ENTRIES),
  })
  .strict();
export type LabelsRecord = z.infer<typeof labelsRecordSchema>;
