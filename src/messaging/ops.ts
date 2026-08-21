/**
 * Vault/session RPC operation registry (spec §5.2).
 *
 * The envelope keeps `op` an open string; this registry is the authority on
 * which ops exist, the shape of each request/response, which sender contexts
 * may invoke it, and whether it requires an active unlock session. The
 * background dispatcher validates against these schemas so unknown variants,
 * malformed payloads, and unauthorized senders are rejected with stable typed
 * error codes — never reaching the wallet state machine.
 *
 * Browser-free by construction (spec §4): only zod + domain validators. No
 * response schema may carry a secret (seed, entropy, DEK, password), with
 * exactly one sanctioned exception: `vault.revealMnemonic` (spec §7.6 seed
 * reveal) returns the mnemonic to a trusted extension surface after password
 * reauthentication. The dispatcher re-validates every response against these
 * as a leak backstop.
 */
import { z } from 'zod';
import { ACCOUNT_GAP_LIMIT, MAX_ACCOUNT_INDEX } from '../domain/accounts/limits';
import { gatewayStatusViewSchema } from '../domain/gateway/status-view';
import {
  detectedAssetSchema,
  fiatPriceQuoteSchema,
  inscriptionDisplayMetadataSchema,
  voutSchema,
} from '../domain/gateway/contract';
import { validateMnemonic } from '../domain/keys/mnemonic';
import type { ErrorCode, SenderContext } from './envelope';
import {
  feeQuoteRequestSchema,
  feeQuoteResultSchema,
  transactionApproveRequestSchema,
  transactionApproveResultSchema,
  transactionCancelRequestSchema,
  transactionCancelResultSchema,
  transactionPlanRequestSchema,
  transactionPlanResultSchema,
  transactionReviewRequestSchema,
  transactionStatusRequestSchema,
  transactionStatusResultSchema,
  utxoListRequestSchema,
  utxoListResultSchema,
} from './transaction-schemas';
import { utxoLabelSchema } from '../domain/classification/labels';
import {
  parsePublicAccountDescriptors,
  publicAccountDefinitionSchema,
} from '../domain/accounts/public-account';
import { publicAccountDescriptorImportShape } from './account-schemas';
import {
  addressBookSchema,
  normalizeRecipientLabel,
} from '../domain/address-book';
import { validateBip322Message } from '../domain/transactions/bip322';
import { BIP321_LIMITS } from '../domain/payments/bip321';
import { backupMetadataSchema } from '../domain/vault/backup-metadata';

// Only ordinary trusted wallet surfaces may drive the portable RPC registry.
// The in-page content bridge, approval window, and ledger page are excluded:
// they use their own narrowly bound transports rather than this broad surface.
const TRUSTED_SENDERS: readonly SenderContext[] = [
  'popup', 'sidepanel', 'fullpage', 'onboarding',
];

// ---- request schemas -------------------------------------------------------

const emptyRequest = z.object({}).strict();

const operationId = z.string().uuid();
const publicAccountId = z.string().regex(/^acct_(?:mainnet|signet|regtest)_[0-9a-f]{64}$/u);

const vaultCreateRequest = z
  .object({ name: z.string().min(1), password: z.string().min(1), operationId })
  .strict();

const vaultRestoreRequest = z
  .object({
    name: z.string().min(1),
    password: z.string().min(1),
    // Checksum-validated here so a bad mnemonic is a typed ERR_INVALID_PAYLOAD
    // at the boundary rather than an opaque failure inside the state machine.
    mnemonic: z.string().refine(validateMnemonic, { message: 'invalid BIP39 mnemonic' }),
    passphrase: z.string().optional(),
    operationId,
  })
  .strict();

const vaultUnlockRequest = z.object({ vaultId: z.string().min(1), password: z.string().min(1) }).strict();

const vaultChangePasswordRequest = z
  .object({ oldPassword: z.string().min(1), newPassword: z.string().min(1) })
  .strict();

const sessionExpectation = {
  expectedVaultId: z.string().min(1),
  expectedSessionId: z.string().uuid(),
} as const;

const vaultRemoveRequest = z.object({
  targetVaultId: z.string().min(1),
  password: z.string().min(1),
  ...sessionExpectation,
}).strict();

const vaultRevealMnemonicRequest = z
  .object({ password: z.string().min(1), ...sessionExpectation })
  .strict();

const verifyWord = z
  .object({ index: z.number().int().min(0).max(23), word: z.string().min(1) })
  .strict();
const vaultVerifyBackupRequest = z
  .object({
    words: z.array(verifyWord).length(3),
    wordCount: z.union([z.literal(12), z.literal(15), z.literal(18), z.literal(21), z.literal(24)]).default(12),
    ...sessionExpectation,
  })
  .strict()
  .refine((req) => new Set(req.words.map((w) => w.index)).size === req.words.length &&
    req.words.every((word) => word.index < req.wordCount), {
    message: 'verification word positions must be distinct',
  });
export const vaultVerifyFullRecoveryRequest = z.object({
  mnemonic: z.string().max(512).refine(validateMnemonic, { message: 'invalid BIP39 mnemonic' }),
  passphrase: z.string().max(1024).optional(),
  ...sessionExpectation,
}).strict();
export type VaultVerifyFullRecoveryRequest = z.infer<typeof vaultVerifyFullRecoveryRequest>;

const addressReceiveRequest = z
  .object({ accountId: publicAccountId, kind: z.enum(['payment', 'ordinals']), ...sessionExpectation })
  .strict();

const paymentInstructionResolveRequest = z.object({
  input: z.string().min(1).max(BIP321_LIMITS.uriBytes),
  ...sessionExpectation,
}).strict();

const messageSignRequest = z
  .object({
    accountId: publicAccountId,
    addressKind: z.enum(['payment', 'ordinals']),
    message: z.string().superRefine((message, context) => {
      try {
        validateBip322Message(message);
      } catch (error) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          message: error instanceof Error ? error.message : 'invalid BIP-322 message',
        });
      }
    }),
    password: z.string().min(1),
    ...sessionExpectation,
  })
  .strict();

const recipientLabel = z.string().superRefine((label, context) => {
  try {
    normalizeRecipientLabel(label);
  } catch (error) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      message: error instanceof Error ? error.message : 'invalid recipient label',
    });
  }
});
const recipientAddress = z.string().trim().min(1).max(128);
const recipientId = z.string().regex(/^[0-9a-f]{32}$/u);
const addressBookAddRequest = z.object({
  label: recipientLabel,
  address: recipientAddress,
  ...sessionExpectation,
}).strict();
const addressBookRenameRequest = z.object({
  id: recipientId,
  label: recipientLabel,
  ...sessionExpectation,
}).strict();
const addressBookRemoveRequest = z.object({ id: recipientId, ...sessionExpectation }).strict();
const addressBookImportRequest = z.object({
  recipients: z.array(z.object({
    label: recipientLabel,
    address: recipientAddress,
  }).strict()).max(250),
  ...sessionExpectation,
}).strict();
const addressBookImportResult = z.object({
  addressBook: addressBookSchema,
  added: z.number().int().nonnegative(),
  skipped: z.number().int().nonnegative(),
}).strict();
const addressBookDismissRecentRequest = z.object({
  address: recipientAddress,
  ...sessionExpectation,
}).strict();

// §7.4: 1 h default with 12 h, 24 h, and one-week options — the only legal idle timeouts.
const idleTimeoutMs = z.union([
  z.literal(3_600_000),
  z.literal(43_200_000),
  z.literal(86_400_000),
  z.literal(604_800_000),
]);
const configSetRequest = z
  .object({
    idleTimeoutMs: idleTimeoutMs.optional(),
    highSecurityMode: z.boolean().optional(),
    advancedPsbtSigning: z.boolean().optional(),
    ...sessionExpectation,
  })
  .strict();

const activeAccountSetRequest = z
  .object({ accountId: publicAccountId, ...sessionExpectation })
  .strict();
const accountAddRequest = z.object({
  acknowledgeEmptyAccountRisk: z.boolean().default(false),
  ...sessionExpectation,
}).strict();
const accountVisibilitySetRequest = z
  .object({
    accountId: publicAccountId,
    hidden: z.boolean(),
    ...sessionExpectation,
  })
  .strict();
const publicAccountImportRequest = z.object({
  name: z.string().trim().min(1).max(80),
  ...publicAccountDescriptorImportShape,
  ...sessionExpectation,
}).strict().superRefine((request, context) => {
  try {
    parsePublicAccountDescriptors(request);
  } catch (error) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      message: error instanceof Error ? error.message : 'invalid public account descriptors',
    });
  }
});
const publicAccountExportRequest = z.object({
  accountId: publicAccountId,
  password: z.string().min(1).max(1024),
  ...sessionExpectation,
}).strict();
const publicAccountRemoveRequest = z.object({ accountId: publicAccountId, ...sessionExpectation }).strict();
const connectedSiteRevokeRequest = z
  .object({ resourceId: z.string().regex(/^[0-9a-f]{32}$/), ...sessionExpectation })
  .strict();

const activeSessionRequest = z.object(sessionExpectation).strict();
const accountSessionRequest = z.object({ accountId: publicAccountId, ...sessionExpectation }).strict();
const inscriptionId = z.string().regex(/^[0-9a-f]{64}i(?:0|[1-9][0-9]*)$/);
const galleryListRequest = z.object({
  accountId: publicAccountId,
  /**
   * Inscriptions whose rendered raster the surface actually needs. Omitted
   * means "every visible inscription", the pre-lazy behaviour. Listed
   * inscriptions still require cached metadata to be skippable, so a first
   * load always fetches in full. Extension-internal only: the signed gateway
   * contract is unchanged, and a skipped inscription is reported with a
   * locally synthesized placeholder rather than a gateway one.
   */
  rasterFor: z.array(inscriptionId).max(4096).optional(),
  ...sessionExpectation,
}).strict();
const galleryCachedRequest = z.object({
  accountId: publicAccountId,
  ...sessionExpectation,
}).strict();
const galleryUpdateRequest = z.object({
  accountId: publicAccountId,
  inscriptionId,
  state: z.enum(['visible', 'hidden']),
  ...sessionExpectation,
}).strict();
const galleryMediaOpenRequest = z.object({ accountId: publicAccountId, inscriptionId, ...sessionExpectation }).strict();
const galleryMediaLeaseRequest = z.object({
  leaseId: z.string().regex(/^[0-9a-f]{32}$/),
  ...sessionExpectation,
}).strict();
const activityInscriptionPreviewRequest = z.object({
  accountId: publicAccountId,
  txid: z.string().regex(/^[0-9a-f]{64}$/),
  inscriptionId,
  ...sessionExpectation,
}).strict();
const activityInscriptionPreviewBatchRequest = z.object({
  accountId: publicAccountId,
  items: z.array(z.object({
    txid: z.string().regex(/^[0-9a-f]{64}$/),
    inscriptionId,
  }).strict()).min(1).max(8),
  ...sessionExpectation,
}).strict().superRefine((request, ctx) => {
  const ids = request.items.map((item) => item.inscriptionId);
  if (new Set(ids).size !== ids.length) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      path: ['items'],
      message: 'activity inscription ids must be unique',
    });
  }
});

const gatewayStatusRequest = z.object({ forceRefresh: z.boolean().optional() }).strict();

// M6 (§8.2, §10.2, §14.4): discovery scan, home view, user freeze. All of
// these expose wallet data or drive wallet mutation — every one is
// requiresUnlock:true and session-bound.
const hexId = z.string().regex(/^[0-9a-f]{64}$/);
const scanStartRequest = z
  .object({ mode: z.enum(['initial', 'rescan', 'refresh', 'resume']), ...sessionExpectation })
  .strict();
const scanControlRequest = z.object({ scanId: z.string().min(1), ...sessionExpectation }).strict();
const utxoSetFrozenRequest = z
  .object({
    accountId: publicAccountId,
    txid: hexId,
    vout: voutSchema,
    frozen: z.boolean(),
    ...sessionExpectation,
  })
  .strict();
/** §14.4 local label; null clears it. Labels never leave the device. */
const utxoSetLabelRequest = z
  .object({
    accountId: publicAccountId,
    txid: hexId,
    vout: voutSchema,
    label: utxoLabelSchema.nullable(),
    ...sessionExpectation,
  })
  .strict();

// ---- response schemas (no secrets) -----------------------------------------

const vaultIdResult = z.object({ vaultId: z.string().min(1) }).strict();
const unlockResult = z
  .object({
    vaultId: z.string().min(1),
    sessionId: z.string().uuid(),
    deadline: z.number().int().positive(),
  })
  .strict();
const lockResult = z.object({ locked: z.literal(true) }).strict();
const vaultSummary = z
  .object({ vaultId: z.string().min(1), name: z.string(), createdAt: z.number().int().nonnegative() })
  .strict();
const listResult = z.object({ vaults: z.array(vaultSummary), activeVaultId: z.string().nullable() }).strict();
const changePasswordResult = z.object({ ok: z.literal(true) }).strict();
const sessionStatusResult = z
  .object({
    locked: z.boolean(),
    activeVaultId: z.string().nullable(),
    sessionId: z.string().uuid().nullable(),
    deadline: z.number().int().positive().nullable(),
    highSecurityMode: z.boolean(),
  })
  .strict();
const activeAccountResult = z.object({
  accountId: publicAccountId,
  account: z.number().int().min(0).max(MAX_ACCOUNT_INDEX),
}).strict();
const publicAccountExportResult = z.object({ definition: publicAccountDefinitionSchema }).strict();
const publicAccountRemoveResult = z.object({ removed: z.literal(true) }).strict();
const accountVisibilityBlocker = z.enum([
  'active', 'last_visible', 'stale', 'holdings', 'pending',
]);
const accountAddState = z.discriminatedUnion('kind', [
  z.object({
    kind: z.literal('available'),
    nextAccount: z.number().int().min(0).max(MAX_ACCOUNT_INDEX),
    trailingEmptyAccounts: z.number().int().min(0).max(ACCOUNT_GAP_LIMIT - 1),
    limit: z.literal(ACCOUNT_GAP_LIMIT),
    requiresAcknowledgement: z.boolean(),
  }).strict(),
  z.object({
    kind: z.literal('empty_limit'),
    firstEmptyAccount: z.number().int().min(0).max(MAX_ACCOUNT_INDEX),
    lastEmptyAccount: z.number().int().min(0).max(MAX_ACCOUNT_INDEX),
    limit: z.literal(ACCOUNT_GAP_LIMIT),
  }).strict(),
  z.object({
    kind: z.literal('index_exhausted'),
    limit: z.literal(ACCOUNT_GAP_LIMIT),
  }).strict(),
]);
const accountListResult = z.object({
  accounts: z.array(z.object({
    accountId: publicAccountId,
    account: z.number().int().min(0).max(MAX_ACCOUNT_INDEX),
    name: z.string().min(1).max(80),
    signingSource: z.enum(['software', 'none']),
    active: z.boolean(),
    hidden: z.boolean(),
    hasHistory: z.boolean(),
    canHide: z.boolean(),
    hideBlocker: accountVisibilityBlocker.nullable(),
  }).strict()).min(1),
  accountAddState: accountAddState.nullable(),
}).strict();
const accountVisibilityResult = z.object({
  accountId: publicAccountId,
  account: z.number().int().min(0).max(MAX_ACCOUNT_INDEX),
  hidden: z.boolean(),
}).strict();
const connectedSitesResult = z.object({ sites: z.array(z.object({
  resourceId: z.string().regex(/^[0-9a-f]{32}$/),
  origin: z.string().url(), network: z.enum(['mainnet', 'signet', 'regtest']),
  accountId: publicAccountId, account: z.number().int().min(0).max(MAX_ACCOUNT_INDEX),
  categories: z.array(z.enum(['account_identity', 'addresses', 'balance', 'inscriptions', 'network'])),
}).strict()) }).strict();
const connectedSiteRevokeResult = z.object({ revoked: z.boolean() }).strict();

// The single sanctioned secret-bearing response (see module header).
const revealMnemonicResult = z.object({ mnemonic: z.string().min(1) }).strict();
const verifyBackupResult = z.object({ verified: z.boolean() }).strict();
const verifyFullRecoveryResult = z.object({ verified: z.boolean() }).strict();
const backupStatusResult = z.object({
  backupVerified: z.boolean(),
  metadata: backupMetadataSchema.optional(),
}).strict();
const receiveAddressResult = z
  .object({
    accountId: publicAccountId,
    address: z.string().min(1),
    path: z.string().min(1),
    kind: z.enum(['payment', 'ordinals']),
    network: z.enum(['mainnet', 'signet', 'regtest']),
  })
  .strict();
const paymentInstructionResolveResult = z.object({
  address: z.string().min(1).max(BIP321_LIMITS.addressBytes),
  amountSats: z.string().regex(/^(0|[1-9][0-9]*)$/u).nullable(),
  label: z.string().max(BIP321_LIMITS.labelBytes).nullable(),
  message: z.string().max(BIP321_LIMITS.messageBytes).nullable(),
}).strict();
const messageSignResult = z.object({
  protocol: z.literal('BIP-322'),
  address: z.string().min(1).max(128),
  signature: z.string().min(1).max(4096),
  messageHashHex: z.string().regex(/^[0-9a-f]{64}$/u),
}).strict();
const configResult = z
  .object({
    idleTimeoutMs: z.number().int().positive(),
    highSecurityMode: z.boolean(),
    advancedPsbtSigning: z.boolean().default(false),
  })
  .strict();
const accountCapabilitiesResult = z.object({
  signMethod: z.enum(['software', 'ledger', 'external', 'none']),
  canView: z.boolean().default(false),
  canDeriveAddresses: z.boolean().default(false),
  canPlanTransactions: z.boolean().default(false),
  canSignTransactions: z.boolean().default(false),
  canSignMessages: z.boolean().default(false),
  canBroadcast: z.boolean().default(false),
  canExposeToProviders: z.boolean().default(false),
  canUseMarketplaces: z.boolean().default(false),
  canBuildUnsignedPsbt: z.boolean(),
  canSignPsbt: z.boolean(),
  canSignBip322: z.boolean(),
  canRevealSeed: z.boolean(),
  canExportPublicAccount: z.boolean(),
  canVerifyAddress: z.boolean(),
}).strict();
const sessionSnapshotResult = z
  .object({
    vaults: z.array(vaultSummary),
    quarantinedVaultCount: z.number().int().nonnegative(),
    locked: z.boolean(),
    activeVaultId: z.string().nullable(),
    sessionId: z.string().uuid().nullable(),
    deadline: z.number().int().positive().nullable(),
    highSecurityMode: z.boolean(),
    activeAccountId: publicAccountId.nullable().default(null),
    activeAccount: z.number().int().min(0).max(MAX_ACCOUNT_INDEX).default(0),
    selectableAccounts: z
      .array(z.number().int().min(0).max(MAX_ACCOUNT_INDEX))
      .min(1)
      .default([0]),
    accountSummaries: z.array(z.object({
      accountId: publicAccountId,
      account: z.number().int().min(0).max(MAX_ACCOUNT_INDEX),
      name: z.string().min(1).max(80),
      signingSource: z.enum(['software', 'none']),
    }).strict()).default([]),
    accountAddState: accountAddState.nullable().default(null),
    activeRecoveredAddressCount: z.number().int().nonnegative().default(0),
    backupVerified: z.boolean(),
    backupMetadata: backupMetadataSchema.optional(),
    capabilities: accountCapabilitiesResult,
  })
  .strict();

// M6 result schemas. Sats travel as decimal strings over RPC (chrome
// messaging is JSON; bigint does not serialize) — parsed with domain/sats.
const decimalSats = z.string().regex(/^(0|[1-9][0-9]*)$/);
const signedDecimalSats = z.string().regex(/^(0|-?[1-9][0-9]*)$/);

const scanIdResult = z.object({ scanId: z.string().min(1) }).strict();
const scanUnitView = z
  .object({
    source: z.enum(['standard', 'descriptor', 'xverse']),
    accountId: z.string().regex(/^acct_(?:mainnet|signet|regtest)_[0-9a-f]{64}$/u).nullable(),
    account: z.number().int().nonnegative(),
    lane: z.enum(['payment', 'ordinals']),
  })
  .strict();
const scanStatusResult = z
  .object({
    kind: z.enum([
      'idle',
      'running',
      'awaiting_extend',
      'completed',
      'cancelled',
      'failed',
      'interrupted',
    ]),
    scanId: z.string().nullable(),
    unitsDone: z.number().int().nonnegative(),
    unitsTotal: z.number().int().nonnegative(),
    currentUnit: scanUnitView.nullable(),
    boundaryUnits: z.array(scanUnitView),
    failureReason: z.string().nullable(),
    historyPartial: z.boolean(),
  })
  .strict();
const scanCancelResult = z.object({ cancelled: z.boolean() }).strict();
const scanExtendResult = z.object({ resumed: z.boolean() }).strict();
const utxoSetFrozenResult = z.object({ updated: z.boolean() }).strict();
const utxoSetLabelResult = z.object({ updated: z.boolean() }).strict();

export const ACTIVITY_PAGE_SIZE = 25;

export const walletActivityItemSchema = z
  .object({
    txid: hexId,
    deltaSats: signedDecimalSats,
    feeSats: decimalSats.nullable(),
    confirmationState: z.enum([
      'confirmed', 'mempool', 'replaced', 'conflicted', 'indeterminate', 'rejected',
    ]),
    pendingAsset: z.literal('ordinal').nullable().optional(),
    actionKind: z.enum([
      'ordinal_receive', 'ordinal_transfer', 'ordinal_batch_transfer', 'rescue', 'ordinal_sweep',
      'ordinal_postage_manage',
    ]).nullable().optional(),
    addressContext: z.enum([
      'ordinals_received', 'ordinals_sent',
    ]).nullable().optional(),
    addressDisplay: z.object({
      kind: z.enum(['sent_to', 'received_at']),
      address: z.string().min(1),
    }).strict().nullable().optional(),
    transactionSource: z.object({
      inputCount: z.number().int().nonnegative().max(100_000),
      singleInputAddress: z.string().min(1).max(128).nullable(),
    }).strict().nullable().optional(),
    bitcoinActionKind: z.literal('self_transfer').nullable().optional(),
    inscriptionId: inscriptionId.nullable().optional(),
    inscriptionIds: z.array(inscriptionId).min(1).max(64).optional(),
    inscriptionNumber: z.number().int().nullable().optional(),
    inscriptionCount: z.number().int().positive().optional(),
    receivedInscriptionCount: z.number().int().positive().optional(),
    ordinalValueSats: decimalSats.nullable().optional(),
    detectedAssets: z.array(detectedAssetSchema).max(16).optional(),
    detectedAssetCount: z.number().int().nonnegative().optional(),
    assetIdentityComplete: z.boolean().optional(),
    returnedBtcSats: decimalSats.nullable().optional(),
    timestamp: z.string().nullable(),
    height: z.number().int().nonnegative().nullable(),
  })
  .strict()
  .superRefine((item, context) => {
    if (item.inscriptionIds !== undefined &&
        (new Set(item.inscriptionIds).size !== item.inscriptionIds.length ||
          item.inscriptionCount !== item.inscriptionIds.length ||
          (item.inscriptionId != null && item.inscriptionId !== item.inscriptionIds[0]))) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['inscriptionIds'],
        message: 'ordered inscription ids differ from activity summary',
      });
    }
  });

const activityPageCursor = z.object({
  version: z.literal(1),
  revision: hexId,
  offset: z.number().int().positive().multipleOf(ACTIVITY_PAGE_SIZE),
}).strict();

const activityListRequest = accountSessionRequest.extend({
  cursor: activityPageCursor.nullable().optional(),
}).strict();

const activityListResult = z.object({
  accountId: publicAccountId,
  items: z.array(walletActivityItemSchema).max(ACTIVITY_PAGE_SIZE),
  nextCursor: activityPageCursor.nullable(),
  reset: z.boolean(),
  historyComplete: z.boolean(),
}).strict();

const walletHomeResult = z
  .object({
    accountId: publicAccountId,
    balances: z
      .object({
        availableSats: decimalSats,
        protectedSats: decimalSats,
        reservedSats: decimalSats,
        pendingSats: decimalSats,
        pendingOrdinalSats: decimalSats.optional(),
        frozenSats: decimalSats,
        unavailableCleanSats: decimalSats,
      })
      .strict(),
    protectionBreakdown: z
      .object({
        assetSats: decimalSats,
        awaitingClassificationSats: decimalSats,
        userFrozenSats: decimalSats,
        dustQuarantinedSats: decimalSats,
      })
      .strict(),
    collectiblesCount: z.number().int().nonnegative(),
    pendingOrdinalCount: z.number().int().nonnegative().optional(),
    wrongLaneCount: z.number().int().nonnegative(),
    dataGating: z
      .object({
        state: z.enum([
          'fresh',
          'backend_unreachable',
          'backend_read_only',
          'index_lag',
          'reorg_reconciliation',
          'conflicting_sources',
        ]),
        blockedActions: z.array(z.string()),
      })
      .strict(),
    activity: z.array(walletActivityItemSchema),
    historyComplete: z.boolean(),
    wrongLane: z.array(
      z
        .object({
          txid: hexId,
          vout: voutSchema,
          valueSats: decimalSats,
          accountId: publicAccountId,
          account: z.number().int().nonnegative(),
          lane: z.enum(['payment', 'ordinals']),
        })
        .strict(),
    ),
    lastSyncedAt: z.number().int().nonnegative().nullable(),
    scan: scanStatusResult,
  })
  .strict();

/**
 * Locally synthesized when a signed raster batch fails outright — typically the
 * gateway shedding load with a 503. Distinct from `not_requested` so the
 * surface does not treat it as a lazy-load cue and retry into an already
 * overloaded gateway; recovery is an explicit Refresh.
 */
export const GALLERY_PREVIEW_UNAVAILABLE = 'preview_service_unavailable';

const galleryPreview = z.discriminatedUnion('kind', [
  z.object({
    kind: z.literal('raster'),
    rasterBase64: z.string().min(1).max(Math.ceil((1024 * 1024) / 3) * 4),
    pngSha256: hexId,
    pngWidth: z.number().int().min(1).max(512),
    pngHeight: z.number().int().min(1).max(512),
  }).strict(),
  z.object({ kind: z.literal('placeholder'), reason: z.string().min(1) }).strict(),
  z.object({
    kind: z.literal('text'),
    textMime: z.enum(['text/plain', 'application/json']),
    excerpt: z.string().min(1).max(4096),
    truncated: z.boolean(),
  }).strict(),
  z.object({
    kind: z.literal('mediaBadge'),
    mediaKind: z.enum(['audio', 'video']),
    contentLength: z.number().int().nonnegative(),
  }).strict(),
]);
const activityInscriptionPreviewResult = z.object({
  inscriptionId,
  preview: galleryPreview,
}).strict();
const activityInscriptionPreviewBatchResult = z.object({
  items: z.array(activityInscriptionPreviewResult).min(1).max(8),
}).strict();
const galleryAction = z.discriminatedUnion('status', [
  z.object({
    status: z.literal('available'),
    kind: z.enum(['send', 'rescue']),
  }).strict(),
  z.object({
    status: z.literal('blocked'),
    kind: z.enum(['send', 'rescue']),
    reason: z.enum([
      'stale_classification',
      'unconfirmed',
      'frozen',
      'unsupported_assets',
      'rare_sats',
      'locked_by_plan',
      'co_located',
      'unverifiable_location',
      'unsafe_lane',
    ]),
  }).strict(),
]);
const galleryOwnership = z.object({
  address: z.string().min(1).max(128),
  lane: z.enum(['payment', 'ordinals']),
  role: z.enum(['primary', 'recovered', 'change']),
}).strict();
const galleryItem = z.object({
  inscriptionId,
  state: z.enum(['visible', 'hidden']),
  number: z.number().int().nullable(),
  contentType: z.string().min(1).max(256).nullable(),
  contentLength: z.number().int().nonnegative().nullable(),
  satpoint: z.string().min(1).max(512),
  outpoint: z.object({ txid: hexId, vout: voutSchema }).strict(),
  confirmations: z.number().int().nonnegative(),
  parent: inscriptionId.nullable(),
  delegate: inscriptionId.nullable(),
  reinscription: z.boolean(),
  cursed: z.boolean(),
  classificationRevision: z.string().min(1).max(256),
  rareSats: z.array(z.string().min(1).max(64)).max(64),
  display: inscriptionDisplayMetadataSchema.default({ title: null, collections: [] }),
  /** Worker-authoritative gallery responses always identify current ownership. */
  ownership: galleryOwnership,
  preview: galleryPreview,
  mediaAvailable: z.boolean(),
  action: galleryAction.default({
    status: 'blocked', kind: 'send', reason: 'stale_classification',
  }),
}).strict();
const galleryListResult = z.object({
  accountId: publicAccountId,
  items: z.array(galleryItem).max(4096),
  collectionCatalog: z.object({
    source: z.literal('TheWizardsOfOrd/ordinals-collections'),
    revision: z.string().regex(/^[0-9a-f]{40}$/),
    sha256: hexId,
    galleryIndexStatus: z.enum(['ready', 'unavailable']),
  }).strict().nullable().default(null),
  attentionItems: z.array(z.object({
    inscriptionId,
    outpoint: z.object({ txid: hexId, vout: voutSchema }).strict(),
    action: galleryAction,
  }).strict()).max(4096).default([]),
  sweepCandidates: z.array(z.object({
    accountId: publicAccountId,
    account: z.number().int().nonnegative(),
    outpoint: z.object({ txid: hexId, vout: voutSchema }).strict(),
    valueSats: decimalSats,
    status: z.enum(['available', 'blocked']),
    reason: z.enum([
      'stale_classification',
      'unconfirmed',
      'frozen',
      'locked_by_plan',
      'no_economic_excess',
    ]).nullable(),
  }).strict()).max(4096).default([]),
  /**
   * At least one signed raster batch could not be fetched, so some items carry
   * a locally synthesized GALLERY_PREVIEW_UNAVAILABLE placeholder. Cosmetic
   * only: identity, confirmations, and `action` are derived from local
   * authoritative UTXO facts in every path, so a missing preview never changes
   * what gates Send or Rescue.
   */
  previewsUnavailable: z.boolean().default(false),
  recoveredAddressCount: z.number().int().nonnegative().default(0),
  refreshedAt: z.number().int().nonnegative(),
}).strict();
/**
 * Paint-only projection of a gallery item, held in memory-backed session
 * storage so a cold popup can paint before its signed batch lands.
 *
 * Deliberately NOT `galleryItem`: there is no `action` and no `mediaAvailable`,
 * so a cached record is structurally incapable of carrying the authority that
 * gates Send, Rescue, or the media viewer. `preview` is raster-only and
 * optional — a placeholder is never cached, on any surface, and an absent
 * preview hydrates to the same local `not_requested` marker that lazy loading
 * already produces.
 */
const galleryCachedItem = z.object({
  inscriptionId,
  state: z.enum(['visible', 'hidden']),
  number: z.number().int().nullable(),
  contentType: z.string().min(1).max(256).nullable(),
  contentLength: z.number().int().nonnegative().nullable(),
  satpoint: z.string().min(1).max(512),
  outpoint: z.object({ txid: hexId, vout: voutSchema }).strict(),
  confirmations: z.number().int().nonnegative(),
  parent: inscriptionId.nullable(),
  delegate: inscriptionId.nullable(),
  reinscription: z.boolean(),
  cursed: z.boolean(),
  classificationRevision: z.string().min(1).max(256),
  rareSats: z.array(z.string().min(1).max(64)).max(64),
  display: inscriptionDisplayMetadataSchema,
  preview: z.discriminatedUnion('kind', [
    z.object({
      kind: z.literal('raster'),
      rasterBase64: z.string().min(1).max(Math.ceil((1024 * 1024) / 3) * 4),
      pngSha256: hexId,
      pngWidth: z.number().int().min(1).max(512),
      pngHeight: z.number().int().min(1).max(512),
    }).strict(),
    z.object({
      kind: z.literal('text'),
      textMime: z.enum(['text/plain', 'application/json']),
      excerpt: z.string().min(1).max(4096),
      truncated: z.boolean(),
    }).strict(),
    z.object({
      kind: z.literal('mediaBadge'),
      mediaKind: z.enum(['audio', 'video']),
      contentLength: z.number().int().nonnegative(),
    }).strict(),
  ]).optional(),
}).strict();
const galleryCachedResult = z.discriminatedUnion('hit', [
  z.object({ hit: z.literal(false), accountId: publicAccountId }).strict(),
  z.object({
    hit: z.literal(true),
    accountId: publicAccountId,
    items: z.array(galleryCachedItem).max(4096),
    cachedAt: z.number().int().nonnegative(),
  }).strict(),
]);
const galleryUpdateResult = z.object({ updated: z.literal(true) }).strict();
const galleryMediaOpenResult = z.discriminatedUnion('disposition', [
  z.object({
    disposition: z.literal('media'),
    leaseId: z.string().regex(/^[0-9a-f]{32}$/),
    expiresAt: z.number().int().positive(),
    inscriptionId,
    contentType: z.enum([
      'image/jpeg', 'image/png', 'image/webp', 'image/gif',
      'audio/mpeg', 'audio/ogg', 'audio/wav',
      'video/mp4', 'video/webm', 'text/plain', 'application/json',
    ]),
    contentSha256: hexId,
    contentByteLength: z.number().int().positive().max(2 * 1024 * 1024),
    bytesBase64: z.string().min(1).max(Math.ceil((2 * 1024 * 1024) / 3) * 4),
  }).strict(),
  z.object({
    disposition: z.literal('unavailable'),
    reason: z.string().min(1),
    inscriptionId,
  }).strict(),
]);
const galleryMediaLeaseResult = z.object({
  valid: z.boolean(),
  expiresAt: z.number().int().positive().nullable(),
}).strict();

// ---- registry --------------------------------------------------------------

export interface OpSpec {
  request: z.ZodTypeAny;
  response: z.ZodTypeAny;
  allowedSenders: readonly SenderContext[];
  requiresUnlock: boolean;
  /**
   * The handler performs its own session check, so the dispatcher must skip the
   * shared locked-privacy preflight. That preflight runs through the service's
   * exclusive queue, which would serialize the op behind whatever long
   * operation currently holds it — unacceptable only for an op whose entire
   * purpose is to answer before that operation finishes.
   *
   * Set this only where the handler starts with `requireSession`, which applies
   * the same idle-expiry and live-session gate and additionally binds the
   * caller's expected vault and session.
   */
  handlerEnforcesUnlock?: true;
}

export const OP_SCHEMAS = {
  'vault.create': {
    request: vaultCreateRequest,
    response: vaultIdResult,
    allowedSenders: TRUSTED_SENDERS,
    requiresUnlock: false,
  },
  'vault.restore': {
    request: vaultRestoreRequest,
    response: vaultIdResult,
    allowedSenders: TRUSTED_SENDERS,
    requiresUnlock: false,
  },
  'vault.unlock': {
    request: vaultUnlockRequest,
    response: unlockResult,
    allowedSenders: TRUSTED_SENDERS,
    requiresUnlock: false,
  },
  'vault.lock': {
    request: emptyRequest,
    response: lockResult,
    allowedSenders: TRUSTED_SENDERS,
    requiresUnlock: false,
  },
  'vault.list': {
    request: emptyRequest,
    response: listResult,
    allowedSenders: TRUSTED_SENDERS,
    requiresUnlock: false,
  },
  'vault.switch': {
    request: vaultUnlockRequest,
    response: unlockResult,
    allowedSenders: TRUSTED_SENDERS,
    requiresUnlock: false,
  },
  'vault.remove': {
    request: vaultRemoveRequest,
    response: z.object({ removed: z.boolean() }).strict(),
    allowedSenders: TRUSTED_SENDERS,
    requiresUnlock: true,
    handlerEnforcesUnlock: true,
  },
  'vault.changePassword': {
    request: vaultChangePasswordRequest,
    response: changePasswordResult,
    allowedSenders: TRUSTED_SENDERS,
    requiresUnlock: false,
  },
  'session.status': {
    request: emptyRequest,
    response: sessionStatusResult,
    allowedSenders: TRUSTED_SENDERS,
    requiresUnlock: false,
  },
  'session.snapshot': {
    request: emptyRequest,
    response: sessionSnapshotResult,
    allowedSenders: TRUSTED_SENDERS,
    requiresUnlock: false,
  },
  // M4 ops below are the first requiresUnlock:true users of the §7.5
  // locked-privacy gate: none of them may answer while locked.
  'vault.revealMnemonic': {
    request: vaultRevealMnemonicRequest,
    response: revealMnemonicResult,
    allowedSenders: TRUSTED_SENDERS,
    requiresUnlock: true,
  },
  'vault.verifyBackup': {
    request: vaultVerifyBackupRequest,
    response: verifyBackupResult,
    allowedSenders: TRUSTED_SENDERS,
    requiresUnlock: true,
  },
  'vault.verifyFullRecovery': {
    request: vaultVerifyFullRecoveryRequest,
    response: verifyFullRecoveryResult,
    allowedSenders: TRUSTED_SENDERS,
    requiresUnlock: true,
  },
  'backup.status': {
    request: activeSessionRequest,
    response: backupStatusResult,
    allowedSenders: TRUSTED_SENDERS,
    requiresUnlock: true,
  },
  'address.receive': {
    request: addressReceiveRequest,
    response: receiveAddressResult,
    allowedSenders: TRUSTED_SENDERS,
    requiresUnlock: true,
  },
  'paymentInstruction.resolve': {
    request: paymentInstructionResolveRequest,
    response: paymentInstructionResolveResult,
    allowedSenders: TRUSTED_SENDERS,
    requiresUnlock: true,
    handlerEnforcesUnlock: true,
  },
  'message.sign': {
    request: messageSignRequest,
    response: messageSignResult,
    allowedSenders: TRUSTED_SENDERS,
    requiresUnlock: true,
    handlerEnforcesUnlock: true,
  },
  'addressBook.list': {
    request: activeSessionRequest,
    response: addressBookSchema,
    allowedSenders: TRUSTED_SENDERS,
    requiresUnlock: true,
    handlerEnforcesUnlock: true,
  },
  'addressBook.add': {
    request: addressBookAddRequest,
    response: addressBookSchema,
    allowedSenders: TRUSTED_SENDERS,
    requiresUnlock: true,
    handlerEnforcesUnlock: true,
  },
  'addressBook.rename': {
    request: addressBookRenameRequest,
    response: addressBookSchema,
    allowedSenders: TRUSTED_SENDERS,
    requiresUnlock: true,
    handlerEnforcesUnlock: true,
  },
  'addressBook.remove': {
    request: addressBookRemoveRequest,
    response: addressBookSchema,
    allowedSenders: TRUSTED_SENDERS,
    requiresUnlock: true,
    handlerEnforcesUnlock: true,
  },
  'addressBook.import': {
    request: addressBookImportRequest,
    response: addressBookImportResult,
    allowedSenders: TRUSTED_SENDERS,
    requiresUnlock: true,
    handlerEnforcesUnlock: true,
  },
  'addressBook.dismissRecent': {
    request: addressBookDismissRecentRequest,
    response: addressBookSchema,
    allowedSenders: TRUSTED_SENDERS,
    requiresUnlock: true,
    handlerEnforcesUnlock: true,
  },
  'addressBook.clearRecent': {
    request: activeSessionRequest,
    response: addressBookSchema,
    allowedSenders: TRUSTED_SENDERS,
    requiresUnlock: true,
    handlerEnforcesUnlock: true,
  },
  'config.get': {
    request: emptyRequest,
    response: configResult,
    allowedSenders: TRUSTED_SENDERS,
    requiresUnlock: false,
  },
  'config.set': {
    request: configSetRequest,
    response: configResult,
    allowedSenders: TRUSTED_SENDERS,
    requiresUnlock: true,
  },
  'account.active.get': {
    request: activeSessionRequest,
    response: activeAccountResult,
    allowedSenders: TRUSTED_SENDERS,
    requiresUnlock: true,
  },
  'account.active.set': {
    request: activeAccountSetRequest,
    response: activeAccountResult,
    allowedSenders: TRUSTED_SENDERS,
    requiresUnlock: true,
  },
  'account.add': {
    request: accountAddRequest,
    response: activeAccountResult,
    allowedSenders: TRUSTED_SENDERS,
    requiresUnlock: true,
  },
  'account.list': {
    request: activeSessionRequest,
    response: accountListResult,
    allowedSenders: TRUSTED_SENDERS,
    requiresUnlock: true,
  },
  'account.visibility.set': {
    request: accountVisibilitySetRequest,
    response: accountVisibilityResult,
    allowedSenders: TRUSTED_SENDERS,
    requiresUnlock: true,
  },
  'account.watch.import': {
    request: publicAccountImportRequest,
    response: activeAccountResult,
    allowedSenders: TRUSTED_SENDERS,
    requiresUnlock: true,
  },
  'account.public.export': {
    request: publicAccountExportRequest,
    response: publicAccountExportResult,
    allowedSenders: TRUSTED_SENDERS,
    requiresUnlock: true,
  },
  'account.remove': {
    request: publicAccountRemoveRequest,
    response: publicAccountRemoveResult,
    allowedSenders: TRUSTED_SENDERS,
    requiresUnlock: true,
  },
  'provider.sites.list': {
    request: activeSessionRequest,
    response: connectedSitesResult,
    allowedSenders: TRUSTED_SENDERS,
    requiresUnlock: true,
  },
  'provider.sites.revoke': {
    request: connectedSiteRevokeRequest,
    response: connectedSiteRevokeResult,
    allowedSenders: TRUSTED_SENDERS,
    requiresUnlock: true,
  },
  // §7.5: security-rule checks continue while locked. The status view carries
  // zero wallet data (no addresses, balances, or activity), and the unlock
  // screen legitimately shows gateway reachability — so no unlock gate and no
  // session binding.
  'gateway.status': {
    request: gatewayStatusRequest,
    response: gatewayStatusViewSchema,
    allowedSenders: TRUSTED_SENDERS,
    requiresUnlock: false,
  },
  // A fiat quote contains no wallet data and may be obtained while locked.
  // The popup requests it only on mainnet while rendering an unlocked balance.
  'price.quote': {
    request: emptyRequest,
    response: fiatPriceQuoteSchema.nullable(),
    allowedSenders: TRUSTED_SENDERS,
    requiresUnlock: false,
  },
  // M6 ops: every one exposes wallet data (balances, UTXOs, scan topology) or
  // mutates wallet state — all behind the §7.5 unlock gate + session binding.
  'wallet.home': {
    request: accountSessionRequest,
    response: walletHomeResult,
    allowedSenders: TRUSTED_SENDERS,
    requiresUnlock: true,
  },
  'activity.list': {
    request: activityListRequest,
    response: activityListResult,
    allowedSenders: ['popup', 'sidepanel', 'fullpage'],
    requiresUnlock: true,
  },
  'activity.inscriptionPreview': {
    request: activityInscriptionPreviewRequest,
    response: activityInscriptionPreviewResult,
    allowedSenders: ['popup', 'sidepanel', 'fullpage'],
    requiresUnlock: true,
  },
  'activity.inscriptionPreviewBatch': {
    request: activityInscriptionPreviewBatchRequest,
    response: activityInscriptionPreviewBatchResult,
    allowedSenders: ['popup', 'sidepanel', 'fullpage'],
    requiresUnlock: true,
  },
  'gallery.list': {
    request: galleryListRequest,
    response: galleryListResult,
    allowedSenders: TRUSTED_SENDERS,
    requiresUnlock: true,
  },
  /** Paint-ahead read of the session preview cache for persistent wallet UIs. */
  'gallery.cached': {
    request: galleryCachedRequest,
    response: galleryCachedResult,
    allowedSenders: ['popup', 'sidepanel', 'fullpage'],
    requiresUnlock: true,
    handlerEnforcesUnlock: true,
  },
  'gallery.update': {
    request: galleryUpdateRequest,
    response: galleryUpdateResult,
    allowedSenders: TRUSTED_SENDERS,
    requiresUnlock: true,
  },
  'gallery.media.open': {
    request: galleryMediaOpenRequest,
    response: galleryMediaOpenResult,
    allowedSenders: TRUSTED_SENDERS,
    requiresUnlock: true,
  },
  'gallery.media.lease': {
    request: galleryMediaLeaseRequest,
    response: galleryMediaLeaseResult,
    allowedSenders: TRUSTED_SENDERS,
    requiresUnlock: true,
  },
  'scan.start': {
    request: scanStartRequest,
    response: scanIdResult,
    allowedSenders: TRUSTED_SENDERS,
    requiresUnlock: true,
  },
  'scan.status': {
    request: activeSessionRequest,
    response: scanStatusResult,
    allowedSenders: TRUSTED_SENDERS,
    requiresUnlock: true,
  },
  'scan.cancel': {
    request: scanControlRequest,
    response: scanCancelResult,
    allowedSenders: TRUSTED_SENDERS,
    requiresUnlock: true,
  },
  'scan.extend': {
    request: scanControlRequest,
    response: scanExtendResult,
    allowedSenders: TRUSTED_SENDERS,
    requiresUnlock: true,
  },
  'utxo.setFrozen': {
    request: utxoSetFrozenRequest,
    response: utxoSetFrozenResult,
    allowedSenders: TRUSTED_SENDERS,
    requiresUnlock: true,
  },
  'utxo.setLabel': {
    request: utxoSetLabelRequest,
    response: utxoSetLabelResult,
    allowedSenders: TRUSTED_SENDERS,
    requiresUnlock: true,
  },
  'fees.quote': {
    request: feeQuoteRequestSchema,
    response: feeQuoteResultSchema,
    allowedSenders: TRUSTED_SENDERS,
    requiresUnlock: true,
  },
  'utxo.list': {
    request: utxoListRequestSchema,
    response: utxoListResultSchema,
    allowedSenders: TRUSTED_SENDERS,
    requiresUnlock: true,
  },
  'transaction.plan': {
    request: transactionPlanRequestSchema,
    response: transactionPlanResultSchema,
    allowedSenders: TRUSTED_SENDERS,
    requiresUnlock: true,
  },
  'transaction.review': {
    request: transactionReviewRequestSchema,
    response: transactionPlanResultSchema,
    allowedSenders: TRUSTED_SENDERS,
    requiresUnlock: true,
  },
  'transaction.approve': {
    request: transactionApproveRequestSchema,
    response: transactionApproveResultSchema,
    allowedSenders: TRUSTED_SENDERS,
    requiresUnlock: true,
  },
  'transaction.cancel': {
    request: transactionCancelRequestSchema,
    response: transactionCancelResultSchema,
    allowedSenders: TRUSTED_SENDERS,
    requiresUnlock: true,
  },
  'transaction.status': {
    request: transactionStatusRequestSchema,
    response: transactionStatusResultSchema,
    allowedSenders: TRUSTED_SENDERS,
    requiresUnlock: true,
  },
} satisfies Record<string, OpSpec>;

export type Op = keyof typeof OP_SCHEMAS;

export type OpRegistry = Record<string, OpSpec>;

export type RpcResponse = { ok: true; result: unknown } | { ok: false; code: ErrorCode };

// Inferred request types the dispatcher casts validated payloads to.
export type VaultCreateRequest = z.infer<typeof vaultCreateRequest>;
export type VaultRestoreRequest = z.infer<typeof vaultRestoreRequest>;
export type VaultUnlockRequest = z.infer<typeof vaultUnlockRequest>;
export type VaultRemoveRequest = z.infer<typeof vaultRemoveRequest>;
export type VaultChangePasswordRequest = z.infer<typeof vaultChangePasswordRequest>;
export type VaultRevealMnemonicRequest = z.infer<typeof vaultRevealMnemonicRequest>;
export type VaultVerifyBackupRequest = z.infer<typeof vaultVerifyBackupRequest>;
export type ActiveSessionRequest = z.infer<typeof activeSessionRequest>;
export type AddressReceiveRequest = z.infer<typeof addressReceiveRequest>;
export type PaymentInstructionResolveRequest = z.infer<typeof paymentInstructionResolveRequest>;
export type PaymentInstructionResolveResult = z.infer<typeof paymentInstructionResolveResult>;
export type MessageSignRequest = z.infer<typeof messageSignRequest>;
export type MessageSignResult = z.infer<typeof messageSignResult>;
export type AddressBookAddRequest = z.infer<typeof addressBookAddRequest>;
export type AddressBookRenameRequest = z.infer<typeof addressBookRenameRequest>;
export type AddressBookRemoveRequest = z.infer<typeof addressBookRemoveRequest>;
export type AddressBookImportRequest = z.infer<typeof addressBookImportRequest>;
export type AddressBookImportResult = z.infer<typeof addressBookImportResult>;
export type AddressBookDismissRecentRequest = z.infer<typeof addressBookDismissRecentRequest>;
export type ConfigSetRequest = z.infer<typeof configSetRequest>;
export type ActiveAccountSetRequest = z.infer<typeof activeAccountSetRequest>;
export type AccountAddRequest = z.infer<typeof accountAddRequest>;
export type AccountAddState = z.infer<typeof accountAddState>;
export type AccountVisibilitySetRequest = z.infer<typeof accountVisibilitySetRequest>;
export type PublicAccountImportRequest = z.infer<typeof publicAccountImportRequest>;
export type PublicAccountExportRequest = z.infer<typeof publicAccountExportRequest>;
export type PublicAccountRemoveRequest = z.infer<typeof publicAccountRemoveRequest>;
export type AccountListResult = z.infer<typeof accountListResult>;
export type ConnectedSiteRevokeRequest = z.infer<typeof connectedSiteRevokeRequest>;
export type GatewayStatusRequest = z.infer<typeof gatewayStatusRequest>;
export type ScanStartRequest = z.infer<typeof scanStartRequest>;
export type ScanCancelRequest = z.infer<typeof scanControlRequest>;
export type UtxoSetFrozenRequest = z.infer<typeof utxoSetFrozenRequest>;
export type UtxoSetLabelRequest = z.infer<typeof utxoSetLabelRequest>;
export type WalletHomeResult = z.infer<typeof walletHomeResult>;
export type WalletActivityItem = z.infer<typeof walletActivityItemSchema>;
export type ActivityPageCursor = z.infer<typeof activityPageCursor>;
export type ActivityListRequest = z.infer<typeof activityListRequest>;
export type ActivityListResult = z.infer<typeof activityListResult>;
export type ActivityInscriptionPreviewRequest = z.infer<typeof activityInscriptionPreviewRequest>;
export type ActivityInscriptionPreviewResult = z.infer<typeof activityInscriptionPreviewResult>;
export type ActivityInscriptionPreviewBatchRequest =
  z.infer<typeof activityInscriptionPreviewBatchRequest>;
export type ActivityInscriptionPreviewBatchResult =
  z.infer<typeof activityInscriptionPreviewBatchResult>;
export type GalleryListRequest = z.infer<typeof galleryListRequest>;
export type GalleryCachedRequest = z.infer<typeof galleryCachedRequest>;
export type GalleryCachedItem = z.infer<typeof galleryCachedItem>;
export const galleryCachedItemSchema = galleryCachedItem;
export type GalleryUpdateRequest = z.infer<typeof galleryUpdateRequest>;
export type GalleryMediaOpenRequest = z.infer<typeof galleryMediaOpenRequest>;
export type GalleryMediaLeaseRequest = z.infer<typeof galleryMediaLeaseRequest>;
export type GalleryListResult = z.infer<typeof galleryListResult>;
export type GalleryOwnership = z.infer<typeof galleryOwnership>;
export type GalleryCachedResult = z.infer<typeof galleryCachedResult>;
export type {
  FeeQuoteRequest,
  TransactionApproveRequest,
  TransactionPlanRequest,
  TransactionPlanResult,
  TransactionReviewRequest,
  UtxoListRequest,
} from './transaction-schemas';
