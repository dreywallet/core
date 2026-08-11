/**
 * Encrypted, append-only provider permission journal (spec §20.3-§20.4).
 *
 * Every grant/revoke is encrypted with the active vault DEK. A write is staged,
 * validated, then committed; startup promotes a valid one-event extension left
 * in staging by an MV3 termination. Revoke tombstones are replayed after every
 * restart, so a stale grant cannot be revived.
 */
import { z } from 'zod';
import { MAX_ACCOUNT_INDEX } from '../accounts/limits';
import { aeadDecrypt, aeadEncrypt, KEY_BYTES, NONCE_BYTES } from '../vault/crypto';
import { bytesToUtf8, utf8ToBytes } from '../vault/encoding';
import { getCryptoProvider } from '../vault/crypto-provider';
import { normalizeProviderOrigin } from './origin';

export interface PermissionStorageArea {
  get(keys: string | string[]): Promise<Record<string, unknown>>;
  set(items: Record<string, unknown>): Promise<void>;
  remove(keys: string | string[]): Promise<void>;
}

export const permissionDataCategorySchema = z.enum([
  'account_identity',
  'addresses',
  'balance',
  'inscriptions',
  'network',
]);
export type PermissionDataCategory = z.infer<typeof permissionDataCategorySchema>;

const opaqueIdSchema = z.string().regex(/^[0-9a-f]{32}$/u, '128-bit opaque id');
const categoriesSchema = z
  .array(permissionDataCategorySchema)
  .min(1)
  .max(permissionDataCategorySchema.options.length)
  .superRefine((categories, context) => {
    const canonical = [...new Set(categories)].sort();
    if (canonical.length !== categories.length || canonical.some((value, i) => value !== categories[i])) {
      context.addIssue({ code: z.ZodIssueCode.custom, message: 'categories must be unique and sorted' });
    }
  });

export const permissionScopeSchema = z
  .object({
    origin: z.string().min(1),
    network: z.enum(['mainnet', 'signet']),
    vaultId: z.string().min(1),
    account: z.number().int().min(0).max(MAX_ACCOUNT_INDEX),
    categories: categoriesSchema,
  })
  .strict()
  .superRefine((scope, context) => {
    try {
      if (normalizeProviderOrigin(scope.origin).asciiOrigin !== scope.origin) {
        context.addIssue({ code: z.ZodIssueCode.custom, message: 'origin must be canonical' });
      }
    } catch {
      context.addIssue({ code: z.ZodIssueCode.custom, message: 'invalid origin' });
    }
  });
export type PermissionScope = z.infer<typeof permissionScopeSchema>;

const grantEventSchema = z
  .object({
    version: z.literal(1),
    kind: z.literal('grant'),
    eventId: opaqueIdSchema,
    resourceId: opaqueIdSchema,
    occurredAtMs: z.number().int().nonnegative(),
    scope: permissionScopeSchema,
  })
  .strict();

const revokeEventSchema = z
  .object({
    version: z.literal(1),
    kind: z.literal('revoke'),
    eventId: opaqueIdSchema,
    targetResourceId: opaqueIdSchema,
    occurredAtMs: z.number().int().nonnegative(),
    reason: z.enum(['disconnect', 'user_revoked', 'vault_removed', 'reset']),
  })
  .strict();

const revokeScopeEventSchema = z
  .object({
    version: z.literal(1),
    kind: z.literal('revoke_scope'),
    eventId: opaqueIdSchema,
    occurredAtMs: z.number().int().nonnegative(),
    origin: z.string().min(1),
    network: z.enum(['mainnet', 'signet']),
    vaultId: z.string().min(1),
    account: z.number().int().min(0).max(MAX_ACCOUNT_INDEX).nullable(),
    reason: z.enum(['disconnect', 'user_revoked', 'vault_removed', 'reset']),
  })
  .strict();

export const permissionJournalEventSchema = z.discriminatedUnion('kind', [
  grantEventSchema,
  revokeEventSchema,
  revokeScopeEventSchema,
]).superRefine((event, context) => {
  if (event.kind !== 'revoke_scope') return;
  try {
    if (normalizeProviderOrigin(event.origin).asciiOrigin !== event.origin) {
      context.addIssue({ code: z.ZodIssueCode.custom, message: 'origin must be canonical' });
    }
  } catch {
    context.addIssue({ code: z.ZodIssueCode.custom, message: 'invalid origin' });
  }
});
export type PermissionJournalEvent = z.infer<typeof permissionJournalEventSchema>;
export type PermissionGrantEvent = z.infer<typeof grantEventSchema>;
export type PermissionRevokeEvent = z.infer<typeof revokeEventSchema>;
export type PermissionRevokeScopeEvent = z.infer<typeof revokeScopeEventSchema>;

const encryptedEventSchema = z
  .object({
    sequence: z.number().int().positive(),
    eventId: opaqueIdSchema,
    nonceB64: z.string().min(1),
    ciphertextB64: z.string().min(1),
  })
  .strict();

export const MAX_PERMISSION_JOURNAL_EVENTS = 4096;

export const permissionJournalRecordSchema = z
  .object({
    schemaVersion: z.literal(1),
    vaultId: z.string().min(1),
    revision: z.number().int().nonnegative(),
    entries: z.array(encryptedEventSchema).max(MAX_PERMISSION_JOURNAL_EVENTS),
  })
  .strict();
export type PermissionJournalRecord = z.infer<typeof permissionJournalRecordSchema>;

export interface PermissionProjection {
  grants: readonly PermissionGrantEvent[];
  revokedResourceIds: ReadonlySet<string>;
}

export interface PermissionJournalLoadResult {
  status: 'ok' | 'recovered' | 'corrupt';
  revision: number;
  events: readonly PermissionJournalEvent[];
  projection: PermissionProjection;
}

export class PermissionJournalError extends Error {
  constructor(
    readonly code: 'corrupt' | 'stale_revision' | 'journal_full' | 'invalid_event',
    message: string,
  ) {
    super(message);
    this.name = 'PermissionJournalError';
  }
}

function eventAad(vaultId: string, sequence: number, eventId: string): string {
  return `drey-provider-permission:v1:${vaultId}:${sequence}:${eventId}`;
}

function assertDek(dek: Uint8Array): void {
  if (dek.length !== KEY_BYTES) throw new PermissionJournalError('corrupt', 'invalid vault DEK');
}

function entryEqual(
  left: PermissionJournalRecord['entries'][number],
  right: PermissionJournalRecord['entries'][number],
): boolean {
  return (
    left.sequence === right.sequence &&
    left.eventId === right.eventId &&
    left.nonceB64 === right.nonceB64 &&
    left.ciphertextB64 === right.ciphertextB64
  );
}

function journalEqual(left: PermissionJournalRecord, right: PermissionJournalRecord): boolean {
  return (
    left.schemaVersion === right.schemaVersion &&
    left.vaultId === right.vaultId &&
    left.revision === right.revision &&
    left.entries.length === right.entries.length &&
    left.entries.every((entry, index) => entryEqual(entry, right.entries[index]!))
  );
}

function extendsByOne(base: PermissionJournalRecord, candidate: PermissionJournalRecord): boolean {
  return (
    candidate.vaultId === base.vaultId &&
    candidate.revision === base.revision + 1 &&
    candidate.entries.length === base.entries.length + 1 &&
    base.entries.every((entry, index) => entryEqual(entry, candidate.entries[index]!))
  );
}

function decryptJournal(
  raw: unknown,
  expectedVaultId: string,
  dek: Uint8Array,
): { record: PermissionJournalRecord; events: PermissionJournalEvent[] } | null {
  const parsed = permissionJournalRecordSchema.safeParse(raw);
  if (!parsed.success || parsed.data.vaultId !== expectedVaultId) return null;
  if (parsed.data.revision !== parsed.data.entries.length) return null;

  const events: PermissionJournalEvent[] = [];
  const eventIds = new Set<string>();
  try {
    for (let index = 0; index < parsed.data.entries.length; index += 1) {
      const entry = parsed.data.entries[index]!;
      if (entry.sequence !== index + 1 || eventIds.has(entry.eventId)) return null;
      const plaintext = aeadDecrypt(
        dek,
        { nonceB64: entry.nonceB64, ciphertextB64: entry.ciphertextB64 },
        eventAad(expectedVaultId, entry.sequence, entry.eventId),
      );
      const event = permissionJournalEventSchema.parse(JSON.parse(bytesToUtf8(plaintext)));
      if (event.eventId !== entry.eventId) return null;
      if (event.kind === 'grant' && event.scope.vaultId !== expectedVaultId) return null;
      if (event.kind === 'revoke_scope' && event.vaultId !== expectedVaultId) return null;
      events.push(event);
      eventIds.add(event.eventId);
    }
    reducePermissionEvents(events);
  } catch {
    return null;
  }
  return { record: parsed.data, events };
}

export function reducePermissionEvents(events: readonly PermissionJournalEvent[]): PermissionProjection {
  const grants = new Map<string, PermissionGrantEvent>();
  const revoked = new Set<string>();
  const eventIds = new Set<string>();
  for (const rawEvent of events) {
    const event = permissionJournalEventSchema.parse(rawEvent);
    if (eventIds.has(event.eventId)) {
      throw new PermissionJournalError('corrupt', 'duplicate permission event id');
    }
    eventIds.add(event.eventId);
    if (event.kind === 'revoke') {
      revoked.add(event.targetResourceId);
      grants.delete(event.targetResourceId);
      continue;
    }
    if (event.kind === 'revoke_scope') {
      for (const [resourceId, grant] of grants) {
        if (grant.scope.origin === event.origin && grant.scope.network === event.network &&
            grant.scope.vaultId === event.vaultId &&
            (event.account === null || grant.scope.account === event.account)) {
          grants.delete(resourceId);
          revoked.add(resourceId);
        }
      }
      continue;
    }
    if (grants.has(event.resourceId) || revoked.has(event.resourceId)) {
      throw new PermissionJournalError('corrupt', 'permission resource id was reused');
    }
    grants.set(event.resourceId, event);
  }
  return { grants: [...grants.values()], revokedResourceIds: revoked };
}

export function normalizePermissionScope(scope: PermissionScope): PermissionScope {
  return permissionScopeSchema.parse({
    ...scope,
    origin: normalizeProviderOrigin(scope.origin).asciiOrigin,
    categories: [...new Set(scope.categories)].sort(),
  });
}

export function hasExactPermission(
  projection: PermissionProjection,
  requested: PermissionScope,
): boolean {
  const scope = normalizePermissionScope(requested);
  const approved = new Set<PermissionDataCategory>();
  for (const grant of projection.grants) {
    if (
      grant.scope.origin === scope.origin &&
      grant.scope.network === scope.network &&
      grant.scope.vaultId === scope.vaultId &&
      grant.scope.account === scope.account
    ) {
      for (const category of grant.scope.categories) approved.add(category);
    }
  }
  return scope.categories.every((category) => approved.has(category));
}

/**
 * True only when the effective grant for an identity tuple is exactly the
 * requested category set. Provider surfaces use this for silent reconnect:
 * a broadened or narrowed request must return to native approval.
 */
export function hasExactPermissionSet(
  projection: PermissionProjection,
  requested: PermissionScope,
): boolean {
  const scope = normalizePermissionScope(requested);
  const approved = new Set<PermissionDataCategory>();
  for (const grant of projection.grants) {
    if (
      grant.scope.origin === scope.origin &&
      grant.scope.network === scope.network &&
      grant.scope.vaultId === scope.vaultId &&
      grant.scope.account === scope.account
    ) {
      for (const category of grant.scope.categories) approved.add(category);
    }
  }
  return approved.size === scope.categories.length &&
    scope.categories.every((category) => approved.has(category));
}

export function createPermissionOpaqueId(): string {
  const bytes = getCryptoProvider().randomBytes(16);
  let id = '';
  for (const byte of bytes) id += byte.toString(16).padStart(2, '0');
  return id;
}

function emptyResult(status: PermissionJournalLoadResult['status']): PermissionJournalLoadResult {
  return { status, revision: 0, events: [], projection: { grants: [], revokedResourceIds: new Set() } };
}

export async function loadPermissionJournal(
  area: PermissionStorageArea,
  storageKey: string,
  dek: Uint8Array,
  vaultId: string,
): Promise<PermissionJournalLoadResult> {
  assertDek(dek);
  const stagingKey = `${storageKey}:staging`;
  const stored = await area.get([storageKey, stagingKey]);
  const canonicalRaw = stored[storageKey];
  const stagingRaw = stored[stagingKey];
  const canonical =
    canonicalRaw === undefined ? null : decryptJournal(canonicalRaw, vaultId, dek);
  if (canonicalRaw !== undefined && canonical === null) {
    if (stagingRaw !== undefined) await area.remove(stagingKey);
    return emptyResult('corrupt');
  }

  const staged = stagingRaw === undefined ? null : decryptJournal(stagingRaw, vaultId, dek);
  if (stagingRaw !== undefined && staged === null) {
    await area.remove(stagingKey);
  }

  if (staged !== null) {
    const recover =
      canonical === null ||
      journalEqual(canonical.record, staged.record) ||
      extendsByOne(canonical.record, staged.record);
    if (recover) {
      if (canonical === null || !journalEqual(canonical.record, staged.record)) {
        await area.set({ [storageKey]: staged.record });
      }
      await area.remove(stagingKey);
      return {
        status: canonical === null || !journalEqual(canonical.record, staged.record) ? 'recovered' : 'ok',
        revision: staged.record.revision,
        events: staged.events,
        projection: reducePermissionEvents(staged.events),
      };
    }
    await area.remove(stagingKey);
  }

  if (canonical === null) return emptyResult('ok');
  return {
    status: 'ok',
    revision: canonical.record.revision,
    events: canonical.events,
    projection: reducePermissionEvents(canonical.events),
  };
}

export async function appendPermissionEvent(input: {
  area: PermissionStorageArea;
  storageKey: string;
  dek: Uint8Array;
  vaultId: string;
  expectedRevision: number;
  event: PermissionJournalEvent;
}): Promise<PermissionJournalLoadResult> {
  const event = permissionJournalEventSchema.safeParse(input.event);
  if (!event.success) throw new PermissionJournalError('invalid_event', 'invalid permission event');
  if ((event.data.kind === 'grant' && event.data.scope.vaultId !== input.vaultId) ||
      (event.data.kind === 'revoke_scope' && event.data.vaultId !== input.vaultId)) {
    throw new PermissionJournalError('invalid_event', 'permission event belongs to another vault');
  }
  const current = await loadPermissionJournal(input.area, input.storageKey, input.dek, input.vaultId);
  if (current.status === 'corrupt') throw new PermissionJournalError('corrupt', 'permission journal corrupt');
  if (current.revision !== input.expectedRevision) {
    throw new PermissionJournalError('stale_revision', 'permission journal revision changed');
  }
  if (current.events.some((existing) => existing.eventId === event.data.eventId)) return current;
  if (current.revision >= MAX_PERMISSION_JOURNAL_EVENTS) {
    throw new PermissionJournalError('journal_full', 'permission journal is full');
  }

  const sequence = current.revision + 1;
  const nonce = getCryptoProvider().randomBytes(NONCE_BYTES);
  const box = aeadEncrypt(
    input.dek,
    utf8ToBytes(JSON.stringify(event.data)),
    eventAad(input.vaultId, sequence, event.data.eventId),
    nonce,
  );
  const existingRaw = (await input.area.get(input.storageKey))[input.storageKey];
  const live =
    existingRaw === undefined ? null : decryptJournal(existingRaw, input.vaultId, input.dek);
  if (
    (current.revision === 0 && existingRaw !== undefined) ||
    (current.revision > 0 && (live === null || live.record.revision !== current.revision))
  ) {
    throw new PermissionJournalError('stale_revision', 'permission journal changed during append');
  }
  const existing =
    live?.record ?? { schemaVersion: 1 as const, vaultId: input.vaultId, revision: 0, entries: [] };
  const next: PermissionJournalRecord = {
    schemaVersion: 1,
    vaultId: input.vaultId,
    revision: sequence,
    entries: [
      ...existing.entries,
      { sequence, eventId: event.data.eventId, nonceB64: box.nonceB64, ciphertextB64: box.ciphertextB64 },
    ],
  };
  const stagingKey = `${input.storageKey}:staging`;
  await input.area.set({ [stagingKey]: next });

  const stagedRaw = (await input.area.get(stagingKey))[stagingKey];
  const staged = decryptJournal(stagedRaw, input.vaultId, input.dek);
  if (staged === null || !journalEqual(next, staged.record)) {
    throw new PermissionJournalError('corrupt', 'staged permission write failed validation');
  }
  await input.area.set({ [input.storageKey]: next });
  await input.area.remove(stagingKey);
  return {
    status: 'ok',
    revision: next.revision,
    events: staged.events,
    projection: reducePermissionEvents(staged.events),
  };
}
