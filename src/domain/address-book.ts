/**
 * Local encrypted saved-recipient semantics (spec §10.7).
 *
 * Persistence, encryption, clocks, and randomness remain consumer ports. This
 * module owns the bounded record shape and pure mutations so extension and
 * mobile cannot drift on duplicate, label, recent, or network behavior.
 */
import { z } from 'zod';
import type { Network } from './keys/derivation';
import { resolvePayableAddress } from './transactions/native-send';

export const MAX_SAVED_RECIPIENTS = 250;
export const MAX_RECENT_RECIPIENTS = 20;
export const MAX_RECIPIENT_LABEL_LENGTH = 80;

const recipientIdSchema = z.string().regex(/^[0-9a-f]{32}$/u);
const networkSchema = z.enum(['mainnet', 'signet', 'regtest']);
const timestampSchema = z.number().int().nonnegative();

export const savedRecipientSchema = z.object({
  id: recipientIdSchema,
  label: z.string().min(1).max(MAX_RECIPIENT_LABEL_LENGTH),
  address: z.string().min(1).max(128),
  createdAtMs: timestampSchema,
  updatedAtMs: timestampSchema,
}).strict();

export const recentRecipientSchema = z.object({
  address: z.string().min(1).max(128),
  lastUsedAtMs: timestampSchema,
  useCount: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
  lastKind: z.enum(['bitcoin', 'ordinal']),
}).strict();

export const addressBookSchema = z.object({
  version: z.literal(1),
  network: networkSchema,
  saved: z.array(savedRecipientSchema).max(MAX_SAVED_RECIPIENTS),
  recent: z.array(recentRecipientSchema).max(MAX_RECENT_RECIPIENTS),
}).strict().superRefine((book, context) => {
  const savedIds = new Set<string>();
  const savedAddresses = new Set<string>();
  for (const [index, entry] of book.saved.entries()) {
    if (savedIds.has(entry.id)) context.addIssue({
      code: z.ZodIssueCode.custom, path: ['saved', index, 'id'], message: 'duplicate recipient id',
    });
    if (savedAddresses.has(entry.address)) context.addIssue({
      code: z.ZodIssueCode.custom, path: ['saved', index, 'address'], message: 'duplicate saved address',
    });
    savedIds.add(entry.id);
    savedAddresses.add(entry.address);
  }
  const recentAddresses = new Set<string>();
  for (const [index, entry] of book.recent.entries()) {
    if (recentAddresses.has(entry.address)) context.addIssue({
      code: z.ZodIssueCode.custom, path: ['recent', index, 'address'], message: 'duplicate recent address',
    });
    recentAddresses.add(entry.address);
  }
});

export type SavedRecipientV1 = z.infer<typeof savedRecipientSchema>;
export type RecentRecipientV1 = z.infer<typeof recentRecipientSchema>;
export type AddressBookV1 = z.infer<typeof addressBookSchema>;

export type AddressBookMutationError =
  | 'invalid-label'
  | 'invalid-address'
  | 'duplicate-address'
  | 'limit-reached'
  | 'not-found';

export class AddressBookError extends Error {
  constructor(readonly code: AddressBookMutationError, message: string) {
    super(message);
    this.name = 'AddressBookError';
  }
}

/** Labels are local display metadata; reject characters that can disguise review text. */
export function normalizeRecipientLabel(label: string): string {
  const normalized = label.normalize('NFKC').trim().replace(/\s+/gu, ' ');
  if (normalized.length === 0 || [...normalized].length > MAX_RECIPIENT_LABEL_LENGTH ||
      /[\p{Cc}\p{Cf}]/u.test(normalized)) {
    throw new AddressBookError('invalid-label', 'recipient label is empty, too long, or contains formatting controls');
  }
  return normalized;
}

export function canonicalRecipientAddress(address: string, network: Network): string {
  const resolved = resolvePayableAddress(address.trim(), network);
  if (!resolved.ok) throw new AddressBookError('invalid-address', 'recipient address is invalid or unsupported');
  const payable = resolved.value.address;
  return /^(?:bc1|tb1)/iu.test(payable) ? payable.toLowerCase() : payable;
}

export function emptyAddressBook(network: Network): AddressBookV1 {
  return { version: 1, network, saved: [], recent: [] };
}

export function addSavedRecipient(
  book: AddressBookV1,
  input: { id: string; label: string; address: string; nowMs: number },
): AddressBookV1 {
  const parsed = addressBookSchema.parse(book);
  if (parsed.saved.length >= MAX_SAVED_RECIPIENTS) {
    throw new AddressBookError('limit-reached', 'saved recipient limit reached');
  }
  if (!recipientIdSchema.safeParse(input.id).success || !timestampSchema.safeParse(input.nowMs).success) {
    throw new AddressBookError('invalid-label', 'recipient identity or timestamp is invalid');
  }
  const address = canonicalRecipientAddress(input.address, parsed.network);
  if (parsed.saved.some((entry) => entry.address === address)) {
    throw new AddressBookError('duplicate-address', 'recipient address is already saved');
  }
  const entry: SavedRecipientV1 = {
    id: input.id,
    label: normalizeRecipientLabel(input.label),
    address,
    createdAtMs: input.nowMs,
    updatedAtMs: input.nowMs,
  };
  return addressBookSchema.parse({ ...parsed, saved: [...parsed.saved, entry] });
}

export function renameSavedRecipient(
  book: AddressBookV1,
  input: { id: string; label: string; nowMs: number },
): AddressBookV1 {
  let found = false;
  const saved = book.saved.map((entry) => {
    if (entry.id !== input.id) return entry;
    found = true;
    return { ...entry, label: normalizeRecipientLabel(input.label), updatedAtMs: input.nowMs };
  });
  if (!found) throw new AddressBookError('not-found', 'saved recipient not found');
  return addressBookSchema.parse({ ...book, saved });
}

export function removeSavedRecipient(book: AddressBookV1, id: string): AddressBookV1 {
  const removed = book.saved.find((entry) => entry.id === id);
  if (!removed) throw new AddressBookError('not-found', 'saved recipient not found');
  return addressBookSchema.parse({
    ...book,
    saved: book.saved.filter((entry) => entry.id !== id),
    recent: book.recent.filter((entry) => entry.address !== removed.address),
  });
}

export function recordRecentRecipient(
  book: AddressBookV1,
  input: { address: string; kind: RecentRecipientV1['lastKind']; nowMs: number },
): AddressBookV1 {
  const address = canonicalRecipientAddress(input.address, book.network);
  const previous = book.recent.find((entry) => entry.address === address);
  const next: RecentRecipientV1 = {
    address,
    lastUsedAtMs: input.nowMs,
    useCount: Math.min(Number.MAX_SAFE_INTEGER, (previous?.useCount ?? 0) + 1),
    lastKind: input.kind,
  };
  const recent = [next, ...book.recent.filter((entry) => entry.address !== address)]
    .sort((a, b) => b.lastUsedAtMs - a.lastUsedAtMs)
    .slice(0, MAX_RECENT_RECIPIENTS);
  return addressBookSchema.parse({ ...book, recent });
}

export function dismissRecentRecipient(book: AddressBookV1, addressInput: string): AddressBookV1 {
  const address = canonicalRecipientAddress(addressInput, book.network);
  return addressBookSchema.parse({
    ...book,
    recent: book.recent.filter((entry) => entry.address !== address),
  });
}
