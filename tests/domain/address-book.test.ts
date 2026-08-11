import { describe, expect, it } from 'vitest';
import {
  AddressBookError,
  addSavedRecipient,
  addressBookSchema,
  dismissRecentRecipient,
  emptyAddressBook,
  normalizeRecipientLabel,
  recordRecentRecipient,
  removeSavedRecipient,
  renameSavedRecipient,
} from '../../src/domain/address-book';

const ALICE = 'bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh';
const BOB = 'bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr';

describe('saved recipients', () => {
  it('normalizes labels, canonicalizes addresses, renames, and removes related recents', () => {
    let book = addSavedRecipient(emptyAddressBook('mainnet'), {
      id: '11'.repeat(16), label: '  Alice   Savings  ', address: ALICE.toUpperCase(), nowMs: 1,
    });
    expect(book.saved[0]).toMatchObject({ label: 'Alice Savings', address: ALICE });
    book = recordRecentRecipient(book, { address: ALICE, kind: 'bitcoin', nowMs: 2 });
    book = renameSavedRecipient(book, { id: '11'.repeat(16), label: 'Alice', nowMs: 3 });
    expect(book.saved[0]).toMatchObject({ label: 'Alice', updatedAtMs: 3 });
    expect(removeSavedRecipient(book, '11'.repeat(16))).toEqual(emptyAddressBook('mainnet'));
  });

  it('rejects duplicate addresses, wrong networks, controls, and duplicate persisted records', () => {
    const book = addSavedRecipient(emptyAddressBook('mainnet'), {
      id: '11'.repeat(16), label: 'Alice', address: ALICE, nowMs: 1,
    });
    expect(() => addSavedRecipient(book, {
      id: '22'.repeat(16), label: 'Other Alice', address: ALICE, nowMs: 2,
    })).toThrowError(expect.objectContaining({ code: 'duplicate-address' }));
    expect(() => addSavedRecipient(book, {
      id: '22'.repeat(16), label: 'Signet', address: `tb1q${'q'.repeat(38)}`, nowMs: 2,
    })).toThrow(AddressBookError);
    expect(() => normalizeRecipientLabel('Alice\u202e')).toThrow(AddressBookError);
    expect(addressBookSchema.safeParse({ ...book, saved: [book.saved[0], book.saved[0]] }).success).toBe(false);
  });

  it('keeps bounded distinct recents in newest-first order and dismisses one', () => {
    let book = emptyAddressBook('mainnet');
    book = recordRecentRecipient(book, { address: ALICE, kind: 'bitcoin', nowMs: 1 });
    book = recordRecentRecipient(book, { address: BOB, kind: 'ordinal', nowMs: 2 });
    book = recordRecentRecipient(book, { address: ALICE, kind: 'bitcoin', nowMs: 3 });
    expect(book.recent).toEqual([
      { address: ALICE, lastUsedAtMs: 3, useCount: 2, lastKind: 'bitcoin' },
      { address: BOB, lastUsedAtMs: 2, useCount: 1, lastKind: 'ordinal' },
    ]);
    expect(dismissRecentRecipient(book, ALICE).recent).toEqual([book.recent[1]]);
  });
});
