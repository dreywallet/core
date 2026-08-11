import { beforeAll, describe, expect, it } from 'vitest';
import {
  createContactTransferRequest,
  mergeContactTransferRecipients,
  openContactTransfer,
  parseContactTransfer,
  sealContactTransfer,
  serializeContactTransfer,
} from '../../src/domain/contact-transfer';
import { addSavedRecipient, emptyAddressBook } from '../../src/domain/address-book';
import { installTestCryptoProvider } from '../helpers/install-crypto-provider';

beforeAll(installTestCryptoProvider);

const ALICE = 'bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh';
const BOB = 'bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr';

function randomSource(seed = 1): (length: number) => Uint8Array {
  let counter = seed;
  return (length) => new Uint8Array(length).fill(counter++);
}

describe('encrypted contact transfer', () => {
  it('round-trips authenticated saved recipients without exporting recents', () => {
    const receiver = createContactTransferRequest({
      network: 'mainnet', nowMs: 100, random: randomSource(1),
    });
    let book = addSavedRecipient(emptyAddressBook('mainnet'), {
      id: '11'.repeat(16), label: 'Alice', address: ALICE, nowMs: 1,
    });
    book = { ...book, recent: [{
      address: BOB, lastUsedAtMs: 2, useCount: 1, lastKind: 'bitcoin',
    }] };
    const response = sealContactTransfer({
      request: receiver.request, addressBook: book, nowMs: 200, random: randomSource(20),
    });
    const decoded = parseContactTransfer(serializeContactTransfer(response));
    expect(decoded.type).toBe('drey-contacts-response');
    if (decoded.type !== 'drey-contacts-response') throw new Error('expected response');
    expect(openContactTransfer({ receiver, response: decoded, nowMs: 300 })).toEqual([
      { label: 'Alice', address: ALICE },
    ]);
  });

  it('rejects tampering, a different receiver, and expired requests', () => {
    const receiver = createContactTransferRequest({
      network: 'mainnet', nowMs: 100, random: randomSource(3),
    });
    const other = createContactTransferRequest({
      network: 'mainnet', nowMs: 100, random: randomSource(7),
    });
    const response = sealContactTransfer({
      request: receiver.request, addressBook: emptyAddressBook('mainnet'),
      nowMs: 200, random: randomSource(30),
    });
    expect(() => openContactTransfer({ receiver: other, response, nowMs: 300 })).toThrow();
    expect(() => openContactTransfer({
      receiver,
      response: { ...response, recipientCount: 1 },
      nowMs: 300,
    })).toThrow();
    expect(() => openContactTransfer({
      receiver, response, nowMs: receiver.request.expiresAtMs + 1,
    })).toThrow('expired');
  });

  it('merges new addresses while preserving local labels and reporting skips', () => {
    const local = addSavedRecipient(emptyAddressBook('mainnet'), {
      id: '11'.repeat(16), label: 'My Alice', address: ALICE, nowMs: 1,
    });
    let nextId = 2;
    const merged = mergeContactTransferRecipients({
      addressBook: local,
      recipients: [
        { label: 'Their Alice', address: ALICE },
        { label: 'Bob', address: BOB },
      ],
      nowMs: 10,
      newId: () => String(nextId++).padStart(32, '0'),
    });
    expect(merged).toMatchObject({ added: 1, skipped: 1 });
    expect(merged.addressBook.saved.map(({ label, address }) => ({ label, address }))).toEqual([
      { label: 'My Alice', address: ALICE },
      { label: 'Bob', address: BOB },
    ]);
  });
});
