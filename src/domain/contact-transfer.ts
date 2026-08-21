/** One-time, serverless transfer of saved recipients between Drey devices. */
import { secp256k1 } from '@noble/curves/secp256k1';
import { z } from 'zod';
import {
  MAX_SAVED_RECIPIENTS,
  addSavedRecipient,
  canonicalRecipientAddress,
  normalizeRecipientLabel,
  type AddressBookV1,
} from './address-book';
import type { Network } from './keys/derivation';
import { aeadDecrypt, aeadEncrypt, NONCE_BYTES, zeroize } from './vault/crypto';
import { bytesToHex, hexToBytes, utf8ToBytes } from './vault/encoding';
import { hkdfSha256 } from './vault/hkdf';

export const CONTACT_TRANSFER_VERSION = 1 as const;
export const CONTACT_TRANSFER_TTL_MS = 10 * 60 * 1000;
export const CONTACT_TRANSFER_MAX_BYTES = 256 * 1024;

const networkSchema = z.enum(['mainnet', 'signet', 'regtest']);
const hex16 = z.string().regex(/^[0-9a-f]{32}$/u);
const compressedPublicKey = z.string().regex(/^(?:02|03)[0-9a-f]{64}$/u);
const boxSchema = z.object({ nonceB64: z.string().min(1), ciphertextB64: z.string().min(1) }).strict();

export const contactTransferRequestSchema = z.object({
  type: z.literal('drey-contacts-request'),
  version: z.literal(CONTACT_TRANSFER_VERSION),
  network: networkSchema,
  sessionIdHex: hex16,
  receiverPublicKeyHex: compressedPublicKey,
  expiresAtMs: z.number().int().positive(),
}).strict();

export const contactTransferResponseSchema = z.object({
  type: z.literal('drey-contacts-response'),
  version: z.literal(CONTACT_TRANSFER_VERSION),
  network: networkSchema,
  sessionIdHex: hex16,
  receiverPublicKeyHex: compressedPublicKey,
  senderPublicKeyHex: compressedPublicKey,
  createdAtMs: z.number().int().nonnegative(),
  recipientCount: z.number().int().nonnegative().max(MAX_SAVED_RECIPIENTS),
  box: boxSchema,
}).strict();

const transferPayloadSchema = z.object({
  version: z.literal(CONTACT_TRANSFER_VERSION),
  network: networkSchema,
  exportedAtMs: z.number().int().nonnegative(),
  recipients: z.array(z.object({
    label: z.string().min(1).max(80),
    address: z.string().min(1).max(128),
  }).strict()).max(MAX_SAVED_RECIPIENTS),
}).strict();

export type ContactTransferRequestV1 = z.infer<typeof contactTransferRequestSchema>;
export type ContactTransferResponseV1 = z.infer<typeof contactTransferResponseSchema>;
export type ContactTransferRecipient = z.infer<typeof transferPayloadSchema>['recipients'][number];

export interface ContactTransferReceiverState {
  request: ContactTransferRequestV1;
  /** Ephemeral and memory-only; wipe after one response or expiry. */
  privateKey: Uint8Array;
}

function randomPrivateKey(random: (length: number) => Uint8Array): Uint8Array {
  for (let attempt = 0; attempt < 128; attempt += 1) {
    const candidate = random(32);
    if (candidate.length !== 32) throw new Error('contact transfer random source returned wrong length');
    if (secp256k1.utils.isValidPrivateKey(candidate)) return candidate;
    zeroize(candidate);
  }
  throw new Error('unable to generate contact transfer key');
}

function aad(response: Omit<ContactTransferResponseV1, 'box'>): string {
  return [
    'drey-contact-transfer/v1', response.network, response.sessionIdHex,
    response.receiverPublicKeyHex, response.senderPublicKeyHex,
    String(response.createdAtMs), String(response.recipientCount),
  ].join(':');
}

function deriveTransferKey(
  privateKey: Uint8Array,
  otherPublicKeyHex: string,
  request: ContactTransferRequestV1,
  senderPublicKeyHex: string,
): Uint8Array {
  const shared = secp256k1.getSharedSecret(privateKey, hexToBytes(otherPublicKeyHex), true);
  const salt = hexToBytes(request.sessionIdHex);
  const info = utf8ToBytes([
    'drey-contact-transfer-key/v1', request.network,
    request.receiverPublicKeyHex, senderPublicKeyHex,
  ].join(':'));
  try {
    return hkdfSha256(shared, salt, info, 32);
  } finally {
    zeroize(shared);
    zeroize(salt);
    zeroize(info);
  }
}

export function createContactTransferRequest(input: {
  network: Network;
  nowMs: number;
  random(length: number): Uint8Array;
}): ContactTransferReceiverState {
  const privateKey = randomPrivateKey(input.random);
  const request = contactTransferRequestSchema.parse({
    type: 'drey-contacts-request',
    version: CONTACT_TRANSFER_VERSION,
    network: input.network,
    sessionIdHex: bytesToHex(input.random(16)),
    receiverPublicKeyHex: bytesToHex(secp256k1.getPublicKey(privateKey, true)),
    expiresAtMs: input.nowMs + CONTACT_TRANSFER_TTL_MS,
  });
  return { request, privateKey };
}

export function sealContactTransfer(input: {
  request: ContactTransferRequestV1;
  addressBook: AddressBookV1;
  nowMs: number;
  random(length: number): Uint8Array;
}): ContactTransferResponseV1 {
  const request = contactTransferRequestSchema.parse(input.request);
  if (input.nowMs > request.expiresAtMs) throw new Error('contact transfer request expired');
  if (input.addressBook.network !== request.network) throw new Error('contact transfer network mismatch');
  const senderPrivateKey = randomPrivateKey(input.random);
  const senderPublicKeyHex = bytesToHex(secp256k1.getPublicKey(senderPrivateKey, true));
  const payload = transferPayloadSchema.parse({
    version: CONTACT_TRANSFER_VERSION,
    network: request.network,
    exportedAtMs: input.nowMs,
    recipients: input.addressBook.saved.map(({ label, address }) => ({ label, address })),
  });
  const plaintext = utf8ToBytes(JSON.stringify(payload));
  if (plaintext.length > CONTACT_TRANSFER_MAX_BYTES) {
    zeroize(senderPrivateKey);
    zeroize(plaintext);
    throw new Error('contact transfer payload too large');
  }
  const metadata = {
    type: 'drey-contacts-response' as const,
    version: CONTACT_TRANSFER_VERSION,
    network: request.network,
    sessionIdHex: request.sessionIdHex,
    receiverPublicKeyHex: request.receiverPublicKeyHex,
    senderPublicKeyHex,
    createdAtMs: input.nowMs,
    recipientCount: payload.recipients.length,
  };
  const key = deriveTransferKey(
    senderPrivateKey, request.receiverPublicKeyHex, request, senderPublicKeyHex,
  );
  try {
    return contactTransferResponseSchema.parse({
      ...metadata,
      box: aeadEncrypt(key, plaintext, aad(metadata), input.random(NONCE_BYTES)),
    });
  } finally {
    zeroize(key);
    zeroize(senderPrivateKey);
    zeroize(plaintext);
  }
}

export function openContactTransfer(input: {
  receiver: ContactTransferReceiverState;
  response: ContactTransferResponseV1;
  nowMs: number;
}): readonly ContactTransferRecipient[] {
  const request = contactTransferRequestSchema.parse(input.receiver.request);
  const response = contactTransferResponseSchema.parse(input.response);
  if (input.receiver.privateKey.length !== 32 ||
      bytesToHex(secp256k1.getPublicKey(input.receiver.privateKey, true)) !== request.receiverPublicKeyHex) {
    throw new Error('contact transfer receiver key mismatch');
  }
  if (input.nowMs > request.expiresAtMs || response.createdAtMs > request.expiresAtMs) {
    throw new Error('contact transfer expired');
  }
  if (response.network !== request.network || response.sessionIdHex !== request.sessionIdHex ||
      response.receiverPublicKeyHex !== request.receiverPublicKeyHex) {
    throw new Error('contact transfer response mismatch');
  }
  const key = deriveTransferKey(
    input.receiver.privateKey, response.senderPublicKeyHex, request, response.senderPublicKeyHex,
  );
  let plaintext: Uint8Array | null = null;
  try {
    const metadata = {
      type: response.type,
      version: response.version,
      network: response.network,
      sessionIdHex: response.sessionIdHex,
      receiverPublicKeyHex: response.receiverPublicKeyHex,
      senderPublicKeyHex: response.senderPublicKeyHex,
      createdAtMs: response.createdAtMs,
      recipientCount: response.recipientCount,
    };
    plaintext = aeadDecrypt(key, response.box, aad(metadata));
    if (plaintext.length > CONTACT_TRANSFER_MAX_BYTES) throw new Error('contact transfer payload too large');
    const payload = transferPayloadSchema.parse(JSON.parse(new TextDecoder().decode(plaintext)));
    if (payload.network !== request.network || payload.recipients.length !== response.recipientCount) {
      throw new Error('contact transfer payload mismatch');
    }
    return payload.recipients.map((recipient) => ({
      label: normalizeRecipientLabel(recipient.label),
      address: canonicalRecipientAddress(recipient.address, request.network),
    }));
  } finally {
    zeroize(key);
    if (plaintext !== null) zeroize(plaintext);
  }
}

export function serializeContactTransfer(value: ContactTransferRequestV1 | ContactTransferResponseV1): Uint8Array {
  const parsed = value.type === 'drey-contacts-request'
    ? contactTransferRequestSchema.parse(value)
    : contactTransferResponseSchema.parse(value);
  return utf8ToBytes(JSON.stringify(parsed));
}

export function parseContactTransfer(bytes: Uint8Array): ContactTransferRequestV1 | ContactTransferResponseV1 {
  if (bytes.length > CONTACT_TRANSFER_MAX_BYTES) throw new Error('contact transfer payload too large');
  const value: unknown = JSON.parse(new TextDecoder().decode(bytes));
  const request = contactTransferRequestSchema.safeParse(value);
  if (request.success) return request.data;
  return contactTransferResponseSchema.parse(value);
}

export function mergeContactTransferRecipients(input: {
  addressBook: AddressBookV1;
  recipients: readonly ContactTransferRecipient[];
  nowMs: number;
  newId(): string;
}): { addressBook: AddressBookV1; added: number; skipped: number } {
  let addressBook = input.addressBook;
  let added = 0;
  let skipped = 0;
  for (const recipient of input.recipients) {
    const address = canonicalRecipientAddress(recipient.address, addressBook.network);
    if (addressBook.saved.some((entry) => entry.address === address) ||
        addressBook.saved.length >= MAX_SAVED_RECIPIENTS) {
      skipped += 1;
      continue;
    }
    addressBook = addSavedRecipient(addressBook, {
      id: input.newId(), label: recipient.label, address, nowMs: input.nowMs,
    });
    added += 1;
  }
  return { addressBook, added, skipped };
}
