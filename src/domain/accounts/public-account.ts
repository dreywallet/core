/**
 * Closed single-signature public account descriptors.
 *
 * This is intentionally not a general Bitcoin descriptor implementation.
 * One account is exactly four separately checksummed ranged descriptors:
 * BIP84 receive/change plus BIP86 receive/change. No private key, arbitrary
 * script, Miniscript, multisig, Taproot tree, or caller-selected fragment can
 * enter the portable account record.
 */
import { HDKey } from '@scure/bip32';
import { NETWORK, TEST_NETWORK, p2tr, p2wpkh } from '@scure/btc-signer';
import { sha256 } from '@scure/btc-signer/utils';
import { z } from 'zod';
import { descriptorChecksum } from '../keys/descriptor-checksum';
import { bip32Versions } from '../keys/extended-key';
import {
  accountPath,
  assertBip32Index,
  type AddressInfo,
  type AddressKind,
  type Network,
} from '../keys/derivation';
import { bytesToHex } from '../vault/encoding';

export type PublicAccountId = string;
export type PublicAccountChain = 0 | 1;

export interface PublicKeyOriginV1 {
  version: 1;
  masterFingerprintHex: string;
  path: string;
  accountXpub: string;
}

export interface PublicAccountLaneV1 {
  version: 1;
  kind: AddressKind;
  purpose: 84 | 86;
  origin: PublicKeyOriginV1;
  receiveDescriptor: string;
  changeDescriptor: string;
}

export interface PublicAccountDefinitionV1 {
  version: 1;
  accountId: PublicAccountId;
  network: Network;
  derivationAccountIndex: number;
  lanes: {
    payment: PublicAccountLaneV1;
    ordinals: PublicAccountLaneV1;
  };
}

export interface PublicAccountDescriptorInput {
  network: Network;
  paymentReceiveDescriptor: string;
  paymentChangeDescriptor: string;
  ordinalsReceiveDescriptor: string;
  ordinalsChangeDescriptor: string;
}

export interface DerivedPublicAccountAddress extends AddressInfo {
  accountId: PublicAccountId;
  accountIndex: number;
  lane: AddressKind;
  chain: PublicAccountChain;
  index: number;
  scriptPubKeyHex: string;
}

const CHECKSUM_CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const ACCOUNT_ID_DOMAIN = 'drey-public-account-v1\0';
const XPUB_BASE58 = '[1-9A-HJ-NP-Za-km-z]{111}';
const DESCRIPTOR_EXPRESSION = new RegExp(
  `^(wpkh|tr)\\(\\[([0-9a-f]{8})\\/(84|86)h\\/(0|1)h\\/(0|[1-9][0-9]*)h\\](${XPUB_BASE58})\\/(0|1)\\/\\*\\)$`,
  'u',
);

interface ParsedDescriptor {
  kind: AddressKind;
  purpose: 84 | 86;
  network: Network;
  accountIndex: number;
  chain: PublicAccountChain;
  origin: PublicKeyOriginV1;
  descriptor: string;
  checksum: string;
}

const originSchema: z.ZodType<PublicKeyOriginV1> = z.object({
  version: z.literal(1),
  masterFingerprintHex: z.string().regex(/^[0-9a-f]{8}$/u),
  path: z.string().min(1).max(64),
  accountXpub: z.string().min(1).max(128),
}).strict();

const laneSchema: z.ZodType<PublicAccountLaneV1> = z.object({
  version: z.literal(1),
  kind: z.enum(['payment', 'ordinals']),
  purpose: z.union([z.literal(84), z.literal(86)]),
  origin: originSchema,
  receiveDescriptor: z.string().min(1).max(512),
  changeDescriptor: z.string().min(1).max(512),
}).strict();

const definitionShape = z.object({
  version: z.literal(1),
  accountId: z.string().regex(/^acct_(?:mainnet|signet)_[0-9a-f]{64}$/u),
  network: z.enum(['mainnet', 'signet']),
  derivationAccountIndex: z.number().int().min(0).max(0x7fff_ffff),
  lanes: z.object({ payment: laneSchema, ordinals: laneSchema }).strict(),
}).strict();

export const publicAccountDefinitionSchema: z.ZodType<PublicAccountDefinitionV1> =
  definitionShape.superRefine((definition, context) => {
    try {
      assertPublicAccountDefinition(definition);
    } catch (error) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message: error instanceof Error ? error.message : 'invalid public account definition',
      });
    }
  });

function descriptorParts(descriptor: string): { payload: string; checksum: string } {
  if (typeof descriptor !== 'string' || descriptor.length > 512 || descriptor.at(-9) !== '#') {
    throw new Error('checksummed ranged descriptor required');
  }
  const payload = descriptor.slice(0, -9);
  const checksum = descriptor.slice(-8);
  if (payload.includes('#') || checksum.length !== 8 ||
      [...checksum].some((character) => !CHECKSUM_CHARSET.includes(character))) {
    throw new Error('malformed descriptor checksum');
  }
  if (descriptorChecksum(payload) !== checksum) throw new Error('descriptor checksum mismatch');
  return { payload, checksum };
}

function descriptorKind(fragment: string): AddressKind {
  if (fragment === 'wpkh') return 'payment';
  if (fragment === 'tr') return 'ordinals';
  throw new Error('unsupported descriptor fragment');
}

function purposeFor(kind: AddressKind): 84 | 86 {
  return kind === 'payment' ? 84 : 86;
}

/** Parse exactly one canonical ranged wpkh/tr descriptor. */
export function parsePublicDescriptor(descriptor: string, expectedNetwork: Network): ParsedDescriptor {
  const { payload, checksum } = descriptorParts(descriptor);
  const match = DESCRIPTOR_EXPRESSION.exec(payload);
  if (!match) throw new Error('unsupported or non-canonical public descriptor');
  const [, fragment, fingerprint, purposeText, coinText, accountText, accountXpub, chainText] = match;
  const kind = descriptorKind(fragment!);
  const purpose = Number(purposeText) as 84 | 86;
  if (purpose !== purposeFor(kind)) throw new Error('descriptor purpose does not match script type');
  const network: Network = coinText === '0' ? 'mainnet' : 'signet';
  if (network !== expectedNetwork) throw new Error('descriptor network mismatch');
  const accountIndex = Number(accountText);
  assertBip32Index(accountIndex, 'descriptor account index');
  const chain = Number(chainText) as PublicAccountChain;
  const path = accountPath(kind, network, accountIndex);
  let account: HDKey;
  try {
    account = HDKey.fromExtendedKey(accountXpub!, bip32Versions(network));
  } catch {
    throw new Error('network-appropriate public account xpub required');
  }
  if (account.privateKey !== null || !account.publicKey || account.depth !== 3 ||
      account.index !== 0x8000_0000 + accountIndex) {
    throw new Error('public hardened account-level xpub required');
  }
  const origin: PublicKeyOriginV1 = {
    version: 1,
    masterFingerprintHex: fingerprint!,
    path,
    accountXpub: account.publicExtendedKey,
  };
  const canonical = canonicalPublicDescriptor(kind, network, accountIndex, origin, chain);
  if (canonical !== descriptor) throw new Error('descriptor is valid but not canonical v1');
  return { kind, purpose, network, accountIndex, chain, origin, descriptor, checksum };
}

export function canonicalPublicDescriptor(
  kind: AddressKind,
  network: Network,
  accountIndex: number,
  origin: PublicKeyOriginV1,
  chain: PublicAccountChain,
): string {
  assertBip32Index(accountIndex, 'descriptor account index');
  if (origin.path !== accountPath(kind, network, accountIndex)) {
    throw new Error('key origin path does not match descriptor lane');
  }
  if (!/^[0-9a-f]{8}$/u.test(origin.masterFingerprintHex)) {
    throw new Error('invalid key-origin fingerprint');
  }
  const account = HDKey.fromExtendedKey(origin.accountXpub, bip32Versions(network));
  if (account.privateKey !== null || account.depth !== 3 ||
      account.index !== 0x8000_0000 + accountIndex || !account.publicKey) {
    throw new Error('public hardened account-level xpub required');
  }
  const originText = origin.path.slice(2).replaceAll("'", 'h');
  const fragment = kind === 'payment' ? 'wpkh' : 'tr';
  const payload = `${fragment}([${origin.masterFingerprintHex}/${originText}]${account.publicExtendedKey}/${chain}/*)`;
  return `${payload}#${descriptorChecksum(payload)}`;
}

function sameOrigin(left: PublicKeyOriginV1, right: PublicKeyOriginV1): boolean {
  return left.masterFingerprintHex === right.masterFingerprintHex && left.path === right.path &&
    left.accountXpub === right.accountXpub;
}

function laneFromPair(
  expectedKind: AddressKind,
  network: Network,
  receiveDescriptor: string,
  changeDescriptor: string,
): PublicAccountLaneV1 {
  const receive = parsePublicDescriptor(receiveDescriptor, network);
  const change = parsePublicDescriptor(changeDescriptor, network);
  if (receive.kind !== expectedKind || change.kind !== expectedKind) {
    throw new Error('descriptor pair has the wrong address lane');
  }
  if (receive.chain !== 0 || change.chain !== 1) {
    throw new Error('descriptor receive/change branches are swapped or duplicated');
  }
  if (receive.accountIndex !== change.accountIndex || !sameOrigin(receive.origin, change.origin)) {
    throw new Error('descriptor pair does not share one key origin');
  }
  return {
    version: 1,
    kind: expectedKind,
    purpose: purposeFor(expectedKind),
    origin: receive.origin,
    receiveDescriptor,
    changeDescriptor,
  };
}

function accountIdFor(network: Network, descriptors: readonly ParsedDescriptor[]): PublicAccountId {
  const lanes = descriptors.filter((descriptor) => descriptor.chain === 0);
  const preimage = new TextEncoder().encode(
    `${ACCOUNT_ID_DOMAIN}${network}\0${lanes.map((descriptor) => [
      descriptor.kind,
      descriptor.accountIndex,
      descriptor.origin.accountXpub,
    ].join(':')).join('\0')}`,
  );
  return `acct_${network}_${bytesToHex(sha256(preimage))}`;
}

/** Validate and normalize the complete four-descriptor public account. */
export function parsePublicAccountDescriptors(input: PublicAccountDescriptorInput): PublicAccountDefinitionV1 {
  const payment = laneFromPair(
    'payment', input.network, input.paymentReceiveDescriptor, input.paymentChangeDescriptor,
  );
  const ordinals = laneFromPair(
    'ordinals', input.network, input.ordinalsReceiveDescriptor, input.ordinalsChangeDescriptor,
  );
  const paymentReceive = parsePublicDescriptor(payment.receiveDescriptor, input.network);
  const paymentChange = parsePublicDescriptor(payment.changeDescriptor, input.network);
  const ordinalsReceive = parsePublicDescriptor(ordinals.receiveDescriptor, input.network);
  const ordinalsChange = parsePublicDescriptor(ordinals.changeDescriptor, input.network);
  if (paymentReceive.accountIndex !== ordinalsReceive.accountIndex) {
    throw new Error('payment and Ordinals descriptors use different account indexes');
  }
  if (payment.origin.masterFingerprintHex !== ordinals.origin.masterFingerprintHex) {
    throw new Error('payment and Ordinals descriptors use different master fingerprints');
  }
  const definition: PublicAccountDefinitionV1 = {
    version: 1,
    accountId: accountIdFor(input.network, [paymentReceive, paymentChange, ordinalsReceive, ordinalsChange]),
    network: input.network,
    derivationAccountIndex: paymentReceive.accountIndex,
    lanes: { payment, ordinals },
  };
  return definition;
}

/** Generate the identical public definition for an existing software seed account. */
export function publicAccountFromSeed(
  seed: Uint8Array,
  network: Network,
  accountIndex: number,
): PublicAccountDefinitionV1 {
  assertBip32Index(accountIndex, 'account index');
  const root = HDKey.fromMasterSeed(seed, bip32Versions(network));
  try {
    return publicAccountFromRoot(root, network, accountIndex);
  } finally {
    root.wipePrivateData();
  }
}

/** Project one definition from an already-open root; the caller owns root cleanup. */
export function publicAccountFromRoot(
  root: HDKey,
  network: Network,
  accountIndex: number,
): PublicAccountDefinitionV1 {
  assertBip32Index(accountIndex, 'account index');
  if (!root.privateKey || root.depth !== 0) throw new Error('private BIP32 root required');
  const fingerprint = root.fingerprint.toString(16).padStart(8, '0');
  const descriptors = {} as Record<string, string>;
  for (const kind of ['payment', 'ordinals'] as const) {
    const account = root.derive(accountPath(kind, network, accountIndex));
    try {
      account.wipePrivateData();
      const origin: PublicKeyOriginV1 = {
        version: 1,
        masterFingerprintHex: fingerprint,
        path: accountPath(kind, network, accountIndex),
        accountXpub: account.publicExtendedKey,
      };
      descriptors[`${kind}Receive`] = canonicalPublicDescriptor(kind, network, accountIndex, origin, 0);
      descriptors[`${kind}Change`] = canonicalPublicDescriptor(kind, network, accountIndex, origin, 1);
    } finally {
      account.wipePrivateData();
    }
  }
  return parsePublicAccountDescriptors({
    network,
    paymentReceiveDescriptor: descriptors.paymentReceive!,
    paymentChangeDescriptor: descriptors.paymentChange!,
    ordinalsReceiveDescriptor: descriptors.ordinalsReceive!,
    ordinalsChangeDescriptor: descriptors.ordinalsChange!,
  });
}

export function assertPublicAccountDefinition(definition: PublicAccountDefinitionV1): void {
  const parsed = parsePublicAccountDescriptors({
    network: definition.network,
    paymentReceiveDescriptor: definition.lanes.payment.receiveDescriptor,
    paymentChangeDescriptor: definition.lanes.payment.changeDescriptor,
    ordinalsReceiveDescriptor: definition.lanes.ordinals.receiveDescriptor,
    ordinalsChangeDescriptor: definition.lanes.ordinals.changeDescriptor,
  });
  if (parsed.accountId !== definition.accountId ||
      parsed.derivationAccountIndex !== definition.derivationAccountIndex ||
      JSON.stringify(parsed.lanes) !== JSON.stringify(definition.lanes)) {
    throw new Error('public account definition does not match its descriptors');
  }
}

/** Derive one receive/change address from the account's public definition only. */
export function derivePublicAccountAddress(
  definitionInput: PublicAccountDefinitionV1,
  lane: AddressKind,
  chain: PublicAccountChain,
  index: number,
): DerivedPublicAccountAddress {
  assertBip32Index(index, 'address index');
  const definition = publicAccountDefinitionSchema.parse(definitionInput);
  const laneDefinition = definition.lanes[lane];
  const descriptor = parsePublicDescriptor(
    chain === 0 ? laneDefinition.receiveDescriptor : laneDefinition.changeDescriptor,
    definition.network,
  );
  const account = HDKey.fromExtendedKey(descriptor.origin.accountXpub, bip32Versions(definition.network));
  const branch = account.deriveChild(chain);
  const child = branch.deriveChild(index);
  if (branch.index !== chain || child.index !== index || !child.publicKey) {
    throw new Error('invalid BIP32 public child derivation');
  }
  const net = definition.network === 'mainnet' ? NETWORK : TEST_NETWORK;
  const payment = lane === 'payment'
    ? p2wpkh(child.publicKey, net)
    : p2tr(child.publicKey.slice(1), undefined, net);
  if (!payment.address || !payment.script) throw new Error('public address derivation failed');
  return {
    accountId: definition.accountId,
    accountIndex: definition.derivationAccountIndex,
    lane,
    chain,
    index,
    address: payment.address,
    path: `${descriptor.origin.path}/${chain}/${index}`,
    publicKeyHex: bytesToHex(child.publicKey),
    scriptPubKeyHex: bytesToHex(payment.script),
  };
}

/** Future signer attachment must reproduce the exact complete public definition. */
export function publicAccountsMatch(
  watched: PublicAccountDefinitionV1,
  candidate: PublicAccountDefinitionV1,
): boolean {
  try {
    const left = publicAccountDefinitionSchema.parse(watched);
    const right = publicAccountDefinitionSchema.parse(candidate);
    return JSON.stringify(left) === JSON.stringify(right);
  } catch {
    return false;
  }
}
