/**
 * Public-only watch-account interchange.
 *
 * Every accepted format is normalized into the closed four-descriptor account
 * policy in public-account.ts. This module is intentionally not a general
 * descriptor, CBOR, or wallet-file parser.
 */
import { HDKey } from '@scure/bip32';
import type { Network } from '../keys/derivation';
import { bip32Versions } from '../keys/extended-key';
import { descriptorChecksum } from '../keys/descriptor-checksum';
import {
  canonicalPublicDescriptor,
  parsePublicAccountDescriptors,
  parsePublicDescriptor,
  type PublicAccountDefinitionV1,
  type PublicKeyOriginV1,
} from './public-account';

const MAX_TEXT_BYTES = 65_536;
const MAX_CBOR_BYTES = 65_536;
const TAG_ACCOUNT_DESCRIPTOR_OUTPUT = 40_308;
const TAG_HDKEY = 40_303;
const TAG_KEYPATH = 40_304;
const TAG_COININFO = 40_305;
const LEGACY_TAG_OUTPUT = 308;
const LEGACY_TAG_HDKEY = 303;
const LEGACY_TAG_KEYPATH = 304;
const LEGACY_TAG_COININFO = 305;
const LEGACY_TAG_WPKH = 404;
const LEGACY_TAG_TR = 409;

export type PublicAccountInterchangeFormat =
  | 'account-descriptor-v2'
  | 'crypto-account-v1'
  | 'bitcoin-core-json'
  | 'bip380-descriptors'
  | 'account-key-expressions';

export type PublicAccountInterchangeErrorCode =
  | 'invalid-format'
  | 'private-material'
  | 'wrong-network'
  | 'missing-payment'
  | 'missing-ordinals'
  | 'conflicting-account'
  | 'unsupported-policy'
  | 'invalid-checksum'
  | 'limit-exceeded';

export class PublicAccountInterchangeError extends Error {
  constructor(readonly code: PublicAccountInterchangeErrorCode, message: string) {
    super(message);
    this.name = 'PublicAccountInterchangeError';
  }
}

export interface PublicAccountInterchangeCandidate {
  format: PublicAccountInterchangeFormat;
  definition: PublicAccountDefinitionV1;
  suggestedName?: string;
}

export interface PublicAccountKeyInput {
  network: Network;
  masterFingerprintHex: string;
  accountIndex: number;
  paymentAccountXpub: string;
  ordinalsAccountXpub: string;
}

type CborValue = number | string | boolean | Uint8Array | CborValue[] |
  Map<number, CborValue> | { tag: number; value: CborValue };

function fail(code: PublicAccountInterchangeErrorCode, message: string): never {
  throw new PublicAccountInterchangeError(code, message);
}

function normalizeError(error: unknown): never {
  if (error instanceof PublicAccountInterchangeError) throw error;
  const message = error instanceof Error ? error.message : 'invalid public account data';
  if (/network/u.test(message)) fail('wrong-network', message);
  if (/checksum/u.test(message)) fail('invalid-checksum', message);
  if (/private|xprv|tprv/u.test(message)) fail('private-material', message);
  if (/fingerprint|account index|one key origin|pair/u.test(message)) {
    fail('conflicting-account', message);
  }
  fail('unsupported-policy', message);
}

function concat(parts: readonly Uint8Array[]): Uint8Array {
  const result = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

function uint(value: number, major = 0): Uint8Array {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff_ffff) {
    fail('invalid-format', 'CBOR integer is outside the supported uint32 range');
  }
  const prefix = major << 5;
  if (value < 24) return Uint8Array.of(prefix | value);
  if (value <= 0xff) return Uint8Array.of(prefix | 24, value);
  if (value <= 0xffff) return Uint8Array.of(prefix | 25, value >>> 8, value);
  return Uint8Array.of(prefix | 26, value >>> 24, value >>> 16, value >>> 8, value);
}

function bytes(value: Uint8Array): Uint8Array {
  return concat([uint(value.length, 2), value]);
}

function text(value: string): Uint8Array {
  const encoded = new TextEncoder().encode(value);
  return concat([uint(encoded.length, 3), encoded]);
}

function array(values: readonly Uint8Array[]): Uint8Array {
  return concat([uint(values.length, 4), ...values]);
}

function map(entries: readonly (readonly [number, Uint8Array])[]): Uint8Array {
  return concat([uint(entries.length, 5), ...entries.flatMap(([key, value]) => [uint(key), value])]);
}

function tag(value: number, body: Uint8Array): Uint8Array {
  return concat([uint(value, 6), body]);
}

function uint32Hex(value: number): string {
  return value.toString(16).padStart(8, '0');
}

function uint32FromHex(value: string): number {
  if (!/^[0-9a-f]{8}$/u.test(value)) fail('invalid-format', 'master fingerprint must be eight lowercase hex characters');
  return Number.parseInt(value, 16);
}

class CborReader {
  private offset = 0;
  private items = 0;

  constructor(private readonly input: Uint8Array) {
    if (input.length === 0 || input.length > MAX_CBOR_BYTES) {
      fail('limit-exceeded', 'account descriptor CBOR is empty or too large');
    }
  }

  read(): CborValue {
    const result = this.value(0);
    if (this.offset !== this.input.length) fail('invalid-format', 'CBOR has trailing bytes');
    return result;
  }

  private head(): { major: number; value: number } {
    const initial = this.input[this.offset++];
    if (initial === undefined) fail('invalid-format', 'CBOR is truncated');
    const major = initial >>> 5;
    const additional = initial & 31;
    if (additional < 24) return { major, value: additional };
    const width = additional === 24 ? 1 : additional === 25 ? 2 : additional === 26 ? 4 : 0;
    if (width === 0 || this.offset + width > this.input.length) {
      fail('invalid-format', 'CBOR uses an unsupported or truncated length');
    }
    let value = 0;
    for (let index = 0; index < width; index += 1) value = value * 256 + this.input[this.offset++]!;
    const minimum = width === 1 ? 24 : width === 2 ? 0x100 : 0x1_0000;
    if (value < minimum) fail('invalid-format', 'CBOR integer is not minimally encoded');
    return { major, value };
  }

  private value(depth: number): CborValue {
    this.items += 1;
    if (depth > 16 || this.items > 512) fail('limit-exceeded', 'CBOR nesting or item count is too large');
    const head = this.head();
    if (head.major === 0) return head.value;
    if (head.major === 2) {
      if (this.offset + head.value > this.input.length) fail('invalid-format', 'CBOR byte string is truncated');
      const result = this.input.slice(this.offset, this.offset + head.value);
      this.offset += head.value;
      return result;
    }
    if (head.major === 3) {
      if (this.offset + head.value > this.input.length) fail('invalid-format', 'CBOR text is truncated');
      try {
        const result = new TextDecoder('utf-8', { fatal: true })
          .decode(this.input.slice(this.offset, this.offset + head.value));
        this.offset += head.value;
        return result;
      } catch {
        fail('invalid-format', 'CBOR text is not valid UTF-8');
      }
    }
    if (head.major === 4) return Array.from({ length: head.value }, () => this.value(depth + 1));
    if (head.major === 5) {
      const result = new Map<number, CborValue>();
      let previous = -1;
      for (let index = 0; index < head.value; index += 1) {
        const key = this.value(depth + 1);
        if (typeof key !== 'number' || key <= previous) fail('invalid-format', 'CBOR map keys are not canonical unsigned integers');
        previous = key;
        result.set(key, this.value(depth + 1));
      }
      return result;
    }
    if (head.major === 6) return { tag: head.value, value: this.value(depth + 1) };
    if (head.major === 7 && (head.value === 20 || head.value === 21)) return head.value === 21;
    fail('invalid-format', 'CBOR contains an unsupported value');
  }
}

function asMap(value: CborValue, label: string): Map<number, CborValue> {
  if (!(value instanceof Map)) fail('invalid-format', `${label} must be a CBOR map`);
  return value;
}

function asArray(value: CborValue | undefined, label: string): CborValue[] {
  if (!Array.isArray(value)) fail('invalid-format', `${label} must be a CBOR array`);
  return value;
}

function asNumber(value: CborValue | undefined, label: string): number {
  if (typeof value !== 'number') fail('invalid-format', `${label} must be an unsigned integer`);
  return value;
}

function asBytes(value: CborValue | undefined, length: number, label: string): Uint8Array {
  if (!(value instanceof Uint8Array) || value.length !== length) {
    fail('invalid-format', `${label} must be ${length} bytes`);
  }
  return value;
}

function asTag(value: CborValue, expected: number, label: string): CborValue {
  if (typeof value !== 'object' || value === null || !('tag' in value) || value.tag !== expected) {
    fail('invalid-format', `${label} has the wrong CBOR tag`);
  }
  return value.value;
}

function originFromHdKey(
  value: CborValue,
  purpose: 84 | 86,
  topFingerprint: number,
  expectedNetwork: Network,
  legacy: boolean,
): { origin: PublicKeyOriginV1; accountIndex: number } {
  const hdTag = legacy ? LEGACY_TAG_HDKEY : TAG_HDKEY;
  const pathTag = legacy ? LEGACY_TAG_KEYPATH : TAG_KEYPATH;
  const coinTag = legacy ? LEGACY_TAG_COININFO : TAG_COININFO;
  const hd = asMap(asTag(value, hdTag, 'account key'), 'account key');
  if (hd.get(1) === true || hd.get(2) === true) fail('private-material', 'private or master keys are not accepted');
  const publicKey = asBytes(hd.get(3), 33, 'public key');
  const chainCode = asBytes(hd.get(4), 32, 'chain code');
  const useInfo = hd.get(5);
  let encodedMainnet = true;
  if (useInfo !== undefined) {
    const coin = asMap(asTag(useInfo, coinTag, 'coin info'), 'coin info');
    if (coin.get(1) !== undefined && asNumber(coin.get(1), 'coin type') !== 0) {
      fail('unsupported-policy', 'only Bitcoin account descriptors are accepted');
    }
    const network = coin.get(2) === undefined ? 0 : asNumber(coin.get(2), 'coin network');
    if (network !== 0 && network !== 1) fail('wrong-network', 'unsupported Bitcoin network');
    encodedMainnet = network === 0;
  }
  if (encodedMainnet !== (expectedNetwork === 'mainnet')) {
    fail('wrong-network', `This is a ${encodedMainnet ? 'mainnet' : 'test-network'} account.`);
  }
  const originValue = hd.get(6);
  if (originValue === undefined) fail('invalid-format', 'account key origin is missing');
  const keypath = asMap(asTag(originValue, pathTag, 'key origin'), 'key origin');
  const components = asArray(keypath.get(1), 'key origin components');
  if (components.length !== 6 || components[0] !== purpose || components[1] !== true ||
      components[2] !== (expectedNetwork === 'mainnet' ? 0 : 1) || components[3] !== true ||
      typeof components[4] !== 'number' || components[5] !== true) {
    fail('unsupported-policy', `BIP${purpose} account-level origin required`);
  }
  const accountIndex = components[4];
  const fingerprint = keypath.get(2) === undefined ? topFingerprint : asNumber(keypath.get(2), 'source fingerprint');
  if (fingerprint !== topFingerprint) fail('conflicting-account', 'account descriptor fingerprints differ');
  const parentFingerprint = asNumber(hd.get(8), 'parent fingerprint');
  let account: HDKey;
  try {
    account = new HDKey({
      versions: bip32Versions(expectedNetwork), depth: 3,
      index: 0x8000_0000 + accountIndex, parentFingerprint, chainCode, publicKey,
    });
  } catch {
    fail('invalid-format', 'account descriptor contains an invalid public account key');
  }
  const origin: PublicKeyOriginV1 = {
    version: 1,
    masterFingerprintHex: uint32Hex(fingerprint),
    path: `m/${purpose}'/${expectedNetwork === 'mainnet' ? 0 : 1}'/${accountIndex}'`,
    accountXpub: account.publicExtendedKey,
  };
  return { origin, accountIndex };
}

function definitionFromOrigins(
  network: Network,
  payment: { origin: PublicKeyOriginV1; accountIndex: number } | undefined,
  ordinals: { origin: PublicKeyOriginV1; accountIndex: number } | undefined,
): PublicAccountDefinitionV1 {
  if (payment === undefined) fail('missing-payment', 'Payment (BIP84) account data is missing.');
  if (ordinals === undefined) fail('missing-ordinals', 'Taproot (BIP86) account data is missing.');
  if (payment.accountIndex !== ordinals.accountIndex ||
      payment.origin.masterFingerprintHex !== ordinals.origin.masterFingerprintHex) {
    fail('conflicting-account', 'Payment and Taproot records describe different accounts.');
  }
  try {
    return parsePublicAccountDescriptors({
      network,
      paymentReceiveDescriptor: canonicalPublicDescriptor('payment', network, payment.accountIndex, payment.origin, 0),
      paymentChangeDescriptor: canonicalPublicDescriptor('payment', network, payment.accountIndex, payment.origin, 1),
      ordinalsReceiveDescriptor: canonicalPublicDescriptor('ordinals', network, ordinals.accountIndex, ordinals.origin, 0),
      ordinalsChangeDescriptor: canonicalPublicDescriptor('ordinals', network, ordinals.accountIndex, ordinals.origin, 1),
    });
  } catch (error) {
    normalizeError(error);
  }
}

export function decodeAccountDescriptor(
  input: Uint8Array,
  type: 'account-descriptor' | 'crypto-account',
  expectedNetwork: Network,
): PublicAccountInterchangeCandidate {
  const root = asMap(new CborReader(input).read(), 'account descriptor');
  const fingerprint = asNumber(root.get(1), 'master fingerprint');
  const outputs = asArray(root.get(2), 'output descriptors');
  if (outputs.length === 0 || outputs.length > 32) fail('limit-exceeded', 'account descriptor has an invalid output count');
  let payment: { origin: PublicKeyOriginV1; accountIndex: number } | undefined;
  let ordinals: { origin: PublicKeyOriginV1; accountIndex: number } | undefined;
  const legacy = type === 'crypto-account';
  for (const output of outputs) {
    if (legacy) {
      const body = asTag(output, LEGACY_TAG_OUTPUT, 'legacy output descriptor');
      if (typeof body !== 'object' || body === null || !('tag' in body)) continue;
      if (body.tag === LEGACY_TAG_WPKH) {
        if (payment !== undefined) fail('conflicting-account', 'duplicate BIP84 account record');
        payment = originFromHdKey(body.value, 84, fingerprint, expectedNetwork, true);
      } else if (body.tag === LEGACY_TAG_TR) {
        if (ordinals !== undefined) fail('conflicting-account', 'duplicate BIP86 account record');
        ordinals = originFromHdKey(body.value, 86, fingerprint, expectedNetwork, true);
      }
      continue;
    }
    const descriptor = asMap(asTag(output, TAG_ACCOUNT_DESCRIPTOR_OUTPUT, 'output descriptor'), 'output descriptor');
    const source = descriptor.get(1);
    if (source !== 'wpkh(@0)' && source !== 'tr(@0)') continue;
    const keys = asArray(descriptor.get(2), 'output descriptor keys');
    if (keys.length !== 1) fail('unsupported-policy', 'single-key account descriptor required');
    if (source === 'wpkh(@0)') {
      if (payment !== undefined) fail('conflicting-account', 'duplicate BIP84 account record');
      payment = originFromHdKey(keys[0]!, 84, fingerprint, expectedNetwork, false);
    } else {
      if (ordinals !== undefined) fail('conflicting-account', 'duplicate BIP86 account record');
      ordinals = originFromHdKey(keys[0]!, 86, fingerprint, expectedNetwork, false);
    }
  }
  return {
    format: legacy ? 'crypto-account-v1' : 'account-descriptor-v2',
    definition: definitionFromOrigins(expectedNetwork, payment, ordinals),
  };
}

function encodeHdKey(definition: PublicAccountDefinitionV1, purpose: 84 | 86): Uint8Array {
  const lane = purpose === 84 ? definition.lanes.payment : definition.lanes.ordinals;
  const account = HDKey.fromExtendedKey(lane.origin.accountXpub, bip32Versions(definition.network));
  const components = array([
    uint(purpose), Uint8Array.of(0xf5), uint(definition.network === 'mainnet' ? 0 : 1),
    Uint8Array.of(0xf5), uint(definition.derivationAccountIndex), Uint8Array.of(0xf5),
  ]);
  const keypath = tag(TAG_KEYPATH, map([
    [1, components],
    [2, uint(uint32FromHex(lane.origin.masterFingerprintHex))],
  ]));
  const entries: Array<readonly [number, Uint8Array]> = [
    [3, bytes(account.publicKey!)],
    [4, bytes(account.chainCode!)],
  ];
  if (definition.network !== 'mainnet') entries.push([5, tag(TAG_COININFO, map([[2, uint(1)]]))]);
  entries.push([6, keypath], [8, uint(account.parentFingerprint)]);
  return tag(TAG_HDKEY, map(entries));
}

/** Current BCR-2023-019 account-descriptor v2 dCBOR body (without top-level tag). */
export function encodeAccountDescriptor(definition: PublicAccountDefinitionV1): Uint8Array {
  const checked = parsePublicAccountDescriptors({
    network: definition.network,
    paymentReceiveDescriptor: definition.lanes.payment.receiveDescriptor,
    paymentChangeDescriptor: definition.lanes.payment.changeDescriptor,
    ordinalsReceiveDescriptor: definition.lanes.ordinals.receiveDescriptor,
    ordinalsChangeDescriptor: definition.lanes.ordinals.changeDescriptor,
  });
  const output = (source: string, purpose: 84 | 86) => tag(
    TAG_ACCOUNT_DESCRIPTOR_OUTPUT,
    map([[1, text(source)], [2, array([encodeHdKey(checked, purpose)])]]),
  );
  return map([
    [1, uint(uint32FromHex(checked.lanes.payment.origin.masterFingerprintHex))],
    [2, array([output('wpkh(@0)', 84), output('tr(@0)', 86)])],
  ]);
}

function expandMultipath(value: string): string[] {
  const trimmed = value.trim();
  if (!trimmed.includes('/<0;1>/*')) return [trimmed];
  const hash = trimmed.lastIndexOf('#');
  if (hash < 0) fail('invalid-checksum', 'checksummed descriptor required');
  const payload = trimmed.slice(0, hash);
  return [0, 1].map((branch) => {
    const expanded = payload.replace('/<0;1>/*', `/${branch}/*`);
    return `${expanded}#${descriptorChecksum(expanded)}`;
  });
}

function collectDescriptorStrings(value: unknown, output: string[], names: string[]): void {
  if (typeof value === 'string') return;
  if (Array.isArray(value)) {
    for (const item of value) collectDescriptorStrings(item, output, names);
    return;
  }
  if (typeof value !== 'object' || value === null) return;
  for (const [key, child] of Object.entries(value)) {
    if ((key === 'desc' || key.endsWith('Descriptor')) && typeof child === 'string') output.push(child);
    else if ((key === 'wallet_name' || key === 'name') && typeof child === 'string' && child.trim() !== '') names.push(child.trim());
    else collectDescriptorStrings(child, output, names);
  }
}

function definitionFromDescriptorStrings(values: readonly string[], network: Network): PublicAccountDefinitionV1 {
  const slots = new Map<string, string>();
  for (const raw of values.flatMap(expandMultipath)) {
    let parsed: ReturnType<typeof parsePublicDescriptor>;
    try {
      parsed = parsePublicDescriptor(raw.trim(), network);
    } catch (error) {
      normalizeError(error);
    }
    const key = `${parsed.kind}:${parsed.chain}`;
    if (slots.has(key)) fail('conflicting-account', `duplicate ${parsed.kind} ${parsed.chain === 0 ? 'receive' : 'change'} descriptor`);
    slots.set(key, parsed.descriptor);
  }
  if (!slots.has('payment:0') || !slots.has('payment:1')) fail('missing-payment', 'Payment receive and change descriptors are required.');
  if (!slots.has('ordinals:0') || !slots.has('ordinals:1')) fail('missing-ordinals', 'Taproot receive and change descriptors are required.');
  try {
    return parsePublicAccountDescriptors({
      network,
      paymentReceiveDescriptor: slots.get('payment:0')!,
      paymentChangeDescriptor: slots.get('payment:1')!,
      ordinalsReceiveDescriptor: slots.get('ordinals:0')!,
      ordinalsChangeDescriptor: slots.get('ordinals:1')!,
    });
  } catch (error) {
    normalizeError(error);
  }
}

export function definitionFromAccountKeys(input: PublicAccountKeyInput): PublicAccountDefinitionV1 {
  const fingerprint = input.masterFingerprintHex.trim().toLowerCase();
  uint32FromHex(fingerprint);
  const make = (purpose: 84 | 86, xpub: string): { origin: PublicKeyOriginV1; accountIndex: number } => {
    const origin: PublicKeyOriginV1 = {
      version: 1,
      masterFingerprintHex: fingerprint,
      path: `m/${purpose}'/${input.network === 'mainnet' ? 0 : 1}'/${input.accountIndex}'`,
      accountXpub: xpub.trim(),
    };
    // Canonical generation performs the strict public/depth/index/network checks.
    canonicalPublicDescriptor(purpose === 84 ? 'payment' : 'ordinals', input.network, input.accountIndex, origin, 0);
    return { origin, accountIndex: input.accountIndex };
  };
  try {
    return definitionFromOrigins(
      input.network,
      make(84, input.paymentAccountXpub),
      make(86, input.ordinalsAccountXpub),
    );
  } catch (error) {
    normalizeError(error);
  }
}

export function parsePublicAccountText(textInput: string, network: Network): PublicAccountInterchangeCandidate {
  if (new TextEncoder().encode(textInput).length > MAX_TEXT_BYTES) fail('limit-exceeded', 'public account document is too large');
  const textValue = textInput.trim();
  if (textValue === '') fail('invalid-format', 'public account document is empty');
  if (/(?:xprv|tprv)[1-9A-HJ-NP-Za-km-z]+/u.test(textValue)) {
    fail('private-material', 'extended private keys are not accepted');
  }
  const keyLines = textValue.split(/\r?\n/u).map((line) => line.trim()).filter(Boolean);
  if (keyLines.length === 2 && keyLines.every((line) => line.startsWith('['))) {
    const parsed = keyLines.map((line) => {
      const match = /^\[([0-9a-fA-F]{8})\/(84|86)(?:h|')\/(0|1)(?:h|')\/([0-9]+)(?:h|')\]([xt]pub[1-9A-HJ-NP-Za-km-z]+)$/u.exec(line);
      if (match === null) fail('invalid-format', 'Public key origins must contain a BIP84 or BIP86 account path.');
      return {
        fingerprint: match[1]!.toLowerCase(), purpose: Number(match[2]), coin: Number(match[3]),
        accountIndex: Number(match[4]), xpub: match[5]!,
      };
    });
    const payment = parsed.find((item) => item.purpose === 84);
    const ordinals = parsed.find((item) => item.purpose === 86);
    if (payment === undefined) fail('missing-payment', 'BIP84 payment account data is missing.');
    if (ordinals === undefined) fail('missing-ordinals', 'BIP86 Taproot account data is missing.');
    const expectedCoin = network === 'mainnet' ? 0 : 1;
    if (payment.coin !== expectedCoin || ordinals.coin !== expectedCoin) {
      fail('wrong-network', `This is a ${expectedCoin === 0 ? 'test-network' : 'mainnet'} account.`);
    }
    if (payment.fingerprint !== ordinals.fingerprint || payment.accountIndex !== ordinals.accountIndex) {
      fail('conflicting-account', 'Payment and Taproot public keys describe different accounts.');
    }
    return {
      format: 'account-key-expressions',
      definition: definitionFromAccountKeys({
        network,
        masterFingerprintHex: payment.fingerprint,
        accountIndex: payment.accountIndex,
        paymentAccountXpub: payment.xpub,
        ordinalsAccountXpub: ordinals.xpub,
      }),
    };
  }
  if (/^(?:xpub|tpub)[1-9A-HJ-NP-Za-km-z]+$/u.test(textValue)) {
    fail('invalid-format', 'A bare extended public key is ambiguous. Include both BIP84 and BIP86 account origins.');
  }
  let jsonText = textValue;
  const wrapper = /^importdescriptors\s+'([\s\S]+)'$/u.exec(textValue);
  if (wrapper !== null) jsonText = wrapper[1]!;
  const descriptors: string[] = [];
  const names: string[] = [];
  let format: PublicAccountInterchangeFormat = 'bip380-descriptors';
  try {
    const parsed = JSON.parse(jsonText) as unknown;
    collectDescriptorStrings(parsed, descriptors, names);
    format = 'bitcoin-core-json';
  } catch {
    for (const line of textValue.split(/\r?\n/u)) {
      const trimmed = line.trim();
      if (trimmed !== '' && !trimmed.startsWith('#')) descriptors.push(trimmed);
    }
  }
  if (descriptors.length === 0) fail('invalid-format', 'No supported output descriptors were found.');
  return {
    format,
    definition: definitionFromDescriptorStrings(descriptors, network),
    ...(names[0] === undefined ? {} : { suggestedName: names[0] }),
  };
}

export function bitcoinCoreDescriptorJson(definition: PublicAccountDefinitionV1): string {
  const records = [
    { desc: definition.lanes.payment.receiveDescriptor, active: true, internal: false, timestamp: 0 },
    { desc: definition.lanes.payment.changeDescriptor, active: true, internal: true, timestamp: 0 },
    { desc: definition.lanes.ordinals.receiveDescriptor, active: true, internal: false, timestamp: 0 },
    { desc: definition.lanes.ordinals.changeDescriptor, active: true, internal: true, timestamp: 0 },
  ];
  return `${JSON.stringify(records, null, 2)}\n`;
}

export function publicAccountKeyExpressions(definition: PublicAccountDefinitionV1): {
  payment: string;
  ordinals: string;
} {
  const expression = (origin: PublicKeyOriginV1) =>
    `[${origin.masterFingerprintHex}/${origin.path.slice(2).replaceAll("'", 'h')}]${origin.accountXpub}`;
  return {
    payment: expression(definition.lanes.payment.origin),
    ordinals: expression(definition.lanes.ordinals.origin),
  };
}
