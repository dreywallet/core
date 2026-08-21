/**
 * BIP 321 bitcoin: payment instructions.
 *
 * Parsing is deliberately syntactic and platform-free. Payment alternatives
 * stay ordered and unselected; callers must explicitly choose a method they
 * support. Drey currently selects only the ordinary on-chain path fallback.
 */
import type { Network } from '../keys/derivation';
import { satsToBtcDecimal, type Sats } from '../sats';
import {
  resolvePayableAddress,
  type ResolvedPayableAddress,
} from '../transactions/native-send';

export const BIP321_LIMITS = {
  uriBytes: 8 * 1024,
  addressBytes: 128,
  parameterCount: 64,
  keyBytes: 64,
  amountBytes: 32,
  labelBytes: 256,
  messageBytes: 1024,
  alternativeValueBytes: 4 * 1024,
} as const;

const SCHEME = 'bitcoin:';
const encoder = new TextEncoder();
const RAW_QUERY_CHAR = /^[A-Za-z0-9\-._~!$'()*+,;:@/?]$/u;
const DECODED_KEY = /^[A-Za-z0-9\-._~!$'()*+,;:@/?]+$/u;
const ADDRESS_BODY = /^[A-Za-z0-9]+$/u;
const AMOUNT = /^[0-9]+(?:\.([0-9]{1,8}))?$/u;
const MAX_SATS = 21_000_000n * 100_000_000n;

export interface Bip321BuildParams {
  address: string;
  amountSats?: Sats;
  label?: string;
  message?: string;
}

export interface Bip321OnchainFallback {
  kind: 'onchain';
  source: 'path';
  address: string;
}

export interface Bip321PaymentAlternative {
  /** Lower-case, decoded query key. */
  key: string;
  /** Strictly UTF-8/percent-decoded value. Empty values remain explicit. */
  value: string;
}

export interface ParsedBip321 {
  onchainFallback?: Bip321OnchainFallback;
  alternatives: Bip321PaymentAlternative[];
  amountSats?: Sats;
  label?: string;
  message?: string;
}

export type Bip321FallbackSelection =
  | { ok: true; value: ResolvedPayableAddress }
  | {
      ok: false;
      reason:
        | 'no_supported_payment_method'
        | 'invalid_address'
        | 'wrong_network'
        | 'unsupported_output_type';
    };

function byteLength(value: string): number {
  return encoder.encode(value).byteLength;
}

function assertByteLimit(value: string, maximum: number, field: string): void {
  if (byteLength(value) > maximum) {
    throw new RangeError(`BIP321 ${field} exceeds ${maximum} UTF-8 bytes`);
  }
}

function assertNoControls(value: string, field: string): void {
  for (const char of value) {
    const point = char.codePointAt(0);
    if (point === undefined || point <= 0x1f || point === 0x7f) {
      throw new RangeError(`BIP321 ${field} contains a control character`);
    }
  }
}

function validateRawQueryComponent(raw: string, field: string): void {
  for (let index = 0; index < raw.length; index += 1) {
    const char = raw[index];
    if (char === '%') {
      const escape = raw.slice(index + 1, index + 3);
      if (!/^[0-9A-Fa-f]{2}$/u.test(escape)) {
        throw new RangeError(`BIP321 ${field} contains malformed percent encoding`);
      }
      index += 2;
      continue;
    }
    if (char === undefined || !RAW_QUERY_CHAR.test(char)) {
      throw new RangeError(`BIP321 ${field} contains a character that must be percent-encoded`);
    }
  }
}

function decodeQueryComponent(raw: string, maximum: number, field: string): string {
  validateRawQueryComponent(raw, field);
  let decoded: string;
  try {
    decoded = decodeURIComponent(raw);
  } catch {
    throw new RangeError(`BIP321 ${field} is not valid percent-encoded UTF-8`);
  }
  assertByteLimit(decoded, maximum, field);
  assertNoControls(decoded, field);
  return decoded;
}

function parseAmount(value: string): Sats {
  assertByteLimit(value, BIP321_LIMITS.amountBytes, 'amount');
  const match = AMOUNT.exec(value);
  if (!match) throw new RangeError(`invalid BIP321 amount: ${JSON.stringify(value)}`);
  const [whole = '0', fraction = ''] = value.split('.');
  const sats = BigInt(whole) * 100_000_000n + BigInt(fraction.padEnd(8, '0'));
  if (sats > MAX_SATS) throw new RangeError(`BIP321 amount exceeds total supply: ${value}`);
  return sats;
}

function validateAddressBody(address: string): void {
  assertByteLimit(address, BIP321_LIMITS.addressBytes, 'address');
  if (!ADDRESS_BODY.test(address)) throw new RangeError('invalid BIP321 address body');
}

/** Build the canonical ordinary on-chain subset of a BIP 321 URI. */
export function buildBip321(params: Bip321BuildParams): string {
  validateAddressBody(params.address);
  const query: string[] = [];
  if (params.amountSats !== undefined) {
    query.push(`amount=${satsToBtcDecimal(params.amountSats)}`);
  }
  if (params.label !== undefined && params.label !== '') {
    assertByteLimit(params.label, BIP321_LIMITS.labelBytes, 'label');
    assertNoControls(params.label, 'label');
    query.push(`label=${encodeURIComponent(params.label)}`);
  }
  if (params.message !== undefined && params.message !== '') {
    assertByteLimit(params.message, BIP321_LIMITS.messageBytes, 'message');
    assertNoControls(params.message, 'message');
    query.push(`message=${encodeURIComponent(params.message)}`);
  }
  const uri = query.length === 0
    ? `${SCHEME}${params.address}`
    : `${SCHEME}${params.address}?${query.join('&')}`;
  assertByteLimit(uri, BIP321_LIMITS.uriBytes, 'URI');
  return uri;
}

/** Parse BIP 321 without choosing or semantically interpreting alternatives. */
export function parseBip321(uri: string): ParsedBip321 {
  assertByteLimit(uri, BIP321_LIMITS.uriBytes, 'URI');
  if (uri.slice(0, SCHEME.length).toLowerCase() !== SCHEME) {
    throw new RangeError('not a bitcoin: URI');
  }
  if (uri.includes('#')) throw new RangeError('BIP321 URI fragments are not supported');

  const rest = uri.slice(SCHEME.length);
  const queryStart = rest.indexOf('?');
  const address = queryStart === -1 ? rest : rest.slice(0, queryStart);
  if (address !== '') validateAddressBody(address);

  const result: ParsedBip321 = {
    ...(address === ''
      ? {}
      : { onchainFallback: { kind: 'onchain' as const, source: 'path' as const, address } }),
    alternatives: [],
  };
  if (queryStart === -1) {
    if (!result.onchainFallback) throw new RangeError('BIP321 URI has no payment instructions');
    return result;
  }

  const parameters = rest.slice(queryStart + 1).split('&');
  if (parameters.length > BIP321_LIMITS.parameterCount) {
    throw new RangeError(`BIP321 URI has more than ${BIP321_LIMITS.parameterCount} parameters`);
  }
  const seen = new Set<'amount' | 'label' | 'message' | 'pop'>();
  for (const parameter of parameters) {
    if (parameter === '') continue;
    const equals = parameter.indexOf('=');
    const rawKey = equals === -1 ? parameter : parameter.slice(0, equals);
    const rawValue = equals === -1 ? '' : parameter.slice(equals + 1);
    if (rawKey === '') throw new RangeError('BIP321 query parameter has no key');
    if (rawValue.includes('=')) {
      throw new RangeError('BIP321 query value contains an unencoded separator');
    }
    const decodedKey = decodeQueryComponent(rawKey, BIP321_LIMITS.keyBytes, 'query key');
    if (!DECODED_KEY.test(decodedKey)) throw new RangeError('BIP321 query key is invalid');
    const key = decodedKey.toLowerCase();
    const required = key.startsWith('req-');
    const baseKey = required ? key.slice(4) : key;

    if (required && !['amount', 'label', 'message'].includes(baseKey)) {
      throw new RangeError(`unsupported required BIP321 parameter: ${key}`);
    }

    if (baseKey === 'amount') {
      if (seen.has('amount')) throw new RangeError('duplicate BIP321 parameter: amount');
      seen.add('amount');
      if (equals === -1) throw new RangeError('BIP321 amount has no value');
      const value = decodeQueryComponent(rawValue, BIP321_LIMITS.amountBytes, 'amount');
      result.amountSats = parseAmount(value);
      continue;
    }
    if (baseKey === 'label') {
      if (seen.has('label')) throw new RangeError('duplicate BIP321 parameter: label');
      seen.add('label');
      if (equals === -1) throw new RangeError('BIP321 label has no value');
      result.label = decodeQueryComponent(rawValue, BIP321_LIMITS.labelBytes, 'label');
      continue;
    }
    if (baseKey === 'message') {
      if (seen.has('message')) throw new RangeError('duplicate BIP321 parameter: message');
      seen.add('message');
      if (equals === -1) throw new RangeError('BIP321 message has no value');
      result.message = decodeQueryComponent(rawValue, BIP321_LIMITS.messageBytes, 'message');
      continue;
    }
    if (baseKey === 'pop') {
      if (seen.has('pop')) throw new RangeError('duplicate BIP321 parameter: pop');
      seen.add('pop');
      if (equals === -1) throw new RangeError('BIP321 pop has no value');
      // Validate encoding and bounds, then deliberately discard. Drey never
      // opens or invokes proof-of-payment callbacks.
      decodeQueryComponent(rawValue, BIP321_LIMITS.alternativeValueBytes, 'pop');
      continue;
    }

    const value = decodeQueryComponent(
      rawValue,
      BIP321_LIMITS.alternativeValueBytes,
      'payment alternative',
    );
    result.alternatives.push({ key, value });
  }

  if (!result.onchainFallback && !result.alternatives.some(({ value }) => value !== '')) {
    throw new RangeError('BIP321 URI has no payment instructions');
  }
  return result;
}

/** Select only Drey's supported ordinary on-chain path fallback. */
export function selectBip321OnchainFallback(
  parsed: ParsedBip321,
  network: Network,
): Bip321FallbackSelection {
  const address = parsed.onchainFallback?.address;
  if (!address) return { ok: false, reason: 'no_supported_payment_method' };
  const current = resolvePayableAddress(address, network);
  if (current.ok) return current;
  if (current.reason === 'unsupported_output_type') return current;

  for (const otherNetwork of (['mainnet', 'signet', 'regtest'] as const).filter((candidate) => candidate !== network)) {
    const other = resolvePayableAddress(address, otherNetwork);
    if (other.ok || other.reason === 'unsupported_output_type') {
      return { ok: false, reason: 'wrong_network' };
    }
  }
  return { ok: false, reason: 'invalid_address' };
}

/** Exact BIP 321 amount parsing, exported for conformance consumers. */
export function bip321AmountToSats(value: string): Sats {
  return parseAmount(value);
}
