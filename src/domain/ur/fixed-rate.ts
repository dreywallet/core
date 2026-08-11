/**
 * Dependency-free fixed-rate UR v2 transport (BCR-2020-005 / BCR-2024-001).
 *
 * This module deliberately stops at the specification-determined transport
 * boundary. Callers supply an already-encoded dCBOR message and a registered
 * application type. It does not invent Drey pairing payload semantics.
 *
 * Multipart output is the standard first `seqLen` MUR fountain parts: each is
 * a simple, in-order fragment and the complete set reconstructs the message.
 * Rateless parts (`seqNum > seqLen`) are recognized and refused with a typed
 * error until the consensus-stack decoder is implemented.
 */
import { crc32, decodeBytewordsMinimal, encodeBytewordsMinimal } from './bytewords';
import { UrTransportError } from './errors';

const UINT32_MAX = 0xffff_ffff;
const DEFAULT_MAX_FRAGMENT_LENGTH = 250;
const DEFAULT_MIN_FRAGMENT_LENGTH = 10;
const DEFAULT_MAX_MESSAGE_LENGTH = 1_048_576;
const DEFAULT_MAX_PARTS = 4_096;

export interface FountainPart {
  seqNum: number;
  seqLen: number;
  messageLen: number;
  checksum: number;
  data: Uint8Array;
}

function assertUint32(value: number, field: string): void {
  if (!Number.isSafeInteger(value) || value < 0 || value > UINT32_MAX) {
    throw new UrTransportError('invalid-cbor', `${field} must be a uint32`);
  }
}

function concatenate(chunks: readonly Uint8Array[]): Uint8Array {
  const length = chunks.reduce((total, chunk) => total + chunk.length, 0);
  const result = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.length;
  }
  return result;
}

function encodeHead(major: number, value: number): Uint8Array {
  assertUint32(value, 'CBOR value');
  const prefix = major << 5;
  if (value < 24) return Uint8Array.of(prefix | value);
  if (value <= 0xff) return Uint8Array.of(prefix | 24, value);
  if (value <= 0xffff) return Uint8Array.of(prefix | 25, value >>> 8, value);
  return Uint8Array.of(prefix | 26, value >>> 24, value >>> 16, value >>> 8, value);
}

function encodeUnsigned(value: number): Uint8Array {
  return encodeHead(0, value);
}

/** Deterministic CBOR for the five-field MUR fountain-part array. */
export function encodeFountainPart(part: FountainPart): Uint8Array {
  assertUint32(part.seqNum, 'seqNum');
  assertUint32(part.seqLen, 'seqLen');
  assertUint32(part.messageLen, 'messageLen');
  assertUint32(part.checksum, 'checksum');
  if (part.seqNum === 0 || part.seqLen === 0 || part.messageLen === 0 || part.data.length === 0) {
    throw new UrTransportError('invalid-cbor', 'fountain part fields must be non-zero');
  }
  assertUint32(part.data.length, 'data length');
  return concatenate([
    Uint8Array.of(0x85),
    encodeUnsigned(part.seqNum),
    encodeUnsigned(part.seqLen),
    encodeUnsigned(part.messageLen),
    encodeUnsigned(part.checksum),
    encodeHead(2, part.data.length),
    part.data,
  ]);
}

interface DecodedHead {
  major: number;
  value: number;
  nextOffset: number;
}

function decodeHead(bytes: Uint8Array, offset: number): DecodedHead {
  const initial = bytes[offset];
  if (initial === undefined) throw new UrTransportError('invalid-cbor', 'truncated CBOR head');
  const major = initial >>> 5;
  const additional = initial & 0x1f;
  if (additional < 24) return { major, value: additional, nextOffset: offset + 1 };

  const byteLength = additional === 24 ? 1 : additional === 25 ? 2 : additional === 26 ? 4 : 0;
  if (byteLength === 0 || offset + 1 + byteLength > bytes.length) {
    throw new UrTransportError('invalid-cbor', 'unsupported or truncated CBOR integer');
  }
  let value = 0;
  for (let index = 0; index < byteLength; index += 1) {
    value = value * 256 + bytes[offset + 1 + index]!;
  }
  const minimum = byteLength === 1 ? 24 : byteLength === 2 ? 0x100 : 0x1_0000;
  if (value < minimum) throw new UrTransportError('invalid-cbor', 'CBOR integer is not minimally encoded');
  return { major, value, nextOffset: offset + 1 + byteLength };
}

function decodeUnsigned(bytes: Uint8Array, offset: number, field: string): DecodedHead {
  const decoded = decodeHead(bytes, offset);
  if (decoded.major !== 0) throw new UrTransportError('invalid-cbor', `${field} must be unsigned`);
  return decoded;
}

/** Strict deterministic-CBOR parser for a MUR fountain part. */
export function decodeFountainPart(bytes: Uint8Array): FountainPart {
  if (bytes[0] !== 0x85) {
    throw new UrTransportError('invalid-cbor', 'fountain part must be a five-item CBOR array');
  }
  let offset = 1;
  const seqNum = decodeUnsigned(bytes, offset, 'seqNum');
  offset = seqNum.nextOffset;
  const seqLen = decodeUnsigned(bytes, offset, 'seqLen');
  offset = seqLen.nextOffset;
  const messageLen = decodeUnsigned(bytes, offset, 'messageLen');
  offset = messageLen.nextOffset;
  const checksum = decodeUnsigned(bytes, offset, 'checksum');
  offset = checksum.nextOffset;
  const dataLength = decodeHead(bytes, offset);
  if (dataLength.major !== 2) throw new UrTransportError('invalid-cbor', 'part data must be bytes');
  offset = dataLength.nextOffset;
  const end = offset + dataLength.value;
  if (end !== bytes.length) throw new UrTransportError('invalid-cbor', 'part data is truncated or has trailing bytes');
  if (seqNum.value === 0 || seqLen.value === 0 || messageLen.value === 0 || dataLength.value === 0) {
    throw new UrTransportError('invalid-cbor', 'fountain part fields must be non-zero');
  }
  return {
    seqNum: seqNum.value,
    seqLen: seqLen.value,
    messageLen: messageLen.value,
    checksum: checksum.value,
    data: bytes.slice(offset, end),
  };
}

export function findNominalFragmentLength(
  messageLength: number,
  minFragmentLength: number,
  maxFragmentLength: number,
): number {
  if (!Number.isSafeInteger(messageLength) || messageLength <= 0 || messageLength > UINT32_MAX) {
    throw new UrTransportError('limit-exceeded', 'message length is outside the MUR uint32 range');
  }
  if (
    !Number.isSafeInteger(minFragmentLength) ||
    !Number.isSafeInteger(maxFragmentLength) ||
    minFragmentLength <= 0 ||
    maxFragmentLength < minFragmentLength
  ) {
    throw new UrTransportError('limit-exceeded', 'fragment limits are invalid');
  }
  const maximumCount = Math.max(1, Math.floor(messageLength / minFragmentLength));
  for (let fragmentCount = 1; fragmentCount <= maximumCount; fragmentCount += 1) {
    const fragmentLength = Math.ceil(messageLength / fragmentCount);
    if (fragmentLength <= maxFragmentLength) return fragmentLength;
  }
  throw new UrTransportError('limit-exceeded', 'message cannot satisfy fragment limits');
}

function partitionMessage(message: Uint8Array, fragmentLength: number): Uint8Array[] {
  const count = Math.ceil(message.length / fragmentLength);
  const fragments: Uint8Array[] = [];
  for (let index = 0; index < count; index += 1) {
    const fragment = new Uint8Array(fragmentLength);
    fragment.set(message.slice(index * fragmentLength, (index + 1) * fragmentLength));
    fragments.push(fragment);
  }
  return fragments;
}

function normalizeType(type: string): string {
  const normalized = type.toLowerCase();
  if (!/^[a-z0-9-]+$/u.test(normalized)) {
    throw new UrTransportError('invalid-type', 'UR type must contain only letters, digits, and hyphens');
  }
  return normalized;
}

export interface FixedRateUrEncoderOptions {
  maxFragmentLength?: number;
  minFragmentLength?: number;
  maxMessageLength?: number;
  maxParts?: number;
}

/**
 * A finite, cyclic frame source for display animation. `nextFrame()` repeats
 * the complete fixed-rate sequence; reset is explicit and deterministic.
 */
export class FixedRateUrEncoder {
  readonly type: string;
  readonly frames: readonly string[];
  readonly isSinglePart: boolean;
  private nextIndex = 0;

  constructor(type: string, cborMessage: Uint8Array, options: FixedRateUrEncoderOptions = {}) {
    this.type = normalizeType(type);
    const maxMessageLength = options.maxMessageLength ?? DEFAULT_MAX_MESSAGE_LENGTH;
    const maxFragmentLength = options.maxFragmentLength ?? DEFAULT_MAX_FRAGMENT_LENGTH;
    const minFragmentLength = options.minFragmentLength ?? DEFAULT_MIN_FRAGMENT_LENGTH;
    const maxParts = options.maxParts ?? DEFAULT_MAX_PARTS;
    if (cborMessage.length === 0 || cborMessage.length > maxMessageLength) {
      throw new UrTransportError('limit-exceeded', 'UR message is empty or exceeds the configured limit');
    }

    if (cborMessage.length <= maxFragmentLength) {
      this.frames = Object.freeze([`ur:${this.type}/${encodeBytewordsMinimal(cborMessage)}`]);
      this.isSinglePart = true;
      return;
    }

    const fragmentLength = findNominalFragmentLength(
      cborMessage.length,
      minFragmentLength,
      maxFragmentLength,
    );
    const fragments = partitionMessage(cborMessage, fragmentLength);
    if (fragments.length > maxParts || fragments.length > UINT32_MAX) {
      throw new UrTransportError('limit-exceeded', 'UR sequence exceeds the configured part limit');
    }
    const checksum = crc32(cborMessage);
    this.frames = Object.freeze(
      fragments.map((data, index) => {
        const part: FountainPart = {
          seqNum: index + 1,
          seqLen: fragments.length,
          messageLen: cborMessage.length,
          checksum,
          data,
        };
        return `ur:${this.type}/${part.seqNum}-${part.seqLen}/${encodeBytewordsMinimal(encodeFountainPart(part))}`;
      }),
    );
    this.isSinglePart = false;
  }

  nextFrame(): string {
    const frame = this.frames[this.nextIndex]!;
    this.nextIndex = (this.nextIndex + 1) % this.frames.length;
    return frame;
  }

  reset(): void {
    this.nextIndex = 0;
  }
}

interface ParsedFrame {
  normalized: string;
  type: string;
  outerSeqNum?: number;
  outerSeqLen?: number;
  payload: Uint8Array;
}

function parseCanonicalPositiveInteger(value: string): number {
  if (!/^[1-9][0-9]*$/u.test(value)) {
    throw new UrTransportError('invalid-ur', 'UR sequence numbers must be canonical positive decimals');
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed > UINT32_MAX) {
    throw new UrTransportError('invalid-ur', 'UR sequence number exceeds uint32');
  }
  return parsed;
}

function parseFrame(value: string): ParsedFrame {
  if ([...value].some((character) => character.codePointAt(0)! > 0x7f)) {
    throw new UrTransportError('invalid-ur', 'UR must be ASCII');
  }
  const normalized = value.toLowerCase();
  if (!normalized.startsWith('ur:')) throw new UrTransportError('invalid-ur', 'UR scheme is missing');
  const components = normalized.slice(3).split('/');
  if (components.length !== 2 && components.length !== 3) {
    throw new UrTransportError('invalid-ur', 'UR has an invalid path component count');
  }
  const type = normalizeType(components[0]!);
  if (components.length === 2) {
    return { normalized, type, payload: decodeBytewordsMinimal(components[1]!) };
  }
  const sequence = /^([^-]+)-([^-]+)$/u.exec(components[1]!);
  if (sequence === null) throw new UrTransportError('invalid-ur', 'multipart UR sequence is invalid');
  return {
    normalized,
    type,
    outerSeqNum: parseCanonicalPositiveInteger(sequence[1]!),
    outerSeqLen: parseCanonicalPositiveInteger(sequence[2]!),
    payload: decodeBytewordsMinimal(components[2]!),
  };
}

export interface FixedRateUrDecoderOptions {
  expectedType?: string;
  maxFragmentLength?: number;
  maxMessageLength?: number;
  maxParts?: number;
}

export type UrReceiveResult =
  | { status: 'accepted'; received: number; expected: number; missing: readonly number[] }
  | { status: 'duplicate'; received: number; expected: number; missing: readonly number[] }
  | { status: 'complete'; type: string; cborMessage: Uint8Array };

interface SessionMetadata {
  type: string;
  seqLen: number;
  messageLen: number;
  checksum: number;
  fragmentLength: number;
}

function equalData(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  for (let index = 0; index < left.length; index += 1) {
    if (left[index] !== right[index]) return false;
  }
  return true;
}

export class FixedRateUrDecoder {
  private readonly expectedType: string | undefined;
  private readonly maxFragmentLength: number;
  private readonly maxMessageLength: number;
  private readonly maxParts: number;
  private metadata: SessionMetadata | undefined;
  private readonly fragments = new Map<number, Uint8Array>();
  private singleFrame: string | undefined;
  private completed: { type: string; cborMessage: Uint8Array } | undefined;

  constructor(options: FixedRateUrDecoderOptions = {}) {
    this.expectedType = options.expectedType === undefined ? undefined : normalizeType(options.expectedType);
    this.maxFragmentLength = options.maxFragmentLength ?? DEFAULT_MAX_FRAGMENT_LENGTH;
    this.maxMessageLength = options.maxMessageLength ?? DEFAULT_MAX_MESSAGE_LENGTH;
    this.maxParts = options.maxParts ?? DEFAULT_MAX_PARTS;
  }

  private missing(): number[] {
    const expected = this.metadata?.seqLen ?? 0;
    const missing: number[] = [];
    for (let seqNum = 1; seqNum <= expected; seqNum += 1) {
      if (!this.fragments.has(seqNum)) missing.push(seqNum);
    }
    return missing;
  }

  receive(value: string): UrReceiveResult {
    const frame = parseFrame(value);
    if (this.expectedType !== undefined && frame.type !== this.expectedType) {
      throw new UrTransportError('invalid-type', `expected ur:${this.expectedType}`);
    }

    if (frame.outerSeqNum === undefined || frame.outerSeqLen === undefined) {
      if (this.metadata !== undefined) {
        throw new UrTransportError('mixed-session', 'single and multipart URs cannot share a session');
      }
      if (this.singleFrame !== undefined && this.singleFrame !== frame.normalized) {
        throw new UrTransportError('mixed-session', 'different single-part UR received');
      }
      if (this.singleFrame === frame.normalized) {
        return {
          status: 'duplicate',
          received: 1,
          expected: 1,
          missing: [],
        };
      }
      if (frame.payload.length > this.maxMessageLength) {
        throw new UrTransportError('limit-exceeded', 'single-part UR exceeds the message limit');
      }
      this.singleFrame = frame.normalized;
      this.completed = { type: frame.type, cborMessage: frame.payload };
      return { status: 'complete', type: frame.type, cborMessage: frame.payload.slice() };
    }

    if (this.singleFrame !== undefined) {
      throw new UrTransportError('mixed-session', 'single and multipart URs cannot share a session');
    }
    const part = decodeFountainPart(frame.payload);
    if (part.seqNum !== frame.outerSeqNum || part.seqLen !== frame.outerSeqLen) {
      throw new UrTransportError('invalid-ur', 'outer and inner sequence metadata disagree');
    }
    if (part.seqNum > part.seqLen) {
      throw new UrTransportError(
        'unsupported-mixed-part',
        'rateless MUR parts are not supported by the fixed-rate decoder',
      );
    }
    if (
      part.seqLen > this.maxParts ||
      part.messageLen > this.maxMessageLength ||
      part.data.length > this.maxFragmentLength
    ) {
      throw new UrTransportError('limit-exceeded', 'multipart UR exceeds configured limits');
    }
    if (
      part.messageLen > part.seqLen * part.data.length ||
      part.messageLen <= (part.seqLen - 1) * part.data.length
    ) {
      throw new UrTransportError('invalid-cbor', 'message length is inconsistent with its fragments');
    }

    const candidate: SessionMetadata = {
      type: frame.type,
      seqLen: part.seqLen,
      messageLen: part.messageLen,
      checksum: part.checksum,
      fragmentLength: part.data.length,
    };
    if (this.metadata === undefined) {
      this.metadata = candidate;
    } else if (
      this.metadata.type !== candidate.type ||
      this.metadata.seqLen !== candidate.seqLen ||
      this.metadata.messageLen !== candidate.messageLen ||
      this.metadata.checksum !== candidate.checksum ||
      this.metadata.fragmentLength !== candidate.fragmentLength
    ) {
      throw new UrTransportError('mixed-session', 'multipart frame belongs to a different UR session');
    }

    const existing = this.fragments.get(part.seqNum);
    if (existing !== undefined) {
      if (!equalData(existing, part.data)) {
        throw new UrTransportError('conflicting-duplicate', 'duplicate sequence number carries different data');
      }
      return {
        status: 'duplicate',
        received: this.fragments.size,
        expected: part.seqLen,
        missing: this.missing(),
      };
    }
    this.fragments.set(part.seqNum, part.data);
    const missing = this.missing();
    if (missing.length !== 0) {
      return {
        status: 'accepted',
        received: this.fragments.size,
        expected: part.seqLen,
        missing,
      };
    }

    const chunks: Uint8Array[] = [];
    for (let seqNum = 1; seqNum <= part.seqLen; seqNum += 1) {
      chunks.push(this.fragments.get(seqNum)!);
    }
    const message = concatenate(chunks).slice(0, part.messageLen);
    if (crc32(message) !== part.checksum) {
      throw new UrTransportError('checksum-mismatch', 'reconstructed MUR message checksum does not match');
    }
    this.completed = { type: frame.type, cborMessage: message };
    return { status: 'complete', type: frame.type, cborMessage: message.slice() };
  }

  result(): { type: string; cborMessage: Uint8Array } | undefined {
    if (this.completed === undefined) return undefined;
    return { type: this.completed.type, cborMessage: this.completed.cborMessage.slice() };
  }

  reset(): void {
    this.metadata = undefined;
    this.fragments.clear();
    this.singleFrame = undefined;
    this.completed = undefined;
  }
}
