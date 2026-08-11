import { UrTransportError } from './errors';

const UINT32_MAX = 0xffff_ffff;

function head(major: number, value: number): Uint8Array {
  if (!Number.isSafeInteger(value) || value < 0 || value > UINT32_MAX) {
    throw new UrTransportError('limit-exceeded', 'CBOR byte-string length exceeds uint32');
  }
  const prefix = major << 5;
  if (value < 24) return Uint8Array.of(prefix | value);
  if (value <= 0xff) return Uint8Array.of(prefix | 24, value);
  if (value <= 0xffff) return Uint8Array.of(prefix | 25, value >>> 8, value);
  return Uint8Array.of(prefix | 26, value >>> 24, value >>> 16, value >>> 8, value);
}

/** Encode the untagged deterministic CBOR byte string used by registry byte types. */
export function encodeCborBytes(payload: Uint8Array): Uint8Array {
  const encoded = new Uint8Array(head(2, payload.length).length + payload.length);
  const prefix = head(2, payload.length);
  encoded.set(prefix);
  encoded.set(payload, prefix.length);
  return encoded;
}

/** Strictly decode one minimally encoded, definite-length CBOR byte string. */
export function decodeCborBytes(encoded: Uint8Array): Uint8Array {
  const initial = encoded[0];
  if (initial === undefined || initial >>> 5 !== 2) {
    throw new UrTransportError('invalid-cbor', 'expected one CBOR byte string');
  }
  const additional = initial & 0x1f;
  let length: number;
  let offset: number;
  if (additional < 24) {
    length = additional;
    offset = 1;
  } else {
    const width = additional === 24 ? 1 : additional === 25 ? 2 : additional === 26 ? 4 : 0;
    if (width === 0 || encoded.length < 1 + width) {
      throw new UrTransportError('invalid-cbor', 'unsupported or truncated CBOR byte string');
    }
    length = 0;
    for (let index = 0; index < width; index += 1) length = length * 256 + encoded[1 + index]!;
    const minimum = width === 1 ? 24 : width === 2 ? 0x100 : 0x1_0000;
    if (length < minimum) throw new UrTransportError('invalid-cbor', 'CBOR length is not minimal');
    offset = 1 + width;
  }
  if (offset + length !== encoded.length) {
    throw new UrTransportError('invalid-cbor', 'CBOR byte string is truncated or has trailing bytes');
  }
  return encoded.slice(offset);
}
