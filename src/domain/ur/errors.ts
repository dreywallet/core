/** Typed failures at the untrusted optical-transport boundary. */
export type UrTransportErrorCode =
  | 'invalid-bytewords'
  | 'checksum-mismatch'
  | 'invalid-ur'
  | 'invalid-type'
  | 'invalid-cbor'
  | 'unsupported-mixed-part'
  | 'mixed-session'
  | 'conflicting-duplicate'
  | 'limit-exceeded';

export class UrTransportError extends Error {
  constructor(
    readonly code: UrTransportErrorCode,
    message: string,
  ) {
    super(message);
    this.name = 'UrTransportError';
  }
}
