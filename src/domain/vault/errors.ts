export type VaultErrorCode =
  | 'wrong-password'
  | 'decrypt-failed'
  | 'tampered'
  | 'unsupported-version'
  | 'crypto-provider-not-initialized'
  | 'weak-password'
  // Passkey envelope rejections (ADR 0007 §5 / Workstream A1).
  | 'identity-mismatch'
  | 'invalid-prf-output'
  | 'duplicate-credential';

export class VaultError extends Error {
  readonly code: VaultErrorCode;

  constructor(code: VaultErrorCode, message?: string) {
    super(message ?? code);
    this.name = 'VaultError';
    this.code = code;
  }
}
