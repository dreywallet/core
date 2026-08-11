/**
 * App password policy (spec §7.2): minimum 12 Unicode characters, no other
 * rules — all-digit PINs are fine. NFKD normalization is an internal
 * byte-determinism measure (matching BIP39's normalization form) so the same
 * typed password always derives the same key; it is not a user-facing rule.
 */
export const MIN_PASSWORD_LENGTH = 12;

export function normalizePassword(password: string): string {
  return password.normalize('NFKD');
}

export function checkPasswordPolicy(
  password: string,
): { ok: true } | { ok: false; reason: 'too-short' } {
  const codePoints = [...normalizePassword(password)];
  return codePoints.length >= MIN_PASSWORD_LENGTH ? { ok: true } : { ok: false, reason: 'too-short' };
}
