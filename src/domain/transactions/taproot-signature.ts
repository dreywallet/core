/** Decode only canonical BIP340 witness signatures.
 *
 * A 64-byte signature implies SIGHASH_DEFAULT. When a sighash byte is
 * present, BIP341 requires it to be non-zero; explicitly encoding DEFAULT is
 * non-canonical and must not be normalized by callers.
 */
export function canonicalTaprootSignatureSighash(signature: Uint8Array): number | null {
  if (signature.length === 64) return 0;
  if (signature.length !== 65 || signature[64] === 0) return null;
  return signature[64]!;
}
