import { describe, expect, it } from 'vitest';
import { canonicalTaprootSignatureSighash } from '../../src/domain/transactions/taproot-signature';

describe('canonical Taproot signatures', () => {
  it('accepts implicit DEFAULT and non-zero explicit sighashes', () => {
    expect(canonicalTaprootSignatureSighash(new Uint8Array(64))).toBe(0);
    expect(canonicalTaprootSignatureSighash(new Uint8Array([...new Uint8Array(64), 1]))).toBe(1);
  });

  it('rejects explicitly encoded DEFAULT and malformed lengths', () => {
    expect(canonicalTaprootSignatureSighash(new Uint8Array(65))).toBeNull();
    expect(canonicalTaprootSignatureSighash(new Uint8Array(63))).toBeNull();
    expect(canonicalTaprootSignatureSighash(new Uint8Array(66))).toBeNull();
  });
});
