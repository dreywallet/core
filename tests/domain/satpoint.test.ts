import { describe, expect, it } from 'vitest';
import { primaryInscriptionForPreview } from '../../src/domain/ordinals/satpoint';

const TXID = 'a'.repeat(64);

describe('primaryInscriptionForPreview', () => {
  it('selects the lowest output offset regardless of input order', () => {
    const later = { inscriptionId: `${'b'.repeat(64)}i0`, satpoint: `${TXID}:0:99` };
    const first = { inscriptionId: `${'c'.repeat(64)}i0`, satpoint: `${TXID}:0:2` };
    expect(primaryInscriptionForPreview([later, first])).toBe(first);
  });

  it('uses inscription id as the stable tie-break', () => {
    const highId = { inscriptionId: `${'f'.repeat(64)}i0`, satpoint: `${TXID}:0:2` };
    const lowId = { inscriptionId: `${'0'.repeat(64)}i0`, satpoint: `${TXID}:0:2` };
    expect(primaryInscriptionForPreview([highId, lowId])).toBe(lowId);
  });

  it('places invalid satpoints after valid ones and still behaves deterministically', () => {
    const invalidHigh = { inscriptionId: 'z', satpoint: 'invalid' };
    const invalidLow = { inscriptionId: 'a', satpoint: 'also-invalid' };
    const valid = { inscriptionId: 'm', satpoint: `${TXID}:0:3` };
    expect(primaryInscriptionForPreview([invalidHigh, valid, invalidLow])).toBe(valid);
    expect(primaryInscriptionForPreview([invalidHigh, invalidLow])).toBe(invalidLow);
  });

  it('returns null for an empty coin', () => {
    expect(primaryInscriptionForPreview([])).toBeNull();
  });
});
