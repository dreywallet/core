import { describe, expect, it } from 'vitest';
import { deriveSafetyMode, FULL_REQUIRED } from '../../src/domain/gateway/safety-mode';
import type { Capability } from '../../src/domain/gateway/contract';

const FULL: Capability[] = [...FULL_REQUIRED, 'preview_service', 'fee_estimation', 'broadcast'];
const STANDARD: Capability[] = [
  'address_history',
  'inscription_index',
  'mempool_overlay',
  'fee_estimation',
  'broadcast',
];

describe('deriveSafetyMode (§11.3)', () => {
  it('grants Full Sat Safety with the complete detector set and eligibility', () => {
    expect(deriveSafetyMode(FULL, ['full_sat_safety', 'standard_ordinals_safety'])).toEqual({
      mode: 'full_sat_safety',
      readOnly: false,
      missingFullProtections: [],
    });
  });

  it.each(['sat_index', 'rarity', 'rune_detection', 'unsupported_asset_detection'] as const)(
    'downgrades to Standard when %s is missing, naming the absent protection',
    (missing) => {
      const caps = FULL.filter((c) => c !== missing);
      const result = deriveSafetyMode(caps, ['full_sat_safety', 'standard_ordinals_safety']);
      expect(result.mode).toBe('standard_ordinals_safety');
      expect(result.readOnly).toBe(false);
      expect(result.missingFullProtections).toEqual([missing]);
    },
  );

  it('lists every absent Full protection for the degraded banner', () => {
    const result = deriveSafetyMode(STANDARD, ['standard_ordinals_safety']);
    expect(result.mode).toBe('standard_ordinals_safety');
    expect(result.missingFullProtections).toEqual([
      'sat_index',
      'rarity',
      'rune_detection',
      'unsupported_asset_detection',
    ]);
  });

  it.each(['inscription_index', 'address_history', 'mempool_overlay'] as const)(
    'becomes read-only when %s is missing (inscription protection unreliable)',
    (missing) => {
      const caps = STANDARD.filter((c) => c !== missing);
      const result = deriveSafetyMode(caps, ['full_sat_safety', 'standard_ordinals_safety']);
      expect(result.mode).toBeNull();
      expect(result.readOnly).toBe(true);
    },
  );

  it('never up-grants past the server-declared eligible modes (§6.2)', () => {
    const result = deriveSafetyMode(FULL, ['standard_ordinals_safety']);
    expect(result.mode).toBe('standard_ordinals_safety');
  });

  it('is read-only when the server declares no eligible mode at all', () => {
    const result = deriveSafetyMode(FULL, []);
    expect(result.mode).toBeNull();
    expect(result.readOnly).toBe(true);
  });
});
