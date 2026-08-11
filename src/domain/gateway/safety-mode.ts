/**
 * §11.3 backend safety-mode derivation.
 *
 * Full Sat Safety needs the complete detector set; Standard Ordinals Safety
 * needs the inscription-protecting core; anything less is read-only. A mode
 * is granted only when both the capability set supports it AND the server
 * declares itself eligible — the client never up-grants beyond the server's
 * own claim (§6.2), because the gateway knows about degradation the
 * capability list alone may not express.
 */
import type { Capability, SafetyMode } from './contract';

export const FULL_REQUIRED: readonly Capability[] = [
  'address_history',
  'inscription_index',
  'sat_index',
  'rarity',
  'rune_detection',
  'unsupported_asset_detection',
  'mempool_overlay',
];

export const STANDARD_REQUIRED: readonly Capability[] = [
  'address_history',
  'inscription_index',
  'mempool_overlay',
];

export interface SafetyDerivation {
  /** null means neither mode qualifies: the wallet is read-only (§11.3). */
  mode: SafetyMode | null;
  readOnly: boolean;
  /**
   * Full-mode capabilities absent in Standard mode — the protections the
   * degraded banner and every transaction review must name (§11.3).
   */
  missingFullProtections: Capability[];
}

export function deriveSafetyMode(
  capabilities: readonly Capability[],
  eligibleSafetyModes: readonly SafetyMode[],
): SafetyDerivation {
  const has = (c: Capability) => capabilities.includes(c);
  const missingFullProtections = FULL_REQUIRED.filter((c) => !has(c));

  const fullCapable = missingFullProtections.length === 0;
  const standardCapable = STANDARD_REQUIRED.every(has);

  const mode: SafetyMode | null =
    fullCapable && eligibleSafetyModes.includes('full_sat_safety')
      ? 'full_sat_safety'
      : standardCapable && eligibleSafetyModes.includes('standard_ordinals_safety')
        ? 'standard_ordinals_safety'
        : null;

  return {
    mode,
    readOnly: mode === null,
    missingFullProtections: mode === 'full_sat_safety' ? [] : missingFullProtections,
  };
}
