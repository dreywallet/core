import type { FeeQuoteResponse } from '../gateway/contract';

export const FEE_QUOTE_MAX_AGE_MS = 120_000;
export const FEE_QUOTE_MAX_FUTURE_SKEW_MS = 5_000;
export const MAX_FEE_RATE_SAT_PER_KVB = 10_000_000;
export const MIN_CUSTOM_FEE_RATE_SAT_PER_KVB = 1_000;
export const CUSTOM_FEE_RATE_DECIMAL_PLACES = 3;
export const DEFAULT_POSTAGE_SATS = 10_000n;
export const RBF_SEQUENCE = 0xfffffffd;
export const FINAL_SEQUENCE = 0xffffffff;

export type CustomFeeRateErrorCode = 'syntax' | 'precision' | 'below_minimum' | 'above_maximum';

export class CustomFeeRateError extends Error {
  constructor(readonly code: CustomFeeRateErrorCode) {
    super(`invalid custom fee rate: ${code}`);
    this.name = 'CustomFeeRateError';
  }
}

export interface ParsedCustomFeeRate {
  /** Canonical sat/vB text with no unnecessary fractional zeroes. */
  normalizedSatPerVb: string;
  /** Exact transaction authority. */
  satPerKvB: bigint;
}

/**
 * Parse user-entered sat/vB exactly into integer sat/kvB.
 *
 * No floating-point value is ever constructed. Three fractional digits are
 * the complete precision of sat/kvB, and the established 1..10,000 sat/vB
 * custom-fee policy remains unchanged.
 */
export function parseCustomFeeRate(text: string): ParsedCustomFeeRate {
  if (typeof text !== 'string' || text.length === 0 || text.length > 32) {
    throw new CustomFeeRateError('syntax');
  }
  const match = /^(0|[1-9][0-9]*)(?:\.([0-9]+))?$/u.exec(text);
  if (!match || match[1] === undefined) throw new CustomFeeRateError('syntax');
  const fraction = match[2] ?? '';
  if (fraction.length > CUSTOM_FEE_RATE_DECIMAL_PLACES) {
    throw new CustomFeeRateError('precision');
  }
  const satPerKvB = BigInt(match[1]) * 1_000n + BigInt(fraction.padEnd(3, '0') || '0');
  if (satPerKvB < BigInt(MIN_CUSTOM_FEE_RATE_SAT_PER_KVB)) {
    throw new CustomFeeRateError('below_minimum');
  }
  if (satPerKvB > BigInt(MAX_FEE_RATE_SAT_PER_KVB)) {
    throw new CustomFeeRateError('above_maximum');
  }
  return { normalizedSatPerVb: formatFeeRateSatPerVb(satPerKvB), satPerKvB };
}

/** Exact inverse display for integer sat/kvB; never rounds meaningful precision away. */
export function formatFeeRateSatPerVb(rateSatPerKvB: bigint): string {
  if (rateSatPerKvB <= 0n || rateSatPerKvB > BigInt(MAX_FEE_RATE_SAT_PER_KVB)) {
    throw new RangeError('invalid fee rate');
  }
  const whole = rateSatPerKvB / 1_000n;
  const fraction = (rateSatPerKvB % 1_000n).toString().padStart(3, '0').replace(/0+$/u, '');
  return fraction.length === 0 ? whole.toString() : `${whole}.${fraction}`;
}

type SequencePolicyKind =
  | 'native_send'
  | 'ordinal_transfer'
  | 'consolidation'
  | 'rbf'
  | 'cpfp'
  | 'rescue'
  | 'ordinal_sweep';

/** Central sequence policy shared by all plan builders and regression tests. */
export function sequenceForInput(kind: SequencePolicyKind, originalSequence?: number): number {
  if (kind === 'ordinal_transfer' || kind === 'rescue' || kind === 'ordinal_sweep') {
    return FINAL_SEQUENCE;
  }
  if (kind === 'rbf' && originalSequence !== undefined) return originalSequence;
  return RBF_SEQUENCE;
}

/**
 * Script types the wallet can *spend*. Deliberately only the two it derives:
 * every wallet input is P2WPKH (payment lane) or key-path P2TR (ordinals lane),
 * so input sizing and sighash policy never have to reason about anything else.
 * Paying someone else's address is a separate question -- see payableScriptKind.
 */
export type ScriptKind = 'p2wpkh' | 'p2tr';

export function scriptKind(scriptPubKey: string): ScriptKind {
  if (/^0014[0-9a-f]{40}$/.test(scriptPubKey)) return 'p2wpkh';
  if (/^5120[0-9a-f]{64}$/.test(scriptPubKey)) return 'p2tr';
  throw new Error('unsupported script type');
}

/** Conservative finalized virtual bytes for the two wallet-owned input types. */
export function inputVbytes(scriptPubKey: string): bigint {
  return scriptKind(scriptPubKey) === 'p2wpkh' ? 68n : 58n;
}

/**
 * Script types the wallet will pay *to*. Broader than ScriptKind because the
 * recipient picks their own address and we do not have to spend it: a peer
 * wallet's nested-SegWit `3...` payment address, or an exchange's legacy
 * deposit address, are ordinary destinations. estimateVsize already measures
 * output scripts from their own length, so only the dust floor is per-kind.
 */
export type PayableScriptKind = ScriptKind | 'p2wsh' | 'p2sh' | 'p2pkh';

export function payableScriptKind(scriptPubKey: string): PayableScriptKind {
  if (/^0014[0-9a-f]{40}$/.test(scriptPubKey)) return 'p2wpkh';
  if (/^5120[0-9a-f]{64}$/.test(scriptPubKey)) return 'p2tr';
  if (/^0020[0-9a-f]{64}$/.test(scriptPubKey)) return 'p2wsh';
  if (/^a914[0-9a-f]{40}87$/.test(scriptPubKey)) return 'p2sh';
  if (/^76a914[0-9a-f]{40}88ac$/.test(scriptPubKey)) return 'p2pkh';
  throw new Error('unsupported script type');
}

/**
 * Bitcoin Core's dust floor at the default 3000 sat/kvB dustrelayfee: three
 * times the serialized output plus the bytes needed to spend it (+67 witness,
 * +148 non-witness). A legacy output costs more to spend, so its floor is
 * higher -- sending 400 sats to a `1...` address is unrelayable even though the
 * same amount is fine to a bech32 address.
 */
const DUST_SATS: Readonly<Record<PayableScriptKind, bigint>> = {
  p2wpkh: 294n,
  p2tr: 330n,
  p2wsh: 330n,
  p2sh: 540n,
  p2pkh: 546n,
};

export function scriptDustSats(scriptPubKey: string): bigint {
  return DUST_SATS[payableScriptKind(scriptPubKey)];
}

export function economicChangeThreshold(scriptPubKey: string, feeRateSatPerKvB: bigint): bigint {
  const futureSpend = feeForVsize(inputVbytes(scriptPubKey), feeRateSatPerKvB);
  const dust = scriptDustSats(scriptPubKey);
  return futureSpend > dust ? futureSpend : dust;
}

function compactSizeBytes(value: number): bigint {
  if (!Number.isSafeInteger(value) || value < 0) throw new RangeError('invalid compact size');
  if (value < 0xfd) return 1n;
  if (value <= 0xffff) return 3n;
  if (value <= 0xffffffff) return 5n;
  return 9n;
}

function witnessBytes(scriptPubKey: string): bigint {
  // Includes stack count and compact item lengths. P2WPKH uses the maximum
  // low-R DER+sighash witness accepted by the signer; key-path Taproot DEFAULT
  // is fixed at 64 bytes.
  return scriptKind(scriptPubKey) === 'p2wpkh' ? 108n : 66n;
}

export function estimateVsize(
  inputScripts: readonly string[],
  outputScripts: readonly string[],
): bigint {
  if (inputScripts.length === 0 || outputScripts.length === 0) {
    throw new RangeError('transaction requires inputs and outputs');
  }
  const strippedBytes =
    8n + // version + locktime
    compactSizeBytes(inputScripts.length) +
    compactSizeBytes(outputScripts.length) +
    41n * BigInt(inputScripts.length) +
    outputScripts.reduce((sum, script) => {
      const scriptBytes = BigInt((script.length / 2));
      return sum + 8n + compactSizeBytes(Number(scriptBytes)) + scriptBytes;
    }, 0n);
  const witnessWeight = 2n + inputScripts.reduce((sum, script) => sum + witnessBytes(script), 0n);
  const weight = strippedBytes * 4n + witnessWeight;
  return (weight + 3n) / 4n;
}

export function feeForVsize(vsize: bigint, feeRateSatPerKvB: bigint): bigint {
  if (vsize <= 0n || feeRateSatPerKvB <= 0n || feeRateSatPerKvB > BigInt(MAX_FEE_RATE_SAT_PER_KVB)) {
    throw new RangeError('invalid fee inputs');
  }
  return (vsize * feeRateSatPerKvB + 999n) / 1000n;
}

export function validateAutomaticQuote(quote: FeeQuoteResponse, nowMs: number): void {
  const age = nowMs - Date.parse(quote.sampledAt);
  if (!Number.isFinite(age) || age < -FEE_QUOTE_MAX_FUTURE_SKEW_MS || age > FEE_QUOTE_MAX_AGE_MS) {
    throw new Error('fee quote stale');
  }
  // An unparseable expiresAt yields NaN, and `nowMs > NaN` is false — the expiry
  // check would pass silently. Guard it the same way `age` is guarded above.
  const expiresAt = Date.parse(quote.expiresAt);
  if (
    !Number.isFinite(expiresAt) ||
    nowMs > expiresAt ||
    quote.ageSeconds > FEE_QUOTE_MAX_AGE_MS / 1_000 ||
    quote.tiers.some((tier) => tier.effectiveSatPerKvB > MAX_FEE_RATE_SAT_PER_KVB)
  ) {
    throw new Error('fee quote unsafe');
  }
}

export function quoteTier(quote: FeeQuoteResponse, target: 2 | 6 | 12) {
  const tier = quote.tiers.find((candidate) => candidate.target === target);
  if (!tier) throw new Error('fee target unavailable');
  return tier;
}
