/** fast-check arbitraries for the §11 classification domain tests. */
import fc from 'fast-check';
import type { FreshnessReport } from '../../src/domain/gateway/freshness';
import type { EligibilityContext } from '../../src/domain/classification/eligibility';
import type { AssetFacts, WalletUtxo } from '../../src/domain/classification/types';

export const hex64 = fc
  .array(fc.integer({ min: 0, max: 15 }), { minLength: 64, maxLength: 64 })
  .map((digits) => digits.map((d) => d.toString(16)).join(''));

export const primaryClassArb = fc.constantFrom(
  'cardinal_clean',
  'inscribed',
  'rare_sat',
  'runic_or_unsupported',
  'mixed',
  'unknown',
) as fc.Arbitrary<AssetFacts['primaryClass']>;

export const factsArb: fc.Arbitrary<AssetFacts> = fc.record({
  primaryClass: primaryClassArb,
  inscriptions: fc.array(
    fc.record({
      inscriptionId: fc
        .array(fc.integer({ min: 0, max: 15 }), { minLength: 4, maxLength: 8 })
        .map((digits) => `${digits.map((d) => d.toString(16)).join('')}i0`),
      satpoint: fc.constant('deadbeef:0:0'),
    }),
    { maxLength: 3 },
  ),
  satRanges: fc.constant(null),
  unsupportedAssetDetected: fc.boolean(),
  confidence: fc.constantFrom('authoritative', 'degraded') as fc.Arbitrary<
    AssetFacts['confidence']
  >,
  classifiedTip: fc.constant({ height: 100, hash: 'a'.repeat(64) }),
  classificationRevision: fc.constantFrom('rev-0001', 'rev-0000'),
});

export const utxoArb: fc.Arbitrary<WalletUtxo> = fc.record({
  outpoint: fc.record({ txid: hex64, vout: fc.nat({ max: 10 }) }),
  valueSats: fc.bigInt({ min: 1n, max: 10_000_000n }),
  scriptPubKey: fc.constant(`0014${'1'.repeat(40)}`),
  account: fc.nat({ max: 9 }),
  lane: fc.constantFrom('payment', 'ordinals') as fc.Arbitrary<WalletUtxo['lane']>,
  chain: fc.constantFrom(0, 1) as fc.Arbitrary<0 | 1>,
  addressIndex: fc.nat({ max: 40 }),
  height: fc.option(fc.nat({ max: 250_000 }), { nil: null }),
  walletCreatedChange: fc.boolean(),
  facts: fc.option(factsArb, { nil: null }),
  flags: fc.record({ userFrozen: fc.boolean(), dustQuarantined: fc.boolean() }),
});

export const freshnessArb: fc.Arbitrary<FreshnessReport> = fc
  .record({
    commonTip: fc.boolean(),
    heartbeatFresh: fc.boolean(),
    revisionActive: fc.boolean(),
  })
  .map((r) => ({ ...r, spendEligible: r.commonTip && r.heartbeatFresh && r.revisionActive }));

export const contextArb: fc.Arbitrary<EligibilityContext> = fc
  .record({
    freshness: freshnessArb,
    activeRevision: fc.constantFrom('rev-0001', 'rev-0000'),
    locked: fc.array(hex64, { maxLength: 2 }),
  })
  .map(({ freshness, activeRevision, locked }) => ({
    freshness,
    activeRevision,
    lockedOutpoints: new Set(locked.map((txid) => `${txid}:0`)),
    marginalFeeSatsFor: () => 0n,
  }));

export const FRESH_CONTEXT: EligibilityContext = {
  freshness: { commonTip: true, heartbeatFresh: true, revisionActive: true, spendEligible: true },
  activeRevision: 'rev-0001',
  lockedOutpoints: new Set<string>(),
  marginalFeeSatsFor: () => 0n,
};
