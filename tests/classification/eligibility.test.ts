import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { evaluateEligibility } from '../../src/domain/classification/eligibility';
import { displayClass, type WalletUtxo } from '../../src/domain/classification/types';
import { contextArb, FRESH_CONTEXT, utxoArb } from './arbitraries';

const cleanUtxo = (overrides: Partial<WalletUtxo> = {}): WalletUtxo => ({
  outpoint: { txid: 'a'.repeat(64), vout: 0 },
  valueSats: 50_000n,
  scriptPubKey: `0014${'1'.repeat(40)}`,
  account: 0,
  lane: 'payment',
  chain: 0,
  addressIndex: 0,
  height: 249_900,
  walletCreatedChange: false,
  facts: {
    primaryClass: 'cardinal_clean',
    inscriptions: [],
    satRanges: null,
    unsupportedAssetDetected: false,
    confidence: 'authoritative',
    classifiedTip: { height: 250_000, hash: 'b'.repeat(64) },
    classificationRevision: 'rev-0001',
  },
  flags: { userFrozen: false, dustQuarantined: false },
  ...overrides,
});

describe('§11.2 eligibility predicate — per-condition examples', () => {
  it('a fresh confirmed clean UTXO is eligible', () => {
    expect(evaluateEligibility(cleanUtxo(), FRESH_CONTEXT)).toEqual({
      eligible: true,
      reasons: [],
    });
  });

  it('condition 1: any non-clean or missing classification is ineligible', () => {
    for (const primaryClass of [
      'inscribed',
      'rare_sat',
      'runic_or_unsupported',
      'mixed',
      'unknown',
    ] as const) {
      const utxo = cleanUtxo();
      utxo.facts = { ...utxo.facts!, primaryClass };
      expect(
        evaluateEligibility(utxo, FRESH_CONTEXT).reasons,
        primaryClass,
      ).toContain('not_cardinal_clean');
    }
    expect(evaluateEligibility(cleanUtxo({ facts: null }), FRESH_CONTEXT).reasons).toContain(
      'not_cardinal_clean',
    );
  });

  it('condition 1: contradictory clean facts are ineligible', () => {
    const baseFacts = cleanUtxo().facts!;
    const contradictions = [
      { ...baseFacts, confidence: 'degraded' as const },
      {
        ...baseFacts,
        inscriptions: [{ inscriptionId: 'a'.repeat(64) + 'i0', satpoint: `${'a'.repeat(64)}:0:0` }],
      },
      { ...baseFacts, unsupportedAssetDetected: true },
      { ...baseFacts, satRanges: [{ start: '0', end: '1', rarity: 'uncommon' as const }] },
    ];
    for (const facts of contradictions) {
      expect(evaluateEligibility(cleanUtxo({ facts }), FRESH_CONTEXT).reasons).toContain(
        'not_cardinal_clean',
      );
    }
    for (const satRanges of [null, [], [{ start: '0', end: '50000', rarity: 'common' as const }]]) {
      expect(evaluateEligibility(cleanUtxo({ facts: { ...baseFacts, satRanges } }), FRESH_CONTEXT).eligible)
        .toBe(true);
    }
  });

  it('condition 2: status staleness or a superseded UTXO revision blocks', () => {
    const staleStatus = {
      ...FRESH_CONTEXT,
      freshness: { commonTip: true, heartbeatFresh: false, revisionActive: true, spendEligible: false },
    };
    expect(evaluateEligibility(cleanUtxo(), staleStatus).reasons).toContain('classification_stale');

    const supersededRevision = { ...FRESH_CONTEXT, activeRevision: 'rev-0002' };
    expect(evaluateEligibility(cleanUtxo(), supersededRevision).reasons).toContain(
      'classification_stale',
    );
  });

  it('condition 3: user freeze blocks', () => {
    const utxo = cleanUtxo({ flags: { userFrozen: true, dustQuarantined: false } });
    expect(evaluateEligibility(utxo, FRESH_CONTEXT).reasons).toEqual(['user_frozen']);
  });

  it('condition 4: dust quarantine blocks', () => {
    const utxo = cleanUtxo({ flags: { userFrozen: false, dustQuarantined: true } });
    expect(evaluateEligibility(utxo, FRESH_CONTEXT).reasons).toEqual(['dust_quarantined']);
  });

  it('condition 5: incoming unconfirmed blocks, wallet-created unconfirmed change passes', () => {
    expect(
      evaluateEligibility(cleanUtxo({ height: null }), FRESH_CONTEXT).reasons,
    ).toEqual(['unconfirmed_not_wallet_change']);
    expect(
      evaluateEligibility(
        cleanUtxo({ height: null, walletCreatedChange: true, chain: 1 }),
        FRESH_CONTEXT,
      ).eligible,
    ).toBe(true);
  });

  it('condition 6: a plan lock blocks', () => {
    const ctx = { ...FRESH_CONTEXT, lockedOutpoints: new Set([`${'a'.repeat(64)}:0`]) };
    expect(evaluateEligibility(cleanUtxo(), ctx).reasons).toEqual(['plan_locked']);
  });

  it('condition 7: non-positive effective value blocks', () => {
    const ctx = { ...FRESH_CONTEXT, marginalFeeSatsFor: () => 50_000n };
    expect(evaluateEligibility(cleanUtxo(), ctx).reasons).toEqual(['uneconomic']);
  });
});

describe('§11.2 eligibility predicate — properties', () => {
  it('never eligible unless facts are authoritatively and consistently cardinal_clean', () => {
    fc.assert(
      fc.property(utxoArb, contextArb, (utxo, ctx) => {
        const { eligible } = evaluateEligibility(utxo, ctx);
        if (eligible) {
          expect(utxo.facts?.primaryClass).toBe('cardinal_clean');
          expect(utxo.facts?.confidence).toBe('authoritative');
          expect(utxo.facts?.inscriptions).toEqual([]);
          expect(utxo.facts?.unsupportedAssetDetected).toBe(false);
        }
      }),
    );
  });

  it('never eligible when the UTXO revision differs from the active revision', () => {
    fc.assert(
      fc.property(utxoArb, contextArb, (utxo, ctx) => {
        const { eligible } = evaluateEligibility(utxo, ctx);
        if (eligible) {
          expect(utxo.facts?.classificationRevision).toBe(ctx.activeRevision);
          expect(ctx.freshness.spendEligible).toBe(true);
        }
      }),
    );
  });

  it('never eligible when frozen, quarantined, plan-locked, or incoming-unconfirmed', () => {
    fc.assert(
      fc.property(utxoArb, contextArb, (utxo, ctx) => {
        const { eligible } = evaluateEligibility(utxo, ctx);
        if (eligible) {
          expect(utxo.flags.userFrozen).toBe(false);
          expect(utxo.flags.dustQuarantined).toBe(false);
          expect(ctx.lockedOutpoints.has(`${utxo.outpoint.txid}:${utxo.outpoint.vout}`)).toBe(false);
          if (utxo.height === null) expect(utxo.walletCreatedChange).toBe(true);
        }
      }),
    );
  });

  it('flag toggling never mutates asset facts, and protected classes always display as themselves', () => {
    fc.assert(
      fc.property(utxoArb, fc.boolean(), fc.boolean(), (utxo, frozen, quarantined) => {
        const before = JSON.stringify(utxo.facts);
        const flipped: WalletUtxo = {
          ...utxo,
          flags: { userFrozen: frozen, dustQuarantined: quarantined },
        };
        expect(JSON.stringify(flipped.facts)).toBe(before);
        const primary = utxo.facts?.primaryClass ?? 'unknown';
        if (primary !== 'cardinal_clean') {
          // A freeze flag never re-labels (or hides) a protected/unknown class.
          expect(displayClass(flipped)).toBe(primary);
        }
      }),
    );
  });
});
