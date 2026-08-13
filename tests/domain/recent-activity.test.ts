import { describe, expect, it } from 'vitest';
import {
  annotateOrdinalFlowActivity,
  annotateReceivedDetectedAssetActivity,
  annotateReceivedInscriptionActivity,
  activityRevision,
  mergeRecentActivity,
  ordinalActionInscriptionId,
  ordinalActionInscriptionIds,
  paginateActivity,
  projectRecentActivity,
  propagateActivityEvidence,
  reconcileTransactionStatus,
  type LaneAwareHistoryEntry,
} from '../../src/domain/recent-activity';
import type { StoredTransaction } from '../../src/scan/cache-schemas';

function transaction(overrides: Partial<{
  txid: string;
  createdAt: number;
  amountSats: bigint;
  feeSats: bigint;
  status: 'accepted' | 'already_known' | 'confirmed' | 'conflicted' | 'rejected';
  replacesTxid: string | null;
}> = {}) {
  return {
    txid: 'a'.repeat(64),
    createdAt: Date.parse('2026-07-22T18:00:00.000Z'),
    amountSats: 2_500n,
    feeSats: 234n,
    status: 'accepted' as const,
    replacesTxid: null,
    ...overrides,
  };
}

function history(overrides: Partial<LaneAwareHistoryEntry> = {}): LaneAwareHistoryEntry {
  return {
    txid: 'a'.repeat(64),
    height: null,
    timestamp: '2026-07-22T18:00:05.000Z',
    fundedScriptHashes: [],
    spentScriptHashes: [],
    deltaSats: '-2734',
    replacesTxid: null,
    replacedByTxid: null,
    confirmationState: 'mempool',
    feeSats: '234',
    vsize: 154,
    replaceable: true,
    packageFeeSats: null,
    packageVsize: null,
    cpfpEligible: false,
    ...overrides,
  };
}

describe('recent wallet activity', () => {
  it('paginates the complete projection in stable 25-row pages', () => {
    const rows = Array.from({ length: 53 }, (_, index) => history({
      txid: index.toString(16).padStart(64, '0'),
      height: 100 + index,
      timestamp: new Date(Date.UTC(2026, 0, 1, 0, 0, index)).toISOString(),
      deltaSats: String(index + 1),
      confirmationState: 'confirmed',
    }));
    const projected = projectRecentActivity(rows, []);
    expect(projected).toHaveLength(53);

    const first = paginateActivity(projected, null);
    expect(first.items).toHaveLength(25);
    expect(first.reset).toBe(false);
    expect(first.nextCursor?.offset).toBe(25);

    const second = paginateActivity(projected, first.nextCursor);
    expect(second.items).toHaveLength(25);
    expect(second.nextCursor?.offset).toBe(50);

    const final = paginateActivity(projected, second.nextCursor);
    expect(final.items).toHaveLength(3);
    expect(final.nextCursor).toBeNull();
    expect(new Set([...first.items, ...second.items, ...final.items].map((item) => item.txid)).size)
      .toBe(53);
  });

  it('uses txid as the final deterministic ordering tie-breaker', () => {
    const tied = ['f', '1', 'a'].map((digit) => history({
      txid: digit.repeat(64),
      height: 100,
      timestamp: '2026-01-01T00:00:00.000Z',
      confirmationState: 'confirmed',
    }));
    expect(projectRecentActivity(tied, []).map((item) => item.txid)).toEqual([
      '1'.repeat(64),
      'a'.repeat(64),
      'f'.repeat(64),
    ]);
  });

  it('resets a stale cursor when activity content changes', () => {
    const original = projectRecentActivity(Array.from({ length: 30 }, (_, index) => history({
      txid: index.toString(16).padStart(64, '0'),
      height: index,
      timestamp: new Date(Date.UTC(2026, 0, 1, 0, 0, index)).toISOString(),
      confirmationState: 'confirmed',
    })), []);
    const first = paginateActivity(original, null);
    const changed = [{
      ...original[0]!,
      confirmationState: 'mempool' as const,
    }, ...original.slice(1)];
    expect(activityRevision(changed)).not.toBe(activityRevision(original));

    const reset = paginateActivity(changed, first.nextCursor);
    expect(reset.reset).toBe(true);
    expect(reset.items).toEqual(changed.slice(0, 25));
    expect(reset.nextCursor?.offset).toBe(25);
  });

  it('aggregates directly observed Rune identities on positive receives only', () => {
    const txid = '9'.repeat(64);
    const activity = mergeRecentActivity([history({ txid, deltaSats: '330', feeSats: null })], []);
    const annotated = annotateReceivedDetectedAssetActivity(activity, [{
      txid,
      vout: 5,
      assets: [{ protocol: 'rune', name: 'MAGIC•INTERNET•MONEY', amountAtoms: '10000', divisibility: 2, symbol: null }],
      identityCount: 1,
      identityComplete: true,
    }]);
    expect(annotated[0]).toMatchObject({
      detectedAssets: [{ name: 'MAGIC•INTERNET•MONEY', amountAtoms: '10000' }],
      detectedAssetCount: 1,
      assetIdentityComplete: true,
    });
    expect(annotateReceivedDetectedAssetActivity(
      mergeRecentActivity([history({ txid, deltaSats: '-330' })], []),
      [{ txid, vout: 5, assets: [], identityCount: 1, identityComplete: false }],
    )[0]?.detectedAssets).toBeUndefined();
  });
  it('backfills and retains the verified 0267 → 03c735 → 6b1c → 7dfea identity chain', () => {
    const chain = [
      '0267'.padEnd(64, '0'),
      '03c735a58943b252e1a341a42401444c02f4963d06453bbdb57887b60ce14d21',
      '6b1c'.padEnd(64, '0'),
      '7dfea'.padEnd(64, '0'),
    ];
    const inscriptionId = `${'5'.repeat(64)}i1`;
    const rows = chain.slice(1).map((txid, index) => history({
      txid,
      deltaSats: index === 0 ? '-546' : '0',
      ordinalFlow: {
        kind: 'complete',
        edges: [{
          source: { txid: chain[index]!, vout: 0, offsetSats: '0' },
          destination: { txid, vout: 0, offsetSats: '0' },
          lengthSats: '546',
          sourceRequested: index === 0,
          destinationRequested: false,
        }],
      },
    }));
    const current = [{
      inscriptionId,
      number: 67_368_437,
      outpoint: { txid: chain[3]!, vout: 0 },
      offsetSats: 0n,
      observedAt: 100,
    }];
    const propagated = propagateActivityEvidence(rows, current);
    expect(propagated.map((item) => item.outpoint.txid)).toEqual(
      expect.arrayContaining(chain),
    );
    const activity = annotateOrdinalFlowActivity(
      mergeRecentActivity(rows, [], 3),
      rows,
      propagated,
    );
    expect(activity.find((item) => item.txid === chain[1])).toMatchObject({
      actionKind: 'ordinal_transfer',
      inscriptionId,
      inscriptionNumber: 67_368_437,
      inscriptionCount: 1,
    });
    expect(activity.find((item) => item.txid === chain[2])?.actionKind).toBeUndefined();
    expect(propagateActivityEvidence(rows, propagated)).toEqual(propagated);
  });

  it('never propagates identity through unavailable or incomplete flow evidence', () => {
    const source = '1'.repeat(64);
    const destination = '2'.repeat(64);
    const seed = [{
      inscriptionId: `${'3'.repeat(64)}i0`,
      number: 1,
      outpoint: { txid: destination, vout: 0 },
      offsetSats: 0n,
      observedAt: 1,
    }];
    const unavailable = history({
      txid: destination,
      ordinalFlow: { kind: 'unavailable', reason: 'response_budget' },
    });
    const propagated = propagateActivityEvidence([unavailable], seed);
    expect(propagated).toEqual(seed);
    expect(propagated.some((item) => item.outpoint.txid === source)).toBe(false);
  });

  it('uses scanned confirmation, conflict, replacement, and mempool states over local uncertainty', () => {
    expect(reconcileTransactionStatus('accepted', 'confirmed')).toBe('confirmed');
    expect(reconcileTransactionStatus('accepted', 'conflicted')).toBe('conflicted');
    expect(reconcileTransactionStatus('accepted', 'replaced')).toBe('replaced');
    expect(reconcileTransactionStatus('pending', 'mempool')).toBe('accepted');
    expect(reconcileTransactionStatus('accepted', undefined)).toBe('accepted');
  });

  it('surfaces an accepted outgoing journal entry immediately with principal and fee data', () => {
    expect(mergeRecentActivity([], [transaction()])).toEqual([{
      txid: 'a'.repeat(64),
      deltaSats: '-2734',
      feeSats: '234',
      confirmationState: 'mempool',
      timestamp: '2026-07-22T18:00:00.000Z',
      height: null,
    }]);
  });

  it('shows a verified recipient and carries the signed public input summary', () => {
    const recipient = 'bc1qrecipient';
    const outgoingPlan = {
      outputs: [
        { role: 'recipient', address: recipient },
        { role: 'payment_change', address: 'bc1qchange', derivation: { account: 0 } },
      ],
    } as unknown as StoredTransaction['plan'];
    expect(mergeRecentActivity([], [{
      ...transaction(),
      kind: 'native_send',
      plan: outgoingPlan,
    }])[0]).toMatchObject({
      addressDisplay: { kind: 'sent_to', address: recipient },
    });

    const incoming = history({
      txid: '1'.repeat(64),
      deltaSats: '1000',
      feeSats: null,
      activitySource: {
        inputCount: 3,
        singleInputAddress: null,
      },
    });
    expect(mergeRecentActivity([incoming], [])[0]).toMatchObject({
      transactionSource: {
        inputCount: 3,
        singleInputAddress: null,
      },
    });
  });

  it('does not present wallet-owned ordinal destinations as external sends', () => {
    const ownAddress = 'bc1powned';
    const ownPlan = {
      outputs: [{ role: 'postage', address: ownAddress, derivation: { account: 0 } }],
      protectedSatFlow: [{ inscriptionId: `${'4'.repeat(64)}i0` }],
      policy: { intent: { kind: 'rescue' } },
      inputs: [],
    } as unknown as StoredTransaction['plan'];
    expect(mergeRecentActivity([], [{ ...transaction(), kind: 'rescue', plan: ownPlan }])[0])
      .toMatchObject({ addressDisplay: null });
  });

  it('de-duplicates by txid and lets authoritative gateway history replace the journal view', () => {
    const scanned = history({
      height: 959_200,
      confirmationState: 'confirmed',
      timestamp: '2026-07-22T18:10:00.000Z',
    });
    const result = mergeRecentActivity([scanned], [transaction()]);
    expect(result).toHaveLength(1);
    expect(result[0]).toMatchObject({
      txid: scanned.txid,
      confirmationState: 'confirmed',
      height: 959_200,
      feeSats: '234',
    });
  });

  it('labels fee-only movement between wallet scripts instead of reporting a zero-sat send', () => {
    const internal = history({
      deltaSats: '-455',
      feeSats: '455',
      fundedScriptHashes: ['funded-script'],
      spentScriptHashes: ['spent-script-a', 'spent-script-b'],
    });
    expect(mergeRecentActivity([internal], [])).toEqual([
      expect.objectContaining({
        txid: internal.txid,
        bitcoinActionKind: 'self_transfer',
        deltaSats: '-455',
        feeSats: '455',
      }),
    ]);

    const external = history({
      txid: 'e'.repeat(64),
      deltaSats: '-1000',
      feeSats: '455',
      fundedScriptHashes: ['funded-script'],
      spentScriptHashes: ['spent-script'],
    });
    expect(mergeRecentActivity([external], [])[0]?.bitcoinActionKind).toBeUndefined();
  });

  it('identifies Ordinals-address direction without claiming an inscription moved', () => {
    expect(mergeRecentActivity([
      history({
        txid: '1'.repeat(64),
        deltaSats: '546',
        feeSats: null,
        ordinalsAddressFunded: true,
      }),
      history({
        txid: '2'.repeat(64),
        deltaSats: '-1021',
        ordinalsAddressSpent: true,
      }),
      history({
        txid: '3'.repeat(64),
        deltaSats: '1000',
        feeSats: null,
      }),
    ], [], 3).map((entry) => [entry.txid, entry.addressContext])).toEqual([
      ['1'.repeat(64), 'ordinals_received'],
      ['2'.repeat(64), 'ordinals_sent'],
      ['3'.repeat(64), undefined],
    ]);
  });

  it('recognizes inbound inscriptions and counts each ordinal outpoint value once', () => {
    const txid = '9'.repeat(64);
    const firstId = `${'1'.repeat(64)}i0`;
    const secondId = `${'2'.repeat(64)}i0`;
    const received = annotateReceivedInscriptionActivity([
      history({ txid, deltaSats: '546', feeSats: null }),
    ], [
      { txid, vout: 0, inscriptionId: secondId, number: 22, valueSats: 546n },
      { txid, vout: 0, inscriptionId: firstId, number: 11, valueSats: 546n },
    ]);
    expect(received[0]).toMatchObject({
      actionKind: 'ordinal_receive',
      inscriptionId: firstId,
      inscriptionNumber: 11,
      receivedInscriptionCount: 2,
      ordinalValueSats: '546',
    });
  });

  it('does not relabel outgoing or already identified activity as an inscription receipt', () => {
    const txid = '8'.repeat(64);
    const evidence = [{
      txid,
      vout: 0,
      inscriptionId: `${'3'.repeat(64)}i0`,
      number: 33,
      valueSats: 546n,
    }];
    const outgoing = history({ txid, deltaSats: '-546' });
    const identified = {
      ...history({ txid, deltaSats: '546' }),
      actionKind: 'rescue' as const,
    };
    expect(annotateReceivedInscriptionActivity([outgoing], evidence)[0]?.actionKind)
      .toBeUndefined();
    expect(annotateReceivedInscriptionActivity([identified], evidence)[0]?.actionKind)
      .toBe('rescue');
  });

  it('shows rejected broadcasts as final failures and marks a replaced journal transaction', () => {
    const originalTxid = 'b'.repeat(64);
    const replacementTxid = 'c'.repeat(64);
    const result = mergeRecentActivity([], [
      transaction({ txid: originalTxid }),
      transaction({ txid: replacementTxid, createdAt: Date.parse('2026-07-22T18:01:00.000Z'), replacesTxid: originalTxid }),
      transaction({ txid: 'd'.repeat(64), status: 'rejected' }),
    ]);
    expect(result.map((entry) => [entry.txid, entry.confirmationState])).toEqual([
      [replacementTxid, 'mempool'],
      [originalTxid, 'replaced'],
      ['d'.repeat(64), 'rejected'],
    ]);
  });

  it('keeps unconfirmed entries ahead of confirmed history and enforces the display limit', () => {
    const confirmed = Array.from({ length: 12 }, (_, index) => history({
      txid: index.toString(16).padStart(64, '0'),
      height: 959_000 + index,
      timestamp: null,
      confirmationState: 'confirmed',
      deltaSats: String(index + 1),
      feeSats: null,
    }));
    const pending = transaction({ txid: 'f'.repeat(64) });
    const result = mergeRecentActivity(confirmed, [pending]);
    expect(result).toHaveLength(10);
    expect(result[0]?.txid).toBe(pending.txid);
    expect(result[1]?.height).toBe(959_011);
  });

  it('preserves transfer, rescue, and sweep identity when scanned history replaces the journal', () => {
    const inscriptionId = `${'1'.repeat(64)}i0`;
    const plan = (kind: 'ordinal_transfer' | 'rescue' | 'ordinal_sweep') => ({
      version: 3,
      kind,
      policy: {
        intent: kind === 'ordinal_transfer'
          ? { kind, account: 0, inscriptionId, outpoint: { txid: '1'.repeat(64), vout: 0 },
              recipient: 'tb1ptest' }
          : { kind, outpoint: { txid: '1'.repeat(64), vout: 0 } },
      },
      protectedSatFlow: kind === 'rescue' ? [{ inscriptionId }] : [],
      outputs: kind === 'ordinal_sweep'
        ? [{ role: 'payment_change', valueSats: 42_000n }]
        : [],
      inputs: [{
        classification: {
          inscriptions: [{ inscriptionId, number: 67_368_437 }],
        },
      }],
      inscriptionPreviews: {
        items: kind === 'ordinal_sweep' ? [] : [{
          metadata: { inscriptionId, number: 67_368_438 },
        }],
      },
    }) as unknown as StoredTransaction['plan'];
    const txids = ['b'.repeat(64), 'c'.repeat(64), 'd'.repeat(64)];
    const journals = (['ordinal_transfer', 'rescue', 'ordinal_sweep'] as const).map((kind, index) => ({
      ...transaction({ txid: txids[index]! }),
      kind,
      plan: plan(kind),
    }));
    const result = mergeRecentActivity([
      history({ txid: txids[0]!, confirmationState: 'confirmed', height: 1 }),
      history({
        txid: txids[1]!,
        confirmationState: 'confirmed',
        height: 2,
        deltaSats: '-234',
        feeSats: '234',
        fundedScriptHashes: ['owned-output'],
        spentScriptHashes: ['owned-input'],
      }),
      history({ txid: txids[2]!, confirmationState: 'confirmed', height: 3 }),
    ], journals);
    expect(result.find((item) => item.txid === txids[0])).toMatchObject({
      actionKind: 'ordinal_transfer',
      inscriptionId,
      inscriptionNumber: 67_368_438,
    });
    expect(result.find((item) => item.txid === txids[1])).toMatchObject({
      actionKind: 'rescue',
      inscriptionId,
      inscriptionNumber: 67_368_438,
    });
    expect(result.find((item) => item.txid === txids[1])?.bitcoinActionKind).toBeNull();
    expect(result.find((item) => item.txid === txids[2])).toMatchObject({
      actionKind: 'ordinal_sweep',
      returnedBtcSats: '42000',
    });
    expect(ordinalActionInscriptionId(plan('ordinal_sweep'))).toBeNull();

    const currentPlan = { ...plan('ordinal_transfer'), version: 4 } as StoredTransaction['plan'];
    const current = mergeRecentActivity([], [{
      ...transaction(),
      kind: 'ordinal_transfer',
      plan: currentPlan,
    }]);
    expect(current[0]).toMatchObject({
      actionKind: 'ordinal_transfer',
      inscriptionId,
      inscriptionNumber: 67_368_438,
    });
  });

  it('falls back to signed classification numbers for legacy ordinal journals', () => {
    const inscriptionId = `${'2'.repeat(64)}i1`;
    const legacy = {
      version: 2,
      kind: 'ordinal_transfer',
      policy: { intent: { kind: 'ordinal_transfer', inscriptionId } },
      inputs: [{
        classification: {
          inscriptions: [{ inscriptionId, number: 444 }],
        },
      }],
      outputs: [],
      protectedSatFlow: [],
    } as unknown as StoredTransaction['plan'];
    const result = mergeRecentActivity([], [{
      ...transaction(),
      kind: 'ordinal_transfer',
      plan: legacy,
    }]);
    expect(result[0]).toMatchObject({
      inscriptionId,
      inscriptionNumber: 444,
    });
  });

  it('projects one atomic batch tx with ordered unique inscription IDs', () => {
    const inscriptionIds = [`${'1'.repeat(64)}i0`, `${'2'.repeat(64)}i0`];
    const plan = {
      version: 4,
      kind: 'ordinal_batch_transfer',
      policy: { intent: {
        kind: 'ordinal_batch_transfer',
        account: 0,
        recipient: 'tb1ptest',
        selections: inscriptionIds.map((inscriptionId, index) => ({
          inscriptionId,
          outpoint: { txid: '1'.repeat(64), vout: 0 },
          satpoint: `${'1'.repeat(64)}:0:${index}`,
          classificationRevision: 'rev-1',
        })),
      } },
      outputs: [{ role: 'postage', address: 'tb1ptest', valueSats: 20_000n }],
      inputs: [],
      protectedSatFlow: [],
      inscriptionPreviews: { items: [] },
    } as unknown as StoredTransaction['plan'];
    const result = mergeRecentActivity([], [{
      ...transaction(),
      kind: 'ordinal_batch_transfer',
      plan,
    }]);
    expect(result[0]).toMatchObject({
      actionKind: 'ordinal_batch_transfer',
      inscriptionId: inscriptionIds[0],
      inscriptionIds,
      inscriptionCount: 2,
    });
    expect(ordinalActionInscriptionIds(plan)).toEqual(inscriptionIds);
  });
});
