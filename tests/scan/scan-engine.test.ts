/**
 * Engine-level scan tests: gap-limit window widening, the §8.2 boundary
 * prompt, cancellation between requests, and the §11.4 revision-equality rule
 * (one refetch, then conflicting_sources) — all against synthetic ports, no
 * crypto.
 */
import { describe, expect, it } from 'vitest';
import type {
  OutpointsClassifyResponse,
  WalletScanSnapshotResponse,
} from '../../src/domain/gateway/contract';
import { scanUnit, type ScanUnitPorts } from '../../src/scan/scan-engine';
import type { ScanUnit } from '../../src/scan/scan-state';

const UNIT: ScanUnit = { source: 'standard', account: 0, lane: 'payment' };

const envelope = (revision = 'rev-0001') => ({
  instanceId: 'fake',
  network: 'signet' as const,
  protocolVersion: 1,
  requestNonce: '00'.repeat(16),
  timestamp: '2026-07-20T00:00:00.000Z',
  coreTip: { height: 250_000, hash: 'a'.repeat(64) },
  indexTip: { height: 250_000, hash: 'a'.repeat(64) },
  classificationRevision: revision,
  capabilities: [],
  signature: 'aa',
});

/** Deterministic fake hash for (chain, index). */
const hashAt = (chain: 0 | 1, index: number) =>
  `${chain}${index.toString(16).padStart(3, '0')}`.padEnd(64, '0');

const txidAt = (index: number) => `${index.toString(16).padStart(4, '0')}`.padEnd(64, 'f');
const SCRIPT = '0014' + 'b'.repeat(40);

type SnapshotUtxo = WalletScanSnapshotResponse['utxos'][number];
type ClassifyBody = Pick<OutpointsClassifyResponse, 'classifications' | 'unknownOutpoints'>;

interface FakeOptions {
  /** External-chain indexes that hold a confirmed 10k-sat clean UTXO. */
  activeExt: number[];
  snapshotRevisions?: string[];
  snapshotHeights?: Array<number | null>;
  classifyRevision?: string;
  classifyInstanceId?: string;
  classifyIndexTipHash?: string;
  cancelAfterSnapshots?: number;
  /** Corrupt the echoed requestedScriptHashes (misrouted-response simulation). */
  echoRequested?: (sent: string[]) => string[];
  mutateSnapshotUtxos?: (utxos: SnapshotUtxo[]) => SnapshotUtxo[];
  /** Used-address evidence that does not depend on a returned UTXO/history row. */
  activeEvidenceExt?: number[];
  historyPartial?: boolean;
  includeFundingHistory?: boolean;
  snapshotFailure?: { reason: 'http'; httpStatus: number };
  mutateClassify?: (body: ClassifyBody) => ClassifyBody;
}

function makePorts(options: FakeOptions) {
  const snapshotRequests: string[][] = [];
  const ordinalFlowRequests: Array<boolean | undefined> = [];
  let cancelled = false;
  const activeByHash = new Map(options.activeExt.map((i) => [hashAt(0, i), i]));
  const activeEvidence = new Set((options.activeEvidenceExt ?? []).map((i) => hashAt(0, i)));
  const ports: ScanUnitPorts = {
    network: 'signet',
    hashesFor: (_unit, chain, from, to) =>
      Array.from({ length: to - from }, (_, k) => ({
        chain,
        index: from + k,
        scriptHash: hashAt(chain, from + k),
        scriptPubKey: SCRIPT,
      })),
    snapshot: (req) => {
      snapshotRequests.push(req.scriptHashes);
      ordinalFlowRequests.push(req.includeOrdinalFlow);
      if (
        options.cancelAfterSnapshots !== undefined &&
        snapshotRequests.length >= options.cancelAfterSnapshots
      ) {
        cancelled = true;
      }
      if (options.snapshotFailure) {
        return Promise.resolve({ ok: false as const, ...options.snapshotFailure });
      }
      const revision =
        options.snapshotRevisions?.[snapshotRequests.length - 1] ??
        options.snapshotRevisions?.at(-1) ??
        'rev-0001';
      let configuredHeight = options.snapshotHeights?.[snapshotRequests.length - 1];
      if (configuredHeight === undefined) configuredHeight = options.snapshotHeights?.at(-1);
      const height = configuredHeight === undefined ? 249_000 : configuredHeight;
      const baseUtxos = req.scriptHashes
        .filter((h) => activeByHash.has(h))
        .map((h) => ({
          txid: txidAt(activeByHash.get(h)!),
          vout: 0,
          valueSats: '10000',
          scriptHash: h,
          scriptPubKey: SCRIPT,
          height,
          fundingSpendsOnlyRequested: false,
        }));
      const activeScriptHashes = req.scriptHashes.filter((hash) =>
        activeByHash.has(hash) || activeEvidence.has(hash));
      const history = options.includeFundingHistory
        ? baseUtxos.map((utxo) => ({
            txid: utxo.txid,
            height: utxo.height,
            timestamp: null,
            fundedScriptHashes: [utxo.scriptHash],
            spentScriptHashes: [],
            deltaSats: utxo.valueSats,
            replacesTxid: null,
            replacedByTxid: null,
            confirmationState: utxo.height === null ? 'mempool' as const : 'confirmed' as const,
            feeSats: null,
            vsize: null,
            replaceable: null,
            packageFeeSats: null,
            packageVsize: null,
            cpfpEligible: false,
          }))
        : [];
      const value: WalletScanSnapshotResponse = {
        ...envelope(revision),
        requestedScriptHashes: options.echoRequested
          ? options.echoRequested(req.scriptHashes)
          : req.scriptHashes,
        utxos: options.mutateSnapshotUtxos?.(baseUtxos) ?? baseUtxos,
        history,
        activeScriptHashes,
        historyCoverage: options.historyPartial
          ? { status: 'partial', limitedScriptHashes: activeScriptHashes }
          : { status: 'complete', limitedScriptHashes: [] },
      };
      return Promise.resolve({ ok: true as const, value, verifiedAtMs: 0 });
    },
    classify: (req) => {
      const base: ClassifyBody = {
        classifications: req.outpoints.map((o) => ({
          txid: o.txid,
          vout: o.vout,
          valueSats: '10000',
          scriptPubKey: SCRIPT,
          confirmations: 1_001,
          primaryClass: 'cardinal_clean' as const,
          inscriptions: [],
          satRanges: null,
          unsupportedAssetDetected: false,
          confidence: 'authoritative' as const,
          classifiedTip: { height: 250_000, hash: 'a'.repeat(64) },
          classificationRevision: options.classifyRevision ?? 'rev-0001',
        })),
        unknownOutpoints: [],
      };
      const body = options.mutateClassify?.(base) ?? base;
      const value: OutpointsClassifyResponse = {
        ...envelope(options.classifyRevision ?? 'rev-0001'),
        ...(options.classifyInstanceId ? { instanceId: options.classifyInstanceId } : {}),
        ...(options.classifyIndexTipHash
          ? { indexTip: { height: 250_000, hash: options.classifyIndexTipHash } }
          : {}),
        ...body,
      };
      return Promise.resolve({ ok: true as const, value, verifiedAtMs: 0 });
    },
    shouldCancel: () => cancelled,
  };
  return { ports, snapshotRequests, ordinalFlowRequests };
}

describe('scan engine (§8.2)', () => {
  it('requests ordinal flow evidence only for the Ordinals lane', async () => {
    const payment = makePorts({ activeExt: [] });
    await scanUnit(UNIT, payment.ports, { maxIndexPerChain: 60, burnedChangeCount: 0 });
    expect(payment.ordinalFlowRequests).toEqual([undefined]);

    const ordinals = makePorts({ activeExt: [] });
    await scanUnit(
      { ...UNIT, lane: 'ordinals' },
      ordinals.ports,
      { maxIndexPerChain: 60, burnedChangeCount: 0 },
    );
    expect(ordinals.ordinalFlowRequests).toEqual([true]);
  });

  it('stops at the gap limit with no activity', async () => {
    const { ports, snapshotRequests } = makePorts({ activeExt: [] });
    const result = await scanUnit(UNIT, ports, { maxIndexPerChain: 60, burnedChangeCount: 0 });
    expect(result.ok).toBe(true);
    expect(result.boundaryPrompt).toBe(false);
    // One round: ext 0..19 + int 0..19.
    expect(snapshotRequests).toHaveLength(1);
    expect(snapshotRequests[0]).toHaveLength(40);
  });

  it('widens the window while activity sits within the gap limit', async () => {
    const { ports, snapshotRequests } = makePorts({ activeExt: [18] });
    const result = await scanUnit(UNIT, ports, { maxIndexPerChain: 60, burnedChangeCount: 0 });
    expect(result.ok).toBe(true);
    expect(result.utxos).toHaveLength(1);
    expect(result.utxos[0]?.addressIndex).toBe(18);
    expect(result.boundaryPrompt).toBe(false);
    // Round 2 fetches only the new external indexes 20..38 (18+1+20).
    expect(snapshotRequests).toHaveLength(2);
    expect(snapshotRequests[1]).toHaveLength(19);
  });

  it('keeps a used zero-balance address active when its history is bounded', async () => {
    const { ports, snapshotRequests } = makePorts({
      activeExt: [],
      activeEvidenceExt: [18],
      historyPartial: true,
    });
    const result = await scanUnit(UNIT, ports, { maxIndexPerChain: 60, burnedChangeCount: 0 });
    expect(result).toMatchObject({
      ok: true,
      active: true,
      confirmedActivity: false,
      utxos: [],
      historyCoverage: { status: 'partial' },
    });
    expect(result.historyCoverage.limitedScriptHashes).toContain(hashAt(0, 18));
    expect(snapshotRequests).toHaveLength(2);
    expect(snapshotRequests[1]).toHaveLength(19);
  });

  it('distinguishes confirmed history from mempool-only activity', async () => {
    const confirmed = await scanUnit(
      UNIT,
      makePorts({ activeExt: [0], includeFundingHistory: true }).ports,
      { maxIndexPerChain: 60, burnedChangeCount: 0 },
    );
    const pending = await scanUnit(
      UNIT,
      makePorts({
        activeExt: [0],
        includeFundingHistory: true,
        snapshotHeights: [null],
        mutateClassify: (body) => ({
          ...body,
          classifications: body.classifications.map((record) => ({
            ...record,
            confirmations: 0,
          })),
        }),
      }).ports,
      { maxIndexPerChain: 60, burnedChangeCount: 0 },
    );
    expect(confirmed).toMatchObject({ active: true, confirmedActivity: true });
    expect(pending).toMatchObject({ active: true, confirmedActivity: false });
  });

  it('keeps an ordinary 1,000-sat inbound payment available to eligibility checks', async () => {
    const { ports } = makePorts({
      activeExt: [0],
      mutateSnapshotUtxos: (utxos) => utxos.map((utxo) => ({ ...utxo, valueSats: '1000' })),
      mutateClassify: (body) => ({
        ...body,
        classifications: body.classifications.map((record) => ({
          ...record,
          valueSats: '1000',
        })),
      }),
    });
    const result = await scanUnit(UNIT, ports, { maxIndexPerChain: 60, burnedChangeCount: 0 });
    expect(result.ok).toBe(true);
    expect(result.utxos[0]).toMatchObject({
      valueSats: 1_000n,
      flags: { userFrozen: false, dustQuarantined: false },
    });
  });

  it('does not grant the first-funding dust exception from partial history', async () => {
    const options: FakeOptions = {
      activeExt: [0],
      includeFundingHistory: true,
      mutateSnapshotUtxos: (utxos) => utxos.map((utxo) => ({ ...utxo, valueSats: '100' })),
      mutateClassify: (body) => ({
        ...body,
        classifications: body.classifications.map((record) => ({
          ...record,
          valueSats: '100',
        })),
      }),
    };
    const complete = makePorts(options);
    const partial = makePorts({ ...options, historyPartial: true });
    const completeResult = await scanUnit(UNIT, complete.ports, {
      maxIndexPerChain: 60,
      burnedChangeCount: 0,
    });
    const partialResult = await scanUnit(UNIT, partial.ports, {
      maxIndexPerChain: 60,
      burnedChangeCount: 0,
    });
    expect(completeResult.utxos[0]?.flags.dustQuarantined).toBe(false);
    expect(partialResult.utxos[0]?.flags.dustQuarantined).toBe(true);
  });

  it('raises the §8.2 Extended-scan prompt when the gap is unsatisfied at the cap', async () => {
    const { ports } = makePorts({ activeExt: [18, 38, 58] });
    const result = await scanUnit(UNIT, ports, { maxIndexPerChain: 60, burnedChangeCount: 0 });
    expect(result.ok).toBe(true);
    expect(result.utxos).toHaveLength(3);
    expect(result.boundaryPrompt).toBe(true);
  });

  it('cancels between requests without partial results', async () => {
    const { ports } = makePorts({ activeExt: [18, 38], cancelAfterSnapshots: 1 });
    const result = await scanUnit(UNIT, ports, { maxIndexPerChain: 60, burnedChangeCount: 0 });
    expect(result).toMatchObject({ ok: false, failure: 'cancelled', utxos: [] });
  });

  it('distinguishes a fail-closed response bound from a connection failure', async () => {
    const limited = makePorts({
      activeExt: [],
      snapshotFailure: { reason: 'http', httpStatus: 422 },
    });
    await expect(scanUnit(UNIT, limited.ports, {
      maxIndexPerChain: 60,
      burnedChangeCount: 0,
    })).resolves.toMatchObject({ ok: false, failure: 'data_limit' });

    const unavailable = makePorts({
      activeExt: [],
      snapshotFailure: { reason: 'http', httpStatus: 503 },
    });
    await expect(scanUnit(UNIT, unavailable.ports, {
      maxIndexPerChain: 60,
      burnedChangeCount: 0,
    })).resolves.toMatchObject({ ok: false, failure: 'gateway' });
  });

  it('rejects a signed response that does not echo this request\'s hashes', async () => {
    // A misrouted-but-validly-signed body answering different hashes must not
    // read as an empty account and terminate the gap scan early.
    const { ports } = makePorts({
      activeExt: [18],
      echoRequested: (sent) => sent.slice(0, sent.length - 1),
    });
    const result = await scanUnit(UNIT, ports, { maxIndexPerChain: 60, burnedChangeCount: 0 });
    expect(result).toMatchObject({ ok: false, failure: 'conflicting_sources', utxos: [] });
  });

  it('refetches once on snapshot/classify revision skew, then fails as conflicting sources', async () => {
    const { ports } = makePorts({ activeExt: [0], classifyRevision: 'rev-0002' });
    const result = await scanUnit(UNIT, ports, { maxIndexPerChain: 60, burnedChangeCount: 0 });
    expect(result).toMatchObject({ ok: false, failure: 'conflicting_sources' });
  });

  it.each([
    ['gateway instance', { classifyInstanceId: 'foreign' }],
    ['index tip', { classifyIndexTipHash: 'd'.repeat(64) }],
  ])('rejects a persistent snapshot/classification %s mismatch', async (_label, mismatch) => {
    const { ports } = makePorts({ activeExt: [0], ...mismatch });
    await expect(scanUnit(UNIT, ports, { maxIndexPerChain: 60, burnedChangeCount: 0 }))
      .resolves.toMatchObject({ ok: false, failure: 'conflicting_sources', utxos: [] });
  });

  it('recovers when the skew resolves on the refetch', async () => {
    // First pass sees rev-0001 then rev-0002 across rounds (intra-unit skew);
    // the retry sees rev-0002 consistently.
    const { ports } = makePorts({
      activeExt: [18],
      snapshotRevisions: ['rev-0001', 'rev-0002', 'rev-0002', 'rev-0002'],
      classifyRevision: 'rev-0002',
    });
    const result = await scanUnit(UNIT, ports, { maxIndexPerChain: 60, burnedChangeCount: 0 });
    expect(result.ok).toBe(true);
    expect(result.revision).toBe('rev-0002');
  });

  it('refetches when a transaction confirms between snapshot and classification', async () => {
    const { ports, snapshotRequests } = makePorts({
      activeExt: [0],
      // First pass still sees the mempool while classification already reports
      // the transaction at 1,001 confirmations. The retry sees one coherent
      // confirmed view without requiring a new block revision.
      snapshotHeights: [null, 249_000],
    });
    const result = await scanUnit(UNIT, ports, { maxIndexPerChain: 60, burnedChangeCount: 0 });
    expect(result.ok).toBe(true);
    expect(result.utxos[0]).toMatchObject({ height: 249_000 });
    // Index 0 activity widens each full pass once, so the initial pass and
    // coherent retry make two snapshot rounds apiece.
    expect(snapshotRequests).toHaveLength(4);
  });

  it('rejects a persistent snapshot/classification confirmation mismatch', async () => {
    const { ports } = makePorts({ activeExt: [0], snapshotHeights: [null] });
    await expect(scanUnit(UNIT, ports, { maxIndexPerChain: 60, burnedChangeCount: 0 }))
      .resolves.toMatchObject({ ok: false, failure: 'conflicting_sources', utxos: [] });
  });

  it.each([
    ['locally derived script', (utxos: SnapshotUtxo[]) => utxos.map((u) => ({ ...u, scriptPubKey: '0014' + 'c'.repeat(40) }))],
    ['foreign script hash', (utxos: SnapshotUtxo[]) => utxos.map((u) => ({ ...u, scriptHash: 'f'.repeat(64) }))],
    ['duplicate outpoint', (utxos: SnapshotUtxo[]) => [...utxos, ...utxos]],
  ])('rejects a snapshot with mismatched %s', async (_label, mutateSnapshotUtxos) => {
    const { ports } = makePorts({ activeExt: [0], mutateSnapshotUtxos });
    await expect(scanUnit(UNIT, ports, { maxIndexPerChain: 60, burnedChangeCount: 0 }))
      .resolves.toMatchObject({ ok: false, failure: 'conflicting_sources', utxos: [] });
  });

  it.each([
    ['omitted result', (body: ClassifyBody): ClassifyBody => ({ ...body, classifications: [] })],
    ['unknown result', (body: ClassifyBody): ClassifyBody => ({
      classifications: [],
      unknownOutpoints: body.classifications.map(({ txid, vout }) => ({ txid, vout })),
    })],
    ['foreign outpoint', (body: ClassifyBody): ClassifyBody => ({
      ...body,
      classifications: body.classifications.map((entry) => ({ ...entry, txid: 'e'.repeat(64) })),
    })],
    ['duplicate outpoint', (body: ClassifyBody): ClassifyBody => ({
      ...body,
      classifications: [...body.classifications, ...body.classifications],
    })],
    ['value mismatch', (body: ClassifyBody): ClassifyBody => ({
      ...body,
      classifications: body.classifications.map((entry) => ({ ...entry, valueSats: '9999' })),
    })],
    ['script mismatch', (body: ClassifyBody): ClassifyBody => ({
      ...body,
      classifications: body.classifications.map((entry) => ({ ...entry, scriptPubKey: '0014' + 'c'.repeat(40) })),
    })],
    ['record revision mismatch', (body: ClassifyBody): ClassifyBody => ({
      ...body,
      classifications: body.classifications.map((entry) => ({
        ...entry,
        classificationRevision: 'rev-foreign',
      })),
    })],
    ['record tip mismatch', (body: ClassifyBody): ClassifyBody => ({
      ...body,
      classifications: body.classifications.map((entry) => ({
        ...entry,
        classifiedTip: { height: 250_001, hash: 'd'.repeat(64) },
      })),
    })],
  ])('rejects a classification with %s', async (_label, mutateClassify) => {
    const { ports } = makePorts({ activeExt: [0], mutateClassify });
    await expect(scanUnit(UNIT, ports, { maxIndexPerChain: 60, burnedChangeCount: 0 }))
      .resolves.toMatchObject({ ok: false, failure: 'conflicting_sources', utxos: [] });
  });
});
