/**
 * Engine-level scan tests: gap-limit window widening, the §8.2 boundary
 * prompt, cancellation between requests, and the §11.4 revision-equality rule
 * (one refetch, then conflicting_sources) — all against synthetic ports, no
 * crypto.
 */
import { describe, expect, it } from 'vitest';
import type {
  OutpointsClassifyResponse,
  WalletSnapshotResponse,
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

type SnapshotUtxo = WalletSnapshotResponse['utxos'][number];
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
  mutateClassify?: (body: ClassifyBody) => ClassifyBody;
}

function makePorts(options: FakeOptions) {
  const snapshotRequests: string[][] = [];
  const ordinalFlowRequests: Array<boolean | undefined> = [];
  let cancelled = false;
  const activeByHash = new Map(options.activeExt.map((i) => [hashAt(0, i), i]));
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
      const value: WalletSnapshotResponse = {
        ...envelope(revision),
        requestedScriptHashes: options.echoRequested
          ? options.echoRequested(req.scriptHashes)
          : req.scriptHashes,
        utxos: options.mutateSnapshotUtxos?.(baseUtxos) ?? baseUtxos,
        history: [],
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
