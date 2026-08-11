import { describe, expect, it } from 'vitest';
import fc from 'fast-check';
import {
  layoutSatFlow,
  projectSatFlowModel,
  satFlowEligible,
  satFlowSummary,
  SAT_FLOW_MAX_INPUTS,
  SAT_FLOW_MAX_OUTPUTS,
  SAT_FLOW_VIEW,
  type SatFlowInscription,
  type SatFlowModel,
} from '../../src/domain/transactions/sat-flow-layout';
import type { TransactionAnalysis } from '../../src/domain/transactions/analysis';

const ID = `${'a1'.repeat(32)}i0`;
const ID2 = `${'b2'.repeat(32)}i0`;
const ID3 = `${'c3'.repeat(32)}i0`;

function model(overrides: Partial<SatFlowModel> = {}): SatFlowModel {
  return {
    inputs: [
      { index: 0, valueSats: 10_000n, ownership: 'wallet' },
      { index: 1, valueSats: 120_000n, ownership: 'wallet' },
    ],
    outputs: [
      { index: 0, valueSats: 10_000n, ownership: 'external', role: 'recipient', committed: true },
      { index: 1, valueSats: 119_589n, ownership: 'wallet', role: 'payment_change', committed: true },
    ],
    inscriptions: [
      { inscriptionId: ID, number: 1234, inputIndex: 0, outputIndex: 0, movement: 'sent' },
    ],
    feeSats: 411n,
    protectedValueExposedToFees: 0n,
    ...overrides,
  };
}

function analysis(overrides: Partial<TransactionAnalysis> = {}): TransactionAnalysis {
  const classifiedTip = { height: 250_000, hash: '11'.repeat(32) };
  const source = {
    backend: 'fixture', instanceId: 'fixture-1', classificationRevision: 'rev-1',
    coreTip: classifiedTip, indexTip: classifiedTip, feeQuoteTimestamp: null, mempoolState: null,
  };
  return {
    version: 1,
    network: 'signet',
    account: 0,
    kind: 'native_send',
    source,
    inputs: [
      {
        index: 0, txid: '22'.repeat(32), vout: 0, valueSats: 10_000n,
        scriptPubKey: `0014${'33'.repeat(20)}`, scriptKind: 'p2wpkh', sequence: 0xfffffffd,
        ownership: 'wallet', derivation: null,
        classification: {
          primaryClass: 'inscribed',
          inscriptions: [{ inscriptionId: ID, number: 42, satpoint: `${'22'.repeat(32)}:0:0` }],
          satRanges: null, unsupportedAssetDetected: false, confidence: 'authoritative',
          classifiedTip, classificationRevision: 'rev-1',
        },
        sighash: {
          raw: 3, outputMode: 'single', anyoneCanPay: false,
          committedOutputIndexes: [0], validEncoding: true,
        },
      },
      {
        index: 1, txid: '44'.repeat(32), vout: 1, valueSats: 120_000n,
        scriptPubKey: `0014${'55'.repeat(20)}`, scriptKind: 'p2wpkh', sequence: 0xfffffffd,
        ownership: 'wallet', derivation: null,
        classification: {
          primaryClass: 'cardinal_clean', inscriptions: [], satRanges: null,
          unsupportedAssetDetected: false, confidence: 'authoritative',
          classifiedTip, classificationRevision: 'rev-1',
        },
        sighash: {
          raw: 3, outputMode: 'single', anyoneCanPay: false,
          committedOutputIndexes: [1], validEncoding: true,
        },
      },
    ],
    outputs: [
      { index: 0, valueSats: 10_000n, scriptPubKey: `5120${'66'.repeat(32)}`,
        address: 'recipient', role: 'recipient', ownership: 'external', derivation: null },
      { index: 1, valueSats: 119_589n, scriptPubKey: `0014${'77'.repeat(20)}`,
        address: 'change', role: 'payment_change', ownership: 'wallet', derivation: null },
    ],
    assetEffects: {
      protectedSatFlow: [{
        inputIndex: 0, inputOffset: 0n, outputIndex: 0, outputOffset: 0n, inscriptionId: ID,
      }],
      protectedInputIndexes: [0],
      protectedValueExposedToFees: 0n,
      inscriptions: [{
        inscriptionId: ID, satpoint: `${'22'.repeat(32)}:0:0`,
        outpoint: { txid: '22'.repeat(32), vout: 0 },
        inputIndex: 0, inputOffset: 0n, outputIndex: 0, outputOffset: 0n,
        inputOwnership: 'wallet', outputOwnership: 'external', movement: 'sent',
        coLocationGroup: `${'22'.repeat(32)}:0:0`, qualifiedPartialAuthorization: false,
      }],
      effectSetHash: '88'.repeat(32),
    },
    fee: {
      sats: 411n, vsize: 200n, targetSatPerKvB: 2_055n,
      effectiveRateNumerator: 411n, effectiveRateDenominator: 200n,
    },
    rbf: { replaceable: true, sequences: [0xfffffffd, 0xfffffffd] },
    warnings: [],
    hardViolations: [],
    marketplaceCommitment: null,
    ...overrides,
  };
}

describe('projectSatFlowModel', () => {
  it('projects exact analyzer-owned values, ownership, commitments, movement and fee exposure', () => {
    const projected = projectSatFlowModel(analysis({
      assetEffects: {
        ...analysis().assetEffects,
        protectedValueExposedToFees: 7n,
      },
    }));
    expect(projected).toEqual({
      inputs: [
        { index: 0, valueSats: 10_000n, ownership: 'wallet' },
        { index: 1, valueSats: 120_000n, ownership: 'wallet' },
      ],
      outputs: [
        { index: 0, valueSats: 10_000n, ownership: 'external', role: 'recipient', committed: true },
        { index: 1, valueSats: 119_589n, ownership: 'wallet', role: 'payment_change', committed: true },
      ],
      inscriptions: [{
        inscriptionId: ID, number: 42, inputIndex: 0, outputIndex: 0, movement: 'sent',
      }],
      feeSats: 411n,
      protectedValueExposedToFees: 7n,
    });
    expect(Object.isFrozen(projected)).toBe(true);
    expect(projected).not.toHaveProperty('address');
  });

  it('marks an output uncommitted only when no analyzed input commits to it', () => {
    const value = analysis();
    value.inputs[1]!.sighash.committedOutputIndexes = [0];
    expect(projectSatFlowModel(value)?.outputs.map((output) => output.committed)).toEqual([true, false]);
  });

  it('fails closed for analyzer violations and malformed indexes, commitments or protected mappings', () => {
    expect(projectSatFlowModel(analysis({ hardViolations: [{ code: 'shape_mismatch' }] }))).toBeNull();

    const skewed = analysis();
    skewed.outputs[0]!.index = 1;
    expect(projectSatFlowModel(skewed)).toBeNull();

    const commitment = analysis();
    commitment.inputs[0]!.sighash.committedOutputIndexes = [9];
    expect(projectSatFlowModel(commitment)).toBeNull();

    const mapping = analysis();
    mapping.assetEffects.protectedSatFlow = [];
    expect(projectSatFlowModel(mapping)).toBeNull();
  });
});

describe('satFlowEligible', () => {
  it('accepts the common transfer shape', () => {
    expect(satFlowEligible(model())).toBe(true);
  });

  it('refuses shapes past the node cap, because crossing curves stop being traceable', () => {
    const many = Array.from({ length: SAT_FLOW_MAX_INPUTS + 1 }, (_, index) => ({
      index,
      valueSats: 1_000n,
      ownership: 'wallet' as const,
    }));
    expect(satFlowEligible(model({ inputs: many, inscriptions: [] }))).toBe(false);

    const manyOutputs = Array.from({ length: SAT_FLOW_MAX_OUTPUTS + 1 }, (_, index) => ({
      index,
      valueSats: 1_000n,
      ownership: 'wallet' as const,
      role: 'recipient',
      committed: true,
    }));
    expect(satFlowEligible(model({ outputs: manyOutputs, inscriptions: [] }))).toBe(false);
  });

  it('refuses an empty transaction', () => {
    expect(satFlowEligible(model({ inputs: [], inscriptions: [] }))).toBe(false);
    expect(satFlowEligible(model({ outputs: [], inscriptions: [] }))).toBe(false);
  });

  it('refuses an inscription pointing outside the input or output range', () => {
    expect(satFlowEligible(model({
      inscriptions: [{ inscriptionId: ID, number: 1, inputIndex: 7, outputIndex: 0, movement: 'sent' }],
    }))).toBe(false);
    expect(satFlowEligible(model({
      inscriptions: [{ inscriptionId: ID, number: 1, inputIndex: 0, outputIndex: 7, movement: 'sent' }],
    }))).toBe(false);
    expect(satFlowEligible(model({
      inscriptions: [{ inscriptionId: ID, number: 1, inputIndex: -1, outputIndex: 0, movement: 'sent' }],
    }))).toBe(false);
  });

  it('refuses indexes that do not match position, so a node cannot misrepresent its index', () => {
    expect(satFlowEligible(model({
      inputs: [
        { index: 1, valueSats: 1n, ownership: 'wallet' },
        { index: 0, valueSats: 1n, ownership: 'wallet' },
      ],
      inscriptions: [],
    }))).toBe(false);
  });

  it('refuses negative amounts', () => {
    expect(satFlowEligible(model({ feeSats: -1n }))).toBe(false);
    expect(satFlowEligible(model({ protectedValueExposedToFees: -1n }))).toBe(false);
  });
});

describe('layoutSatFlow', () => {
  it('throws rather than drawing an ineligible shape', () => {
    expect(() => layoutSatFlow(model({ inputs: [], inscriptions: [] }))).toThrow();
  });

  it('adds a fee node beyond the declared outputs', () => {
    const layout = layoutSatFlow(model());
    expect(layout.nodes.filter((node) => node.kind === 'output')).toHaveLength(2);
    expect(layout.nodes.filter((node) => node.kind === 'fee')).toHaveLength(1);
  });

  it('marks only inscription edges as proven', () => {
    const layout = layoutSatFlow(model());
    const proven = layout.edges.filter((edge) => edge.proven);
    expect(proven).toHaveLength(1);
    expect(proven[0]?.kind).toBe('inscription');
    expect(layout.edges.every((edge) => edge.kind === 'inscription' || !edge.proven)).toBe(true);
  });

  it('gives co-located inscriptions a single shared curve', () => {
    const coLocated: SatFlowInscription[] = [
      { inscriptionId: ID, number: 1, inputIndex: 0, outputIndex: 0, movement: 'sent' },
      { inscriptionId: ID2, number: 2, inputIndex: 0, outputIndex: 0, movement: 'sent' },
    ];
    const layout = layoutSatFlow(model({ inscriptions: coLocated }));
    const proven = layout.edges.filter((edge) => edge.proven);
    expect(proven).toHaveLength(1);
    expect(proven[0]?.inscriptions).toHaveLength(2);
  });

  it('splits one input across two outputs when the proof says so', () => {
    const split: SatFlowInscription[] = [
      { inscriptionId: ID, number: 1, inputIndex: 0, outputIndex: 0, movement: 'sent' },
      { inscriptionId: ID2, number: 2, inputIndex: 0, outputIndex: 1, movement: 'retained' },
    ];
    const layout = layoutSatFlow(model({ inscriptions: split }));
    expect(layout.edges.filter((edge) => edge.proven)).toHaveLength(2);
  });

  it('never routes a proven curve into the fee node', () => {
    const layout = layoutSatFlow(model());
    const feeNode = layout.nodes.find((node) => node.kind === 'fee');
    const feeAnchor = `${feeNode?.anchorX.toFixed(2)} ${feeNode?.anchorY.toFixed(2)}`;
    for (const edge of layout.edges.filter((item) => item.proven)) {
      expect(edge.d.endsWith(feeAnchor)).toBe(false);
    }
  });

  it('flags the fee edge and node as danger only when protected value is exposed', () => {
    const safe = layoutSatFlow(model());
    expect(safe.edges.some((edge) => edge.danger)).toBe(false);
    expect(safe.nodes.some((node) => node.danger)).toBe(false);

    const risky = layoutSatFlow(model({ protectedValueExposedToFees: 6_000n }));
    expect(risky.edges.filter((edge) => edge.danger && edge.kind === 'fee')).toHaveLength(1);
    expect(risky.nodes.filter((node) => node.danger)).toHaveLength(1);
  });

  it('marks edges into an output the signature does not commit to', () => {
    const layout = layoutSatFlow(model({
      outputs: [
        { index: 0, valueSats: 10_000n, ownership: 'external', role: 'recipient', committed: true },
        { index: 1, valueSats: 5_000n, ownership: 'unproven', role: 'unknown', committed: false },
      ],
      inscriptions: [],
    }));
    expect(layout.edges.filter((edge) => edge.uncommitted)).toHaveLength(1);
  });

  it('keeps every node inside the view box', () => {
    const layout = layoutSatFlow(model());
    for (const node of layout.nodes) {
      expect(node.x).toBeGreaterThanOrEqual(0);
      expect(node.x + node.width).toBeLessThanOrEqual(SAT_FLOW_VIEW.width + 0.01);
      expect(node.y).toBeGreaterThanOrEqual(SAT_FLOW_VIEW.rowTop);
      expect(node.y + node.height).toBeLessThanOrEqual(SAT_FLOW_VIEW.height + 0.01);
    }
  });

  it('emits path data containing only finite numbers', () => {
    const layout = layoutSatFlow(model({ protectedValueExposedToFees: 1n }));
    for (const edge of layout.edges) {
      expect(edge.d).toMatch(/^M[-\d. C]+$/u);
      expect(edge.d).not.toContain('NaN');
      expect(edge.d).not.toContain('Infinity');
    }
  });
});

describe('satFlowSummary', () => {
  it('counts movements and uncommitted outputs', () => {
    const summary = satFlowSummary(model({
      inscriptions: [
        { inscriptionId: ID, number: 1, inputIndex: 0, outputIndex: 0, movement: 'sent' },
        { inscriptionId: ID2, number: 2, inputIndex: 0, outputIndex: 1, movement: 'retained' },
        { inscriptionId: ID3, number: 3, inputIndex: 1, outputIndex: 1, movement: 'received' },
      ],
      outputs: [
        { index: 0, valueSats: 1n, ownership: 'external', role: 'recipient', committed: true },
        { index: 1, valueSats: 1n, ownership: 'wallet', role: 'payment_change', committed: false },
      ],
    }));
    expect(summary).toMatchObject({
      sent: 1, retained: 1, received: 1, inputCount: 2, outputCount: 2, uncommittedOutputCount: 1,
    });
  });
});

describe('sat-flow properties', () => {
  const inscriptionArb = (inputCount: number, outputCount: number) =>
    fc.array(
      fc.record({
        inputIndex: fc.integer({ min: 0, max: inputCount - 1 }),
        outputIndex: fc.integer({ min: 0, max: outputCount - 1 }),
        movement: fc.constantFrom('sent', 'retained', 'received'),
      }),
      { maxLength: 6 },
    ).map((items) => items.map((item, i) => ({
      inscriptionId: `${i.toString(16).padStart(2, '0').repeat(32)}i0`,
      number: i,
      ...item,
    })) as SatFlowInscription[]);

  // Counts must be drawn before the inscriptions, so that generated indexes are
  // always in range; chaining keeps it a single flat property.
  const shapeArb = fc.integer({ min: 1, max: SAT_FLOW_MAX_INPUTS }).chain((inputCount) =>
    fc.integer({ min: 1, max: SAT_FLOW_MAX_OUTPUTS }).chain((outputCount) =>
      fc.tuple(
        fc.constant(inputCount),
        fc.constant(outputCount),
        fc.bigInt({ min: 0n, max: 1_000_000n }),
        inscriptionArb(inputCount, outputCount),
      )));

  it('draws exactly one proven edge per distinct input/output pair, and none into the fee', () => {
    fc.assert(fc.property(
      shapeArb,
      ([inputCount, outputCount, fee, inscriptions]) => {
        const candidate: SatFlowModel = {
          inputs: Array.from({ length: inputCount }, (_, index) => ({
            index,
            valueSats: 10_000n,
            ownership: 'wallet' as const,
          })),
          outputs: Array.from({ length: outputCount }, (_, index) => ({
            index,
            valueSats: 1_000n,
            ownership: 'wallet' as const,
            role: 'recipient',
            committed: true,
          })),
          inscriptions,
          feeSats: fee,
          protectedValueExposedToFees: 0n,
        };
        expect(satFlowEligible(candidate)).toBe(true);
        const layout = layoutSatFlow(candidate);

        const pairs = new Set(inscriptions.map((item) => `${item.inputIndex}->${item.outputIndex}`));
        expect(layout.edges.filter((edge) => edge.proven)).toHaveLength(pairs.size);

        // Every inscription must be represented exactly once across all edges.
        const drawn = layout.edges.flatMap((edge) => edge.inscriptions);
        expect(drawn).toHaveLength(inscriptions.length);

        // A proven curve may never terminate at the fee node.
        const feeNode = layout.nodes.find((node) => node.kind === 'fee')!;
        const feeAnchor = `${feeNode.anchorX.toFixed(2)} ${feeNode.anchorY.toFixed(2)}`;
        for (const edge of layout.edges.filter((item) => item.proven)) {
          expect(edge.d.endsWith(feeAnchor)).toBe(false);
        }
        return true;
      },
    ), { numRuns: 200 });
  });
});
