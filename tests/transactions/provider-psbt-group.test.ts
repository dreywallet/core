import { beforeAll, describe, expect, it } from 'vitest';
import { SigHash, Transaction } from '@scure/btc-signer';
import {
  deriveLinkedProviderPsbtGroup,
  validateLinkedProviderPsbtTopology,
  type LinkedProviderPsbtGroupItem,
} from '../../src/domain/transactions/provider-psbt-group';
import { bytesToBase64, hexToBytes } from '../../src/domain/vault/encoding';
import { installTestCryptoProvider } from '../helpers/install-crypto-provider';

beforeAll(() => installTestCryptoProvider());

const PAYMENT = `0014${'11'.repeat(20)}`;
const OTHER_PAYMENT = `0014${'22'.repeat(20)}`;
const ORDINAL = `5120${'33'.repeat(32)}`;
const LEGACY = `76a914${'44'.repeat(20)}88ac`;

interface Input {
  txid: string;
  vout?: number;
  amount: bigint;
  script: string;
  sighash?: number;
}

function psbt(input: {
  inputs: Input[];
  outputs: Array<{ amount: bigint; script: string }>;
  psbtVersion?: 0 | 2;
}): string {
  const tx = new Transaction({ lowR: true, PSBTVersion: input.psbtVersion ?? 0 });
  for (const item of input.inputs) {
    tx.addInput({
      txid: item.txid,
      index: item.vout ?? 0,
      sequence: 0xfffffffd,
      witnessUtxo: { amount: item.amount, script: hexToBytes(item.script) },
      ...(item.sighash === undefined ? {} : { sighashType: item.sighash }),
    });
  }
  for (const output of input.outputs) {
    tx.addOutput({ amount: output.amount, script: hexToBytes(output.script) });
  }
  return bytesToBase64(tx.toPSBT());
}

function item(nodeId: string, psbtBase64: string, selectedInputIndexes = [0]): LinkedProviderPsbtGroupItem {
  return { nodeId, psbtBase64, selectedInputIndexes };
}

function parent(sighash = SigHash.ALL, inputScript = PAYMENT, psbtVersion: 0 | 2 = 0): string {
  return psbt({
    inputs: [{ txid: 'aa'.repeat(32), amount: 100_000n, script: inputScript, sighash }],
    outputs: [{ amount: 99_000n, script: ORDINAL }],
    psbtVersion,
  });
}

function child(parentTxid: string, input: {
  amount?: bigint;
  script?: string;
  vout?: number;
  sighash?: number;
  outputAmount?: bigint;
  outputScript?: string;
  psbtVersion?: 0 | 2;
} = {}): string {
  return psbt({
    inputs: [{
      txid: parentTxid,
      ...(input.vout === undefined ? {} : { vout: input.vout }),
      amount: input.amount ?? 99_000n,
      script: input.script ?? ORDINAL,
      sighash: input.sighash ?? SigHash.ALL,
    }],
    outputs: [{ amount: input.outputAmount ?? 98_000n, script: input.outputScript ?? OTHER_PAYMENT }],
    ...(input.psbtVersion === undefined ? {} : { psbtVersion: input.psbtVersion }),
  });
}

function parentTxid(psbtBase64: string): string {
  return deriveLinkedProviderPsbtGroup([item('parent', psbtBase64)]).nodes[0]!.unsignedTxid;
}

function manyInputPsbt(inputCount: number, offset: number): string {
  return psbt({
    inputs: Array.from({ length: inputCount }, (_value, index) => ({
      txid: (offset + index + 1).toString(16).padStart(64, '0'),
      amount: 10_000n,
      script: PAYMENT,
      sighash: SigHash.ALL,
    })),
    outputs: [{ amount: 9_000n, script: OTHER_PAYMENT }],
  });
}

describe('derived linked provider PSBT groups', () => {
  it('derives a parent-child edge and normalizes topological order without changing response order', () => {
    const parentPsbt = parent(SigHash.ALL, PAYMENT, 2);
    const childPsbt = child(parentTxid(parentPsbt));
    const group = deriveLinkedProviderPsbtGroup([
      item('child', childPsbt),
      item('parent', parentPsbt),
    ]);
    expect(group.nodes.map((node) => [node.nodeId, node.requestIndex, node.psbtVersion])).toEqual([
      ['child', 0, 0], ['parent', 1, 2],
    ]);
    expect(group.topologicalNodeIds).toEqual(['parent', 'child']);
    expect(group.edges).toEqual([{
      parentNodeId: 'parent', parentOutputIndex: 0, childNodeId: 'child', childInputIndex: 0,
    }]);
    expect(group.independent).toBe(false);
    expect(group.signatureRelease).toBe('all_or_nothing');
    expect(Object.isFrozen(group)).toBe(true);
    expect(Object.isFrozen(group.nodes[0]!.commitments[0]!)).toBe(true);
  });

  it('represents settlement and recovery as bounded alternatives over one internal output', () => {
    const parentPsbt = parent();
    const txid = parentTxid(parentPsbt);
    const settlement = child(txid, { sighash: SigHash.SINGLE_ANYONECANPAY });
    const recovery = child(txid, { outputScript: PAYMENT, outputAmount: 97_000n });
    const group = deriveLinkedProviderPsbtGroup([
      item('settlement', settlement), item('parent', parentPsbt), item('recovery', recovery),
    ]);
    expect(group.topologicalNodeIds).toEqual(['parent', 'settlement', 'recovery']);
    expect(group.alternatives).toEqual([{
      source: 'linked_output',
      parentNodeId: 'parent',
      parentOutputIndex: 0,
      outpoint: `${txid}:0`,
      consumers: [{ nodeId: 'settlement', inputIndex: 0 }, { nodeId: 'recovery', inputIndex: 0 }],
    }]);
    expect(group.nodes.find((node) => node.nodeId === 'settlement')?.commitments[0]).toMatchObject({
      anyoneCanPay: true, committedInputIndexes: [0], committedOutputIndexes: [0], fee: 'mutable',
    });
  });

  it('keeps independent mixed-v0/v2 groups independent', () => {
    const group = deriveLinkedProviderPsbtGroup([
      item('v0', parent()),
      item('v2', psbt({
        inputs: [{ txid: 'bb'.repeat(32), amount: 90_000n, script: PAYMENT, sighash: SigHash.ALL }],
        outputs: [{ amount: 89_000n, script: OTHER_PAYMENT }],
        psbtVersion: 2,
      })),
    ]);
    expect(group.independent).toBe(true);
    expect(group.edges).toEqual([]);
    expect(group.alternatives).toEqual([]);
    expect(group.topologicalNodeIds).toEqual(['v0', 'v2']);
  });

  it('permits 500 selected group inputs but retains the 200-input per-item ceiling', () => {
    const first = item('first', manyInputPsbt(200, 0), Array.from({ length: 200 }, (_v, i) => i));
    const second = item('second', manyInputPsbt(200, 1_000), Array.from({ length: 200 }, (_v, i) => i));
    const hundred = item('hundred', manyInputPsbt(100, 2_000), Array.from({ length: 100 }, (_v, i) => i));
    const group = deriveLinkedProviderPsbtGroup([first, second, hundred]);
    expect(group.nodes.reduce((total, node) => total + node.inputs.length, 0)).toBe(500);
    expect(group.nodes.reduce((total, node) => total + node.selectedInputIndexes.length, 0)).toBe(500);

    const hundredAndOne = item('hundred-and-one', manyInputPsbt(101, 3_000),
      Array.from({ length: 101 }, (_v, i) => i));
    expect(() => deriveLinkedProviderPsbtGroup([first, second, hundredAndOne]))
      .toThrow(/aggregate resource limits/u);
    expect(() => deriveLinkedProviderPsbtGroup([
      item('too-large', manyInputPsbt(201, 4_000), Array.from({ length: 201 }, (_v, i) => i)),
    ])).toThrow(/PSBT input count exceeds 200/u);
  });

  it('rejects malformed links and represents bounded multi-consumer conflict sets', () => {
    const parentPsbt = parent();
    const txid = parentTxid(parentPsbt);
    expect(() => deriveLinkedProviderPsbtGroup([
      item('parent', parentPsbt), item('mismatch', child(txid, { amount: 99_001n })),
    ])).toThrow(/differs from its parent output/u);
    expect(() => deriveLinkedProviderPsbtGroup([
      item('parent', parentPsbt), item('missing', child(txid, { vout: 1 })),
    ])).toThrow(/missing parent output/u);
    const alternatives = deriveLinkedProviderPsbtGroup([
      item('parent', parentPsbt),
      item('one', child(txid)),
      item('two', child(txid, { outputAmount: 97_000n })),
      item('three', child(txid, { outputAmount: 96_000n })),
    ]);
    expect(alternatives.alternatives[0]?.consumers.map((consumer) => consumer.nodeId))
      .toEqual(['one', 'two', 'three']);
  });

  it('represents repeated external inputs as bounded conflict sets', () => {
    const first = psbt({
      inputs: [{ txid: 'cc'.repeat(32), amount: 50_000n, script: PAYMENT, sighash: SigHash.ALL }],
      outputs: [{ amount: 49_000n, script: OTHER_PAYMENT }],
    });
    const second = psbt({
      inputs: [{ txid: 'cc'.repeat(32), amount: 50_000n, script: PAYMENT, sighash: SigHash.ALL }],
      outputs: [{ amount: 48_000n, script: OTHER_PAYMENT }],
    });
    const group = deriveLinkedProviderPsbtGroup([item('one', first), item('two', second)]);
    expect(group.independent).toBe(false);
    expect(group.alternatives).toEqual([{
      source: 'external_input',
      parentNodeId: null,
      parentOutputIndex: 0,
      outpoint: `${'cc'.repeat(32)}:0`,
      consumers: [{ nodeId: 'one', inputIndex: 0 }, { nodeId: 'two', inputIndex: 0 }],
    }]);
  });

  it('requires linked parents to fix a native-SegWit transaction id', () => {
    for (const [label, parentPsbt] of [
      ['mutable', parent(SigHash.ALL_ANYONECANPAY)],
      ['legacy', parent(SigHash.ALL, LEGACY)],
    ] as const) {
      const txid = parentTxid(parentPsbt);
      expect(() => deriveLinkedProviderPsbtGroup([
        item(label, parentPsbt), item('child', child(txid)),
      ])).toThrow(label === 'mutable' ? /does not fix its transaction id/u : /scriptSig-mutable/u);
    }
  });

  it('recomputes commitment facts before applying atomic linked-parent policy', () => {
    const parentPsbt = parent();
    const linked = deriveLinkedProviderPsbtGroup([
      item('parent', parentPsbt), item('child', child(parentTxid(parentPsbt))),
    ]);
    const nodes = structuredClone(linked.nodes);
    nodes[0]!.commitments[0]!.mutableOutputIndexes = [0];
    expect(() => validateLinkedProviderPsbtTopology(nodes))
      .toThrow(/commitment facts are inconsistent/u);
  });

  it('rejects structurally invalid SINGLE at the group commitment boundary', () => {
    const invalid = psbt({
      inputs: [
        { txid: 'dd'.repeat(32), amount: 40_000n, script: PAYMENT, sighash: SigHash.ALL },
        { txid: 'ee'.repeat(32), amount: 30_000n, script: PAYMENT, sighash: SigHash.SINGLE },
      ],
      outputs: [{ amount: 69_000n, script: OTHER_PAYMENT }],
    });
    expect(() => deriveLinkedProviderPsbtGroup([item('invalid', invalid, [1])]))
      .toThrow(/SINGLE without a corresponding output/u);
  });

  it('detects a cycle in already-derived node facts', () => {
    const parentPsbt = parent();
    const linked = deriveLinkedProviderPsbtGroup([
      item('one', parentPsbt), item('two', child(parentTxid(parentPsbt))),
    ]);
    const nodes = structuredClone(linked.nodes);
    nodes[0]!.unsignedTxid = '11'.repeat(32);
    nodes[1]!.unsignedTxid = '22'.repeat(32);
    nodes[0]!.inputs[0] = {
      txid: nodes[1]!.unsignedTxid, vout: 0, ...nodes[1]!.outputs[0]!,
    };
    nodes[1]!.inputs[0] = {
      txid: nodes[0]!.unsignedTxid, vout: 0, ...nodes[0]!.outputs[0]!,
    };
    expect(() => validateLinkedProviderPsbtTopology(nodes)).toThrow(/cycle/u);
  });
});
