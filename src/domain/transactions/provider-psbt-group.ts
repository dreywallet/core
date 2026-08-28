import { RawTx, Transaction } from '@scure/btc-signer';
import { base64ToBytes, bytesToBase64, bytesToHex } from '../vault/encoding';
import { getCryptoProvider } from '../vault/crypto-provider';
import {
  analyzePsbtInputCommitment,
  type PsbtInputCommitmentAnalysis,
} from './psbt-commitment';
import {
  assertProviderPsbtItemCounts,
  PROVIDER_MAX_LINKED_PSBT_GROUP_INPUTS,
  PROVIDER_MAX_LINKED_PSBT_GROUP_SELECTED_INPUTS,
  PROVIDER_MAX_PSBT_BATCH_BASE64_CHARS,
  PROVIDER_MAX_PSBT_BATCH_ITEMS,
  PROVIDER_MAX_PSBT_OUTPUTS,
} from './provider-psbt-limits';

export interface LinkedProviderPsbtGroupItem {
  nodeId: string;
  psbtBase64: string;
  selectedInputIndexes: readonly number[];
}

export interface LinkedProviderPsbtInput {
  txid: string;
  vout: number;
  valueSats: bigint;
  scriptPubKey: string;
}

export interface LinkedProviderPsbtOutput {
  valueSats: bigint;
  scriptPubKey: string;
}

export interface LinkedProviderPsbtNode {
  nodeId: string;
  requestIndex: number;
  unsignedTxid: string;
  psbtVersion: 0 | 2;
  inputs: LinkedProviderPsbtInput[];
  outputs: LinkedProviderPsbtOutput[];
  selectedInputIndexes: number[];
  commitments: PsbtInputCommitmentAnalysis[];
}

export interface LinkedProviderPsbtEdge {
  parentNodeId: string;
  parentOutputIndex: number;
  childNodeId: string;
  childInputIndex: number;
}

export interface LinkedProviderPsbtAlternative {
  source: 'linked_output' | 'external_input';
  parentNodeId: string | null;
  parentOutputIndex: number;
  outpoint: string;
  consumers: Array<{ nodeId: string; inputIndex: number }>;
}

export interface LinkedProviderPsbtGroupTopologyV1 {
  version: 1;
  /** A future signer must release either every result or none of them. */
  signatureRelease: 'all_or_nothing';
  nodes: LinkedProviderPsbtNode[];
  edges: LinkedProviderPsbtEdge[];
  alternatives: LinkedProviderPsbtAlternative[];
  topologicalNodeIds: string[];
  independent: boolean;
}

function doubleSha256Txid(bytes: Uint8Array): string {
  const crypto = getCryptoProvider();
  return bytesToHex(crypto.sha256(crypto.sha256(bytes)).reverse());
}

function previousOutput(tx: Transaction, index: number): LinkedProviderPsbtOutput {
  const input = tx.getInput(index);
  let witness = input.witnessUtxo;
  if (input.nonWitnessUtxo) {
    const previous = Transaction.fromRaw(RawTx.encode(input.nonWitnessUtxo));
    if (!input.txid || previous.id !== bytesToHex(input.txid)) {
      throw new Error('linked PSBT non-witness transaction id mismatch');
    }
    const output = input.index === undefined ? undefined : previous.getOutput(input.index);
    if (!output?.script || output.amount === undefined) {
      throw new Error('linked PSBT non-witness prevout is missing');
    }
    const decoded = { valueSats: output.amount, scriptPubKey: bytesToHex(output.script) };
    if (witness && (witness.amount !== decoded.valueSats ||
        bytesToHex(witness.script) !== decoded.scriptPubKey)) {
      throw new Error('linked PSBT witness and non-witness prevouts disagree');
    }
    witness = { amount: decoded.valueSats, script: output.script };
  }
  if (!witness) throw new Error('linked PSBT input is missing its previous output');
  return { valueSats: witness.amount, scriptPubKey: bytesToHex(witness.script) };
}

function selectedSighash(tx: Transaction, index: number, scriptPubKey: string): number {
  const explicit = tx.getInput(index).sighashType;
  if (explicit !== undefined) return explicit;
  // Native Taproot defaults to DEFAULT; the supported SegWit v0 paths default
  // to ALL. Other selected scripts must declare their sighash explicitly.
  if (/^5120[0-9a-f]{64}$/u.test(scriptPubKey)) return 0;
  if (/^00(?:14[0-9a-f]{40}|20[0-9a-f]{64})$/u.test(scriptPubKey)) return 1;
  throw new Error('linked PSBT selected input has no supported default sighash');
}

function nativeWitnessScript(scriptPubKey: string): boolean {
  return /^(?:0014[0-9a-f]{40}|0020[0-9a-f]{64}|5120[0-9a-f]{64})$/u.test(scriptPubKey);
}

function fixedTransactionCommitment(commitment: PsbtInputCommitmentAnalysis): boolean {
  return commitment.committedInputIndexes === 'all' &&
    commitment.committedOutputIndexes === 'all';
}

function sameIndexes(left: number[] | 'all', right: number[] | 'all'): boolean {
  return left === 'all' || right === 'all'
    ? left === right
    : left.length === right.length && left.every((value, index) => value === right[index]);
}

function sameCommitment(
  actual: PsbtInputCommitmentAnalysis,
  expected: PsbtInputCommitmentAnalysis,
): boolean {
  return actual.inputIndex === expected.inputIndex && actual.rawSighash === expected.rawSighash &&
    actual.outputMode === expected.outputMode && actual.anyoneCanPay === expected.anyoneCanPay &&
    sameIndexes(actual.committedInputIndexes, expected.committedInputIndexes) &&
    sameIndexes(actual.mutableInputIndexes, expected.mutableInputIndexes) &&
    sameIndexes(actual.committedOutputIndexes, expected.committedOutputIndexes) &&
    sameIndexes(actual.mutableOutputIndexes, expected.mutableOutputIndexes) && actual.fee === expected.fee;
}

function validScript(scriptPubKey: string): boolean {
  return /^(?:[0-9a-f]{2})+$/u.test(scriptPubKey);
}

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value as Record<string, unknown>)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

function nodeOrder(a: LinkedProviderPsbtNode, b: LinkedProviderPsbtNode): number {
  return a.requestIndex - b.requestIndex || a.nodeId.localeCompare(b.nodeId);
}

function cloneNode(node: LinkedProviderPsbtNode): LinkedProviderPsbtNode {
  return {
    ...node,
    inputs: node.inputs.map((input) => ({ ...input })),
    outputs: node.outputs.map((output) => ({ ...output })),
    selectedInputIndexes: [...node.selectedInputIndexes],
    commitments: node.commitments.map((commitment) => ({
      ...commitment,
      committedInputIndexes: commitment.committedInputIndexes === 'all'
        ? 'all' : [...commitment.committedInputIndexes],
      mutableInputIndexes: [...commitment.mutableInputIndexes],
      committedOutputIndexes: commitment.committedOutputIndexes === 'all'
        ? 'all' : [...commitment.committedOutputIndexes],
      mutableOutputIndexes: [...commitment.mutableOutputIndexes],
    })),
  };
}

/**
 * Validate already-derived node facts. This separate boundary makes topology
 * policy testable without asking tests to solve transaction-id fixed points in
 * order to construct a malicious cycle.
 */
export function validateLinkedProviderPsbtTopology(
  sourceNodes: readonly LinkedProviderPsbtNode[],
): LinkedProviderPsbtGroupTopologyV1 {
  if (sourceNodes.length === 0 || sourceNodes.length > PROVIDER_MAX_PSBT_BATCH_ITEMS) {
    throw new Error(`linked PSBT group must contain 1-${PROVIDER_MAX_PSBT_BATCH_ITEMS} nodes`);
  }
  // Keep Core portable across MV3, Hermes, and recovery runtimes without
  // depending on a host-provided structuredClone implementation.
  const nodes = sourceNodes.map(cloneNode);
  const byId = new Map<string, LinkedProviderPsbtNode>();
  const byTxid = new Map<string, LinkedProviderPsbtNode>();
  const requestIndexes = new Set<number>();
  let inputCount = 0;
  let outputCount = 0;
  let selectedInputCount = 0;
  for (const node of nodes) {
    if (!node.nodeId || node.nodeId.length > 128 || byId.has(node.nodeId) ||
        !Number.isSafeInteger(node.requestIndex) || node.requestIndex < 0 ||
        requestIndexes.has(node.requestIndex) || !/^[0-9a-f]{64}$/u.test(node.unsignedTxid) ||
        byTxid.has(node.unsignedTxid) || (node.psbtVersion !== 0 && node.psbtVersion !== 2)) {
      throw new Error('linked PSBT node identity is invalid or duplicated');
    }
    if (node.selectedInputIndexes.length === 0 ||
        new Set(node.selectedInputIndexes).size !== node.selectedInputIndexes.length ||
        node.selectedInputIndexes.some((index, position) =>
          position > 0 && index <= node.selectedInputIndexes[position - 1]!) ||
        node.selectedInputIndexes.some((index) => !Number.isSafeInteger(index) || index < 0 ||
          index >= node.inputs.length) ||
        node.commitments.length !== node.selectedInputIndexes.length ||
        node.commitments.some((commitment, index) =>
          commitment.inputIndex !== node.selectedInputIndexes[index])) {
      throw new Error('linked PSBT signing selection is invalid');
    }
    if (node.outputs.length === 0 || node.inputs.some((input) =>
      !/^[0-9a-f]{64}$/u.test(input.txid) || !Number.isSafeInteger(input.vout) || input.vout < 0 ||
      input.vout > 0xffffffff || typeof input.valueSats !== 'bigint' || input.valueSats < 0n ||
      !validScript(input.scriptPubKey)) || node.outputs.some((output) =>
      typeof output.valueSats !== 'bigint' || output.valueSats < 0n || !validScript(output.scriptPubKey))) {
      throw new Error('linked PSBT transaction facts are invalid');
    }
    for (const commitment of node.commitments) {
      const expected = analyzePsbtInputCommitment({
        rawSighash: commitment.rawSighash,
        inputIndex: commitment.inputIndex,
        inputCount: node.inputs.length,
        outputCount: node.outputs.length,
      });
      if (!sameCommitment(commitment, expected)) {
        throw new Error('linked PSBT commitment facts are inconsistent');
      }
    }
    assertProviderPsbtItemCounts({
      inputsLength: node.inputs.length,
      outputsLength: node.outputs.length,
    });
    byId.set(node.nodeId, node);
    byTxid.set(node.unsignedTxid, node);
    requestIndexes.add(node.requestIndex);
    inputCount += node.inputs.length;
    outputCount += node.outputs.length;
    selectedInputCount += node.selectedInputIndexes.length;
  }
  if (inputCount > PROVIDER_MAX_LINKED_PSBT_GROUP_INPUTS ||
      selectedInputCount > PROVIDER_MAX_LINKED_PSBT_GROUP_SELECTED_INPUTS ||
      outputCount > PROVIDER_MAX_PSBT_OUTPUTS) {
    throw new Error('linked PSBT group exceeds aggregate resource limits');
  }

  const edges: LinkedProviderPsbtEdge[] = [];
  const consumers = new Map<string, Array<{ node: LinkedProviderPsbtNode; inputIndex: number }>>();
  for (const node of nodes) {
    const nodeOutpoints = new Set<string>();
    for (let inputIndex = 0; inputIndex < node.inputs.length; inputIndex += 1) {
      const input = node.inputs[inputIndex]!;
      const outpoint = `${input.txid}:${input.vout}`;
      if (nodeOutpoints.has(outpoint)) throw new Error('linked PSBT node repeats an input outpoint');
      nodeOutpoints.add(outpoint);
      const list = consumers.get(outpoint) ?? [];
      list.push({ node, inputIndex });
      consumers.set(outpoint, list);

      const parent = byTxid.get(input.txid);
      if (!parent) continue;
      const output = parent.outputs[input.vout];
      if (!output) throw new Error('linked PSBT input references a missing parent output');
      if (input.valueSats !== output.valueSats || input.scriptPubKey !== output.scriptPubKey) {
        throw new Error('linked PSBT child prevout differs from its parent output');
      }
      edges.push({
        parentNodeId: parent.nodeId,
        parentOutputIndex: input.vout,
        childNodeId: node.nodeId,
        childInputIndex: inputIndex,
      });
    }
  }

  const alternatives: LinkedProviderPsbtAlternative[] = [];
  for (const [outpoint, list] of consumers) {
    if (list.length <= 1) continue;
    const [txid, voutText] = outpoint.split(':');
    const parent = txid ? byTxid.get(txid) : undefined;
    alternatives.push({
      source: parent ? 'linked_output' : 'external_input',
      parentNodeId: parent?.nodeId ?? null,
      parentOutputIndex: Number(voutText),
      outpoint,
      consumers: list
        .map(({ node, inputIndex }) => ({ nodeId: node.nodeId, inputIndex }))
        .sort((a, b) => (byId.get(a.nodeId)?.requestIndex ?? 0) -
          (byId.get(b.nodeId)?.requestIndex ?? 0) || a.inputIndex - b.inputIndex),
    });
  }

  const indegree = new Map(nodes.map((node) => [node.nodeId, 0]));
  const children = new Map(nodes.map((node) => [node.nodeId, new Set<string>()]));
  for (const edge of edges) {
    const childSet = children.get(edge.parentNodeId)!;
    if (!childSet.has(edge.childNodeId)) {
      childSet.add(edge.childNodeId);
      indegree.set(edge.childNodeId, indegree.get(edge.childNodeId)! + 1);
    }
  }
  const ready = nodes.filter((node) => indegree.get(node.nodeId) === 0).sort(nodeOrder);
  const topologicalNodeIds: string[] = [];
  while (ready.length > 0) {
    const node = ready.shift()!;
    topologicalNodeIds.push(node.nodeId);
    for (const childId of children.get(node.nodeId) ?? []) {
      const remaining = indegree.get(childId)! - 1;
      indegree.set(childId, remaining);
      if (remaining === 0) {
        ready.push(byId.get(childId)!);
        ready.sort(nodeOrder);
      }
    }
  }
  if (topologicalNodeIds.length !== nodes.length) throw new Error('linked PSBT group contains a cycle');

  const parentIds = new Set(edges.map((edge) => edge.parentNodeId));
  for (const parentId of parentIds) {
    const parent = byId.get(parentId)!;
    if (parent.commitments.some((commitment) => !fixedTransactionCommitment(commitment))) {
      throw new Error('linked PSBT parent signature does not fix its transaction id');
    }
    if (parent.inputs.some((input) => !nativeWitnessScript(input.scriptPubKey))) {
      throw new Error('linked PSBT parent has a scriptSig-mutable input');
    }
  }

  edges.sort((a, b) =>
    (byId.get(a.parentNodeId)?.requestIndex ?? 0) - (byId.get(b.parentNodeId)?.requestIndex ?? 0) ||
    a.parentOutputIndex - b.parentOutputIndex ||
    (byId.get(a.childNodeId)?.requestIndex ?? 0) - (byId.get(b.childNodeId)?.requestIndex ?? 0) ||
    a.childInputIndex - b.childInputIndex);
  alternatives.sort((a, b) =>
    (a.parentNodeId === null ? -1 : (byId.get(a.parentNodeId)?.requestIndex ?? 0)) -
      (b.parentNodeId === null ? -1 : (byId.get(b.parentNodeId)?.requestIndex ?? 0)) ||
    a.parentOutputIndex - b.parentOutputIndex);

  return deepFreeze({
    version: 1,
    signatureRelease: 'all_or_nothing',
    nodes,
    edges,
    alternatives,
    topologicalNodeIds,
    independent: edges.length === 0 && alternatives.length === 0,
  });
}

/** Parse PSBTs, derive links from their real unsigned transaction IDs, and validate the bounded group. */
export function deriveLinkedProviderPsbtGroup(
  items: readonly LinkedProviderPsbtGroupItem[],
): LinkedProviderPsbtGroupTopologyV1 {
  if (items.length === 0 || items.length > PROVIDER_MAX_PSBT_BATCH_ITEMS) {
    throw new Error(`linked PSBT group must contain 1-${PROVIDER_MAX_PSBT_BATCH_ITEMS} items`);
  }
  const encodedChars = items.reduce((total, item) => total + item.psbtBase64.length, 0);
  if (encodedChars > PROVIDER_MAX_PSBT_BATCH_BASE64_CHARS) {
    throw new Error('linked PSBT group exceeds encoded resource limits');
  }
  const nodes = items.map((item, requestIndex): LinkedProviderPsbtNode => {
    const bytes = base64ToBytes(item.psbtBase64);
    if (bytesToBase64(bytes) !== item.psbtBase64) throw new Error('linked PSBT base64 is not canonical');
    const tx = Transaction.fromPSBT(bytes, {
      lowR: true,
      allowUnknownInputs: true,
      allowUnknownOutputs: true,
    });
    const rawVersion = tx.opts.PSBTVersion;
    if (rawVersion !== 0 && rawVersion !== 2) throw new Error('linked PSBT version is unsupported');
    if (tx.inputsLength === 0 || tx.outputsLength === 0) throw new Error('linked PSBT is empty');
    assertProviderPsbtItemCounts(tx);
    const selectedInputIndexes = [...item.selectedInputIndexes].sort((a, b) => a - b);
    if (selectedInputIndexes.length === 0 ||
        new Set(selectedInputIndexes).size !== selectedInputIndexes.length ||
        selectedInputIndexes.some((index) => !Number.isSafeInteger(index) || index < 0 ||
          index >= tx.inputsLength)) {
      throw new Error('linked PSBT signing selection is invalid');
    }
    const inputs = Array.from({ length: tx.inputsLength }, (_value, inputIndex) => {
      const input = tx.getInput(inputIndex);
      if (!input.txid || input.index === undefined) throw new Error('linked PSBT input outpoint is missing');
      return {
        txid: bytesToHex(input.txid),
        vout: input.index,
        ...previousOutput(tx, inputIndex),
      };
    });
    const outputs = Array.from({ length: tx.outputsLength }, (_value, outputIndex) => {
      const output = tx.getOutput(outputIndex);
      if (!output.script || output.amount === undefined) throw new Error('linked PSBT output is missing');
      return { valueSats: output.amount, scriptPubKey: bytesToHex(output.script) };
    });
    const commitments = selectedInputIndexes.map((inputIndex) => analyzePsbtInputCommitment({
      rawSighash: selectedSighash(tx, inputIndex, inputs[inputIndex]!.scriptPubKey),
      inputIndex,
      inputCount: tx.inputsLength,
      outputCount: tx.outputsLength,
    }));
    return {
      nodeId: item.nodeId,
      requestIndex,
      unsignedTxid: doubleSha256Txid(tx.unsignedTx),
      psbtVersion: rawVersion,
      inputs,
      outputs,
      selectedInputIndexes,
      commitments,
    };
  });
  return validateLinkedProviderPsbtTopology(nodes);
}
