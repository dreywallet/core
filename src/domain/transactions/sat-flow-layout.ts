/**
 * Sat-flow diagram geometry (§16.2 review, §10.4 presentation).
 *
 * Pure module: no React, no DOM, no browser API, so it stays unit testable and
 * cannot reach anything sensitive. Follows the `QrCode` precedent — path data is
 * computed locally from validated integers and emitted as inert `<path>`
 * elements. No markup is parsed and no image source is loaded, which matters
 * because the approval page CSP is `default-src 'none'` with no `img-src`.
 *
 * Two honesty rules are encoded here and must not be relaxed:
 *
 * 1. A curve is drawn between a specific input and a specific output ONLY for an
 *    inscription, where `analysis.ts` has already proven the FIFO assignment.
 *    Cardinal value merges at the confluence node, because the analysis exposes
 *    an exact partition for protected sats only. Drawing per-input/per-output
 *    curves for unpartitioned value would assert something unproven.
 *
 * 2. Above a small node count the diagram stops being readable and starts being
 *    misleading: many curves crossing a shared point cannot be traced, so a
 *    reversed mapping is misread as a straight-through one. `satFlowEligible`
 *    refuses those shapes outright. The caller then renders the ordinary
 *    output list, which stays authoritative in every case.
 */
import type { TransactionAnalysis } from './analysis';

/**
 * Above these counts curves through a shared confluence stop being traceable.
 * Raising them re-introduces a diagram that looks credible while conveying the
 * wrong mapping; see `design/sat-flow-concept/README.md`.
 */
export const SAT_FLOW_MAX_INPUTS = 4;
export const SAT_FLOW_MAX_OUTPUTS = 4;

export const SAT_FLOW_VIEW = {
  width: 378,
  height: 196,
  nodeHeight: 44,
  nodeGap: 8,
  rowTop: 0,
  rowBottom: 152,
  confluenceY: 98,
} as const;

const CURVE_LIFT = 26;

export type SatFlowOwnership = 'wallet' | 'external' | 'unproven';
export type SatFlowMovement = 'received' | 'sent' | 'retained';

/*
 * Note the absence of an address field on both node types. A truncated address
 * is grindable on prefix and suffix, so putting one in a small diagram node adds
 * a phishing surface for no benefit; full addresses belong to the authoritative
 * output list. Omitting the field makes that a structural guarantee rather than
 * a convention a later change could quietly break.
 */
export interface SatFlowInput {
  index: number;
  valueSats: bigint;
  ownership: SatFlowOwnership;
}

export interface SatFlowOutput {
  index: number;
  valueSats: bigint;
  ownership: SatFlowOwnership;
  role: string;
  /**
   * False when no input's sighash commits to this output, i.e. it can still be
   * changed after signing. Derived from `SighashAnalysis.committedOutputIndexes`.
   */
  committed: boolean;
}

export interface SatFlowInscription {
  inscriptionId: string;
  number: number | null;
  inputIndex: number;
  outputIndex: number;
  movement: SatFlowMovement;
}

export interface SatFlowModel {
  inputs: readonly SatFlowInput[];
  outputs: readonly SatFlowOutput[];
  inscriptions: readonly SatFlowInscription[];
  feeSats: bigint;
  protectedValueExposedToFees: bigint;
}

function validModelIndex(value: unknown, limit: number): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 && value < limit;
}

/**
 * Project analyzer-owned transaction facts into the presentation-only model.
 *
 * This is the sole analysis -> SatFlowModel authority. Consumers must not
 * reconstruct commitment, ownership, protected movement, or fee exposure from
 * a plan or approval payload. `null` is deliberately safe: callers retain the
 * exact transaction review and complete textual lists without a diagram.
 */
export function projectSatFlowModel(analysis: TransactionAnalysis): SatFlowModel | null {
  if (analysis.hardViolations.length > 0 || analysis.inputs.length < 1 || analysis.outputs.length < 1 ||
      analysis.fee.sats < 0n || analysis.assetEffects.protectedValueExposedToFees < 0n) return null;

  for (let index = 0; index < analysis.inputs.length; index += 1) {
    const input = analysis.inputs[index];
    if (!input || input.index !== index || input.valueSats < 0n ||
        !['wallet', 'external', 'unproven'].includes(input.ownership) ||
        !input.sighash.validEncoding) return null;
    const committed = input.sighash.committedOutputIndexes;
    if (committed !== 'all' && (
      new Set(committed).size !== committed.length ||
      committed.some((outputIndex) => !validModelIndex(outputIndex, analysis.outputs.length))
    )) return null;
  }

  for (let index = 0; index < analysis.outputs.length; index += 1) {
    const output = analysis.outputs[index];
    if (!output || output.index !== index || output.valueSats < 0n ||
        !['wallet', 'external', 'unproven'].includes(output.ownership) ||
        typeof output.role !== 'string' || output.role.length === 0) return null;
  }

  const inscriptionIds = new Set<string>();
  const inscriptions: SatFlowInscription[] = [];
  for (const effect of analysis.assetEffects.inscriptions) {
    if (inscriptionIds.has(effect.inscriptionId) ||
        !validModelIndex(effect.inputIndex, analysis.inputs.length) ||
        !validModelIndex(effect.outputIndex, analysis.outputs.length) ||
        !['received', 'sent', 'retained'].includes(effect.movement)) return null;
    const classified = analysis.inputs
      .flatMap((input) => input.classification.inscriptions)
      .filter((item) => item.inscriptionId === effect.inscriptionId);
    if (classified.length !== 1) return null;
    const number = classified[0]!.number ?? null;
    if (number !== null && !Number.isSafeInteger(number)) return null;
    const matchingFlows = analysis.assetEffects.protectedSatFlow.filter((flow) =>
      flow.inscriptionId === effect.inscriptionId &&
      flow.inputIndex === effect.inputIndex && flow.inputOffset === effect.inputOffset &&
      flow.outputIndex === effect.outputIndex && flow.outputOffset === effect.outputOffset);
    if (matchingFlows.length !== 1) return null;
    inscriptionIds.add(effect.inscriptionId);
    inscriptions.push(Object.freeze({
      inscriptionId: effect.inscriptionId,
      number,
      inputIndex: effect.inputIndex,
      outputIndex: effect.outputIndex,
      movement: effect.movement,
    }));
  }

  const inputs = analysis.inputs.map((input) => Object.freeze({
    index: input.index,
    valueSats: input.valueSats,
    ownership: input.ownership,
  }));
  const outputs = analysis.outputs.map((output) => Object.freeze({
    index: output.index,
    valueSats: output.valueSats,
    ownership: output.ownership,
    role: output.role,
    committed: analysis.inputs.some((input) =>
      input.sighash.committedOutputIndexes === 'all' ||
      input.sighash.committedOutputIndexes.includes(output.index)),
  }));
  return Object.freeze({
    inputs: Object.freeze(inputs),
    outputs: Object.freeze(outputs),
    inscriptions: Object.freeze(inscriptions),
    feeSats: analysis.fee.sats,
    protectedValueExposedToFees: analysis.assetEffects.protectedValueExposedToFees,
  });
}

export interface SatFlowNode {
  key: string;
  index: number;
  kind: 'input' | 'output' | 'fee';
  ownership: SatFlowOwnership | 'fee';
  valueSats: bigint;
  role: string;
  committed: boolean;
  /** Derived from `inscriptions`, never supplied, so the two cannot disagree. */
  carriesInscription: boolean;
  inscriptions: SatFlowInscription[];
  x: number;
  y: number;
  width: number;
  height: number;
  anchorX: number;
  anchorY: number;
  danger: boolean;
}

export interface SatFlowEdge {
  key: string;
  kind: 'inscription' | 'value' | 'fee';
  /** True only for an edge backed by the FIFO partition proof. */
  proven: boolean;
  danger: boolean;
  uncommitted: boolean;
  inscriptions: SatFlowInscription[];
  d: string;
}

export interface SatFlowLayout {
  nodes: SatFlowNode[];
  edges: SatFlowEdge[];
  confluence: { x: number; y: number };
  view: typeof SAT_FLOW_VIEW;
}

function isIndex(value: unknown, limit: number): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 && value < limit;
}

/**
 * Fail-closed gate. Every rejection leaves the caller with the ordinary output
 * list, which is always sufficient on its own — the diagram is additive.
 */
export function satFlowEligible(model: SatFlowModel): boolean {
  const { inputs, outputs, inscriptions } = model;
  if (inputs.length < 1 || inputs.length > SAT_FLOW_MAX_INPUTS) return false;
  if (outputs.length < 1 || outputs.length > SAT_FLOW_MAX_OUTPUTS) return false;
  if (model.feeSats < 0n || model.protectedValueExposedToFees < 0n) return false;

  // Indexes must be dense and in order so a node's position matches its index.
  for (let i = 0; i < inputs.length; i += 1) {
    if (inputs[i]?.index !== i || (inputs[i]?.valueSats ?? -1n) < 0n) return false;
  }
  for (let i = 0; i < outputs.length; i += 1) {
    if (outputs[i]?.index !== i || (outputs[i]?.valueSats ?? -1n) < 0n) return false;
  }

  // Every inscription must land on a real input and a real output. An
  // out-of-range index means the projection and the analysis disagree; refuse
  // rather than guess.
  for (const item of inscriptions) {
    if (!isIndex(item.inputIndex, inputs.length)) return false;
    if (!isIndex(item.outputIndex, outputs.length)) return false;
  }
  return true;
}

function rowNodes(count: number): Array<{ x: number; width: number }> {
  const width = (SAT_FLOW_VIEW.width - (count - 1) * SAT_FLOW_VIEW.nodeGap) / count;
  return Array.from({ length: count }, (_, i) => ({
    x: i * (width + SAT_FLOW_VIEW.nodeGap),
    width,
  }));
}

function fixed(value: number): string {
  return value.toFixed(2);
}

/** Two cubics so the curve visibly passes through the confluence, not near it. */
function throughConfluence(
  from: { x: number; y: number },
  to: { x: number; y: number },
  cx: number,
  cy: number,
): string {
  return `M${fixed(from.x)} ${fixed(from.y)} ` +
    `C${fixed(from.x)} ${fixed(from.y + CURVE_LIFT)} ${fixed(cx)} ${fixed(cy - CURVE_LIFT)} ${fixed(cx)} ${fixed(cy)} ` +
    `C${fixed(cx)} ${fixed(cy + CURVE_LIFT)} ${fixed(to.x)} ${fixed(to.y - CURVE_LIFT)} ${fixed(to.x)} ${fixed(to.y)}`;
}

function halfCurve(
  from: { x: number; y: number },
  to: { x: number; y: number },
): string {
  return `M${fixed(from.x)} ${fixed(from.y)} ` +
    `C${fixed(from.x)} ${fixed(from.y + CURVE_LIFT)} ${fixed(to.x)} ${fixed(to.y - CURVE_LIFT)} ${fixed(to.x)} ${fixed(to.y)}`;
}

/**
 * Throws when the model is not eligible; call `satFlowEligible` first. Callers
 * in the UI must treat a throw as "render no diagram", never as an approval
 * failure — the diagram never gates signing.
 */
export function layoutSatFlow(model: SatFlowModel): SatFlowLayout {
  if (!satFlowEligible(model)) throw new Error('sat flow model is not eligible for diagram rendering');

  const feeExposed = model.protectedValueExposedToFees > 0n;
  const cx = SAT_FLOW_VIEW.width / 2;
  const cy = SAT_FLOW_VIEW.confluenceY;

  const inputSlots = rowNodes(model.inputs.length);
  const outputSlots = rowNodes(model.outputs.length + 1);

  const inputNodes: SatFlowNode[] = model.inputs.map((input, i) => {
    const slot = inputSlots[i]!;
    const carried = model.inscriptions.filter((item) => item.inputIndex === input.index);
    return {
      key: `in-${input.index}`,
      index: input.index,
      kind: 'input',
      ownership: input.ownership,
      valueSats: input.valueSats,
      role: 'input',
      committed: true,
      carriesInscription: carried.length > 0,
      inscriptions: carried,
      x: slot.x,
      y: SAT_FLOW_VIEW.rowTop,
      width: slot.width,
      height: SAT_FLOW_VIEW.nodeHeight,
      anchorX: slot.x + slot.width / 2,
      anchorY: SAT_FLOW_VIEW.rowTop + SAT_FLOW_VIEW.nodeHeight,
      danger: false,
    };
  });

  const outputNodes: SatFlowNode[] = model.outputs.map((output, i) => {
    const slot = outputSlots[i]!;
    const carried = model.inscriptions.filter((item) => item.outputIndex === output.index);
    return {
      key: `out-${output.index}`,
      index: output.index,
      kind: 'output',
      ownership: output.ownership,
      valueSats: output.valueSats,
      role: output.role,
      committed: output.committed,
      carriesInscription: carried.length > 0,
      inscriptions: carried,
      x: slot.x,
      y: SAT_FLOW_VIEW.rowBottom,
      width: slot.width,
      height: SAT_FLOW_VIEW.nodeHeight,
      anchorX: slot.x + slot.width / 2,
      anchorY: SAT_FLOW_VIEW.rowBottom,
      danger: false,
    };
  });

  const feeSlot = outputSlots[model.outputs.length]!;
  const feeNode: SatFlowNode = {
    key: 'fee',
    index: -1,
    kind: 'fee',
    ownership: 'fee',
    valueSats: model.feeSats,
    role: 'fee',
    committed: true,
    carriesInscription: false,
    inscriptions: [],
    x: feeSlot.x,
    y: SAT_FLOW_VIEW.rowBottom,
    width: feeSlot.width,
    height: SAT_FLOW_VIEW.nodeHeight,
    anchorX: feeSlot.x + feeSlot.width / 2,
    anchorY: SAT_FLOW_VIEW.rowBottom,
    danger: feeExposed,
  };

  const edges: SatFlowEdge[] = [];

  // 1. Proven inscription edges. Co-located inscriptions share a sat range and
  //    therefore share one curve.
  const byPair = new Map<string, SatFlowInscription[]>();
  for (const item of model.inscriptions) {
    const pair = `${item.inputIndex}->${item.outputIndex}`;
    const existing = byPair.get(pair);
    if (existing) existing.push(item);
    else byPair.set(pair, [item]);
  }
  for (const [pair, items] of byPair) {
    const from = inputNodes[items[0]!.inputIndex]!;
    const to = outputNodes[items[0]!.outputIndex]!;
    edges.push({
      key: `ins-${pair}`,
      kind: 'inscription',
      proven: true,
      danger: false,
      uncommitted: !to.committed,
      inscriptions: items,
      d: throughConfluence(
        { x: from.anchorX, y: from.anchorY },
        { x: to.anchorX, y: to.anchorY },
        cx,
        cy,
      ),
    });
  }

  // 2. Cardinal value merges into the confluence and fans back out. Never a
  //    specific input->output pair, because that partition is not proven.
  for (const node of inputNodes) {
    if (node.carriesInscription) continue;
    edges.push({
      key: `val-in-${node.index}`,
      kind: 'value',
      proven: false,
      danger: false,
      uncommitted: false,
      inscriptions: [],
      d: halfCurve({ x: node.anchorX, y: node.anchorY }, { x: cx, y: cy }),
    });
  }

  for (const node of [...outputNodes, feeNode]) {
    if (node.kind === 'output' && node.carriesInscription) continue;
    edges.push({
      key: `val-out-${node.key}`,
      kind: node.kind === 'fee' ? 'fee' : 'value',
      proven: false,
      danger: node.kind === 'fee' && feeExposed,
      uncommitted: !node.committed,
      inscriptions: [],
      d: halfCurve({ x: cx, y: cy }, { x: node.anchorX, y: node.anchorY }),
    });
  }

  return {
    nodes: [...inputNodes, ...outputNodes, feeNode],
    edges,
    confluence: { x: cx, y: cy },
    view: SAT_FLOW_VIEW,
  };
}

export interface SatFlowSummary {
  sent: number;
  retained: number;
  received: number;
  inputCount: number;
  outputCount: number;
  uncommittedOutputCount: number;
  feeSats: bigint;
  protectedValueExposedToFees: bigint;
}

/**
 * Counts for the plain-language summary. The summary is rendered whether or not
 * the diagram is, so movement and fee information is never available only from
 * the picture (§10.4).
 */
export function satFlowSummary(model: SatFlowModel): SatFlowSummary {
  let sent = 0;
  let retained = 0;
  let received = 0;
  for (const item of model.inscriptions) {
    if (item.movement === 'sent') sent += 1;
    else if (item.movement === 'retained') retained += 1;
    else received += 1;
  }
  return {
    sent,
    retained,
    received,
    inputCount: model.inputs.length,
    outputCount: model.outputs.length,
    uncommittedOutputCount: model.outputs.filter((output) => !output.committed).length,
    feeSats: model.feeSats,
    protectedValueExposedToFees: model.protectedValueExposedToFees,
  };
}
