import { p2tr, p2wpkh, Transaction } from '@scure/btc-signer';
import type { UtxoClassification } from '../gateway/contract';
import { bitcoinNetwork, type Network } from '../keys/derivation';
import { scriptPubKeyHex } from '../keys/script-hash';
import { templateForResolution } from '../marketplaces/resolver';
import type { MarketplaceContext, MarketplaceResolution } from '../marketplaces/types';
import { verifyOrdnetSaleKeyPath, verifyOrdnetSaleScriptPath } from '../marketplaces/ordnet-script-path';
import { parseCanonicalSatpoint } from '../ordinals/satpoint';
import type { PlanDerivation } from './plan';
import { base64ToBytes, bytesToHex, hexToBytes } from '../vault/encoding';
import { getCryptoProvider } from '../vault/crypto-provider';
import {
  deriveLinkedProviderPsbtGroup,
  type LinkedProviderPsbtGroupItem,
  type LinkedProviderPsbtGroupTopologyV1,
  type LinkedProviderPsbtNode,
} from './provider-psbt-group';

export type ProviderPsbtInputClassificationProvenanceV1 =
  | { kind: 'gateway'; outpoint: string }
  | {
      kind: 'linked_output';
      parentNodeId: string;
      parentOutputIndex: number;
      projectionHash: string;
      walletControl?: 'standard' | 'ordnet_sale_script_path' | 'ordnet_sale_key_path';
    };

export interface InspectedProviderPsbtGroupV1 {
  version: 1;
  topology: LinkedProviderPsbtGroupTopologyV1;
  /** The only outpoints the host may send to the gateway for this group. */
  externalOutpoints: Array<{ txid: string; vout: number }>;
}

export interface PreparedProviderPsbtGroupItemInputsV1 {
  nodeId: string;
  classifications: UtxoClassification[];
  provenance: ProviderPsbtInputClassificationProvenanceV1[];
  /** Internally-created selected inputs whose control was independently proven by Core. */
  walletInputs: Array<{ outpoint: string; derivation: PlanDerivation }>;
}

export interface ProviderPsbtGroupPreparationItem extends LinkedProviderPsbtGroupItem {
  inputsToSign?: Array<{ address: string; signingIndexes: readonly number[] }>;
  marketplace?: { context: MarketplaceContext; resolution: MarketplaceResolution };
}

export interface PreparedProviderPsbtGroupInputsV1 extends InspectedProviderPsbtGroupV1 {
  groupId: string;
  items: PreparedProviderPsbtGroupItemInputsV1[];
  preparationHash: string;
}

export function providerPsbtLinkedGroupBinding(
  preparation: PreparedProviderPsbtGroupInputsV1,
  nodeId: string,
): {
  linkedGroup: {
    groupId: string;
    nodeId: string;
    preparationHash: string;
    inputProvenance: ProviderPsbtInputClassificationProvenanceV1[];
  };
  classifications: UtxoClassification[];
  walletInputs: Array<{ outpoint: string; derivation: PlanDerivation }>;
} {
  const item = preparation.items.find((candidate) => candidate.nodeId === nodeId);
  if (!item) throw new Error('linked PSBT preparation does not contain the requested node');
  return {
    linkedGroup: {
      groupId: preparation.groupId,
      nodeId,
      preparationHash: preparation.preparationHash,
      inputProvenance: item.provenance.map((entry) => ({ ...entry })),
    },
    classifications: item.classifications.map((classification) => ({
      ...classification,
      inscriptions: classification.inscriptions.map((inscription) => ({ ...inscription })),
      satRanges: classification.satRanges?.map((range) => ({ ...range })) ?? null,
      classifiedTip: { ...classification.classifiedTip },
    })),
    walletInputs: item.walletInputs.map((walletInput) => ({
      outpoint: walletInput.outpoint,
      derivation: { ...walletInput.derivation },
    })),
  };
}

interface ClassificationSource {
  classificationRevision: string;
  coreTip: { height: number; hash: string };
}

function canonical(value: unknown): unknown {
  if (typeof value === 'bigint') return value.toString();
  if (Array.isArray(value)) return value.map(canonical);
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value as Record<string, unknown>)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, child]) => [key, canonical(child)]));
  }
  return value;
}

function hash(value: unknown): string {
  return bytesToHex(getCryptoProvider().sha256(
    new TextEncoder().encode(JSON.stringify(canonical(value))),
  ));
}

function outpoint(txid: string, vout: number): string {
  return `${txid}:${vout}`;
}

function derivationAddress(derivation: PlanDerivation, network: Network): string {
  const publicKey = hexToBytes(derivation.publicKeyHex);
  const address = derivation.lane === 'payment'
    ? p2wpkh(publicKey, bitcoinNetwork(network)).address
    : p2tr(publicKey.slice(1), undefined, bitcoinNetwork(network)).address;
  if (!address) throw new Error('linked PSBT control address cannot be encoded');
  return address;
}

function proveInternalWalletControl(input: {
  item: ProviderPsbtGroupPreparationItem;
  transaction: Transaction;
  inputIndex: number;
  transactionInput: LinkedProviderPsbtNode['inputs'][number];
  candidates: readonly { address: string; derivation: PlanDerivation }[];
  network: Network;
  origin: string;
  accountId: string;
  account: number;
}): { derivation: PlanDerivation; control: NonNullable<Extract<
  ProviderPsbtInputClassificationProvenanceV1,
  { kind: 'linked_output' }
>['walletControl']> } {
  const declarations = input.item.inputsToSign?.filter((selection) =>
    selection.signingIndexes.includes(input.inputIndex)) ?? [];
  if (declarations.length !== 1) {
    throw new Error('linked PSBT selected internal input needs one exact address declaration');
  }
  const candidate = input.candidates.find((entry) => entry.address === declarations[0]!.address);
  if (!candidate || candidate.derivation.accountId !== input.accountId ||
      candidate.derivation.account !== input.account ||
      derivationAddress(candidate.derivation, input.network) !== candidate.address) {
    throw new Error('linked PSBT internal input address is not controlled by the active account');
  }
  if (scriptPubKeyHex(candidate.derivation.publicKeyHex, candidate.derivation.lane, input.network) ===
      input.transactionInput.scriptPubKey) {
    return { derivation: candidate.derivation, control: 'standard' };
  }
  const marketplace = input.item.marketplace;
  const template = marketplace ? templateForResolution(marketplace.resolution) : null;
  const rule = template?.steps.find((entry) => entry.step === marketplace!.context.step) ??
    (template?.stepCount === 'context' ? template.steps[0] : undefined);
  const contextMatches = marketplace && template && rule && template.marketplaceId === 'ordnet' &&
    template.origins.includes(input.origin) && template.networks.includes(input.network) &&
    template.templateVersion === marketplace.context.templateVersion &&
    template.action === marketplace.context.action && template.role === marketplace.context.role &&
    template.assetKind === marketplace.context.assetKind;
  const contextlessOrdnet = !marketplace &&
    (input.origin === 'https://ord.net' || input.origin === 'https://www.ord.net');
  if ((!contextMatches && !contextlessOrdnet) || candidate.derivation.lane !== 'ordinals') {
    throw new Error('linked PSBT nonstandard internal control is not covered by a recognized template');
  }
  const parsed = input.transaction.getInput(input.inputIndex);
  if (parsed.tapLeafScript?.length && (contextlessOrdnet || rule?.allowTaprootScriptPath)) {
    verifyOrdnetSaleScriptPath(input.transaction, input.inputIndex, candidate.derivation.publicKeyHex.slice(2));
    return { derivation: candidate.derivation, control: 'ordnet_sale_script_path' };
  }
  if (!parsed.tapLeafScript?.length && (contextlessOrdnet || rule?.allowTaprootTreeKeyPath)) {
    verifyOrdnetSaleKeyPath(input.transaction, input.inputIndex, candidate.derivation.publicKeyHex.slice(2));
    return { derivation: candidate.derivation, control: 'ordnet_sale_key_path' };
  }
  throw new Error('linked PSBT internal input control path differs from the pinned template');
}

function externalInputs(topology: LinkedProviderPsbtGroupTopologyV1): Array<{ txid: string; vout: number }> {
  const internalTxids = new Set(topology.nodes.map((node) => node.unsignedTxid));
  const candidates = topology.nodes
    .flatMap((node) => node.inputs)
    .filter((input) => !internalTxids.has(input.txid))
    .map(({ txid, vout }) => ({ txid, vout }))
    .sort((left, right) => left.txid.localeCompare(right.txid) || left.vout - right.vout);
  return [...new Map(candidates.map((candidate) =>
    [outpoint(candidate.txid, candidate.vout), candidate])).values()];
}

export function inspectProviderPsbtGroupRequest(
  items: readonly LinkedProviderPsbtGroupItem[],
): InspectedProviderPsbtGroupV1 {
  const topology = deriveLinkedProviderPsbtGroup(items);
  return Object.freeze({ version: 1, topology, externalOutpoints: externalInputs(topology) });
}

function assertGatewayClassification(
  classification: UtxoClassification,
  expected: LinkedProviderPsbtNode['inputs'][number],
  source: ClassificationSource,
): void {
  if (classification.confidence !== 'authoritative' ||
      classification.classificationRevision !== source.classificationRevision ||
      classification.classifiedTip.height !== source.coreTip.height ||
      classification.classifiedTip.hash !== source.coreTip.hash) {
    throw new Error('linked PSBT root classification is not current and authoritative');
  }
  if (classification.valueSats !== expected.valueSats.toString() ||
      classification.scriptPubKey !== expected.scriptPubKey) {
    throw new Error('linked PSBT root classification differs from its PSBT prevout');
  }
}

function projectionHash(input: {
  parentNodeId: string;
  parentUnsignedTxid: string;
  parentOutputIndex: number;
  classification: UtxoClassification;
}): string {
  return hash(input);
}

function projectNodeOutputs(input: {
  node: LinkedProviderPsbtNode;
  classifications: readonly UtxoClassification[];
  source: ClassificationSource;
}): UtxoClassification[] {
  const { node, classifications, source } = input;
  if (classifications.length !== node.inputs.length) {
    throw new Error('linked PSBT projected input partition is incomplete');
  }
  if (classifications.some((classification) => classification.unsupportedAssetDetected ||
      classification.satRanges?.some((range) =>
        range.rarity !== undefined && range.rarity !== 'common') === true ||
      (classification.primaryClass !== 'cardinal_clean' && classification.primaryClass !== 'inscribed'))) {
    throw new Error('linked PSBT output projection supports only cardinal and inscription inputs');
  }

  const outputStarts: bigint[] = [];
  let totalOutputSats = 0n;
  for (const output of node.outputs) {
    outputStarts.push(totalOutputSats);
    totalOutputSats += output.valueSats;
  }

  const projectedInscriptions = node.outputs.map(() => [] as UtxoClassification['inscriptions']);
  const inscriptionIds = new Set<string>();
  const outputForOffset = (absoluteOffset: bigint): number => {
    let low = 0;
    let high = node.outputs.length - 1;
    while (low <= high) {
      const middle = Math.floor((low + high) / 2);
      const start = outputStarts[middle]!;
      const end = start + node.outputs[middle]!.valueSats;
      if (absoluteOffset < start) high = middle - 1;
      else if (absoluteOffset >= end) low = middle + 1;
      else return middle;
    }
    return -1;
  };
  let inputStart = 0n;
  for (let inputIndex = 0; inputIndex < classifications.length; inputIndex += 1) {
    const classification = classifications[inputIndex]!;
    const transactionInput = node.inputs[inputIndex]!;
    for (const inscription of classification.inscriptions) {
      if (inscriptionIds.has(inscription.inscriptionId)) {
        throw new Error('linked PSBT projection repeats an inscription');
      }
      inscriptionIds.add(inscription.inscriptionId);
      const parsed = parseCanonicalSatpoint(inscription.satpoint);
      if (!parsed || parsed.txid !== transactionInput.txid || parsed.vout !== transactionInput.vout ||
          parsed.offset >= transactionInput.valueSats) {
        throw new Error('linked PSBT projection has an invalid inscription satpoint');
      }
      const absoluteOffset = inputStart + parsed.offset;
      const outputIndex = outputForOffset(absoluteOffset);
      if (outputIndex < 0 || absoluteOffset >= totalOutputSats) {
        throw new Error('linked PSBT projection would expose an inscription to fees');
      }
      const outputOffset = absoluteOffset - outputStarts[outputIndex]!;
      projectedInscriptions[outputIndex]!.push({
        ...inscription,
        satpoint: `${node.unsignedTxid}:${outputIndex}:${outputOffset}`,
      });
    }
    inputStart += transactionInput.valueSats;
  }

  return node.outputs.map((output, outputIndex): UtxoClassification => {
    const inscriptions = projectedInscriptions[outputIndex]!
      .sort((left, right) => left.satpoint.localeCompare(right.satpoint) ||
        left.inscriptionId.localeCompare(right.inscriptionId));
    return {
      txid: node.unsignedTxid,
      vout: outputIndex,
      valueSats: output.valueSats.toString(),
      scriptPubKey: output.scriptPubKey,
      confirmations: 0,
      primaryClass: inscriptions.length === 0 ? 'cardinal_clean' : 'inscribed',
      inscriptions,
      satRanges: null,
      unsupportedAssetDetected: false,
      confidence: 'authoritative',
      classifiedTip: { ...source.coreTip },
      classificationRevision: source.classificationRevision,
    };
  });
}

/**
 * Build child-input facts from authenticated roots and the graph itself. The
 * host supplies no classification for an outpoint created inside the group.
 */
export function prepareProviderPsbtGroupInputs(input: {
  groupId: string;
  items: readonly ProviderPsbtGroupPreparationItem[];
  externalClassifications: readonly UtxoClassification[];
  source: ClassificationSource;
  walletControl?: {
    network: Network;
    origin: string;
    accountId: string;
    account: number;
    candidates: readonly { address: string; derivation: PlanDerivation }[];
  };
}): PreparedProviderPsbtGroupInputsV1 {
  if (!input.groupId || input.groupId.length > 128) throw new Error('linked PSBT group identity is invalid');
  const inspected = inspectProviderPsbtGroupRequest(input.items);
  const expectedRoots = inspected.externalOutpoints.map(({ txid, vout }) => outpoint(txid, vout));
  const roots = new Map(input.externalClassifications.map((classification) =>
    [outpoint(classification.txid, classification.vout), classification]));
  if (roots.size !== input.externalClassifications.length || roots.size !== expectedRoots.length ||
      expectedRoots.some((key) => !roots.has(key))) {
    throw new Error('linked PSBT gateway classification partition must contain exactly the external roots');
  }

  const byNodeId = new Map(inspected.topology.nodes.map((node) => [node.nodeId, node]));
  const outputs = new Map<string, { parentNodeId: string; classification: UtxoClassification }>();
  const prepared = new Map<string, PreparedProviderPsbtGroupItemInputsV1>();
  const requestItems = new Map(inspected.topology.nodes.map((node) => [node.nodeId, input.items[node.requestIndex]!]));
  for (const nodeId of inspected.topology.topologicalNodeIds) {
    const node = byNodeId.get(nodeId);
    if (!node) throw new Error('linked PSBT topology references an unknown node');
    const classifications: UtxoClassification[] = [];
    const provenance: ProviderPsbtInputClassificationProvenanceV1[] = [];
    const walletInputs: PreparedProviderPsbtGroupItemInputsV1['walletInputs'] = [];
    const requestItem = requestItems.get(nodeId);
    if (!requestItem) throw new Error('linked PSBT request item is missing');
    const transaction = Transaction.fromPSBT(base64ToBytes(requestItem.psbtBase64), {
      lowR: true,
      allowUnknownInputs: true,
      allowUnknownOutputs: true,
    });
    for (let inputIndex = 0; inputIndex < node.inputs.length; inputIndex += 1) {
      const transactionInput = node.inputs[inputIndex]!;
      const key = outpoint(transactionInput.txid, transactionInput.vout);
      const internal = outputs.get(key);
      if (internal) {
        const parentOutputIndex = transactionInput.vout;
        classifications.push(internal.classification);
        const linkedProvenance: Extract<ProviderPsbtInputClassificationProvenanceV1, {
          kind: 'linked_output';
        }> = {
          kind: 'linked_output',
          parentNodeId: internal.parentNodeId,
          parentOutputIndex,
          projectionHash: projectionHash({
            parentNodeId: internal.parentNodeId,
            parentUnsignedTxid: transactionInput.txid,
            parentOutputIndex,
            classification: internal.classification,
          }),
        };
        provenance.push(linkedProvenance);
        if (node.selectedInputIndexes.includes(inputIndex)) {
          if (!input.walletControl) {
            throw new Error('linked PSBT selected internal input is missing wallet control evidence');
          }
          const control = proveInternalWalletControl({
            item: requestItem,
            transaction,
            inputIndex,
            transactionInput,
            candidates: input.walletControl.candidates,
            network: input.walletControl.network,
            origin: input.walletControl.origin,
            accountId: input.walletControl.accountId,
            account: input.walletControl.account,
          });
          linkedProvenance.walletControl = control.control;
          walletInputs.push({
            outpoint: key,
            derivation: control.derivation,
          });
        }
        continue;
      }
      const classification = roots.get(key);
      if (!classification) throw new Error('linked PSBT external root classification is missing');
      assertGatewayClassification(classification, transactionInput, input.source);
      classifications.push(classification);
      provenance.push({ kind: 'gateway', outpoint: key });
    }
    prepared.set(nodeId, { nodeId, classifications, provenance, walletInputs });
    const projected = projectNodeOutputs({ node, classifications, source: input.source });
    projected.forEach((classification, outputIndex) => outputs.set(
      outpoint(node.unsignedTxid, outputIndex),
      { parentNodeId: node.nodeId, classification },
    ));
  }

  const items = inspected.topology.nodes
    .toSorted((left, right) => left.requestIndex - right.requestIndex)
    .map((node) => prepared.get(node.nodeId)!);
  const withoutHash = {
    ...inspected,
    groupId: input.groupId,
    items,
  };
  return Object.freeze({ ...withoutHash, preparationHash: hash(withoutHash) });
}
