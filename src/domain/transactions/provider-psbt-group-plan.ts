import { Transaction } from '@scure/btc-signer';
import { bytesToBase64, bytesToHex, hexToBytes } from '../vault/encoding';
import { getCryptoProvider } from '../vault/crypto-provider';
import {
  assertProviderPsbtPlan,
  resolveProviderPsbtInputSelections,
  signValidatedProviderPsbtGroupAtomically,
  type ProviderAuthorityBinding,
  type ProviderPsbtInputSelection,
  type ProviderPsbtPlanV3,
} from './provider-psbt';
import {
  deriveLinkedProviderPsbtGroup,
  type LinkedProviderPsbtAlternative,
  type LinkedProviderPsbtGroupTopologyV1,
  type LinkedProviderPsbtNode,
} from './provider-psbt-group';
import {
  prepareProviderPsbtGroupInputs,
  type PreparedProviderPsbtGroupInputsV1,
} from './provider-psbt-group-prepare';

export interface ProviderPsbtGroupItemV1 {
  nodeId: string;
  plan: ProviderPsbtPlanV3;
  /** Labeled by the adapter from a reviewed provider response, then checked against the real unsigned txid. */
  expectedUnsignedTxid?: string;
  /** Exact Sats Connect declarations, in request order. */
  inputsToSign?: ProviderPsbtInputSelection[];
  requestedInputIndexes: number[];
}

export interface ProviderPsbtGroupAlternativeProofV1 {
  outpoint: string;
  parentNodeId: string;
  parentOutputIndex: number;
  settlements: Array<{
    nodeId: string;
    inputIndex: number;
    proof: 'recognized_marketplace_plan' | 'pinned_ordnet_sale_control';
    guaranteedWalletReturnSats: bigint;
    maximumWalletDebitSats: bigint;
  }>;
  recoveryNodeId: string;
  recoveryInputIndex: number;
  recoveryProof: 'committed_wallet_return';
  recoveryWalletInputSats: bigint;
  recoveryGuaranteedWalletReturnSats: bigint;
  recoveryMaximumWalletDebitSats: bigint;
  recoveredInscriptionIds: string[];
}

export interface ProviderPsbtGroupPlanV1 {
  version: 1;
  groupId: string;
  createdAt: number;
  expiresAt: number;
  network: ProviderPsbtPlanV3['network'];
  vaultId: string;
  sessionId: string;
  accountId: string;
  account: number;
  provider: ProviderAuthorityBinding & { providerMethod: 'signMultipleTransactions' };
  approvalGeneration: number;
  requiresAdvanced: boolean;
  signatureRelease: 'all_or_nothing';
  items: ProviderPsbtGroupItemV1[];
  topology: LinkedProviderPsbtGroupTopologyV1;
  preparation: PreparedProviderPsbtGroupInputsV1 | null;
  alternativeProofs: ProviderPsbtGroupAlternativeProofV1[];
  aggregate: {
    encodedPsbtChars: number;
    inputs: number;
    outputs: number;
    selectedInputs: number;
  };
  approvalSummary: {
    action: 'sign_transaction_group';
    transactionCount: number;
    linked: boolean;
    alternativeCount: number;
    marketplaceActions: string[];
    walletInputSats: bigint;
    walletOutputSats: bigint;
    feeExposureSats: bigint;
    maximumWalletDebitSats: bigint;
    maximumFeeExposureSats: bigint;
    branchEconomicsExact: boolean;
    externalConflicts: Array<{ outpoints: string[]; nodeIds: string[] }>;
    alternativeOutcomes: Array<{
      /** Canonical representative retained for compact clients. */
      outpoint: string;
      /** All coupled outpoints governed by this same transaction branch set. */
      outpoints: string[];
      settlements: Array<{
        nodeId: string;
        guaranteedWalletReturnSats: bigint;
        maximumWalletDebitSats: bigint;
      }>;
      recovery: {
        nodeId: string;
        guaranteedWalletReturnSats: bigint;
        maximumWalletDebitSats: bigint;
      };
    }>;
  };
  groupHash: string;
}

export interface SignedProviderPsbtGroupV1 {
  version: 1;
  groupHash: string;
  /** Exact original request order, regardless of topological signing order. */
  results: Array<{ nodeId: string; psbtBase64: string }>;
}

function canonical(value: unknown): unknown {
  if (typeof value === 'bigint') return value.toString();
  if (value instanceof Uint8Array) return bytesToHex(value);
  if (Array.isArray(value)) return value.map(canonical);
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value as Record<string, unknown>)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([key, child]) => [key, canonical(child)]));
  }
  return value;
}

function hash(value: unknown): string {
  return bytesToHex(getCryptoProvider().sha256(new TextEncoder().encode(JSON.stringify(canonical(value)))));
}

function sameAuthority(left: ProviderAuthorityBinding, right: ProviderAuthorityBinding): boolean {
  return left.origin === right.origin && left.tabId === right.tabId && left.frameId === right.frameId &&
    left.documentId === right.documentId && left.requestNonce === right.requestNonce &&
    left.providerMethod === right.providerMethod;
}

function sameCanonical(left: unknown, right: unknown): boolean {
  return JSON.stringify(canonical(left)) === JSON.stringify(canonical(right));
}

function groupProjection(plan: Omit<ProviderPsbtGroupPlanV1, 'groupHash'>): unknown {
  return {
    version: plan.version,
    groupId: plan.groupId,
    createdAt: plan.createdAt,
    expiresAt: plan.expiresAt,
    network: plan.network,
    vaultId: plan.vaultId,
    sessionId: plan.sessionId,
    accountId: plan.accountId,
    account: plan.account,
    provider: plan.provider,
    approvalGeneration: plan.approvalGeneration,
    requiresAdvanced: plan.requiresAdvanced,
    signatureRelease: plan.signatureRelease,
    items: plan.items.map((item, requestIndex) => ({
      requestIndex,
      nodeId: item.nodeId,
      planId: item.plan.planId,
      planHash: item.plan.planHash,
      psbtHash: item.plan.psbtHash,
      analysisHash: item.plan.analysisHash,
      transactionCommitmentHash: item.plan.transactionCommitmentHash,
      requestedInputIndexes: item.requestedInputIndexes,
      ...(item.inputsToSign === undefined ? {} : { inputsToSign: item.inputsToSign }),
      ...(item.expectedUnsignedTxid === undefined ? {} : { expectedUnsignedTxid: item.expectedUnsignedTxid }),
    })),
    // The complete derived graph is intentional: the hash binds request order,
    // topological order, every edge, every alternative, and every sighash fact.
    topology: plan.topology,
    preparation: plan.preparation,
    alternativeProofs: plan.alternativeProofs,
    aggregate: plan.aggregate,
    approvalSummary: plan.approvalSummary,
  };
}

interface RecoveryProof {
  walletInputSats: bigint;
  guaranteedWalletReturnSats: bigint;
  maximumWalletDebitSats: bigint;
  inscriptionIds: string[];
}

function proveCommittedWalletRecovery(
  plan: ProviderPsbtPlanV3,
  node: LinkedProviderPsbtNode,
  inputIndex: number,
): RecoveryProof | null {
  const plannedInput = plan.inputs[inputIndex];
  const commitment = node.commitments.find((item) => item.inputIndex === inputIndex);
  const explanation = plan.approvalExplanation;
  if (!plannedInput || plannedInput.ownership !== 'wallet' || !plannedInput.derivation || !commitment ||
      commitment.committedOutputIndexes !== 'all' || !explanation ||
      explanation.commitments.outputs !== 'fixed' ||
      plan.outputs.length === 0 || plan.outputs.some((output) => !output.derivation) ||
      explanation.outputs.some((output) => output.ownership !== 'wallet' || !output.guaranteed)) {
    return null;
  }
  const selected = new Set(node.selectedInputIndexes);
  // A recovery is useful only when this wallet can finalize it without a
  // counterparty. Fixed wallet outputs are not enough if an external input can
  // still withhold its signature.
  if (plan.inputs.some((candidate, index) =>
    candidate.ownership !== 'wallet' || !candidate.derivation || !selected.has(index))) {
    return null;
  }
  const walletInputSats = plan.inputs.reduce((sum, candidate) =>
    candidate.ownership === 'wallet' ? sum + candidate.valueSats : sum, 0n);
  const guaranteedWalletReturnSats = BigInt(explanation.guaranteedWalletReturnSats);
  const maximumWalletDebitSats = BigInt(explanation.maximumWalletDebitSats);
  if (guaranteedWalletReturnSats !== plan.outputs.reduce((sum, output) => sum + output.valueSats, 0n) ||
      maximumWalletDebitSats !== (walletInputSats > guaranteedWalletReturnSats
        ? walletInputSats - guaranteedWalletReturnSats : 0n) || maximumWalletDebitSats > plan.feeSats) {
    return null;
  }

  const inscriptionIds: string[] = [];
  for (let index = 0; index < plan.inputs.length; index += 1) {
    const candidate = plan.inputs[index]!;
    if (candidate.ownership !== 'wallet') continue;
    if (candidate.classification.unsupportedAssetDetected || candidate.classification.satRanges?.some((range) =>
      range.rarity !== undefined && range.rarity !== 'common') === true) return null;
    const expected = candidate.classification.inscriptions.map((item) => item.inscriptionId).sort();
    const flows = plan.protectedSatFlow.filter((flow) => flow.inputIndex === index);
    const actual = flows.map((flow) => flow.inscriptionId).sort();
    if (expected.length !== actual.length || expected.some((id, position) => id !== actual[position]) ||
        flows.some((flow) => !plan.outputs[flow.outputIndex]?.derivation ||
          plan.outputs[flow.outputIndex]?.derivation?.lane !== 'ordinals')) {
      return null;
    }
    inscriptionIds.push(...expected);
  }
  return {
    walletInputSats,
    guaranteedWalletReturnSats,
    maximumWalletDebitSats,
    inscriptionIds: [...new Set(inscriptionIds)].sort(),
  };
}

function recognizedMarketplace(plan: ProviderPsbtPlanV3): boolean {
  return plan.marketplace?.resolution.status === 'recognized';
}

function proveSettlement(
  item: ProviderPsbtGroupItemV1,
  node: LinkedProviderPsbtNode,
  inputIndex: number,
): ProviderPsbtGroupAlternativeProofV1['settlements'][number] | null {
  if (!node.selectedInputIndexes.includes(inputIndex) ||
      item.plan.inputs[inputIndex]?.ownership !== 'wallet' || !item.plan.approvalExplanation) return null;
  const linked = item.plan.linkedGroup?.inputProvenance[inputIndex];
  const proof = recognizedMarketplace(item.plan)
    ? 'recognized_marketplace_plan' as const
    : linked?.kind === 'linked_output' && linked.walletControl === 'ordnet_sale_script_path' &&
      item.plan.genericListing
      ? 'pinned_ordnet_sale_control' as const
      : null;
  if (!proof) return null;
  const plannedInput = item.plan.inputs[inputIndex]!;
  const correspondingOutput = item.plan.outputs[inputIndex];
  const pinnedGuaranteedReturn = proof === 'pinned_ordnet_sale_control' && correspondingOutput?.derivation
    ? correspondingOutput.valueSats : null;
  return {
    nodeId: item.nodeId,
    inputIndex,
    proof,
    guaranteedWalletReturnSats: pinnedGuaranteedReturn ??
      BigInt(item.plan.approvalExplanation.guaranteedWalletReturnSats),
    maximumWalletDebitSats: pinnedGuaranteedReturn === null
      ? BigInt(item.plan.approvalExplanation.maximumWalletDebitSats)
      : plannedInput.valueSats > pinnedGuaranteedReturn
        ? plannedInput.valueSats - pinnedGuaranteedReturn : 0n,
  };
}

function sameMarketplaceWorkflow(left: ProviderPsbtPlanV3, right: ProviderPsbtPlanV3): boolean {
  if (Boolean(left.marketplace) !== Boolean(right.marketplace)) return false;
  if (!left.marketplace || !right.marketplace) return true;
  return left.marketplace.resolution.templateId === right.marketplace.resolution.templateId &&
    left.marketplace.context.version === right.marketplace.context.version &&
    left.marketplace.context.marketplaceId === right.marketplace.context.marketplaceId &&
    left.marketplace.context.templateVersion === right.marketplace.context.templateVersion &&
    left.marketplace.context.action === right.marketplace.context.action &&
    left.marketplace.context.role === right.marketplace.context.role &&
    left.marketplace.context.assetKind === right.marketplace.context.assetKind &&
    left.marketplace.context.stepCount === right.marketplace.context.stepCount &&
    left.marketplace.context.workflowId === right.marketplace.context.workflowId &&
    left.marketplace.context.broadcaster === right.marketplace.context.broadcaster &&
    left.marketplace.context.expiresAt === right.marketplace.context.expiresAt &&
    left.marketplace.context.revision === right.marketplace.context.revision &&
    sameCanonical(left.marketplace.context.identifiers, right.marketplace.context.identifiers) &&
    sameCanonical(left.marketplace.context.economics, right.marketplace.context.economics);
}

function assertOmbOrdnetListingWorkflow(items: readonly ProviderPsbtGroupItemV1[]): void {
  if (items[0]?.plan.marketplace?.resolution.templateId !== 'omb-wiki-ordnet-list-v1') return;
  if (items.length !== 3) throw new Error('OMB ord.net listing requires exactly three transactions');
  const stages = ['escrow', 'settlement', 'recovery'] as const;
  for (let index = 0; index < items.length; index += 1) {
    const item = items[index]!;
    const marketplace = item.plan.marketplace;
    if (!marketplace || marketplace.resolution.templateId !== 'omb-wiki-ordnet-list-v1' ||
        marketplace.context.step !== index + 1 || marketplace.context.stepCount !== 3 ||
        marketplace.context.stage !== stages[index] || marketplace.context.broadcaster !== 'site') {
      throw new Error('OMB ord.net listing steps are missing, duplicated, or reordered');
    }
  }
  const first = items[0]!.plan;
  const settlement = items[1]!.plan;
  const recovery = items[2]!.plan;
  const context = first.marketplace!.context;
  const identifiers = context.identifiers;
  const economics = context.economics;
  if (!identifiers?.inscriptionId || !identifiers.inscriptionOutpoint || !identifiers.preflightHandle ||
      !economics?.priceSats || !economics.sellerProceedsSats || !economics.marketplaceFeeSats ||
      !economics.payoutAddress || !economics.assetDestination ||
      BigInt(economics.sellerProceedsSats) + BigInt(economics.marketplaceFeeSats) !== BigInt(economics.priceSats)) {
    throw new Error('OMB ord.net listing outcome binding is incomplete or inconsistent');
  }
  if (first.inputs.length !== 1 || first.outputs.length !== 1 ||
      first.selectedInputIndexes?.length !== 1 || first.selectedInputIndexes[0] !== 0 ||
      `${first.inputs[0]!.txid}:${first.inputs[0]!.vout}` !== identifiers.inscriptionOutpoint ||
      first.inputs[0]!.classification.inscriptions.length !== 1 ||
      first.inputs[0]!.classification.inscriptions[0]!.inscriptionId !== identifiers.inscriptionId ||
      first.inputs[0]!.classification.inscriptions[0]!.satpoint !== `${identifiers.inscriptionOutpoint}:0` ||
      first.inputs[0]!.classification.unsupportedAssetDetected || first.inputs[0]!.sighash !== 0) {
    throw new Error('OMB ord.net escrow input or inscription provenance differs');
  }
  const parentTxid = topologyTxid(first);
  const settlementSelection = items[1]!.inputsToSign?.find((selection) =>
    selection.signingIndexes.includes(0));
  if (settlement.selectedInputIndexes?.length !== 1 || settlement.selectedInputIndexes[0] !== 0 ||
      settlement.inputs[0]?.txid !== parentTxid || settlement.inputs[0]?.vout !== 0 ||
      settlement.inputs[0]?.sighash !== 0x83 || settlementSelection?.disableTweakSigner !== true ||
      settlement.outputs[0]?.address !== economics.payoutAddress ||
      settlement.outputs[0]!.valueSats < BigInt(economics.sellerProceedsSats)) {
    throw new Error('OMB ord.net settlement authorization differs from the approved outcome');
  }
  const recoveryFlows = recovery.protectedSatFlow.filter((flow) =>
    flow.inscriptionId === identifiers.inscriptionId);
  if (recovery.inputs.length !== 1 || recovery.outputs.length !== 1 ||
      recovery.selectedInputIndexes?.length !== 1 || recovery.selectedInputIndexes[0] !== 0 ||
      recovery.inputs[0]!.txid !== parentTxid || recovery.inputs[0]!.vout !== 0 ||
      recovery.inputs[0]!.sighash !== 1 || recovery.outputs[0]!.address !== economics.assetDestination ||
      recovery.outputs[0]!.derivation?.lane !== 'ordinals' || recoveryFlows.length !== 1 ||
      recoveryFlows[0]!.inputOffset !== 0n || recoveryFlows[0]!.outputIndex !== 0 ||
      recoveryFlows[0]!.outputOffset !== 0n) {
    throw new Error('OMB ord.net recovery path differs from the approved destination');
  }
}

function topologyTxid(plan: ProviderPsbtPlanV3): string {
  const unsigned = Transaction.fromPSBT(hexToBytes(plan.psbtHex), {
    lowR: true,
    allowUnknownInputs: true,
    allowUnknownOutputs: true,
  }).unsignedTx;
  const first = getCryptoProvider().sha256(unsigned);
  return bytesToHex(getCryptoProvider().sha256(first).reverse());
}

/**
 * Prove one consumer is a recognized settlement and the other is a committed
 * wallet return. This does not claim that arbitrary double-spends are safe.
 * More complex recovery shapes require an explicit compile-time policy seam
 * that identifies the recovery leg and proves its intended asset/value bounds.
 */
function proveAlternative(
  alternative: LinkedProviderPsbtAlternative,
  byNodeId: ReadonlyMap<string, ProviderPsbtGroupItemV1>,
  topologyByNodeId: ReadonlyMap<string, LinkedProviderPsbtNode>,
): ProviderPsbtGroupAlternativeProofV1 {
  if (alternative.source !== 'linked_output' || alternative.parentNodeId === null) {
    throw new Error('linked PSBT recovery proof requires an internal output');
  }
  const assignments: ProviderPsbtGroupAlternativeProofV1[] = [];
  for (const recoveryConsumer of alternative.consumers) {
    const recoveryItem = byNodeId.get(recoveryConsumer.nodeId);
    const recoveryNode = topologyByNodeId.get(recoveryConsumer.nodeId);
    const parentItem = byNodeId.get(alternative.parentNodeId);
    if (!recoveryItem || !recoveryNode || !parentItem) continue;
    const recovery = proveCommittedWalletRecovery(
      recoveryItem.plan,
      recoveryNode,
      recoveryConsumer.inputIndex,
    );
    if (!recovery) continue;
    const settlements = alternative.consumers
      .filter((consumer) => consumer !== recoveryConsumer)
      .map((consumer) => {
        const item = byNodeId.get(consumer.nodeId);
        const node = topologyByNodeId.get(consumer.nodeId);
        if (!item || !node || !sameMarketplaceWorkflow(recoveryItem.plan, item.plan) ||
            !sameMarketplaceWorkflow(parentItem.plan, item.plan)) return null;
        return proveSettlement(item, node, consumer.inputIndex);
      });
    if (settlements.length === 0 || settlements.some((settlement) => settlement === null)) continue;
    assignments.push({
      outpoint: alternative.outpoint,
      parentNodeId: alternative.parentNodeId,
      parentOutputIndex: alternative.parentOutputIndex,
      settlements: settlements as ProviderPsbtGroupAlternativeProofV1['settlements'],
      recoveryNodeId: recoveryConsumer.nodeId,
      recoveryInputIndex: recoveryConsumer.inputIndex,
      recoveryProof: 'committed_wallet_return',
      recoveryWalletInputSats: recovery.walletInputSats,
      recoveryGuaranteedWalletReturnSats: recovery.guaranteedWalletReturnSats,
      recoveryMaximumWalletDebitSats: recovery.maximumWalletDebitSats,
      recoveredInscriptionIds: recovery.inscriptionIds,
    });
  }
  if (assignments.length !== 1) {
    throw new Error('linked PSBT alternative needs an explicit compile-time recovery policy');
  }
  return assignments[0]!;
}

function proveExternalConflict(
  alternative: LinkedProviderPsbtAlternative,
  byNodeId: ReadonlyMap<string, ProviderPsbtGroupItemV1>,
  topologyByNodeId: ReadonlyMap<string, LinkedProviderPsbtNode>,
): { outpoint: string; nodeIds: string[] } {
  if (alternative.source !== 'external_input' || alternative.parentNodeId !== null ||
      alternative.consumers.length < 2) {
    throw new Error('external PSBT conflict proof is invalid');
  }
  let expectedInput: ProviderPsbtPlanV3['inputs'][number] | null = null;
  const nodeIds = new Set<string>();
  for (const consumer of alternative.consumers) {
    const item = byNodeId.get(consumer.nodeId);
    const node = topologyByNodeId.get(consumer.nodeId);
    const planned = item?.plan.inputs[consumer.inputIndex];
    const provenance = item?.plan.linkedGroup?.inputProvenance[consumer.inputIndex];
    const commitment = node?.commitments.find((candidate) => candidate.inputIndex === consumer.inputIndex);
    if (!item || !node || !planned || planned.ownership !== 'wallet' ||
        !node.selectedInputIndexes.includes(consumer.inputIndex) ||
        item.plan.inputs.some((input, index) => input.ownership === 'wallet' &&
          !node.selectedInputIndexes.includes(index)) ||
        node.commitments.some((candidate) => candidate.rawSighash !== 0 && candidate.rawSighash !== 1) ||
        node.commitments.some((candidate) => candidate.committedInputIndexes !== 'all' ||
          candidate.committedOutputIndexes !== 'all') ||
        !commitment || (commitment.rawSighash !== 0 && commitment.rawSighash !== 1) ||
        commitment.committedInputIndexes !== 'all' || commitment.committedOutputIndexes !== 'all' ||
        provenance?.kind !== 'gateway' || provenance.outpoint !== alternative.outpoint || item.plan.genericListing) {
      throw new Error('repeated external PSBT input is not an exact selected wallet conflict');
    }
    if (expectedInput && (planned.txid !== expectedInput.txid || planned.vout !== expectedInput.vout ||
        planned.valueSats !== expectedInput.valueSats || planned.scriptPubKey !== expectedInput.scriptPubKey ||
        !sameCanonical(planned.classification, expectedInput.classification))) {
      throw new Error('repeated external PSBT prevout facts differ');
    }
    expectedInput = planned;
    nodeIds.add(consumer.nodeId);
  }
  return { outpoint: alternative.outpoint, nodeIds: [...nodeIds].sort() };
}

function validateItems(
  items: readonly ProviderPsbtGroupItemV1[],
  suppliedPreparation?: PreparedProviderPsbtGroupInputsV1,
): {
  topology: LinkedProviderPsbtGroupTopologyV1;
  alternativeProofs: ProviderPsbtGroupAlternativeProofV1[];
  aggregate: ProviderPsbtGroupPlanV1['aggregate'];
  approvalSummary: ProviderPsbtGroupPlanV1['approvalSummary'];
  preparation: PreparedProviderPsbtGroupInputsV1 | null;
} {
  const planIds = new Set<string>();
  for (const item of items) {
    assertProviderPsbtPlan(item.plan);
    if (!item.nodeId || planIds.has(item.plan.planId) || item.plan.broadcast ||
        item.plan.provider.providerMethod !== 'signMultipleTransactions' ||
        item.plan.communityVaultAcquisition || item.plan.communityVaultSale ||
        item.plan.communityVaultSaleBuyer || item.plan.communityVaultPositionTransfer ||
        (item.plan.marketplace !== undefined && !recognizedMarketplace(item.plan))) {
      throw new Error('provider group item is invalid, duplicated, or may broadcast');
    }
    const expected = resolveProviderPsbtInputSelections(item.plan, item.inputsToSign);
    if (!sameCanonical(expected, item.requestedInputIndexes)) {
      throw new Error('provider group signing indexes differ from prepared plan');
    }
    planIds.add(item.plan.planId);
  }
  const marketplaceItems = items.filter((item) => item.plan.marketplace !== undefined);
  if (marketplaceItems.length > 0 && marketplaceItems.length !== items.length) {
    throw new Error('provider group may not mix recognized and contextless marketplace workflows');
  }
  const firstMarketplace = marketplaceItems[0]?.plan;
  if (firstMarketplace && marketplaceItems.slice(1).some((item) =>
    !sameMarketplaceWorkflow(firstMarketplace, item.plan))) {
    throw new Error('provider group marketplace workflow differs between items');
  }
  assertOmbOrdnetListingWorkflow(items);
  const topology = deriveLinkedProviderPsbtGroup(items.map((item) => ({
    nodeId: item.nodeId,
    psbtBase64: bytesToBase64(hexToBytes(item.plan.psbtHex)),
    selectedInputIndexes: item.requestedInputIndexes,
  })));
  for (const node of topology.nodes) {
    const item = items[node.requestIndex];
    if (item?.expectedUnsignedTxid !== undefined && item.expectedUnsignedTxid !== node.unsignedTxid) {
      throw new Error('provider group expected transaction id differs from the PSBT');
    }
  }
  const preparedGroup = items.some((item) => item.plan.linkedGroup !== undefined);
  const firstLinked = items.find((item) => item.plan.linkedGroup)?.plan.linkedGroup;
  let preparation: PreparedProviderPsbtGroupInputsV1 | null = null;
  if (preparedGroup) {
    if (!firstLinked || items.some((item) => !item.plan.linkedGroup ||
        item.plan.linkedGroup.groupId !== firstLinked.groupId ||
        item.plan.linkedGroup.preparationHash !== firstLinked.preparationHash ||
        item.plan.linkedGroup.nodeId !== item.nodeId)) {
      throw new Error('linked provider group preparation is missing or differs between items');
    }
    const supplied = suppliedPreparation;
    if (!supplied || supplied.groupId !== firstLinked.groupId ||
        supplied.preparationHash !== firstLinked.preparationHash) {
      throw new Error('linked provider group preparation evidence is missing');
    }
    const roots = supplied.items.flatMap((preparedItem) => preparedItem.classifications.filter((_classification, index) =>
      preparedItem.provenance[index]?.kind === 'gateway'));
    const uniqueRoots = [...new Map(roots.map((classification) =>
      [`${classification.txid}:${classification.vout}`, classification])).values()];
    const controlCandidates = items.flatMap((item, requestIndex) => {
      const preparedItem = supplied.items[requestIndex];
      return (item.inputsToSign ?? []).flatMap((selection) => selection.signingIndexes.flatMap((inputIndex) => {
        const planInput = item.plan.inputs[inputIndex];
        const preparedWalletInput = preparedItem?.walletInputs.find((candidate) =>
          candidate.outpoint === (planInput ? `${planInput.txid}:${planInput.vout}` : ''));
        return preparedWalletInput ? [{ address: selection.address, derivation: preparedWalletInput.derivation }] : [];
      }));
    });
    const recomputed = prepareProviderPsbtGroupInputs({
      groupId: supplied.groupId,
      items: items.map((item) => ({
        nodeId: item.nodeId,
        psbtBase64: bytesToBase64(hexToBytes(item.plan.psbtHex)),
        selectedInputIndexes: item.requestedInputIndexes,
        ...(item.inputsToSign === undefined ? {} : { inputsToSign: item.inputsToSign }),
        ...(item.plan.marketplace === undefined ? {} : { marketplace: {
          context: item.plan.marketplace.context,
          resolution: item.plan.marketplace.resolution,
        } }),
      })),
      externalClassifications: uniqueRoots,
      prospectiveOutpoints: supplied.prospectiveOutpoints,
      source: items[0]!.plan.source,
      walletControl: {
        network: items[0]!.plan.network,
        origin: items[0]!.plan.provider.origin,
        accountId: items[0]!.plan.accountId,
        account: items[0]!.plan.account,
        candidates: controlCandidates,
      },
    });
    if (!sameCanonical(recomputed, supplied)) {
      throw new Error('linked provider group preparation evidence changed');
    }
    for (let requestIndex = 0; requestIndex < items.length; requestIndex += 1) {
      const item = items[requestIndex]!;
      const preparedItem = supplied.items[requestIndex];
      if (!preparedItem || preparedItem.nodeId !== item.nodeId ||
          !sameCanonical(preparedItem.provenance, item.plan.linkedGroup!.inputProvenance) ||
          item.plan.inputs.some((planInput, inputIndex) => {
            const expected = preparedItem.classifications[inputIndex];
            return !expected || planInput.txid !== expected.txid || planInput.vout !== expected.vout ||
              planInput.valueSats.toString() !== expected.valueSats ||
              planInput.scriptPubKey !== expected.scriptPubKey ||
              !sameCanonical(planInput.classification, {
                primaryClass: expected.primaryClass,
                inscriptions: expected.inscriptions,
                satRanges: expected.satRanges,
                unsupportedAssetDetected: expected.unsupportedAssetDetected,
                confidence: expected.confidence,
                classifiedTip: expected.classifiedTip,
                classificationRevision: expected.classificationRevision,
              });
          })) {
        throw new Error('linked provider plan differs from projected input evidence');
      }
    }
    preparation = supplied;
  } else if (suppliedPreparation) {
    throw new Error('provider group may not carry unused preparation evidence');
  }
  const byNodeId = new Map(items.map((item) => [item.nodeId, item]));
  const topologyByNodeId = new Map(topology.nodes.map((node) => [node.nodeId, node]));
  const alternativeProofs = topology.alternatives
    .filter((alternative) => alternative.source === 'linked_output')
    .map((alternative) => proveAlternative(alternative, byNodeId, topologyByNodeId));
  const externalConflictProofs = topology.alternatives
    .filter((alternative) => alternative.source === 'external_input')
    .map((alternative) => proveExternalConflict(alternative, byNodeId, topologyByNodeId));
  const recoveredInscriptionIds = new Set(alternativeProofs.flatMap((proof) => proof.recoveredInscriptionIds));
  const unprovenContextlessInscription = items.some((item) => !item.plan.marketplace &&
    item.requestedInputIndexes.some((inputIndex) => item.plan.inputs[inputIndex]!.classification.inscriptions
      .some((inscription) => !recoveredInscriptionIds.has(inscription.inscriptionId))));
  if (unprovenContextlessInscription) {
    throw new Error('linked PSBT contextless protected asset lacks a committed recovery alternative');
  }
  const aggregate = {
    encodedPsbtChars: items.reduce((total, item) =>
      total + bytesToBase64(hexToBytes(item.plan.psbtHex)).length, 0),
    inputs: topology.nodes.reduce((total, node) => total + node.inputs.length, 0),
    outputs: topology.nodes.reduce((total, node) => total + node.outputs.length, 0),
    selectedInputs: topology.nodes.reduce((total, node) => total + node.selectedInputIndexes.length, 0),
  };
  const marketplaceActions = [...new Set(items.flatMap((item) =>
    item.plan.marketplace ? [item.plan.marketplace.context.action] : []))].sort();
  const settlementDebits = new Map<string, Map<number, bigint>>();
  const recoveryDebits = new Map<string, bigint>();
  const controlledParentOutputs = new Map<string, Set<number>>();
  for (const proof of alternativeProofs) {
    const controlled = controlledParentOutputs.get(proof.parentNodeId) ?? new Set<number>();
    controlled.add(proof.parentOutputIndex);
    controlledParentOutputs.set(proof.parentNodeId, controlled);
    for (const settlement of proof.settlements) {
      const byInput = settlementDebits.get(settlement.nodeId) ?? new Map<number, bigint>();
      byInput.set(settlement.inputIndex, settlement.maximumWalletDebitSats);
      settlementDebits.set(settlement.nodeId, byInput);
    }
    recoveryDebits.set(proof.recoveryNodeId, proof.recoveryMaximumWalletDebitSats);
  }
  const planDebit = (item: ProviderPsbtGroupItemV1): bigint => {
    const settlement = settlementDebits.get(item.nodeId);
    const settlementDebit = settlement
      ? [...settlement.values()].reduce((total, debit) => total + debit, 0n) : null;
    const recoveryDebit = recoveryDebits.get(item.nodeId) ?? null;
    if (settlementDebit !== null || recoveryDebit !== null) {
      return (settlementDebit ?? 0n) > (recoveryDebit ?? 0n)
        ? settlementDebit ?? 0n : recoveryDebit ?? 0n;
    }
    const controlled = controlledParentOutputs.get(item.nodeId);
    if (controlled) {
      const node = topologyByNodeId.get(item.nodeId);
      if (!node) throw new Error('linked PSBT controlled parent is missing');
      const walletInputs = item.plan.inputs.reduce((total, candidate) =>
        candidate.ownership === 'wallet' ? total + candidate.valueSats : total, 0n);
      const walletOutputs = item.plan.outputs.reduce((total, output) =>
        output.derivation ? total + output.valueSats : total, 0n);
      const controlledOutputs = [...controlled].reduce((total, outputIndex) => {
        const output = node.outputs[outputIndex];
        if (!output) throw new Error('linked PSBT controlled parent output is missing');
        return total + (item.plan.outputs[outputIndex]?.derivation ? 0n : output.valueSats);
      }, 0n);
      const exposed = walletInputs - walletOutputs - controlledOutputs;
      return exposed > 0n ? exposed : 0n;
    }
    return BigInt(item.plan.approvalExplanation?.maximumWalletDebitSats ?? '0');
  };
  const allDebit = items.reduce((total, item) => total + planDebit(item), 0n);
  const allFees = items.reduce((total, item) => total + item.plan.feeSats, 0n);
  let maximumWalletDebitSats = allDebit;
  let maximumFeeExposureSats = allFees;
  const conflictSets = [...new Map(topology.alternatives.map((alternative) => {
    const nodeIds = [...new Set(alternative.consumers.map((consumer) => consumer.nodeId))].sort();
    return [nodeIds.join('\u0000'), new Set(nodeIds)] as const;
  })).values()];
  const conflictNodeIds = new Set<string>();
  let branchEconomicsExact = true;
  for (const set of conflictSets) {
    if ([...set].some((nodeId) => conflictNodeIds.has(nodeId))) branchEconomicsExact = false;
    for (const nodeId of set) conflictNodeIds.add(nodeId);
  }
  if (branchEconomicsExact && conflictSets.length > 0) {
    const common = items.filter((item) => !conflictNodeIds.has(item.nodeId));
    maximumWalletDebitSats = common.reduce((total, item) => total + planDebit(item), 0n) +
      conflictSets.reduce((total, set) => total + items.filter((item) => set.has(item.nodeId))
        .reduce((maximum, item) => planDebit(item) > maximum ? planDebit(item) : maximum, 0n), 0n);
    maximumFeeExposureSats = common.reduce((total, item) => total + item.plan.feeSats, 0n) +
      conflictSets.reduce((total, set) => total + items.filter((item) => set.has(item.nodeId))
        .reduce((maximum, item) => item.plan.feeSats > maximum ? item.plan.feeSats : maximum, 0n), 0n);
  }
  const collapsedAlternativeOutcomes = [...alternativeProofs.reduce((groups, proof) => {
    const key = JSON.stringify({
      settlements: proof.settlements.map((settlement) => settlement.nodeId).sort(),
      recovery: proof.recoveryNodeId,
    });
    const existing = groups.get(key);
    if (existing) existing.outpoints.push(proof.outpoint);
    else groups.set(key, { proof, outpoints: [proof.outpoint] });
    return groups;
  }, new Map<string, { proof: ProviderPsbtGroupAlternativeProofV1; outpoints: string[] }>()).values()];
  const externalConflicts = [...externalConflictProofs.reduce((groups, proof) => {
    const key = proof.nodeIds.join('\u0000');
    const existing = groups.get(key);
    if (existing) existing.outpoints.push(proof.outpoint);
    else groups.set(key, { outpoints: [proof.outpoint], nodeIds: proof.nodeIds });
    return groups;
  }, new Map<string, { outpoints: string[]; nodeIds: string[] }>()).values()]
    .map((conflict) => ({ ...conflict, outpoints: conflict.outpoints.sort() }));
  return {
    topology,
    preparation,
    alternativeProofs,
    aggregate,
    approvalSummary: {
      action: 'sign_transaction_group',
      transactionCount: items.length,
      linked: !topology.independent,
      alternativeCount: topology.alternatives.length,
      marketplaceActions,
      walletInputSats: items.reduce((total, item) => total + item.plan.inputs.reduce((sum, planInput) =>
        planInput.ownership === 'wallet' ? sum + planInput.valueSats : sum, 0n), 0n),
      walletOutputSats: items.reduce((total, item) => total + item.plan.outputs.reduce((sum, output) =>
        output.derivation ? sum + output.valueSats : sum, 0n), 0n),
      feeExposureSats: allFees,
      maximumWalletDebitSats,
      maximumFeeExposureSats,
      branchEconomicsExact,
      externalConflicts,
      alternativeOutcomes: collapsedAlternativeOutcomes.map(({ proof, outpoints }) => ({
        outpoint: proof.outpoint,
        outpoints: [...outpoints].sort(),
        settlements: proof.settlements.map((settlement) => ({
          nodeId: settlement.nodeId,
          guaranteedWalletReturnSats: settlement.guaranteedWalletReturnSats,
          maximumWalletDebitSats: settlement.maximumWalletDebitSats,
        })),
        recovery: {
          nodeId: proof.recoveryNodeId,
          guaranteedWalletReturnSats: proof.recoveryGuaranteedWalletReturnSats,
          maximumWalletDebitSats: proof.recoveryMaximumWalletDebitSats,
        },
      })),
    },
  };
}

export function createProviderPsbtGroupPlan(input: {
  items: Array<{
    nodeId: string;
    plan: ProviderPsbtPlanV3;
    inputsToSign?: ProviderPsbtInputSelection[];
    expectedUnsignedTxid?: string;
  }>;
  groupId: string;
  now: number;
  approvalGeneration: number;
  preparation?: PreparedProviderPsbtGroupInputsV1;
}): ProviderPsbtGroupPlanV1 {
  if (!input.groupId || input.groupId.length > 128 || !Number.isSafeInteger(input.now) || input.now < 0 ||
      !Number.isSafeInteger(input.approvalGeneration) || input.approvalGeneration < 0) {
    throw new Error('provider group identity is invalid');
  }
  const items = input.items.map((item) => ({
    ...item,
    requestedInputIndexes: resolveProviderPsbtInputSelections(item.plan, item.inputsToSign),
  }));
  const validated = validateItems(items, input.preparation);
  const first = items[0]?.plan;
  if (!first) throw new Error('provider group must contain at least one item');
  if (validated.preparation && validated.preparation.groupId !== input.groupId) {
    throw new Error('provider group identity differs from its preparation evidence');
  }
  for (const item of items.slice(1)) {
    const plan = item.plan;
    if (plan.network !== first.network || plan.vaultId !== first.vaultId ||
        plan.sessionId !== first.sessionId || plan.accountId !== first.accountId ||
        plan.account !== first.account || !sameAuthority(plan.provider, first.provider)) {
      throw new Error('provider group context differs between items');
    }
  }
  const withoutHash: Omit<ProviderPsbtGroupPlanV1, 'groupHash'> = {
    version: 1,
    groupId: input.groupId,
    createdAt: input.now,
    expiresAt: Math.min(...items.map((item) => item.plan.expiresAt)),
    network: first.network,
    vaultId: first.vaultId,
    sessionId: first.sessionId,
    accountId: first.accountId,
    account: first.account,
    provider: first.provider as ProviderPsbtGroupPlanV1['provider'],
    approvalGeneration: input.approvalGeneration,
    requiresAdvanced: items.some((item) => item.plan.requiresAdvanced),
    signatureRelease: 'all_or_nothing',
    items,
    ...validated,
  };
  return Object.freeze({ ...withoutHash, groupHash: hash(groupProjection(withoutHash)) });
}

export function assertProviderPsbtGroupPlan(plan: ProviderPsbtGroupPlanV1): void {
  if (!plan || plan.version !== 1 || plan.signatureRelease !== 'all_or_nothing' ||
      !plan.groupId || plan.groupId.length > 128 || !Number.isSafeInteger(plan.createdAt) || plan.createdAt < 0 ||
      !Number.isSafeInteger(plan.approvalGeneration) || plan.approvalGeneration < 0) {
    throw new Error('provider group plan mutated');
  }
  const validated = validateItems(plan.items, plan.preparation ?? undefined);
  const first = plan.items[0]?.plan;
  if (!first || plan.expiresAt !== Math.min(...plan.items.map((item) => item.plan.expiresAt)) ||
      plan.network !== first.network || plan.vaultId !== first.vaultId ||
      plan.sessionId !== first.sessionId || plan.accountId !== first.accountId || plan.account !== first.account ||
      !sameAuthority(plan.provider, first.provider) ||
      plan.requiresAdvanced !== plan.items.some((item) => item.plan.requiresAdvanced) ||
      plan.items.some((item) => item.plan.network !== plan.network || item.plan.vaultId !== plan.vaultId ||
        item.plan.sessionId !== plan.sessionId || item.plan.accountId !== plan.accountId ||
        item.plan.account !== plan.account || !sameAuthority(item.plan.provider, plan.provider)) ||
      !sameCanonical(validated.topology, plan.topology) ||
      !sameCanonical(validated.alternativeProofs, plan.alternativeProofs) ||
      !sameCanonical(validated.aggregate, plan.aggregate) ||
      !sameCanonical(validated.approvalSummary, plan.approvalSummary) ||
      hash(groupProjection(plan)) !== plan.groupHash) {
    throw new Error('provider group plan mutated');
  }
}

/**
 * Sign in dependency order and release only after every result and the final
 * lifecycle guard succeed. A rejection exposes no partially signed PSBT.
 */
export async function signProviderPsbtGroupPlan(input: {
  plan: ProviderPsbtGroupPlanV1;
  seed: Uint8Array;
  now: () => number;
  random: (length: number) => Uint8Array;
  guard?: () => void;
  yieldControl: () => Promise<void>;
}): Promise<SignedProviderPsbtGroupV1> {
  return signValidatedProviderPsbtGroupAtomically(input);
}
