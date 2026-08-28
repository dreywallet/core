import { beforeAll, describe, expect, it } from 'vitest';
import { NETWORK, p2tr, p2tr_ns, SigHash, Transaction } from '@scure/btc-signer';
import { publicAccountFromSeed } from '../../src/domain/accounts/public-account';
import { deriveAccountNode, deriveAddress } from '../../src/domain/keys/derivation';
import { mnemonicToSeed } from '../../src/domain/keys/mnemonic';
import { scriptPubKeyHex } from '../../src/domain/keys/script-hash';
import type { UtxoClassification } from '../../src/domain/gateway/contract';
import {
  assertProviderPsbtGroupPlan,
  createProviderPsbtGroupPlan,
  signProviderPsbtGroupPlan,
} from '../../src/domain/transactions/provider-psbt-group-plan';
import { providerPsbtUnsignedTxid } from '../../src/domain/transactions/provider-psbt-batch';
import {
  bindProviderPsbtPlanPreviews,
  createProviderPsbtPlan,
  signProviderPsbtPlan,
  type ProviderPsbtPlanV3,
} from '../../src/domain/transactions/provider-psbt';
import {
  prepareProviderPsbtGroupInputs,
  providerPsbtLinkedGroupBinding,
  type PreparedProviderPsbtGroupInputsV1,
} from '../../src/domain/transactions/provider-psbt-group-prepare';
import { deriveLinkedProviderPsbtGroup } from '../../src/domain/transactions/provider-psbt-group';
import { base64ToBytes, bytesToBase64, hexToBytes } from '../../src/domain/vault/encoding';
import { installTestCryptoProvider } from '../helpers/install-crypto-provider';
import { ORDNET_SALE_PUBLIC_KEY } from '../../src/domain/marketplaces/ordnet-script-path';

beforeAll(() => installTestCryptoProvider());

const NOW = 1_800_000_000_000;
const seed = mnemonicToSeed('abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about');
const publicAccount = publicAccountFromSeed(seed, 'mainnet', 0);
const account = deriveAccountNode(seed, 'payment', 'mainnet', 0);
const addresses = Array.from({ length: 4 }, (_value, index) =>
  deriveAddress(account, 'payment', 'mainnet', 0, index));
account.wipePrivateData();
const scripts = addresses.map((address) => scriptPubKeyHex(address.publicKeyHex, 'payment', 'mainnet'));
const ordinalAccount = deriveAccountNode(seed, 'ordinals', 'mainnet', 0);
const ordinalAddresses = Array.from({ length: 4 }, (_value, index) =>
  deriveAddress(ordinalAccount, 'ordinals', 'mainnet', 0, index));
ordinalAccount.wipePrivateData();
const ordinalScripts = ordinalAddresses.map((address) =>
  scriptPubKeyHex(address.publicKeyHex, 'ordinals', 'mainnet'));
const source = {
  backend: 'https://gateway.example', instanceId: 'gateway-1', classificationRevision: 'rev-1',
  coreTip: { height: 100, hash: 'aa'.repeat(32) }, indexTip: { height: 100, hash: 'aa'.repeat(32) },
  feeQuoteTimestamp: null, mempoolState: null,
};
const binding = {
  origin: 'https://ord.net', tabId: 1, frameId: 0,
  documentId: '123e4567-e89b-42d3-a456-426614174000',
  requestNonce: '123e4567-e89b-42d3-a456-426614174001',
  providerMethod: 'signMultipleTransactions' as const,
};

function derivation(index: number) {
  const address = addresses[index]!;
  return {
    accountId: publicAccount.accountId,
    account: 0,
    lane: 'payment' as const,
    chain: 0 as const,
    index,
    path: address.path,
    publicKeyHex: address.publicKeyHex,
  };
}

function ordinalDerivation(index: number) {
  const address = ordinalAddresses[index]!;
  return {
    accountId: publicAccount.accountId,
    account: 0,
    lane: 'ordinals' as const,
    chain: 0 as const,
    index,
    path: address.path,
    publicKeyHex: address.publicKeyHex,
  };
}

function bindPreviewPlaceholders(plan: ProviderPsbtPlanV3): ProviderPsbtPlanV3 {
  if (plan.inscriptionPreviews) return plan;
  return bindProviderPsbtPlanPreviews(plan, {
    transactionCommitmentHash: plan.transactionCommitmentHash,
    analysisHash: plan.analysisHash,
    psbtHash: plan.psbtHash,
    effectSetHash: plan.analysis.assetEffects.effectSetHash,
    classificationRevision: plan.source.classificationRevision,
    verifiedAtMs: plan.createdAt,
    items: plan.analysis.assetEffects.inscriptions.map((effect) => ({
      metadata: {
        inscriptionId: effect.inscriptionId,
        satpoint: effect.satpoint,
        outpoint: effect.outpoint,
        classificationRevision: plan.source.classificationRevision,
        number: null,
        contentType: null,
        contentLength: null,
        confirmations: 0,
        parent: null,
        delegate: null,
        reinscription: false,
        cursed: false,
      },
      preview: {
        disposition: 'placeholder' as const,
        reason: 'unavailable' as const,
        requestedInscriptionId: effect.inscriptionId,
        sourceInscriptionId: effect.inscriptionId,
        resolvedInscriptionId: effect.inscriptionId,
        delegateInscriptionId: null,
        sourceContentSha256: null,
        declaredMime: null,
        declaredContentLength: null,
        detectedMime: null,
        detectedFormat: null,
        sourceContentLength: null,
        policyRevision: 'm9p-preview-v2' as const,
        rendererRevision: 'test-v1',
        pngSha256: null,
        pngWidth: null,
        pngHeight: null,
        pngByteLength: null,
        bytesBase64: null,
      },
    })),
  });
}

function makePlan(input: {
  planId: string;
  txid: string;
  inputKeyIndex: number;
  inputAmount: bigint;
  outputKeyIndex: number;
  outputAmount: bigint;
  outputOwned: boolean;
  marketplace?: boolean;
  broadcast?: boolean;
  sessionId?: string;
  origin?: string;
  workflowId?: string;
  providerMethod?: 'signPsbt' | 'signMultipleTransactions';
  externalInputAmount?: bigint;
  sighash?: number;
}): ProviderPsbtPlanV3 {
  const tx = new Transaction({ lowR: true });
  tx.addInput({
    txid: input.txid,
    index: 0,
    sequence: 0xfffffffd,
    sighashType: input.sighash ?? SigHash.ALL,
    witnessUtxo: { amount: input.inputAmount, script: hexToBytes(scripts[input.inputKeyIndex]!) },
  });
  if (input.externalInputAmount !== undefined) {
    tx.addInput({
      txid: 'ee'.repeat(32),
      index: 1,
      sequence: 0xfffffffd,
      sighashType: SigHash.ALL,
      witnessUtxo: { amount: input.externalInputAmount, script: hexToBytes(scripts[3]!) },
    });
  }
  tx.addOutput({ amount: input.outputAmount, script: hexToBytes(scripts[input.outputKeyIndex]!) });
  const classification: UtxoClassification = {
    txid: input.txid,
    vout: 0,
    valueSats: input.inputAmount.toString(),
    scriptPubKey: scripts[input.inputKeyIndex]!,
    confirmations: 10,
    primaryClass: 'cardinal_clean',
    inscriptions: [],
    satRanges: [{ start: '0', end: '10000', rarity: 'common' }],
    unsupportedAssetDetected: false,
    confidence: 'authoritative',
    classifiedTip: source.coreTip,
    classificationRevision: source.classificationRevision,
  };
  const classifications = [classification];
  if (input.externalInputAmount !== undefined) {
    classifications.push({
      ...classification,
      txid: 'ee'.repeat(32),
      vout: 1,
      valueSats: input.externalInputAmount.toString(),
      scriptPubKey: scripts[3]!,
    });
  }
  return createProviderPsbtPlan({
    psbtBase64: bytesToBase64(tx.toPSBT()),
    binding: {
      ...binding,
      ...(input.origin === undefined ? {} : { origin: input.origin }),
      ...(input.providerMethod === undefined ? {} : { providerMethod: input.providerMethod }),
    },
    network: 'mainnet',
    vaultId: 'vault-1',
    sessionId: input.sessionId ?? 'session-1',
    accountId: publicAccount.accountId,
    account: 0,
    classifications,
    walletInputs: [{ outpoint: `${input.txid}:0`, derivation: derivation(input.inputKeyIndex) }],
    walletOutputs: input.outputOwned ? [{
      scriptPubKey: scripts[input.outputKeyIndex]!,
      output: {
        valueSats: input.outputAmount,
        scriptPubKey: scripts[input.outputKeyIndex]!,
        address: addresses[input.outputKeyIndex]!.address,
        role: 'payment_change',
        derivation: derivation(input.outputKeyIndex),
      },
    }] : [],
    source,
    broadcast: input.broadcast ?? false,
    selectedInputIndexes: [0],
    planId: input.planId,
    now: NOW,
    ...(input.marketplace ? { marketplace: {
      context: {
        version: 1,
        marketplaceId: 'ordnet',
        templateVersion: 'drey-1',
        action: 'offer' as const,
        role: 'buyer' as const,
        assetKind: 'inscription' as const,
        workflowId: input.workflowId ?? 'workflow-1',
        step: 1,
        stepCount: 1,
        broadcaster: 'site' as const,
      },
      resolution: {
        status: 'recognized' as const,
        marketplaceId: 'ordnet' as const,
        displayName: 'ord.net',
        templateId: 'ordnet-offer',
        templateVersion: 'drey-1',
        flexible: false,
        reason: 'fixture',
      },
      selectedInputIndexes: [0],
    } } : {}),
  });
}

function rebindLinkedPlan(
  plan: ProviderPsbtPlanV3,
  nodeId: string,
  preparation: PreparedProviderPsbtGroupInputsV1,
  preserveMarketplace = true,
): ProviderPsbtPlanV3 {
  const binding = providerPsbtLinkedGroupBinding(preparation, nodeId);
  const rootWalletInputs = plan.inputs.flatMap((item, index) =>
    binding.linkedGroup.inputProvenance[index]?.kind === 'gateway' && item.derivation
      ? [{ outpoint: `${item.txid}:${item.vout}`, derivation: item.derivation }] : []);
  return createProviderPsbtPlan({
    psbtBase64: bytesToBase64(hexToBytes(plan.psbtHex)),
    binding: plan.provider,
    network: plan.network,
    vaultId: plan.vaultId,
    sessionId: plan.sessionId,
    accountId: plan.accountId,
    account: plan.account,
    classifications: binding.classifications,
    walletInputs: [...rootWalletInputs, ...binding.walletInputs],
    walletOutputs: plan.outputs.flatMap((output) => output.derivation ? [{
      scriptPubKey: output.scriptPubKey,
      output: {
        valueSats: output.valueSats,
        scriptPubKey: output.scriptPubKey,
        address: output.address!,
        role: output.role === 'payment_change' || output.role === 'ordinal_change' || output.role === 'postage'
          ? output.role : 'payment_change' as const,
        derivation: output.derivation,
      },
    }] : []),
    source: plan.source,
    broadcast: false,
    ...(plan.selectedInputIndexes === undefined ? {} : { selectedInputIndexes: plan.selectedInputIndexes }),
    planId: plan.planId,
    now: plan.createdAt,
    ...(preserveMarketplace && plan.marketplace ? { marketplace: {
      context: plan.marketplace.context,
      resolution: plan.marketplace.resolution,
      selectedInputIndexes: plan.marketplace.selectedInputIndexes,
    } } : {}),
    linkedGroup: binding.linkedGroup,
  });
}

function linkedPlans(): {
  parent: ProviderPsbtPlanV3;
  settlement: ProviderPsbtPlanV3;
  recovery: ProviderPsbtPlanV3;
  preparation: PreparedProviderPsbtGroupInputsV1;
} {
  const parent = makePlan({
    planId: 'parent-plan', txid: '11'.repeat(32), inputKeyIndex: 0, inputAmount: 100_000n,
    outputKeyIndex: 1, outputAmount: 99_000n, outputOwned: true, marketplace: true,
  });
  const parentTxid = providerPsbtUnsignedTxid(parent);
  const settlement = makePlan({
    planId: 'settlement-plan', txid: parentTxid, inputKeyIndex: 1, inputAmount: 99_000n,
    outputKeyIndex: 3, outputAmount: 98_000n, outputOwned: false, marketplace: true,
  });
  const recovery = makePlan({
    planId: 'recovery-plan', txid: parentTxid, inputKeyIndex: 1, inputAmount: 99_000n,
    outputKeyIndex: 2, outputAmount: 97_500n, outputOwned: true, marketplace: true,
  });
  const request = [
    { nodeId: 'settlement', plan: settlement, address: addresses[1]!.address },
    { nodeId: 'parent', plan: parent, address: addresses[0]!.address },
    { nodeId: 'recovery', plan: recovery, address: addresses[1]!.address },
  ].map(({ nodeId, plan, address }) => ({
    nodeId,
    psbtBase64: bytesToBase64(hexToBytes(plan.psbtHex)),
    selectedInputIndexes: plan.selectedInputIndexes!,
    inputsToSign: [{ address, signingIndexes: plan.selectedInputIndexes! }],
    ...(plan.marketplace ? { marketplace: {
      context: plan.marketplace.context,
      resolution: plan.marketplace.resolution,
    } } : {}),
  }));
  const root = parent.inputs[0]!;
  const preparation = prepareProviderPsbtGroupInputs({
    groupId: 'group-1',
    items: request,
    externalClassifications: [{
      txid: root.txid,
      vout: root.vout,
      valueSats: root.valueSats.toString(),
      scriptPubKey: root.scriptPubKey,
      confirmations: 10,
      ...root.classification,
    }],
    source,
    walletControl: {
      network: 'mainnet', origin: binding.origin, accountId: publicAccount.accountId, account: 0,
      candidates: addresses.map((address, index) => ({ address: address.address, derivation: derivation(index) })),
    },
  });
  return {
    parent: rebindLinkedPlan(parent, 'parent', preparation),
    settlement: rebindLinkedPlan(settlement, 'settlement', preparation),
    recovery: rebindLinkedPlan(recovery, 'recovery', preparation),
    preparation,
  };
}

function createLinked() {
  const plans = linkedPlans();
  return createProviderPsbtGroupPlan({
    items: [
      { nodeId: 'settlement', plan: plans.settlement,
        inputsToSign: [{ address: addresses[1]!.address, signingIndexes: [0] }] },
      { nodeId: 'parent', plan: plans.parent,
        inputsToSign: [{ address: addresses[0]!.address, signingIndexes: [0] }] },
      { nodeId: 'recovery', plan: plans.recovery,
        inputsToSign: [{ address: addresses[1]!.address, signingIndexes: [0] }] },
    ],
    groupId: 'group-1',
    now: NOW,
    approvalGeneration: 7,
    preparation: plans.preparation,
  });
}

function contextlessOrdListingGroup(): ReturnType<typeof createProviderPsbtGroupPlan> {
  const sales = [0, 1].map((index) => {
    const seller = ordinalAddresses[index]!.publicKeyHex.slice(2);
    const leaf = p2tr_ns(2, [hexToBytes(seller), hexToBytes(ORDNET_SALE_PUBLIC_KEY)])[0]!;
    return p2tr(hexToBytes(seller), { script: leaf.script }, NETWORK, true);
  });
  const parent = new Transaction({ lowR: true });
  for (let index = 0; index < 2; index += 1) {
    parent.addInput({
      txid: (index + 1).toString(16).padStart(64, '0'),
      index: 0,
      sequence: 0xfffffffd,
      sighashType: SigHash.DEFAULT,
      witnessUtxo: { amount: 10_000n, script: hexToBytes(ordinalScripts[index]!) },
      tapInternalKey: hexToBytes(ordinalAddresses[index]!.publicKeyHex.slice(2)),
    });
    parent.addOutput({ amount: 10_000n, script: sales[index]!.script });
  }
  const parentPsbt = bytesToBase64(parent.toPSBT());
  const parentTxid = deriveLinkedProviderPsbtGroup([{
    nodeId: 'parent', psbtBase64: parentPsbt, selectedInputIndexes: [0, 1],
  }]).nodes[0]!.unsignedTxid;

  const settlement = new Transaction({ lowR: true });
  const recovery = new Transaction({ lowR: true });
  for (let index = 0; index < 2; index += 1) {
    const sale = sales[index]!;
    settlement.addInput({
      txid: parentTxid,
      index,
      sequence: 0xfffffffd,
      sighashType: SigHash.SINGLE_ANYONECANPAY,
      witnessUtxo: { amount: 10_000n, script: sale.script },
      tapInternalKey: sale.tapInternalKey,
      tapMerkleRoot: sale.tapMerkleRoot,
      tapLeafScript: sale.tapLeafScript!,
    });
    settlement.addOutput({ amount: 20_000n, script: hexToBytes(scripts[index + 2]!) });
    recovery.addInput({
      txid: parentTxid,
      index,
      sequence: 0xfffffffd,
      sighashType: SigHash.ALL_ANYONECANPAY,
      witnessUtxo: { amount: 10_000n, script: sale.script },
      tapInternalKey: sale.tapInternalKey,
      tapMerkleRoot: sale.tapMerkleRoot,
    });
    recovery.addOutput({ amount: 9_000n, script: hexToBytes(ordinalScripts[index + 2]!) });
  }
  const rawItems = [
    { nodeId: 'settlement', psbtBase64: bytesToBase64(settlement.toPSBT()), selectedInputIndexes: [0, 1],
      inputsToSign: [0, 1].map((index) => ({
        address: ordinalAddresses[index]!.address,
        signingIndexes: [index],
        sigHash: 131 as const,
      })) },
    { nodeId: 'parent', psbtBase64: parentPsbt, selectedInputIndexes: [0, 1],
      inputsToSign: [0, 1].map((index) => ({
        address: ordinalAddresses[index]!.address,
        signingIndexes: [index],
        sigHash: 0 as const,
      })) },
    { nodeId: 'recovery', psbtBase64: bytesToBase64(recovery.toPSBT()), selectedInputIndexes: [0, 1],
      inputsToSign: [0, 1].map((index) => ({
        address: ordinalAddresses[index]!.address,
        signingIndexes: [index],
        sigHash: 129 as const,
      })) },
  ];
  const externalClassifications: UtxoClassification[] = [0, 1].map((index) => ({
    txid: (index + 1).toString(16).padStart(64, '0'),
    vout: 0,
    valueSats: '10000',
    scriptPubKey: ordinalScripts[index]!,
    confirmations: 10,
    primaryClass: 'inscribed',
    inscriptions: [{
      inscriptionId: `${(index + 1).toString(16).padStart(64, '0')}i0`,
      satpoint: `${(index + 1).toString(16).padStart(64, '0')}:0:0`,
    }],
    satRanges: null,
    unsupportedAssetDetected: false,
    confidence: 'authoritative',
    classifiedTip: source.coreTip,
    classificationRevision: source.classificationRevision,
  }));
  const preparation = prepareProviderPsbtGroupInputs({
    groupId: 'contextless-ord-listing',
    items: rawItems,
    externalClassifications,
    source,
    walletControl: {
      network: 'mainnet',
      origin: 'https://ord.net',
      accountId: publicAccount.accountId,
      account: 0,
      candidates: [0, 1].map((index) => ({
        address: ordinalAddresses[index]!.address,
        derivation: ordinalDerivation(index),
      })),
    },
  });
  const plans = rawItems.map((item) => {
    const prepared = providerPsbtLinkedGroupBinding(preparation, item.nodeId);
    const rootWalletInputs = item.nodeId === 'parent' ? [0, 1].map((index) => ({
      outpoint: `${(index + 1).toString(16).padStart(64, '0')}:0`,
      derivation: ordinalDerivation(index),
    })) : [];
    const walletOutputs = item.nodeId === 'settlement'
      ? [0, 1].map((index) => ({
          scriptPubKey: scripts[index + 2]!,
          output: {
            valueSats: 20_000n,
            scriptPubKey: scripts[index + 2]!,
            address: addresses[index + 2]!.address,
            role: 'payment_change' as const,
            derivation: derivation(index + 2),
          },
        }))
      : item.nodeId === 'recovery'
        ? [0, 1].map((index) => ({
            scriptPubKey: ordinalScripts[index + 2]!,
            output: {
              valueSats: 9_000n,
              scriptPubKey: ordinalScripts[index + 2]!,
              address: ordinalAddresses[index + 2]!.address,
              role: 'ordinal_change' as const,
              derivation: ordinalDerivation(index + 2),
            },
          }))
        : [];
    try {
      return bindPreviewPlaceholders(createProviderPsbtPlan({
      psbtBase64: item.psbtBase64,
      binding,
      network: 'mainnet',
      vaultId: 'vault-1',
      sessionId: 'session-1',
      accountId: publicAccount.accountId,
      account: 0,
      classifications: prepared.classifications,
      walletInputs: [...rootWalletInputs, ...prepared.walletInputs],
      walletOutputs,
      ...(item.nodeId === 'parent' ? { protectedSatFlow: [0, 1].map((index) => ({
        inputIndex: index,
        inputOffset: 0n,
        outputIndex: index,
        outputOffset: 0n,
        inscriptionId: externalClassifications[index]!.inscriptions[0]!.inscriptionId,
      })) } : {}),
      source,
      broadcast: false,
      selectedInputIndexes: [0, 1],
      planId: `${item.nodeId}-contextless-plan`,
      now: NOW,
        linkedGroup: prepared.linkedGroup,
      }));
    } catch (error) {
      throw new Error(`${item.nodeId}: ${error instanceof Error ? error.message : String(error)}`);
    }
  });
  return createProviderPsbtGroupPlan({
    items: rawItems.map((item, index) => ({
      nodeId: item.nodeId,
      plan: plans[index]!,
      inputsToSign: item.inputsToSign,
    })),
    groupId: 'contextless-ord-listing',
    now: NOW,
    approvalGeneration: 12,
    preparation,
  });
}

describe('provider PSBT group plans', () => {
  it('signs exact zero-fee alternatives sharing one external wallet input and rejects flexible conflicts', () => {
    const first = makePlan({
      planId: 'shared-first', txid: 'ab'.repeat(32), inputKeyIndex: 0, inputAmount: 50_000n,
      outputKeyIndex: 1, outputAmount: 50_000n, outputOwned: true,
    });
    const second = makePlan({
      planId: 'shared-second', txid: 'ab'.repeat(32), inputKeyIndex: 0, inputAmount: 50_000n,
      outputKeyIndex: 2, outputAmount: 50_000n, outputOwned: true,
    });
    const prepare = (plans: ProviderPsbtPlanV3[]) => prepareProviderPsbtGroupInputs({
      groupId: 'shared-external',
      items: plans.map((plan, index) => ({
        nodeId: `offer-${index}`,
        psbtBase64: bytesToBase64(hexToBytes(plan.psbtHex)),
        selectedInputIndexes: [0],
        inputsToSign: [{ address: addresses[0]!.address, signingIndexes: [0] }],
      })),
      externalClassifications: [{
        txid: 'ab'.repeat(32), vout: 0, valueSats: '50000', scriptPubKey: scripts[0]!,
        confirmations: 10, primaryClass: 'cardinal_clean', inscriptions: [], satRanges: [],
        unsupportedAssetDetected: false, confidence: 'authoritative', classifiedTip: source.coreTip,
        classificationRevision: source.classificationRevision,
      }],
      source,
      walletControl: {
        network: 'mainnet', origin: binding.origin, accountId: publicAccount.accountId, account: 0,
        candidates: [{ address: addresses[0]!.address, derivation: derivation(0) }],
      },
    });
    const preparation = prepare([first, second]);
    const rebound = [first, second].map((plan, index) =>
      rebindLinkedPlan(plan, `offer-${index}`, preparation));
    const group = createProviderPsbtGroupPlan({
      items: rebound.map((plan, index) => ({
        nodeId: `offer-${index}`,
        plan,
        inputsToSign: [{ address: addresses[0]!.address, signingIndexes: [0] }],
      })),
      groupId: 'shared-external', now: NOW, approvalGeneration: 3, preparation,
    });
    expect(group.items.every((item) => item.plan.deferredZeroFee)).toBe(true);
    expect(group.approvalSummary).toMatchObject({
      linked: true,
      maximumWalletDebitSats: 0n,
      maximumFeeExposureSats: 0n,
      branchEconomicsExact: true,
      externalConflicts: [{
        outpoints: [`${'ab'.repeat(32)}:0`],
        nodeIds: ['offer-0', 'offer-1'],
      }],
    });

    const flexible = makePlan({
      planId: 'shared-flexible', txid: 'ab'.repeat(32), inputKeyIndex: 0, inputAmount: 50_000n,
      outputKeyIndex: 3, outputAmount: 49_000n, outputOwned: true,
      sighash: SigHash.SINGLE_ANYONECANPAY,
    });
    const unsafePreparation = prepare([first, flexible]);
    const unsafe = [first, flexible].map((plan, index) =>
      rebindLinkedPlan(plan, `offer-${index}`, unsafePreparation));
    expect(() => createProviderPsbtGroupPlan({
      items: unsafe.map((plan, index) => ({ nodeId: `offer-${index}`, plan })),
      groupId: 'shared-external', now: NOW, approvalGeneration: 3, preparation: unsafePreparation,
    })).toThrow(/exact selected wallet conflict/u);

    const inconsistent = makePlan({
      planId: 'shared-inconsistent', txid: 'ab'.repeat(32), inputKeyIndex: 0, inputAmount: 50_001n,
      outputKeyIndex: 3, outputAmount: 49_000n, outputOwned: true,
    });
    expect(() => prepare([first, inconsistent])).toThrow(/differs from its PSBT prevout/u);

    const unselected = [0, 1].map((index) => makePlan({
      planId: `unselected-${index}`,
      txid: (0xc0 + index).toString(16).repeat(64).slice(0, 64),
      inputKeyIndex: 0,
      inputAmount: 50_000n,
      outputKeyIndex: index + 1,
      outputAmount: 50_000n,
      outputOwned: true,
      externalInputAmount: 1_000n,
    }));
    const unselectedItems = unselected.map((plan, index) => ({
      nodeId: `unselected-${index}`,
      psbtBase64: bytesToBase64(hexToBytes(plan.psbtHex)),
      selectedInputIndexes: [0],
      inputsToSign: [{ address: addresses[0]!.address, signingIndexes: [0] }],
    }));
    const unselectedRoots = [...new Map(unselected.flatMap((plan) => plan.inputs).map((input) => [
      `${input.txid}:${input.vout}`,
      {
        txid: input.txid, vout: input.vout, valueSats: input.valueSats.toString(),
        scriptPubKey: input.scriptPubKey, confirmations: 10, ...input.classification,
      } satisfies UtxoClassification,
    ])).values()];
    const unselectedPreparation = prepareProviderPsbtGroupInputs({
      groupId: 'unselected-conflict', items: unselectedItems,
      externalClassifications: unselectedRoots, source,
      walletControl: {
        network: 'mainnet', origin: binding.origin, accountId: publicAccount.accountId, account: 0,
        candidates: [{ address: addresses[0]!.address, derivation: derivation(0) }],
      },
    });
    const unselectedRebound = unselected.map((plan, index) =>
      rebindLinkedPlan(plan, `unselected-${index}`, unselectedPreparation));
    expect(() => createProviderPsbtGroupPlan({
      items: unselectedRebound.map((plan, index) => ({ nodeId: `unselected-${index}`, plan })),
      groupId: 'unselected-conflict', now: NOW, approvalGeneration: 3,
      preparation: unselectedPreparation,
    })).toThrow(/exact selected wallet conflict/u);
  });

  it('proves and atomically signs a contextless two-inscription ord.net settlement and bounded recovery', async () => {
    const group = contextlessOrdListingGroup();
    expect(group.items.find((item) => item.nodeId === 'settlement')?.plan.inputs.map((input) => input.sighash))
      .toEqual([SigHash.SINGLE_ANYONECANPAY, SigHash.SINGLE_ANYONECANPAY]);
    expect(group.items.find((item) => item.nodeId === 'recovery')?.plan.inputs.map((input) => input.sighash))
      .toEqual([SigHash.ALL_ANYONECANPAY, SigHash.ALL_ANYONECANPAY]);
    expect(group.items.find((item) => item.nodeId === 'parent')?.plan.deferredZeroFee).toBe(true);
    expect(group.alternativeProofs).toHaveLength(2);
    expect(group.alternativeProofs.every((proof) =>
      proof.settlements.length === 1 && proof.settlements[0]!.proof === 'pinned_ordnet_sale_control' &&
      proof.recoveryMaximumWalletDebitSats === 2_000n)).toBe(true);
    expect([...new Set(group.alternativeProofs.flatMap((proof) => proof.recoveredInscriptionIds))].sort()).toEqual([
      `${'0'.repeat(63)}1i0`, `${'0'.repeat(63)}2i0`,
    ]);
    expect(group.approvalSummary).toMatchObject({
      linked: true,
      branchEconomicsExact: true,
      alternativeCount: 2,
      marketplaceActions: [],
      maximumWalletDebitSats: 2_000n,
      maximumFeeExposureSats: 2_000n,
    });
    expect(group.approvalSummary.alternativeOutcomes).toHaveLength(1);
    expect(group.approvalSummary.alternativeOutcomes[0]?.outpoints).toHaveLength(2);
    expect(() => assertProviderPsbtGroupPlan(group)).not.toThrow();
    const signed = await signProviderPsbtGroupPlan({
      plan: group,
      seed,
      now: () => NOW + 1,
      random: (length) => new Uint8Array(length).fill(5),
      yieldControl: async () => undefined,
    });
    const signedByNode = new Map(signed.results.map((result) =>
      [result.nodeId, Transaction.fromPSBT(base64ToBytes(result.psbtBase64), { lowR: true })]));
    expect([0, 1].every((index) =>
      signedByNode.get('settlement')?.getInput(index).tapScriptSig?.length === 1)).toBe(true);
    expect([0, 1].every((index) =>
      signedByNode.get('recovery')?.getInput(index).tapKeySig !== undefined)).toBe(true);
    expect([0, 1].every((index) =>
      signedByNode.get('parent')?.getInput(index).tapKeySig !== undefined)).toBe(true);
  });

  it('binds recognized marketplace settlement, linked topology, recovery proof, and compact summary', () => {
    const group = createLinked();
    expect(group.topology.topologicalNodeIds).toEqual(['parent', 'settlement', 'recovery']);
    expect(group.items.map((item) => item.nodeId)).toEqual(['settlement', 'parent', 'recovery']);
    expect(group.alternativeProofs).toEqual([expect.objectContaining({
      settlements: [expect.objectContaining({
        nodeId: 'settlement',
        proof: 'recognized_marketplace_plan',
      })],
      recoveryNodeId: 'recovery',
      recoveryProof: 'committed_wallet_return',
      recoveryWalletInputSats: 99_000n,
      recoveryGuaranteedWalletReturnSats: 97_500n,
      recoveryMaximumWalletDebitSats: 1_500n,
    })]);
    expect(group.approvalSummary).toMatchObject({
      action: 'sign_transaction_group',
      transactionCount: 3,
      linked: true,
      alternativeCount: 1,
      marketplaceActions: ['offer'],
    });
    expect(group.signatureRelease).toBe('all_or_nothing');
    expect(group.aggregate).toMatchObject({ inputs: 3, outputs: 3, selectedInputs: 3 });
    expect(group.aggregate.encodedPsbtChars).toBeGreaterThan(0);
    expect(group.preparation?.externalOutpoints).toEqual([{ txid: '11'.repeat(32), vout: 0 }]);
    expect(group.preparation?.items[0]).toMatchObject({
      nodeId: 'settlement',
      provenance: [expect.objectContaining({ kind: 'linked_output', parentNodeId: 'parent' })],
      walletInputs: [{ outpoint: `${providerPsbtUnsignedTxid(group.items[1]!.plan)}:0` }],
    });
    expect(group.approvalSummary).toMatchObject({
      branchEconomicsExact: true,
      maximumWalletDebitSats: 100_000n,
      maximumFeeExposureSats: 2_500n,
    });
    expect(Object.isFrozen(group)).toBe(true);
    expect(() => assertProviderPsbtGroupPlan(group)).not.toThrow();
  });

  it('binds every callback address, index, and sighash declaration into the group plan', () => {
    const plans = linkedPlans();
    const declaredItems = [
      { nodeId: 'settlement', plan: plans.settlement, address: addresses[1]!.address },
      { nodeId: 'parent', plan: plans.parent, address: addresses[0]!.address },
      { nodeId: 'recovery', plan: plans.recovery, address: addresses[1]!.address },
    ].map(({ nodeId, plan, address }) => ({
      nodeId,
      plan,
      inputsToSign: [{ address, signingIndexes: [0], sigHash: 1 as const }],
    }));
    const group = createProviderPsbtGroupPlan({
      items: declaredItems,
      groupId: 'group-1',
      now: NOW,
      approvalGeneration: 9,
      preparation: plans.preparation,
    });
    expect(group.items.map((item) => item.inputsToSign)).toEqual(
      declaredItems.map((item) => item.inputsToSign),
    );
    expect(() => assertProviderPsbtGroupPlan(group)).not.toThrow();

    const changed = structuredClone(group);
    changed.items[0]!.inputsToSign![0]!.address = addresses[2]!.address;
    expect(() => assertProviderPsbtGroupPlan(changed)).toThrow();
    expect(() => createProviderPsbtGroupPlan({
      items: [{
        ...declaredItems[0]!,
        inputsToSign: [{
          address: addresses[1]!.address,
          signingIndexes: [0],
          sigHash: 129,
        }],
      }],
      groupId: 'bad-sighash-group',
      now: NOW,
      approvalGeneration: 9,
    })).toThrow(/sighash declaration/u);
    expect(() => createProviderPsbtGroupPlan({
      items: [{ ...declaredItems[0]!, inputsToSign: [] }],
      groupId: 'empty-declarations-group',
      now: NOW,
      approvalGeneration: 9,
    })).toThrow(/declarations are invalid/u);
  });

  it('signs in dependency order and releases results only in original request order', async () => {
    const group = createLinked();
    const signed = await signProviderPsbtGroupPlan({
      plan: group,
      seed,
      now: () => NOW + 1,
      random: (length) => new Uint8Array(length).fill(7),
      yieldControl: async () => undefined,
    });
    expect(signed.groupHash).toBe(group.groupHash);
    expect(signed.results.map((item) => item.nodeId)).toEqual(['settlement', 'parent', 'recovery']);
    expect(signed.results.every((item) =>
      Transaction.fromPSBT(base64ToBytes(item.psbtBase64)).getInput(0).partialSig?.length === 1)).toBe(true);

    const retry = await signProviderPsbtGroupPlan({
      plan: group,
      seed,
      now: () => NOW + 1,
      random: (length) => new Uint8Array(length).fill(7),
      yieldControl: async () => undefined,
    });
    expect(retry).toEqual(signed);
    expect(() => signProviderPsbtPlan({
      plan: group.items[0]!.plan,
      seed,
      requestedInputIndexes: [0],
      random: (length) => new Uint8Array(length),
    })).toThrow(/validated group/u);
  });

  it('compares an adapter-labeled expected txid with the actual unsigned transaction', () => {
    const plans = linkedPlans();
    expect(() => createProviderPsbtGroupPlan({
      items: [
        { nodeId: 'settlement', plan: plans.settlement,
          inputsToSign: [{ address: addresses[1]!.address, signingIndexes: [0] }],
          expectedUnsignedTxid: providerPsbtUnsignedTxid(plans.settlement) },
        { nodeId: 'parent', plan: plans.parent,
          inputsToSign: [{ address: addresses[0]!.address, signingIndexes: [0] }],
          expectedUnsignedTxid: providerPsbtUnsignedTxid(plans.parent) },
        { nodeId: 'recovery', plan: plans.recovery,
          inputsToSign: [{ address: addresses[1]!.address, signingIndexes: [0] }],
          expectedUnsignedTxid: providerPsbtUnsignedTxid(plans.recovery) },
      ],
      preparation: plans.preparation,
      groupId: 'group-1', now: NOW, approvalGeneration: 1,
    })).not.toThrow();
    expect(() => createProviderPsbtGroupPlan({
      items: [
        { nodeId: 'settlement', plan: plans.settlement,
          inputsToSign: [{ address: addresses[1]!.address, signingIndexes: [0] }],
          expectedUnsignedTxid: 'ff'.repeat(32) },
        { nodeId: 'parent', plan: plans.parent,
          inputsToSign: [{ address: addresses[0]!.address, signingIndexes: [0] }] },
        { nodeId: 'recovery', plan: plans.recovery,
          inputsToSign: [{ address: addresses[1]!.address, signingIndexes: [0] }] },
      ],
      preparation: plans.preparation,
      groupId: 'group-1', now: NOW, approvalGeneration: 1,
    })).toThrow(/expected transaction id/u);
  });

  it('hash-binds item order, topology, commitments, approval generation, and prepared plans', () => {
    const group = createLinked();
    const candidates = [
      { ...structuredClone(group), approvalGeneration: 8 },
      { ...structuredClone(group), items: structuredClone(group.items).toReversed() },
    ];
    for (const candidate of candidates) {
      expect(() => assertProviderPsbtGroupPlan(candidate)).toThrow(/mutated|preparation evidence/u);
    }
    const topology = structuredClone(group);
    topology.topology.topologicalNodeIds.reverse();
    expect(() => assertProviderPsbtGroupPlan(topology)).toThrow(/mutated/u);
    const commitment = structuredClone(group);
    commitment.topology.nodes[0]!.commitments[0]!.mutableOutputIndexes = [0];
    expect(() => assertProviderPsbtGroupPlan(commitment)).toThrow();
    const prepared = structuredClone(group);
    prepared.items[0]!.plan.outputs[0]!.valueSats += 1n;
    expect(() => assertProviderPsbtGroupPlan(prepared)).toThrow(/mutated/u);
  });

  it('rejects mixed authority/session context and every wallet-broadcast item', () => {
    const first = makePlan({
      planId: 'first', txid: '31'.repeat(32), inputKeyIndex: 0, inputAmount: 50_000n,
      outputKeyIndex: 1, outputAmount: 49_000n, outputOwned: true,
    });
    for (const different of [
      makePlan({
        planId: 'session', txid: '32'.repeat(32), inputKeyIndex: 0, inputAmount: 50_000n,
        outputKeyIndex: 1, outputAmount: 49_000n, outputOwned: true, sessionId: 'session-2',
      }),
      makePlan({
        planId: 'origin', txid: '33'.repeat(32), inputKeyIndex: 0, inputAmount: 50_000n,
        outputKeyIndex: 1, outputAmount: 49_000n, outputOwned: true, origin: 'https://www.ord.net',
      }),
    ]) {
      expect(() => createProviderPsbtGroupPlan({
        items: [{ nodeId: 'first', plan: first }, { nodeId: 'different', plan: different }],
        groupId: 'mixed', now: NOW, approvalGeneration: 1,
      })).toThrow(/context/u);
    }
    const broadcast = makePlan({
      planId: 'broadcast', txid: '34'.repeat(32), inputKeyIndex: 0, inputAmount: 50_000n,
      outputKeyIndex: 1, outputAmount: 49_000n, outputOwned: true, broadcast: true,
    });
    expect(() => createProviderPsbtGroupPlan({
      items: [{ nodeId: 'broadcast', plan: broadcast }],
      groupId: 'broadcast-group', now: NOW, approvalGeneration: 1,
    })).toThrow(/may broadcast/u);

    const unrelatedMethod = makePlan({
      planId: 'unrelated-method', txid: '37'.repeat(32), inputKeyIndex: 0, inputAmount: 50_000n,
      outputKeyIndex: 1, outputAmount: 49_000n, outputOwned: true, providerMethod: 'signPsbt',
    });
    expect(() => createProviderPsbtGroupPlan({
      items: [{ nodeId: 'unrelated-method', plan: unrelatedMethod }],
      groupId: 'unrelated-method', now: NOW, approvalGeneration: 1,
    })).toThrow();

    const marketOne = makePlan({
      planId: 'market-one', txid: '35'.repeat(32), inputKeyIndex: 0, inputAmount: 50_000n,
      outputKeyIndex: 1, outputAmount: 49_000n, outputOwned: false, marketplace: true,
    });
    const marketTwo = makePlan({
      planId: 'market-two', txid: '36'.repeat(32), inputKeyIndex: 0, inputAmount: 50_000n,
      outputKeyIndex: 1, outputAmount: 49_000n, outputOwned: false, marketplace: true,
      workflowId: 'workflow-2',
    });
    expect(() => createProviderPsbtGroupPlan({
      items: [{ nodeId: 'market-one', plan: marketOne }, { nodeId: 'market-two', plan: marketTwo }],
      groupId: 'mixed-workflow', now: NOW, approvalGeneration: 1,
    })).toThrow(/marketplace workflow differs/u);

    const linked = linkedPlans();
    const contextlessSettlement = rebindLinkedPlan(linked.settlement, 'settlement', linked.preparation, false);
    expect(() => createProviderPsbtGroupPlan({
      items: [
        { nodeId: 'settlement', plan: contextlessSettlement,
          inputsToSign: [{ address: addresses[1]!.address, signingIndexes: [0] }] },
        { nodeId: 'parent', plan: linked.parent,
          inputsToSign: [{ address: addresses[0]!.address, signingIndexes: [0] }] },
        { nodeId: 'recovery', plan: linked.recovery,
          inputsToSign: [{ address: addresses[1]!.address, signingIndexes: [0] }] },
      ],
      preparation: linked.preparation,
      groupId: 'group-1', now: NOW, approvalGeneration: 1,
    })).toThrow(/mix recognized and contextless/u);
  });

  it('fails alternatives that were not constructed from one complete preparation', () => {
    const { parent, settlement } = linkedPlans();
    const unsafeRecovery = makePlan({
      planId: 'unsafe-recovery', txid: providerPsbtUnsignedTxid(parent), inputKeyIndex: 1,
      inputAmount: 99_000n, outputKeyIndex: 2, outputAmount: 97_500n, outputOwned: false,
    });
    expect(() => createProviderPsbtGroupPlan({
      items: [
        { nodeId: 'parent', plan: parent },
        { nodeId: 'settlement', plan: settlement },
        { nodeId: 'unsafe-recovery', plan: unsafeRecovery },
      ],
      groupId: 'unsafe-alternative', now: NOW, approvalGeneration: 1,
    })).toThrow(/preparation|mix recognized/u);

    const externallyBlockedRecovery = makePlan({
      planId: 'externally-blocked-recovery', txid: providerPsbtUnsignedTxid(parent), inputKeyIndex: 1,
      inputAmount: 99_000n, outputKeyIndex: 2, outputAmount: 97_500n, outputOwned: true,
      externalInputAmount: 1_000n,
    });
    expect(() => createProviderPsbtGroupPlan({
      items: [
        { nodeId: 'parent', plan: parent },
        { nodeId: 'settlement', plan: settlement },
        { nodeId: 'externally-blocked-recovery', plan: externallyBlockedRecovery },
      ],
      groupId: 'externally-blocked-recovery', now: NOW, approvalGeneration: 1,
    })).toThrow(/preparation|mix recognized/u);

    const genericSettlement = makePlan({
      planId: 'generic-settlement', txid: providerPsbtUnsignedTxid(parent), inputKeyIndex: 1,
      inputAmount: 99_000n, outputKeyIndex: 3, outputAmount: 98_000n, outputOwned: false,
    });
    expect(() => createProviderPsbtGroupPlan({
      items: [
        { nodeId: 'parent', plan: parent },
        { nodeId: 'generic-settlement', plan: genericSettlement },
        { nodeId: 'unsafe-recovery', plan: unsafeRecovery },
      ],
      groupId: 'unrecognized-settlement', now: NOW, approvalGeneration: 1,
    })).toThrow(/preparation|mix recognized/u);
  });

  it('expires or cancels without releasing a partial result, including after all signing work', async () => {
    const group = createLinked();
    await expect(signProviderPsbtGroupPlan({
      plan: group,
      seed,
      now: () => group.expiresAt,
      random: (length) => new Uint8Array(length),
      yieldControl: async () => undefined,
    })).rejects.toThrow(/expired/u);

    for (const failAt of [1, 2, 4]) {
      let guardCalls = 0;
      let released = false;
      try {
        await signProviderPsbtGroupPlan({
          plan: group,
          seed,
          now: () => NOW + 1,
          random: (length) => new Uint8Array(length),
          yieldControl: async () => undefined,
          guard: () => {
            guardCalls += 1;
            if (guardCalls === failAt) throw new Error('cancelled group');
          },
        });
        released = true;
      } catch (error) {
        expect(error).toMatchObject({ message: 'cancelled group' });
      }
      expect(released).toBe(false);
      expect(guardCalls).toBe(failAt);
    }

    const wrongSeed = mnemonicToSeed(
      'legal winner thank year wave sausage worth useful legal winner thank yellow',
    );
    let releasedAfterSignFailure = false;
    try {
      await signProviderPsbtGroupPlan({
        plan: group,
        seed: wrongSeed,
        now: () => NOW + 1,
        random: (length) => new Uint8Array(length),
        yieldControl: async () => undefined,
      });
      releasedAfterSignFailure = true;
    } catch (error) {
      expect(error).toMatchObject({ message: expect.stringMatching(/public account/u) });
    }
    expect(releasedAfterSignFailure).toBe(false);

    let yieldCalls = 0;
    let releasedAfterInternalFailure = false;
    try {
      await signProviderPsbtGroupPlan({
        plan: group,
        seed,
        now: () => NOW + 1,
        random: (length) => new Uint8Array(length),
        yieldControl: async () => {
          yieldCalls += 1;
          if (yieldCalls === 2) throw new Error('internal signing interruption');
        },
      });
      releasedAfterInternalFailure = true;
    } catch (error) {
      expect(error).toMatchObject({ message: 'internal signing interruption' });
    }
    expect(releasedAfterInternalFailure).toBe(false);

    for (const expireAfterYield of [1, 4]) {
      let now = NOW + 1;
      let yieldCalls = 0;
      let released = false;
      try {
        await signProviderPsbtGroupPlan({
          plan: group,
          seed,
          now: () => now,
          random: (length) => new Uint8Array(length),
          yieldControl: async () => {
            yieldCalls += 1;
            if (yieldCalls === expireAfterYield) now = group.expiresAt;
          },
        });
        released = true;
      } catch (error) {
        expect(error).toMatchObject({ message: 'provider group plan expired' });
      }
      expect(released).toBe(false);
      expect(yieldCalls).toBe(expireAfterYield);
    }
  });
});
