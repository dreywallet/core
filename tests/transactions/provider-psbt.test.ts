import { beforeAll, describe, expect, it } from 'vitest';
import { SigHash, Transaction } from '@scure/btc-signer';
import { mnemonicToSeed } from '../../src/domain/keys/mnemonic';
import { deriveAccountNode, deriveAddress } from '../../src/domain/keys/derivation';
import { scriptPubKeyHex } from '../../src/domain/keys/script-hash';
import { base64ToBytes, bytesToBase64, bytesToHex, hexToBytes } from '../../src/domain/vault/encoding';
import { installTestCryptoProvider } from '../helpers/install-crypto-provider';
import {
  bindProviderPsbtPlanPreviews,
  assertProviderPsbtPlan,
  createProviderPsbtPlan,
  partitionOrdinalSatFlow,
  providerPsbtPlanPreviews,
  providerPsbtOutpoints,
  signProviderPsbtPlan,
} from '../../src/domain/transactions/provider-psbt';
import type { ProviderPsbtPlanV3 } from '../../src/domain/transactions/provider-psbt';
import type { UtxoClassification } from '../../src/domain/gateway/contract';
import { publicAccountFromSeed } from '../../src/domain/accounts/public-account';
import { PROVIDER_MAX_PSBT_INPUTS } from '../../src/domain/transactions/provider-psbt-limits';
import type { InscriptionPreviewSet } from '../../src/domain/transactions/inscription-previews';

beforeAll(() => installTestCryptoProvider());

const seed = mnemonicToSeed('abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about');
const accountId = publicAccountFromSeed(seed, 'signet', 0).accountId;
const source = {
  backend: 'https://gateway.example', instanceId: 'gateway-1', classificationRevision: 'rev-1',
  coreTip: { height: 100, hash: 'aa'.repeat(32) }, indexTip: { height: 100, hash: 'aa'.repeat(32) },
  feeQuoteTimestamp: null, mempoolState: null,
};
const binding = {
  origin: 'https://app.example', tabId: 1, frameId: 0,
  documentId: '123e4567-e89b-42d3-a456-426614174000',
  requestNonce: '123e4567-e89b-42d3-a456-426614174001', providerMethod: 'signPsbt' as const,
};

it.each([SigHash.DEFAULT, SigHash.ALL])('finalizes a Taproot key-path transaction at sighash %s within its size bound', (sighash) => {
  const root = deriveAccountNode(seed, 'ordinals', 'signet', 0);
  const wallet = deriveAddress(root, 'ordinals', 'signet', 0, 0);
  const destination = deriveAddress(root, 'ordinals', 'signet', 0, 1);
  root.wipePrivateData();
  const script = scriptPubKeyHex(wallet.publicKeyHex, 'ordinals', 'signet');
  const tx = new Transaction({ lowR: true });
  tx.addInput({ txid: 'aa'.repeat(32), index: 0, sighashType: sighash,
    witnessUtxo: { script: hexToBytes(script), amount: 50_000n },
    tapInternalKey: hexToBytes(wallet.publicKeyHex.slice(2)),
  });
  tx.addOutput({ script: hexToBytes(scriptPubKeyHex(destination.publicKeyHex, 'ordinals', 'signet')), amount: 49_000n });
  const plan = createProviderPsbtPlan({
    accountId, account: 0, network: 'signet', vaultId: 'vault', sessionId: 'session',
    binding, source, psbtBase64: bytesToBase64(tx.toPSBT()), broadcast: true,
    planId: 'taproot-size', now: 1_800_000_000_000,
    classifications: [{ txid: 'aa'.repeat(32), vout: 0, valueSats: '50000', scriptPubKey: script,
      confirmations: 10, primaryClass: 'cardinal_clean', inscriptions: [], satRanges: null,
      unsupportedAssetDetected: false, confidence: 'authoritative', classifiedTip: source.coreTip,
      classificationRevision: source.classificationRevision }],
    walletInputs: [{ outpoint: `${'aa'.repeat(32)}:0`, derivation: {
      accountId, account: 0, lane: 'ordinals', chain: 0, index: 0,
      path: wallet.path, publicKeyHex: wallet.publicKeyHex,
    } }],
  });
  const signed = signProviderPsbtPlan({ plan, seed, random: (length) => new Uint8Array(length).fill(7) });
  const finalized = Transaction.fromRaw(hexToBytes(signed.transactionHex!));
  expect(plan.vsize).toBe(BigInt(finalized.vsize));
  expect(finalized.getInput(0).finalScriptWitness?.[0]?.length).toBe(sighash === 0 ? 64 : 65);
  expect(plan.vsize).toBe(sighash === 0 ? 111n : 112n);
});

it('rejects a provider PSBT with too many inputs before outpoint analysis', () => {
  const tx = new Transaction({ lowR: true });
  const script = Uint8Array.from([0x00, 0x14, ...new Uint8Array(20)]);
  for (let index = 0; index <= PROVIDER_MAX_PSBT_INPUTS; index += 1) {
    tx.addInput({
      txid: index.toString(16).padStart(64, '0'),
      index: 0,
      witnessUtxo: { script, amount: 1n },
    });
  }
  tx.addOutput({ script, amount: 1n });
  expect(() => providerPsbtOutpoints(bytesToBase64(tx.toPSBT())))
    .toThrow(`PSBT input count exceeds ${PROVIDER_MAX_PSBT_INPUTS}`);
});

function testPlaceholders(plan: ProviderPsbtPlanV3): InscriptionPreviewSet {
  return {
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
        confirmations: 10,
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
  };
}

function bindTestPlaceholders(plan: ProviderPsbtPlanV3): ProviderPsbtPlanV3 {
  return bindProviderPsbtPlanPreviews(plan, testPlaceholders(plan));
}

function fixture(primaryClass: UtxoClassification['primaryClass'] = 'cardinal_clean') {
  const account = deriveAccountNode(seed, 'payment', 'signet', 0);
  const wallet = deriveAddress(account, 'payment', 'signet', 0, 0);
  const recipient = deriveAddress(account, 'payment', 'signet', 0, 1);
  account.wipePrivateData();
  const walletScript = scriptPubKeyHex(wallet.publicKeyHex, 'payment', 'signet');
  const foreignKey = `02${'33'.repeat(32)}`;
  const foreignScript = scriptPubKeyHex(foreignKey, 'payment', 'signet');
  const outputScript = scriptPubKeyHex(recipient.publicKeyHex, 'payment', 'signet');
  const tx = new Transaction({ lowR: true });
  tx.addInput({ txid: '22'.repeat(32), index: 1, sequence: 0xffffffff,
    witnessUtxo: { script: Uint8Array.from(Buffer.from(foreignScript, 'hex')), amount: 30_000n } });
  tx.addInput({ txid: '11'.repeat(32), index: 0, sequence: 0xfffffffd,
    witnessUtxo: { script: Uint8Array.from(Buffer.from(walletScript, 'hex')), amount: 50_000n } });
  tx.addOutput({ script: Uint8Array.from(Buffer.from(outputScript, 'hex')), amount: 78_000n });
  const classification = (
    txid: string, vout: number, valueSats: string, scriptPubKey: string, kind: UtxoClassification['primaryClass'],
  ): UtxoClassification => ({
    txid, vout, valueSats, scriptPubKey, confirmations: 10, primaryClass: kind,
    inscriptions: kind === 'inscribed' ? [{ inscriptionId: `${txid}i0`, satpoint: `${txid}:${vout}:0` }] : [],
    satRanges: null, unsupportedAssetDetected: false, confidence: 'authoritative',
    classifiedTip: source.coreTip, classificationRevision: source.classificationRevision,
  });
  return {
    accountId,
    psbtBase64: bytesToBase64(tx.toPSBT()),
    classifications: [
      classification('22'.repeat(32), 1, '30000', foreignScript, primaryClass),
      classification('11'.repeat(32), 0, '50000', walletScript, 'cardinal_clean'),
    ],
    outputScript,
    walletAddress: wallet.address,
    recipientAddress: recipient.address,
    walletInputs: [{
      outpoint: `${'11'.repeat(32)}:0`,
      derivation: { accountId, account: 0, lane: 'payment' as const, chain: 0 as const, index: 0,
        path: wallet.path, publicKeyHex: wallet.publicKeyHex },
    }],
  };
}

function createFixturePlan(
  value: ReturnType<typeof fixture>,
  overrides: Partial<Parameters<typeof createProviderPsbtPlan>[0]> = {},
) {
  return createProviderPsbtPlan({
    ...value,
    binding,
    network: 'signet',
    vaultId: 'vault-1',
    sessionId: binding.requestNonce,
    account: 0,
    source,
    broadcast: false,
    planId: 'provider-policy-fixture',
    now: 1_800_000_000_000,
    ...overrides,
  });
}

describe('provider PSBT analysis binding', () => {
  it('allows only fully committed non-broadcast zero-fee requests with every wallet input selected', () => {
    const f = fixture();
    const zeroFeePsbt = (outputAmount: bigint, sighash = SigHash.ALL): string => {
      const tx = Transaction.fromPSBT(base64ToBytes(f.psbtBase64), { lowR: true });
      tx.updateInput(1, { sighashType: sighash }, true);
      tx.updateOutput(0, { amount: outputAmount }, true);
      return bytesToBase64(tx.toPSBT());
    };
    const batchBinding = { ...binding, providerMethod: 'signMultipleTransactions' as const };
    const plan = createFixturePlan(f, {
      psbtBase64: zeroFeePsbt(80_000n),
      binding: batchBinding,
      selectedInputIndexes: [1],
    });
    expect(plan.deferredZeroFee).toBe(true);
    expect(plan.feeSats).toBe(0n);
    expect(plan.analysis.hardViolations).toEqual([]);
    const mutated = structuredClone(plan);
    mutated.deferredZeroFee = false;
    expect(() => assertProviderPsbtPlan(mutated)).toThrow(/mutated/u);

    const singlePlan = createFixturePlan(f, {
      psbtBase64: zeroFeePsbt(80_000n), selectedInputIndexes: [1],
    });
    expect(singlePlan.deferredZeroFee).toBe(true);
    const signedSingle = signProviderPsbtPlan({
      plan: singlePlan,
      seed,
      requestedInputIndexes: [1],
      random: (length) => new Uint8Array(length).fill(9),
    });
    const signedSinglePsbt = Transaction.fromPSBT(base64ToBytes(signedSingle.psbtBase64), { lowR: true });
    expect(signedSinglePsbt.getInput(0).partialSig).toBeUndefined();
    expect(signedSinglePsbt.getInput(1).partialSig).toHaveLength(1);
    expect(signedSinglePsbt.getOutput(0).amount).toBe(80_000n);
    expect(() => createFixturePlan(f, {
      psbtBase64: zeroFeePsbt(80_000n), binding: batchBinding, selectedInputIndexes: [1], broadcast: true,
    })).toThrow(/fee is not positive/u);
    expect(() => createFixturePlan(f, {
      psbtBase64: zeroFeePsbt(80_000n, SigHash.ALL_ANYONECANPAY),
      binding: batchBinding, selectedInputIndexes: [1],
    })).toThrow(/fee is not positive/u);
    expect(() => createFixturePlan(f, {
      psbtBase64: zeroFeePsbt(80_001n), binding: batchBinding, selectedInputIndexes: [1],
    })).toThrow(/fee is not positive/u);

    const hiddenWallet = structuredClone(f);
    const hiddenTx = Transaction.fromPSBT(base64ToBytes(f.psbtBase64), { lowR: true });
    hiddenTx.updateInput(0, {
      witnessUtxo: {
        amount: 30_000n,
        script: hexToBytes(hiddenWallet.classifications[1]!.scriptPubKey),
      },
    }, true);
    hiddenTx.updateInput(1, { sighashType: SigHash.ALL }, true);
    hiddenTx.updateOutput(0, { amount: 80_000n }, true);
    hiddenWallet.psbtBase64 = bytesToBase64(hiddenTx.toPSBT());
    hiddenWallet.classifications[0]!.scriptPubKey = hiddenWallet.classifications[1]!.scriptPubKey;
    hiddenWallet.walletInputs.push({
      outpoint: `${'22'.repeat(32)}:1`,
      derivation: { ...hiddenWallet.walletInputs[0]!.derivation },
    });
    expect(() => createFixturePlan(hiddenWallet, {
      binding: batchBinding, selectedInputIndexes: [1],
    })).toThrow(/fee is not positive/u);
  });

  it('partitions co-located inscriptions by FIFO position and rejects inseparable postage', () => {
    expect(partitionOrdinalSatFlow(50_000n, [
      { inscriptionId: 'other', inputOffset: 0n, minimumOutputSats: 330n, target: false },
      { inscriptionId: 'target', inputOffset: 20_000n, minimumOutputSats: 10_000n, target: true },
    ])).toEqual([
      { inscriptionId: 'other', inputOffset: 0n, outputOffset: 0n, valueSats: 330n, target: false },
      { inscriptionId: 'target', inputOffset: 20_000n, outputOffset: 19_670n, valueSats: 49_670n, target: true },
    ]);
    expect(() => partitionOrdinalSatFlow(50_000n, [
      { inscriptionId: 'target', inputOffset: 0n, minimumOutputSats: 10_000n, target: true },
      { inscriptionId: 'other', inputOffset: 5_000n, minimumOutputSats: 330n, target: false },
    ])).toThrow(/partitioned safely/u);
    expect(() => partitionOrdinalSatFlow(50_000n, [
      { inscriptionId: 'target', inputOffset: 1n, minimumOutputSats: 10_000n, target: true },
      { inscriptionId: 'other', inputOffset: 1n, minimumOutputSats: 330n, target: false },
    ])).toThrow(/partitioned safely/u);
  });

  it('analyzes foreign inputs but signs only the active-account input', () => {
    const f = fixture();
    const plan = bindTestPlaceholders(createProviderPsbtPlan({
      ...f, binding, network: 'signet', vaultId: 'vault-1', sessionId: binding.requestNonce,
      account: 0, source, broadcast: false,
      planId: 'plan-1', now: 1_800_000_000_000,
    }));
    expect(plan.inputs.map((item) => item.ownership)).toEqual(['external', 'wallet']);
    expect(plan.analysis.hardViolations).toEqual([]);
    const signed = signProviderPsbtPlan({ plan, seed, random: (length) => new Uint8Array(length).fill(7) });
    const parsed = Transaction.fromPSBT(Uint8Array.from(Buffer.from(signed.psbtBase64, 'base64')));
    expect(parsed.getInput(0).partialSig).toBeUndefined();
    expect(parsed.getInput(1).partialSig).toHaveLength(1);
    expect(signed.transactionHex).toBeUndefined();
  });

  it('signs a §21.1 generic listing and refuses value-losing or misdirected variants', () => {
    const ordinalAccount = deriveAccountNode(seed, 'ordinals', 'signet', 0);
    const ordinal = deriveAddress(ordinalAccount, 'ordinals', 'signet', 0, 0);
    ordinalAccount.wipePrivateData();
    const paymentAccount = deriveAccountNode(seed, 'payment', 'signet', 0);
    const payment = deriveAddress(paymentAccount, 'payment', 'signet', 0, 0);
    paymentAccount.wipePrivateData();
    const ordinalScript = scriptPubKeyHex(ordinal.publicKeyHex, 'ordinals', 'signet');
    const paymentScript = scriptPubKeyHex(payment.publicKeyHex, 'payment', 'signet');
    const foreignScript = scriptPubKeyHex(`02${'33'.repeat(32)}`, 'payment', 'signet');
    const listingPsbt = (payoutSats: bigint, payoutScript: string): string => {
      const tx = new Transaction({ lowR: true, allowUnknownInputs: true });
      tx.addInput({
        txid: '44'.repeat(32), index: 0, sequence: 0xffffffff,
        sighashType: SigHash.SINGLE_ANYONECANPAY,
        witnessUtxo: { script: Uint8Array.from(Buffer.from(ordinalScript, 'hex')), amount: 10_000n },
        tapInternalKey: Uint8Array.from(Buffer.from(ordinal.publicKeyHex.slice(2), 'hex')),
      });
      tx.addOutput({ script: Uint8Array.from(Buffer.from(payoutScript, 'hex')), amount: payoutSats });
      return bytesToBase64(tx.toPSBT());
    };
    const classifications: UtxoClassification[] = [{
      txid: '44'.repeat(32), vout: 0, valueSats: '10000', scriptPubKey: ordinalScript,
      confirmations: 10, primaryClass: 'inscribed',
      inscriptions: [{ inscriptionId: `${'44'.repeat(32)}i0`, satpoint: `${'44'.repeat(32)}:0:0` }],
      satRanges: null, unsupportedAssetDetected: false, confidence: 'authoritative',
      classifiedTip: source.coreTip, classificationRevision: source.classificationRevision,
    }];
    const walletInputs = [{
      outpoint: `${'44'.repeat(32)}:0`,
      derivation: { accountId, account: 0, lane: 'ordinals' as const, chain: 0 as const, index: 0,
        path: ordinal.path, publicKeyHex: ordinal.publicKeyHex },
    }];
    const walletOutputs = [{
      scriptPubKey: paymentScript,
      output: {
        valueSats: 0n, scriptPubKey: paymentScript, address: payment.address,
        role: 'payment_change' as const,
        derivation: { accountId, account: 0, lane: 'payment' as const, chain: 0 as const, index: 0,
          path: payment.path, publicKeyHex: payment.publicKeyHex },
      },
    }];
    const create = (psbtBase64: string, broadcast = false) => createProviderPsbtPlan({
      psbtBase64, binding, network: 'signet', vaultId: 'vault-1', sessionId: 'session-1',
      accountId, account: 0, classifications, walletInputs, source, broadcast,
      planId: '123e4567-e89b-42d3-a456-426614174002', now: 1_700_000_000_000,
      walletOutputs, selectedInputIndexes: [0],
    });
    expect(() => create(listingPsbt(500_000n, paymentScript), true))
      .toThrow(/generic listing may not request wallet broadcast/u);
    const unboundPlan = create(listingPsbt(500_000n, paymentScript));
    const previews = testPlaceholders(unboundPlan);
    const plan = bindProviderPsbtPlanPreviews(unboundPlan, previews);
    previews.items[0]!.metadata.number = 42;
    expect(providerPsbtPlanPreviews(plan).items[0]!.metadata.number).toBeNull();
    const returned = providerPsbtPlanPreviews(plan);
    returned.items[0]!.metadata.number = 43;
    expect(providerPsbtPlanPreviews(plan).items[0]!.metadata.number).toBeNull();
    // A proven listing is one-click: no Advanced ceremony, no wallet fee exposure.
    expect(plan.requiresAdvanced).toBe(false);
    expect(plan.feeSats).toBe(0n);
    expect(plan.analysis.hardViolations).toEqual([]);
    const signed = signProviderPsbtPlan({
      plan, seed, requestedInputIndexes: [0], random: (length) => new Uint8Array(length).fill(7),
    });
    const reparsed = Transaction.fromPSBT(Uint8Array.from(Buffer.from(signed.psbtBase64, 'base64')));
    expect(reparsed.getInput(0).tapKeySig).toBeDefined();
    expect(reparsed.getInput(0).sighashType).toBe(SigHash.SINGLE_ANYONECANPAY);
    // Payout below the listed input value is a hard failure, not a warning.
    expect(() => create(listingPsbt(5_000n, paymentScript)))
      .toThrow(/payout is below the listed input value/u);
    // Payout to any script the wallet does not own is a hard failure.
    expect(() => create(listingPsbt(500_000n, foreignScript)))
      .toThrow(/must return to the active account/u);
  });

  it('accepts a zero-value OP_RETURN output and rejects a material one', () => {
    const f = fixture();
    const tx = Transaction.fromPSBT(
      Uint8Array.from(Buffer.from(f.psbtBase64, 'base64')),
      { allowUnknownOutputs: true },
    );
    tx.addOutput({
      script: Uint8Array.from(Buffer.from('6a04deadbeef', 'hex')),
      amount: 0n,
    });

    const plan = createProviderPsbtPlan({
      ...f,
      psbtBase64: bytesToBase64(tx.toPSBT()),
      binding,
      network: 'signet',
      vaultId: 'vault-1',
      sessionId: binding.requestNonce,
      account: 0,
      source,
      broadcast: false,
      planId: 'op-return-output',
      now: 1_800_000_000_000,
    });
    expect(plan.outputs.at(-1)).toMatchObject({
      address: null,
      role: 'data',
      scriptType: 'op_return',
      valueSats: 0n,
    });

    const material = Transaction.fromPSBT(tx.toPSBT(), { allowUnknownOutputs: true });
    material.updateOutput(material.outputsLength - 1, { amount: 1n });
    expect(() => createProviderPsbtPlan({
      ...f,
      psbtBase64: bytesToBase64(material.toPSBT()),
      binding,
      network: 'signet',
      vaultId: 'vault-1',
      sessionId: binding.requestNonce,
      account: 0,
      source,
      broadcast: false,
      planId: 'material-op-return-output',
      now: 1_800_000_000_000,
    })).toThrow(/OP_RETURN output must have zero value/u);
  });

  it('allows safe flexible sighashes and explains exactly what remains changeable', () => {
    const f = fixture();
    const singleTx = Transaction.fromPSBT(Uint8Array.from(Buffer.from(f.psbtBase64, 'base64')));
    singleTx.updateInput(1, { sighashType: SigHash.SINGLE });
    singleTx.addOutput({ script: Uint8Array.from(Buffer.from(f.outputScript, 'hex')), amount: 1_000n });
    const single = createFixturePlan(f, {
      psbtBase64: bytesToBase64(singleTx.toPSBT()),
      planId: 'single',
    });
    expect(single.approvalExplanation).toMatchObject({
      presentation: 'flexible',
      commitments: { inputs: 'fixed', outputs: 'changeable', fee: 'changeable' },
    });
    expect(single.approvalExplanation?.outputs.map((output) => output.guaranteed)).toEqual([false, true]);
    const singleSigned = signProviderPsbtPlan({
      plan: single,
      seed,
      requestedInputIndexes: [1],
      random: (length) => new Uint8Array(length).fill(7),
    });
    const signedSingle = Transaction.fromPSBT(Uint8Array.from(Buffer.from(singleSigned.psbtBase64, 'base64')));
    expect(signedSingle.getInput(1).partialSig?.[0]?.[1].at(-1)).toBe(SigHash.SINGLE);

    const allAcpTx = Transaction.fromPSBT(Uint8Array.from(Buffer.from(f.psbtBase64, 'base64')));
    allAcpTx.updateInput(1, { sighashType: SigHash.ALL_ANYONECANPAY });
    const allAcp = createFixturePlan(f, {
      psbtBase64: bytesToBase64(allAcpTx.toPSBT()),
      planId: 'all-acp',
    });
    expect(allAcp.approvalExplanation).toMatchObject({
      presentation: 'flexible',
      commitments: { inputs: 'changeable', outputs: 'fixed', fee: 'changeable' },
    });

    const singleAcpTx = Transaction.fromPSBT(singleTx.toPSBT());
    singleAcpTx.updateInput(1, { sighashType: SigHash.SINGLE_ANYONECANPAY });
    const singleAcp = createFixturePlan(f, {
      psbtBase64: bytesToBase64(singleAcpTx.toPSBT()),
      planId: 'single-acp',
    });
    expect(singleAcp.approvalExplanation).toMatchObject({
      presentation: 'flexible',
      commitments: { inputs: 'changeable', outputs: 'changeable', fee: 'changeable' },
    });
  });

  it('hard-blocks destination-free, reserved, and incomplete SINGLE sighashes before signing', () => {
    const f = fixture();
    for (const [sighash, message] of [
      [SigHash.NONE, /does not commit to a destination/u],
      [SigHash.NONE_ANYONECANPAY, /does not commit to a destination/u],
      [SigHash.DEFAULT_ANYONECANPAY, /invalid or reserved sighash/u],
    ] as const) {
      const tx = Transaction.fromPSBT(Uint8Array.from(Buffer.from(f.psbtBase64, 'base64')));
      tx.updateInput(1, { sighashType: sighash });
      expect(() => createFixturePlan(f, {
        psbtBase64: bytesToBase64(tx.toPSBT()),
        planId: `blocked-${sighash}`,
      })).toThrow(message);
    }
    const single = Transaction.fromPSBT(Uint8Array.from(Buffer.from(f.psbtBase64, 'base64')));
    single.updateInput(1, { sighashType: SigHash.SINGLE });
    expect(() => createFixturePlan(f, {
      psbtBase64: bytesToBase64(single.toPSBT()),
      planId: 'blocked-single',
    })).toThrow(/SINGLE without a corresponding output/u);
  });

  it('validates signInputs address-to-index ownership instead of flattening indexes', () => {
    const f = fixture();
    expect(createFixturePlan(f, {
      signInputBindings: [{ address: f.walletAddress, inputIndexes: [1] }],
      planId: 'correct-address-binding',
    }).selectedInputIndexes).toEqual([1]);
    expect(() => createFixturePlan(f, {
      signInputBindings: [{ address: f.recipientAddress, inputIndexes: [1] }],
      planId: 'wrong-address-binding',
    })).toThrow(/address does not own input 1/u);
  });

  it('accepts classified external standard or unknown scripts without claiming a reliable fee rate', () => {
    const f = fixture();
    const scripts = [
      ['p2pkh', `76a914${'44'.repeat(20)}88ac`],
      ['p2sh', `a914${'44'.repeat(20)}87`],
      ['p2wpkh', `0014${'44'.repeat(20)}`],
      ['p2wsh', `0020${'44'.repeat(32)}`],
      ['p2tr', `5120${'44'.repeat(32)}`],
      ['unknown', '51'],
    ] as const;
    for (const [scriptType, scriptPubKey] of scripts) {
      const tx = Transaction.fromPSBT(Uint8Array.from(Buffer.from(f.psbtBase64, 'base64')), {
        allowUnknownInputs: true,
      });
      tx.updateInput(0, {
        witnessUtxo: { script: Uint8Array.from(Buffer.from(scriptPubKey, 'hex')), amount: 30_000n },
      }, true);
      const classifications = structuredClone(f.classifications);
      classifications[0]!.scriptPubKey = scriptPubKey;
      const plan = createFixturePlan(f, {
        psbtBase64: bytesToBase64(tx.toPSBT()),
        classifications,
        planId: `external-${scriptType}`,
      });
      expect(plan.inputs[0]?.scriptType).toBe(scriptType);
      if (scriptType === 'p2wpkh' || scriptType === 'p2tr') {
        expect(plan.vsize).not.toBeNull();
      } else {
        expect(plan.vsize).toBeNull();
        expect(plan.approvalExplanation?.commitments.feeRate).toBe('unavailable');
      }
      expect(signProviderPsbtPlan({
        plan,
        seed,
        requestedInputIndexes: [1],
        random: (length) => new Uint8Array(length).fill(7),
      }).psbtBase64).toBeTruthy();
    }
  });

  it('describes every standard provider output and blocks an unexplained material script', () => {
    const f = fixture();
    const ordinalAccount = deriveAccountNode(seed, 'ordinals', 'signet', 0);
    const taproot = deriveAddress(ordinalAccount, 'ordinals', 'signet', 0, 7);
    ordinalAccount.wipePrivateData();
    const scripts = [
      ['p2pkh', `76a914${'55'.repeat(20)}88ac`],
      ['p2sh', `a914${'55'.repeat(20)}87`],
      ['p2wpkh', `0014${'55'.repeat(20)}`],
      ['p2wsh', `0020${'55'.repeat(32)}`],
      ['p2tr', scriptPubKeyHex(taproot.publicKeyHex, 'ordinals', 'signet')],
    ] as const;
    for (const [scriptType, scriptPubKey] of scripts) {
      const tx = Transaction.fromPSBT(Uint8Array.from(Buffer.from(f.psbtBase64, 'base64')));
      tx.updateOutput(0, { script: Uint8Array.from(Buffer.from(scriptPubKey, 'hex')) });
      expect(createFixturePlan(f, {
        psbtBase64: bytesToBase64(tx.toPSBT()),
        planId: `output-${scriptType}`,
      }).outputs[0]?.scriptType).toBe(scriptType);
    }
    const unknown = Transaction.fromPSBT(Uint8Array.from(Buffer.from(f.psbtBase64, 'base64')), {
      allowUnknownOutputs: true,
    });
    unknown.updateOutput(0, { script: Uint8Array.from([0x51]) }, true);
    expect(() => createFixturePlan(f, {
      psbtBase64: bytesToBase64(unknown.toPSBT()),
      planId: 'unknown-material-output',
    })).toThrow(/cannot be explained safely/u);
  });

  it('preserves PSBTv0/v2 and proprietary fields while adding only the selected signature', () => {
    const f = fixture();
    for (const version of [0, 2] as const) {
      const tx = new Transaction({ lowR: true, PSBTVersion: version });
      for (let index = 0; index < f.classifications.length; index += 1) {
        const classification = f.classifications[index]!;
        tx.addInput({
          txid: classification.txid,
          index: classification.vout,
          sequence: index === 0 ? 0xffffffff : 0xfffffffd,
          witnessUtxo: {
            script: Uint8Array.from(Buffer.from(classification.scriptPubKey, 'hex')),
            amount: BigInt(classification.valueSats),
          },
          ...(index === 1 ? {
            proprietary: [[
              new Uint8Array([0x64, 0x72, 0x65, 0x79, 0x05]),
              new Uint8Array([0xaa, 0xbb]),
            ]] as [Uint8Array, Uint8Array][],
          } : {}),
        });
      }
      tx.addOutput({ script: Uint8Array.from(Buffer.from(f.outputScript, 'hex')), amount: 78_000n });
      const psbt = tx.toPSBT();
      const plan = createFixturePlan(f, {
        psbtBase64: bytesToBase64(psbt),
        planId: `psbt-v${version}`,
      });
      expect(plan.psbtVersion).toBe(version);
      expect(plan.psbtHex).toBe(bytesToHex(psbt));
      const signed = signProviderPsbtPlan({
        plan,
        seed,
        requestedInputIndexes: [1],
        random: (length) => new Uint8Array(length).fill(7),
      });
      const reparsed = Transaction.fromPSBT(Uint8Array.from(Buffer.from(signed.psbtBase64, 'base64')));
      expect(reparsed.opts.PSBTVersion).toBe(version);
      expect(reparsed.getInput(1).proprietary).toEqual(tx.getInput(1).proprietary);
      expect(reparsed.getInput(0).partialSig).toBeUndefined();
      expect(reparsed.getInput(1).partialSig).toHaveLength(1);
    }
  });

  it('rejects a protected foreign input through M7H hard violations', () => {
    const f = fixture('inscribed');
    expect(() => createProviderPsbtPlan({
      ...f, binding, network: 'signet', vaultId: 'vault-1', sessionId: binding.requestNonce,
      account: 0, source, broadcast: false,
      planId: 'plan-2', now: 1_800_000_000_000,
    })).toThrow(/safety policy/);
  });

  it('signs only deterministic buyer inputs while accepting a seller flexible signature and proven inscription delivery', () => {
    const f = fixture('inscribed');
    const tx = Transaction.fromPSBT(Uint8Array.from(Buffer.from(f.psbtBase64, 'base64')));
    tx.updateInput(0, { sighashType: SigHash.SINGLE_ANYONECANPAY });
    const ordinalAccount = deriveAccountNode(seed, 'ordinals', 'signet', 0);
    const ordinalReceive = deriveAddress(ordinalAccount, 'ordinals', 'signet', 0, 0);
    ordinalAccount.wipePrivateData();
    const ordinalScript = scriptPubKeyHex(ordinalReceive.publicKeyHex, 'ordinals', 'signet');
    tx.updateOutput(0, { script: Uint8Array.from(Buffer.from(ordinalScript, 'hex')) });
    const plan = bindTestPlaceholders(createProviderPsbtPlan({
      ...f,
      psbtBase64: bytesToBase64(tx.toPSBT()),
      selectedInputIndexes: [1],
      walletOutputs: [{
        scriptPubKey: ordinalScript,
        output: {
          address: ordinalReceive.address,
          scriptPubKey: ordinalScript,
          valueSats: 78_000n,
          role: 'ordinal_change',
          derivation: {
            accountId, account: 0, lane: 'ordinals', chain: 0, index: 0,
            path: ordinalReceive.path, publicKeyHex: ordinalReceive.publicKeyHex,
          },
        },
      }],
      binding, network: 'signet', vaultId: 'vault-1', sessionId: binding.requestNonce,
      account: 0, source, broadcast: false, planId: 'mixed-buyer', now: 1_800_000_000_000,
    }));
    expect(plan.selectedInputIndexes).toEqual([1]);
    expect(plan.protectedSatFlow).toEqual([{
      inputIndex: 0, inputOffset: 0n, outputIndex: 0, outputOffset: 0n,
      inscriptionId: `${'22'.repeat(32)}i0`,
    }]);
    expect(plan.analysis.hardViolations).toEqual([]);
    const signed = signProviderPsbtPlan({ plan, seed, requestedInputIndexes: [1],
      random: (length) => new Uint8Array(length).fill(3) });
    const reparsed = Transaction.fromPSBT(Uint8Array.from(Buffer.from(signed.psbtBase64, 'base64')));
    expect(reparsed.getInput(0).partialSig).toBeUndefined();
    expect(reparsed.getInput(1).partialSig).toHaveLength(1);
    expect(() => signProviderPsbtPlan({ plan, seed, requestedInputIndexes: [0],
      random: (length) => new Uint8Array(length) })).toThrow(/indexes changed/u);
  });

  it('allows one proven ordinal flow and rejects co-located inscription ambiguity', () => {
    const f = fixture('inscribed');
    const ordinalInput = {
      ...f,
      kind: 'provider_ordinal_transfer' as const,
      walletOutputs: [{
        scriptPubKey: f.outputScript,
        output: { address: f.recipientAddress, scriptPubKey: f.outputScript, valueSats: 78_000n, role: 'postage' as const },
      }],
      protectedSatFlow: [{ inputIndex: 0, inputOffset: 0n, outputIndex: 0, outputOffset: 0n,
        inscriptionId: `${'22'.repeat(32)}i0` }],
      binding: { ...binding, providerMethod: 'ord_sendInscriptions' as const },
      network: 'signet' as const, vaultId: 'vault-1', sessionId: binding.requestNonce,
      account: 0, source, broadcast: true, planId: 'ord-plan', now: 1_800_000_000_000,
    };
    expect(createProviderPsbtPlan(ordinalInput).analysis.hardViolations).toEqual([]);
    const ambiguous = structuredClone(f.classifications);
    ambiguous[0]!.inscriptions.push({
      inscriptionId: `${'22'.repeat(32)}i1`, satpoint: `${'22'.repeat(32)}:1:1`,
    });
    expect(() => createProviderPsbtPlan({ ...ordinalInput, classifications: ambiguous }))
      .toThrow(/safety policy/);
  });

  it('accepts co-located inscriptions only when every non-target sat reaches owned ordinal change', () => {
    const f = fixture('inscribed');
    const ordinalAccount = deriveAccountNode(seed, 'ordinals', 'signet', 0);
    const ordinalChange = deriveAddress(ordinalAccount, 'ordinals', 'signet', 1, 0);
    ordinalAccount.wipePrivateData();
    const ordinalChangeScript = scriptPubKeyHex(ordinalChange.publicKeyHex, 'ordinals', 'signet');
    const tx = Transaction.fromPSBT(Uint8Array.from(Buffer.from(f.psbtBase64, 'base64')));
    tx.updateOutput(0, { amount: 10_000n });
    tx.addOutput({ script: Uint8Array.from(Buffer.from(ordinalChangeScript, 'hex')), amount: 68_000n });
    const classifications = structuredClone(f.classifications);
    classifications[0]!.primaryClass = 'mixed';
    classifications[0]!.inscriptions.push({
      inscriptionId: `${'22'.repeat(32)}i1`, satpoint: `${'22'.repeat(32)}:1:20000`,
    });
    const plan = createProviderPsbtPlan({
      ...f,
      psbtBase64: bytesToBase64(tx.toPSBT()),
      classifications,
      kind: 'provider_ordinal_transfer',
      walletOutputs: [
        {
          scriptPubKey: f.outputScript,
          output: {
            address: f.recipientAddress,
            scriptPubKey: f.outputScript,
            valueSats: 10_000n,
            role: 'postage',
          },
        },
        {
          scriptPubKey: ordinalChangeScript,
          output: {
          address: ordinalChange.address,
          scriptPubKey: ordinalChangeScript,
          valueSats: 68_000n,
          role: 'ordinal_change',
          derivation: {
            accountId, account: 0, lane: 'ordinals', chain: 1, index: 0,
            path: ordinalChange.path, publicKeyHex: ordinalChange.publicKeyHex,
          },
        },
        },
      ],
      protectedSatFlow: [
        { inputIndex: 0, inputOffset: 0n, outputIndex: 0, outputOffset: 0n,
          inscriptionId: `${'22'.repeat(32)}i0` },
        { inputIndex: 0, inputOffset: 20_000n, outputIndex: 1, outputOffset: 10_000n,
          inscriptionId: `${'22'.repeat(32)}i1` },
      ],
      binding: { ...binding, providerMethod: 'ord_sendInscriptions' },
      network: 'signet', vaultId: 'vault-1', sessionId: binding.requestNonce,
      account: 0, source, broadcast: true, planId: 'co-located-safe', now: 1_800_000_000_000,
    });
    expect(plan.analysis.hardViolations).toEqual([]);

    expect(() => createProviderPsbtPlan({
      ...f,
      psbtBase64: bytesToBase64(tx.toPSBT()),
      classifications,
      kind: 'provider_ordinal_transfer',
      protectedSatFlow: [
        { inputIndex: 0, inputOffset: 0n, outputIndex: 0, outputOffset: 0n,
          inscriptionId: `${'22'.repeat(32)}i0` },
        { inputIndex: 0, inputOffset: 20_000n, outputIndex: 1, outputOffset: 10_000n,
          inscriptionId: `${'22'.repeat(32)}i1` },
      ],
      binding: { ...binding, providerMethod: 'ord_sendInscriptions' },
      network: 'signet', vaultId: 'vault-1', sessionId: binding.requestNonce,
      account: 0, source, broadcast: true, planId: 'co-located-unowned', now: 1_800_000_000_000,
    })).toThrow(/safety policy/u);
  });

  it('detects approval-plan mutation before signing', () => {
    const f = fixture();
    const plan = createProviderPsbtPlan({
      ...f, binding, network: 'signet', vaultId: 'vault-1', sessionId: binding.requestNonce,
      account: 0, source, broadcast: false,
      planId: 'plan-3', now: 1_800_000_000_000,
    });
    const mutated = { ...plan, feeSats: plan.feeSats + 1n };
    expect(() => signProviderPsbtPlan({
      plan: mutated, seed, random: (length) => new Uint8Array(length),
    })).toThrow(/mutated/);
    expect(bytesToHex(seed)).toHaveLength(128);
  });

  it('rejects ownership lies, incomplete classification, and unsafe sighashes', () => {
    const f = fixture();
    expect(() => createProviderPsbtPlan({
      ...f,
      walletInputs: f.walletInputs.map((input) => ({
        ...input,
        derivation: {
          ...input.derivation,
          accountId: `acct_signet_${'b'.repeat(64)}`,
        },
      })),
      binding,
      network: 'signet',
      vaultId: 'vault-1',
      sessionId: binding.requestNonce,
      account: 0,
      source,
      broadcast: false,
      planId: 'foreign-account-id',
      now: 1_800_000_000_000,
    })).toThrow('public account identity');
    expect(() => createProviderPsbtPlan({
      ...f,
      walletOutputs: [{
        scriptPubKey: f.outputScript,
        output: {
          address: f.recipientAddress,
          scriptPubKey: f.outputScript,
          valueSats: 78_000n,
          role: 'payment_change',
          derivation: {
            ...f.walletInputs[0]!.derivation,
            chain: 1,
            accountId: `acct_signet_${'b'.repeat(64)}`,
          },
        },
      }],
      binding,
      network: 'signet',
      vaultId: 'vault-1',
      sessionId: binding.requestNonce,
      account: 0,
      source,
      broadcast: false,
      planId: 'foreign-output-account-id',
      now: 1_800_000_000_000,
    })).toThrow('output public account identity');
    expect(() => createProviderPsbtPlan({
      ...f, classifications: f.classifications.slice(1), binding, network: 'signet',
      vaultId: 'vault-1', sessionId: binding.requestNonce, account: 0, source,
      broadcast: false, planId: 'missing-classification', now: 1_800_000_000_000,
    })).toThrow(/classify every input/u);
    expect(() => createProviderPsbtPlan({
      ...f,
      walletInputs: [
        ...f.walletInputs,
        { outpoint: `${'22'.repeat(32)}:1`, derivation: f.walletInputs[0]!.derivation },
      ],
      binding, network: 'signet', vaultId: 'vault-1', sessionId: binding.requestNonce,
      account: 0, source, broadcast: false, planId: 'ownership-lie', now: 1_800_000_000_000,
    })).toThrow(/ownership proof mismatch/u);

    const unsafe = Transaction.fromPSBT(Uint8Array.from(Buffer.from(f.psbtBase64, 'base64')));
    unsafe.updateInput(1, { sighashType: SigHash.SINGLE });
    expect(() => createProviderPsbtPlan({
      ...f, psbtBase64: bytesToBase64(unsafe.toPSBT()), binding, network: 'signet',
      vaultId: 'vault-1', sessionId: binding.requestNonce, account: 0, source,
      broadcast: false, planId: 'unsafe-sighash', now: 1_800_000_000_000,
    })).toThrow(/SINGLE without a corresponding output/u);
  });

  it('rejects degraded classifications and non-overridable provider fee anomalies', () => {
    const f = fixture();
    const degraded = structuredClone(f.classifications);
    degraded[1]!.confidence = 'degraded';
    expect(() => createProviderPsbtPlan({
      ...f, classifications: degraded, binding, network: 'signet', vaultId: 'vault-1',
      sessionId: binding.requestNonce, account: 0, source, broadcast: false,
      planId: 'degraded', now: 1_800_000_000_000,
    })).toThrow(/authoritative/u);

    const relativeFee = Transaction.fromPSBT(Uint8Array.from(Buffer.from(f.psbtBase64, 'base64')));
    relativeFee.updateOutput(0, { amount: 60_000n });
    expect(() => createProviderPsbtPlan({
      ...f, psbtBase64: bytesToBase64(relativeFee.toPSBT()), binding, network: 'signet',
      vaultId: 'vault-1', sessionId: binding.requestNonce, account: 0, source,
      broadcast: false, planId: 'relative-fee', now: 1_800_000_000_000,
    })).toThrow(/fee anomaly/u);

    const absoluteFee = Transaction.fromPSBT(Uint8Array.from(Buffer.from(f.psbtBase64, 'base64')));
    absoluteFee.updateInput(0, {
      witnessUtxo: {
        ...absoluteFee.getInput(0).witnessUtxo!,
        amount: 130_000n,
      },
    });
    const costlyClassifications = structuredClone(f.classifications);
    costlyClassifications[0]!.valueSats = '130000';
    expect(() => createProviderPsbtPlan({
      ...f, psbtBase64: bytesToBase64(absoluteFee.toPSBT()), classifications: costlyClassifications,
      binding, network: 'signet', vaultId: 'vault-1', sessionId: binding.requestNonce,
      account: 0, source, broadcast: false, planId: 'absolute-fee', now: 1_800_000_000_000,
    })).toThrow(/fee anomaly/u);
  });

  it('binds the immutable analysis itself as well as its hash', () => {
    const f = fixture();
    const plan = createProviderPsbtPlan({
      ...f, binding, network: 'signet', vaultId: 'vault-1', sessionId: binding.requestNonce,
      account: 0, source, broadcast: false, planId: 'analysis-plan', now: 1_800_000_000_000,
    });
    const mutated = structuredClone(plan);
    (mutated.analysis.outputs[0] as { valueSats: bigint }).valueSats += 1n;
    expect(() => signProviderPsbtPlan({
      plan: mutated, seed, random: (length) => new Uint8Array(length),
    })).toThrow(/mutated/u);
  });
});
