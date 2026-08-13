import { beforeAll, describe, expect, it } from 'vitest';
import { deriveAccountNode, deriveAddress } from '../../src/domain/keys/derivation';
import { mnemonicToSeed } from '../../src/domain/keys/mnemonic';
import { scriptPubKeyHex } from '../../src/domain/keys/script-hash';
import { installTestCryptoProvider } from '../helpers/install-crypto-provider';
import {
  buildPsbtHex,
  MAX_STANDARD_TRANSACTION_VSIZE,
  assertStandardTransactionVsize,
  signAndValidatePlan,
  validateSignedTransactionHex,
} from '../../src/domain/transactions/signing';
import {
  assertLegacyCurrentPlanHash,
  assertPlanHash,
  finalizePlan,
  hashHex,
  hashPlan,
  legacyCurrentTransactionPlanSchema,
  legacyTransactionPlanSchema,
  customPlanFeePolicy,
  reviewFromPlan,
  transactionCommitmentHash,
  transactionPlanSchema,
  type LegacyTransactionPlan,
  type LegacyCurrentTransactionPlan,
  type TransactionPlan,
} from '../../src/domain/transactions/plan';
import { analyzePsbtHex } from '../../src/domain/transactions/analysis';
import { estimateVsize } from '../../src/domain/transactions/fees';
import { publicAccountFromSeed } from '../../src/domain/accounts/public-account';

const MNEMONIC = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const seed = mnemonicToSeed(MNEMONIC);
const accountId = publicAccountFromSeed(seed, 'signet', 0).accountId;

beforeAll(async () => { await installTestCryptoProvider(); });

function makePlan(): TransactionPlan {
  const account = deriveAccountNode(seed, 'payment', 'signet', 0);
  const inputAddress = deriveAddress(account, 'payment', 'signet', 0, 0);
  const changeAddress = deriveAddress(account, 'payment', 'signet', 1, 0);
  const input = {
    txid: '1'.repeat(64), vout: 1, valueSats: 100_000n,
    scriptPubKey: scriptPubKeyHex(inputAddress.publicKeyHex, 'payment', 'signet'),
    sequence: 0xfffffffd, sighash: 1 as const,
    derivation: { accountId, account: 0, lane: 'payment' as const, chain: 0 as const, index: 0,
      path: inputAddress.path, publicKeyHex: inputAddress.publicKeyHex },
    classification: { primaryClass: 'cardinal_clean' as const, inscriptions: [], satRanges: null,
      unsupportedAssetDetected: false, confidence: 'authoritative' as const,
      classifiedTip: { height: 250_000, hash: '2'.repeat(64) }, classificationRevision: 'rev-1' },
  };
  const output = { valueSats: 99_000n,
    scriptPubKey: scriptPubKeyHex(changeAddress.publicKeyHex, 'payment', 'signet'),
    address: changeAddress.address, role: 'payment_change' as const,
    derivation: { accountId, account: 0, lane: 'payment' as const, chain: 1 as const, index: 0,
      path: changeAddress.path, publicKeyHex: changeAddress.publicKeyHex } };
  const psbtHex = buildPsbtHex([input], [output]);
  const source = { backend: 'http://gateway', instanceId: 'fixture', classificationRevision: 'rev-1',
    coreTip: { height: 250_000, hash: '2'.repeat(64) }, indexTip: { height: 250_000, hash: '2'.repeat(64) },
    feeQuoteTimestamp: null, mempoolState: null };
  const analyzed = analyzePsbtHex(psbtHex, {
    network: 'signet', account: 0, kind: 'native_send', source,
    inputs: [input], outputs: [output], protectedSatFlow: [], feeSats: 1_000n,
    vsize: 110n, feeRateSatPerKvB: 5_000n, rbf: true,
  });
  if (!analyzed.ok) throw new Error('fixture analysis failed');
  const transaction: Omit<TransactionPlan, 'planHash' | 'transactionCommitmentHash' | 'inscriptionPreviews'> = {
    version: 4 as const, planId: 'plan-vector', createdAt: 1, expiresAt: 600_001,
    network: 'signet', accountId, account: 0, kind: 'native_send',
    policy: { intent: { kind: 'native_send', account: 0, recipient: changeAddress.address,
      amountSats: '99000', sendMax: false }, fee: customPlanFeePolicy('5') },
    source,
    inputs: [input], outputs: [output], protectedSatFlow: [], feeSats: 1_000n,
    vsize: 110n, feeRateSatPerKvB: 5_000n, urgency: 'custom', rbf: true,
    parentTxid: null, replacesTxid: null, broadcast: true as const, psbtHex, psbtHash: hashHex(psbtHex),
    analysisHash: analyzed.analysisHash,
  };
  const commitment = transactionCommitmentHash(transaction);
  return finalizePlan({ ...transaction, inscriptionPreviews: {
    transactionCommitmentHash: commitment, analysisHash: analyzed.analysisHash,
    psbtHash: transaction.psbtHash, effectSetHash: analyzed.analysis.assetEffects.effectSetHash,
    classificationRevision: source.classificationRevision, verifiedAtMs: 1, items: [],
  } });
}

function makeTaprootPlan(): TransactionPlan {
  const account = deriveAccountNode(seed, 'ordinals', 'signet', 0);
  const paymentAccount = deriveAccountNode(seed, 'payment', 'signet', 0);
  const inputAddress = deriveAddress(account, 'ordinals', 'signet', 0, 0);
  const changeAddress = deriveAddress(account, 'ordinals', 'signet', 1, 0);
  const paymentAddress = deriveAddress(paymentAccount, 'payment', 'signet', 1, 0);
  const input = {
    txid: '3'.repeat(64), vout: 0, valueSats: 100_000n,
    scriptPubKey: scriptPubKeyHex(inputAddress.publicKeyHex, 'ordinals', 'signet'),
    sequence: 0xffffffff, sighash: 0 as const,
    derivation: { accountId, account: 0, lane: 'ordinals' as const, chain: 0 as const, index: 0,
      path: inputAddress.path, publicKeyHex: inputAddress.publicKeyHex },
    classification: { primaryClass: 'cardinal_clean' as const, inscriptions: [], satRanges: null,
      unsupportedAssetDetected: false, confidence: 'authoritative' as const,
      classifiedTip: { height: 250_000, hash: '2'.repeat(64) }, classificationRevision: 'rev-1' },
  };
  const output = { valueSats: 10_000n,
    scriptPubKey: scriptPubKeyHex(changeAddress.publicKeyHex, 'ordinals', 'signet'),
    address: changeAddress.address, role: 'ordinal_change' as const,
    derivation: { accountId, account: 0, lane: 'ordinals' as const, chain: 1 as const, index: 0,
      path: changeAddress.path, publicKeyHex: changeAddress.publicKeyHex } };
  const paymentOutput = { valueSats: 89_000n,
    scriptPubKey: scriptPubKeyHex(paymentAddress.publicKeyHex, 'payment', 'signet'),
    address: paymentAddress.address, role: 'payment_change' as const,
    derivation: { accountId, account: 0, lane: 'payment' as const, chain: 1 as const, index: 0,
      path: paymentAddress.path, publicKeyHex: paymentAddress.publicKeyHex } };
  const outputs = [output, paymentOutput];
  const vsize = estimateVsize([input.scriptPubKey], outputs.map((entry) => entry.scriptPubKey));
  const source = { backend: 'http://gateway', instanceId: 'fixture', classificationRevision: 'rev-1',
    coreTip: { height: 250_000, hash: '2'.repeat(64) }, indexTip: { height: 250_000, hash: '2'.repeat(64) },
    feeQuoteTimestamp: null, mempoolState: null };
  const psbtHex = buildPsbtHex([input], outputs);
  const analyzed = analyzePsbtHex(psbtHex, {
    network: 'signet', account: 0, kind: 'ordinal_sweep', source,
    inputs: [input], outputs, protectedSatFlow: [], feeSats: 1_000n,
    vsize, feeRateSatPerKvB: 5_000n, rbf: false,
  });
  account.wipePrivateData();
  paymentAccount.wipePrivateData();
  if (!analyzed.ok) throw new Error('Taproot fixture analysis failed');
  const transaction: Omit<TransactionPlan, 'planHash' | 'transactionCommitmentHash' | 'inscriptionPreviews'> = {
    version: 4 as const, planId: 'plan-bip86', createdAt: 1, expiresAt: 600_001,
    network: 'signet', accountId, account: 0, kind: 'ordinal_sweep',
    policy: { intent: { kind: 'ordinal_sweep', outpoint: { txid: input.txid, vout: input.vout } },
      fee: customPlanFeePolicy('5') },
    source, inputs: [input], outputs, protectedSatFlow: [], feeSats: 1_000n,
    vsize, feeRateSatPerKvB: 5_000n, urgency: 'custom', rbf: false,
    parentTxid: null, replacesTxid: null, broadcast: true as const, psbtHex, psbtHash: hashHex(psbtHex),
    analysisHash: analyzed.analysisHash,
  };
  const commitment = transactionCommitmentHash(transaction);
  return finalizePlan({ ...transaction, inscriptionPreviews: {
    transactionCommitmentHash: commitment, analysisHash: analyzed.analysisHash,
    psbtHash: transaction.psbtHash, effectSetHash: analyzed.analysis.assetEffects.effectSetHash,
    classificationRevision: source.classificationRevision, verifiedAtMs: 1, items: [],
  } });
}

function makeOrdinalBatchPlan(): TransactionPlan {
  const ordinalAccount = deriveAccountNode(seed, 'ordinals', 'signet', 0);
  const paymentAccount = deriveAccountNode(seed, 'payment', 'signet', 0);
  const externalAccount = deriveAccountNode(seed, 'ordinals', 'signet', 1);
  try {
    const ordinalAddresses = [0, 1].map((index) =>
      deriveAddress(ordinalAccount, 'ordinals', 'signet', 0, index));
    const paymentInput = deriveAddress(paymentAccount, 'payment', 'signet', 0, 0);
    const paymentChanges = [0, 1].map((index) =>
      deriveAddress(paymentAccount, 'payment', 'signet', 1, index));
    const recipient = deriveAddress(externalAccount, 'ordinals', 'signet', 0, 0);
    const inscriptionIds = [`${'6'.repeat(64)}i0`, `${'7'.repeat(64)}i0`];
    const sources = ordinalAddresses.map((address, index) => ({
      txid: String(6 + index).repeat(64), vout: 0, valueSats: index === 0 ? 10_000n : 20_000n,
      scriptPubKey: scriptPubKeyHex(address.publicKeyHex, 'ordinals', 'signet'),
      sequence: 0xffffffff, sighash: 0 as const, ownership: 'wallet' as const,
      derivation: { accountId, account: 0, lane: 'ordinals' as const, chain: 0 as const,
        index, path: address.path, publicKeyHex: address.publicKeyHex },
      classification: { primaryClass: 'inscribed' as const,
        inscriptions: [{ inscriptionId: inscriptionIds[index]!,
          satpoint: `${String(6 + index).repeat(64)}:0:0` }], satRanges: null,
        unsupportedAssetDetected: false, confidence: 'authoritative' as const,
        classifiedTip: { height: 250_000, hash: '2'.repeat(64) }, classificationRevision: 'rev-1' },
    }));
    const funding = {
      txid: '8'.repeat(64), vout: 0, valueSats: 50_000n,
      scriptPubKey: scriptPubKeyHex(paymentInput.publicKeyHex, 'payment', 'signet'),
      sequence: 0xffffffff, sighash: 1 as const, ownership: 'wallet' as const,
      derivation: { accountId, account: 0, lane: 'payment' as const, chain: 0 as const,
        index: 0, path: paymentInput.path, publicKeyHex: paymentInput.publicKeyHex },
      classification: { primaryClass: 'cardinal_clean' as const, inscriptions: [], satRanges: null,
        unsupportedAssetDetected: false, confidence: 'authoritative' as const,
        classifiedTip: { height: 250_000, hash: '2'.repeat(64) }, classificationRevision: 'rev-1' },
    };
    const postage = (valueSats: bigint) => ({ valueSats,
      scriptPubKey: scriptPubKeyHex(recipient.publicKeyHex, 'ordinals', 'signet'),
      address: recipient.address, role: 'postage' as const });
    const paymentChange = (valueSats: bigint, index: number) => ({ valueSats,
      scriptPubKey: scriptPubKeyHex(paymentChanges[index]!.publicKeyHex, 'payment', 'signet'),
      address: paymentChanges[index]!.address, role: 'payment_change' as const,
      derivation: { accountId, account: 0, lane: 'payment' as const, chain: 1 as const,
        index, path: paymentChanges[index]!.path, publicKeyHex: paymentChanges[index]!.publicKeyHex } });
    const selections = sources.map((source, index) => ({ inscriptionId: inscriptionIds[index]!,
      outpoint: { txid: source.txid, vout: source.vout },
      satpoint: source.classification.inscriptions[0]!.satpoint, classificationRevision: 'rev-1' }));
    return rebuildOrdinalBatchPlan({
      version: 4, planId: 'plan-ordinal-batch', createdAt: 1, expiresAt: 600_001,
      network: 'signet', accountId, account: 0, kind: 'ordinal_batch_transfer',
      policy: { intent: { kind: 'ordinal_batch_transfer', account: 0,
        recipient: recipient.address, selections }, fee: customPlanFeePolicy('5') },
      source: { backend: 'http://gateway', instanceId: 'fixture', classificationRevision: 'rev-1',
        coreTip: { height: 250_000, hash: '2'.repeat(64) },
        indexTip: { height: 250_000, hash: '2'.repeat(64) },
        feeQuoteTimestamp: null, mempoolState: null },
      inputs: [...sources, funding],
      outputs: [postage(10_000n), postage(10_000n), paymentChange(10_000n, 0), paymentChange(49_000n, 1)],
      protectedSatFlow: selections.map((selection, index) => ({ inputIndex: index,
        inputOffset: 0n, outputIndex: index, outputOffset: 0n, inscriptionId: selection.inscriptionId })),
      feeSats: 1_000n, vsize: 1n, feeRateSatPerKvB: 5_000n, urgency: 'custom', rbf: false,
      parentTxid: null, replacesTxid: null, broadcast: true,
    });
  } finally {
    ordinalAccount.wipePrivateData();
    paymentAccount.wipePrivateData();
    externalAccount.wipePrivateData();
  }
}

type BatchPlanDraft = Omit<TransactionPlan,
  'planHash' | 'transactionCommitmentHash' | 'inscriptionPreviews' |
  'psbtHex' | 'psbtHash' | 'analysisHash'>;

function rebuildOrdinalBatchPlan(draft: BatchPlanDraft): TransactionPlan {
  const psbtHex = buildPsbtHex(draft.inputs, draft.outputs);
  const vsize = estimateVsize(draft.inputs.map((input) => input.scriptPubKey),
    draft.outputs.map((output) => output.scriptPubKey));
  const feeSats = draft.inputs.reduce((sum, input) => sum + input.valueSats, 0n) -
    draft.outputs.reduce((sum, output) => sum + output.valueSats, 0n);
  const analyzed = analyzePsbtHex(psbtHex, { network: draft.network, account: draft.account,
    kind: draft.kind, source: draft.source, inputs: draft.inputs, outputs: draft.outputs,
    protectedSatFlow: draft.protectedSatFlow, feeSats, vsize,
    feeRateSatPerKvB: draft.feeRateSatPerKvB, rbf: draft.rbf });
  if (!analyzed.ok) throw new Error('batch fixture analysis failed');
  const transaction = { ...draft, feeSats, vsize, psbtHex, psbtHash: hashHex(psbtHex),
    analysisHash: analyzed.analysisHash };
  const commitment = transactionCommitmentHash(transaction);
  return finalizePlan({ ...transaction, inscriptionPreviews: {
    transactionCommitmentHash: commitment, analysisHash: analyzed.analysisHash,
    psbtHash: transaction.psbtHash, effectSetHash: analyzed.analysis.assetEffects.effectSetHash,
    classificationRevision: draft.source.classificationRevision, verifiedAtMs: 1, items: [],
  } });
}

function mutateOrdinalBatchPlan(
  plan: TransactionPlan,
  mutate: (draft: BatchPlanDraft) => void,
): TransactionPlan {
  const { planHash: _planHash, transactionCommitmentHash: _commitment,
    inscriptionPreviews: _previews, psbtHex: _psbtHex, psbtHash: _psbtHash,
    analysisHash: _analysisHash, ...body } = structuredClone(plan);
  void _planHash; void _commitment; void _previews; void _psbtHex; void _psbtHash; void _analysisHash;
  const draft = body as BatchPlanDraft;
  mutate(draft);
  return rebuildOrdinalBatchPlan(draft);
}

function bytes(hex: string): Uint8Array {
  return Uint8Array.from(hex.match(/../gu) ?? [], (pair) => Number.parseInt(pair, 16));
}

function hex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

describe('M7 canonical plans and signing validation', () => {
  it('fails closed before signing a plan above the standard transaction weight limit', () => {
    expect(() => assertStandardTransactionVsize(MAX_STANDARD_TRANSACTION_VSIZE)).not.toThrow();
    expect(() => assertStandardTransactionVsize(MAX_STANDARD_TRANSACTION_VSIZE + 1n))
      .toThrow(/standard weight limit/u);
    expect(() => assertStandardTransactionVsize(MAX_STANDARD_TRANSACTION_VSIZE + 1n, true))
      .toThrow(/signed transaction/u);
  });
  it('explains every password-confirmation reason without turning fee warnings into hard blocks', () => {
    const base = makePlan();
    const review = reviewFromPlan({
      ...base,
      feeSats: 100_001n,
      outputs: [{ ...base.outputs[0]!, role: 'recipient' }],
    }, [], true);
    expect(review.requiresReauth).toBe(true);
    expect(review.reauthReasons).toEqual([
      'high_security_mode',
      'high_absolute_fee',
      'high_relative_fee',
    ]);
  });

  it('projects exact normalized fee rate, miner fee, and transaction total', () => {
    const base = makePlan();
    const review = reviewFromPlan({
      ...base,
      outputs: [{ ...base.outputs[0]!, role: 'recipient', derivation: undefined }],
    }, [], false);
    expect(review).toMatchObject({
      amountSats: '99000',
      feeSats: '1000',
      totalSats: '100000',
      feeRateSatPerKvB: '5000',
      feeRateSatPerVb: '5',
    });
  });

  it('does not treat inscription postage as the value of the inscription', () => {
    const base = makePlan();
    const ordinalPlan = {
      ...base,
      kind: 'ordinal_transfer' as const,
      outputs: [{
        ...base.outputs[0]!,
        role: 'postage' as const,
        valueSats: 546n,
      }],
      feeSats: 1_000n,
    };
    const review = reviewFromPlan(ordinalPlan, [], false);
    expect(review.requiresReauth).toBe(false);
    expect(review.reauthReasons).toEqual([]);

    const unusuallyHighFee = reviewFromPlan({
      ...ordinalPlan,
      feeSats: 100_001n,
    }, [], false);
    expect(unusuallyHighFee.requiresReauth).toBe(true);
    expect(unusuallyHighFee.reauthReasons).toEqual(['high_absolute_fee']);
  });

  it('builds a compact ordered review for an atomic ordinal batch', () => {
    const base = makePlan();
    const inscriptionIds = [`${'1'.repeat(64)}i0`, `${'2'.repeat(64)}i0`];
    const source = {
      ...base.inputs[0]!,
      classification: {
        ...base.inputs[0]!.classification,
        primaryClass: 'inscribed' as const,
        inscriptions: inscriptionIds.map((inscriptionId) => ({
          inscriptionId,
          satpoint: `${base.inputs[0]!.txid}:${base.inputs[0]!.vout}:0`,
        })),
      },
    };
    const postage = {
      ...base.outputs[0]!,
      role: 'postage' as const,
      derivation: undefined,
      address: 'tb1ptest',
      valueSats: 10_000n,
    };
    const review = reviewFromPlan({
      ...base,
      kind: 'ordinal_batch_transfer',
      policy: {
        ...base.policy,
        intent: {
          kind: 'ordinal_batch_transfer',
          account: 0,
          recipient: postage.address,
          selections: inscriptionIds.map((inscriptionId) => ({
            inscriptionId,
            outpoint: { txid: source.txid, vout: source.vout },
            satpoint: `${source.txid}:${source.vout}:0`,
            classificationRevision: 'rev-1',
          })),
        },
      },
      inputs: [source],
      outputs: [postage],
      protectedSatFlow: inscriptionIds.map((inscriptionId) => ({
        inputIndex: 0,
        inputOffset: 0n,
        outputIndex: 0,
        outputOffset: 0n,
        inscriptionId,
      })),
    }, [], false);
    expect(review.ordinalAction).toMatchObject({
      action: 'batch_transfer',
      inscriptionIds,
      inscriptionCount: 2,
      destination: { address: 'tb1ptest', ownership: 'external' },
      aggregatePostageSats: '10000',
      groups: [{ inscriptionIds, destinationOutputIndex: 0, travelsTogether: true }],
    });
  });

  it('round-trips the versioned schema and canonical hash', () => {
    const plan = makePlan();
    const parsed = transactionPlanSchema.parse(plan);
    expect(parsed).toEqual(plan);
    expect(() => assertPlanHash(parsed)).not.toThrow();
    expect(Object.isFrozen(plan.inputs)).toBe(true);
    expect(Object.isFrozen(plan.outputs[0])).toBe(true);
  });

  it('rejects unsafe cached input classifications and out-of-range output indexes', () => {
    const plan = makePlan();
    const input = plan.inputs[0]!;
    expect(
      transactionPlanSchema.safeParse({
        ...plan,
        inputs: [{
          ...input,
          classification: { ...input.classification, confidence: 'degraded' },
        }],
      }).success,
    ).toBe(false);
    expect(
      transactionPlanSchema.safeParse({
        ...plan,
        inputs: [{ ...input, vout: 0x100000000 }],
      }).success,
    ).toBe(false);
    expect(transactionPlanSchema.safeParse({
      ...plan,
      accountId: `acct_mainnet_${'a'.repeat(64)}`,
    }).success).toBe(false);
    expect(transactionPlanSchema.safeParse({
      ...plan,
      inputs: [{
        ...input,
        derivation: { ...input.derivation!, account: 1 },
      }],
    }).success).toBe(false);
    const foreignAccountId = publicAccountFromSeed(seed, 'signet', 1).accountId;
    expect(transactionPlanSchema.safeParse({
      ...plan,
      inputs: [{
        ...input,
        derivation: { ...input.derivation!, accountId: foreignAccountId },
      }],
    }).success).toBe(false);
    expect(transactionPlanSchema.safeParse({
      ...plan,
      outputs: [{
        ...plan.outputs[0]!,
        derivation: { ...plan.outputs[0]!.derivation!, accountId: foreignAccountId },
      }],
    }).success).toBe(false);
  });

  it('binds the software signer to the stable public account identity', () => {
    const plan = makePlan();
    const {
      planHash: _planHash,
      transactionCommitmentHash: _transactionCommitmentHash,
      ...unsigned
    } = plan;
    void _planHash;
    void _transactionCommitmentHash;
    const mutated = finalizePlan({
      ...unsigned,
      accountId: publicAccountFromSeed(seed, 'signet', 1).accountId,
    });
    expect(() => signAndValidatePlan(mutated, seed.slice(), (length) => new Uint8Array(length)))
      .toThrow(/public account identity mismatch/u);
  });

  it('signs the BIP84 vector deterministically and reparses exact plan fields', () => {
    const plan = makePlan();
    const first = signAndValidatePlan(plan, seed.slice(), (length) => new Uint8Array(length));
    const second = signAndValidatePlan(plan, seed.slice(), (length) => new Uint8Array(length));
    expect(first.txid).toMatch(/^[0-9a-f]{64}$/u);
    expect(second).toEqual(first);
  });

  it('signs and cryptographically verifies a BIP86 key-path transaction', () => {
    const plan = makeTaprootPlan();
    const signed = signAndValidatePlan(plan, seed.slice(), (length) => new Uint8Array(length));
    expect(() => validateSignedTransactionHex(plan, signed.transactionHex)).not.toThrow();
  });

  it('signs and independently verifies a realistic multi-source ordinal batch', () => {
    const plan = makeOrdinalBatchPlan();
    const signed = signAndValidatePlan(plan, seed.slice(), (length) => new Uint8Array(length));
    expect(() => validateSignedTransactionHex(plan, signed.transactionHex)).not.toThrow();
  });

  it('rejects unsafe ordinal batch input policy through the public signing path', () => {
    const plan = makeOrdinalBatchPlan();
    const mutations: Array<(draft: BatchPlanDraft) => void> = [
      (draft) => { draft.inputs = [draft.inputs[2]!, draft.inputs[0]!, draft.inputs[1]!]; },
      (draft) => { draft.inputs = [draft.inputs[1]!, draft.inputs[0]!, draft.inputs[2]!]; },
      (draft) => {
        if (draft.policy.intent.kind !== 'ordinal_batch_transfer') throw new Error('batch intent missing');
        draft.policy.intent.selections = draft.policy.intent.selections.slice(0, 1);
      },
      (draft) => { draft.inputs[0]!.classification.classificationRevision = 'rev-stale'; },
      (draft) => { draft.inputs[2]!.classification.primaryClass = 'unknown'; },
    ];
    for (const mutate of mutations) {
      const unsafe = mutateOrdinalBatchPlan(plan, mutate);
      expect(() => signAndValidatePlan(unsafe, seed.slice(), (length) => new Uint8Array(length)))
        .toThrow(/analysis|ordinal batch/u);
    }
  });

  it('rejects unsafe ordinal batch output policy while preserving valid self-send policy', () => {
    const plan = makeOrdinalBatchPlan();
    const separateCoLocated = mutateOrdinalBatchPlan(plan, (draft) => {
      const first = draft.policy.intent.kind === 'ordinal_batch_transfer'
        ? draft.policy.intent.selections[0]! : null;
      if (!first || draft.policy.intent.kind !== 'ordinal_batch_transfer') throw new Error('batch intent missing');
      const companion = { ...first, inscriptionId: `${'9'.repeat(64)}i0` };
      draft.policy.intent.selections.splice(1, 0, companion);
      draft.inputs[0]!.classification.inscriptions.push({ inscriptionId: companion.inscriptionId,
        satpoint: companion.satpoint });
      draft.protectedSatFlow.splice(1, 0, { ...draft.protectedSatFlow[0]!,
        outputIndex: 1, inscriptionId: companion.inscriptionId });
    });
    expect(() => signAndValidatePlan(separateCoLocated, seed.slice(), (length) => new Uint8Array(length)))
      .toThrow(/analysis|co-located/u);

    const sharedDistinct = mutateOrdinalBatchPlan(plan, (draft) => {
      draft.outputs[0]!.valueSats = 20_000n;
      draft.outputs.splice(1, 1);
      draft.protectedSatFlow[1]!.outputIndex = 0;
      draft.protectedSatFlow[1]!.outputOffset = 10_000n;
      for (let index = 2; index < draft.protectedSatFlow.length; index += 1) {
        draft.protectedSatFlow[index]!.outputIndex -= 1;
      }
    });
    expect(() => signAndValidatePlan(sharedDistinct, seed.slice(), (length) => new Uint8Array(length)))
      .toThrow(/distinct ordinal batch satpoints|analysis/u);

    const badChangeOwnership = mutateOrdinalBatchPlan(plan, (draft) => {
      draft.outputs[2]!.derivation = { ...draft.outputs[2]!.derivation!, lane: 'ordinals' };
    });
    expect(() => signAndValidatePlan(badChangeOwnership, seed.slice(), (length) => new Uint8Array(length)))
      .toThrow(/analysis|payment change/u);

    const dustChange = mutateOrdinalBatchPlan(plan, (draft) => {
      const donated = draft.outputs[2]!.valueSats - 1n;
      draft.outputs[2]!.valueSats = 1n;
      draft.outputs[3]!.valueSats += donated;
    });
    expect(() => signAndValidatePlan(dustChange, seed.slice(), (length) => new Uint8Array(length)))
      .toThrow(/payment change|dust/u);

    const annotatedOrdinalRecipient = mutateOrdinalBatchPlan(plan, (draft) => {
      const destination = draft.inputs[0]!.derivation!;
      const account = deriveAccountNode(seed, 'ordinals', 'signet', 0);
      try {
        const address = deriveAddress(account, 'ordinals', 'signet', destination.chain, destination.index);
        for (const output of draft.outputs.filter((item) => item.role === 'postage')) {
          output.address = address.address;
          output.scriptPubKey = draft.inputs[0]!.scriptPubKey;
          output.derivation = { ...destination };
        }
      } finally {
        account.wipePrivateData();
      }
      if (draft.policy.intent.kind === 'ordinal_batch_transfer') {
        draft.policy.intent.recipient = draft.outputs[0]!.address;
      }
    });
    expect(() => signAndValidatePlan(annotatedOrdinalRecipient, seed.slice(),
      (length) => new Uint8Array(length))).not.toThrow();

    const annotatedPaymentRecipient = mutateOrdinalBatchPlan(plan, (draft) => {
      const destination = draft.inputs[2]!.derivation!;
      const account = deriveAccountNode(seed, 'payment', 'signet', 0);
      try {
        const address = deriveAddress(account, 'payment', 'signet', destination.chain, destination.index);
        for (const output of draft.outputs.filter((item) => item.role === 'postage')) {
          output.address = address.address;
          output.scriptPubKey = draft.inputs[2]!.scriptPubKey;
          output.derivation = { ...destination };
        }
      } finally {
        account.wipePrivateData();
      }
      if (draft.policy.intent.kind === 'ordinal_batch_transfer') {
        draft.policy.intent.recipient = draft.outputs[0]!.address;
      }
    });
    expect(() => signAndValidatePlan(annotatedPaymentRecipient, seed.slice(),
      (length) => new Uint8Array(length))).toThrow(/analysis|destination policy/u);
  });

  it('rejects output, witness-signature, and Taproot script-path serialized mutations', () => {
    const plan = makePlan();
    const signed = signAndValidatePlan(plan, seed.slice(), (length) => new Uint8Array(length));
    const outputMutation = bytes(signed.transactionHex);
    outputMutation[49] = outputMutation[49]! ^ 1;
    expect(() => validateSignedTransactionHex(plan, hex(outputMutation))).toThrow(/output|analysis/u);

    const witnessMutation = bytes(signed.transactionHex);
    witnessMutation[85] = witnessMutation[85]! ^ 1;
    expect(() => validateSignedTransactionHex(plan, hex(witnessMutation))).toThrow(/signature|witness|tlv/u);

    const taproot = makeTaprootPlan();
    const taprootSigned = signAndValidatePlan(taproot, seed.slice(), (length) => new Uint8Array(length));
    const original = bytes(taprootSigned.transactionHex);
    const scriptPath = new Uint8Array(original.length + 2);
    scriptPath.set(original.slice(0, -4), 0);
    scriptPath[92] = 2;
    scriptPath[original.length - 4] = 1;
    scriptPath[original.length - 3] = 0;
    scriptPath.set(original.slice(-4), original.length - 2);
    expect(() => validateSignedTransactionHex(taproot, hex(scriptPath))).toThrow(/analysis|script-path/u);
  });

  it('keeps legacy accepted-plan records readable with their original hash', () => {
    const plan = makePlan();
    const { version: _version, accountId: _accountId, analysisHash: _analysisHash, planHash: _planHash,
      transactionCommitmentHash: _transactionCommitmentHash,
      inscriptionPreviews: _inscriptionPreviews, ...body } = plan;
    void _version;
    void _accountId;
    void _analysisHash;
    void _planHash;
    void _transactionCommitmentHash;
    void _inscriptionPreviews;
    const unhashed = {
      ...body,
      version: 1 as const,
      policy: { ...body.policy, fee: { type: 'custom' as const, satPerVb: 5 } },
    };
    const legacy: LegacyTransactionPlan = { ...unhashed, planHash: hashPlan(unhashed) };
    expect(legacyTransactionPlanSchema.parse(legacy)).toEqual(legacy);
  });

  it('keeps version-3 exact-byte recovery plans readable without changing their hashes', () => {
    const plan = makePlan();
    const {
      version: _version,
      accountId: _accountId,
      planHash: _planHash,
      transactionCommitmentHash: _commitment,
      inscriptionPreviews,
      ...body
    } = plan;
    void _version;
    void _accountId;
    void _planHash;
    void _commitment;
    const legacyBody = {
      ...body,
      version: 3 as const,
      policy: { ...body.policy, fee: { type: 'custom' as const, satPerVb: 5 } },
    };
    const commitment = transactionCommitmentHash(legacyBody);
    const withCommitment = {
      ...legacyBody,
      transactionCommitmentHash: commitment,
      inscriptionPreviews: { ...inscriptionPreviews, transactionCommitmentHash: commitment },
    };
    const legacy: LegacyCurrentTransactionPlan = {
      ...withCommitment,
      planHash: hashPlan(withCommitment),
    };
    expect(legacyCurrentTransactionPlanSchema.parse(legacy)).toEqual(legacy);
    expect(() => assertLegacyCurrentPlanHash(legacy)).not.toThrow();
  });

  it('refuses to hash malformed hex instead of coercing it to zero bytes', () => {
    // Number.parseInt returns NaN for a non-hex pair and a Uint8Array stores
    // that as 0, so an unvalidated decoder would return a real-looking digest
    // for input it never actually read.
    expect(() => hashHex('zz')).toThrow('invalid hex');
    expect(() => hashHex('abc')).toThrow('invalid hex');
    expect(hashHex('00')).not.toBe(hashHex('0000'));
  });

  it('rejects mutated outputs even when the attacker recomputes the plan hash', () => {
    const plan = makePlan();
    const { planHash: _planHash, ...unsigned } = plan;
    void _planHash;
    const mutated = finalizePlan({ ...unsigned, outputs: [{ ...plan.outputs[0]!, valueSats: 98_999n }], feeSats: 1_001n });
    expect(() => signAndValidatePlan(mutated, seed.slice(), (length) => new Uint8Array(length))).toThrow(/analysis|output differs/u);
  });

  it('rejects a changed ordinal action intent even with recomputed plan hashes', () => {
    const plan = makeTaprootPlan();
    const { planHash: _planHash, transactionCommitmentHash: _commitment, ...unsigned } = plan;
    void _planHash;
    void _commitment;
    const mutated = finalizePlan({
      ...unsigned,
      policy: {
        ...plan.policy,
        intent: {
          kind: 'ordinal_sweep',
          outpoint: { txid: '4'.repeat(64), vout: 1 },
        },
      },
    });
    expect(() => signAndValidatePlan(
      mutated,
      seed.slice(),
      (length) => new Uint8Array(length),
    )).toThrow(/sweep policy mismatch/u);
  });

  it('rejects derivation/script and network mutations before signing', () => {
    const plan = makePlan();
    const { planHash: _planHash, ...unsigned } = plan;
    void _planHash;
    const wrongScript = finalizePlan({ ...unsigned, inputs: [{ ...plan.inputs[0]!, scriptPubKey: `0014${'f'.repeat(40)}` }] });
    expect(() => signAndValidatePlan(wrongScript, seed.slice(), (length) => new Uint8Array(length))).toThrow(/analysis|prevout|ownership proof/u);
    const wrongNetwork = finalizePlan({ ...unsigned, network: 'mainnet' });
    expect(() => signAndValidatePlan(wrongNetwork, seed.slice(), (length) => new Uint8Array(length)))
      .toThrow(/analysis|ownership proof|public account/u);
    const wrongOutputIdentity = finalizePlan({
      ...unsigned,
      outputs: [{
        ...plan.outputs[0]!,
        derivation: {
          ...plan.outputs[0]!.derivation!,
          accountId: publicAccountFromSeed(seed, 'signet', 1).accountId,
        },
      }],
    });
    expect(() => signAndValidatePlan(
      wrongOutputIdentity,
      seed.slice(),
      (length) => new Uint8Array(length),
    )).toThrow('output public account identity');
  });
});
