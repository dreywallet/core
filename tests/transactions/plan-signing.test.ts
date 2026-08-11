import { beforeAll, describe, expect, it } from 'vitest';
import { deriveAccountNode, deriveAddress } from '../../src/domain/keys/derivation';
import { mnemonicToSeed } from '../../src/domain/keys/mnemonic';
import { scriptPubKeyHex } from '../../src/domain/keys/script-hash';
import { installTestCryptoProvider } from '../helpers/install-crypto-provider';
import { buildPsbtHex, signAndValidatePlan, validateSignedTransactionHex } from '../../src/domain/transactions/signing';
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

function bytes(hex: string): Uint8Array {
  return Uint8Array.from(hex.match(/../gu) ?? [], (pair) => Number.parseInt(pair, 16));
}

function hex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

describe('M7 canonical plans and signing validation', () => {
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
