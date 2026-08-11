import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { HDKey } from '@scure/bip32';
import { Transaction } from '@scure/btc-signer';
import fc from 'fast-check';
import { beforeAll, describe, expect, it } from 'vitest';
import { installTestCryptoProvider } from '../helpers/install-crypto-provider';
import { MAX_FEE_RATE_SAT_PER_KVB } from '../../src/domain/transactions/fees';
import { bytesToHex, hexToBytes } from '../../src/domain/vault/encoding';
import {
  VAULT_FULL_SAT_SAFETY_CAPABILITIES,
  VaultAssetPolicyError,
  combineVaultAssetSafePartialSignatureResults,
  computeVaultInputAssetEvidenceHash,
  createVaultAssetSafePartialSignatureInput,
  finalizeVaultAssetSafePsbt,
  finalizeVaultInputAssetEvidence,
  signVaultAssetSafePartialSignature,
  validateVaultAssetPolicy,
  vaultAssetPolicyEvidenceSchema,
  vaultInputAssetEvidenceSchema,
  type VaultAssetPolicyEvidenceV1,
  type VaultAssetPolicyValidationV1,
} from '../../src/domain/vault/multisig-asset-policy';
import {
  bip32Versions,
  type VaultPolicyIdentityV1,
  type VaultSignerRole,
  type VaultUnsignedPlanV1,
} from '../../src/domain/vault/multisig-contracts';
import { deriveVaultOutput } from '../../src/domain/vault/multisig-descriptors';
import { finalizeVaultUnsignedPlan } from '../../src/domain/vault/multisig-encoding';
import { constructVaultPsbt } from '../../src/domain/vault/multisig-psbt';

type B3Case = {
  plan: VaultUnsignedPlanV1;
  evidence: VaultAssetPolicyEvidenceV1;
  psbtHex: string;
  validation: VaultAssetPolicyValidationV1 | null;
  previousPlan?: VaultUnsignedPlanV1;
  nowMs?: string;
  expectedError?: VaultAssetPolicyError['code'];
  aPlusB?: {
    combinedPsbtHex: string;
    combinedPsbtHash: string;
    finalized: ReturnType<typeof finalizeVaultAssetSafePsbt>;
  };
};

type B3Record = {
  network: 'mainnet' | 'signet';
  policyId: string;
  cases: Record<'ordinary' | 'multiInput' | 'inscription' | 'rbf' | 'cpfp', B3Case>;
  adversarial: Record<string, B3Case>;
};

const contracts = JSON.parse(readFileSync(
  join(import.meta.dirname, '..', '..', 'vectors', 'vault-contracts-v1.json'),
  'utf8',
)) as { records: Record<'mainnet' | 'signet', { policy: VaultPolicyIdentityV1 }> };
const vectors = JSON.parse(readFileSync(
  join(import.meta.dirname, '..', '..', 'vectors', 'vault-asset-policy-v1.json'),
  'utf8',
)) as { vectorVersion: number; records: Record<'mainnet' | 'signet', B3Record> };

beforeAll(() => installTestCryptoProvider());

function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

function policy(network: 'mainnet' | 'signet'): VaultPolicyIdentityV1 {
  return contracts.records[network].policy;
}

function validate(network: 'mainnet' | 'signet', item: B3Case): VaultAssetPolicyValidationV1 {
  return validateVaultAssetPolicy({
    policy: policy(network),
    plan: item.plan,
    psbtHex: item.psbtHex,
    evidence: item.evidence,
    nowMs: item.nowMs ?? '1785542402000',
    ...(item.previousPlan ? { previousPlan: item.previousPlan } : {}),
  });
}

function fixtureRoot(network: 'mainnet' | 'signet', role: VaultSignerRole): HDKey {
  const label = role === 'desktop-a' ? 'root-a' : role === 'mobile-b' ? 'root-b' : 'root-c';
  const seed = new Uint8Array(createHash('sha256')
    .update(`PUBLIC DISPOSABLE B0 FIXTURE ONLY:${network}:${label}`).digest());
  return HDKey.fromMasterSeed(seed, bip32Versions(network));
}

function expectPolicyError(action: () => unknown, code: VaultAssetPolicyError['code']): void {
  try {
    action();
    throw new Error('expected VaultAssetPolicyError');
  } catch (error) {
    expect(error).toBeInstanceOf(VaultAssetPolicyError);
    expect((error as VaultAssetPolicyError).code).toBe(code);
  }
}

function rebindPlan(
  item: B3Case,
  mutate: (plan: Omit<VaultUnsignedPlanV1, 'planDigest'>) => void,
): B3Case {
  const mutable = clone(item.plan);
  const { planDigest: _digest, ...withoutDigest } = mutable;
  void _digest;
  mutate(withoutDigest);
  const plan = finalizeVaultUnsignedPlan(withoutDigest);
  return {
    ...item,
    plan,
    evidence: { ...clone(item.evidence), planId: plan.planId, planDigest: plan.planDigest },
  };
}

describe('ADR 0007 B3 deterministic Vault asset-policy vectors', () => {
  it.each(['mainnet', 'signet'] as const)(
    'accepts ordinary BTC, multi-input fee funding, whole-UTXO inscription, RBF, and CPFP on %s',
    (network) => {
      expect(vectors.vectorVersion).toBe(1);
      const record = vectors.records[network];
      expect(record.policyId).toBe(policy(network).policyId);
      for (const [name, item] of Object.entries(record.cases)) {
        const result = validate(network, item);
        expect(result).toEqual(item.validation);
        expect(result.planDigest).toBe(item.plan.planDigest);
        expect(result.psbtHash).toMatch(/^[0-9a-f]{64}$/u);
        if (name === 'inscription') {
          expect(result).toMatchObject({ movement: 'inscription', protectedOutputIndex: 0 });
        }
      }
      expect(record.cases.ordinary.validation?.cpfpCandidateOutputIndexes).toEqual([1]);
      expect(record.cases.inscription.validation?.cpfpCandidateOutputIndexes).toEqual([1]);
      expect(record.cases.cpfp.validation).toMatchObject({ replacement: 'cpfp', movement: 'cardinal' });
    },
  );

  it.each(['mainnet', 'signet'] as const)('replays every stable %s adversarial B3 vector', (network) => {
    for (const item of Object.values(vectors.records[network].adversarial)) {
      expect(item.expectedError).toBeDefined();
      expectPolicyError(() => validate(network, item), item.expectedError!);
    }
  });

  it('pins SQVE evidence hashes and strict evidence parsing', () => {
    const item = vectors.records.signet.cases.inscription;
    for (const evidence of item.evidence.inputs) {
      expect(computeVaultInputAssetEvidenceHash(evidence)).toBe(evidence.evidenceHash);
      expect(vaultInputAssetEvidenceSchema.parse(evidence)).toEqual(evidence);
    }
    expect(vaultAssetPolicyEvidenceSchema.parse(item.evidence)).toEqual(item.evidence);
    expect(() => vaultAssetPolicyEvidenceSchema.parse({ ...item.evidence, remotePolicy: 'allow' })).toThrow();
    expect(() => vaultAssetPolicyEvidenceSchema.parse({
      ...item.evidence,
      capabilities: [...VAULT_FULL_SAT_SAFETY_CAPABILITIES, 'broadcast'],
    })).toThrow();
  });

  it.each([
    ['malformed text', 'many', false],
    ['negative', '-1', false],
    ['u64 overflow', '18446744073709551616', false],
    ['zero boundary', '0', true],
    ['u64 maximum boundary', '18446744073709551615', true],
    ['ordinary valid value', '21000', true],
  ] as const)('returns a typed result for %s asset value', (_case, valueSats, success) => {
    const candidate = { ...vectors.records.signet.cases.ordinary.evidence.inputs[0]!, valueSats };
    expect(() => vaultInputAssetEvidenceSchema.safeParse(candidate)).not.toThrow();
    expect(vaultInputAssetEvidenceSchema.safeParse(candidate).success).toBe(success);
  });
});

describe('ADR 0007 B3 mandatory safe signing boundary', () => {
  it('revalidates B0 digest, B2 PSBT meaning, and B3 evidence before two-role signing/finalization', () => {
    const network = 'signet';
    const item = vectors.records[network].cases.inscription;
    const roots = [fixtureRoot(network, 'desktop-a'), fixtureRoot(network, 'mobile-b')];
    try {
      const results = (['desktop-a', 'mobile-b'] as const).map((role, index) => {
        const request = createVaultAssetSafePartialSignatureInput({
          policy: policy(network), plan: item.plan, role, psbtHex: item.psbtHex,
          evidence: item.evidence, nowMs: '1785542402000',
        });
        return signVaultAssetSafePartialSignature({
          policy: policy(network), plan: item.plan, request, signerRoot: roots[index]!,
          evidence: item.evidence, nowMs: '1785542402000',
        });
      });
      const combined = combineVaultAssetSafePartialSignatureResults({
        policy: policy(network), plan: item.plan, results,
        evidence: item.evidence, nowMs: '1785542402000',
      });
      const finalized = finalizeVaultAssetSafePsbt({
        policy: policy(network), plan: item.plan, psbtHex: combined.psbtHex,
        evidence: item.evidence, nowMs: '1785542402000',
      });
      expect(finalized.roles).toEqual(['desktop-a', 'mobile-b']);
      expect(finalized.vsize).toBeLessThanOrEqual(item.plan.vsize);
      expect(combined.psbtHex).toBe(item.aPlusB?.combinedPsbtHex);
      expect(combined.psbtHash).toBe(item.aPlusB?.combinedPsbtHash);
      expect(finalized).toEqual(item.aPlusB?.finalized);
    } finally {
      roots.forEach((root) => root.wipePrivateData());
    }
  });

  it('never reaches a signing root with stale or conflicting evidence', () => {
    const item = vectors.records.signet.cases.ordinary;
    const root = fixtureRoot('signet', 'desktop-a');
    try {
      const request = createVaultAssetSafePartialSignatureInput({
        policy: policy('signet'), plan: item.plan, role: 'desktop-a', psbtHex: item.psbtHex,
        evidence: item.evidence, nowMs: '1785542402000',
      });
      expectPolicyError(() => signVaultAssetSafePartialSignature({
        policy: policy('signet'), plan: item.plan, request, signerRoot: root,
        evidence: { ...item.evidence, ordTip: { ...item.evidence.ordTip, hash: 'ff'.repeat(32) } },
        nowMs: '1785542402000',
      }), 'conflicting_source');
    } finally {
      root.wipePrivateData();
    }
  });

  it('binds signing to the exact B3-validated plan when two plans share unsigned transaction bytes', () => {
    const item = vectors.records.signet.cases.ordinary;
    const alternative = rebindPlan(item, (plan) => {
      plan.planId = 'ab'.repeat(16);
      plan.requestId = 'cd'.repeat(16);
    });
    const request = createVaultAssetSafePartialSignatureInput({
      policy: policy('signet'),
      plan: alternative.plan,
      role: 'desktop-a',
      psbtHex: alternative.psbtHex,
      evidence: alternative.evidence,
      nowMs: '1785542402000',
    });
    expect(alternative.plan.unsignedTransactionHex).toBe(item.plan.unsignedTransactionHex);
    expect(alternative.plan.planDigest).not.toBe(item.plan.planDigest);
    const root = fixtureRoot('signet', 'desktop-a');
    try {
      expectPolicyError(() => signVaultAssetSafePartialSignature({
        policy: policy('signet'),
        plan: item.plan,
        request,
        signerRoot: root,
        evidence: item.evidence,
        nowMs: '1785542402000',
      }), 'input_binding_mismatch');
    } finally {
      root.wipePrivateData();
    }
  });
});

describe('ADR 0007 B3 property and adversarial safety invariants', () => {
  it('rejects every mutated protected offset or silently reduced postage', () => {
    const base = vectors.records.signet.cases.inscription;
    fc.assert(fc.property(
      fc.record({ offsetDelta: fc.integer({ min: 1, max: 10_000 }), postageDelta: fc.integer({ min: 1, max: 20_999 }) }),
      ({ offsetDelta, postageDelta }) => {
        const changedOffset = rebindPlan(base, (plan) => {
          plan.assetEffects[0]!.outputOffsetSats = (123n + BigInt(offsetDelta)).toString();
        });
        expectPolicyError(() => validate('signet', changedOffset), 'inscription_policy');
        const reducedPostage = rebindPlan(base, (plan) => {
          plan.assetEffects[0]!.postageSats = (21_000n - BigInt(postageDelta)).toString();
        });
        expectPolicyError(() => validate('signet', reducedPostage), 'inscription_policy');
      },
    ), { numRuns: 20 });
  }, 15_000);

  it('rejects every degraded, incomplete, suspicious, rare, unsupported, or co-located evidence mutation', () => {
    const base = vectors.records.signet.cases.inscription;
    const mutation = fc.constantFrom(
      'degraded', 'incomplete', 'sat-incomplete', 'frozen', 'dust', 'rare', 'unsupported', 'co-located',
      'unconfirmed-protected',
    );
    fc.assert(fc.property(mutation, (kind) => {
      const evidence = clone(base.evidence);
      const source = evidence.inputs[0]!;
      if (kind === 'degraded') source.confidence = 'degraded';
      if (kind === 'incomplete') source.classificationComplete = false;
      if (kind === 'sat-incomplete') source.satRangesComplete = false;
      if (kind === 'frozen') source.userFrozen = true;
      if (kind === 'dust') source.dustQuarantined = true;
      if (kind === 'rare') source.rareSatDetected = true;
      if (kind === 'unsupported') source.unsupportedAssetDetected = true;
      if (kind === 'co-located') source.inscriptions.push({ inscriptionId: `${'ab'.repeat(32)}i0`, offsetSats: '456' });
      if (kind === 'unconfirmed-protected') {
        source.confirmations = 0;
        source.walletCreatedUnconfirmedChange = true;
      }
      const { evidenceHash: _hash, ...withoutHash } = source;
      void _hash;
      evidence.inputs[0] = finalizeVaultInputAssetEvidence(withoutHash);
      const rebound = rebindPlan({ ...base, evidence }, (plan) => {
        plan.inputs[0]!.classificationEvidenceHash = evidence.inputs[0]!.evidenceHash;
      });
      rebound.evidence.inputs = evidence.inputs;
      expectPolicyError(
        () => validate('signet', rebound),
        ['co-located', 'unconfirmed-protected'].includes(kind) ? 'inscription_policy' : 'unsupported_classification',
      );
    }), { numRuns: 80 });
  });

  it('rejects retained digests, evidence hashes, and PSBT bytes after any ordered-plan mutation', () => {
    const base = vectors.records.signet.cases.inscription;
    const changed = clone(base);
    changed.plan.inputs.reverse();
    expectPolicyError(() => validate('signet', changed), 'invalid_evidence');

    const changedEvidence = clone(base);
    changedEvidence.evidence.inputs[0]!.evidenceHash = '00'.repeat(32);
    expectPolicyError(() => validate('signet', changedEvidence), 'input_binding_mismatch');

    const changedPsbt = clone(base);
    changedPsbt.psbtHex = vectors.records.signet.cases.ordinary.psbtHex;
    expect(() => validate('signet', changedPsbt)).toThrow(/PSBT|transaction/u);
  });

  it('requires RBF to be a distinct two-role plan and CPFP to spend only the exact clean parent change', () => {
    const { rbf, cpfp, inscription } = vectors.records.signet.cases;
    expectPolicyError(() => validate('signet', { ...rbf, previousPlan: rbf.plan }), 'rbf_policy');
    const { previousPlan: _previousPlan, ...rbfWithoutPrevious } = rbf;
    void _previousPlan;
    expectPolicyError(() => validate('signet', rbfWithoutPrevious), 'rbf_policy');

    expectPolicyError(() => validate('signet', {
      ...cpfp,
      previousPlan: vectors.records.signet.cases.multiInput.plan,
    }), 'cpfp_policy');

    const inscriptionRbf = rebindPlan(inscription, (plan) => {
      plan.replacement = { kind: 'rbf', replacesTxid: '11'.repeat(32), parentTxid: null };
    });
    expectPolicyError(() => validate('signet', { ...inscriptionRbf, previousPlan: inscription.plan }), 'rbf_policy');
  });

  it('requires RBF to increase the absolute fee and stay within the shared maximum fee rate', () => {
    const base = vectors.records.signet.cases.rbf;
    const previous = base.previousPlan!;
    const sameFee = rebindPlan(base, (plan) => {
      plan.unsignedTransactionHex = previous.unsignedTransactionHex;
      plan.outputs = clone(previous.outputs);
      plan.changeSats = previous.changeSats;
      plan.feeSats = previous.feeSats;
      plan.vsize = previous.vsize;
      plan.feeRateSatPerKvB = previous.feeRateSatPerKvB;
    });
    sameFee.psbtHex = constructVaultPsbt(policy('signet'), sameFee.plan);
    expectPolicyError(() => validate('signet', sameFee), 'rbf_policy');

    const excessiveRate = rebindPlan(base, (plan) => {
      plan.feeRateSatPerKvB = (BigInt(MAX_FEE_RATE_SAT_PER_KVB) + 1n).toString();
    });
    expectPolicyError(() => validate('signet', excessiveRate), 'rbf_policy');
  });

  it('rejects an appended RBF input that spends an output of the replaced transaction', () => {
    const base = vectors.records.signet.cases.rbf;
    const previous = base.previousPlan!;
    const replacedTxid = base.plan.replacement.replacesTxid!;
    const parentOutput = previous.outputs[1]!;
    const ownership = deriveVaultOutput(policy('signet'), 'change', parentOutput.derivationIndex!);
    const secondEvidenceSource = {
      ...clone(base.evidence.inputs[0]!),
      inputIndex: 1,
      txid: replacedTxid,
      vout: 1,
      valueSats: parentOutput.valueSats,
      scriptPubKeyHex: parentOutput.scriptPubKeyHex,
      confirmations: 0,
      walletCreatedUnconfirmedChange: true,
    };
    const { evidenceHash: _evidenceHash, ...secondEvidenceWithoutHash } = secondEvidenceSource;
    void _evidenceHash;
    const secondEvidence = finalizeVaultInputAssetEvidence(secondEvidenceWithoutHash);
    const secondInput: VaultUnsignedPlanV1['inputs'][number] = {
      ...clone(base.plan.inputs[0]!),
      txid: replacedTxid,
      vout: 1,
      valueSats: parentOutput.valueSats,
      scriptPubKeyHex: parentOutput.scriptPubKeyHex,
      witnessScriptHex: ownership.witnessScriptHex,
      branch: 'change',
      derivationIndex: parentOutput.derivationIndex!,
      classificationEvidenceHash: secondEvidence.evidenceHash,
    };
    const inputs = [...clone(base.plan.inputs), secondInput];
    const raw = new Transaction({ version: 2 });
    for (const input of inputs) raw.addInput({ txid: input.txid, index: input.vout, sequence: input.sequence });
    for (const output of base.plan.outputs) {
      raw.addOutput({ script: hexToBytes(output.scriptPubKeyHex), amount: BigInt(output.valueSats) });
    }
    const sized = Transaction.fromRaw(raw.unsignedTx);
    for (const [index, input] of inputs.entries()) {
      sized.updateInput(index, { finalScriptWitness: [
        new Uint8Array(), new Uint8Array(72), new Uint8Array(72), hexToBytes(input.witnessScriptHex),
      ] }, true);
    }
    const inputTotal = inputs.reduce((sum, input) => sum + BigInt(input.valueSats), 0n);
    const outputTotal = base.plan.outputs.reduce((sum, output) => sum + BigInt(output.valueSats), 0n);
    const fee = inputTotal - outputTotal;
    const { planDigest: _digest, ...withoutDigest } = clone(base.plan);
    void _digest;
    const plan = finalizeVaultUnsignedPlan({
      ...withoutDigest,
      unsignedTransactionHex: bytesToHex(raw.unsignedTx),
      inputs,
      feeSats: fee.toString(),
      vsize: sized.vsize,
      feeRateSatPerKvB: ((fee * 1000n + BigInt(sized.vsize) - 1n) / BigInt(sized.vsize)).toString(),
      assetEffects: [
        ...clone(base.plan.assetEffects),
        { ...clone(base.plan.assetEffects[0]!), inputIndex: 1 },
      ],
    });
    const item: B3Case = {
      ...base,
      plan,
      psbtHex: constructVaultPsbt(policy('signet'), plan),
      evidence: {
        ...clone(base.evidence),
        planId: plan.planId,
        planDigest: plan.planDigest,
        inputs: [clone(base.evidence.inputs[0]!), secondEvidence],
      },
    };
    expectPolicyError(() => validate('signet', item), 'rbf_policy');
  });

  it('rejects a previous plan whose raw bytes do not exactly equal its unsigned reserialization', () => {
    const base = vectors.records.signet.cases.rbf;
    const previous = base.previousPlan!;
    const transaction = Transaction.fromRaw(hexToBytes(previous.unsignedTransactionHex));
    transaction.updateInput(0, { finalScriptWitness: [new Uint8Array(), Uint8Array.of(1)] }, true);
    const { planDigest: _digest, ...withoutDigest } = clone(previous);
    void _digest;
    const nonCanonicalPrevious = finalizeVaultUnsignedPlan({
      ...withoutDigest,
      unsignedTransactionHex: bytesToHex(transaction.toBytes(true, true)),
    });
    expectPolicyError(() => validate('signet', {
      ...base,
      previousPlan: nonCanonicalPrevious,
    }), 'input_binding_mismatch');
  });
});
