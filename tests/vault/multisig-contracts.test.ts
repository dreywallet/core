import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { beforeAll, describe, expect, it } from 'vitest';
import { installTestCryptoProvider } from '../helpers/install-crypto-provider';
import { bytesToHex, hexToBytes } from '../../src/domain/vault/encoding';
import {
  descriptorChecksum,
  vaultPairingEnvelopeSchema,
  vaultPolicyIdentitySchema,
  vaultProofOfPossessionInputSchema,
  vaultPsbtApprovalEnvelopeSchema,
  vaultSignerOriginSchema,
  vaultUnsignedPlanSchema,
  type VaultBranchDerivationV1,
  type VaultPairingEnvelopeV1,
  type VaultPartialSignatureInputV1,
  type VaultPartialSignatureResultV1,
  type VaultPolicyIdentityV1,
  type VaultPolicyMetadataV1,
  type VaultPolicyRecordV1,
  type VaultProofOfPossessionInputV1,
  type VaultProofOfPossessionResultV1,
  type VaultPsbtApprovalEnvelopeV1,
  type VaultRecoveryKitV1,
  type VaultSignerOriginV1,
  type VaultUnsignedPlanV1,
} from '../../src/domain/vault/multisig-contracts';
import {
  assertVaultPartialSignatureResult,
  assertVaultPolicyIdentity,
  assertVaultUnsignedPlan,
  canonicalVaultPlanBytes,
  canonicalVaultPolicyBytes,
  computeVaultPlanDigest,
  computeVaultPolicyId,
  finalizeVaultPolicyIdentity,
  finalizeVaultUnsignedPlan,
  parseCanonicalVaultPlan,
  parseCanonicalVaultPolicy,
  parseVaultBranchDerivation,
  parseVaultPairingEnvelope,
  parseVaultPartialSignatureInput,
  parseVaultPartialSignatureResult,
  parseVaultPolicyRecord,
  parseVaultProofInput,
  parseVaultProofResult,
  parseVaultPsbtApprovalEnvelope,
  parseVaultRecoveryKit,
  parseVaultSignerOrigin,
  serializeVaultBranchDerivation,
  serializeVaultPairingEnvelope,
  serializeVaultPartialSignatureInput,
  serializeVaultPartialSignatureResult,
  serializeVaultPolicyRecord,
  serializeVaultProofInput,
  serializeVaultProofResult,
  serializeVaultPsbtApprovalEnvelope,
  serializeVaultRecoveryKit,
  serializeVaultSignerOrigin,
  verifyVaultProofOfPossession,
  verifyVaultPairingEnvelopeAuthentication,
  verifyVaultPsbtApprovalEnvelopeAuthentication,
} from '../../src/domain/vault/multisig-encoding';

interface VectorBytes {
  signerOriginHex: string;
  proofInputHex: string;
  proofResultHex: string;
  canonicalPolicyHex: string;
  policyRecordHex: string;
  branchReceive0Hex: string;
  canonicalPlanHex: string;
  partialInputHex: string;
  partialResultHex: string;
  recoveryKitHex: string;
  pairingEnvelopeHex: string;
  approvalEnvelopeHex: string;
}

interface VectorRecord {
  network: 'mainnet' | 'signet';
  signers: [VaultSignerOriginV1, VaultSignerOriginV1, VaultSignerOriginV1];
  proofInput: VaultProofOfPossessionInputV1;
  proofResult: VaultProofOfPossessionResultV1;
  policy: VaultPolicyIdentityV1;
  metadata: VaultPolicyMetadataV1;
  policyRecord: VaultPolicyRecordV1;
  branchReceive0: VaultBranchDerivationV1;
  plan: VaultUnsignedPlanV1;
  partialInput: VaultPartialSignatureInputV1;
  partialResult: VaultPartialSignatureResultV1;
  recoveryKit: VaultRecoveryKitV1;
  pairing: VaultPairingEnvelopeV1;
  approval: VaultPsbtApprovalEnvelopeV1;
  bytes: VectorBytes;
  negativeBinary: Record<string, string>;
}

const vectors = JSON.parse(
  readFileSync(join(import.meta.dirname, '..', '..', 'vectors', 'vault-contracts-v1.json'), 'utf8'),
) as { vectorVersion: number; records: { mainnet: VectorRecord; signet: VectorRecord } };

beforeAll(() => installTestCryptoProvider());

function canonicalDescriptorMutation(descriptor: string, oldXpub: string, foreignXpub: string): string {
  const payload = descriptor.slice(0, descriptor.lastIndexOf('#')).replace(oldXpub, foreignXpub);
  return `${payload}#${descriptorChecksum(payload)}`;
}

describe('ADR 0007 B0 deterministic Vault contracts', () => {
  it('matches the published BIP380 descriptor checksum vector', () => {
    expect(descriptorChecksum('raw(deadbeef)')).toBe('89f8spxm');
  });

  it.each(['mainnet', 'signet'] as const)('pins every %s record byte-for-byte and round-trips canonically', (network) => {
    const vector = vectors.records[network];
    expect(vectors.vectorVersion).toBe(1);

    expect(bytesToHex(serializeVaultSignerOrigin(vector.signers[0]))).toBe(vector.bytes.signerOriginHex);
    expect(parseVaultSignerOrigin(hexToBytes(vector.bytes.signerOriginHex))).toEqual(vector.signers[0]);
    expect(bytesToHex(serializeVaultProofInput(vector.proofInput))).toBe(vector.bytes.proofInputHex);
    expect(parseVaultProofInput(hexToBytes(vector.bytes.proofInputHex))).toEqual(vector.proofInput);
    expect(bytesToHex(serializeVaultProofResult(vector.proofResult))).toBe(vector.bytes.proofResultHex);
    expect(parseVaultProofResult(hexToBytes(vector.bytes.proofResultHex))).toEqual(vector.proofResult);

    expect(bytesToHex(canonicalVaultPolicyBytes(vector.policy))).toBe(vector.bytes.canonicalPolicyHex);
    expect(parseCanonicalVaultPolicy(hexToBytes(vector.bytes.canonicalPolicyHex))).toEqual(vector.policy);
    expect(bytesToHex(serializeVaultPolicyRecord(vector.policyRecord))).toBe(vector.bytes.policyRecordHex);
    expect(parseVaultPolicyRecord(hexToBytes(vector.bytes.policyRecordHex))).toEqual(vector.policyRecord);
    expect(bytesToHex(serializeVaultBranchDerivation(vector.branchReceive0))).toBe(vector.bytes.branchReceive0Hex);
    expect(parseVaultBranchDerivation(hexToBytes(vector.bytes.branchReceive0Hex))).toEqual(vector.branchReceive0);

    expect(bytesToHex(canonicalVaultPlanBytes(vector.plan))).toBe(vector.bytes.canonicalPlanHex);
    expect(parseCanonicalVaultPlan(hexToBytes(vector.bytes.canonicalPlanHex))).toEqual(vector.plan);
    expect(bytesToHex(serializeVaultPartialSignatureInput(vector.partialInput))).toBe(vector.bytes.partialInputHex);
    expect(parseVaultPartialSignatureInput(hexToBytes(vector.bytes.partialInputHex))).toEqual(vector.partialInput);
    expect(bytesToHex(serializeVaultPartialSignatureResult(vector.partialResult))).toBe(vector.bytes.partialResultHex);
    expect(parseVaultPartialSignatureResult(hexToBytes(vector.bytes.partialResultHex))).toEqual(vector.partialResult);
    expect(bytesToHex(serializeVaultRecoveryKit(vector.recoveryKit))).toBe(vector.bytes.recoveryKitHex);
    expect(parseVaultRecoveryKit(hexToBytes(vector.bytes.recoveryKitHex))).toEqual(vector.recoveryKit);
    expect(bytesToHex(serializeVaultPairingEnvelope(vector.pairing))).toBe(vector.bytes.pairingEnvelopeHex);
    expect(parseVaultPairingEnvelope(hexToBytes(vector.bytes.pairingEnvelopeHex))).toEqual(vector.pairing);
    expect(bytesToHex(serializeVaultPsbtApprovalEnvelope(vector.approval))).toBe(vector.bytes.approvalEnvelopeHex);
    expect(parseVaultPsbtApprovalEnvelope(hexToBytes(vector.bytes.approvalEnvelopeHex))).toEqual(vector.approval);
  });

  it.each(['mainnet', 'signet'] as const)('keeps %s hashes stable across parse/serialize cycles', (network) => {
    const vector = vectors.records[network];
    const parsedPolicy = parseCanonicalVaultPolicy(canonicalVaultPolicyBytes(vector.policy));
    const parsedPlan = parseCanonicalVaultPlan(canonicalVaultPlanBytes(vector.plan));
    expect(computeVaultPolicyId(parsedPolicy)).toBe(vector.policy.policyId);
    expect(computeVaultPlanDigest(parsedPlan)).toBe(vector.plan.planDigest);
    expect(bytesToHex(canonicalVaultPolicyBytes(parsedPolicy))).toBe(vector.bytes.canonicalPolicyHex);
    expect(bytesToHex(canonicalVaultPlanBytes(parsedPlan))).toBe(vector.bytes.canonicalPlanHex);
  });

  it('verifies proof of possession against the complete origin xpub, challenge, and expiry', () => {
    const { proofInput, proofResult } = vectors.records.signet;
    expect(verifyVaultProofOfPossession(proofInput, proofResult, '1785542699999')).toBe(true);
    expect(verifyVaultProofOfPossession(proofInput, proofResult, '1785542700001')).toBe(false);
    expect(verifyVaultProofOfPossession(
      { ...proofInput, transcriptHashHex: 'ff'.repeat(32) }, proofResult,
    )).toBe(false);
    expect(verifyVaultProofOfPossession(
      proofInput, { ...proofResult, proofPublicKeyHex: vectors.records.signet.proofResult.proofPublicKeyHex.replace(/^../u, '03') },
    )).toBe(false);
  });

  it.each(['mainnet', 'signet'] as const)('authenticates every %s QR envelope field with the sender origin', (network) => {
    const vector = vectors.records[network];
    const sender = vector.signers[0];
    expect(verifyVaultPairingEnvelopeAuthentication(vector.pairing, sender)).toBe(true);
    expect(verifyVaultPsbtApprovalEnvelopeAuthentication(vector.approval, sender)).toBe(true);
    expect(verifyVaultPairingEnvelopeAuthentication({
      ...vector.pairing,
      counter: String(BigInt(vector.pairing.counter) + 1n),
    }, sender)).toBe(false);
    expect(verifyVaultPsbtApprovalEnvelopeAuthentication({
      ...vector.approval,
      antiReplayNonceHex: 'ff'.repeat(32),
    }, sender)).toBe(false);
    expect(verifyVaultPairingEnvelopeAuthentication({
      ...vector.pairing,
      senderOriginHex: bytesToHex(serializeVaultSignerOrigin(vector.signers[1])),
    })).toBe(false);
    expect(verifyVaultPsbtApprovalEnvelopeAuthentication(vector.approval, vector.signers[1])).toBe(false);
  });

  it.each([
    ['malformed text', 'soon', false],
    ['empty text', '', false],
    ['negative', '-1', false],
    ['leading zero', '01', false],
    ['u64 overflow', '18446744073709551616', false],
    ['zero boundary', '0', true],
    ['u64 maximum boundary', '18446744073709551615', true],
    ['ordinary valid value', '1785542700000', true],
  ] as const)('returns a typed result for %s u64 input', (_case, expiresAtMs, success) => {
    const candidate = { ...vectors.records.signet.proofInput, expiresAtMs };
    expect(() => vaultProofOfPossessionInputSchema.safeParse(candidate)).not.toThrow();
    expect(vaultProofOfPossessionInputSchema.safeParse(candidate).success).toBe(success);
  });

  it('excludes creation, birthday, labels, and presentation metadata from policyId', () => {
    const { policy } = vectors.records.mainnet;
    const rebuilt = finalizeVaultPolicyIdentity({
      version: 1, policyVersion: 1, network: policy.network, threshold: 2,
      signers: policy.signers, receiveDescriptor: policy.receiveDescriptor, changeDescriptor: policy.changeDescriptor,
    });
    expect(rebuilt.policyId).toBe(policy.policyId);
    const recordA = { version: 1 as const, identity: policy, metadata: vectors.records.mainnet.metadata };
    const recordB = {
      ...recordA,
      metadata: {
        ...recordA.metadata,
        createdAtMs: '1',
        birthdayHeight: null,
        vaultLabel: 'renamed',
        signerLabels: ['', '', ''] as [string, string, string],
      },
    };
    expect(parseVaultPolicyRecord(serializeVaultPolicyRecord(recordA)).identity.policyId).toBe(
      parseVaultPolicyRecord(serializeVaultPolicyRecord(recordB)).identity.policyId,
    );
  });

  it('rejects reordered/duplicate roles, duplicate or foreign keys, wrong network, and wrong origin', () => {
    const mainnet = vectors.records.mainnet;
    const signet = vectors.records.signet;
    expect(vaultPolicyIdentitySchema.safeParse({
      ...mainnet.policy, signers: [mainnet.signers[1], mainnet.signers[0], mainnet.signers[2]],
    }).success).toBe(false);
    expect(vaultPolicyIdentitySchema.safeParse({
      ...mainnet.policy, signers: [mainnet.signers[0], mainnet.signers[0], mainnet.signers[2]],
    }).success).toBe(false);
    const duplicateKey = {
      ...mainnet.signers[1], masterFingerprintHex: mainnet.signers[0].masterFingerprintHex,
      accountXpub: mainnet.signers[0].accountXpub,
    };
    expect(vaultPolicyIdentitySchema.safeParse({
      ...mainnet.policy, signers: [mainnet.signers[0], duplicateKey, mainnet.signers[2]],
    }).success).toBe(false);
    expect(vaultPolicyIdentitySchema.safeParse({
      ...mainnet.policy,
      receiveDescriptor: canonicalDescriptorMutation(
        mainnet.policy.receiveDescriptor, mainnet.signers[0].accountXpub, signet.signers[0].accountXpub,
      ),
    }).success).toBe(false);
    expect(vaultPolicyIdentitySchema.safeParse({ ...mainnet.policy, network: 'signet' }).success).toBe(false);
    expect(vaultSignerOriginSchema.safeParse({ ...mainnet.signers[0], originPath: "m/48'/0'/1'/2'" }).success).toBe(false);
    expect(vaultSignerOriginSchema.safeParse({
      ...mainnet.signers[0], network: 'signet', originPath: "m/48'/1'/0'/2'",
    }).success).toBe(false);
  });

  it('rejects unknown fields, versions, policies, roles, sighashes, and signing-meaning enums', () => {
    const vector = vectors.records.signet;
    expect(vaultSignerOriginSchema.safeParse({ ...vector.signers[0], futureRoleRule: true }).success).toBe(false);
    expect(vaultSignerOriginSchema.safeParse({ ...vector.signers[0], version: 0 }).success).toBe(false);
    expect(vaultPolicyIdentitySchema.safeParse({ ...vector.policy, policyVersion: 2 }).success).toBe(false);
    expect(vaultUnsignedPlanSchema.safeParse({ ...vector.plan, sighash: 'single' }).success).toBe(false);
    expect(vaultUnsignedPlanSchema.safeParse({ ...vector.plan, kind: 'deposit' }).success).toBe(false);
    expect(vaultPairingEnvelopeSchema.safeParse({ ...vector.pairing, messageType: 'relay-policy' }).success).toBe(false);
    expect(vaultPsbtApprovalEnvelopeSchema.safeParse({ ...vector.approval, stage: 'finalized' }).success).toBe(false);
  });

  it('rejects duplicate plan outpoints during finalization and canonical parsing', () => {
    const { plan } = vectors.records.signet;
    const { planDigest: _digest, ...base } = plan;
    void _digest;
    expect(() => finalizeVaultUnsignedPlan({
      ...base,
      inputs: [base.inputs[0]!, { ...base.inputs[0]! }],
    })).toThrow('duplicate plan outpoint');

    const distinctTxid = 'ab'.repeat(32);
    const distinctVout = 1;
    const encodable = finalizeVaultUnsignedPlan({
      ...base,
      inputs: [base.inputs[0]!, { ...base.inputs[0]!, txid: distinctTxid, vout: distinctVout }],
    });
    const canonicalHex = bytesToHex(canonicalVaultPlanBytes(encodable));
    const distinctOutpointHex = `${distinctTxid}${distinctVout.toString(16).padStart(8, '0')}`;
    const duplicateOutpointHex = `${base.inputs[0]!.txid}${base.inputs[0]!.vout.toString(16).padStart(8, '0')}`;
    expect(canonicalHex.split(distinctOutpointHex)).toHaveLength(2);
    expect(() => parseCanonicalVaultPlan(hexToBytes(
      canonicalHex.replace(distinctOutpointHex, duplicateOutpointHex),
    ))).toThrow('duplicate plan outpoint');
  });

  it('rejects descriptor/policy mutation and every plan mutation under retained identities', () => {
    const mainnet = vectors.records.mainnet;
    const signet = vectors.records.signet;
    const mutatedDescriptor = canonicalDescriptorMutation(
      mainnet.policy.receiveDescriptor, mainnet.signers[0].accountXpub, signet.signers[0].accountXpub,
    );
    expect(() => assertVaultPolicyIdentity({ ...mainnet.policy, receiveDescriptor: mutatedDescriptor })).toThrow();
    expect(() => assertVaultPolicyIdentity({ ...mainnet.policy, threshold: 3 } as unknown as VaultPolicyIdentityV1)).toThrow();
    expect(() => assertVaultUnsignedPlan({ ...mainnet.plan, amountSats: '90001' })).toThrow('planDigest mismatch');
    expect(() => assertVaultUnsignedPlan({
      ...mainnet.plan, unsignedTransactionHex: `${mainnet.plan.unsignedTransactionHex.slice(0, -2)}01`,
    })).toThrow('planDigest mismatch');
    expect(() => assertVaultUnsignedPlan({
      ...mainnet.plan, source: { ...mainnet.plan.source, classificationRevisionHash: 'ff'.repeat(32) },
    })).toThrow('planDigest mismatch');
  });

  it('binds recovery exits and on-chain rotations as distinct compile-time plan meanings', () => {
    const { plan } = vectors.records.signet;
    const { planDigest: _digest, ...base } = plan;
    void _digest;
    const recovery = finalizeVaultUnsignedPlan({
      ...base,
      kind: 'recovery',
      outputs: base.outputs.map((output, index) => index === 0
        ? { ...output, purpose: 'recovery-exit' as const }
        : output),
      destination: {
        kind: 'recovery-exit', pairedSpendingWalletIdHash: null, targetPolicyId: null,
        address: base.destination.address, outputIndex: 0,
      },
    });
    expect(() => assertVaultUnsignedPlan(recovery)).not.toThrow();

    const rotation = finalizeVaultUnsignedPlan({
      ...base,
      kind: 'rotation',
      outputs: base.outputs.map((output, index) => index === 0
        ? { ...output, purpose: 'vault-rotation' as const }
        : output),
      destination: {
        kind: 'vault-policy', pairedSpendingWalletIdHash: null, targetPolicyId: 'ff'.repeat(32),
        address: base.destination.address, outputIndex: 0,
      },
    });
    expect(() => assertVaultUnsignedPlan(rotation)).not.toThrow();
    expect(recovery.planDigest).not.toBe(rotation.planDigest);
  });

  it('rejects malformed, downgraded, unknown-network, unknown-role, truncated, and trailing encodings', () => {
    for (const vector of Object.values(vectors.records)) {
      expect(() => parseCanonicalVaultPolicy(hexToBytes(vector.negativeBinary.unknownContractVersionPolicyHex!))).toThrow();
      expect(() => parseCanonicalVaultPolicy(hexToBytes(vector.negativeBinary.unknownNetworkPolicyHex!))).toThrow();
      expect(() => parseCanonicalVaultPolicy(hexToBytes(vector.negativeBinary.unknownRolePolicyHex!))).toThrow();
      expect(() => parseCanonicalVaultPolicy(hexToBytes(vector.negativeBinary.trailingPolicyHex!))).toThrow();
      expect(() => parseCanonicalVaultPlan(hexToBytes(vector.negativeBinary.truncatedPlanHex!))).toThrow();
      expect(() => parseCanonicalVaultPolicy(hexToBytes(`00${vector.bytes.canonicalPolicyHex.slice(2)}`))).toThrow();
    }
  });

  it('binds partial-signature and approval results to one expected logical role and exact bytes', () => {
    const vector = vectors.records.signet;
    expect(() => assertVaultPartialSignatureResult(vector.partialInput, vector.partialResult)).not.toThrow();
    expect(() => assertVaultPartialSignatureResult(
      vector.partialInput, { ...vector.partialResult, roleAdded: 'mobile-b' },
    )).toThrow('binding mismatch');
    expect(() => serializeVaultPartialSignatureInput({
      ...vector.partialInput, psbtHex: `${vector.partialInput.psbtHex}00`,
    })).toThrow('binding mismatch');
    expect(() => serializeVaultPartialSignatureResult({
      ...vector.partialResult, signedPsbtHex: `${vector.partialResult.signedPsbtHex}00`,
    })).toThrow('hash mismatch');
    expect(() => serializeVaultPsbtApprovalEnvelope({
      ...vector.approval, policyId: 'ff'.repeat(32),
    })).toThrow('binding mismatch');
  });
});
