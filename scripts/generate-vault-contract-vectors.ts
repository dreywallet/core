/**
 * ADR 0007 / B0 deterministic public-contract vectors.
 *
 * Private fixture material is deterministically generated in memory from
 * disposable labels and never written. Output is public test data only and
 * must never be funded.
 */
import { createHash } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { join } from 'node:path';
import { HDKey } from '@scure/bip32';
import { secp256k1 } from '@noble/curves/secp256k1';
import { Address, NETWORK, SigHash, TEST_NETWORK, Transaction, p2ms, p2wpkh, p2wsh } from '@scure/btc-signer';
import { setCryptoProvider, type CryptoProvider } from '../src/domain/vault/crypto-provider';
import { base64ToBytes, bytesToBase64, bytesToHex, hexToBytes } from '../src/domain/vault/encoding';
import { hkdfSha256 } from '../src/domain/vault/hkdf';
import {
  createPasskeyEnvelope, passkeyPrfEvalInput, unwrapPasskeyDek,
} from '../src/domain/vault/passkey-envelope';
import {
  VAULT_ROLES, bip32Versions, canonicalVaultDescriptor, vaultAccountOriginPath,
  type VaultPartialSignatureInputV1, type VaultPartialSignatureResultV1,
  type VaultPolicyMetadataV1, type VaultSignerOriginV1, type VaultSignerRole,
  type VaultUnsignedPlanV1,
} from '../src/domain/vault/multisig-contracts';
import {
  canonicalVaultPlanBytes, canonicalVaultPolicyBytes,
  finalizeVaultPolicyIdentity, finalizeVaultUnsignedPlan,
  signVaultPairingEnvelope, signVaultPsbtApprovalEnvelope,
  serializeVaultBranchDerivation, serializeVaultPairingEnvelope, serializeVaultPartialSignatureInput,
  serializeVaultPartialSignatureResult, serializeVaultPolicyRecord, serializeVaultProofInput,
  serializeVaultProofResult, serializeVaultPsbtApprovalEnvelope, serializeVaultRecoveryKit,
  serializeVaultSignerOrigin, vaultProofInputDigest, vaultPsbtHash,
  vaultTransportChannelId,
} from '../src/domain/vault/multisig-encoding';
import {
  combineVaultPartialSignatureResults,
  constructVaultPsbt,
  createVaultPartialSignatureInput,
  finalizeVaultPsbt,
  signVaultPartialSignature,
} from '../src/domain/vault/multisig-psbt';
import {
  deriveVaultOutput, parseCanonicalVaultPolicyDescriptors, validateVaultPolicyRecordDescriptors,
} from '../src/domain/vault/multisig-descriptors';
import {
  deriveProofPublicKeyHex, deriveVaultRoleOrigin, signVaultProofOfPossession,
} from '../src/domain/vault/multisig-role';
import {
  VAULT_FULL_SAT_SAFETY_CAPABILITIES,
  combineVaultAssetSafePartialSignatureResults,
  createVaultAssetSafePartialSignatureInput,
  finalizeVaultAssetSafePsbt,
  finalizeVaultInputAssetEvidence,
  signVaultAssetSafePartialSignature,
  validateVaultAssetPolicy,
  type VaultAssetPolicyEvidenceV1,
  type VaultInputAssetEvidenceV1,
} from '../src/domain/vault/multisig-asset-policy';
import { buildVaultCardinalWithdrawal } from '../src/domain/vault/multisig-planning';
import type { VaultEvidenceSourceV1, VaultUtxoV1 } from '../src/domain/vault/multisig-evidence';
import {
  completeVaultBroadcast,
  consumeVaultBroadcastAttempt,
  prepareVaultBroadcast,
} from '../src/domain/vault/multisig-lifecycle';
import {
  encodeVaultApprovalContextCbor,
  encodeVaultPairingContextCbor,
  encodeVaultPsbtCbor,
  vaultApprovalContextUrEncoder,
  vaultPairingContextUrEncoder,
  vaultPsbtUrEncoder,
} from '../src/domain/vault/multisig-qr';
import { deriveAccountNode, deriveAddress, type Network } from '../src/domain/keys/derivation';
import { scriptPubKeyHex } from '../src/domain/keys/script-hash';
import type { WalletUtxo } from '../src/domain/classification/types';
import {
  buildNativeSendCandidate,
  resolvePayableAddress,
  type NativeSendCandidateOutcome,
} from '../src/domain/transactions/native-send';
import type { PlanDerivation } from '../src/domain/transactions/plan';
import { analyzePsbtHex } from '../src/domain/transactions/analysis';
import { buildPsbtHex } from '../src/domain/transactions/signing';
import {
  derivePublicAccountAddress,
  publicAccountFromSeed,
} from '../src/domain/accounts/public-account';
import { encodeAccountDescriptor } from '../src/domain/accounts/public-account-interchange';
import { feeForVsize, parseCustomFeeRate } from '../src/domain/transactions/fees';

const sha256 = (bytes: Uint8Array): Uint8Array => new Uint8Array(createHash('sha256').update(bytes).digest());
const fixtureProvider: CryptoProvider = {
  argon2id: async () => { throw new Error('unused'); },
  // Independent XChaCha20-Poly1305 implementation on purpose: the passkey
  // envelope vectors are generated with @noble/ciphers here and verified
  // against the libsodium reference provider by the vitest suite, so a defect
  // in either implementation fails the golden vectors.
  xchaEncrypt: (plaintext, aad, nonce, key) => xchacha20poly1305(key, nonce, aad).encrypt(plaintext),
  xchaDecrypt: (box, aad, nonce, key) => xchacha20poly1305(key, nonce, aad).decrypt(box),
  sha256,
  ed25519Verify: () => { throw new Error('unused'); },
  randomBytes: () => { throw new Error('vectors never use runtime randomness'); },
};
setCryptoProvider(fixtureProvider);

const utf8 = (value: string): Uint8Array => new TextEncoder().encode(value);
const hashHex = (value: string): string => bytesToHex(sha256(utf8(value)));
const seed = (label: string): Uint8Array => sha256(utf8(`PUBLIC DISPOSABLE B0 FIXTURE ONLY:${label}`));
const fingerprintHex = (value: number): string => value.toString(16).padStart(8, '0');

function compareBytes(left: Uint8Array, right: Uint8Array): number {
  for (let index = 0; index < left.length; index += 1) {
    const difference = left[index]! - right[index]!;
    if (difference !== 0) return difference;
  }
  return left.length - right.length;
}

function domainHash(domain: string, bytes: Uint8Array): string {
  return bytesToHex(sha256(new Uint8Array([...utf8(domain), 0, ...bytes])));
}

function transactionId(rawUnsigned: string): string {
  return bytesToHex(Uint8Array.from(sha256(sha256(hexToBytes(rawUnsigned)))).reverse());
}

function roleFixture(network: Network, role: VaultSignerOriginV1['role'], label: string) {
  const root = HDKey.fromMasterSeed(seed(`${network}:${label}`), bip32Versions(network));
  const account = root.derive(vaultAccountOriginPath(network));
  const origin: VaultSignerOriginV1 = {
    version: 1, role, network, masterFingerprintHex: fingerprintHex(root.fingerprint),
    originPath: vaultAccountOriginPath(network), accountXpub: account.publicExtendedKey,
  };
  return { root, account, origin };
}

function compactSize(value: number): Uint8Array {
  if (value < 0xfd) return Uint8Array.of(value);
  throw new Error('fixture compactSize exceeds one byte');
}
function u32le(value: number): Uint8Array {
  const out = new Uint8Array(4); new DataView(out.buffer).setUint32(0, value, true); return out;
}
function u64le(value: bigint): Uint8Array {
  const out = new Uint8Array(8); new DataView(out.buffer).setBigUint64(0, value, true); return out;
}
function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) { out.set(part, offset); offset += part.length; }
  return out;
}
function rawUnsignedTransaction(
  txidDisplayHex: string, vout: number, sequence: number,
  outputs: readonly { script: Uint8Array; amount: bigint }[],
): Uint8Array {
  return concat(
    u32le(2), compactSize(1), Uint8Array.from(hexToBytes(txidDisplayHex)).reverse(), u32le(vout),
    Uint8Array.of(0), u32le(sequence), compactSize(outputs.length),
    ...outputs.flatMap((output) => [u64le(output.amount), compactSize(output.script.length), output.script]),
    u32le(0),
  );
}
function rawUnsignedTransactionMany(
  inputs: readonly { txid: string; vout: number; sequence: number }[],
  outputs: readonly { script: Uint8Array; amount: bigint }[],
): Uint8Array {
  return concat(
    u32le(2), compactSize(inputs.length),
    ...inputs.flatMap((input) => [
      Uint8Array.from(hexToBytes(input.txid)).reverse(), u32le(input.vout), Uint8Array.of(0), u32le(input.sequence),
    ]),
    compactSize(outputs.length),
    ...outputs.flatMap((output) => [u64le(output.amount), compactSize(output.script.length), output.script]),
    u32le(0),
  );
}
function mutateByte(hex: string, offset: number, byte: number): string {
  const bytes = hexToBytes(hex); bytes[offset] = byte; return bytesToHex(bytes);
}

function makeVector(network: Network) {
  const roles = [
    roleFixture(network, 'desktop-a', 'root-a'),
    roleFixture(network, 'mobile-b', 'root-b'),
    roleFixture(network, 'recovery-c', 'root-c'),
  ] as const;
  const signers = roles.map((entry) => entry.origin) as [VaultSignerOriginV1, VaultSignerOriginV1, VaultSignerOriginV1];
  const receiveDescriptor = canonicalVaultDescriptor(signers, 'receive');
  const changeDescriptor = canonicalVaultDescriptor(signers, 'change');
  const policy = finalizeVaultPolicyIdentity({
    version: 1, policyVersion: 1, network, threshold: 2, signers, receiveDescriptor, changeDescriptor,
  });
  const policyBytes = canonicalVaultPolicyBytes(policy);
  if (domainHash('drey-vault-policy-v1', policyBytes) !== policy.policyId) {
    throw new Error('independent policyId cross-check failed');
  }

  const metadata: VaultPolicyMetadataV1 = {
    version: 1, createdAtMs: '1785542400000', birthdayHeight: network === 'mainnet' ? 910_000 : 250_000,
    vaultLabel: `${network} public fixture vault`, signerLabels: ['Fixture Desktop', 'Fixture Mobile', 'Fixture Recovery'],
  };
  const policyRecord = { version: 1 as const, identity: policy, metadata };
  const proofInput = {
    version: 1 as const, origin: signers[0], sessionIdHex: hashHex(`${network}:session`).slice(0, 32),
    challengeNonceHex: hashHex(`${network}:challenge`), transcriptHashHex: hashHex(`${network}:transcript`),
    expiresAtMs: '1785542700000',
  };
  const proofDigest = vaultProofInputDigest(proofInput);
  const proofNode = roles[0].account.deriveChild(0).deriveChild(0);
  if (!proofNode.privateKey || !proofNode.publicKey) throw new Error('fixture proof key unavailable');
  const proofResult = {
    version: 1 as const, role: 'desktop-a' as const, inputDigestHex: proofDigest,
    proofPublicKeyHex: bytesToHex(proofNode.publicKey),
    signatureHex: bytesToHex(proofNode.sign(hexToBytes(proofDigest))),
    scheme: 'secp256k1-ecdsa-compact-low-s-v1' as const,
  };

  const net = network === 'mainnet' ? NETWORK : TEST_NETWORK;
  const receiveChildren = roles.map((entry) => entry.account.deriveChild(0).deriveChild(0).publicKey!);
  const changeChildren = roles.map((entry) => entry.account.deriveChild(1).deriveChild(1).publicKey!);
  const receivePayment = p2wsh(p2ms(2, [...receiveChildren].sort(compareBytes)), net);
  const changePayment = p2wsh(p2ms(2, [...changeChildren].sort(compareBytes)), net);
  const spendingRoot = HDKey.fromMasterSeed(seed(`${network}:independent-spending-s`), bip32Versions(network));
  const spendingKey = spendingRoot.derive(`m/84'/${network === 'mainnet' ? 0 : 1}'/0'/0/0`);
  if (!spendingKey.publicKey) throw new Error('fixture spending key unavailable');
  const destinationPayment = p2wpkh(spendingKey.publicKey, net);
  const prevTxid = hashHex(`${network}:synthetic-prevout`);
  const sequence = 0xffff_fffd;
  const outputs = [
    { script: destinationPayment.script, amount: 90_000n },
    { script: changePayment.script, amount: 9_000n },
  ];
  const unsignedTx = rawUnsignedTransaction(prevTxid, 0, sequence, outputs);
  const psbt = new Transaction({ lowR: true });
  psbt.addInput({
    txid: prevTxid, index: 0, sequence,
    witnessUtxo: { script: receivePayment.script, amount: 100_000n },
    witnessScript: receivePayment.witnessScript, sighashType: SigHash.ALL,
  });
  for (const output of outputs) psbt.addOutput(output);
  const unsignedPsbtHex = bytesToHex(psbt.toPSBT());
  const plan = finalizeVaultUnsignedPlan({
    version: 1, policyVersion: 1, network, policyId: policy.policyId,
    planId: hashHex(`${network}:plan`).slice(0, 32), requestId: hashHex(`${network}:request`).slice(0, 32),
    createdAtMs: '1785542401000', expiresAtMs: '1785542699000',
    kind: 'withdrawal', unsignedTransactionHex: bytesToHex(unsignedTx),
    inputs: [{
      txid: prevTxid, vout: 0, valueSats: '100000', scriptPubKeyHex: bytesToHex(receivePayment.script),
      witnessScriptHex: bytesToHex(receivePayment.witnessScript), branch: 'receive', derivationIndex: 0,
      sequence, sighash: 'all', classification: 'cardinal_clean',
      classificationEvidenceHash: hashHex(`${network}:input-0-classification`),
    }],
    outputs: [
      { outputIndex: 0, valueSats: '90000', scriptPubKeyHex: bytesToHex(destinationPayment.script),
        address: destinationPayment.address, purpose: 'paired-spending', branch: null, derivationIndex: null },
      { outputIndex: 1, valueSats: '9000', scriptPubKeyHex: bytesToHex(changePayment.script),
        address: changePayment.address, purpose: 'vault-change', branch: 'change', derivationIndex: 1 },
    ],
    destination: {
      kind: 'paired-spending',
      pairedSpendingWalletIdHash: hashHex(`${network}:spending-wallet-id`),
      targetPolicyId: null, address: destinationPayment.address, outputIndex: 0,
    },
    amountSats: '90000', changeSats: '9000', feeSats: '1000', vsize: 153,
    feeRateSatPerKvB: '6536', sighash: 'all',
    assetEffects: [{
      kind: 'cardinal', assetId: '', inputIndex: 0, inputOffsetSats: '0', outputIndex: 0,
      outputOffsetSats: '0', postageSats: '0', protected: false,
    }],
    source: {
      backendInstanceIdHash: hashHex(`${network}:backend-instance`),
      classificationRevisionHash: hashHex(`${network}:classification-revision`),
      coreTip: { height: network === 'mainnet' ? 910_000 : 250_000, hash: hashHex(`${network}:core-tip`) },
      indexTip: { height: network === 'mainnet' ? 910_000 : 250_000, hash: hashHex(`${network}:index-tip`) },
      observedAtMs: '1785542400000', validUntilMs: '1785542700000',
    },
    replacement: { kind: 'none', replacesTxid: null, parentTxid: null },
    broadcastIntent: 'broadcast',
  });
  const planBytes = canonicalVaultPlanBytes(plan);
  if (domainHash('drey-vault-plan-v1', planBytes) !== plan.planDigest) {
    throw new Error('independent planDigest cross-check failed');
  }
  const partialInput = {
    version: 1 as const, network, policyId: policy.policyId, planId: plan.planId, planDigest: plan.planDigest,
    role: 'desktop-a' as const, canonicalPlanHex: bytesToHex(planBytes), psbtHex: unsignedPsbtHex,
    psbtHash: vaultPsbtHash(unsignedPsbtHex),
  };
  const signer = roles[0].account.deriveChild(0).deriveChild(0);
  if (!signer.privateKey) throw new Error('fixture PSBT signer unavailable');
  psbt.signIdx(signer.privateKey, 0, [SigHash.ALL]);
  const signedPsbtHex = bytesToHex(psbt.toPSBT());
  const partialResult = {
    version: 1 as const, network, policyId: policy.policyId, planId: plan.planId, planDigest: plan.planDigest,
    roleAdded: 'desktop-a' as const, priorPsbtHash: partialInput.psbtHash, signedPsbtHex,
    signedPsbtHash: vaultPsbtHash(signedPsbtHex),
  };
  const recoveryKit = {
    version: 1 as const, network, policyVersion: 1 as const, policyId: policy.policyId, signers,
    receiveDescriptor, changeDescriptor, createdAtMs: metadata.createdAtMs, birthdayHeight: metadata.birthdayHeight,
    vaultLabel: metadata.vaultLabel, signerLabels: metadata.signerLabels, firstReceiveAddress: receivePayment.address,
    compatibilityRequirements: ['SQVB contract reader v1', 'BIP48 native P2WSH sortedmulti support', 'BIP174 PSBT v0'],
    minimumReaderVersion: 1 as const, standaloneToolSourceDigest: hashHex('standalone-tool-source-v1'),
    standaloneToolArtifactDigest: hashHex('standalone-tool-artifact-v1'),
    recoveryInstructions: 'Verify the policy ID and descriptors, then use two distinct valid roles to construct and review a recovery spend.',
    rotationInstructions: 'Create a fresh independent replacement root and policy, then move all assets on chain after complete review.',
    recoveryInstructionsVersion: 1 as const,
  };
  const pairing = signVaultPairingEnvelope({
    version: 1, network, sessionIdHex: proofInput.sessionIdHex,
    senderChannelIdHex: vaultTransportChannelId(roles[0].origin),
    recipientChannelIdHex: vaultTransportChannelId(roles[1].origin),
    counter: '1', createdAtMs: '1785542400000', expiresAtMs: '1785542700000',
    antiReplayNonceHex: hashHex(`${network}:pairing-replay`), transcriptHashHex: proofInput.transcriptHashHex,
    messageType: 'signer-origin', payloadHex: bytesToHex(serializeVaultSignerOrigin(signers[0])),
  }, roles[0].root, roles[0].origin);
  const approval = signVaultPsbtApprovalEnvelope({
    version: 1, network, policyId: policy.policyId, planId: plan.planId, planDigest: plan.planDigest,
    senderChannelIdHex: pairing.senderChannelIdHex, recipientChannelIdHex: pairing.recipientChannelIdHex,
    counter: '2', expiresAtMs: '1785542700000', antiReplayNonceHex: hashHex(`${network}:approval-replay`),
    transcriptHashHex: pairing.transcriptHashHex, stage: 'request',
    payloadHex: bytesToHex(serializeVaultPartialSignatureInput(partialInput)),
  }, roles[0].root, roles[0].origin);
  const bytes = {
    signerOriginHex: bytesToHex(serializeVaultSignerOrigin(signers[0])),
    proofInputHex: bytesToHex(serializeVaultProofInput(proofInput)),
    proofResultHex: bytesToHex(serializeVaultProofResult(proofResult)),
    canonicalPolicyHex: bytesToHex(policyBytes),
    policyRecordHex: bytesToHex(serializeVaultPolicyRecord(policyRecord)),
    branchReceive0Hex: bytesToHex(serializeVaultBranchDerivation({
      version: 1, network, policyId: policy.policyId, branch: 'receive', index: 0,
    })),
    canonicalPlanHex: bytesToHex(planBytes),
    partialInputHex: bytesToHex(serializeVaultPartialSignatureInput(partialInput)),
    partialResultHex: bytesToHex(serializeVaultPartialSignatureResult(partialResult)),
    recoveryKitHex: bytesToHex(serializeVaultRecoveryKit(recoveryKit)),
    pairingEnvelopeHex: bytesToHex(serializeVaultPairingEnvelope(pairing)),
    approvalEnvelopeHex: bytesToHex(serializeVaultPsbtApprovalEnvelope(approval)),
  };
  const negativeBinary = {
    unknownContractVersionPolicyHex: mutateByte(bytes.canonicalPolicyHex, 5, 2),
    unknownNetworkPolicyHex: mutateByte(bytes.canonicalPolicyHex, 7, 2),
    unknownRolePolicyHex: mutateByte(bytes.canonicalPolicyHex, 23, 9),
    trailingPolicyHex: `${bytes.canonicalPolicyHex}00`,
    truncatedPlanHex: bytes.canonicalPlanHex.slice(0, -2),
  };
  for (const entry of roles) { entry.root.wipePrivateData(); entry.account.wipePrivateData(); }
  spendingRoot.wipePrivateData(); spendingKey.wipePrivateData(); proofNode.wipePrivateData(); signer.wipePrivateData();
  return {
    network, note: 'PUBLIC DISPOSABLE FIXTURE ONLY; never fund these keys or addresses.',
    signers, proofInput, proofResult, policy, metadata, policyRecord,
    branchReceive0: { version: 1, network, policyId: policy.policyId, branch: 'receive', index: 0 },
    plan, partialInput, partialResult, recoveryKit, pairing, approval, bytes, negativeBinary,
  };
}

const records = { mainnet: makeVector('mainnet'), signet: makeVector('signet') };

const fixture = {
  vectorVersion: 1,
  generatedBy: 'scripts/generate-vault-contract-vectors.ts',
  encoding: {
    name: 'SQVB fixed-order binary v1', magicHex: '53515642', byteOrder: 'big-endian',
    text: 'u32 byte length followed by strict UTF-8', bytes: 'u32 byte length followed by exact bytes',
    arrays: 'u32 element count followed by elements', nullable: '00 absent or 01 followed by value',
    parserRule: 'known type/version/enums only; exact EOF; no extension fields or alternate encodings',
    txidRule: '32 display-order bytes; raw transaction and PSBT bytes remain byte-exact',
    policyId: 'SHA256(UTF8("drey-vault-policy-v1") || 00 || canonicalPolicyBytes)',
    planDigest: 'SHA256(UTF8("drey-vault-plan-v1") || 00 || canonicalPlanBytes)',
  },
  records,
  negativeObjectCases: [
    'reordered roles', 'duplicate roles', 'duplicate fingerprint/xpub', 'foreign descriptor key',
    'wrong network', 'wrong BIP48 origin', 'unknown object field', 'descriptor mutation with retained policyId',
    'plan mutation with retained planDigest', 'unknown sighash', 'unknown policy/record version',
  ],
};

const outPath = join(process.cwd(), 'vectors', 'vault-contracts-v1.json');
writeFileSync(outPath, `${JSON.stringify(fixture, null, 2)}\n`);
console.log(`wrote ${outPath}`);

// ---- Produced-proof vectors (multisig-role.ts) -----------------------------
//
// `vault-contracts-v1.json` publishes proofs whose roots it does not, so an
// implementation can only ever *verify* them. These vectors publish the
// disposable seed as well, which is what lets a second implementation — a
// native signer, another language, a hardware adapter — produce the same bytes
// and compare rather than agree that somebody else's signature checks out.
//
// Deterministic because the ECDSA here is RFC 6979 with low-S normalization,
// so a correct producer emits exactly one signature for a given key and digest.
// Every seed below is a published label-derived fixture and must never be
// funded.

function makeSignerRoleVector(network: Network) {
  const roleSeed = concat(seed(`${network}:role-vector-mobile-b`), seed(`${network}:role-vector-mobile-b/1`));
  const spendingSeed = concat(seed(`${network}:role-vector-spending-s`), seed(`${network}:role-vector-spending-s/1`));
  const origin = deriveVaultRoleOrigin(roleSeed, 'mobile-b', network);
  const proofInput = {
    version: 1 as const, origin,
    sessionIdHex: hashHex(`${network}:role-vector-session`).slice(0, 32),
    challengeNonceHex: hashHex(`${network}:role-vector-nonce`),
    transcriptHashHex: hashHex(`${network}:role-vector-transcript`),
    expiresAtMs: '1893456000000',
  };
  const proofResult = signVaultProofOfPossession(roleSeed, proofInput, '1893455999999');
  // The independence case is a real collision, not a hand-written one: the
  // published Spending seed derives to the origin published beside it, so a
  // producer that compares only raw seed strings passes the easy check and
  // fails this one.
  const spendingAsRole = deriveVaultRoleOrigin(spendingSeed, 'mobile-b', network);
  return {
    seedHex: bytesToHex(roleSeed),
    role: 'mobile-b' as const,
    masterFingerprintHex: origin.masterFingerprintHex,
    accountXpub: origin.accountXpub,
    originPath: origin.originPath,
    originHex: bytesToHex(serializeVaultSignerOrigin(origin)),
    proofPublicKeyHex: deriveProofPublicKeyHex(origin),
    proofInput,
    proofResult,
    proofResultHex: bytesToHex(serializeVaultProofResult(proofResult)),
    independence: {
      spendingSeedHex: bytesToHex(spendingSeed),
      spendingOriginPath: spendingAsRole.originPath,
      spendingMasterFingerprintHex: spendingAsRole.masterFingerprintHex,
      spendingAccountXpub: spendingAsRole.accountXpub,
    },
  };
}

const signerRoleFixture = {
  vectorVersion: 1,
  generatedBy: 'scripts/generate-vault-contract-vectors.ts',
  scope: 'ADR 0007 §§1-2 signer-role production: origin derivation and proof of possession',
  note: 'PUBLIC DISPOSABLE FIXTURE ONLY. These seeds are published on purpose so a produced proof can be reproduced byte for byte; never fund an address derived from them.',
  determinism: 'secp256k1 ECDSA, RFC 6979 deterministic nonce, low-S normalized, compact 64-byte encoding',
  records: { mainnet: makeSignerRoleVector('mainnet'), signet: makeSignerRoleVector('signet') },
};

const roleOutPath = join(process.cwd(), 'vectors', 'vault-role-v1.json');
writeFileSync(roleOutPath, `${JSON.stringify(signerRoleFixture, null, 2)}\n`);
console.log(`wrote ${roleOutPath}`);

function makeDescriptorVector(record: (typeof records)[keyof typeof records]) {
  const policyRecord = validateVaultPolicyRecordDescriptors(record.policyRecord);
  const reparsedPolicy = parseCanonicalVaultPolicyDescriptors(
    policyRecord.identity.receiveDescriptor,
    policyRecord.identity.changeDescriptor,
  );
  if (reparsedPolicy.policyId !== policyRecord.identity.policyId) {
    throw new Error('B1 descriptor pair changed the established B0 policy identity');
  }
  return {
    network: record.network,
    note: record.note,
    policyId: record.policy.policyId,
    birthdayHeight: record.metadata.birthdayHeight,
    receiveDescriptor: record.policy.receiveDescriptor,
    changeDescriptor: record.policy.changeDescriptor,
    outputs: [
      deriveVaultOutput(record.policy, 'receive', 0),
      deriveVaultOutput(record.policy, 'receive', 1),
      deriveVaultOutput(record.policy, 'change', 0),
      deriveVaultOutput(record.policy, 'change', 7),
    ],
  };
}

const descriptorFixture = {
  vectorVersion: 1,
  generatedBy: 'scripts/generate-vault-contract-vectors.ts',
  scope: 'ADR 0007 Workstream B1 descriptor, public derivation, native P2WSH, and complete-policy ownership',
  note: 'PUBLIC DISPOSABLE CONFORMANCE DATA ONLY; never fund these keys or addresses.',
  standards: ['BIP32', 'BIP48', 'BIP67', 'BIP380', 'BIP382', 'BIP383'],
  externalReference: {
    implementation: 'Bitcoin Core v30.2.0',
    offlineRpcs: ['getdescriptorinfo', 'deriveaddresses', 'createmultisig', 'validateaddress'],
    rule: 'Every descriptor checksum, ranged address, sorted witness script, and P2WSH scriptPubKey below was cross-checked byte-for-byte.',
  },
  records: {
    mainnet: makeDescriptorVector(records.mainnet),
    signet: makeDescriptorVector(records.signet),
  },
  negativeCases: [
    'missing, malformed, or retained checksum after mutation',
    'non-canonical whitespace, hardened-marker, source order, or descriptor normalization',
    'P2SH wrapper, Taproot, Miniscript, multi(), flexible threshold, or alternate fragment',
    'reordered, duplicated, substituted, uncompressed, private, or malformed key',
    'wrong network, BIP48 origin, role, branch, child index, wildcard, or hardened child',
    'one-xpub, fingerprint-only, incomplete-script, or foreign-policy ownership claim',
    'unknown version, field, network, branch, role, policy ID, or signing meaning',
  ],
};

const descriptorOutPath = join(process.cwd(), 'vectors', 'vault-descriptors-v1.json');
writeFileSync(descriptorOutPath, `${JSON.stringify(descriptorFixture, null, 2)}\n`);
console.log(`wrote ${descriptorOutPath}`);

function makePsbtVector(record: (typeof records)[keyof typeof records]) {
  const { planDigest: _b0PlaceholderDigest, ...b0Plan } = record.plan;
  void _b0PlaceholderDigest;
  // B0 intentionally pinned its pre-B2 sample before witness finalization was
  // implemented. B2 retains those bytes and creates a new plan/digest with the
  // conservative 2-of-3 P2WSH vsize upper bound and corresponding ceiling fee rate.
  const plan = finalizeVaultUnsignedPlan({ ...b0Plan, vsize: 189, feeRateSatPerKvB: '5292' });
  const unsignedPsbtHex = constructVaultPsbt(record.policy, plan);
  const roleFixtures = {
    'desktop-a': roleFixture(record.network, 'desktop-a', 'root-a'),
    'mobile-b': roleFixture(record.network, 'mobile-b', 'root-b'),
    'recovery-c': roleFixture(record.network, 'recovery-c', 'root-c'),
  } as const;
  const partials = Object.fromEntries(VAULT_ROLES.map((role) => {
    const request = createVaultPartialSignatureInput({ policy: record.policy, plan, role, psbtHex: unsignedPsbtHex });
    const result = signVaultPartialSignature({
      policy: record.policy,
      request,
      signerRoot: roleFixtures[role].root,
      nowMs: '1785542402000',
    });
    return [role, { request, result }];
  })) as Record<VaultSignerRole, {
    request: VaultPartialSignatureInputV1;
    result: VaultPartialSignatureResultV1;
  }>;
  const pairRecords = Object.fromEntries(([
    ['desktop-a', 'mobile-b'],
    ['desktop-a', 'recovery-c'],
    ['mobile-b', 'recovery-c'],
  ] as const).map((roles) => {
    const combined = combineVaultPartialSignatureResults({
      policy: record.policy,
      plan,
      results: roles.map((role) => partials[role].result),
    });
    const finalized = finalizeVaultPsbt({
      policy: record.policy,
      plan,
      psbtHex: combined.psbtHex,
      nowMs: '1785542402000',
    });
    return [roles.map((role) => role === 'desktop-a' ? 'A' : role === 'mobile-b' ? 'B' : 'C').join('+'), {
      roles,
      combinedPsbtHex: combined.psbtHex,
      combinedPsbtHash: combined.psbtHash,
      transactionHex: finalized.transactionHex,
      txid: finalized.txid,
      wtxid: finalized.wtxid,
      vsize: finalized.vsize,
    }];
  }));
  const changedUnsigned = Transaction.fromPSBT(hexToBytes(unsignedPsbtHex), { lowR: true });
  changedUnsigned.updateOutput(0, { amount: BigInt(plan.outputs[0]!.valueSats) - 1n });
  const unsupportedSighash = Transaction.fromPSBT(hexToBytes(unsignedPsbtHex), { lowR: true });
  unsupportedSighash.updateInput(0, { sighashType: SigHash.NONE });
  const firstOwnership = deriveVaultOutput(record.policy, plan.inputs[0]!.branch, plan.inputs[0]!.derivationIndex);
  const firstPublicKey = hexToBytes(firstOwnership.logicalKeys[0].publicKeyHex);
  const malformedSignature = Transaction.fromPSBT(hexToBytes(unsignedPsbtHex), { lowR: true });
  malformedSignature.updateInput(0, {
    partialSig: [[firstPublicKey, Uint8Array.of(0x30, 0x00, SigHash.ALL)]],
  }, true);
  const aSigned = Transaction.fromPSBT(hexToBytes(partials['desktop-a'].result.signedPsbtHex), { lowR: true });
  const [, lowSignature] = aSigned.getInput(0).partialSig![0]!;
  const parsedLow = secp256k1.Signature.fromBytes(lowSignature.slice(0, -1), 'der');
  const highSignature = new secp256k1.Signature(parsedLow.r, secp256k1.CURVE.n - parsedLow.s).toBytes('der');
  const highS = Transaction.fromPSBT(hexToBytes(unsignedPsbtHex), { lowR: true });
  highS.updateInput(0, {
    partialSig: [[firstPublicKey, new Uint8Array([...highSignature, SigHash.ALL])]],
  }, true);
  const replaceFirst = (source: string, before: string, after: string): string => {
    const offset = source.indexOf(before);
    if (offset < 0 || before.length !== after.length) throw new Error('B2 adversarial mutation target mismatch');
    return `${source.slice(0, offset)}${after}${source.slice(offset + before.length)}`;
  };
  const witnessScriptHex = plan.inputs[0]!.witnessScriptHex;
  const globalMapEnd = (5 + 1 + 1 + 1 + hexToBytes(plan.unsignedTransactionHex).length) * 2;
  const adversarial = {
    truncatedPsbtHex: unsignedPsbtHex.slice(0, -2),
    trailingPsbtHex: `${unsignedPsbtHex}00`,
    unknownGlobalFieldPsbtHex: `${unsignedPsbtHex.slice(0, globalMapEnd)}02fc010102${unsignedPsbtHex.slice(globalMapEnd)}`,
    changedUnsignedOutputPsbtHex: bytesToHex(changedUnsigned.toPSBT(0)),
    unsupportedSighashPsbtHex: bytesToHex(unsupportedSighash.toPSBT(0)),
    substitutedWitnessScriptPsbtHex: replaceFirst(
      unsignedPsbtHex,
      witnessScriptHex,
      `${witnessScriptHex.slice(0, -2)}00`,
    ),
    malformedPartialSignaturePsbtHex: bytesToHex(malformedSignature.toPSBT(0)),
    highSPartialSignaturePsbtHex: bytesToHex(highS.toPSBT(0)),
    duplicateRolePsbtHexes: [partials['desktop-a'].result.signedPsbtHex, partials['desktop-a'].result.signedPsbtHex],
    unexpectedRoleResult: { ...partials['desktop-a'].result, roleAdded: 'mobile-b' },
  };
  for (const fixture of Object.values(roleFixtures)) {
    fixture.account.wipePrivateData();
    fixture.root.wipePrivateData();
  }
  return {
    network: record.network,
    note: record.note,
    policyId: record.policy.policyId,
    plan,
    unsignedPsbtHex,
    unsignedPsbtHash: vaultPsbtHash(unsignedPsbtHex),
    partials,
    quorums: pairRecords,
    adversarial,
  };
}

const psbtFixture = {
  vectorVersion: 1,
  generatedBy: 'scripts/generate-vault-contract-vectors.ts',
  scope: 'ADR 0007 Workstream B2 closed PSBTv0 partial-signing, combination, quorum, and finalization',
  note: 'PUBLIC DISPOSABLE CONFORMANCE DATA ONLY; never fund these keys, prevouts, addresses, or transactions.',
  standards: ['BIP32', 'BIP48', 'BIP67', 'BIP174', 'BIP380', 'BIP382', 'BIP383'],
  psbtProfile: {
    version: 0,
    globalFields: ['unsigned transaction'],
    inputFields: ['witness UTXO', 'witness script', 'BIP32 derivation for A/B/C', 'SIGHASH_ALL', 'partial signatures'],
    vaultChangeOutputFields: ['witness script', 'BIP32 derivation for A/B/C'],
    rule: 'No proprietary, unknown, alternate-script, final, or uncommitted signing-meaning fields are accepted.',
  },
  externalReference: {
    implementation: 'Bitcoin Core v30.2.0',
    offlineRpcs: ['decodepsbt', 'analyzepsbt', 'combinepsbt', 'finalizepsbt', 'decoderawtransaction'],
    rule: 'Every unsigned/partial/combined PSBT and finalized transaction below was checked offline with networking disabled.',
  },
  records: {
    mainnet: makePsbtVector(records.mainnet),
    signet: makePsbtVector(records.signet),
  },
  negativeCases: [
    'duplicate A+A or B+B logical-role combination',
    'foreign key, policy, network, origin, branch, index, witness script, or scriptPubKey',
    'missing, extra, duplicated, malformed, high-S, non-ALL, or unexpected-role partial signature',
    'missing or extra BIP32 derivation and any unknown/proprietary PSBT map field',
    'changed unsigned bytes, input/output order, amount, fee, change, classification, freshness evidence, or request identity',
    'sub-quorum finalization and malformed, reordered, foreign, or non-ALL final witness',
  ],
};

const psbtOutPath = join(process.cwd(), 'vectors', 'vault-psbt-v1.json');
writeFileSync(psbtOutPath, `${JSON.stringify(psbtFixture, null, 2)}\n`);
console.log(`wrote ${psbtOutPath}`);

// ---- Coordinator-neutral plan, QR, and crash-safe lifecycle vectors -------

function makeCoordinatorVector(record: (typeof records)[keyof typeof records]) {
  const owned = deriveVaultOutput(record.policy, 'receive', 12);
  const source: VaultEvidenceSourceV1 = {
    network: record.network,
    backendInstanceIdHash: hashHex(`${record.network}:coordinator:backend`),
    classificationRevisionHash: hashHex(`${record.network}:coordinator:revision`),
    coreTip: { height: record.network === 'mainnet' ? 910_100 : 250_100, hash: hashHex(`${record.network}:coordinator:tip`) },
    indexTip: { height: record.network === 'mainnet' ? 910_100 : 250_100, hash: hashHex(`${record.network}:coordinator:tip`) },
    historyTip: { height: record.network === 'mainnet' ? 910_100 : 250_100, hash: hashHex(`${record.network}:coordinator:tip`) },
    ordTip: { height: record.network === 'mainnet' ? 910_100 : 250_100, hash: hashHex(`${record.network}:coordinator:tip`) },
    observedAtMs: '1785542400000',
    validUntilMs: '1785543000000',
  };
  const utxo: VaultUtxoV1 = {
    txid: hashHex(`${record.network}:coordinator:utxo`), vout: 0, valueSats: '160000',
    scriptPubKeyHex: owned.scriptPubKeyHex, branch: 'receive', derivationIndex: 12,
    confirmations: 6, walletCreatedUnconfirmedChange: false, primaryClass: 'cardinal_clean',
    confidence: 'authoritative', classificationComplete: true, satRangesComplete: true,
    inscriptions: [], rareSatDetected: false, unsupportedAssetDetected: false,
    userFrozen: false, dustQuarantined: false, refusal: null,
  };
  const request = {
    policy: record.policy, source, utxos: [utxo], destinationAddress: record.plan.destination.address,
    pairedSpendingWalletIdHash: hashHex(`${record.network}:coordinator:spending-wallet`),
    feeRateSatPerKvB: '5000', changeDerivationIndex: 13,
    planId: hashHex(`${record.network}:coordinator:plan`).slice(0, 32),
    requestId: hashHex(`${record.network}:coordinator:request`).slice(0, 32),
    createdAtMs: '1785542401000', expiresAtMs: '1785542700000',
    broadcastIntent: 'broadcast' as const, amountSats: '50000',
  };
  const built = buildVaultCardinalWithdrawal(request);
  const roleA = roleFixture(record.network, 'desktop-a', 'root-a');
  const roleB = roleFixture(record.network, 'mobile-b', 'root-b');
  try {
    const aRequest = createVaultAssetSafePartialSignatureInput({
      policy: record.policy, plan: built.plan, role: 'desktop-a', psbtHex: built.psbtHex,
      evidence: built.evidence, nowMs: request.createdAtMs,
    });
    const bRequest = createVaultAssetSafePartialSignatureInput({
      policy: record.policy, plan: built.plan, role: 'mobile-b', psbtHex: built.psbtHex,
      evidence: built.evidence, nowMs: request.createdAtMs,
    });
    const aResult = signVaultAssetSafePartialSignature({
      policy: record.policy, plan: built.plan, request: aRequest, signerRoot: roleA.root,
      evidence: built.evidence, nowMs: '1785542402000',
    });
    const bResult = signVaultAssetSafePartialSignature({
      policy: record.policy, plan: built.plan, request: bRequest, signerRoot: roleB.root,
      evidence: built.evidence, nowMs: '1785542402000',
    });
    const combined = combineVaultAssetSafePartialSignatureResults({
      policy: record.policy, plan: built.plan, results: [aResult, bResult],
      evidence: built.evidence, nowMs: '1785542402000',
    });
    const finalized = finalizeVaultAssetSafePsbt({
      policy: record.policy, plan: built.plan, psbtHex: combined.psbtHex,
      evidence: built.evidence, nowMs: '1785542402000',
    });
    const approvalRequest = signVaultPsbtApprovalEnvelope({
      version: 1, network: record.network, policyId: built.plan.policyId,
      planId: built.plan.planId, planDigest: built.plan.planDigest,
      senderChannelIdHex: record.pairing.senderChannelIdHex,
      recipientChannelIdHex: record.pairing.recipientChannelIdHex,
      counter: '3', expiresAtMs: built.plan.expiresAtMs,
      antiReplayNonceHex: hashHex(`${record.network}:coordinator:approval-request`),
      transcriptHashHex: record.pairing.transcriptHashHex, stage: 'request',
      payloadHex: bytesToHex(serializeVaultPartialSignatureInput(bRequest)),
    }, roleA.root, roleA.origin);
    const approvalResult = signVaultPsbtApprovalEnvelope({
      version: 1, network: record.network, policyId: built.plan.policyId,
      planId: built.plan.planId, planDigest: built.plan.planDigest,
      senderChannelIdHex: record.pairing.recipientChannelIdHex,
      recipientChannelIdHex: record.pairing.senderChannelIdHex,
      counter: '4', expiresAtMs: built.plan.expiresAtMs,
      antiReplayNonceHex: hashHex(`${record.network}:coordinator:approval-result`),
      transcriptHashHex: record.pairing.transcriptHashHex, stage: 'partial-signature',
      payloadHex: bytesToHex(serializeVaultPartialSignatureResult(bResult)),
    }, roleB.root, roleB.origin);
    const prepared = prepareVaultBroadcast({
      policy: record.policy, plan: built.plan, transactionHex: finalized.transactionHex,
      coordinator: 'mobile', preparedAtMs: '1785542403000',
    });
    const consumed = consumeVaultBroadcastAttempt({
      policy: record.policy, plan: built.plan, record: prepared,
      attemptIdHex: hashHex(`${record.network}:coordinator:attempt`).slice(0, 32),
      consumedAtMs: '1785542404000',
    });
    const terminal = completeVaultBroadcast({
      policy: record.policy, plan: built.plan, record: consumed,
      status: 'accepted', detail: 'public synthetic vector', observedAtMs: '1785542405000',
    });
    const fragmentOptions = { maxFragmentLength: 120 };
    return {
      network: record.network,
      input: { policy: record.policy, source, utxos: [utxo], request },
      expected: {
        plan: built.plan, canonicalPlanHex: bytesToHex(canonicalVaultPlanBytes(built.plan)),
        evidence: built.evidence, unsignedPsbtHex: built.psbtHex,
        psbtCborHex: bytesToHex(encodeVaultPsbtCbor(built.psbtHex)),
        psbtUrFrames: vaultPsbtUrEncoder(built.psbtHex, fragmentOptions).frames,
        pairingContextCborHex: bytesToHex(encodeVaultPairingContextCbor(record.pairing)),
        pairingContextUrFrames: vaultPairingContextUrEncoder(record.pairing, fragmentOptions).frames,
        approvalRequest,
        approvalRequestContextCborHex: bytesToHex(encodeVaultApprovalContextCbor(approvalRequest)),
        approvalRequestContextUrFrames: vaultApprovalContextUrEncoder(approvalRequest, fragmentOptions).frames,
        approvalResult,
        approvalResultContextCborHex: bytesToHex(encodeVaultApprovalContextCbor(approvalResult)),
        approvalResultContextUrFrames: vaultApprovalContextUrEncoder(approvalResult, fragmentOptions).frames,
        aResult, bResult, combinedPsbtHex: combined.psbtHex, finalized,
        lifecycle: { prepared, consumed, terminal },
      },
    };
  } finally {
    roleA.account.wipePrivateData(); roleA.root.wipePrivateData();
    roleB.account.wipePrivateData(); roleB.root.wipePrivateData();
  }
}

const coordinatorFixture = {
  vectorVersion: 1,
  generatedBy: 'scripts/generate-vault-contract-vectors.ts',
  scope: 'symmetric coordinator canonical plan, PSBT, authenticated QR context, and durable broadcast lifecycle',
  note: 'PUBLIC DISPOSABLE CROSS-PLATFORM CONFORMANCE DATA ONLY; never fund any key, address, prevout, or transaction.',
  qr: {
    psbt: 'Current Blockchain Commons ur:psbt with an untagged deterministic CBOR byte string; deprecated ur:crypto-psbt is accepted only.',
    context: 'Proprietary ur:x-drey-vault in the registry-reserved x-* namespace; context supplements the separately verified PSBT.',
  },
  records: { mainnet: makeCoordinatorVector(records.mainnet), signet: makeCoordinatorVector(records.signet) },
};
const coordinatorOutPath = join(process.cwd(), 'vectors', 'vault-coordinator-v1.json');
writeFileSync(coordinatorOutPath, `${JSON.stringify(coordinatorFixture, null, 2)}\n`);
console.log(`wrote ${coordinatorOutPath}`);

type B3InputSpec = {
  label: string;
  valueSats: bigint;
  branch: 'receive' | 'change';
  derivationIndex: number;
  primaryClass: VaultInputAssetEvidenceV1['primaryClass'];
  inscriptions?: VaultInputAssetEvidenceV1['inscriptions'];
  txid?: string;
  vout?: number;
  sequence?: number;
  confirmations?: number;
  walletCreatedUnconfirmedChange?: boolean;
  confidence?: VaultInputAssetEvidenceV1['confidence'];
  userFrozen?: boolean;
  dustQuarantined?: boolean;
  classificationComplete?: boolean;
  satRangesComplete?: boolean;
  rareSatDetected?: boolean;
  unsupportedAssetDetected?: boolean;
};

type B3OutputSpec = {
  valueSats: bigint;
  purpose: 'paired-spending' | 'vault-change';
  derivationIndex?: number;
};

function makeB3Case(
  record: (typeof records)[keyof typeof records],
  input: {
    label: string;
    inputs: B3InputSpec[];
    outputs: B3OutputSpec[];
    assetEffects: VaultUnsignedPlanV1['assetEffects'];
    replacement?: VaultUnsignedPlanV1['replacement'];
    previousPlan?: VaultUnsignedPlanV1;
    destinationOutputIndex?: number;
    validate?: boolean;
  },
) {
  const classificationRevisionHash = hashHex(`${record.network}:b3:classification-revision`);
  const tip = {
    height: record.network === 'mainnet' ? 910_007 : 250_007,
    hash: hashHex(`${record.network}:b3:common-tip`),
  };
  const planInputs = input.inputs.map((item, index) => {
    const owned = deriveVaultOutput(record.policy, item.branch, item.derivationIndex);
    const facts = finalizeVaultInputAssetEvidence({
      version: 1,
      network: record.network,
      inputIndex: index,
      txid: item.txid ?? hashHex(`${record.network}:b3:${input.label}:${item.label}:prevout`),
      vout: item.vout ?? 0,
      valueSats: item.valueSats.toString(),
      scriptPubKeyHex: owned.scriptPubKeyHex,
      primaryClass: item.primaryClass,
      confidence: item.confidence ?? 'authoritative',
      confirmations: item.confirmations ?? 6,
      walletCreatedUnconfirmedChange: item.walletCreatedUnconfirmedChange ?? false,
      userFrozen: item.userFrozen ?? false,
      dustQuarantined: item.dustQuarantined ?? false,
      classificationComplete: item.classificationComplete ?? true,
      satRangesComplete: item.satRangesComplete ?? true,
      inscriptions: item.inscriptions ?? [],
      rareSatDetected: item.rareSatDetected ?? false,
      unsupportedAssetDetected: item.unsupportedAssetDetected ?? false,
      classificationRevisionHash,
      classifiedTip: tip,
    });
    return {
      facts,
      plan: {
        txid: facts.txid,
        vout: facts.vout,
        valueSats: facts.valueSats,
        scriptPubKeyHex: facts.scriptPubKeyHex,
        witnessScriptHex: owned.witnessScriptHex,
        branch: item.branch,
        derivationIndex: item.derivationIndex,
        sequence: item.sequence ?? 0xffff_fffd,
        sighash: 'all' as const,
        classification: item.primaryClass,
        classificationEvidenceHash: facts.evidenceHash,
      },
    };
  });
  const planOutputs = input.outputs.map((item, outputIndex) => {
    if (item.purpose === 'paired-spending') {
      const destination = record.plan.outputs[0]!;
      return {
        outputIndex,
        valueSats: item.valueSats.toString(),
        scriptPubKeyHex: destination.scriptPubKeyHex,
        address: destination.address,
        purpose: item.purpose,
        branch: null,
        derivationIndex: null,
      } as const;
    }
    const owned = deriveVaultOutput(record.policy, 'change', item.derivationIndex ?? 0);
    return {
      outputIndex,
      valueSats: item.valueSats.toString(),
      scriptPubKeyHex: owned.scriptPubKeyHex,
      address: owned.address,
      purpose: item.purpose,
      branch: 'change' as const,
      derivationIndex: item.derivationIndex ?? 0,
    };
  });
  const raw = rawUnsignedTransactionMany(
    planInputs.map(({ plan }) => ({ txid: plan.txid, vout: plan.vout, sequence: plan.sequence })),
    planOutputs.map((output) => ({ script: hexToBytes(output.scriptPubKeyHex), amount: BigInt(output.valueSats) })),
  );
  const sized = Transaction.fromRaw(raw);
  for (const [index, item] of planInputs.entries()) {
    sized.updateInput(index, { finalScriptWitness: [
      new Uint8Array(), new Uint8Array(72), new Uint8Array(72), hexToBytes(item.plan.witnessScriptHex),
    ] }, true);
  }
  const inputTotal = planInputs.reduce((sum, item) => sum + BigInt(item.plan.valueSats), 0n);
  const outputTotal = planOutputs.reduce((sum, item) => sum + BigInt(item.valueSats), 0n);
  const fee = inputTotal - outputTotal;
  if (fee <= 0n) throw new Error('B3 fixture requires a positive fee');
  const destinationOutputIndex = input.destinationOutputIndex ?? planOutputs.findIndex((item) => item.purpose === 'paired-spending');
  const destination = planOutputs[destinationOutputIndex];
  if (!destination) throw new Error('B3 fixture destination missing');
  const plan = finalizeVaultUnsignedPlan({
    version: 1,
    policyVersion: 1,
    network: record.network,
    policyId: record.policy.policyId,
    planId: hashHex(`${record.network}:b3:${input.label}:plan`).slice(0, 32),
    requestId: hashHex(`${record.network}:b3:${input.label}:request`).slice(0, 32),
    createdAtMs: '1785542401000',
    expiresAtMs: '1785542699000',
    kind: 'withdrawal',
    unsignedTransactionHex: bytesToHex(raw),
    inputs: planInputs.map((item) => item.plan),
    outputs: planOutputs,
    destination: {
      kind: 'paired-spending',
      pairedSpendingWalletIdHash: hashHex(`${record.network}:spending-wallet-id`),
      targetPolicyId: null,
      address: destination.address,
      outputIndex: destinationOutputIndex,
    },
    amountSats: destination.valueSats,
    changeSats: planOutputs.filter((item) => item.purpose === 'vault-change')
      .reduce((sum, item) => sum + BigInt(item.valueSats), 0n).toString(),
    feeSats: fee.toString(),
    vsize: sized.vsize,
    feeRateSatPerKvB: ((fee * 1000n + BigInt(sized.vsize) - 1n) / BigInt(sized.vsize)).toString(),
    sighash: 'all',
    assetEffects: input.assetEffects,
    source: {
      backendInstanceIdHash: hashHex(`${record.network}:b3:backend-instance`),
      classificationRevisionHash,
      coreTip: tip,
      indexTip: tip,
      observedAtMs: '1785542400000',
      validUntilMs: '1785542700000',
    },
    replacement: input.replacement ?? { kind: 'none', replacesTxid: null, parentTxid: null },
    broadcastIntent: 'broadcast',
  });
  const psbtHex = constructVaultPsbt(record.policy, plan);
  const evidence: VaultAssetPolicyEvidenceV1 = {
    version: 1,
    network: record.network,
    policyId: record.policy.policyId,
    planId: plan.planId,
    planDigest: plan.planDigest,
    safetyMode: 'full_sat_safety',
    capabilities: [...VAULT_FULL_SAT_SAFETY_CAPABILITIES],
    backendInstanceIdHash: plan.source.backendInstanceIdHash,
    classificationRevisionHash,
    coreTip: tip,
    indexTip: tip,
    historyTip: tip,
    ordTip: tip,
    observedAtMs: plan.source.observedAtMs,
    validUntilMs: plan.source.validUntilMs,
    inputs: planInputs.map((item) => item.facts),
  };
  const validation = input.validate === false ? null : validateVaultAssetPolicy({
    policy: record.policy,
    plan,
    psbtHex,
    evidence,
    nowMs: '1785542402000',
    ...(input.previousPlan ? { previousPlan: input.previousPlan } : {}),
  });
  return { plan, evidence, psbtHex, validation };
}

function cardinalEffects(count: number): VaultUnsignedPlanV1['assetEffects'] {
  return Array.from({ length: count }, (_, inputIndex) => ({
    kind: 'cardinal' as const,
    assetId: '',
    inputIndex,
    inputOffsetSats: '0',
    outputIndex: 0,
    outputOffsetSats: '0',
    postageSats: '0',
    protected: false,
  }));
}

function signB3Case(
  record: (typeof records)[keyof typeof records],
  item: ReturnType<typeof makeB3Case>,
  previousPlan?: VaultUnsignedPlanV1,
) {
  const roles = ['desktop-a', 'mobile-b'] as const;
  const roots = roles.map((role) => roleFixture(record.network, role, role === 'desktop-a' ? 'root-a' : 'root-b'));
  try {
    const partials = Object.fromEntries(roles.map((role, index) => {
      const request = createVaultAssetSafePartialSignatureInput({
        policy: record.policy,
        plan: item.plan,
        role,
        psbtHex: item.psbtHex,
        evidence: item.evidence,
        nowMs: '1785542402000',
        ...(previousPlan ? { previousPlan } : {}),
      });
      const result = signVaultAssetSafePartialSignature({
        policy: record.policy,
        plan: item.plan,
        request,
        signerRoot: roots[index]!.root,
        evidence: item.evidence,
        nowMs: '1785542402000',
        ...(previousPlan ? { previousPlan } : {}),
      });
      return [role, result];
    }));
    const combined = combineVaultAssetSafePartialSignatureResults({
      policy: record.policy,
      plan: item.plan,
      results: Object.values(partials),
      evidence: item.evidence,
      nowMs: '1785542402000',
      ...(previousPlan ? { previousPlan } : {}),
    });
    const finalized = finalizeVaultAssetSafePsbt({
      policy: record.policy,
      plan: item.plan,
      psbtHex: combined.psbtHex,
      evidence: item.evidence,
      nowMs: '1785542402000',
      ...(previousPlan ? { previousPlan } : {}),
    });
    return { roles, partials, combinedPsbtHex: combined.psbtHex, combinedPsbtHash: combined.psbtHash, finalized };
  } finally {
    for (const fixture of roots) {
      fixture.account.wipePrivateData();
      fixture.root.wipePrivateData();
    }
  }
}

function makeB3Vector(record: (typeof records)[keyof typeof records]) {
  const inscriptionId = `${hashHex(`${record.network}:b3:inscription`)}i0`;
  const ordinary = makeB3Case(record, {
    label: 'ordinary',
    inputs: [{ label: 'clean-0', valueSats: 100_000n, branch: 'receive', derivationIndex: 2, primaryClass: 'cardinal_clean' }],
    outputs: [{ valueSats: 90_000n, purpose: 'paired-spending' }, { valueSats: 9_000n, purpose: 'vault-change', derivationIndex: 2 }],
    assetEffects: cardinalEffects(1),
  });
  const multiInput = makeB3Case(record, {
    label: 'multi-input',
    inputs: [
      { label: 'clean-0', valueSats: 60_000n, branch: 'receive', derivationIndex: 3, primaryClass: 'cardinal_clean' },
      { label: 'clean-1', valueSats: 50_000n, branch: 'change', derivationIndex: 4, primaryClass: 'cardinal_clean' },
    ],
    outputs: [{ valueSats: 90_000n, purpose: 'paired-spending' }, { valueSats: 18_000n, purpose: 'vault-change', derivationIndex: 5 }],
    assetEffects: cardinalEffects(2),
  });
  const inscription = makeB3Case(record, {
    label: 'inscription',
    inputs: [
      { label: 'protected', valueSats: 20_000n, branch: 'receive', derivationIndex: 6,
        primaryClass: 'inscribed', inscriptions: [{ inscriptionId, offsetSats: '123' }] },
      { label: 'clean-fee', valueSats: 5_000n, branch: 'change', derivationIndex: 7, primaryClass: 'cardinal_clean' },
    ],
    outputs: [{ valueSats: 21_000n, purpose: 'paired-spending' }, { valueSats: 3_000n, purpose: 'vault-change', derivationIndex: 8 }],
    assetEffects: [{ kind: 'inscription', assetId: inscriptionId, inputIndex: 0, inputOffsetSats: '123',
      outputIndex: 0, outputOffsetSats: '123', postageSats: '21000', protected: true },
      ...cardinalEffects(1).map((effect) => ({ ...effect, inputIndex: 1 }))],
  });
  const rbf = makeB3Case(record, {
    label: 'rbf',
    inputs: ordinary.plan.inputs.map((item, index) => ({
      label: `clean-${index}`,
      valueSats: BigInt(item.valueSats),
      branch: item.branch,
      derivationIndex: item.derivationIndex,
      primaryClass: 'cardinal_clean' as const,
      txid: item.txid,
      vout: item.vout,
      sequence: item.sequence,
    })),
    outputs: [{ valueSats: 90_000n, purpose: 'paired-spending' }, { valueSats: 8_000n, purpose: 'vault-change', derivationIndex: 2 }],
    assetEffects: cardinalEffects(1),
    replacement: { kind: 'rbf', replacesTxid: transactionId(ordinary.plan.unsignedTransactionHex), parentTxid: null },
    previousPlan: ordinary.plan,
  });
  const parentTxid = transactionId(ordinary.plan.unsignedTransactionHex);
  const cpfp = makeB3Case(record, {
    label: 'cpfp',
    inputs: [{ label: 'parent-change', valueSats: 9_000n, branch: 'change', derivationIndex: 2,
      primaryClass: 'cardinal_clean', txid: parentTxid, vout: 1, confirmations: 0, walletCreatedUnconfirmedChange: true }],
    outputs: [{ valueSats: 8_000n, purpose: 'paired-spending' }],
    assetEffects: cardinalEffects(1),
    replacement: { kind: 'cpfp', replacesTxid: null, parentTxid },
    previousPlan: ordinary.plan,
  });

  const protectedFee = makeB3Case(record, {
    label: 'protected-fee',
    inputs: inscription.evidence.inputs.map((item, index) => ({
      label: index === 0 ? 'protected' : 'clean-fee',
      valueSats: BigInt(item.valueSats),
      branch: inscription.plan.inputs[index]!.branch,
      derivationIndex: inscription.plan.inputs[index]!.derivationIndex,
      primaryClass: item.primaryClass,
      inscriptions: item.inscriptions,
    })),
    outputs: [{ valueSats: 19_000n, purpose: 'paired-spending' }, { valueSats: 5_000n, purpose: 'vault-change', derivationIndex: 8 }],
    assetEffects: [{ kind: 'inscription', assetId: inscriptionId, inputIndex: 0, inputOffsetSats: '123',
      outputIndex: 0, outputOffsetSats: '123', postageSats: '19000', protected: true },
      ...cardinalEffects(1).map((effect) => ({ ...effect, inputIndex: 1 }))],
    validate: false,
  });
  const reorderedInputs = makeB3Case(record, {
    label: 'reordered-inputs',
    inputs: [
      { label: 'clean-fee', valueSats: 5_000n, branch: 'change', derivationIndex: 7, primaryClass: 'cardinal_clean' },
      { label: 'protected', valueSats: 20_000n, branch: 'receive', derivationIndex: 6,
        primaryClass: 'inscribed', inscriptions: [{ inscriptionId, offsetSats: '123' }] },
    ],
    outputs: [{ valueSats: 21_000n, purpose: 'paired-spending' }, { valueSats: 3_000n, purpose: 'vault-change', derivationIndex: 8 }],
    assetEffects: [{ kind: 'inscription', assetId: inscriptionId, inputIndex: 1, inputOffsetSats: '123',
      outputIndex: 0, outputOffsetSats: '5123', postageSats: '21000', protected: true }],
    validate: false,
  });
  const reorderedOutputs = makeB3Case(record, {
    label: 'reordered-outputs',
    inputs: [
      { label: 'protected', valueSats: 20_000n, branch: 'receive', derivationIndex: 6,
        primaryClass: 'inscribed', inscriptions: [{ inscriptionId, offsetSats: '123' }] },
      { label: 'clean-fee', valueSats: 5_000n, branch: 'change', derivationIndex: 7, primaryClass: 'cardinal_clean' },
    ],
    outputs: [{ valueSats: 3_000n, purpose: 'vault-change', derivationIndex: 8 }, { valueSats: 21_000n, purpose: 'paired-spending' }],
    destinationOutputIndex: 1,
    assetEffects: [{ kind: 'inscription', assetId: inscriptionId, inputIndex: 0, inputOffsetSats: '123',
      outputIndex: 0, outputOffsetSats: '123', postageSats: '3000', protected: true }],
    validate: false,
  });
  const changedOffset = makeB3Case(record, {
    label: 'changed-offset',
    inputs: [
      { label: 'protected', valueSats: 20_000n, branch: 'receive', derivationIndex: 6,
        primaryClass: 'inscribed', inscriptions: [{ inscriptionId, offsetSats: '123' }] },
      { label: 'clean-fee', valueSats: 5_000n, branch: 'change', derivationIndex: 7, primaryClass: 'cardinal_clean' },
    ],
    outputs: [{ valueSats: 21_000n, purpose: 'paired-spending' }, { valueSats: 3_000n, purpose: 'vault-change', derivationIndex: 8 }],
    assetEffects: [{ kind: 'inscription', assetId: inscriptionId, inputIndex: 0, inputOffsetSats: '123',
      outputIndex: 0, outputOffsetSats: '124', postageSats: '21000', protected: true }],
    validate: false,
  });
  const reducedPostage = makeB3Case(record, {
    label: 'reduced-postage',
    inputs: [
      { label: 'protected', valueSats: 20_000n, branch: 'receive', derivationIndex: 6,
        primaryClass: 'inscribed', inscriptions: [{ inscriptionId, offsetSats: '123' }] },
      { label: 'clean-fee', valueSats: 5_000n, branch: 'change', derivationIndex: 7, primaryClass: 'cardinal_clean' },
    ],
    outputs: [{ valueSats: 21_000n, purpose: 'paired-spending' }, { valueSats: 3_000n, purpose: 'vault-change', derivationIndex: 8 }],
    assetEffects: [{ kind: 'inscription', assetId: inscriptionId, inputIndex: 0, inputOffsetSats: '123',
      outputIndex: 0, outputOffsetSats: '123', postageSats: '20000', protected: true }],
    validate: false,
  });
  const unsupported = makeB3Case(record, {
    label: 'unsupported',
    inputs: [{ label: 'runic', valueSats: 100_000n, branch: 'receive', derivationIndex: 9,
      primaryClass: 'runic_or_unsupported', unsupportedAssetDetected: true }],
    outputs: [{ valueSats: 90_000n, purpose: 'paired-spending' }, { valueSats: 9_000n, purpose: 'vault-change', derivationIndex: 10 }],
    assetEffects: cardinalEffects(1),
    validate: false,
  });
  return {
    network: record.network,
    note: record.note,
    policyId: record.policy.policyId,
    cases: {
      ordinary: { ...ordinary, aPlusB: signB3Case(record, ordinary) },
      multiInput: { ...multiInput, aPlusB: signB3Case(record, multiInput) },
      inscription: { ...inscription, aPlusB: signB3Case(record, inscription) },
      rbf: { ...rbf, previousPlan: ordinary.plan, aPlusB: signB3Case(record, rbf, ordinary.plan) },
      cpfp: { ...cpfp, previousPlan: ordinary.plan, aPlusB: signB3Case(record, cpfp, ordinary.plan) },
    },
    adversarial: {
      stale: { ...ordinary, nowMs: '1785542700001', expectedError: 'stale_evidence' },
      conflictingTips: {
        ...ordinary,
        evidence: { ...ordinary.evidence, ordTip: { ...ordinary.evidence.ordTip, hash: hashHex(`${record.network}:b3:conflict`) } },
        expectedError: 'conflicting_source',
      },
      protectedFee: { ...protectedFee, expectedError: 'protected_fee_exposure' },
      reorderedInputs: { ...reorderedInputs, expectedError: 'inscription_policy' },
      reorderedOutputs: { ...reorderedOutputs, expectedError: 'inscription_policy' },
      changedOffset: { ...changedOffset, expectedError: 'inscription_policy' },
      reducedPostage: { ...reducedPostage, expectedError: 'inscription_policy' },
      unsupported: { ...unsupported, expectedError: 'unsupported_classification' },
    },
  };
}

const assetPolicyFixture = {
  vectorVersion: 1,
  generatedBy: 'scripts/generate-vault-contract-vectors.ts',
  scope: 'ADR 0007 Workstream B3 Full Sat Safety BTC and whole-UTXO inscription invariants',
  note: 'PUBLIC DISPOSABLE CONFORMANCE DATA ONLY; never fund these keys, prevouts, addresses, or transactions.',
  standards: ['BIP174', 'Ordinal Theory FIFO sat assignment', 'Drey Full Sat Safety'],
  records: {
    mainnet: makeB3Vector(records.mainnet),
    signet: makeB3Vector(records.signet),
  },
  negativeCases: [
    'stale, degraded, conflicting, suspicious, frozen, or incomplete Full Sat Safety evidence',
    'mixed, rare-sat, runic/unsupported, unknown, co-located, or unconfirmed protected inputs',
    'protected value becoming fee, split across outputs, burned, misrouted, or silently reduced postage',
    'changed protected input/output order, input/output offset, destination, value, evidence hash, or plan digest',
    'inscription RBF, same-plan RBF reuse, or CPFP from anything except proven-clean cardinal Vault change',
  ],
};

const assetPolicyOutPath = join(process.cwd(), 'vectors', 'vault-asset-policy-v1.json');
writeFileSync(assetPolicyOutPath, `${JSON.stringify(assetPolicyFixture, null, 2)}\n`);
console.log(`wrote ${assetPolicyOutPath}`);

// ---------------------------------------------------------------------------
// ADR 0007 Workstream A1: passkey-wrapped-DEK envelope vectors.
//
// Generated with the @noble/ciphers XChaCha20-Poly1305 above and verified by
// the vitest suite against the libsodium reference provider, so the two
// independent AEAD implementations must agree byte-for-byte. PRF outputs and
// DEKs are synthetic label-derived bytes; no WebAuthn credential exists.
// The RP origin is the stable TEST-channel extension origin from the A0
// spike; production envelopes are never manufactured in fixtures.
// ---------------------------------------------------------------------------

const PASSKEY_TEST_RP_ORIGIN = 'chrome-extension://lgcnmmbgabemdkgacjpcdebbjmmblbmn';
const PASSKEY_WRONG_RP_ORIGIN = 'chrome-extension://abcdefghijklmnopabcdefghijklmnop';

function retagBase64(value: string, mutate: (bytes: Uint8Array) => void): string {
  const bytes = base64ToBytes(value);
  mutate(bytes);
  return bytesToBase64(bytes);
}

function makePasskeyVector(network: Network) {
  const rpOrigin = PASSKEY_TEST_RP_ORIGIN;
  const vaultId = `passkey-fixture-${network}`;
  const credentialIdB64 = bytesToBase64(seed(`passkey credential:${network}`).slice(0, 20));
  const dek = seed(`passkey dek:${network}`);
  const prfOutput = seed(`passkey prf output:${network}`);
  const prfSalt = seed(`passkey prf salt:${network}`);
  const hkdfSalt = seed(`passkey hkdf salt:${network}`);
  const nonce = seed(`passkey nonce:${network}`).slice(0, 24);
  const envelope = createPasskeyEnvelope({
    dek, prfOutput, rpOrigin, vaultId, network, credentialIdB64,
    label: 'Fixture credential', createdAtMs: 1785542400000,
    prfSalt, hkdfSalt, nonce,
  });
  const expected = { rpOrigin, vaultId, network };
  const unwrapped = unwrapPasskeyDek({ envelope, prfOutput, expected });
  if (bytesToHex(unwrapped) !== bytesToHex(dek)) throw new Error('passkey vector round-trip failed');
  const aadJson = JSON.stringify([
    'drey-passkey-envelope', 1, rpOrigin, vaultId, network,
    credentialIdB64, envelope.prfSaltB64, envelope.hkdfSaltB64,
  ]);
  const kekInfoJson = JSON.stringify([
    'drey-passkey-kek', 1, rpOrigin, vaultId, network, credentialIdB64,
  ]);
  return {
    rpOrigin, vaultId, network,
    dekHex: bytesToHex(dek),
    prfOutputHex: bytesToHex(prfOutput),
    prfEvalInputHex: bytesToHex(passkeyPrfEvalInput(prfSalt)),
    aadJson, kekInfoJson,
    envelope,
    // Display metadata is deliberately outside the AAD: this mutation MUST
    // still unwrap to dekHex.
    labelMutationStillDecrypts: { ...envelope, label: 'renamed after enrollment' },
    negatives: {
      versionTwo: { envelope: { ...envelope, version: 2 }, expectedError: 'unsupported-version' },
      unknownField: { envelope: { ...envelope, extra: true }, expectedError: 'tampered' },
      kdfLabelMutation: { envelope: { ...envelope, kdf: 'hkdf-sha256-v2' }, expectedError: 'tampered' },
      nonExtensionRpOrigin: { envelope: { ...envelope, rpOrigin: 'https://example.com' }, expectedError: 'tampered' },
      tamperedCiphertext: {
        envelope: {
          ...envelope,
          wrappedDek: {
            ...envelope.wrappedDek,
            ciphertextB64: retagBase64(envelope.wrappedDek.ciphertextB64, (bytes) => { bytes[0]! ^= 0xff; }),
          },
        },
        expectedError: 'decrypt-failed',
      },
      tamperedNonce: {
        envelope: {
          ...envelope,
          wrappedDek: {
            ...envelope.wrappedDek,
            nonceB64: retagBase64(envelope.wrappedDek.nonceB64, (bytes) => { bytes[0]! ^= 0xff; }),
          },
        },
        expectedError: 'decrypt-failed',
      },
      tamperedCredentialId: {
        envelope: { ...envelope, credentialIdB64: bytesToBase64(seed(`passkey foreign credential:${network}`).slice(0, 20)) },
        expectedError: 'decrypt-failed',
      },
      tamperedPrfSalt: {
        envelope: { ...envelope, prfSaltB64: bytesToBase64(seed(`passkey foreign prf salt:${network}`)) },
        expectedError: 'decrypt-failed',
      },
      tamperedHkdfSalt: {
        envelope: { ...envelope, hkdfSaltB64: bytesToBase64(seed(`passkey foreign hkdf salt:${network}`)) },
        expectedError: 'decrypt-failed',
      },
      wrongExpectedVaultId: {
        envelope, expected: { ...expected, vaultId: 'another-wallet' }, expectedError: 'identity-mismatch',
      },
      wrongExpectedNetwork: {
        envelope,
        expected: { ...expected, network: network === 'mainnet' ? 'signet' : 'mainnet' },
        expectedError: 'identity-mismatch',
      },
      wrongExpectedRpOrigin: {
        envelope, expected: { ...expected, rpOrigin: PASSKEY_WRONG_RP_ORIGIN }, expectedError: 'identity-mismatch',
      },
      wrongPrfOutput: {
        envelope, prfOutputHex: bytesToHex(seed(`passkey foreign prf output:${network}`)), expectedError: 'decrypt-failed',
      },
      truncatedPrfOutput: {
        envelope, prfOutputHex: bytesToHex(prfOutput.slice(0, 31)), expectedError: 'invalid-prf-output',
      },
      allZeroPrfOutput: {
        envelope, prfOutputHex: '00'.repeat(32), expectedError: 'invalid-prf-output',
      },
      // atob() also accepts unpadded/whitespace spellings of the same bytes;
      // only the exact canonical padded encoding may pass, or one physical
      // credential could hold two envelopes past the uniqueness check.
      nonCanonicalCredentialId: {
        envelope: { ...envelope, credentialIdB64: credentialIdB64.replace(/=+$/u, '') },
        expectedError: 'tampered',
      },
      // Genuinely authenticated under the correct KEK and AAD, but wrapping a
      // 16-byte plaintext: an envelope that authenticates must still only
      // ever unwrap to a 32-byte DEK.
      authenticatedWrongLengthDek: {
        envelope: {
          ...envelope,
          wrappedDek: (() => {
            const kek = hkdfSha256(prfOutput, hkdfSalt, utf8(kekInfoJson), 32);
            const shortNonce = seed(`passkey short nonce:${network}`).slice(0, 24);
            const shortCiphertext = xchacha20poly1305(kek, shortNonce, utf8(aadJson))
              .encrypt(seed(`passkey short plaintext:${network}`).slice(0, 16));
            return { nonceB64: bytesToBase64(shortNonce), ciphertextB64: bytesToBase64(shortCiphertext) };
          })(),
        },
        expectedError: 'tampered',
      },
    },
  };
}

const passkeyFixture = {
  vectorVersion: 1,
  generatedBy: 'scripts/generate-vault-contract-vectors.ts',
  scope: 'ADR 0007 Workstream A1 passkey-wrapped-DEK envelope v1',
  note: 'PUBLIC DISPOSABLE CONFORMANCE DATA ONLY; synthetic PRF outputs, DEKs, and credential IDs; no WebAuthn credential exists and nothing here may touch production storage.',
  construction: {
    prfEvalInput: 'UTF8("drey-passkey-prf/v1") || 00 || prfSalt(32)',
    kek: 'HKDF-SHA256(ikm = prfOutput(32), salt = hkdfSalt(32), info = UTF8(JSON(["drey-passkey-kek", 1, rpOrigin, vaultId, network, credentialIdB64])), length 32)',
    aad: 'UTF8(JSON(["drey-passkey-envelope", 1, rpOrigin, vaultId, network, credentialIdB64, prfSaltB64, hkdfSaltB64]))',
    wrappedDek: 'XChaCha20-Poly1305(KEK, nonce(24), AAD) over DEK(32); ciphertext || tag(16)',
    displayMetadata: 'label and createdAtMs are outside the AAD; nothing security-relevant may branch on them',
    rpOrigin: 'exact chrome-extension://[a-p]{32} serialized origin (A0 identity decision); any other platform identity is a new envelope version',
  },
  records: { mainnet: makePasskeyVector('mainnet'), signet: makePasskeyVector('signet') },
};

const passkeyOutPath = join(process.cwd(), 'vectors', 'passkey-envelope-v1.json');
writeFileSync(passkeyOutPath, `${JSON.stringify(passkeyFixture, null, 2)}\n`);
console.log(`wrote ${passkeyOutPath}`);

const nativeSendRecipientAddress = Address(TEST_NETWORK).encode({
  type: 'wpkh', hash: new Uint8Array(20).fill(7),
});
const nativeSendRecipient = resolvePayableAddress(nativeSendRecipientAddress, 'signet');
if (!nativeSendRecipient.ok) throw new Error('native-send vector recipient did not resolve');
const nativeSendSeed = seed('M2m native send ownership');
const nativeSendAccountId = publicAccountFromSeed(nativeSendSeed, 'signet', 0).accountId;
const nativeSendAccount = deriveAccountNode(nativeSendSeed, 'payment', 'signet', 0);
const nativeSendInputInfo = deriveAddress(nativeSendAccount, 'payment', 'signet', 0, 0);
const nativeSendChangeInfo = deriveAddress(nativeSendAccount, 'payment', 'signet', 1, 4);
nativeSendAccount.wipePrivateData();
nativeSendSeed.fill(0);
const nativeSendScript = scriptPubKeyHex(nativeSendInputInfo.publicKeyHex, 'payment', 'signet');
const nativeSendEligibility = {
  freshness: { commonTip: true, heartbeatFresh: true, revisionActive: true, spendEligible: true },
  activeRevision: 'native-send-vector-revision',
  lockedOutpoints: new Set<string>(),
};
const nativeSendChange = {
  address: nativeSendChangeInfo.address,
  scriptPubKey: scriptPubKeyHex(nativeSendChangeInfo.publicKeyHex, 'payment', 'signet'),
  role: 'payment_change' as const,
  derivation: {
    accountId: nativeSendAccountId,
    account: 0, lane: 'payment' as const, chain: 1 as const, index: 4,
    path: nativeSendChangeInfo.path, publicKeyHex: nativeSendChangeInfo.publicKeyHex,
  },
};
const nativeSendInputDerivation: PlanDerivation = {
  accountId: nativeSendAccountId,
  account: 0, lane: 'payment', chain: 0, index: 0,
  path: nativeSendInputInfo.path, publicKeyHex: nativeSendInputInfo.publicKeyHex,
};
const nativeSendAnalysisSource = {
  backend: 'native-send-vector', instanceId: 'fixture',
  classificationRevision: 'native-send-vector-revision',
  coreTip: { height: 10, hash: 'f'.repeat(64) },
  indexTip: { height: 10, hash: 'f'.repeat(64) },
  feeQuoteTimestamp: null, mempoolState: null,
};

function nativeSendCoin(nibble: string, valueSats: bigint, protectedInput = false): WalletUtxo {
  return {
    outpoint: { txid: nibble.repeat(64), vout: 0 }, valueSats, scriptPubKey: nativeSendScript,
    accountId: nativeSendAccountId,
    account: 0, lane: 'payment', chain: 0, addressIndex: 0, height: 1,
    walletCreatedChange: false,
    facts: {
      primaryClass: protectedInput ? 'inscribed' : 'cardinal_clean',
      inscriptions: protectedInput
        ? [{ inscriptionId: `${'e'.repeat(64)}i0`, satpoint: `${nibble.repeat(64)}:0:0` }]
        : [],
      satRanges: null, unsupportedAssetDetected: false, confidence: 'authoritative',
      classifiedTip: { height: 10, hash: 'f'.repeat(64) },
      classificationRevision: 'native-send-vector-revision',
    },
    flags: { userFrozen: false, dustQuarantined: false },
  };
}

function nativeSendDerivation(utxo: WalletUtxo): PlanDerivation {
  if (utxo.account !== 0 || utxo.lane !== 'payment' || utxo.chain !== 0 ||
      utxo.addressIndex !== 0 || utxo.scriptPubKey !== nativeSendScript) {
    throw new Error('native-send vector ownership mismatch');
  }
  return nativeSendInputDerivation;
}

function serializeNativeSendOutcome(outcome: NativeSendCandidateOutcome) {
  if (!outcome.ok) return outcome;
  const psbtHex = buildPsbtHex(outcome.candidate.inputs, outcome.candidate.outputs);
  const analysis = analyzePsbtHex(psbtHex, {
    network: 'signet', account: outcome.candidate.account, kind: 'native_send',
    source: nativeSendAnalysisSource,
    inputs: outcome.candidate.inputs, outputs: outcome.candidate.outputs,
    protectedSatFlow: outcome.candidate.protectedSatFlow,
    feeSats: outcome.candidate.feeSats, vsize: outcome.candidate.vsize,
    feeRateSatPerKvB: 2_000n, rbf: outcome.candidate.rbf,
  });
  if (!analysis.ok || analysis.analysis.hardViolations.length > 0) {
    throw new Error(`native-send vector failed transaction analysis${
      analysis.ok ? `: ${analysis.analysis.hardViolations.map(({ code }) => code).join(',')}` : ''
    }`);
  }
  return {
    ok: true as const,
    candidate: {
      accountId: outcome.candidate.accountId,
      account: outcome.candidate.account,
      inputs: outcome.candidate.inputs.map((input) => ({
        outpoint: `${input.txid}:${input.vout}`,
        valueSats: input.valueSats.toString(),
        sequence: input.sequence,
        sighash: input.sighash,
        ownership: input.ownership,
        path: input.derivation?.path ?? null,
        primaryClass: input.classification.primaryClass,
      })),
      outputs: outcome.candidate.outputs.map((output) => ({
        address: output.address,
        scriptPubKey: output.scriptPubKey,
        valueSats: output.valueSats.toString(),
        role: output.role,
      })),
      feeSats: outcome.candidate.feeSats.toString(),
      vsize: outcome.candidate.vsize.toString(),
      protectedSatFlow: outcome.candidate.protectedSatFlow,
      rbf: outcome.candidate.rbf,
      parentTxid: outcome.candidate.parentTxid,
      replacesTxid: outcome.candidate.replacesTxid,
      psbtHex,
      psbtHash: bytesToHex(sha256(hexToBytes(psbtHex))),
    },
  };
}

const nativeSendCases = [
  { name: 'fixed_amount_change', values: [['a', '30000']], amountSats: '20000', sendMax: false },
  { name: 'exact_no_change', values: [['a', '20220']], amountSats: '20000', sendMax: false },
  { name: 'send_max_excludes_protected', values: [['a', '50000'], ['b', '80000', 'protected']],
    amountSats: '0', sendMax: true },
  { name: 'labeled_tie', values: [['a', '12000'], ['b', '12000'], ['c', '12000']],
    amountSats: '15000', sendMax: false,
    labels: { [`${'a'.repeat(64)}:0`]: 'savings|', [`${'b'.repeat(64)}:0`]: 'exchange|',
      [`${'c'.repeat(64)}:0`]: 'exchange|' } },
  { name: 'recipient_dust', values: [['a', '10000']], amountSats: '293', sendMax: false },
  { name: 'insufficient_eligible_funds', values: [], amountSats: '20000', sendMax: false },
  { name: 'manual_selection_mismatch', values: [['a', '100000']], amountSats: '20000', sendMax: false,
    selectedOutpoints: [`${'b'.repeat(64)}:0`] },
] as const;

const nativeSendFixture = {
  vectorVersion: 1,
  generatedBy: 'scripts/generate-vault-contract-vectors.ts',
  scope: 'M2m ordinary native-send compatibility',
  note: 'PUBLIC SYNTHETIC COMPATIBILITY DATA ONLY; no private key or funded outpoint exists.',
  network: 'signet',
  accountId: nativeSendAccountId,
  recipientAddress: nativeSendRecipientAddress,
  recipientScriptPubKey: nativeSendRecipient.value.scriptPubKey,
  inputTemplate: {
    scriptPubKey: nativeSendScript,
    derivation: nativeSendInputDerivation,
  },
  changeOutput: {
    address: nativeSendChange.address,
    scriptPubKey: nativeSendChange.scriptPubKey,
    role: nativeSendChange.role,
    derivation: nativeSendChange.derivation,
  },
  addressOutcomes: {
    malformed: { address: 'not-an-address', network: 'signet',
      expected: resolvePayableAddress('not-an-address', 'signet') },
    wrongNetwork: { address: nativeSendRecipientAddress, network: 'mainnet',
      expected: resolvePayableAddress(nativeSendRecipientAddress, 'mainnet') },
    unsupportedFutureWitness: { address: 'BC1SW50QGDZ25J', network: 'mainnet',
      expected: resolvePayableAddress('BC1SW50QGDZ25J', 'mainnet') },
  },
  cases: nativeSendCases.map((entry) => {
    const coins = entry.values.map(([nibble, value, kind]) =>
      nativeSendCoin(nibble, BigInt(value), kind === 'protected'));
    const labels = 'labels' in entry
      ? new Map(Object.entries(entry.labels))
      : undefined;
    const selectedOutpoints = 'selectedOutpoints' in entry
      ? new Set<string>(entry.selectedOutpoints)
      : undefined;
    const outcome = buildNativeSendCandidate({
      recipient: nativeSendRecipient.value,
      amountSats: BigInt(entry.amountSats),
      sendMax: entry.sendMax,
      accountId: nativeSendAccountId,
      account: 0,
      utxos: coins,
      eligibility: nativeSendEligibility,
      feeRate: 2_000n,
      changeOutput: nativeSendChange,
      deriveInput: nativeSendDerivation,
      ...(labels ? { labelGroupByOutpoint: labels } : {}),
      ...(selectedOutpoints ? { selectedOutpoints } : {}),
    });
    return { ...entry, expected: serializeNativeSendOutcome(outcome) };
  }),
};

const nativeSendOutPath = join(process.cwd(), 'vectors', 'native-send-v1.json');
writeFileSync(nativeSendOutPath, `${JSON.stringify(nativeSendFixture, null, 2)}\n`);
console.log(`wrote ${nativeSendOutPath}`);

const publicAccountFixture = {
  vectorVersion: 1,
  generatedBy: 'scripts/generate-vault-contract-vectors.ts',
  scope: 'single-signature public accounts and exact fractional custom fees',
  note: 'PUBLIC SYNTHETIC WATCH-ONLY DATA ONLY; no private key or funded outpoint is included.',
  accounts: Object.fromEntries((['mainnet', 'signet'] as const).map((network) => {
    const disposableSeed = seed(`public-account-v1:${network}`);
    try {
      const definition = publicAccountFromSeed(disposableSeed, network, 0);
      const addresses = (['payment', 'ordinals'] as const).flatMap((lane) =>
        ([0, 1] as const).flatMap((chain) => [0, 1, 21].map((index) => {
          const derived = derivePublicAccountAddress(definition, lane, chain, index);
          return {
            lane,
            chain,
            index,
            address: derived.address,
            path: derived.path,
            publicKeyHex: derived.publicKeyHex,
            scriptPubKeyHex: derived.scriptPubKeyHex,
          };
        })));
      return [network, {
        definition,
        accountDescriptorCborHex: bytesToHex(encodeAccountDescriptor(definition)),
        addresses,
      }];
    } finally {
      disposableSeed.fill(0);
    }
  })),
  customFees: ['1', '1.25', '1.001', '12.340', '10000.000'].map((text) => {
    const parsed = parseCustomFeeRate(text);
    return {
      input: text,
      normalizedSatPerVb: parsed.normalizedSatPerVb,
      satPerKvB: parsed.satPerKvB.toString(),
      vsize: '141',
      feeSats: feeForVsize(141n, parsed.satPerKvB).toString(),
    };
  }),
};

const publicAccountOutPath = join(process.cwd(), 'vectors', 'public-account-v1.json');
writeFileSync(publicAccountOutPath, `${JSON.stringify(publicAccountFixture, null, 2)}\n`);
console.log(`wrote ${publicAccountOutPath}`);
