import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { HDKey } from '@scure/bip32';
import { SigHash, Transaction } from '@scure/btc-signer';
import { secp256k1 } from '@noble/curves/secp256k1';
import { beforeAll, describe, expect, it } from 'vitest';
import { installTestCryptoProvider } from '../helpers/install-crypto-provider';
import { bytesToHex, hexToBytes } from '../../src/domain/vault/encoding';
import {
  VAULT_ROLES,
  bip32Versions,
  type VaultPolicyIdentityV1,
  type VaultSignerRole,
  type VaultUnsignedPlanV1,
} from '../../src/domain/vault/multisig-contracts';
import { deriveVaultOutput } from '../../src/domain/vault/multisig-descriptors';
import {
  combineVaultPartialSignatureResults,
  combineVaultPsbts,
  constructVaultPsbt,
  createVaultPartialSignatureInput,
  finalizeVaultPsbt,
  signVaultPartialSignature,
  validateVaultPsbt,
  verifyFinalizedVaultTransaction,
} from '../../src/domain/vault/multisig-psbt';
import { finalizeVaultUnsignedPlan, vaultPsbtHash } from '../../src/domain/vault/multisig-encoding';

interface ContractRecord {
  policy: VaultPolicyIdentityV1;
  plan: VaultUnsignedPlanV1;
}

const vectors = JSON.parse(readFileSync(
  join(import.meta.dirname, '..', '..', 'vectors', 'vault-contracts-v1.json'),
  'utf8',
)) as { records: { mainnet: ContractRecord; signet: ContractRecord } };
const psbtVectors = JSON.parse(readFileSync(
  join(import.meta.dirname, '..', '..', 'vectors', 'vault-psbt-v1.json'),
  'utf8',
)) as { records: Record<'mainnet' | 'signet', {
  policyId: string;
  plan: VaultUnsignedPlanV1;
  unsignedPsbtHex: string;
  partials: Record<VaultSignerRole, { result: ReturnType<typeof signVaultPartialSignature> }>;
  quorums: Record<string, { combinedPsbtHex: string; transactionHex: string }>;
  adversarial: {
    truncatedPsbtHex: string;
    trailingPsbtHex: string;
    unknownGlobalFieldPsbtHex: string;
    changedUnsignedOutputPsbtHex: string;
    unsupportedSighashPsbtHex: string;
    substitutedWitnessScriptPsbtHex: string;
    malformedPartialSignaturePsbtHex: string;
    highSPartialSignaturePsbtHex: string;
    duplicateRolePsbtHexes: [string, string];
    unexpectedRoleResult: ReturnType<typeof signVaultPartialSignature>;
  };
}> };

beforeAll(() => installTestCryptoProvider());

const b2Cache = new Map<'mainnet' | 'signet', ContractRecord>();
let multiInputCache: ContractRecord | undefined;

function b2Record(network: 'mainnet' | 'signet'): ContractRecord {
  const cached = b2Cache.get(network);
  if (cached) return cached;
  const established = vectors.records[network];
  const { planDigest: _placeholderDigest, ...placeholder } = clone(established.plan);
  void _placeholderDigest;
  const value = {
    policy: established.policy,
    plan: finalizeVaultUnsignedPlan({ ...placeholder, vsize: 189, feeRateSatPerKvB: '5292' }),
  };
  b2Cache.set(network, value);
  return value;
}

function multiInputRecord(): ContractRecord {
  if (multiInputCache) return multiInputCache;
  const { policy, plan: base } = b2Record('signet');
  const secondOwnership = deriveVaultOutput(policy, 'receive', 1);
  const secondTxid = bytesToHex(sha256('signet:B2 second synthetic prevout'));
  const inputs: VaultUnsignedPlanV1['inputs'] = [clone(base.inputs[0]!), {
    ...clone(base.inputs[0]!),
    txid: secondTxid,
    valueSats: '50000',
    scriptPubKeyHex: secondOwnership.scriptPubKeyHex,
    witnessScriptHex: secondOwnership.witnessScriptHex,
    derivationIndex: 1,
    classificationEvidenceHash: bytesToHex(sha256('signet:B2 input 1 classification')),
  }];
  const outputs = clone(base.outputs);
  outputs[1]!.valueSats = '59000';
  const raw = new Transaction({ version: 2 });
  for (const input of inputs) raw.addInput({ txid: input.txid, index: input.vout, sequence: input.sequence });
  for (const output of outputs) raw.addOutput({ script: hexToBytes(output.scriptPubKeyHex), amount: BigInt(output.valueSats) });
  const sized = Transaction.fromRaw(raw.unsignedTx);
  for (let index = 0; index < inputs.length; index += 1) sized.updateInput(index, { finalScriptWitness: [
    new Uint8Array(), new Uint8Array(72), new Uint8Array(72), hexToBytes(inputs[index]!.witnessScriptHex),
  ] }, true);
  const { planDigest: _digest, ...withoutDigest } = clone(base);
  void _digest;
  const vsize = sized.vsize;
  multiInputCache = {
    policy,
    plan: finalizeVaultUnsignedPlan({
      ...withoutDigest,
      unsignedTransactionHex: bytesToHex(raw.unsignedTx),
      inputs,
      outputs,
      changeSats: '59000',
      vsize,
      feeRateSatPerKvB: ((1_000_000n + BigInt(vsize) - 1n) / BigInt(vsize)).toString(),
    }),
  };
  return multiInputCache;
}

const sha256 = (value: string): Uint8Array => new Uint8Array(createHash('sha256').update(value).digest());
const fixtureSeed = (network: 'mainnet' | 'signet', label: string): Uint8Array =>
  sha256(`PUBLIC DISPOSABLE B0 FIXTURE ONLY:${network}:${label}`);

function root(network: 'mainnet' | 'signet', role: VaultSignerRole): HDKey {
  const label = role === 'desktop-a' ? 'root-a' : role === 'mobile-b' ? 'root-b' : 'root-c';
  return HDKey.fromMasterSeed(fixtureSeed(network, label), bip32Versions(network));
}

function foreignRoot(network: 'mainnet' | 'signet'): HDKey {
  return HDKey.fromMasterSeed(fixtureSeed(network, 'foreign-root'), bip32Versions(network));
}

function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

function signRecordRole(record: ContractRecord, role: VaultSignerRole) {
  const { policy, plan } = record;
  const signerRoot = root(plan.network, role);
  try {
    const request = createVaultPartialSignatureInput({ policy, plan, role });
    return {
      request,
      result: signVaultPartialSignature({ policy, request, signerRoot, nowMs: '1785542402000' }),
    };
  } finally {
    signerRoot.wipePrivateData();
  }
}

function signRole(network: 'mainnet' | 'signet', role: VaultSignerRole) {
  return signRecordRole(b2Record(network), role);
}

function signRecordRoleWithoutLowR(record: ContractRecord, role: VaultSignerRole): string {
  const tx = Transaction.fromPSBT(hexToBytes(constructVaultPsbt(record.policy, record.plan)), {
    PSBTVersion: 0,
    lowR: false,
  });
  const signerRoot = root(record.plan.network, role);
  const origin = record.policy.signers[VAULT_ROLES.indexOf(role)]!;
  const account = signerRoot.derive(origin.originPath);
  try {
    for (const [index, input] of record.plan.inputs.entries()) {
      const branch = account.deriveChild(input.branch === 'receive' ? 0 : 1);
      const child = branch.deriveChild(input.derivationIndex);
      try {
        tx.signIdx(child.privateKey!, index, [SigHash.ALL]);
      } finally {
        child.wipePrivateData();
        branch.wipePrivateData();
      }
    }
    return bytesToHex(tx.toPSBT(0));
  } finally {
    account.wipePrivateData();
    signerRoot.wipePrivateData();
  }
}

function updatePsbt(psbtHex: string, update: (tx: Transaction) => void, allowUnknown = false): string {
  const tx = Transaction.fromPSBT(hexToBytes(psbtHex), { PSBTVersion: 0, lowR: true, allowUnknown });
  update(tx);
  return bytesToHex(tx.toPSBT(0));
}

function u32le(value: number): string {
  const bytes = new Uint8Array(4);
  new DataView(bytes.buffer).setUint32(0, value, true);
  return bytesToHex(bytes);
}

function derivationValueHex(value: NonNullable<ReturnType<Transaction['getInput']>['bip32Derivation']>[number][1]): string {
  return `${value.fingerprint.toString(16).padStart(8, '0')}${value.path.map(u32le).join('')}`;
}

function replaceOnce(hex: string, before: string, after: string): string {
  const offset = hex.indexOf(before);
  if (offset < 0 || before.length !== after.length) throw new Error('test mutation target mismatch');
  return `${hex.slice(0, offset)}${after}${hex.slice(offset + before.length)}`;
}

function compactAt(bytes: Uint8Array, offset: number): { value: number; size: number } {
  const prefix = bytes[offset]!;
  if (prefix < 0xfd) return { value: prefix, size: 1 };
  if (prefix === 0xfd) return { value: new DataView(bytes.buffer, bytes.byteOffset + offset + 1, 2).getUint16(0, true), size: 3 };
  throw new Error('test PSBT field unexpectedly large');
}

function mapBounds(psbtHex: string, wanted: number): { start: number; end: number; firstEnd: number } {
  const bytes = hexToBytes(psbtHex);
  let offset = 5;
  for (let mapIndex = 0; mapIndex <= wanted; mapIndex += 1) {
    const start = offset;
    let firstEnd = start;
    while (true) {
      const keyLength = compactAt(bytes, offset);
      offset += keyLength.size;
      if (keyLength.value === 0) {
        if (mapIndex === wanted) return { start, end: offset - 1, firstEnd };
        break;
      }
      offset += keyLength.value;
      const valueLength = compactAt(bytes, offset);
      offset += valueLength.size + valueLength.value;
      if (firstEnd === start) firstEnd = offset;
    }
  }
  throw new Error('test PSBT map not found');
}

function insertHexAt(psbtHex: string, byteOffset: number, insertedHex: string): string {
  const offset = byteOffset * 2;
  return `${psbtHex.slice(0, offset)}${insertedHex}${psbtHex.slice(offset)}`;
}

describe('ADR 0007 B2 deterministic PSBT construction and signing', () => {
  it.each(['mainnet', 'signet'] as const)(
    'constructs exact PSBTv0 inputs and change metadata for %s',
    (network) => {
      const { policy, plan } = b2Record(network);
      const first = constructVaultPsbt(policy, plan);
      const second = constructVaultPsbt(policy, plan);
      expect(first).toBe(second);
      expect(psbtVectors.records[network].policyId).toBe(policy.policyId);
      expect(psbtVectors.records[network].plan).toEqual(plan);
      expect(psbtVectors.records[network].unsignedPsbtHex).toBe(first);
      const validated = validateVaultPsbt(policy, plan, first);
      expect(validated.roles).toEqual([]);
      expect(validated.psbtHash).toBe(vaultPsbtHash(first));
      const tx = Transaction.fromPSBT(hexToBytes(first));
      expect(tx.opts.PSBTVersion).toBe(0);
      expect(bytesToHex(tx.unsignedTx)).toBe(plan.unsignedTransactionHex);
      for (let index = 0; index < plan.inputs.length; index += 1) {
        const actual = tx.getInput(index);
        expect(actual.witnessUtxo?.amount).toBe(BigInt(plan.inputs[index]!.valueSats));
        expect(bytesToHex(actual.witnessUtxo!.script)).toBe(plan.inputs[index]!.scriptPubKeyHex);
        expect(bytesToHex(actual.witnessScript!)).toBe(plan.inputs[index]!.witnessScriptHex);
        expect(actual.sighashType).toBe(SigHash.ALL);
        expect(actual.bip32Derivation).toHaveLength(3);
      }
      expect(tx.getOutput(0).bip32Derivation).toBeUndefined();
      expect(tx.getOutput(1).bip32Derivation).toHaveLength(3);
      expect(tx.getOutput(1).witnessScript).toBeDefined();
    },
  );

  it.each(['mainnet', 'signet'] as const)(
    'adds exactly one complete valid logical role for %s',
    (network) => {
      for (const role of VAULT_ROLES) {
        const { policy, plan } = b2Record(network);
        const { request, result } = signRole(network, role);
        expect(result.roleAdded).toBe(role);
        expect(result.priorPsbtHash).toBe(request.psbtHash);
        expect(result.signedPsbtHash).toBe(vaultPsbtHash(result.signedPsbtHex));
        expect(result).toEqual(psbtVectors.records[network].partials[role].result);
        expect(validateVaultPsbt(policy, plan, result.signedPsbtHex).roles).toEqual([role]);
      }
    },
  );

  it('rejects a foreign root and a root assigned to a different logical role before signing', () => {
    const { policy, plan } = b2Record('signet');
    const request = createVaultPartialSignatureInput({ policy, plan, role: 'desktop-a' });
    const foreign = foreignRoot('signet');
    const mobile = root('signet', 'mobile-b');
    try {
      expect(() => signVaultPartialSignature({ policy, request, signerRoot: foreign, nowMs: '1785542402000' }))
        .toThrow('complete expected Vault origin');
      expect(() => signVaultPartialSignature({ policy, request, signerRoot: mobile, nowMs: '1785542402000' }))
        .toThrow('complete expected Vault origin');
    } finally {
      foreign.wipePrivateData();
      mobile.wipePrivateData();
    }
  });

  it('rejects stale/future signing and any retained plan or request identity mutation', () => {
    const { policy, plan } = b2Record('signet');
    const signerRoot = root('signet', 'desktop-a');
    const request = createVaultPartialSignatureInput({ policy, plan, role: 'desktop-a' });
    try {
      expect(() => signVaultPartialSignature({ policy, request, signerRoot, nowMs: '1785542400000' }))
        .toThrow('freshness');
      expect(() => signVaultPartialSignature({ policy, request, signerRoot, nowMs: '1785542700001' }))
        .toThrow('freshness');
      expect(() => signVaultPartialSignature({
        policy, request: { ...request, planId: 'ff'.repeat(16) }, signerRoot, nowMs: '1785542402000',
      })).toThrow();
      expect(() => signVaultPartialSignature({
        policy, request: { ...request, psbtHash: 'ff'.repeat(32) }, signerRoot, nowMs: '1785542402000',
      })).toThrow();
    } finally {
      signerRoot.wipePrivateData();
    }
  });
});

describe('ADR 0007 B2 combination, quorum, and finalization', () => {
  it.each(['mainnet', 'signet'] as const)(
    'combines and finalizes A+B, A+C, and B+C on %s',
    (network) => {
      const { policy, plan } = b2Record(network);
      const signed = Object.fromEntries(VAULT_ROLES.map((role) => [role, signRole(network, role).result])) as
        Record<VaultSignerRole, ReturnType<typeof signRole>['result']>;
      const pairs: [VaultSignerRole, VaultSignerRole][] = [
        ['desktop-a', 'mobile-b'],
        ['desktop-a', 'recovery-c'],
        ['mobile-b', 'recovery-c'],
      ];
      for (const pair of pairs) {
        const pairName = pair.map((role) => role === 'desktop-a' ? 'A' : role === 'mobile-b' ? 'B' : 'C').join('+');
        const combined = combineVaultPartialSignatureResults({
          policy, plan, results: pair.map((role) => signed[role]),
        });
        expect(combined.roles).toEqual([...pair].sort((a, b) => VAULT_ROLES.indexOf(a) - VAULT_ROLES.indexOf(b)));
        expect(combined.psbtHex).toBe(psbtVectors.records[network].quorums[pairName]!.combinedPsbtHex);
        const finalized = finalizeVaultPsbt({ policy, plan, psbtHex: combined.psbtHex, nowMs: '1785542402000' });
        expect(finalized.transactionHex).toBe(psbtVectors.records[network].quorums[pairName]!.transactionHex);
        expect(finalized.roles).toEqual(combined.roles);
        expect(finalized.vsize).toBe(plan.vsize);
        expect(verifyFinalizedVaultTransaction({ policy, plan, transactionHex: finalized.transactionHex })).toEqual(finalized);
      }
    },
    10_000,
  );

  it('deterministically combines independent partial order and selects A+B from a three-role PSBT', () => {
    const { policy, plan } = b2Record('signet');
    const a = signRole('signet', 'desktop-a').result;
    const b = signRole('signet', 'mobile-b').result;
    const c = signRole('signet', 'recovery-c').result;
    const abc = combineVaultPsbts({ policy, plan, psbtHexes: [c.signedPsbtHex, a.signedPsbtHex, b.signedPsbtHex] });
    const cba = combineVaultPsbts({ policy, plan, psbtHexes: [b.signedPsbtHex, c.signedPsbtHex, a.signedPsbtHex] });
    expect(abc.psbtHex).toBe(cba.psbtHex);
    expect(abc.roles).toEqual(VAULT_ROLES);
    expect(finalizeVaultPsbt({ policy, plan, psbtHex: abc.psbtHex, nowMs: '1785542402000' }).roles)
      .toEqual(['desktop-a', 'mobile-b']);
  });

  it('accepts valid shorter DER signatures and returns the smaller actual finalized vsize', () => {
    const record = multiInputRecord();
    const a = signRecordRole(record, 'desktop-a').result;
    const b = signRecordRole(record, 'mobile-b').result;
    for (const result of [a, b]) {
      const signed = Transaction.fromPSBT(hexToBytes(result.signedPsbtHex));
      for (let index = 0; index < record.plan.inputs.length; index += 1) {
        expect(signed.getInput(index).partialSig?.[0]?.[1].length).toBeLessThan(72);
      }
    }
    const combined = combineVaultPartialSignatureResults({
      policy: record.policy,
      plan: record.plan,
      results: [a, b],
    });
    const finalized = finalizeVaultPsbt({
      policy: record.policy,
      plan: record.plan,
      psbtHex: combined.psbtHex,
      nowMs: '1785542402000',
    });
    expect(finalized.vsize).toBeLessThan(record.plan.vsize);
    expect(verifyFinalizedVaultTransaction({
      policy: record.policy,
      plan: record.plan,
      transactionHex: finalized.transactionHex,
    })).toEqual(finalized);
  });

  it('accepts valid 72-byte DER+sighash witness signatures at the approved vsize bound', () => {
    const record = b2Record('signet');
    const partials = (['desktop-a', 'recovery-c'] as const)
      .map((role) => signRecordRoleWithoutLowR(record, role));
    for (const psbtHex of partials) {
      expect(Transaction.fromPSBT(hexToBytes(psbtHex)).getInput(0).partialSig?.[0]?.[1]).toHaveLength(72);
    }
    const combined = combineVaultPsbts({
      policy: record.policy,
      plan: record.plan,
      psbtHexes: partials,
    });
    const finalized = finalizeVaultPsbt({
      policy: record.policy,
      plan: record.plan,
      psbtHex: combined.psbtHex,
      nowMs: '1785542402000',
    });
    expect(finalized.vsize).toBe(record.plan.vsize);
    expect(finalized.roles).toEqual(['desktop-a', 'recovery-c']);
  });

  it('supports sequential A then B signing without changing A partial signatures', () => {
    const { policy, plan } = b2Record('signet');
    const a = signRole('signet', 'desktop-a').result;
    const request = createVaultPartialSignatureInput({
      policy, plan, role: 'mobile-b', psbtHex: a.signedPsbtHex,
    });
    const mobile = root('signet', 'mobile-b');
    try {
      const result = signVaultPartialSignature({ policy, request, signerRoot: mobile, nowMs: '1785542402000' });
      expect(validateVaultPsbt(policy, plan, result.signedPsbtHex).roles).toEqual(['desktop-a', 'mobile-b']);
      expect(finalizeVaultPsbt({ policy, plan, psbtHex: result.signedPsbtHex, nowMs: '1785542402000' }).roles)
        .toEqual(['desktop-a', 'mobile-b']);
    } finally {
      mobile.wipePrivateData();
    }
  });

  it('rejects A+A, B+B, duplicate-role results, unexpected role labels, and sub-quorum finalization', () => {
    const { policy, plan } = b2Record('signet');
    const a = signRole('signet', 'desktop-a').result;
    const b = signRole('signet', 'mobile-b').result;
    expect(() => combineVaultPsbts({ policy, plan, psbtHexes: [a.signedPsbtHex, a.signedPsbtHex] }))
      .toThrow('duplicate logical role');
    expect(() => combineVaultPsbts({ policy, plan, psbtHexes: [b.signedPsbtHex, b.signedPsbtHex] }))
      .toThrow('duplicate logical role');
    expect(() => combineVaultPartialSignatureResults({
      policy, plan, results: [a, { ...b, roleAdded: 'desktop-a' }],
    })).toThrow('role');
    expect(() => finalizeVaultPsbt({ policy, plan, psbtHex: a.signedPsbtHex, nowMs: '1785542402000' }))
      .toThrow('quorum');
  });
});

describe('ADR 0007 B2 fail-closed PSBT and immutable-plan controls', () => {
  it('rejects wrong policy/network and all unsigned transaction, output order, amount, fee, and change mutations', () => {
    const signet = b2Record('signet');
    const mainnet = b2Record('mainnet');
    const base = constructVaultPsbt(signet.policy, signet.plan);
    expect(() => validateVaultPsbt(mainnet.policy, signet.plan, base)).toThrow('policy');
    expect(() => validateVaultPsbt(signet.policy, { ...signet.plan, network: 'mainnet' }, base)).toThrow();

    const changedUnsigned = updatePsbt(base, (tx) => tx.updateOutput(0, { amount: 89_999n }));
    expect(() => validateVaultPsbt(signet.policy, signet.plan, changedUnsigned)).toThrow('unsigned transaction');

    for (const mutation of [
      (plan: VaultUnsignedPlanV1) => { plan.outputs.reverse(); },
      (plan: VaultUnsignedPlanV1) => { plan.outputs[0]!.valueSats = '89999'; },
      (plan: VaultUnsignedPlanV1) => { plan.feeSats = '1001'; },
      (plan: VaultUnsignedPlanV1) => { plan.changeSats = '8999'; },
      (plan: VaultUnsignedPlanV1) => { plan.inputs[0]!.classificationEvidenceHash = 'ff'.repeat(32); },
      (plan: VaultUnsignedPlanV1) => { plan.source.classificationRevisionHash = 'ff'.repeat(32); },
      (plan: VaultUnsignedPlanV1) => { plan.requestId = 'ff'.repeat(16); },
    ]) {
      const changed = clone(signet.plan);
      mutation(changed);
      expect(() => constructVaultPsbt(signet.policy, changed)).toThrow();
    }
  });

  it('rejects wrong/missing/extra origins, wrong branch/index, substituted scripts/prevouts, and unsupported sighashes', () => {
    const { policy, plan } = b2Record('signet');
    const base = constructVaultPsbt(policy, plan);
    const tx = Transaction.fromPSBT(hexToBytes(base));
    const derivations = tx.getInput(0).bip32Derivation!;

    const missing = updatePsbt(base, (value) => value.updateInput(0, {
      bip32Derivation: [[derivations[0]![0], undefined]] as unknown as typeof derivations,
    }));
    expect(() => validateVaultPsbt(policy, plan, missing)).toThrow('cardinality');

    const foreign = foreignRoot('signet');
    try {
      const foreignChild = foreign.derive("m/48'/1'/0'/2'/0/0");
      const extra = updatePsbt(base, (value) => value.updateInput(0, { bip32Derivation: [[
        foreignChild.publicKey!, { fingerprint: foreign.fingerprint, path: [
          0x8000_0030, 0x8000_0001, 0x8000_0000, 0x8000_0002, 0, 0,
        ] },
      ]] }));
      expect(() => validateVaultPsbt(policy, plan, extra)).toThrow('cardinality');
      foreignChild.wipePrivateData();
    } finally {
      foreign.wipePrivateData();
    }

    const originalOrigin = derivations[0]![1];
    const wrongOrigin = replaceOnce(base, derivationValueHex(originalOrigin), derivationValueHex({
      ...originalOrigin, fingerprint: 0xffff_ffff,
    }));
    expect(() => validateVaultPsbt(policy, plan, wrongOrigin)).toThrow('derivation/origin');

    const wrongBranch = replaceOnce(base, derivationValueHex(originalOrigin), derivationValueHex({
      ...originalOrigin, path: [...originalOrigin.path.slice(0, -2), 1, 0],
    }));
    expect(() => validateVaultPsbt(policy, plan, wrongBranch)).toThrow('derivation/origin');

    const wrongIndex = replaceOnce(base, derivationValueHex(originalOrigin), derivationValueHex({
      ...originalOrigin, path: [...originalOrigin.path.slice(0, -1), 1],
    }));
    expect(() => validateVaultPsbt(policy, plan, wrongIndex)).toThrow('derivation/origin');

    const witnessHex = plan.inputs[0]!.witnessScriptHex;
    const substitutedWitness = replaceOnce(base, witnessHex, `${witnessHex.slice(0, -2)}00`);
    expect(() => validateVaultPsbt(policy, plan, substitutedWitness)).toThrow();
    const substitutedPrevout = updatePsbt(base, (value) => value.updateInput(0, {
      witnessUtxo: { amount: 99_999n, script: hexToBytes(plan.inputs[0]!.scriptPubKeyHex) },
    }));
    expect(() => validateVaultPsbt(policy, plan, substitutedPrevout)).toThrow('prevout');
    const wrongSighash = updatePsbt(base, (value) => value.updateInput(0, { sighashType: SigHash.NONE }));
    expect(() => validateVaultPsbt(policy, plan, wrongSighash)).toThrow('sighash');
  });

  it('rejects malformed PSBTs, duplicate map keys, unknown/proprietary signing fields, and foreign signatures', () => {
    const { policy, plan } = b2Record('signet');
    const base = constructVaultPsbt(policy, plan);
    expect(() => validateVaultPsbt(policy, plan, `${base}00`)).toThrow();
    expect(() => validateVaultPsbt(policy, plan, base.slice(0, -2))).toThrow();

    const unknown = updatePsbt(base, (tx) => tx.updateInput(0, {
      unknown: [[{ type: 0xfc, key: Uint8Array.of(1) }, Uint8Array.of(2)]],
    } as unknown as Parameters<Transaction['updateInput']>[1], true), true);
    expect(() => validateVaultPsbt(policy, plan, unknown)).toThrow('unknown input');

    const globalBounds = mapBounds(base, 0);
    const unknownGlobal = insertHexAt(base, globalBounds.end, '02fc010102');
    expect(() => validateVaultPsbt(policy, plan, unknownGlobal)).toThrow();

    const inputBounds = mapBounds(base, 1);
    const bytes = hexToBytes(base);
    const duplicateEntryHex = bytesToHex(bytes.slice(inputBounds.start, inputBounds.firstEnd));
    const duplicateKey = insertHexAt(base, inputBounds.end, duplicateEntryHex);
    expect(() => validateVaultPsbt(policy, plan, duplicateKey)).toThrow();

    const por = updatePsbt(base, (tx) => tx.updateInput(0, { porCommitment: Uint8Array.of(1) }));
    expect(() => validateVaultPsbt(policy, plan, por)).toThrow('unknown input');

    const foreign = foreignRoot('signet');
    try {
      const foreignKey = foreign.derive("m/48'/1'/0'/2'/0/0");
      const tx = Transaction.fromPSBT(hexToBytes(base), { lowR: true });
      tx.updateInput(0, { partialSig: [[foreignKey.publicKey!, Uint8Array.of(0x30, 0x00, SigHash.ALL)]] }, true);
      expect(() => validateVaultPsbt(policy, plan, bytesToHex(tx.toPSBT(0)))).toThrow('foreign');
      foreignKey.wipePrivateData();
    } finally {
      foreign.wipePrivateData();
    }
  });

  it.each(['mainnet', 'signet'] as const)('replays every stable %s adversarial PSBT vector', (network) => {
    const { policy, plan } = b2Record(network);
    const adversarial = psbtVectors.records[network].adversarial;
    for (const psbtHex of [
      adversarial.truncatedPsbtHex,
      adversarial.trailingPsbtHex,
      adversarial.unknownGlobalFieldPsbtHex,
      adversarial.changedUnsignedOutputPsbtHex,
      adversarial.unsupportedSighashPsbtHex,
      adversarial.substitutedWitnessScriptPsbtHex,
      adversarial.malformedPartialSignaturePsbtHex,
      adversarial.highSPartialSignaturePsbtHex,
    ]) expect(() => validateVaultPsbt(policy, plan, psbtHex)).toThrow();
    expect(() => combineVaultPsbts({ policy, plan, psbtHexes: adversarial.duplicateRolePsbtHexes }))
      .toThrow('duplicate logical role');
    expect(() => combineVaultPartialSignatureResults({
      policy,
      plan,
      results: [
        psbtVectors.records[network].partials['desktop-a'].result,
        adversarial.unexpectedRoleResult,
      ],
    })).toThrow();
  });

  it('rejects malformed, high-S, and non-ALL partial signatures', () => {
    const { policy, plan } = b2Record('signet');
    const a = signRole('signet', 'desktop-a').result;
    const base = constructVaultPsbt(policy, plan);
    const signed = Transaction.fromPSBT(hexToBytes(a.signedPsbtHex));
    const [publicKey, signature] = signed.getInput(0).partialSig![0]!;
    const malformed = updatePsbt(base, (tx) => {
      tx.updateInput(0, { partialSig: [[publicKey, Uint8Array.of(0x30, 0x00, SigHash.ALL)]] }, true);
    });
    expect(() => validateVaultPsbt(policy, plan, malformed)).toThrow();
    const nonAll = updatePsbt(base, (tx) => {
      tx.updateInput(0, { partialSig: [[publicKey, new Uint8Array([...signature.slice(0, -1), SigHash.NONE])]] }, true);
    });
    expect(() => validateVaultPsbt(policy, plan, nonAll)).toThrow('SIGHASH_ALL');
    const low = secp256k1.Signature.fromBytes(signature.slice(0, -1), 'der');
    const high = new secp256k1.Signature(low.r, secp256k1.CURVE.n - low.s).toBytes('der');
    const highS = updatePsbt(base, (tx) => {
      tx.updateInput(0, { partialSig: [[publicKey, new Uint8Array([...high, SigHash.ALL])]] }, true);
    });
    expect(() => validateVaultPsbt(policy, plan, highS)).toThrow('invalid SIGHASH_ALL');
  });

  it('rejects a logical role that signed only a subset of a multi-input plan', () => {
    const { policy, plan } = multiInputRecord();
    const base = constructVaultPsbt(policy, plan);
    const tx = Transaction.fromPSBT(hexToBytes(base), { lowR: true });
    const signerRoot = root('signet', 'desktop-a');
    const child = signerRoot.derive("m/48'/1'/0'/2'/0/0");
    try {
      tx.signIdx(child.privateKey!, 0, [SigHash.ALL]);
      expect(() => validateVaultPsbt(policy, plan, bytesToHex(tx.toPSBT(0))))
        .toThrow('did not sign every Vault input');
    } finally {
      child.wipePrivateData();
      signerRoot.wipePrivateData();
    }
  });

  it('rejects finalized transaction witness/script/signature/order and unsigned-byte mutation', () => {
    const { policy, plan } = b2Record('signet');
    const a = signRole('signet', 'desktop-a').result;
    const b = signRole('signet', 'mobile-b').result;
    const combined = combineVaultPartialSignatureResults({ policy, plan, results: [a, b] });
    const final = finalizeVaultPsbt({ policy, plan, psbtHex: combined.psbtHex, nowMs: '1785542402000' });
    const tx = Transaction.fromRaw(hexToBytes(final.transactionHex));
    const witness = tx.getInput(0).finalScriptWitness!;
    tx.updateInput(0, { finalScriptWitness: [witness[0]!, witness[2]!, witness[1]!, witness[3]!] }, true);
    expect(() => verifyFinalizedVaultTransaction({ policy, plan, transactionHex: bytesToHex(tx.toBytes(true, true)) }))
      .toThrow('ordering');

    const changed = Transaction.fromRaw(hexToBytes(final.transactionHex));
    changed.updateOutput(0, { amount: 89_999n }, true);
    expect(() => verifyFinalizedVaultTransaction({ policy, plan, transactionHex: bytesToHex(changed.toBytes(true, true)) }))
      .toThrow('unsigned meaning');
  });
});
