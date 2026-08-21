/**
 * ADR 0007 Workstream B2 PSBT construction, partial signing, combination, and
 * native-P2WSH finalization.
 *
 * This is a closed PSBTv0 profile for the established B0/B1 policy. It is not a
 * general multisig or PSBT policy engine. Every map key and signing-meaning
 * field is enumerated below; unknown/proprietary fields, alternate scripts,
 * incomplete logical-role signatures, and non-SIGHASH_ALL signatures fail
 * closed before a private key is used.
 *
 * These low-level B2 mechanics deliberately do not enforce B3 asset safety.
 * They remain available for conformance and provider-independent recovery;
 * production coordinators must use the asset-safe B3 wrappers instead.
 */
import { secp256k1 } from '@noble/curves/secp256k1';
import { HDKey } from '@scure/bip32';
import { SigHash, Transaction } from '@scure/btc-signer';
import { bitcoinNetwork } from '../keys/derivation';
import { getCryptoProvider } from './crypto-provider';
import { bytesToHex, hexToBytes } from './encoding';
import {
  VAULT_ROLES,
  bip32Versions,
  vaultPartialSignatureInputSchema,
  vaultPartialSignatureResultSchema,
  type VaultPartialSignatureInputV1,
  type VaultPartialSignatureResultV1,
  type VaultSignerRole,
  type VaultUnsignedPlanV1,
  type VaultPolicyIdentityV1,
} from './multisig-contracts';
import {
  assertVaultOwnership,
  deriveVaultOutput,
  type VaultDerivedOutputV1,
} from './multisig-descriptors';
import {
  assertVaultPolicyIdentity,
  assertVaultUnsignedPlan,
  canonicalVaultPlanBytes,
  parseCanonicalVaultPlan,
  serializeVaultPartialSignatureInput,
  serializeVaultPartialSignatureResult,
  vaultPsbtHash,
} from './multisig-encoding';

const PSBT_MAGIC = Uint8Array.of(0x70, 0x73, 0x62, 0x74, 0xff);
const HARDENED = 0x8000_0000;
const MAX_PSBT_BYTES = 2_000_000;
const MAX_DER_SIGHASH_SIGNATURE_BYTES = 72;

type KeyValue = { key: Uint8Array; value: Uint8Array };
type PsbtMap = KeyValue[];

export interface VaultPsbtValidation {
  version: 1;
  psbtHex: string;
  psbtHash: string;
  roles: VaultSignerRole[];
  inputOwnership: VaultDerivedOutputV1[];
}

export interface CombinedVaultPsbt extends VaultPsbtValidation {
  roles: [VaultSignerRole, VaultSignerRole] | [VaultSignerRole, VaultSignerRole, VaultSignerRole];
}

export interface FinalizedVaultTransaction {
  version: 1;
  transactionHex: string;
  txid: string;
  wtxid: string;
  vsize: number;
  roles: [VaultSignerRole, VaultSignerRole];
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((byte, index) => byte === right[index]);
}

function compareBytes(left: Uint8Array, right: Uint8Array): number {
  const length = Math.min(left.length, right.length);
  for (let index = 0; index < length; index += 1) {
    const difference = left[index]! - right[index]!;
    if (difference !== 0) return difference;
  }
  return left.length - right.length;
}

function roleOrder(left: VaultSignerRole, right: VaultSignerRole): number {
  return VAULT_ROLES.indexOf(left) - VAULT_ROLES.indexOf(right);
}

function fingerprintNumber(hex: string): number {
  return Number.parseInt(hex, 16);
}

function fullDerivationPath(network: VaultPolicyIdentityV1['network'], branch: 'receive' | 'change', index: number): number[] {
  return [
    HARDENED + 48,
    HARDENED + (network === 'mainnet' ? 0 : 1),
    HARDENED,
    HARDENED + 2,
    branch === 'receive' ? 0 : 1,
    index,
  ];
}

function readCompactSize(bytes: Uint8Array, cursor: { offset: number }): number {
  if (cursor.offset >= bytes.length) throw new Error('truncated PSBT compact size');
  const prefix = bytes[cursor.offset++]!;
  if (prefix < 0xfd) return prefix;
  const width = prefix === 0xfd ? 2 : prefix === 0xfe ? 4 : 8;
  if (cursor.offset + width > bytes.length) throw new Error('truncated PSBT compact size');
  const view = new DataView(bytes.buffer, bytes.byteOffset + cursor.offset, width);
  const value = width === 2 ? BigInt(view.getUint16(0, true))
    : width === 4 ? BigInt(view.getUint32(0, true)) : view.getBigUint64(0, true);
  cursor.offset += width;
  if ((width === 2 && value < 0xfdn) || (width === 4 && value <= 0xffffn) ||
      (width === 8 && value <= 0xffff_ffffn) || value > BigInt(MAX_PSBT_BYTES)) {
    throw new Error('non-canonical or excessive PSBT compact size');
  }
  return Number(value);
}

function take(bytes: Uint8Array, cursor: { offset: number }, length: number): Uint8Array {
  if (length < 0 || cursor.offset + length > bytes.length) throw new Error('truncated PSBT field');
  const result = bytes.slice(cursor.offset, cursor.offset + length);
  cursor.offset += length;
  return result;
}

function readMap(bytes: Uint8Array, cursor: { offset: number }): PsbtMap {
  const result: PsbtMap = [];
  const keys = new Set<string>();
  while (true) {
    const keyLength = readCompactSize(bytes, cursor);
    if (keyLength === 0) return result;
    const key = take(bytes, cursor, keyLength);
    const keyHex = bytesToHex(key);
    if (keys.has(keyHex)) throw new Error('duplicate PSBT map key');
    keys.add(keyHex);
    const value = take(bytes, cursor, readCompactSize(bytes, cursor));
    result.push({ key, value });
  }
}

function scanPsbtMaps(psbtHex: string, inputCount: number, outputCount: number): PsbtMap[] {
  const bytes = hexToBytes(psbtHex);
  if (bytes.length > MAX_PSBT_BYTES || !equalBytes(bytes.slice(0, PSBT_MAGIC.length), PSBT_MAGIC)) {
    throw new Error('invalid PSBTv0 framing');
  }
  const cursor = { offset: PSBT_MAGIC.length };
  const maps: PsbtMap[] = [];
  for (let index = 0; index < 1 + inputCount + outputCount; index += 1) maps.push(readMap(bytes, cursor));
  if (cursor.offset !== bytes.length) throw new Error('trailing or excess PSBT maps');
  return maps;
}

function assertMapKeys(map: PsbtMap, allowed: (key: Uint8Array) => boolean, label: string): void {
  for (const { key } of map) if (!allowed(key)) throw new Error(`unknown ${label} PSBT field`);
}

function entriesOfType(map: PsbtMap, type: number): KeyValue[] {
  return map.filter(({ key }) => key[0] === type);
}

function assertRawPsbtProfile(maps: PsbtMap[], plan: VaultUnsignedPlanV1): void {
  const global = maps[0]!;
  if (global.length !== 1 || bytesToHex(global[0]!.key) !== '00' ||
      bytesToHex(global[0]!.value) !== plan.unsignedTransactionHex) {
    throw new Error('PSBT global map is not the exact v0 unsigned transaction');
  }
  for (let index = 0; index < plan.inputs.length; index += 1) {
    const map = maps[1 + index]!;
    assertMapKeys(map, (key) => key.length === 1
      ? [0x01, 0x03, 0x05].includes(key[0]!)
      : key.length === 34 && (key[0] === 0x02 || key[0] === 0x06), `input ${index}`);
    if (entriesOfType(map, 0x01).length !== 1 || entriesOfType(map, 0x03).length !== 1 ||
        entriesOfType(map, 0x05).length !== 1 || entriesOfType(map, 0x06).length !== 3 ||
        entriesOfType(map, 0x02).length > 3) {
      throw new Error(`input ${index} PSBT field cardinality mismatch`);
    }
  }
  for (let index = 0; index < plan.outputs.length; index += 1) {
    const map = maps[1 + plan.inputs.length + index]!;
    const isChange = plan.outputs[index]!.purpose === 'vault-change';
    assertMapKeys(map, (key) => isChange && (key.length === 1 ? key[0] === 0x01 : key.length === 34 && key[0] === 0x02),
      `output ${index}`);
    if (isChange && (entriesOfType(map, 0x01).length !== 1 || entriesOfType(map, 0x02).length !== 3)) {
      throw new Error(`output ${index} Vault change metadata is incomplete`);
    }
    if (!isChange && map.length !== 0) throw new Error(`output ${index} has unexpected signing metadata`);
  }
}

function assertCanonicalPlanBytes(plan: VaultUnsignedPlanV1, canonicalPlanHex?: string): void {
  assertVaultUnsignedPlan(plan);
  const canonicalHex = bytesToHex(canonicalVaultPlanBytes(plan));
  if (canonicalPlanHex !== undefined) {
    const reparsed = parseCanonicalVaultPlan(hexToBytes(canonicalPlanHex));
    if (canonicalPlanHex !== canonicalHex || reparsed.planDigest !== plan.planDigest) {
      throw new Error('canonical Vault plan bytes differ from the approved plan');
    }
  }
}

function assertPlanPolicyAndTransaction(policy: VaultPolicyIdentityV1, plan: VaultUnsignedPlanV1): VaultDerivedOutputV1[] {
  assertVaultPolicyIdentity(policy);
  assertCanonicalPlanBytes(plan);
  if (plan.network !== policy.network || plan.policyId !== policy.policyId || plan.policyVersion !== policy.policyVersion ||
      plan.sighash !== 'all') throw new Error('Vault plan policy binding mismatch');

  const raw = Transaction.fromRaw(hexToBytes(plan.unsignedTransactionHex));
  if (raw.inputsLength !== plan.inputs.length || raw.outputsLength !== plan.outputs.length ||
      bytesToHex(raw.unsignedTx) !== plan.unsignedTransactionHex) {
    throw new Error('Vault plan unsigned transaction shape mismatch');
  }
  const ownership = plan.inputs.map((input, index) => {
    if (input.sighash !== 'all') throw new Error('unsupported Vault input sighash');
    const derived = deriveVaultOutput(policy, input.branch, input.derivationIndex);
    assertVaultOwnership(policy, derived);
    if (derived.witnessScriptHex !== input.witnessScriptHex || derived.scriptPubKeyHex !== input.scriptPubKeyHex) {
      throw new Error(`Vault input ${index} ownership differs from B1 policy`);
    }
    const actual = raw.getInput(index);
    if (!actual.txid || bytesToHex(actual.txid) !== input.txid || actual.index !== input.vout ||
        actual.sequence !== input.sequence || (actual.finalScriptSig?.length ?? 0) !== 0 ||
        (actual.finalScriptWitness?.length ?? 0) !== 0) {
      throw new Error(`Vault plan input ${index} differs from unsigned bytes`);
    }
    return derived;
  });
  for (let index = 0; index < plan.outputs.length; index += 1) {
    const output = plan.outputs[index]!;
    const actual = raw.getOutput(index);
    if (!actual.script || bytesToHex(actual.script) !== output.scriptPubKeyHex || actual.amount !== BigInt(output.valueSats)) {
      throw new Error(`Vault plan output ${index} differs from unsigned bytes`);
    }
    const address = raw.getOutputAddress(index, bitcoinNetwork(plan.network));
    if (address !== output.address) throw new Error(`Vault plan output ${index} address mismatch`);
    if (output.purpose === 'vault-change') {
      const derived = deriveVaultOutput(policy, 'change', output.derivationIndex!);
      if (derived.scriptPubKeyHex !== output.scriptPubKeyHex || derived.address !== output.address) {
        throw new Error(`Vault change output ${index} ownership mismatch`);
      }
    }
  }
  const inputTotal = plan.inputs.reduce((sum, input) => sum + BigInt(input.valueSats), 0n);
  const outputTotal = plan.outputs.reduce((sum, output) => sum + BigInt(output.valueSats), 0n);
  const fee = inputTotal - outputTotal;
  const sized = Transaction.fromRaw(hexToBytes(plan.unsignedTransactionHex));
  for (let index = 0; index < plan.inputs.length; index += 1) {
    sized.updateInput(index, { finalScriptWitness: [
      new Uint8Array(),
      new Uint8Array(MAX_DER_SIGHASH_SIGNATURE_BYTES),
      new Uint8Array(MAX_DER_SIGHASH_SIGNATURE_BYTES),
      hexToBytes(plan.inputs[index]!.witnessScriptHex),
    ] }, true);
  }
  if (sized.vsize !== plan.vsize) throw new Error('Vault plan native-P2WSH vsize upper-bound mismatch');
  const change = plan.outputs.filter((output) => output.purpose === 'vault-change')
    .reduce((sum, output) => sum + BigInt(output.valueSats), 0n);
  const destination = plan.outputs[plan.destination.outputIndex];
  if (fee <= 0n || fee !== BigInt(plan.feeSats) || change !== BigInt(plan.changeSats) || !destination ||
      BigInt(destination.valueSats) !== BigInt(plan.amountSats) || destination.address !== plan.destination.address ||
      (fee * 1000n + BigInt(plan.vsize) - 1n) / BigInt(plan.vsize) !== BigInt(plan.feeRateSatPerKvB)) {
    throw new Error('Vault plan amount, change, fee, or fee-rate binding mismatch');
  }
  return ownership;
}

function expectedDerivations(output: VaultDerivedOutputV1) {
  return output.logicalKeys.map((key) => [
    hexToBytes(key.publicKeyHex),
    { fingerprint: fingerprintNumber(key.masterFingerprintHex), path: fullDerivationPath(output.network, output.branch, output.index) },
  ] as [Uint8Array, { fingerprint: number; path: number[] }]);
}

function assertDerivations(
  actual: ReturnType<Transaction['getInput']>['bip32Derivation'],
  expected: VaultDerivedOutputV1,
  label: string,
): void {
  if (!actual || actual.length !== 3) throw new Error(`${label} requires all three BIP32 derivations`);
  const expectedEntries = expectedDerivations(expected).sort((left, right) => compareBytes(left[0], right[0]));
  const actualEntries = [...actual].sort((left, right) => compareBytes(left[0], right[0]));
  for (let index = 0; index < 3; index += 1) {
    const [actualKey, actualOrigin] = actualEntries[index]!;
    const [expectedKey, expectedOrigin] = expectedEntries[index]!;
    if (!equalBytes(actualKey, expectedKey) || actualOrigin.fingerprint !== expectedOrigin.fingerprint ||
        actualOrigin.path.length !== expectedOrigin.path.length ||
        actualOrigin.path.some((value, pathIndex) => value !== expectedOrigin.path[pathIndex])) {
      throw new Error(`${label} BIP32 derivation/origin mismatch`);
    }
  }
}

function roleForPublicKey(ownership: VaultDerivedOutputV1, publicKey: Uint8Array): VaultSignerRole | undefined {
  return ownership.logicalKeys.find((key) => key.publicKeyHex === bytesToHex(publicKey))?.role;
}

function validatePartialSignatures(tx: Transaction, ownership: VaultDerivedOutputV1[], plan: VaultUnsignedPlanV1): VaultSignerRole[] {
  let commonRoles: VaultSignerRole[] | undefined;
  for (let index = 0; index < plan.inputs.length; index += 1) {
    const input = tx.getInput(index);
    const entries = input.partialSig ?? [];
    const publicKeys = new Set<string>();
    const roles: VaultSignerRole[] = [];
    const message = tx.preimageWitnessV0(index, hexToBytes(plan.inputs[index]!.witnessScriptHex), SigHash.ALL,
      BigInt(plan.inputs[index]!.valueSats));
    for (const [publicKey, signatureWithType] of entries) {
      const publicKeyHex = bytesToHex(publicKey);
      if (publicKeys.has(publicKeyHex)) throw new Error(`duplicate partial signature on input ${index}`);
      publicKeys.add(publicKeyHex);
      const role = roleForPublicKey(ownership[index]!, publicKey);
      if (!role) throw new Error(`foreign partial-signature key on input ${index}`);
      if (signatureWithType.length < 2 || signatureWithType.at(-1) !== SigHash.ALL ||
          !secp256k1.verify(signatureWithType.slice(0, -1), message, publicKey, {
            format: 'der', prehash: false, lowS: true,
          })) throw new Error(`invalid SIGHASH_ALL partial signature on input ${index}`);
      roles.push(role);
    }
    roles.sort(roleOrder);
    if (new Set(roles).size !== roles.length) throw new Error(`duplicate logical role on input ${index}`);
    if (commonRoles === undefined) commonRoles = roles;
    else if (commonRoles.length !== roles.length || commonRoles.some((role, roleIndex) => role !== roles[roleIndex])) {
      throw new Error('logical roles did not sign every Vault input');
    }
  }
  return commonRoles ?? [];
}

function canonicalValue(value: unknown): unknown {
  if (typeof value === 'bigint') return value.toString();
  if (value instanceof Uint8Array) return bytesToHex(value);
  if (Array.isArray(value)) return value.map(canonicalValue);
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value as Record<string, unknown>)
      .filter(([key]) => key !== 'partialSig')
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, child]) => [key, canonicalValue(child)]));
  }
  return value;
}

function psbtMeaningSnapshot(tx: Transaction): string {
  return JSON.stringify({
    unsigned: bytesToHex(tx.unsignedTx),
    inputs: Array.from({ length: tx.inputsLength }, (_, index) => canonicalValue(tx.getInput(index))),
    outputs: Array.from({ length: tx.outputsLength }, (_, index) => canonicalValue(tx.getOutput(index))),
  });
}

function assertExpectedPartialSignatureMutation(
  before: Transaction,
  after: Transaction,
  ownership: VaultDerivedOutputV1[],
  role: VaultSignerRole,
): void {
  for (let index = 0; index < before.inputsLength; index += 1) {
    const prior = new Map((before.getInput(index).partialSig ?? []).map(([publicKey, signature]) =>
      [bytesToHex(publicKey), bytesToHex(signature)]));
    const signed = new Map((after.getInput(index).partialSig ?? []).map(([publicKey, signature]) =>
      [bytesToHex(publicKey), bytesToHex(signature)]));
    const expectedKey = ownership[index]!.logicalKeys[VAULT_ROLES.indexOf(role)]!.publicKeyHex;
    if (prior.has(expectedKey) || !signed.has(expectedKey) || signed.size !== prior.size + 1) {
      throw new Error(`input ${index} did not add exactly the expected role signature`);
    }
    for (const [publicKey, signature] of prior) {
      if (signed.get(publicKey) !== signature) {
        throw new Error(`input ${index} changed an existing partial signature`);
      }
    }
  }
}

function assertFresh(plan: VaultUnsignedPlanV1, nowMs: string): void {
  if (!/^(?:0|[1-9][0-9]*)$/u.test(nowMs)) throw new Error('canonical signing time required');
  const now = BigInt(nowMs);
  if (now < BigInt(plan.createdAtMs) || now > BigInt(plan.expiresAtMs) ||
      now < BigInt(plan.source.observedAtMs) || now > BigInt(plan.source.validUntilMs)) {
    throw new Error('Vault plan freshness window is not valid for signing');
  }
}

/** Construct the one deterministic PSBTv0 profile accepted by policy v1. */
export function constructVaultPsbt(policy: VaultPolicyIdentityV1, plan: VaultUnsignedPlanV1): string {
  const ownership = assertPlanPolicyAndTransaction(policy, plan);
  const tx = new Transaction({ PSBTVersion: 0, lowR: true });
  for (let index = 0; index < plan.inputs.length; index += 1) {
    const input = plan.inputs[index]!;
    const owned = ownership[index]!;
    tx.addInput({
      txid: input.txid,
      index: input.vout,
      sequence: input.sequence,
      witnessUtxo: { script: hexToBytes(input.scriptPubKeyHex), amount: BigInt(input.valueSats) },
      witnessScript: hexToBytes(input.witnessScriptHex),
      bip32Derivation: expectedDerivations(owned),
      sighashType: SigHash.ALL,
    });
  }
  for (let index = 0; index < plan.outputs.length; index += 1) {
    const output = plan.outputs[index]!;
    tx.addOutput({ script: hexToBytes(output.scriptPubKeyHex), amount: BigInt(output.valueSats) });
    if (output.purpose === 'vault-change') {
      const owned = deriveVaultOutput(policy, 'change', output.derivationIndex!);
      tx.updateOutput(index, {
        witnessScript: hexToBytes(owned.witnessScriptHex),
        bip32Derivation: expectedDerivations(owned),
      });
    }
  }
  if (bytesToHex(tx.unsignedTx) !== plan.unsignedTransactionHex) {
    throw new Error('constructed PSBT unsigned transaction differs from plan');
  }
  const psbtHex = bytesToHex(tx.toPSBT(0));
  validateVaultPsbt(policy, plan, psbtHex);
  return psbtHex;
}

/** Reparse and validate the complete closed PSBT profile against B0 and B1. */
export function validateVaultPsbt(
  policy: VaultPolicyIdentityV1,
  plan: VaultUnsignedPlanV1,
  psbtHex: string,
): VaultPsbtValidation {
  const ownership = assertPlanPolicyAndTransaction(policy, plan);
  const tx = Transaction.fromPSBT(hexToBytes(psbtHex), { PSBTVersion: 0, lowR: true });
  if (tx.opts.PSBTVersion !== 0 || tx.inputsLength !== plan.inputs.length || tx.outputsLength !== plan.outputs.length ||
      bytesToHex(tx.unsignedTx) !== plan.unsignedTransactionHex) {
    throw new Error('PSBT unsigned transaction differs from approved plan');
  }
  const maps = scanPsbtMaps(psbtHex, tx.inputsLength, tx.outputsLength);
  assertRawPsbtProfile(maps, plan);
  for (let index = 0; index < plan.inputs.length; index += 1) {
    const expected = plan.inputs[index]!;
    const actual = tx.getInput(index);
    if (!actual.txid || bytesToHex(actual.txid) !== expected.txid || actual.index !== expected.vout ||
        actual.sequence !== expected.sequence || actual.sighashType !== SigHash.ALL ||
        actual.witnessUtxo?.amount !== BigInt(expected.valueSats) || !actual.witnessUtxo.script ||
        bytesToHex(actual.witnessUtxo.script) !== expected.scriptPubKeyHex || !actual.witnessScript ||
        bytesToHex(actual.witnessScript) !== expected.witnessScriptHex) {
      throw new Error(`PSBT input ${index} prevout/script/sighash mismatch`);
    }
    assertDerivations(actual.bip32Derivation, ownership[index]!, `PSBT input ${index}`);
  }
  for (let index = 0; index < plan.outputs.length; index += 1) {
    const expected = plan.outputs[index]!;
    const actual = tx.getOutput(index);
    if (!actual.script || bytesToHex(actual.script) !== expected.scriptPubKeyHex || actual.amount !== BigInt(expected.valueSats)) {
      throw new Error(`PSBT output ${index} mismatch`);
    }
    if (expected.purpose === 'vault-change') {
      const owned = deriveVaultOutput(policy, 'change', expected.derivationIndex!);
      if (!actual.witnessScript || bytesToHex(actual.witnessScript) !== owned.witnessScriptHex) {
        throw new Error(`PSBT change output ${index} witness script mismatch`);
      }
      assertDerivations(actual.bip32Derivation, owned, `PSBT output ${index}`);
    } else if (actual.witnessScript || actual.bip32Derivation) {
      throw new Error(`PSBT output ${index} has unexpected derivation metadata`);
    }
  }
  const roles = validatePartialSignatures(tx, ownership, plan);
  return { version: 1, psbtHex, psbtHash: vaultPsbtHash(psbtHex), roles, inputOwnership: ownership };
}

export function createVaultPartialSignatureInput(input: {
  policy: VaultPolicyIdentityV1;
  plan: VaultUnsignedPlanV1;
  role: VaultSignerRole;
  psbtHex?: string;
}): VaultPartialSignatureInputV1 {
  const psbtHex = input.psbtHex ?? constructVaultPsbt(input.policy, input.plan);
  const validated = validateVaultPsbt(input.policy, input.plan, psbtHex);
  if (validated.roles.includes(input.role)) throw new Error('expected logical role already signed this PSBT');
  const value = vaultPartialSignatureInputSchema.parse({
    version: 1,
    network: input.plan.network,
    policyId: input.plan.policyId,
    planId: input.plan.planId,
    planDigest: input.plan.planDigest,
    role: input.role,
    canonicalPlanHex: bytesToHex(canonicalVaultPlanBytes(input.plan)),
    psbtHex,
    psbtHash: validated.psbtHash,
  });
  serializeVaultPartialSignatureInput(value);
  return value;
}

function assertSignerRoot(policy: VaultPolicyIdentityV1, role: VaultSignerRole, root: HDKey): HDKey {
  const origin = policy.signers[VAULT_ROLES.indexOf(role)];
  if (!origin || root.depth !== 0 || root.index !== 0 || !root.privateKey ||
      root.fingerprint !== fingerprintNumber(origin.masterFingerprintHex)) {
    throw new Error('signing root does not match the complete expected Vault origin');
  }
  const account = root.derive(origin.originPath);
  if (!account.privateKey || account.publicExtendedKey !== origin.accountXpub ||
      HDKey.fromExtendedKey(origin.accountXpub, bip32Versions(policy.network)).publicExtendedKey !== origin.accountXpub) {
    account.wipePrivateData();
    throw new Error('signing root does not match the expected account xpub and network');
  }
  return account;
}

/**
 * Add exactly one complete logical role and prove signature-only mutation.
 * Low-level B2 only: this function does not enforce B3 asset safety.
 */
export function signVaultPartialSignature(input: {
  policy: VaultPolicyIdentityV1;
  request: VaultPartialSignatureInputV1;
  signerRoot: HDKey;
  nowMs: string;
}): VaultPartialSignatureResultV1 {
  serializeVaultPartialSignatureInput(input.request);
  const plan = parseCanonicalVaultPlan(hexToBytes(input.request.canonicalPlanHex));
  assertCanonicalPlanBytes(plan, input.request.canonicalPlanHex);
  if (input.request.network !== input.policy.network || input.request.policyId !== input.policy.policyId ||
      input.request.planDigest !== plan.planDigest || input.request.planId !== plan.planId ||
      input.request.psbtHash !== vaultPsbtHash(input.request.psbtHex)) {
    throw new Error('partial-signature request policy/plan binding mismatch');
  }
  assertFresh(plan, input.nowMs);
  const before = validateVaultPsbt(input.policy, plan, input.request.psbtHex);
  if (before.roles.includes(input.request.role)) throw new Error('duplicate logical-role signature request');
  const beforeTx = Transaction.fromPSBT(hexToBytes(input.request.psbtHex), { PSBTVersion: 0, lowR: true });
  const priorTx = Transaction.fromPSBT(hexToBytes(input.request.psbtHex), { PSBTVersion: 0, lowR: true });
  const meaning = psbtMeaningSnapshot(beforeTx);
  const account = assertSignerRoot(input.policy, input.request.role, input.signerRoot);
  try {
    for (let index = 0; index < plan.inputs.length; index += 1) {
      const planned = plan.inputs[index]!;
      const branch = account.deriveChild(planned.branch === 'receive' ? 0 : 1);
      const child = branch.deriveChild(planned.derivationIndex);
      try {
        const expected = before.inputOwnership[index]!.logicalKeys[VAULT_ROLES.indexOf(input.request.role)]!;
        if (!child.privateKey || !child.publicKey || child.index !== planned.derivationIndex ||
            bytesToHex(child.publicKey) !== expected.publicKeyHex) {
          throw new Error(`signing key does not match complete input ${index} derivation`);
        }
        const privateKey = child.privateKey;
        try {
          beforeTx.signIdx(privateKey, index, [SigHash.ALL]);
        } finally {
          privateKey.fill(0);
        }
      } finally {
        child.wipePrivateData();
        branch.wipePrivateData();
      }
    }
  } finally {
    account.wipePrivateData();
  }
  const signedPsbtHex = bytesToHex(beforeTx.toPSBT(0));
  const reparsed = Transaction.fromPSBT(hexToBytes(signedPsbtHex), { PSBTVersion: 0, lowR: true });
  if (psbtMeaningSnapshot(reparsed) !== meaning) throw new Error('signing changed non-signature PSBT meaning');
  assertExpectedPartialSignatureMutation(priorTx, reparsed, before.inputOwnership, input.request.role);
  const after = validateVaultPsbt(input.policy, plan, signedPsbtHex);
  const expectedRoles = [...before.roles, input.request.role].sort(roleOrder);
  if (after.roles.length !== expectedRoles.length || after.roles.some((role, index) => role !== expectedRoles[index])) {
    throw new Error('signing added signatures for an unexpected logical role');
  }
  const result = vaultPartialSignatureResultSchema.parse({
    version: 1,
    network: plan.network,
    policyId: plan.policyId,
    planId: plan.planId,
    planDigest: plan.planDigest,
    roleAdded: input.request.role,
    priorPsbtHash: input.request.psbtHash,
    signedPsbtHex,
    signedPsbtHash: after.psbtHash,
  });
  serializeVaultPartialSignatureResult(result);
  return result;
}

/** Combine standards-compliant one-role partials after strict meaning equality. */
export function combineVaultPsbts(input: {
  policy: VaultPolicyIdentityV1;
  plan: VaultUnsignedPlanV1;
  psbtHexes: readonly string[];
}): CombinedVaultPsbt {
  if (input.psbtHexes.length < 2 || input.psbtHexes.length > 3) {
    throw new Error('Vault combination requires two or three one-role PSBTs');
  }
  const validated = input.psbtHexes.map((psbtHex) => validateVaultPsbt(input.policy, input.plan, psbtHex));
  if (validated.some((item) => item.roles.length !== 1)) throw new Error('each combined PSBT must contain exactly one logical role');
  const roles = validated.map((item) => item.roles[0]!).sort(roleOrder);
  if (new Set(roles).size !== roles.length) throw new Error('duplicate logical role cannot be combined');
  const meaning = psbtMeaningSnapshot(Transaction.fromPSBT(hexToBytes(input.psbtHexes[0]!), { PSBTVersion: 0, lowR: true }));
  for (const psbtHex of input.psbtHexes.slice(1)) {
    const candidate = Transaction.fromPSBT(hexToBytes(psbtHex), { PSBTVersion: 0, lowR: true });
    if (psbtMeaningSnapshot(candidate) !== meaning) throw new Error('combined PSBT signing meaning differs');
  }
  const combined = Transaction.fromPSBT(hexToBytes(constructVaultPsbt(input.policy, input.plan)), { PSBTVersion: 0, lowR: true });
  for (let index = 0; index < input.plan.inputs.length; index += 1) {
    const signatures = input.psbtHexes.flatMap((psbtHex) =>
      Transaction.fromPSBT(hexToBytes(psbtHex), { PSBTVersion: 0, lowR: true }).getInput(index).partialSig ?? []);
    combined.updateInput(index, { partialSig: signatures }, true);
  }
  const psbtHex = bytesToHex(combined.toPSBT(0));
  const result = validateVaultPsbt(input.policy, input.plan, psbtHex);
  if (result.roles.length !== roles.length || result.roles.some((role, index) => role !== roles[index])) {
    throw new Error('combined Vault PSBT role set mismatch');
  }
  return { ...result, roles: roles as CombinedVaultPsbt['roles'] };
}

export function combineVaultPartialSignatureResults(input: {
  policy: VaultPolicyIdentityV1;
  plan: VaultUnsignedPlanV1;
  results: readonly VaultPartialSignatureResultV1[];
}): CombinedVaultPsbt {
  const baseHash = vaultPsbtHash(constructVaultPsbt(input.policy, input.plan));
  for (const result of input.results) {
    serializeVaultPartialSignatureResult(result);
    if (result.network !== input.plan.network || result.policyId !== input.plan.policyId ||
        result.planId !== input.plan.planId || result.planDigest !== input.plan.planDigest ||
        result.priorPsbtHash !== baseHash || result.signedPsbtHash !== vaultPsbtHash(result.signedPsbtHex)) {
      throw new Error('partial-signature result binding differs from combination plan');
    }
    const parsed = validateVaultPsbt(input.policy, input.plan, result.signedPsbtHex);
    if (parsed.roles.length !== 1 || parsed.roles[0] !== result.roleAdded) {
      throw new Error('partial-signature result role does not match cryptographic signatures');
    }
  }
  return combineVaultPsbts({ policy: input.policy, plan: input.plan, psbtHexes: input.results.map((item) => item.signedPsbtHex) });
}

function signatureAssignments(
  signatures: Uint8Array[],
  publicKeys: Uint8Array[],
  message: Uint8Array,
): number[][] {
  const results: number[][] = [];
  const visit = (signatureIndex: number, nextKey: number, selected: number[]) => {
    if (signatureIndex === signatures.length) {
      results.push([...selected]);
      return;
    }
    for (let keyIndex = nextKey; keyIndex < publicKeys.length; keyIndex += 1) {
      if (secp256k1.verify(signatures[signatureIndex]!.slice(0, -1), message, publicKeys[keyIndex]!, {
        format: 'der', prehash: false, lowS: true,
      })) visit(signatureIndex + 1, keyIndex + 1, [...selected, keyIndex]);
    }
  };
  visit(0, 0, []);
  return results;
}

/** Independently verify finalized witness/signatures and immutable plan meaning. */
export function verifyFinalizedVaultTransaction(input: {
  policy: VaultPolicyIdentityV1;
  plan: VaultUnsignedPlanV1;
  transactionHex: string;
}): FinalizedVaultTransaction {
  const ownership = assertPlanPolicyAndTransaction(input.policy, input.plan);
  const tx = Transaction.fromRaw(hexToBytes(input.transactionHex));
  if (bytesToHex(tx.unsignedTx) !== input.plan.unsignedTransactionHex || tx.inputsLength !== input.plan.inputs.length ||
      tx.outputsLength !== input.plan.outputs.length) throw new Error('final transaction unsigned meaning differs from approved plan');
  let quorum: VaultSignerRole[] | undefined;
  for (let index = 0; index < input.plan.inputs.length; index += 1) {
    const actual = tx.getInput(index);
    const witness = actual.finalScriptWitness ?? [];
    const expected = ownership[index]!;
    if ((actual.finalScriptSig?.length ?? 0) !== 0 || witness.length !== 4 || witness[0]!.length !== 0 ||
        bytesToHex(witness[3]!) !== expected.witnessScriptHex) {
      throw new Error(`final input ${index} is not exact native P2WSH 2-of-3`);
    }
    const signatures = [witness[1]!, witness[2]!];
    if (signatures.some((signature) => signature.length < 2 || signature.at(-1) !== SigHash.ALL)) {
      throw new Error(`final input ${index} has unsupported sighash or malformed DER`);
    }
    const sortedPublicKeys = expected.bip67SortedPublicKeysHex.map(hexToBytes);
    const message = tx.preimageWitnessV0(index, witness[3]!, SigHash.ALL, BigInt(input.plan.inputs[index]!.valueSats));
    const assignments = signatureAssignments(signatures, sortedPublicKeys, message);
    if (assignments.length !== 1) throw new Error(`final input ${index} signature ordering or validity mismatch`);
    const roles = assignments[0]!.map((keyIndex) => roleForPublicKey(expected, sortedPublicKeys[keyIndex]!)!).sort(roleOrder);
    if (new Set(roles).size !== 2 || roles.some((role) => role === undefined)) {
      throw new Error(`final input ${index} does not contain two distinct logical roles`);
    }
    if (quorum === undefined) quorum = roles;
    else if (quorum.some((role, roleIndex) => role !== roles[roleIndex])) {
      throw new Error('final transaction inputs use inconsistent logical-role quorums');
    }
  }
  if (!quorum || quorum.length !== 2) throw new Error('final transaction does not contain an approved quorum');
  if (tx.vsize > input.plan.vsize) {
    throw new Error(`final transaction vsize exceeds approved upper bound (${tx.vsize}/${input.plan.vsize})`);
  }
  const raw = hexToBytes(input.transactionHex);
  const digest = getCryptoProvider().sha256(getCryptoProvider().sha256(raw));
  return {
    version: 1,
    transactionHex: input.transactionHex,
    txid: tx.id,
    wtxid: bytesToHex(Uint8Array.from(digest).reverse()),
    vsize: tx.vsize,
    roles: quorum as [VaultSignerRole, VaultSignerRole],
  };
}

/**
 * Finalize with a deterministic logical-role quorum, never device copies.
 * Low-level B2 only: this function does not enforce B3 asset safety.
 */
export function finalizeVaultPsbt(input: {
  policy: VaultPolicyIdentityV1;
  plan: VaultUnsignedPlanV1;
  psbtHex: string;
  nowMs: string;
}): FinalizedVaultTransaction {
  assertFresh(input.plan, input.nowMs);
  const validated = validateVaultPsbt(input.policy, input.plan, input.psbtHex);
  if (validated.roles.length < 2) throw new Error('Vault PSBT does not have a distinct-role quorum');
  const quorum = validated.roles.slice(0, 2).sort(roleOrder);
  const source = Transaction.fromPSBT(hexToBytes(input.psbtHex), { PSBTVersion: 0, lowR: true });
  const finalizer = Transaction.fromPSBT(hexToBytes(constructVaultPsbt(input.policy, input.plan)), { PSBTVersion: 0, lowR: true });
  for (let index = 0; index < input.plan.inputs.length; index += 1) {
    const owned = validated.inputOwnership[index]!;
    const sourceSignatures = source.getInput(index).partialSig ?? [];
    const selected = quorum.map((role) => {
      const publicKeyHex = owned.logicalKeys[VAULT_ROLES.indexOf(role)]!.publicKeyHex;
      const signature = sourceSignatures.find(([publicKey]) => bytesToHex(publicKey) === publicKeyHex);
      if (!signature) throw new Error(`quorum role ${role} did not sign every input`);
      return signature;
    });
    finalizer.updateInput(index, { partialSig: selected }, true);
  }
  finalizer.finalize();
  return verifyFinalizedVaultTransaction({
    policy: input.policy,
    plan: input.plan,
    transactionHex: bytesToHex(finalizer.extract()),
  });
}
