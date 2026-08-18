/** Community Vault v1 mainnet transaction plans and BIP371 PSBT handling. */
import { schnorr } from '@noble/curves/secp256k1';
import { HDKey } from '@scure/bip32';
import {
  OutScript,
  SigHash,
  TaprootControlBlock,
  Transaction,
} from '@scure/btc-signer';
import { bip32Versions } from '../keys/extended-key';
import { getCryptoProvider } from '../vault/crypto-provider';
import { bytesToHex, hexToBytes, utf8ToBytes } from '../vault/encoding';
import { zeroize } from '../vault/vault';
import {
  COMMUNITY_VAULT_NUMS_INTERNAL_KEY,
  COMMUNITY_VAULT_TAPLEAF_VERSION,
  COMMUNITY_VAULT_THRESHOLD,
  COMMUNITY_VAULT_UNIT_COUNT,
  communityVaultSpendPlanSchema,
  type CommunityVaultOwnerInputV1,
  type CommunityVaultPolicyV1,
  type CommunityVaultSpendInputV1,
  type CommunityVaultSpendOutputV1,
  type CommunityVaultSpendPlanV1,
} from './contracts';
import { assertCommunityVaultPolicy } from './policy';

const PLAN_DOMAIN = 'drey-community-vault-plan-v1';
const MAX_PSBT_BYTES = 2_000_000;
const MAX_STANDARD_TRANSACTION_WEIGHT = 400_000;
export const COMMUNITY_VAULT_MAX_TAPSCRIPT_BYTES = 3_500;
export const COMMUNITY_VAULT_MAX_FINAL_WITNESS_BYTES = 9_000;

type PsbtKeyValue = { key: Uint8Array; value: Uint8Array };

function readCompactSize(bytes: Uint8Array, cursor: { offset: number }): number {
  if (cursor.offset >= bytes.length) throw new Error('truncated Community Vault PSBT compact size');
  const prefix = bytes[cursor.offset++]!;
  if (prefix < 0xfd) return prefix;
  const width = prefix === 0xfd ? 2 : prefix === 0xfe ? 4 : 8;
  if (cursor.offset + width > bytes.length) throw new Error('truncated Community Vault PSBT compact size');
  const view = new DataView(bytes.buffer, bytes.byteOffset + cursor.offset, width);
  const value = width === 2 ? BigInt(view.getUint16(0, true))
    : width === 4 ? BigInt(view.getUint32(0, true)) : view.getBigUint64(0, true);
  cursor.offset += width;
  if ((width === 2 && value < 0xfdn) || (width === 4 && value <= 0xffffn) ||
      (width === 8 && value <= 0xffff_ffffn) || value > BigInt(MAX_PSBT_BYTES)) {
    throw new Error('non-canonical or excessive Community Vault PSBT compact size');
  }
  return Number(value);
}

function take(bytes: Uint8Array, cursor: { offset: number }, length: number): Uint8Array {
  if (length < 0 || cursor.offset + length > bytes.length) throw new Error('truncated Community Vault PSBT field');
  const value = bytes.slice(cursor.offset, cursor.offset + length);
  cursor.offset += length;
  return value;
}

function readPsbtMap(bytes: Uint8Array, cursor: { offset: number }): PsbtKeyValue[] {
  const values: PsbtKeyValue[] = [];
  const keys = new Set<string>();
  while (true) {
    const keyLength = readCompactSize(bytes, cursor);
    if (keyLength === 0) return values;
    const key = take(bytes, cursor, keyLength);
    const keyHex = bytesToHex(key);
    if (keys.has(keyHex)) throw new Error('duplicate Community Vault PSBT map key');
    keys.add(keyHex);
    values.push({ key, value: take(bytes, cursor, readCompactSize(bytes, cursor)) });
  }
}

function scanPsbtMaps(psbt: Uint8Array, inputCount: number, outputCount: number): PsbtKeyValue[][] {
  if (psbt.length < 5 || bytesToHex(psbt.slice(0, 5)) !== '70736274ff') throw new Error('invalid Community Vault PSBT framing');
  const cursor = { offset: 5 };
  const maps = Array.from({ length: 1 + inputCount + outputCount }, () => readPsbtMap(psbt, cursor));
  if (cursor.offset !== psbt.length) throw new Error('trailing Community Vault PSBT maps');
  return maps;
}

function assertRawPsbtProfile(bytes: Uint8Array, tx: Transaction, plan: CommunityVaultSpendPlanV1): void {
  const maps = scanPsbtMaps(bytes, tx.inputsLength, tx.outputsLength);
  const global = maps[0]!;
  if (global.length !== 1 || bytesToHex(global[0]!.key) !== '00' ||
      bytesToHex(global[0]!.value) !== plan.unsignedTransactionHex) {
    throw new Error('Community Vault PSBT global map differs from exact PSBTv0 transaction');
  }
  for (let index = 0; index < plan.inputs.length; index += 1) {
    const map = maps[index + 1]!;
    const allowed = index === plan.vaultInputIndex
      ? new Set([0x01, 0x03, 0x14, 0x15, 0x16, 0x17, 0x18])
      : new Set([0x00, 0x01, 0x02, 0x03, 0x06, 0x07, 0x08, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18]);
    if (map.some(({ key }) => key.length < 1 || !allowed.has(key[0]!))) {
      throw new Error(`Community Vault input ${index} contains an unapproved PSBT field`);
    }
    if (index === plan.vaultInputIndex) {
      const count = (type: number) => map.filter(({ key }) => key[0] === type).length;
      if (count(0x01) !== 1 || count(0x03) > 1 || count(0x14) > 100 || count(0x15) !== 1 ||
          count(0x16) !== 100 || count(0x17) !== 1 || count(0x18) !== 1) {
        throw new Error('Community Vault input BIP371 field cardinality mismatch');
      }
    }
  }
  for (let index = 0; index < plan.outputs.length; index += 1) {
    if (maps[1 + plan.inputs.length + index]!.length !== 0) {
      throw new Error(`Community Vault spend output ${index} contains unexpected PSBT metadata`);
    }
  }
}

interface SpendPlanDraftV1 {
  version: 1;
  policyVersion: 1;
  network: 'mainnet';
  policyId: string;
  capTableHash: string;
  capTableVersion: number;
  planId: string;
  kind: 'rotation' | 'sale';
  createdAtMs: string;
  expiresAtMs: string;
  inputs: CommunityVaultSpendInputV1[];
  vaultInputIndex: number;
  outputs: CommunityVaultSpendOutputV1[];
  feeSats: string;
  ordinalRoute: CommunityVaultSpendPlanV1['ordinalRoute'];
  unsignedTransactionHex: string;
}

export interface CommunityVaultPsbtValidation {
  version: 1;
  psbtHex: string;
  psbtHash: string;
  signedUnits: number[];
  signedOwnerIds: string[];
}

export interface CommunityVaultOwnerApprovalResultV1 extends CommunityVaultPsbtValidation {
  approvedOwnerId: string;
  addedUnits: number[];
}

export interface FinalizedCommunityVaultTransactionV1 {
  version: 1;
  transactionHex: string;
  txid: string;
  wtxid: string;
  weight: number;
  vsize: number;
  witnessBytes: number;
  signedUnits: number[];
}

class Writer {
  private readonly parts: Uint8Array[] = [];
  u8(value: number): void { this.parts.push(Uint8Array.of(value)); }
  u32(value: number): void {
    const out = new Uint8Array(4);
    new DataView(out.buffer).setUint32(0, value, false);
    this.parts.push(out);
  }
  u64(value: string): void {
    const out = new Uint8Array(8);
    new DataView(out.buffer).setBigUint64(0, BigInt(value), false);
    this.parts.push(out);
  }
  bytes(value: Uint8Array): void { this.u32(value.length); this.parts.push(value); }
  fixed(value: Uint8Array): void { this.parts.push(value); }
  text(value: string): void { this.bytes(utf8ToBytes(value)); }
  hex(value: string): void { this.bytes(hexToBytes(value)); }
  finish(): Uint8Array {
    const length = this.parts.reduce((sum, part) => sum + part.length, 0);
    const out = new Uint8Array(length);
    let offset = 0;
    for (const part of this.parts) { out.set(part, offset); offset += part.length; }
    return out;
  }
}

function domainHash(domain: string, value: Uint8Array): string {
  const prefix = utf8ToBytes(domain);
  const input = new Uint8Array(prefix.length + 1 + value.length);
  input.set(prefix);
  input[prefix.length] = 0;
  input.set(value, prefix.length + 1);
  return bytesToHex(getCryptoProvider().sha256(input));
}

function canonicalPlanBytes(plan: SpendPlanDraftV1): Uint8Array {
  const writer = new Writer();
  writer.fixed(Uint8Array.of(0x44, 0x43, 0x56, 0x50)); // DCVP
  writer.u8(1); writer.u8(1); writer.u8(0);
  writer.fixed(hexToBytes(plan.policyId));
  writer.fixed(hexToBytes(plan.capTableHash));
  writer.u32(plan.capTableVersion);
  writer.text(plan.planId);
  writer.u8(plan.kind === 'rotation' ? 0 : 1);
  writer.u64(plan.createdAtMs); writer.u64(plan.expiresAtMs);
  writer.u32(plan.inputs.length);
  for (const input of plan.inputs) {
    writer.fixed(hexToBytes(input.txid)); writer.u32(input.vout); writer.u64(input.valueSats);
    writer.hex(input.scriptPubKeyHex); writer.u32(input.sequence);
  }
  writer.u32(plan.vaultInputIndex);
  writer.u32(plan.outputs.length);
  for (const output of plan.outputs) { writer.u64(output.valueSats); writer.hex(output.scriptPubKeyHex); }
  writer.u64(plan.feeSats);
  writer.text(plan.ordinalRoute.inscriptionId);
  writer.u32(plan.ordinalRoute.inputIndex); writer.u64(plan.ordinalRoute.inputOffsetSats);
  writer.u32(plan.ordinalRoute.outputIndex); writer.u64(plan.ordinalRoute.outputOffsetSats);
  writer.u64(plan.ordinalRoute.postageSats);
  writer.hex(plan.unsignedTransactionHex);
  return writer.finish();
}

function buildUnsignedTransaction(inputs: readonly CommunityVaultSpendInputV1[], outputs: readonly CommunityVaultSpendOutputV1[]): string {
  const tx = new Transaction({ PSBTVersion: 0 });
  for (const input of inputs) tx.addInput({ txid: input.txid, index: input.vout, sequence: input.sequence });
  for (const output of outputs) tx.addOutput({ script: hexToBytes(output.scriptPubKeyHex), amount: BigInt(output.valueSats) });
  return bytesToHex(tx.unsignedTx);
}

export function createCommunityVaultSpendPlan(input: Omit<SpendPlanDraftV1, 'unsignedTransactionHex'>): CommunityVaultSpendPlanV1 {
  const unsignedTransactionHex = buildUnsignedTransaction(input.inputs, input.outputs);
  const draft: SpendPlanDraftV1 = { ...input, unsignedTransactionHex };
  const plan = communityVaultSpendPlanSchema.parse({ ...draft, planDigest: domainHash(PLAN_DOMAIN, canonicalPlanBytes(draft)) });
  assertCommunityVaultSpendPlan(plan);
  return plan;
}

function assertOrdinalRoute(plan: CommunityVaultSpendPlanV1): void {
  const route = plan.ordinalRoute;
  const source = plan.inputs[route.inputIndex];
  const destination = plan.outputs[route.outputIndex];
  if (!source || !destination || route.inputIndex !== plan.vaultInputIndex ||
      BigInt(route.inputOffsetSats) >= BigInt(source.valueSats)) {
    throw new Error('Community Vault ordinal route source is invalid');
  }
  const inputPosition = plan.inputs.slice(0, route.inputIndex)
    .reduce((sum, item) => sum + BigInt(item.valueSats), 0n) + BigInt(route.inputOffsetSats);
  const outputStart = plan.outputs.slice(0, route.outputIndex)
    .reduce((sum, item) => sum + BigInt(item.valueSats), 0n);
  const expectedOffset = inputPosition - outputStart;
  if (expectedOffset < 0n || expectedOffset >= BigInt(destination.valueSats) ||
      expectedOffset.toString() !== route.outputOffsetSats ||
      BigInt(destination.valueSats) - expectedOffset < BigInt(route.postageSats)) {
    throw new Error('Community Vault ordinal route does not preserve the exact inscribed sat and postage');
  }
}

export function assertCommunityVaultSpendPlan(plan: CommunityVaultSpendPlanV1): void {
  const parsed = communityVaultSpendPlanSchema.parse(plan);
  if (BigInt(parsed.createdAtMs) >= BigInt(parsed.expiresAtMs)) throw new Error('Community Vault plan expiry must follow creation');
  if (parsed.vaultInputIndex >= parsed.inputs.length || parsed.ordinalRoute.outputIndex >= parsed.outputs.length) {
    throw new Error('Community Vault plan index is out of range');
  }
  const inputTotal = parsed.inputs.reduce((sum, item) => sum + BigInt(item.valueSats), 0n);
  const outputTotal = parsed.outputs.reduce((sum, item) => sum + BigInt(item.valueSats), 0n);
  if (inputTotal <= outputTotal || inputTotal - outputTotal !== BigInt(parsed.feeSats)) {
    throw new Error('Community Vault plan fee is inconsistent');
  }
  if (buildUnsignedTransaction(parsed.inputs, parsed.outputs) !== parsed.unsignedTransactionHex) {
    throw new Error('Community Vault unsigned transaction differs from plan');
  }
  const draft: Record<string, unknown> = { ...parsed };
  delete draft.planDigest;
  if (domainHash(PLAN_DOMAIN, canonicalPlanBytes(draft as unknown as SpendPlanDraftV1)) !== parsed.planDigest) {
    throw new Error('Community Vault plan digest mismatch');
  }
  assertOrdinalRoute(parsed);
}

function assertPlanPolicy(policy: CommunityVaultPolicyV1, plan: CommunityVaultSpendPlanV1): void {
  assertCommunityVaultPolicy(policy);
  assertCommunityVaultSpendPlan(plan);
  if (plan.policyId !== policy.policyId || plan.capTableHash !== policy.capTableHash ||
      plan.capTableVersion !== policy.capTableVersion || plan.network !== policy.network ||
      plan.ordinalRoute.inscriptionId !== policy.inscriptionId) {
    throw new Error('Community Vault plan policy binding mismatch');
  }
  const input = plan.inputs[plan.vaultInputIndex]!;
  if (input.txid !== policy.currentOutpoint.txid || input.vout !== policy.currentOutpoint.vout ||
      input.scriptPubKeyHex !== policy.scriptPubKeyHex) {
    throw new Error('Community Vault plan does not spend the frozen policy outpoint');
  }
}

function tapLeafScript(policy: CommunityVaultPolicyV1) {
  return [[
    TaprootControlBlock.decode(hexToBytes(policy.controlBlockHex)),
    Uint8Array.from([...hexToBytes(policy.tapscriptHex), COMMUNITY_VAULT_TAPLEAF_VERSION]),
  ]] as NonNullable<ReturnType<Transaction['getInput']>['tapLeafScript']>;
}

function tapDerivations(policy: CommunityVaultPolicyV1) {
  const leafHash = hexToBytes(policy.tapLeafHashHex);
  return policy.units.map((unit) => [
    hexToBytes(unit.publicKeyHex),
    {
      hashes: [leafHash],
      der: { fingerprint: Number.parseInt(unit.masterFingerprintHex, 16), path: [unit.unit] },
    },
  ] as [Uint8Array, { hashes: Uint8Array[]; der: { fingerprint: number; path: number[] } }]);
}

export function constructCommunityVaultPsbt(policy: CommunityVaultPolicyV1, plan: CommunityVaultSpendPlanV1): string {
  assertPlanPolicy(policy, plan);
  const tx = new Transaction({ PSBTVersion: 0 });
  for (const input of plan.inputs) {
    tx.addInput({
      txid: input.txid, index: input.vout, sequence: input.sequence,
      witnessUtxo: { script: hexToBytes(input.scriptPubKeyHex), amount: BigInt(input.valueSats) },
    });
  }
  for (const output of plan.outputs) tx.addOutput({ script: hexToBytes(output.scriptPubKeyHex), amount: BigInt(output.valueSats) });
  tx.updateInput(plan.vaultInputIndex, {
    sighashType: SigHash.DEFAULT,
    tapInternalKey: hexToBytes(COMMUNITY_VAULT_NUMS_INTERNAL_KEY),
    tapMerkleRoot: hexToBytes(policy.tapMerkleRootHex),
    tapLeafScript: tapLeafScript(policy),
    tapBip32Derivation: tapDerivations(policy),
  });
  const psbtHex = bytesToHex(tx.toPSBT(0));
  validateCommunityVaultPsbt(policy, plan, psbtHex);
  return psbtHex;
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((byte, index) => byte === right[index]);
}

function psbtHash(psbtHex: string): string { return bytesToHex(getCryptoProvider().sha256(hexToBytes(psbtHex))); }

function assertNoUnknownPsbtFields(tx: Transaction): void {
  for (let index = 0; index < tx.inputsLength; index += 1) {
    const input = tx.getInput(index);
    if ((input.unknown?.length ?? 0) > 0 || (input.proprietary?.length ?? 0) > 0) {
      throw new Error(`Community Vault input ${index} contains unknown PSBT fields`);
    }
  }
  for (let index = 0; index < tx.outputsLength; index += 1) {
    const output = tx.getOutput(index);
    if ((output.unknown?.length ?? 0) > 0 || (output.proprietary?.length ?? 0) > 0) {
      throw new Error(`Community Vault output ${index} contains unknown PSBT fields`);
    }
  }
}

function signatureMessage(tx: Transaction, plan: CommunityVaultSpendPlanV1, policy: CommunityVaultPolicyV1): Uint8Array {
  return tx.preimageWitnessV1(
    plan.vaultInputIndex,
    plan.inputs.map((input) => hexToBytes(input.scriptPubKeyHex)),
    SigHash.DEFAULT,
    plan.inputs.map((input) => BigInt(input.valueSats)),
    undefined,
    hexToBytes(policy.tapscriptHex),
    COMMUNITY_VAULT_TAPLEAF_VERSION,
  );
}

function validatePartialSignatures(tx: Transaction, policy: CommunityVaultPolicyV1, plan: CommunityVaultSpendPlanV1): number[] {
  const input = tx.getInput(plan.vaultInputIndex);
  const message = signatureMessage(tx, plan, policy);
  const expectedKeys = new Map(policy.units.map((unit) => [unit.publicKeyHex, unit.unit]));
  const signed = new Set<number>();
  for (const [key, signature] of input.tapScriptSig ?? []) {
    const publicKeyHex = bytesToHex(key.pubKey);
    const unit = expectedKeys.get(publicKeyHex);
    if (unit === undefined || !equalBytes(key.leafHash, hexToBytes(policy.tapLeafHashHex)) ||
        signature.length !== 64 || !schnorr.verify(signature, message, key.pubKey) || signed.has(unit)) {
      throw new Error('invalid, foreign, duplicate, or non-default Community Vault unit signature');
    }
    signed.add(unit);
  }
  return [...signed].sort((left, right) => left - right);
}

function assertTapDerivations(actual: ReturnType<Transaction['getInput']>['tapBip32Derivation'], policy: CommunityVaultPolicyV1): void {
  if (!actual || actual.length !== COMMUNITY_VAULT_UNIT_COUNT) {
    throw new Error('Community Vault PSBT requires all 100 BIP371 key origins');
  }
  const byKey = new Map(actual.map(([key, value]) => [bytesToHex(key), value]));
  for (const unit of policy.units) {
    const value = byKey.get(unit.publicKeyHex);
    if (!value || value.hashes.length !== 1 || bytesToHex(value.hashes[0]!) !== policy.tapLeafHashHex ||
        value.der.fingerprint !== Number.parseInt(unit.masterFingerprintHex, 16) ||
        value.der.path.length !== 1 || value.der.path[0] !== unit.unit) {
      throw new Error(`Community Vault unit ${unit.unit} BIP371 origin mismatch`);
    }
  }
}

export function validateCommunityVaultPsbt(
  policy: CommunityVaultPolicyV1,
  plan: CommunityVaultSpendPlanV1,
  psbtHex: string,
): CommunityVaultPsbtValidation {
  assertPlanPolicy(policy, plan);
  const bytes = hexToBytes(psbtHex);
  if (bytes.length > MAX_PSBT_BYTES) throw new Error('Community Vault PSBT exceeds size limit');
  const tx = Transaction.fromPSBT(bytes, { PSBTVersion: 0 });
  if (tx.inputsLength !== plan.inputs.length || tx.outputsLength !== plan.outputs.length ||
      bytesToHex(tx.unsignedTx) !== plan.unsignedTransactionHex) {
    throw new Error('Community Vault PSBT unsigned transaction differs from plan');
  }
  assertRawPsbtProfile(bytes, tx, plan);
  assertNoUnknownPsbtFields(tx);
  for (let index = 0; index < plan.inputs.length; index += 1) {
    const expected = plan.inputs[index]!;
    const actual = tx.getInput(index);
    if (!actual.txid || bytesToHex(actual.txid) !== expected.txid || actual.index !== expected.vout ||
        actual.sequence !== expected.sequence || actual.witnessUtxo?.amount !== BigInt(expected.valueSats) ||
        !actual.witnessUtxo.script || bytesToHex(actual.witnessUtxo.script) !== expected.scriptPubKeyHex) {
      throw new Error(`Community Vault PSBT input ${index} differs from plan`);
    }
  }
  for (let index = 0; index < plan.outputs.length; index += 1) {
    const expected = plan.outputs[index]!;
    const actual = tx.getOutput(index);
    if (!actual.script || bytesToHex(actual.script) !== expected.scriptPubKeyHex || actual.amount !== BigInt(expected.valueSats)) {
      throw new Error(`Community Vault PSBT output ${index} differs from plan`);
    }
  }
  const input = tx.getInput(plan.vaultInputIndex);
  const expectedLeaf = tapLeafScript(policy)[0]!;
  if ((input.sighashType !== undefined && input.sighashType !== SigHash.DEFAULT) || input.tapKeySig || !input.tapInternalKey ||
      bytesToHex(input.tapInternalKey) !== COMMUNITY_VAULT_NUMS_INTERNAL_KEY || !input.tapMerkleRoot ||
      bytesToHex(input.tapMerkleRoot) !== policy.tapMerkleRootHex || input.tapLeafScript?.length !== 1 ||
      bytesToHex(TaprootControlBlock.encode(input.tapLeafScript[0]![0])) !== bytesToHex(TaprootControlBlock.encode(expectedLeaf[0])) ||
      !equalBytes(input.tapLeafScript[0]![1], expectedLeaf[1]) || (input.finalScriptSig?.length ?? 0) !== 0 ||
      (input.finalScriptWitness?.length ?? 0) !== 0) {
    throw new Error('Community Vault PSBT contains a hidden, altered, key-path, or finalized spend path');
  }
  assertTapDerivations(input.tapBip32Derivation, policy);
  const signedUnits = validatePartialSignatures(tx, policy, plan);
  const signedOwnerIds = [...new Set(signedUnits.map((unit) => policy.units[unit]!.ownerId))];
  return { version: 1, psbtHex, psbtHash: psbtHash(psbtHex), signedUnits, signedOwnerIds };
}

function ownerRecord(policy: CommunityVaultPolicyV1, ownerId: string): CommunityVaultOwnerInputV1 {
  const owner = policy.owners.find((candidate) => candidate.ownerId === ownerId);
  if (!owner) throw new Error('Community Vault owner is not in frozen cap table');
  return owner;
}

function assertOwnerRoot(owner: CommunityVaultOwnerInputV1, root: HDKey): void {
  if (root.depth !== 0 || root.index !== 0 || !root.privateKey || !root.publicKey ||
      root.fingerprint.toString(16).padStart(8, '0') !== owner.campaignRoot.masterFingerprintHex ||
      root.publicExtendedKey !== owner.campaignRoot.campaignXpub ||
      HDKey.fromExtendedKey(owner.campaignRoot.campaignXpub, bip32Versions('mainnet')).publicExtendedKey !== owner.campaignRoot.campaignXpub) {
    throw new Error('Community Vault signing root differs from owner campaign root');
  }
}

/** One approval signs every numbered unit owned by the approving campaign root. */
export function approveCommunityVaultSpend(input: {
  policy: CommunityVaultPolicyV1;
  plan: CommunityVaultSpendPlanV1;
  psbtHex: string;
  ownerId: string;
  signerRoot: HDKey;
  nowMs: string;
  random: (length: number) => Uint8Array;
}): CommunityVaultOwnerApprovalResultV1 {
  const now = BigInt(input.nowMs);
  if (now < BigInt(input.plan.createdAtMs) || now > BigInt(input.plan.expiresAtMs)) {
    throw new Error('Community Vault approval is outside the plan freshness window');
  }
  const before = validateCommunityVaultPsbt(input.policy, input.plan, input.psbtHex);
  const owner = ownerRecord(input.policy, input.ownerId);
  if (owner.units.some((unit) => before.signedUnits.includes(unit))) {
    throw new Error('Community Vault owner already approved one or more owned units');
  }
  assertOwnerRoot(owner, input.signerRoot);
  const tx = Transaction.fromPSBT(hexToBytes(input.psbtHex), { PSBTVersion: 0 });
  for (const unitNumber of owner.units) {
    const child = input.signerRoot.deriveChild(unitNumber);
    try {
      const expected = input.policy.units[unitNumber]!;
      if (!child.privateKey || !child.publicKey || bytesToHex(child.publicKey.slice(1)) !== expected.publicKeyHex) {
        throw new Error(`Community Vault unit ${unitNumber} private derivation differs from cap table`);
      }
      const privateKey = child.privateKey;
      try {
        const aux = input.random(32);
        if (aux.length !== 32) throw new Error('Community Vault Schnorr auxiliary randomness must be 32 bytes');
        tx.signIdx(privateKey, input.plan.vaultInputIndex, [SigHash.DEFAULT], aux);
      } finally {
        zeroize(privateKey);
      }
    } finally {
      child.wipePrivateData();
    }
  }
  const psbtHex = bytesToHex(tx.toPSBT(0));
  const after = validateCommunityVaultPsbt(input.policy, input.plan, psbtHex);
  const addedUnits = after.signedUnits.filter((unit) => !before.signedUnits.includes(unit));
  if (addedUnits.length !== owner.units.length || addedUnits.some((unit, index) => unit !== owner.units[index])) {
    throw new Error('Community Vault approval did not add exactly every owned unit signature');
  }
  return { ...after, approvedOwnerId: owner.ownerId, addedUnits };
}

export function combineCommunityVaultPsbts(
  policy: CommunityVaultPolicyV1,
  plan: CommunityVaultSpendPlanV1,
  psbtHexes: readonly string[],
): CommunityVaultPsbtValidation {
  if (psbtHexes.length < 1 || psbtHexes.length > 100) throw new Error('invalid Community Vault PSBT combination count');
  for (const psbtHex of psbtHexes) validateCommunityVaultPsbt(policy, plan, psbtHex);
  const combined = Transaction.fromPSBT(hexToBytes(psbtHexes[0]!), { PSBTVersion: 0 });
  for (const psbtHex of psbtHexes.slice(1)) combined.combine(Transaction.fromPSBT(hexToBytes(psbtHex), { PSBTVersion: 0 }));
  return validateCommunityVaultPsbt(policy, plan, bytesToHex(combined.toPSBT(0)));
}

function compactSizeLength(value: number): number {
  if (value < 0xfd) return 1;
  if (value <= 0xffff) return 3;
  if (value <= 0xffff_ffff) return 5;
  return 9;
}

function serializedWitnessBytes(witness: readonly Uint8Array[]): number {
  return compactSizeLength(witness.length) + witness.reduce((sum, item) => sum + compactSizeLength(item.length) + item.length, 0);
}

export function verifyFinalizedCommunityVaultTransaction(input: {
  policy: CommunityVaultPolicyV1;
  plan: CommunityVaultSpendPlanV1;
  transactionHex: string;
}): FinalizedCommunityVaultTransactionV1 {
  assertPlanPolicy(input.policy, input.plan);
  const tx = Transaction.fromRaw(hexToBytes(input.transactionHex));
  if (bytesToHex(tx.unsignedTx) !== input.plan.unsignedTransactionHex || tx.inputsLength !== input.plan.inputs.length ||
      tx.outputsLength !== input.plan.outputs.length) {
    throw new Error('finalized Community Vault transaction differs from approved plan');
  }
  const vaultInput = tx.getInput(input.plan.vaultInputIndex);
  const witness = vaultInput.finalScriptWitness;
  if (!witness || witness.length !== COMMUNITY_VAULT_UNIT_COUNT + 2 ||
      !equalBytes(witness[COMMUNITY_VAULT_UNIT_COUNT]!, hexToBytes(input.policy.tapscriptHex)) ||
      !equalBytes(witness[COMMUNITY_VAULT_UNIT_COUNT + 1]!, hexToBytes(input.policy.controlBlockHex))) {
    throw new Error('finalized Community Vault witness is not the exact 69-of-100 script path');
  }
  const message = signatureMessage(tx, input.plan, input.policy);
  const signedUnits: number[] = [];
  for (let unit = 0; unit < COMMUNITY_VAULT_UNIT_COUNT; unit += 1) {
    const signature = witness[COMMUNITY_VAULT_UNIT_COUNT - 1 - unit]!;
    if (signature.length === 0) continue;
    if (signature.length !== 64 || !schnorr.verify(signature, message, hexToBytes(input.policy.units[unit]!.publicKeyHex))) {
      throw new Error(`invalid finalized Community Vault signature for unit ${unit}`);
    }
    signedUnits.push(unit);
  }
  if (signedUnits.length !== COMMUNITY_VAULT_THRESHOLD) {
    throw new Error('finalized Community Vault witness must contain exactly 69 valid unit signatures');
  }
  const witnessBytes = serializedWitnessBytes(witness);
  if (hexToBytes(input.policy.tapscriptHex).length > COMMUNITY_VAULT_MAX_TAPSCRIPT_BYTES ||
      witnessBytes > COMMUNITY_VAULT_MAX_FINAL_WITNESS_BYTES || tx.weight > MAX_STANDARD_TRANSACTION_WEIGHT ||
      COMMUNITY_VAULT_THRESHOLD * 50 > 50 + witnessBytes) {
    throw new Error('finalized Community Vault witness exceeds Tapscript or standard weight bounds');
  }
  const raw = hexToBytes(input.transactionHex);
  const digest = getCryptoProvider().sha256(getCryptoProvider().sha256(raw));
  return {
    version: 1,
    transactionHex: input.transactionHex,
    txid: tx.id,
    wtxid: bytesToHex(Uint8Array.from(digest).reverse()),
    weight: tx.weight,
    vsize: tx.vsize,
    witnessBytes,
    signedUnits,
  };
}

export function finalizeCommunityVaultPsbt(
  policy: CommunityVaultPolicyV1,
  plan: CommunityVaultSpendPlanV1,
  psbtHex: string,
): FinalizedCommunityVaultTransactionV1 {
  const validated = validateCommunityVaultPsbt(policy, plan, psbtHex);
  if (validated.signedUnits.length < COMMUNITY_VAULT_THRESHOLD) {
    throw new Error('Community Vault requires at least 69 valid unit signatures');
  }
  const tx = Transaction.fromPSBT(hexToBytes(psbtHex), { PSBTVersion: 0 });
  tx.finalizeIdx(plan.vaultInputIndex);
  if (!tx.isFinal) throw new Error('Community Vault cannot extract until every non-vault input is finalized');
  return verifyFinalizedCommunityVaultTransaction({ policy, plan, transactionHex: bytesToHex(tx.extract()) });
}

/** Independent decode-level policy check used by profile validators and fixtures. */
export function decodeCommunityVaultPolicyScript(policy: CommunityVaultPolicyV1): { threshold: number; publicKeysHex: string[] } {
  const decoded = OutScript.decode(hexToBytes(policy.tapscriptHex));
  if (decoded.type !== 'tr_ms' || decoded.m !== COMMUNITY_VAULT_THRESHOLD || decoded.pubkeys.length !== COMMUNITY_VAULT_UNIT_COUNT) {
    throw new Error('Community Vault tapscript is not one exact multi_a(69,100) policy');
  }
  const publicKeysHex = decoded.pubkeys.map(bytesToHex);
  if (publicKeysHex.some((key, index) => key !== policy.units[index]!.publicKeyHex)) {
    throw new Error('Community Vault tapscript key order differs from numbered units');
  }
  return { threshold: decoded.m, publicKeysHex };
}
