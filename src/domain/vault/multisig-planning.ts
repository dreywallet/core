/**
 * Coordinator-neutral Vault planning.
 *
 * Both extension and mobile call these functions. Platform layers supply only
 * verified gateway evidence, durable counters, user intent, and storage; input
 * selection, exact fee/vsize solving, canonical plan bytes, PSBT construction,
 * and B3 Full Sat Safety validation live here.
 */
import { Transaction } from '@scure/btc-signer';
import { BIP32_MAX_INDEX, bitcoinNetwork, type Network } from '../keys/derivation';
import { scriptDustSats } from '../transactions/fees';
import { createVaultAssetSafePartialSignatureInput, type VaultAssetPolicyEvidenceV1 } from './multisig-asset-policy';
import type {
  VaultPolicyIdentityV1,
  VaultUnsignedPlanV1,
} from './multisig-contracts';
import { assertVaultOwnership, deriveVaultOutput } from './multisig-descriptors';
import {
  canonicalVaultPlanBytes,
  finalizeVaultUnsignedPlan,
  parseCanonicalVaultPlan,
} from './multisig-encoding';
import { constructVaultPsbt } from './multisig-psbt';
import { bytesToHex, hexToBytes } from './encoding';
import { getCryptoProvider } from './crypto-provider';
import {
  buildVaultAssetPolicyEvidence,
  type VaultEvidenceSourceV1,
  type VaultUtxoV1,
} from './multisig-evidence';

const MAX_DER_SIGHASH_SIGNATURE_BYTES = 72;
const VAULT_INPUT_VBYTES = 105n;
export const VAULT_RBF_SEQUENCE = 0xffff_fffd;

export function vaultPlanTxid(plan: VaultUnsignedPlanV1): string {
  const first = getCryptoProvider().sha256(hexToBytes(plan.unsignedTransactionHex));
  return bytesToHex(Uint8Array.from(getCryptoProvider().sha256(first)).reverse());
}

/**
 * The two online coordinators share branch 1 without sharing mutable storage.
 * Desktop A owns even change indexes and Mobile B owns odd change indexes.
 * This compile-time partition makes simultaneous reservations disjoint while
 * preserving one ordinary BIP48 change branch and standards-compatible PSBTs.
 */
export type VaultOnlineCoordinator = 'extension' | 'mobile';

export function initialVaultCoordinatorChangeIndex(coordinator: VaultOnlineCoordinator): number {
  return coordinator === 'extension' ? 0 : 1;
}

export function isVaultCoordinatorChangeIndex(
  index: number,
  coordinator: VaultOnlineCoordinator,
): boolean {
  return Number.isSafeInteger(index) && index >= 0 && index <= BIP32_MAX_INDEX &&
    index % 2 === initialVaultCoordinatorChangeIndex(coordinator);
}

export function reserveVaultCoordinatorChangeIndex(
  nextIndex: number,
  coordinator: VaultOnlineCoordinator,
): { index: number; nextIndex: number } {
  if (!isVaultCoordinatorChangeIndex(nextIndex, coordinator)) {
    throw new Error(`invalid ${coordinator} Vault change index: ${nextIndex}`);
  }
  return { index: nextIndex, nextIndex: nextIndex + 2 };
}

export type VaultPlanBuildErrorCode =
  | 'no_spendable_inputs'
  | 'insufficient_funds'
  | 'unsupported_inscription'
  | 'not_vault_owned';

export class VaultPlanBuildError extends Error {
  override readonly name = 'VaultPlanBuildError';

  constructor(readonly code: VaultPlanBuildErrorCode, message: string) {
    super(message);
  }
}

function networkFor(network: Network) {
  return bitcoinNetwork(network);
}

function buildUnsignedTransaction(
  inputs: ReadonlyArray<{ txid: string; vout: number; sequence: number }>,
  outputs: ReadonlyArray<{ scriptPubKeyHex: string; valueSats: string }>,
  witnessScriptsHex: readonly string[],
): { unsignedTransactionHex: string; vsize: number } {
  const tx = new Transaction({ PSBTVersion: 0, lowR: true });
  for (const input of inputs) {
    tx.addInput({ txid: input.txid, index: input.vout, sequence: input.sequence });
  }
  for (const output of outputs) {
    tx.addOutput({ script: hexToBytes(output.scriptPubKeyHex), amount: BigInt(output.valueSats) });
  }
  const unsignedTransactionHex = bytesToHex(tx.unsignedTx);
  const sized = Transaction.fromRaw(hexToBytes(unsignedTransactionHex));
  for (let index = 0; index < inputs.length; index += 1) {
    sized.updateInput(index, {
      finalScriptWitness: [
        new Uint8Array(),
        new Uint8Array(MAX_DER_SIGHASH_SIGNATURE_BYTES),
        new Uint8Array(MAX_DER_SIGHASH_SIGNATURE_BYTES),
        hexToBytes(witnessScriptsHex[index]!),
      ],
    }, true);
  }
  return { unsignedTransactionHex, vsize: sized.vsize };
}

function effectiveFeeRate(feeSats: bigint, vsize: number): string {
  return ((feeSats * 1000n + BigInt(vsize) - 1n) / BigInt(vsize)).toString();
}

function feeForVsize(rateSatPerKvB: bigint, vsize: number): bigint {
  return (rateSatPerKvB * BigInt(vsize) + 999n) / 1000n;
}

function vaultChangeThreshold(scriptPubKeyHex: string, feeRate: bigint): bigint {
  const futureSpend = (feeRate * VAULT_INPUT_VBYTES + 999n) / 1000n;
  const dust = scriptDustSats(scriptPubKeyHex);
  return futureSpend > dust ? futureSpend : dust;
}

function addressScriptHex(address: string, network: Network): string {
  const tx = new Transaction({ PSBTVersion: 0 });
  try {
    tx.addOutputAddress(address, 1n, networkFor(network));
  } catch {
    throw new VaultPlanBuildError('not_vault_owned', 'destination address is invalid for the Vault network');
  }
  const script = tx.getOutput(0).script;
  if (!script) throw new VaultPlanBuildError('not_vault_owned', 'destination address has no script');
  return bytesToHex(script);
}

export function selectVaultCardinalInputs(
  utxos: readonly VaultUtxoV1[],
  targetSats: bigint,
  excludedOutpoints: ReadonlySet<string> = new Set(),
): VaultUtxoV1[] {
  const eligible = utxos
    .filter((utxo) =>
      !excludedOutpoints.has(`${utxo.txid}:${utxo.vout}`) &&
      utxo.refusal === null &&
      utxo.primaryClass === 'cardinal_clean' &&
      utxo.inscriptions.length === 0)
    .sort((left, right) => BigInt(right.valueSats) > BigInt(left.valueSats) ? 1 : -1);
  if (eligible.length === 0 && targetSats > 0n) {
    throw new VaultPlanBuildError('no_spendable_inputs', 'no proven-clean cardinal Vault inputs');
  }
  const selected: VaultUtxoV1[] = [];
  let total = 0n;
  for (const utxo of eligible) {
    selected.push(utxo);
    total += BigInt(utxo.valueSats);
    if (total >= targetSats) return selected;
  }
  if (targetSats === 0n) return [];
  throw new VaultPlanBuildError('insufficient_funds', 'Vault cardinal balance cannot fund this plan');
}

export interface VaultPlanRequestBase {
  policy: VaultPolicyIdentityV1;
  source: VaultEvidenceSourceV1;
  utxos: readonly VaultUtxoV1[];
  destinationAddress: string;
  pairedSpendingWalletIdHash: string;
  feeRateSatPerKvB: string;
  changeDerivationIndex: number;
  planId: string;
  requestId: string;
  createdAtMs: string;
  expiresAtMs: string;
  broadcastIntent: 'broadcast' | 'return-psbt';
}

export interface VaultPlanBuildResult {
  plan: VaultUnsignedPlanV1;
  evidence: VaultAssetPolicyEvidenceV1;
  psbtHex: string;
  selected: readonly VaultUtxoV1[];
}

function assertBase(request: VaultPlanRequestBase): {
  destinationScript: string;
  change: ReturnType<typeof deriveVaultOutput>;
  feeRate: bigint;
} {
  if (request.policy.network !== request.source.network) {
    throw new VaultPlanBuildError('not_vault_owned', 'policy and evidence networks differ');
  }
  const destinationScript = addressScriptHex(request.destinationAddress, request.policy.network);
  const change = deriveVaultOutput(request.policy, 'change', request.changeDerivationIndex);
  assertVaultOwnership(request.policy, change);
  const feeRate = BigInt(request.feeRateSatPerKvB);
  if (feeRate <= 0n) throw new VaultPlanBuildError('insufficient_funds', 'fee rate must be positive');
  return { destinationScript, change, feeRate };
}

function finishPlan(
  request: VaultPlanRequestBase,
  input: {
    selected: readonly VaultUtxoV1[];
    outputs: VaultUnsignedPlanV1['outputs'];
    amountSats: string;
    changeSats: string;
    feeSats: string;
    assetEffects: VaultUnsignedPlanV1['assetEffects'];
    unsignedTransactionHex: string;
    vsize: number;
    replacement?: VaultUnsignedPlanV1['replacement'];
    previousPlan?: VaultUnsignedPlanV1;
  },
): VaultPlanBuildResult {
  const evidence = buildVaultAssetPolicyEvidence({
    source: request.source,
    policyId: request.policy.policyId,
    planId: request.planId,
    planDigest: '00'.repeat(32),
    utxos: input.selected,
  });
  const witnessScripts = input.selected.map((utxo) =>
    deriveVaultOutput(request.policy, utxo.branch, utxo.derivationIndex).witnessScriptHex);
  const plan = finalizeVaultUnsignedPlan({
    version: 1,
    policyVersion: 1,
    network: request.policy.network,
    policyId: request.policy.policyId,
    planId: request.planId,
    requestId: request.requestId,
    createdAtMs: request.createdAtMs,
    expiresAtMs: request.expiresAtMs,
    kind: 'withdrawal',
    unsignedTransactionHex: input.unsignedTransactionHex,
    inputs: input.selected.map((utxo, index) => ({
      txid: utxo.txid,
      vout: utxo.vout,
      valueSats: utxo.valueSats,
      scriptPubKeyHex: utxo.scriptPubKeyHex,
      witnessScriptHex: witnessScripts[index]!,
      branch: utxo.branch,
      derivationIndex: utxo.derivationIndex,
      sequence: VAULT_RBF_SEQUENCE,
      sighash: 'all',
      classification: utxo.primaryClass,
      classificationEvidenceHash: evidence.inputs[index]!.evidenceHash,
    })),
    outputs: input.outputs,
    destination: {
      kind: 'paired-spending',
      pairedSpendingWalletIdHash: request.pairedSpendingWalletIdHash,
      targetPolicyId: null,
      address: request.destinationAddress,
      outputIndex: 0,
    },
    amountSats: input.amountSats,
    changeSats: input.changeSats,
    feeSats: input.feeSats,
    vsize: input.vsize,
    feeRateSatPerKvB: effectiveFeeRate(BigInt(input.feeSats), input.vsize),
    sighash: 'all',
    assetEffects: input.assetEffects,
    source: {
      backendInstanceIdHash: request.source.backendInstanceIdHash,
      classificationRevisionHash: request.source.classificationRevisionHash,
      coreTip: request.source.coreTip,
      indexTip: request.source.indexTip,
      observedAtMs: request.source.observedAtMs,
      validUntilMs: request.source.validUntilMs,
    },
    replacement: input.replacement ?? { kind: 'none', replacesTxid: null, parentTxid: null },
    broadcastIntent: request.broadcastIntent,
  });
  const boundEvidence = { ...evidence, planDigest: plan.planDigest };
  const psbtHex = constructVaultPsbt(request.policy, plan);
  const safe = createVaultAssetSafePartialSignatureInput({
    policy: request.policy,
    plan,
    role: 'desktop-a',
    psbtHex,
    evidence: boundEvidence,
    nowMs: request.createdAtMs,
    ...(input.previousPlan === undefined ? {} : { previousPlan: input.previousPlan }),
  });
  return { plan, evidence: boundEvidence, psbtHex: safe.psbtHex, selected: input.selected };
}

export function buildVaultCardinalWithdrawal(
  request: VaultPlanRequestBase & { amountSats: string },
): VaultPlanBuildResult {
  const { destinationScript, change, feeRate } = assertBase(request);
  const amount = BigInt(request.amountSats);
  if (amount <= 0n) throw new VaultPlanBuildError('insufficient_funds', 'withdrawal amount must be positive');
  let selected = selectVaultCardinalInputs(request.utxos, amount);
  let withChange = true;

  for (let attempt = 0; attempt < 4; attempt += 1) {
    const witnessScripts = selected.map((utxo) =>
      deriveVaultOutput(request.policy, utxo.branch, utxo.derivationIndex).witnessScriptHex);
    const inputTotal = selected.reduce((sum, utxo) => sum + BigInt(utxo.valueSats), 0n);
    const provisional = [
      { scriptPubKeyHex: destinationScript, valueSats: amount.toString() },
      ...(withChange ? [{ scriptPubKeyHex: change.scriptPubKeyHex, valueSats: '0' }] : []),
    ];
    const sizing = buildUnsignedTransaction(
      selected.map((utxo) => ({ txid: utxo.txid, vout: utxo.vout, sequence: VAULT_RBF_SEQUENCE })),
      provisional,
      witnessScripts,
    );
    const fee = feeForVsize(feeRate, sizing.vsize);
    const changeSats = inputTotal - amount - fee;
    if (changeSats < 0n) {
      const wider = selectVaultCardinalInputs(request.utxos, amount + fee);
      if (wider.length === selected.length) {
        throw new VaultPlanBuildError('insufficient_funds', 'Vault balance cannot cover amount and fee');
      }
      selected = wider;
      withChange = true;
      continue;
    }
    if (withChange && changeSats < vaultChangeThreshold(change.scriptPubKeyHex, feeRate)) {
      withChange = false;
      continue;
    }
    const outputs: VaultUnsignedPlanV1['outputs'] = [
      {
        outputIndex: 0,
        valueSats: amount.toString(),
        scriptPubKeyHex: destinationScript,
        address: request.destinationAddress,
        purpose: 'paired-spending',
        branch: null,
        derivationIndex: null,
      },
      ...(withChange ? [{
        outputIndex: 1,
        valueSats: changeSats.toString(),
        scriptPubKeyHex: change.scriptPubKeyHex,
        address: change.address,
        purpose: 'vault-change' as const,
        branch: 'change' as const,
        derivationIndex: request.changeDerivationIndex,
      }] : []),
    ];
    const built = buildUnsignedTransaction(
      selected.map((utxo) => ({ txid: utxo.txid, vout: utxo.vout, sequence: VAULT_RBF_SEQUENCE })),
      outputs,
      witnessScripts,
    );
    const actualFee = inputTotal - amount - (withChange ? changeSats : 0n);
    return finishPlan(request, {
      selected,
      outputs,
      amountSats: amount.toString(),
      changeSats: (withChange ? changeSats : 0n).toString(),
      feeSats: actualFee.toString(),
      vsize: built.vsize,
      unsignedTransactionHex: built.unsignedTransactionHex,
      assetEffects: selected.map((_utxo, index) => ({
        kind: 'cardinal', assetId: '', inputIndex: index, inputOffsetSats: '0',
        outputIndex: 0, outputOffsetSats: '0', postageSats: '0', protected: false,
      })),
    });
  }
  throw new VaultPlanBuildError('insufficient_funds', 'Vault fee solving did not converge');
}

export function buildVaultInscriptionWithdrawal(
  request: VaultPlanRequestBase & { inscriptionId: string },
): VaultPlanBuildResult {
  const { destinationScript, change, feeRate } = assertBase(request);
  const protectedUtxo = request.utxos.find((utxo) =>
    utxo.refusal === null && utxo.primaryClass === 'inscribed' &&
    utxo.inscriptions.some((item) => item.inscriptionId === request.inscriptionId));
  if (!protectedUtxo || protectedUtxo.inscriptions.length !== 1 || protectedUtxo.confirmations === 0) {
    throw new VaultPlanBuildError(
      'unsupported_inscription',
      'Vault v1 moves exactly one confirmed, fully classified inscription UTXO',
    );
  }
  const excluded = new Set([`${protectedUtxo.txid}:${protectedUtxo.vout}`]);
  let feeInputs = selectVaultCardinalInputs(request.utxos, 1n, excluded);
  let withChange = true;

  for (let attempt = 0; attempt < 4; attempt += 1) {
    const selected = [protectedUtxo, ...feeInputs];
    const witnessScripts = selected.map((utxo) =>
      deriveVaultOutput(request.policy, utxo.branch, utxo.derivationIndex).witnessScriptHex);
    const feeInputTotal = feeInputs.reduce((sum, utxo) => sum + BigInt(utxo.valueSats), 0n);
    const provisional = [
      { scriptPubKeyHex: destinationScript, valueSats: protectedUtxo.valueSats },
      ...(withChange ? [{ scriptPubKeyHex: change.scriptPubKeyHex, valueSats: '0' }] : []),
    ];
    const sizing = buildUnsignedTransaction(
      selected.map((utxo) => ({ txid: utxo.txid, vout: utxo.vout, sequence: VAULT_RBF_SEQUENCE })),
      provisional,
      witnessScripts,
    );
    const fee = feeForVsize(feeRate, sizing.vsize);
    const changeSats = feeInputTotal - fee;
    if (changeSats < 0n) {
      const wider = selectVaultCardinalInputs(request.utxos, fee, excluded);
      if (wider.length === feeInputs.length) {
        throw new VaultPlanBuildError('insufficient_funds', 'clean Vault fee reserve cannot fund inscription movement');
      }
      feeInputs = wider;
      withChange = true;
      continue;
    }
    if (withChange && changeSats < vaultChangeThreshold(change.scriptPubKeyHex, feeRate)) {
      withChange = false;
      continue;
    }
    const outputs: VaultUnsignedPlanV1['outputs'] = [
      {
        outputIndex: 0,
        valueSats: protectedUtxo.valueSats,
        scriptPubKeyHex: destinationScript,
        address: request.destinationAddress,
        purpose: 'paired-spending',
        branch: null,
        derivationIndex: null,
      },
      ...(withChange ? [{
        outputIndex: 1,
        valueSats: changeSats.toString(),
        scriptPubKeyHex: change.scriptPubKeyHex,
        address: change.address,
        purpose: 'vault-change' as const,
        branch: 'change' as const,
        derivationIndex: request.changeDerivationIndex,
      }] : []),
    ];
    const built = buildUnsignedTransaction(
      selected.map((utxo) => ({ txid: utxo.txid, vout: utxo.vout, sequence: VAULT_RBF_SEQUENCE })),
      outputs,
      witnessScripts,
    );
    const actualFee = feeInputTotal - (withChange ? changeSats : 0n);
    const inscription = protectedUtxo.inscriptions[0]!;
    return finishPlan(request, {
      selected,
      outputs,
      amountSats: protectedUtxo.valueSats,
      changeSats: (withChange ? changeSats : 0n).toString(),
      feeSats: actualFee.toString(),
      vsize: built.vsize,
      unsignedTransactionHex: built.unsignedTransactionHex,
      assetEffects: [
        {
          kind: 'inscription',
          assetId: inscription.inscriptionId,
          inputIndex: 0,
          inputOffsetSats: inscription.offsetSats,
          outputIndex: 0,
          outputOffsetSats: inscription.offsetSats,
          postageSats: protectedUtxo.valueSats,
          protected: true,
        },
        ...feeInputs.map((_utxo, index) => ({
          kind: 'cardinal' as const,
          assetId: '',
          inputIndex: index + 1,
          inputOffsetSats: '0',
          outputIndex: 0,
          outputOffsetSats: '0',
          postageSats: '0',
          protected: false,
        })),
      ],
    });
  }
  throw new VaultPlanBuildError('insufficient_funds', 'Vault inscription fee solving did not converge');
}

/**
 * Build a child-pays-for-parent acceleration from one freshly classified,
 * wallet-created Vault change output. The child returns the remaining value to
 * the paired Spending wallet; it never selects another input or touches a
 * protected output.
 */
export function buildVaultCpfp(
  request: VaultPlanRequestBase & { previousPlan: VaultUnsignedPlanV1 },
): VaultPlanBuildResult {
  const previousPlan = parseCanonicalVaultPlan(canonicalVaultPlanBytes(request.previousPlan));
  if (previousPlan.network !== request.policy.network ||
      previousPlan.policyId !== request.policy.policyId ||
      previousPlan.destination.kind !== 'paired-spending' ||
      previousPlan.destination.address !== request.destinationAddress ||
      previousPlan.destination.pairedSpendingWalletIdHash !== request.pairedSpendingWalletIdHash) {
    throw new VaultPlanBuildError('not_vault_owned', 'CPFP parent and paired destination differ');
  }
  const parentTxid = vaultPlanTxid(previousPlan);
  const changeOutputs = previousPlan.outputs.filter((output) => output.purpose === 'vault-change');
  if (changeOutputs.length !== 1) {
    throw new VaultPlanBuildError('no_spendable_inputs', 'CPFP requires one parent Vault change output');
  }
  const parentOutput = changeOutputs[0]!;
  const selected = request.utxos.find((utxo) =>
    utxo.txid === parentTxid && utxo.vout === parentOutput.outputIndex);
  const derived = parentOutput.branch === null || parentOutput.derivationIndex === null
    ? null
    : deriveVaultOutput(request.policy, parentOutput.branch, parentOutput.derivationIndex);
  if (selected === undefined || selected.refusal !== null || selected.primaryClass !== 'cardinal_clean' ||
      selected.inscriptions.length !== 0 || selected.confirmations !== 0 ||
      !selected.walletCreatedUnconfirmedChange || selected.branch !== 'change' ||
      selected.valueSats !== parentOutput.valueSats ||
      selected.scriptPubKeyHex !== parentOutput.scriptPubKeyHex ||
      selected.derivationIndex !== parentOutput.derivationIndex || derived === null ||
      derived.scriptPubKeyHex !== selected.scriptPubKeyHex) {
    throw new VaultPlanBuildError(
      'no_spendable_inputs',
      'parent change is absent or lacks fresh clean wallet-created classification',
    );
  }
  const destinationScript = addressScriptHex(request.destinationAddress, request.policy.network);
  const witnessScript = derived.witnessScriptHex;
  const sizing = buildUnsignedTransaction(
    [{ txid: selected.txid, vout: selected.vout, sequence: VAULT_RBF_SEQUENCE }],
    [{ scriptPubKeyHex: destinationScript, valueSats: '1' }],
    [witnessScript],
  );
  const packageRate = BigInt(request.feeRateSatPerKvB);
  if (packageRate <= 0n) {
    throw new VaultPlanBuildError('insufficient_funds', 'CPFP package fee rate must be positive');
  }
  const targetPackageFee = feeForVsize(packageRate, previousPlan.vsize + sizing.vsize);
  const relayFloor = feeForVsize(1_000n, sizing.vsize);
  const packageDelta = targetPackageFee - BigInt(previousPlan.feeSats);
  const childFee = packageDelta > relayFloor ? packageDelta : relayFloor;
  const amount = BigInt(selected.valueSats) - childFee;
  if (amount <= scriptDustSats(destinationScript)) {
    throw new VaultPlanBuildError('insufficient_funds', 'parent change cannot fund an economic CPFP child');
  }
  const outputs: VaultUnsignedPlanV1['outputs'] = [{
    outputIndex: 0,
    valueSats: amount.toString(),
    scriptPubKeyHex: destinationScript,
    address: request.destinationAddress,
    purpose: 'paired-spending',
    branch: null,
    derivationIndex: null,
  }];
  const built = buildUnsignedTransaction(
    [{ txid: selected.txid, vout: selected.vout, sequence: VAULT_RBF_SEQUENCE }],
    outputs,
    [witnessScript],
  );
  return finishPlan(request, {
    selected: [selected],
    outputs,
    amountSats: amount.toString(),
    changeSats: '0',
    feeSats: childFee.toString(),
    vsize: built.vsize,
    unsignedTransactionHex: built.unsignedTransactionHex,
    assetEffects: [{
      kind: 'cardinal', assetId: '', inputIndex: 0, inputOffsetSats: '0',
      outputIndex: 0, outputOffsetSats: '0', postageSats: '0', protected: false,
    }],
    replacement: { kind: 'cpfp', replacesTxid: null, parentTxid },
    previousPlan,
  });
}

export function parseApprovedVaultPlan(record: {
  planDigest: string;
  canonicalPlanHex: string;
}): VaultUnsignedPlanV1 | null {
  try {
    const plan = parseCanonicalVaultPlan(hexToBytes(record.canonicalPlanHex));
    return plan.planDigest === record.planDigest ? plan : null;
  } catch {
    return null;
  }
}

export function canonicalApprovedVaultPlanHex(plan: VaultUnsignedPlanV1): string {
  return bytesToHex(canonicalVaultPlanBytes(plan));
}

export function assertVaultDepositAddress(
  policy: VaultPolicyIdentityV1,
  branch: 'receive' | 'change',
  index: number,
): { address: string; scriptPubKeyHex: string } {
  const derived = deriveVaultOutput(policy, branch, index);
  assertVaultOwnership(policy, derived);
  return { address: derived.address, scriptPubKeyHex: derived.scriptPubKeyHex };
}
