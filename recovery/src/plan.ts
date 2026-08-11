/**
 * ADR 0007 §6, capability 5: "create a standard SIGHASH_ALL recovery spend
 * without Drey's gateway, relay, production application, or company."
 *
 * The UTXO set arrives as a file the operator obtained from anywhere — a full
 * node, an Electrum server, a block explorer, a friend. That source is treated
 * as untrusted, and it is safe to do so for a specific reason worth stating
 * plainly, because it is what makes a source-agnostic tool defensible:
 *
 *   - The scriptPubKey is never believed. Every outpoint is located inside the
 *     policy's own derivation space, so a source cannot smuggle in an input the
 *     Vault does not own.
 *   - The amount is never believed either, but it does not have to be. BIP143
 *     commits each input's value to the signature hash, so a wrong amount
 *     yields a signature that no node will accept. A lying source can waste the
 *     operator's time; it cannot move a satoshi anywhere.
 *
 * What a source *can* do is withhold — show fewer UTXOs than exist. That is an
 * availability problem, not an integrity one, and the answer to it is to ask a
 * second source, which is exactly what a tool with no built-in source allows.
 */
import { Transaction } from '@scure/btc-signer';
import { randomBytes } from 'node:crypto';
import { finalizeVaultUnsignedPlan } from '../../src/domain/vault/multisig-encoding';
import { resolvePayableAddress } from '../../src/domain/transactions/native-send';
import { bytesToHex, hexToBytes } from '../../src/domain/vault/encoding';
import type {
  VaultPolicyIdentityV1,
  VaultUnsignedPlanV1,
} from '../../src/domain/vault/multisig-contracts';
import { derive, locateScript } from './kit';
import { sha256Hex } from './crypto-node';

/**
 * Where a gateway would have spoken, the standalone tool writes a published
 * sentinel rather than a zero or a plausible-looking hash. Two reasons: an
 * auditor can tell an offline plan from a gateway plan on sight, and the
 * sentinel is not the evidence hash of any real classification record, so a
 * standalone plan cannot be laundered back through core's B3 asset-safe path
 * without finding a SHA-256 preimage.
 */
export const STANDALONE_SOURCE_SENTINEL = {
  backend: sha256Hex('drey-vault-standalone-recovery-v1/no-backend'),
  revision: sha256Hex('drey-vault-standalone-recovery-v1/no-revision'),
  classification: sha256Hex('drey-vault-standalone-recovery-v1/no-classification'),
} as const;

/**
 * The fee rate above which the tool demands an explicit acknowledgement.
 *
 * This is a confirmation, not a refusal, and the distinction is the whole
 * point. ADR 0007 §8.1's 25 sat/vB ceiling is pilot economics: a bounded
 * experiment may sensibly decline to pay more than it is worth. A recovery tool
 * must not inherit that shape. An absolute cap that hard-refuses would stop a
 * user rescuing their own funds during a fee spike — precisely the moment
 * moving matters most. So: warn loudly, require the operator to say yes, and
 * then do as they ask.
 */
export const FEE_RATE_ACKNOWLEDGEMENT_THRESHOLD_SAT_PER_VB = 50n;

/**
 * A change output below this is refused rather than absorbed into the fee.
 * Silently donating change to miners is how tools lose money on their users'
 * behalf; being told to sweep instead costs nothing.
 */
export const MIN_CHANGE_SATS = 1_000n;

/** Default depth searched on each branch when locating a supplied outpoint. */
export const DEFAULT_SEARCH_DEPTH = 100;

/** 180 days. An offline signer may take a long time to reach the plan. */
export const DEFAULT_PLAN_WINDOW_MS = 180n * 24n * 60n * 60n * 1000n;

export interface SuppliedUtxo {
  txid: string;
  vout: number;
  /** Either form is accepted; both are independently re-derived before use. */
  valueSats?: string | number;
  value?: number;
  address?: string;
  scriptPubKeyHex?: string;
}

export interface ResolvedInput {
  txid: string;
  vout: number;
  valueSats: bigint;
  branch: 'receive' | 'change';
  index: number;
  scriptPubKeyHex: string;
  witnessScriptHex: string;
}

const SEQUENCE = 0xffff_fffd; // opt into RBF; a stuck recovery must be replaceable

function parseValue(utxo: SuppliedUtxo): bigint {
  const raw = utxo.valueSats ?? utxo.value;
  if (raw === undefined) throw new Error(`utxo ${utxo.txid}:${utxo.vout} has no value`);
  const value = typeof raw === 'number' ? BigInt(Math.trunc(raw)) : BigInt(String(raw).trim());
  if (value <= 0n) throw new Error(`utxo ${utxo.txid}:${utxo.vout} has a non-positive value`);
  return value;
}

/**
 * Turn a supplied UTXO list into inputs this policy provably owns.
 *
 * An outpoint whose script the policy cannot regenerate is refused outright
 * rather than skipped, because silently dropping an input the operator believes
 * they are spending is how a "sweep" quietly leaves money behind.
 */
export function resolveInputs(
  identity: VaultPolicyIdentityV1,
  utxos: readonly SuppliedUtxo[],
  searchDepth = DEFAULT_SEARCH_DEPTH,
): ResolvedInput[] {
  if (utxos.length === 0) throw new Error('the supplied UTXO set is empty');
  const seen = new Set<string>();
  return utxos.map((utxo) => {
    if (!/^[0-9a-f]{64}$/iu.test(utxo.txid)) throw new Error(`utxo txid is not 32-byte hex: ${utxo.txid}`);
    if (!Number.isInteger(utxo.vout) || utxo.vout < 0) throw new Error(`utxo ${utxo.txid} has an invalid vout`);
    const outpoint = `${utxo.txid.toLowerCase()}:${utxo.vout}`;
    if (seen.has(outpoint)) throw new Error(`duplicate outpoint in the supplied UTXO set: ${outpoint}`);
    seen.add(outpoint);

    let scriptPubKeyHex = utxo.scriptPubKeyHex?.toLowerCase();
    if (scriptPubKeyHex === undefined) {
      if (utxo.address === undefined) {
        throw new Error(`utxo ${outpoint} supplies neither an address nor a scriptPubKeyHex`);
      }
      const resolved = resolvePayableAddress(utxo.address, identity.network);
      if (!resolved.ok) throw new Error(`utxo ${outpoint} address is unusable: ${resolved.reason}`);
      scriptPubKeyHex = resolved.value.scriptPubKey;
    }

    const located = locateScript(identity, scriptPubKeyHex, searchDepth);
    if (!located) {
      throw new Error(
        `utxo ${outpoint} is not owned by this Vault policy: its script does not appear on the receive or ` +
        `change branch within ${searchDepth} indexes. Check the kit, or raise --search-depth.`,
      );
    }
    return {
      txid: utxo.txid.toLowerCase(), vout: utxo.vout, valueSats: parseValue(utxo),
      branch: located.branch, index: located.index,
      scriptPubKeyHex, witnessScriptHex: located.witnessScriptHex,
    };
  });
}

/** The conservative finalized native-P2WSH vsize, computed core's own way. */
function upperBoundVsize(unsignedTxHex: string, witnessScriptHexes: readonly string[]): number {
  const sized = Transaction.fromRaw(hexToBytes(unsignedTxHex));
  witnessScriptHexes.forEach((witnessScriptHex, index) => {
    sized.updateInput(index, { finalScriptWitness: [
      new Uint8Array(),
      new Uint8Array(72),
      new Uint8Array(72),
      hexToBytes(witnessScriptHex),
    ] }, true);
  });
  return sized.vsize;
}

export interface BuildRecoveryPlanRequest {
  identity: VaultPolicyIdentityV1;
  inputs: readonly ResolvedInput[];
  destinationAddress: string;
  feeRateSatPerVb: bigint;
  /** Omit to sweep everything to the destination with no change output. */
  amountSats?: bigint;
  /** Change branch index used when `amountSats` is given. */
  changeIndex?: number;
  nowMs?: bigint;
  windowMs?: bigint;
  /**
   * Fixed plan and request identifiers, for the golden vectors only.
   *
   * They exist so committed vectors can pin exact canonical bytes; a plan built
   * with fresh random identifiers could never be compared against a fixture.
   * They are labels rather than secrets — nothing in the signing path derives
   * from them — but ordinary use must leave them unset so that two plans built
   * seconds apart are distinguishable in a transcript.
   */
  planId?: string;
  requestId?: string;
}

export interface BuiltRecoveryPlan {
  plan: VaultUnsignedPlanV1;
  totalInputSats: bigint;
  feeSats: bigint;
  changeSats: bigint;
}

export function buildRecoveryPlan(request: BuildRecoveryPlanRequest): BuiltRecoveryPlan {
  const { identity, inputs, feeRateSatPerVb } = request;
  if (inputs.length === 0) throw new Error('a recovery plan needs at least one input');
  if (feeRateSatPerVb <= 0n) throw new Error('fee rate must be positive');

  const destination = resolvePayableAddress(request.destinationAddress, identity.network);
  if (!destination.ok) {
    throw new Error(
      `destination address is unusable on ${identity.network}: ${destination.reason}. ` +
      'A recovery exit sends to a wallet you control outside this Vault.',
    );
  }
  const ownsDestination = locateScript(identity, destination.value.scriptPubKey, DEFAULT_SEARCH_DEPTH);
  if (ownsDestination) {
    throw new Error(
      'the destination address belongs to this same Vault policy. A recovery exit moves funds out of the ' +
      'Vault; sending them back into it would leave them behind exactly the quorum you are working around.',
    );
  }

  const totalInputSats = inputs.reduce((sum, input) => sum + input.valueSats, 0n);
  const sweeping = request.amountSats === undefined;
  const changeIndex = request.changeIndex ?? 0;
  const change = sweeping ? undefined : derive(identity, 'change', changeIndex);

  // vsize depends only on the input and output shapes, never on the amounts,
  // so one pass settles the fee.
  const shape = new Transaction({ version: 2 });
  for (const input of inputs) shape.addInput({ txid: input.txid, index: input.vout, sequence: SEQUENCE });
  shape.addOutput({ script: hexToBytes(destination.value.scriptPubKey), amount: 1n });
  if (change) shape.addOutput({ script: hexToBytes(change.scriptPubKeyHex), amount: 1n });
  const vsize = upperBoundVsize(bytesToHex(shape.unsignedTx), inputs.map((input) => input.witnessScriptHex));
  const feeSats = BigInt(vsize) * feeRateSatPerVb;

  const amountSats = sweeping ? totalInputSats - feeSats : request.amountSats!;
  const changeSats = totalInputSats - amountSats - feeSats;

  if (amountSats <= 0n) {
    throw new Error(
      `these inputs total ${totalInputSats} sats and the fee at ${feeRateSatPerVb} sat/vB is ${feeSats} sats, ` +
      'so nothing would reach the destination. Wait for a lower fee rate or add inputs.',
    );
  }
  if (changeSats < 0n) {
    throw new Error(
      `${amountSats} sats plus a ${feeSats}-sat fee exceeds the ${totalInputSats} sats available`,
    );
  }
  if (!sweeping && changeSats > 0n && changeSats < MIN_CHANGE_SATS) {
    throw new Error(
      `the change would be ${changeSats} sats, below the ${MIN_CHANGE_SATS}-sat floor this tool will create. ` +
      'Lower --amount, or omit it to sweep everything. Change is never silently absorbed into the fee here.',
    );
  }
  if (!sweeping && changeSats === 0n) {
    throw new Error('this amount leaves exactly zero change; omit --amount to sweep instead');
  }

  const withChange = !sweeping && changeSats > 0n;
  const raw = new Transaction({ version: 2 });
  for (const input of inputs) raw.addInput({ txid: input.txid, index: input.vout, sequence: SEQUENCE });
  raw.addOutput({ script: hexToBytes(destination.value.scriptPubKey), amount: amountSats });
  if (withChange && change) raw.addOutput({ script: hexToBytes(change.scriptPubKeyHex), amount: changeSats });
  const unsignedTransactionHex = bytesToHex(raw.unsignedTx);

  const nowMs = request.nowMs ?? BigInt(Date.now());
  const windowMs = request.windowMs ?? DEFAULT_PLAN_WINDOW_MS;
  const expiresAtMs = nowMs + windowMs;

  const outputs: VaultUnsignedPlanV1['outputs'] = [{
    outputIndex: 0, valueSats: amountSats.toString(),
    scriptPubKeyHex: destination.value.scriptPubKey, address: destination.value.address,
    purpose: 'recovery-exit', branch: null, derivationIndex: null,
  }];
  if (withChange && change) {
    outputs.push({
      outputIndex: 1, valueSats: changeSats.toString(),
      scriptPubKeyHex: change.scriptPubKeyHex, address: change.address,
      purpose: 'vault-change', branch: 'change', derivationIndex: changeIndex,
    });
  }

  const plan = finalizeVaultUnsignedPlan({
    version: 1, policyVersion: 1, network: identity.network, policyId: identity.policyId,
    planId: request.planId ?? bytesToHex(new Uint8Array(randomBytes(16))),
    requestId: request.requestId ?? bytesToHex(new Uint8Array(randomBytes(16))),
    createdAtMs: nowMs.toString(), expiresAtMs: expiresAtMs.toString(),
    kind: 'recovery', unsignedTransactionHex,
    inputs: inputs.map((input) => ({
      txid: input.txid, vout: input.vout, valueSats: input.valueSats.toString(),
      scriptPubKeyHex: input.scriptPubKeyHex, witnessScriptHex: input.witnessScriptHex,
      branch: input.branch, derivationIndex: input.index, sequence: SEQUENCE, sighash: 'all',
      classification: 'unknown', classificationEvidenceHash: STANDALONE_SOURCE_SENTINEL.classification,
    })),
    outputs,
    destination: {
      kind: 'recovery-exit', pairedSpendingWalletIdHash: null, targetPolicyId: null,
      address: destination.value.address, outputIndex: 0,
    },
    amountSats: amountSats.toString(),
    changeSats: (withChange ? changeSats : 0n).toString(),
    feeSats: feeSats.toString(), vsize,
    feeRateSatPerKvB: ((feeSats * 1000n + BigInt(vsize) - 1n) / BigInt(vsize)).toString(),
    sighash: 'all',
    // No asset effects are claimed. This tool has no Ordinals data source, so
    // it cannot assert that an input is cardinal — and ADR 0007 §6 keeps
    // inscription movement out of the standalone exit for exactly that reason.
    assetEffects: [],
    source: {
      backendInstanceIdHash: STANDALONE_SOURCE_SENTINEL.backend,
      classificationRevisionHash: STANDALONE_SOURCE_SENTINEL.revision,
      coreTip: { height: 0, hash: STANDALONE_SOURCE_SENTINEL.backend },
      indexTip: { height: 0, hash: STANDALONE_SOURCE_SENTINEL.backend },
      observedAtMs: nowMs.toString(), validUntilMs: expiresAtMs.toString(),
    },
    replacement: { kind: 'none', replacesTxid: null, parentTxid: null },
    // The tool never opens a socket. The operator broadcasts the finished
    // bytes from wherever they choose, so the plan says so.
    broadcastIntent: 'return-psbt',
  });

  return { plan, totalInputSats, feeSats, changeSats: withChange ? changeSats : 0n };
}
