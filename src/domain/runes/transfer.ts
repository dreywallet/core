import { SigHash, Transaction } from '@scure/btc-signer';
import { schnorr, secp256k1 } from '@noble/curves/secp256k1';
import { assertPublicAccountDefinition, derivePublicAccountAddress, publicAccountFromSeed, type PublicAccountDefinitionV1 } from '../accounts/public-account';
import { evaluateEligibility } from '../classification/eligibility';
import { outpointKey, type WalletUtxo } from '../classification/types';
import type { FreshnessReport } from '../gateway/freshness';
import { deriveAccountNode } from '../keys/derivation';
import type { PlanDerivation, PlanInput } from '../transactions/plan';
import { hashHex } from '../transactions/plan';
import { estimateVsize, feeForVsize, FINAL_SEQUENCE, inputVbytes, MAX_FEE_RATE_SAT_PER_KVB, scriptDustSats } from '../transactions/fees';
import { resolvePayableAddress } from '../transactions/native-send';
import type { SignedTransaction } from '../transactions/signing';
import { getCryptoProvider } from '../vault/crypto-provider';
import { zeroize } from '../vault/vault';
import { assertRuneAtomic, parseRuneAtomic, parseRuneId } from './amounts';
import { assertBoundRuneEvidence, runeInputUnavailable, runeOutputSchema, type RuneEvidenceContext, type RuneOutput } from './evidence';
import { encodeRunestone, evaluateRuneAllocations } from './protocol';

export const RUNE_POSTAGE_SATS = 546n;
export const RUNE_MAX_TRANSFER_INPUTS = 128;
export const RUNE_PLAN_LIFETIME_MS = 120_000;

export interface RuneTransferCurrent {
  /** Public account must be independently loaded from the active wallet. */
  publicAccount: PublicAccountDefinitionV1;
  context: RuneEvidenceContext;
  freshness: FreshnessReport;
  utxos: readonly WalletUtxo[];
  /** Fresh signature-verified responses joined by bindRuneEvidence. */
  evidence: ReadonlyMap<string, RuneOutput>;
}
export interface RuneTransferRequest extends RuneTransferCurrent {
  planId: string;
  runeId: string;
  amount: string | 'max';
  recipient: string;
  feeRateSatPerKvB: bigint;
  paymentChangeIndex: number;
  ordinalChangeIndex: number;
}
export interface RuneTransferOutput {
  role: 'runestone' | 'recipient' | 'rune_change' | 'payment_change';
  valueSats: bigint;
  scriptPubKey: string;
  address: string | null;
  derivation: PlanDerivation | null;
}
export interface RuneTransferPlan {
  version: 1;
  kind: 'rune_transfer';
  planId: string;
  createdAt: number;
  expiresAt: number;
  network: RuneEvidenceContext['network'];
  accountId: string;
  account: number;
  source: { instanceId: string; classificationRevision: string; tip: { hash: string; height: number } };
  rune: { id: string; name: string; divisibility: number; symbol: string | null };
  amount: string;
  sourceRuneAmount: string;
  retainedAmount: string;
  recipient: string;
  sendMax: boolean;
  paymentChangeIndex: number;
  ordinalChangeIndex: number;
  inputs: PlanInput[];
  outputs: RuneTransferOutput[];
  feeSats: bigint;
  feeRateSatPerKvB: bigint;
  vsize: bigint;
  psbtHex: string;
  planHash: string;
}
function hex(bytes: Uint8Array): string { return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join(''); }
function bytes(text: string): Uint8Array {
  if (text.length > 800_000 || text.length % 2 || !/^[0-9a-f]*$/u.test(text)) throw new Error('Invalid Rune transaction hex');
  return Uint8Array.from(text.match(/../gu) ?? [], pair => Number.parseInt(pair, 16));
}
function canonical(value: unknown): unknown {
  if (typeof value === 'bigint') return value.toString();
  if (Array.isArray(value)) return value.map(canonical);
  if (value !== null && typeof value === 'object') return Object.fromEntries(Object.entries(value).sort(([a], [b]) => a.localeCompare(b)).map(([key, item]) => [key, canonical(item)]));
  return value;
}
export function hashRuneTransferPlan(plan: Omit<RuneTransferPlan, 'planHash'> | RuneTransferPlan): string {
  const { planHash: _ignored, ...body } = plan as RuneTransferPlan;
  void _ignored;
  return hex(getCryptoProvider().sha256(new TextEncoder().encode(JSON.stringify(canonical(body)))));
}
function freeze<T>(value: T): T {
  if (value !== null && typeof value === 'object') { for (const child of Object.values(value)) freeze(child); Object.freeze(value); }
  return value;
}
function assertCurrent(current: RuneTransferCurrent): void {
  const { context, publicAccount, utxos, evidence, freshness } = current;
  assertPublicAccountDefinition(publicAccount);
  assertBoundRuneEvidence(evidence, context);
  if (publicAccount.accountId !== context.accountId || publicAccount.network !== context.network ||
    !context.scanComplete || !Number.isSafeInteger(context.nowMs) || !freshness.spendEligible ||
    !freshness.commonTip || !freshness.heartbeatFresh || !freshness.revisionActive ||
    freshness.spendingReady === false || freshness.walletDataFresh === false ||
    utxos.length > 10_000 || evidence.size !== utxos.length) throw new Error('Rune spending context unavailable');
  const seen = new Set<string>();
  for (const utxo of utxos) {
    const key = outpointKey(utxo.outpoint);
    const evidenceRaw = evidence.get(key);
    const output = evidenceRaw ? runeOutputSchema.parse(evidenceRaw) : undefined;
    if (!output || seen.has(key) || utxo.accountId !== context.accountId || utxo.account !== publicAccount.derivationAccountIndex ||
      output.txid !== utxo.outpoint.txid || output.vout !== utxo.outpoint.vout || !output.complete ||
      output.scriptPubKey !== utxo.scriptPubKey || BigInt(output.valueSats) !== utxo.valueSats ||
      output.confirmations !== (utxo.height === null ? 0 : context.tip.height - utxo.height + 1)) throw new Error('Rune evidence changed');
    if (utxo.height !== null && (!utxo.facts || utxo.facts.confidence !== 'authoritative' ||
      utxo.facts.classifiedTip.hash !== context.tip.hash || utxo.facts.classifiedTip.height !== context.tip.height ||
      utxo.facts.classificationRevision !== context.classificationRevision ||
      utxo.facts.unsupportedAssetDetected !== (output.balances.length > 0))) throw new Error('Rune classification changed');
    seen.add(key);
  }
}
function derived(current: RuneTransferCurrent, lane: 'payment' | 'ordinals', chain: 0 | 1, index: number) {
  const address = derivePublicAccountAddress(current.publicAccount, lane, chain, index);
  const derivation: PlanDerivation = { accountId: address.accountId, account: address.accountIndex, lane, chain, index, path: address.path, publicKeyHex: address.publicKeyHex };
  return { address, derivation };
}
function planInput(utxo: WalletUtxo, current: RuneTransferCurrent): PlanInput {
  const { address, derivation } = derived(current, utxo.lane, utxo.chain, utxo.addressIndex);
  if (utxo.scriptPubKey !== address.scriptPubKeyHex || !utxo.facts) throw new Error('Rune input ownership mismatch');
  return { txid: utxo.outpoint.txid, vout: utxo.outpoint.vout, valueSats: utxo.valueSats, scriptPubKey: utxo.scriptPubKey,
    sequence: FINAL_SEQUENCE, sighash: utxo.lane === 'ordinals' ? 0 : 1, ownership: 'wallet', derivation,
    classification: structuredClone(utxo.facts) };
}
function cleanFunding(utxo: WalletUtxo, current: RuneTransferCurrent, rate: bigint): boolean {
  return utxo.height !== null && utxo.lane === 'payment' && current.evidence.get(outpointKey(utxo.outpoint))?.balances.length === 0 &&
    evaluateEligibility(utxo, { freshness: current.freshness, activeRevision: current.context.classificationRevision,
      lockedOutpoints: current.context.reservedOutpoints, marginalFeeSatsFor: value => feeForVsize(inputVbytes(value.scriptPubKey), rate) }).eligible;
}
function makePsbt(inputs: readonly PlanInput[], outputs: readonly RuneTransferOutput[]): Transaction {
  const tx = new Transaction({ version: 2, lockTime: 0, lowR: true, allowUnknownOutputs: true });
  for (const input of inputs) tx.addInput({ txid: input.txid, index: input.vout, sequence: input.sequence,
    sighashType: input.sighash, witnessUtxo: { script: bytes(input.scriptPubKey), amount: input.valueSats },
    ...(input.sighash === 0 ? { tapInternalKey: bytes(input.derivation!.publicKeyHex).slice(1) } : {}) });
  for (const output of outputs) tx.addOutput({ script: bytes(output.scriptPubKey), amount: output.valueSats });
  return tx;
}

/** Separate policy: none of the ordinary BTC/Ordinals signing guards are relaxed. */
export function buildRuneTransferPlan(request: RuneTransferRequest): RuneTransferPlan {
  assertCurrent(request);
  parseRuneId(request.runeId);
  if (request.runeId === '0:0' || !/^[a-zA-Z0-9_-]{1,128}$/u.test(request.planId)) throw new Error('Invalid Rune transfer identity');
  if (request.feeRateSatPerKvB < 1000n || request.feeRateSatPerKvB > BigInt(MAX_FEE_RATE_SAT_PER_KVB)) throw new Error('Invalid Rune fee rate');
  const destination = resolvePayableAddress(request.recipient, request.context.network);
  if (!destination.ok) throw new Error('Invalid Rune recipient address');
  const candidates = request.utxos.filter(utxo => runeInputUnavailable(utxo, request.evidence.get(outpointKey(utxo.outpoint))!, request.runeId, request.context.reservedOutpoints) === null)
    .sort((a, b) => outpointKey(a.outpoint).localeCompare(outpointKey(b.outpoint)));
  const available = candidates.reduce((sum, utxo) => assertRuneAtomic(sum + BigInt(request.evidence.get(outpointKey(utxo.outpoint))!.balances[0]!.amount)), 0n);
  const amount = request.amount === 'max' ? available : parseRuneAtomic(request.amount);
  if (amount === 0n || amount > available) throw new Error('Insufficient available Rune quantity');
  const selected: WalletUtxo[] = [];
  let selectedAmount = 0n;
  for (const utxo of candidates) {
    if (selectedAmount >= amount) break;
    selected.push(utxo);
    selectedAmount += BigInt(request.evidence.get(outpointKey(utxo.outpoint))!.balances[0]!.amount);
  }
  if (selected.length > RUNE_MAX_TRANSFER_INPUTS) throw new Error('Too many Rune inputs');
  const metadata = request.evidence.get(outpointKey(selected[0]!.outpoint))!.balances[0]!;
  for (const utxo of request.utxos) for (const balance of request.evidence.get(outpointKey(utxo.outpoint))!.balances) {
    if (balance.id === request.runeId && (balance.name !== metadata.name || balance.divisibility !== metadata.divisibility || balance.symbol !== metadata.symbol)) throw new Error('Rune metadata disagreement');
  }
  const tokenChange = selectedAmount - amount;
  const payment = derived(request, 'payment', 1, request.paymentChangeIndex);
  const ordinal = derived(request, 'ordinals', 1, request.ordinalChangeIndex);
  const outputs: RuneTransferOutput[] = [
    { role: 'runestone', valueSats: 0n, scriptPubKey: '', address: null, derivation: null },
    { role: 'recipient', valueSats: RUNE_POSTAGE_SATS, scriptPubKey: destination.value.scriptPubKey, address: destination.value.address, derivation: null },
  ];
  if (tokenChange > 0n) outputs.push({ role: 'rune_change', valueSats: RUNE_POSTAGE_SATS, scriptPubKey: ordinal.address.scriptPubKeyHex, address: ordinal.address.address, derivation: ordinal.derivation });
  // All existing supply is explicitly assigned. Pointer is still explicit, with no residual.
  outputs[0]!.scriptPubKey = hex(encodeRunestone({ pointer: tokenChange > 0n ? 2 : 1,
    edicts: [{ id: request.runeId, amount, output: 1 }, ...(tokenChange > 0n ? [{ id: request.runeId, amount: tokenChange, output: 2 }] : [])] }, outputs.length));
  const inputs = selected.map(utxo => planInput(utxo, request));
  const carrierValue = inputs.reduce((sum, input) => sum + input.valueSats, 0n);
  const funding = request.utxos.filter(utxo => cleanFunding(utxo, request, request.feeRateSatPerKvB))
    .sort((a, b) => a.valueSats > b.valueSats ? -1 : a.valueSats < b.valueSats ? 1 : outpointKey(a.outpoint).localeCompare(outpointKey(b.outpoint)));
  const outputValue = outputs.reduce((sum, output) => sum + output.valueSats, 0n);
  let feeSats = 0n;
  let vsize = 0n;
  for (let next = 0;; next++) {
    const total = inputs.reduce((sum, input) => sum + input.valueSats, 0n);
    vsize = estimateVsize(inputs.map(input => input.scriptPubKey), outputs.map(output => output.scriptPubKey));
    const minimumFee = feeForVsize(vsize, request.feeRateSatPerKvB);
    const changeVsize = estimateVsize(inputs.map(input => input.scriptPubKey), [...outputs.map(output => output.scriptPubKey), payment.address.scriptPubKeyHex]);
    const withChangeFee = feeForVsize(changeVsize, request.feeRateSatPerKvB);
    const fundingValue = total - carrierValue;
    const postageDeficit = outputValue > carrierValue ? outputValue - carrierValue : 0n;
    const hasCleanFunding = inputs.length > selected.length;
    if (hasCleanFunding && fundingValue >= withChangeFee + postageDeficit &&
        total >= outputValue + withChangeFee + scriptDustSats(payment.address.scriptPubKeyHex)) {
      outputs.push({ role: 'payment_change', valueSats: total - outputValue - withChangeFee, scriptPubKey: payment.address.scriptPubKeyHex, address: payment.address.address, derivation: payment.derivation });
      feeSats = withChangeFee; vsize = changeVsize; break;
    }
    if (hasCleanFunding && total >= outputValue + minimumFee &&
        fundingValue >= total - outputValue + postageDeficit) { feeSats = total - outputValue; break; }
    const utxo = funding[next];
    if (!utxo) throw new Error('Insufficient clean Bitcoin fee funding');
    if (inputs.length >= RUNE_MAX_TRANSFER_INPUTS) throw new Error('Too many Rune transfer inputs');
    inputs.push(planInput(utxo, request));
  }
  if (vsize > 100_000n) throw new Error('Rune transaction too large');
  const totalHolding = request.utxos.reduce((sum, utxo) => sum + request.evidence.get(outpointKey(utxo.outpoint))!.balances.filter(balance => balance.id === request.runeId).reduce((part, balance) => part + BigInt(balance.amount), 0n), 0n);
  assertRuneAtomic(totalHolding);
  const body: Omit<RuneTransferPlan, 'planHash'> = {
    version: 1, kind: 'rune_transfer', planId: request.planId, createdAt: request.context.nowMs, expiresAt: request.context.nowMs + RUNE_PLAN_LIFETIME_MS,
    network: request.context.network, accountId: request.context.accountId, account: request.publicAccount.derivationAccountIndex,
    source: { instanceId: request.context.instanceId, classificationRevision: request.context.classificationRevision, tip: { ...request.context.tip } },
    rune: { id: metadata.id, name: metadata.name, divisibility: metadata.divisibility, symbol: metadata.symbol }, amount: amount.toString(), sourceRuneAmount: selectedAmount.toString(), retainedAmount: (totalHolding - amount).toString(),
    recipient: destination.value.address, sendMax: request.amount === 'max', paymentChangeIndex: request.paymentChangeIndex, ordinalChangeIndex: request.ordinalChangeIndex,
    inputs, outputs, feeSats, feeRateSatPerKvB: request.feeRateSatPerKvB, vsize, psbtHex: hex(makePsbt(inputs, outputs).toPSBT()),
  };
  const plan = freeze({ ...body, planHash: hashRuneTransferPlan(body) });
  assertRuneTransferPlan(plan, request);
  return plan;
}

export function assertRuneTransferPlan(plan: RuneTransferPlan, current: RuneTransferCurrent): void {
  assertCurrent(current);
  if (plan.planHash !== hashRuneTransferPlan(plan) || plan.kind !== 'rune_transfer' || plan.version !== 1 ||
    plan.network !== current.context.network || plan.accountId !== current.context.accountId || plan.account !== current.publicAccount.derivationAccountIndex ||
    plan.source.instanceId !== current.context.instanceId || plan.source.classificationRevision !== current.context.classificationRevision ||
    plan.source.tip.hash !== current.context.tip.hash || plan.source.tip.height !== current.context.tip.height ||
    !Number.isSafeInteger(plan.createdAt) || !Number.isSafeInteger(plan.expiresAt) || plan.expiresAt !== plan.createdAt + RUNE_PLAN_LIFETIME_MS ||
    current.context.nowMs < plan.createdAt || current.context.nowMs > plan.expiresAt) throw new Error('Rune plan identity or freshness changed');
  if (!plan.inputs.length || plan.inputs.length > RUNE_MAX_TRANSFER_INPUTS || plan.outputs.length < 2 || plan.outputs.length > 4) throw new Error('Invalid Rune transaction shape');
  const byOutpoint = new Map(current.utxos.map(utxo => [outpointKey(utxo.outpoint), utxo]));
  const seen = new Set<string>();
  let runeAmount = 0n;
  let carrierValue = 0n;
  let fundingValue = 0n;
  let cleanInputCount = 0;
  const balances: Array<{ id: string; amount: bigint }> = [];
  for (const input of plan.inputs) {
    const key = outpointKey(input);
    const utxo = byOutpoint.get(key);
    if (!utxo || seen.has(key)) throw new Error('Rune input missing or duplicated');
    seen.add(key);
    const output = current.evidence.get(key)!;
    const expected = planInput(utxo, current);
    if (JSON.stringify(canonical(expected)) !== JSON.stringify(canonical(input))) throw new Error('Rune input ownership or classification changed');
    if (output.balances.length) {
      if (runeInputUnavailable(utxo, output, plan.rune.id, current.context.reservedOutpoints) !== null) throw new Error('Rune input unavailable');
      const balance = output.balances[0]!;
      if (balance.name !== plan.rune.name || balance.divisibility !== plan.rune.divisibility || balance.symbol !== plan.rune.symbol) throw new Error('Rune metadata changed');
      runeAmount = assertRuneAtomic(runeAmount + BigInt(balance.amount));
      carrierValue += input.valueSats;
      balances.push({ id: balance.id, amount: BigInt(balance.amount) });
    } else {
      if (!cleanFunding(utxo, current, plan.feeRateSatPerKvB)) throw new Error('Rune fee funding is not clean');
      fundingValue += input.valueSats; cleanInputCount++;
    }
  }
  const amount = parseRuneAtomic(plan.amount);
  if (amount === 0n || runeAmount < amount || runeAmount !== parseRuneAtomic(plan.sourceRuneAmount)) throw new Error('Rune amount mismatch');
  const currentAvailable = current.utxos.reduce((sum, utxo) => {
    const output = current.evidence.get(outpointKey(utxo.outpoint))!;
    return runeInputUnavailable(utxo, output, plan.rune.id, current.context.reservedOutpoints) === null
      ? assertRuneAtomic(sum + BigInt(output.balances[0]!.amount)) : sum;
  }, 0n);
  if (plan.sendMax && amount !== currentAvailable) throw new Error('Rune Max eligible quantity changed');
  const totalHolding = current.utxos.reduce((sum, utxo) => sum + current.evidence.get(outpointKey(utxo.outpoint))!.balances.filter(balance => balance.id === plan.rune.id).reduce((part, balance) => part + BigInt(balance.amount), 0n), 0n);
  if (totalHolding - amount !== parseRuneAtomic(plan.retainedAmount)) throw new Error('Rune retained balance changed');
  const tokenChange = runeAmount - amount;
  const destination = resolvePayableAddress(plan.recipient, plan.network);
  if (!destination.ok || destination.value.address !== plan.recipient) throw new Error('Rune recipient changed');
  const stone = plan.outputs[0]!;
  const recipient = plan.outputs[1]!;
  const canonicalStone = hex(encodeRunestone({ pointer: tokenChange > 0n ? 2 : 1, edicts: [{ id: plan.rune.id, amount, output: 1 }, ...(tokenChange > 0n ? [{ id: plan.rune.id, amount: tokenChange, output: 2 }] : [])] }, plan.outputs.length));
  if (stone.role !== 'runestone' || stone.valueSats !== 0n || stone.address !== null || stone.derivation !== null || stone.scriptPubKey !== canonicalStone ||
    recipient.role !== 'recipient' || recipient.address !== plan.recipient || recipient.scriptPubKey !== destination.value.scriptPubKey ||
    recipient.valueSats !== RUNE_POSTAGE_SATS || recipient.derivation !== null) throw new Error('Rune recipient or runestone policy changed');
  const owned = plan.outputs.slice(2);
  if (owned.length !== (tokenChange > 0n ? 1 : 0) + (owned.at(-1)?.role === 'payment_change' ? 1 : 0)) throw new Error('Unexpected Rune output');
  for (const [offset, output] of owned.entries()) {
    const runeChange = tokenChange > 0n && offset === 0;
    const expected = derived(current, runeChange ? 'ordinals' : 'payment', 1, runeChange ? plan.ordinalChangeIndex : plan.paymentChangeIndex);
    if (output.role !== (runeChange ? 'rune_change' : 'payment_change') || output.address !== expected.address.address || output.scriptPubKey !== expected.address.scriptPubKeyHex ||
      JSON.stringify(canonical(output.derivation)) !== JSON.stringify(canonical(expected.derivation)) ||
      (runeChange ? output.valueSats !== RUNE_POSTAGE_SATS : output.valueSats < scriptDustSats(output.scriptPubKey))) throw new Error('Rune change ownership changed');
  }
  const allocation = evaluateRuneAllocations(plan.outputs.map(output => bytes(output.scriptPubKey)), balances);
  if (allocation.artifact.kind !== 'runestone' || allocation.burned.size || allocation.outputs.some((output, index) =>
    [...output.keys()].some(id => id !== plan.rune.id) || (output.get(plan.rune.id) ?? 0n) !== (index === 1 ? amount : index === 2 && tokenChange > 0n ? tokenChange : 0n))) throw new Error('Rune allocation mismatch');
  const postageValue = RUNE_POSTAGE_SATS * (tokenChange > 0n ? 2n : 1n);
  const postageDeficit = postageValue > carrierValue ? postageValue - carrierValue : 0n;
  if (cleanInputCount < 1 || fundingValue < plan.feeSats + postageDeficit) throw new Error('Insufficient clean Bitcoin fee funding');
  const inputValue = plan.inputs.reduce((sum, input) => sum + input.valueSats, 0n);
  const outputValue = plan.outputs.reduce((sum, output) => sum + output.valueSats, 0n);
  const vsize = estimateVsize(plan.inputs.map(input => input.scriptPubKey), plan.outputs.map(output => output.scriptPubKey));
  const minimumFee = feeForVsize(vsize, plan.feeRateSatPerKvB);
  if (plan.feeRateSatPerKvB < 1000n || plan.feeRateSatPerKvB > BigInt(MAX_FEE_RATE_SAT_PER_KVB) || plan.vsize !== vsize || vsize > 100_000n ||
    inputValue - outputValue !== plan.feeSats || plan.feeSats < minimumFee) throw new Error('Rune fee mismatch');
  if (plan.outputs.at(-1)?.role === 'payment_change') {
    if (plan.feeSats !== minimumFee) throw new Error('Excess Rune fee');
  } else {
    const payment = derived(current, 'payment', 1, plan.paymentChangeIndex);
    const withChange = estimateVsize(plan.inputs.map(input => input.scriptPubKey), [...plan.outputs.map(output => output.scriptPubKey), payment.address.scriptPubKeyHex]);
    if (plan.feeSats - feeForVsize(withChange, plan.feeRateSatPerKvB) >= scriptDustSats(payment.address.scriptPubKeyHex)) throw new Error('Missing owned Bitcoin change');
  }
  if (hex(makePsbt(plan.inputs, plan.outputs).toPSBT()) !== plan.psbtHex) throw new Error('Rune PSBT changed');
}

function validateRawShape(plan: RuneTransferPlan, tx: Transaction): void {
  if (tx.version !== 2 || tx.lockTime !== 0 || tx.inputsLength !== plan.inputs.length || tx.outputsLength !== plan.outputs.length) throw new Error('Rune final transaction shape changed');
  for (const [i, expected] of plan.inputs.entries()) {
    const input = tx.getInput(i);
    if (!input.txid || hex(input.txid) !== expected.txid || input.index !== expected.vout || input.sequence !== FINAL_SEQUENCE || (input.finalScriptSig?.length ?? 0) !== 0) throw new Error('Rune final transaction input changed');
  }
  for (const [i, expected] of plan.outputs.entries()) {
    const output = tx.getOutput(i);
    if (!output.script || hex(output.script) !== expected.scriptPubKey || output.amount !== expected.valueSats) throw new Error('Rune final transaction output changed');
  }
}

/** Broadcast boundary: independently reparse exact serialized bytes and verify signatures. */
export function validateRuneTransferRaw(plan: RuneTransferPlan, transactionHex: string, current: RuneTransferCurrent): SignedTransaction {
  assertRuneTransferPlan(plan, current);
  const raw = bytes(transactionHex);
  const tx = Transaction.fromRaw(raw, { allowUnknownOutputs: true });
  if (hex(tx.toBytes(true, true)) !== transactionHex) throw new Error('Noncanonical Rune transaction bytes');
  validateRawShape(plan, tx);
  if (BigInt(tx.vsize) > plan.vsize) throw new Error('Rune final transaction exceeds reviewed fee size');
  const scripts = plan.inputs.map(input => bytes(input.scriptPubKey));
  const amounts = plan.inputs.map(input => input.valueSats);
  for (const [i, input] of plan.inputs.entries()) {
    const witness = tx.getInput(i).finalScriptWitness ?? [];
    if (input.sighash === 0) {
      if (witness.length !== 1 || witness[0]?.length !== 64 || !schnorr.verify(witness[0], tx.preimageWitnessV1(i, scripts, 0, amounts), bytes(input.scriptPubKey).slice(2))) throw new Error('Invalid Rune Taproot signature');
    } else {
      const signature = witness[0]; const key = witness[1];
      if (witness.length !== 2 || !signature || signature.length < 2 || signature.at(-1) !== 1 || !key || hex(key) !== input.derivation!.publicKeyHex ||
        !secp256k1.verify(signature.slice(0, -1), tx.preimageWitnessV0(i, bytes(`76a914${input.scriptPubKey.slice(4)}88ac`), 1, input.valueSats), key, { format: 'der', prehash: false, lowS: true })) throw new Error('Invalid Rune funding signature');
    }
  }
  // Reconstruct allocations from the actual outputs and current, complete input balances.
  const balances = plan.inputs.flatMap(input => current.evidence.get(outpointKey(input))!.balances.map(balance => ({ id: balance.id, amount: BigInt(balance.amount) })));
  const allocation = evaluateRuneAllocations(Array.from({ length: tx.outputsLength }, (_, i) => tx.getOutput(i).script!), balances);
  if (allocation.artifact.kind !== 'runestone' || allocation.burned.size || allocation.outputs[1]!.get(plan.rune.id) !== BigInt(plan.amount)) throw new Error('Rune final allocation changed');
  const digest = getCryptoProvider().sha256(getCryptoProvider().sha256(raw));
  return { transactionHex, txid: tx.id, wtxid: hex(Uint8Array.from(digest).reverse()), vsize: BigInt(tx.vsize) };
}

export function signRuneTransferPlan(plan: RuneTransferPlan, seed: Uint8Array, random: (length: number) => Uint8Array, current: RuneTransferCurrent): SignedTransaction {
  assertRuneTransferPlan(plan, current);
  const signer = publicAccountFromSeed(seed, plan.network, plan.account);
  if (signer.accountId !== plan.accountId) throw new Error('Rune signer account mismatch');
  const tx = Transaction.fromPSBT(bytes(plan.psbtHex), { lowR: true, allowUnknownOutputs: true });
  for (const [index, input] of plan.inputs.entries()) {
    const derivation = input.derivation!;
    const account = deriveAccountNode(seed, derivation.lane, plan.network, derivation.account);
    const chain = account.deriveChild(derivation.chain);
    const key = chain.deriveChild(derivation.index);
    try {
      if (!key.publicKey || hex(key.publicKey) !== derivation.publicKeyHex || !key.privateKey) throw new Error('Rune signing ownership mismatch');
      const privateKey = key.privateKey;
      try { tx.signIdx(privateKey, index, [input.sighash === 0 ? SigHash.DEFAULT : SigHash.ALL], input.sighash === 0 ? random(32) : undefined); }
      finally { zeroize(privateKey); }
    } finally { key.wipePrivateData(); chain.wipePrivateData(); account.wipePrivateData(); }
  }
  tx.finalize();
  return validateRuneTransferRaw(plan, hex(tx.extract()), current);
}

/** Exact serialized-byte commitment for pending/reconciliation storage. */
export function runeTransferBytesHash(transactionHex: string): string { return hashHex(transactionHex); }
