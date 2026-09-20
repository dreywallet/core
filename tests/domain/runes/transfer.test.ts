import { beforeAll, describe, expect, it } from 'vitest';
import { Transaction } from '@scure/btc-signer';
import { derivePublicAccountAddress, publicAccountFromSeed } from '../../../src/domain/accounts/public-account';
import type { WalletUtxo } from '../../../src/domain/classification/types';
import { mnemonicToSeed } from '../../../src/domain/keys/mnemonic';
import { installTestCryptoProvider } from '../../helpers/install-crypto-provider';
import { assertRuneTransferPlan, buildRuneTransferPlan, hashRuneTransferPlan, signRuneTransferPlan, validateRuneTransferRaw, type RuneTransferPlan, type RuneTransferRequest } from '../../../src/domain/runes/transfer';
import { bindRuneEvidence, type RuneOutput } from '../../../src/domain/runes/evidence';
import { evaluateRuneAllocations } from '../../../src/domain/runes/protocol';

const seed = mnemonicToSeed('abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about');
const account = publicAccountFromSeed(seed, 'signet', 0);
const recipient = derivePublicAccountAddress(publicAccountFromSeed(seed, 'signet', 1), 'ordinals', 0, 0).address;
const tip = { height: 250000, hash: '2'.repeat(64) };
beforeAll(installTestCryptoProvider);
function fixture(): RuneTransferRequest {
  const utxos: WalletUtxo[] = [];
  const evidence = new Map<string, RuneOutput>();
  for (let i = 0; i < 3; i++) {
    const lane = i === 2 ? 'payment' : 'ordinals';
    const derived = derivePublicAccountAddress(account, lane, 0, i);
    const valueSats = i === 2 ? 10000n : 546n;
    const outpoint = { txid: String(i + 3).repeat(64), vout: 0 };
    utxos.push({ outpoint, valueSats, scriptPubKey: derived.scriptPubKeyHex, accountId: account.accountId, account: 0, lane, chain: 0, addressIndex: i, height: 249999,
      walletCreatedChange: false, flags: { userFrozen: false, dustQuarantined: false }, facts: { primaryClass: i === 2 ? 'cardinal_clean' : 'runic_or_unsupported',
        inscriptions: [], satRanges: [{ start: '100000001', end: (100000001n + valueSats).toString(), rarity: 'common' }], unsupportedAssetDetected: i !== 2,
        confidence: 'authoritative', classifiedTip: tip, classificationRevision: 'rev-runes' } });
    evidence.set(`${outpoint.txid}:0`, { ...outpoint, valueSats: valueSats.toString(), scriptPubKey: derived.scriptPubKeyHex, confirmations: 2, complete: true,
      balances: i === 2 ? [] : [{ id: '840000:1', name: 'TEST•RUNE', divisibility: 2, symbol: null, amount: i === 0 ? '1000' : '2000' }] });
  }
  return rebind({ publicAccount: account, context: { network: 'signet', accountId: account.accountId, instanceId: 'fixture', classificationRevision: 'rev-runes', tip, nowMs: 100000,
    scanComplete: true, reservedOutpoints: new Set() }, freshness: { commonTip: true, heartbeatFresh: true, revisionActive: true, spendEligible: true }, utxos, evidence,
    planId: 'rune-test', runeId: '840000:1', amount: '400', recipient, feeRateSatPerKvB: 1000n, paymentChangeIndex: 0, ordinalChangeIndex: 0 });
}
function rebind(request: RuneTransferRequest): RuneTransferRequest {
  request.evidence = bindRuneEvidence(request.utxos, [{ protocolVersion: 2, runeProtocol: 'ord-0.27.1/native-v1',
    network: request.context.network, instanceId: request.context.instanceId, classificationRevision: request.context.classificationRevision,
    coreTip: request.context.tip, indexTip: request.context.tip, requestNonce: 'fixture', timestamp: new Date(request.context.nowMs).toISOString(),
    capabilities: [], signature: 'verified-test-envelope', outputs: [...request.evidence.values()], unknownOutpoints: [] }], request.context);
  return request;
}
function mutated(plan: RuneTransferPlan, change: (plan: RuneTransferPlan) => void): RuneTransferPlan {
  const copy = structuredClone(plan); change(copy); copy.planHash = hashRuneTransferPlan(copy); return copy;
}
function rawBytes(hex: string): Uint8Array { return Uint8Array.from(hex.match(/../g) ?? [], byte => parseInt(byte, 16)); }
function hex(bytes: Uint8Array): string { return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join(''); }

describe('native Rune transfer policy and signer', () => {
  it('plans and signs a partial transfer with exact Rune and Bitcoin change', () => {
    const request = fixture(); const plan = buildRuneTransferPlan(request);
    expect(plan.amount).toBe('400'); expect(plan.retainedAmount).toBe('2600'); expect(plan.sourceRuneAmount).toBe('1000');
    expect(plan.inputs.map(input => input.valueSats)).toEqual([546n, 10000n]);
    expect(plan.outputs.map(output => output.role)).toEqual(['runestone', 'recipient', 'rune_change', 'payment_change']);
    expect(plan.inputs.reduce((sum, input) => sum + input.valueSats, 0n) - plan.outputs.reduce((sum, output) => sum + output.valueSats, 0n)).toBe(plan.feeSats);
    const signed = signRuneTransferPlan(plan, seed, size => new Uint8Array(size).fill(7), request);
    expect(validateRuneTransferRaw(plan, signed.transactionHex, request)).toEqual(signed);
    expect(signed.vsize <= plan.vsize).toBe(true);
    const allocation = evaluateRuneAllocations(plan.outputs.map(output => rawBytes(output.scriptPubKey)), [{ id: plan.rune.id, amount: 1000n }]);
    expect(allocation.outputs[1]!.get(plan.rune.id)).toBe(400n); expect(allocation.outputs[2]!.get(plan.rune.id)).toBe(600n);
  });
  it('combines confirmed same-Rune outputs for Max and retains no token residue', () => {
    const request = { ...fixture(), amount: 'max' }; const plan = buildRuneTransferPlan(request);
    expect(plan.amount).toBe('3000'); expect(plan.retainedAmount).toBe('0'); expect(plan.sourceRuneAmount).toBe('3000');
    expect(plan.outputs.some(output => output.role === 'rune_change')).toBe(false);
    expect(plan.inputs.filter(input => input.derivation!.lane === 'ordinals')).toHaveLength(2);
    expect(() => signRuneTransferPlan(plan, seed, size => new Uint8Array(size), request)).not.toThrow();
  });
  it('requires independent account derivation, not a supplied change label', () => {
    const request = fixture(); const plan = buildRuneTransferPlan(request);
    const forged = mutated(plan, copy => { copy.outputs[2]!.scriptPubKey = copy.outputs[1]!.scriptPubKey; });
    expect(() => assertRuneTransferPlan(forged, request)).toThrow('ownership');
    request.utxos[0]!.scriptPubKey = request.utxos[1]!.scriptPubKey;
    (request.evidence.get(`${'3'.repeat(64)}:0`)!).scriptPubKey = request.utxos[1]!.scriptPubKey;
    expect(() => buildRuneTransferPlan(rebind(request))).toThrow('ownership');
  });
  it.each(['other_rune', 'inscription', 'rare', 'unknown', 'wrong_role', 'pending', 'frozen', 'reserved'] as const)('rejects a constrained selected carrier: %s', reason => {
    const request = fixture(); const source = request.utxos[0]!;
    const evidence = request.evidence.get(`${source.outpoint.txid}:0`)!;
    if (reason === 'other_rune') evidence.balances.push({ ...evidence.balances[0]!, id: '840000:2' });
    if (reason === 'inscription') source.facts!.inscriptions.push({ inscriptionId: `${'a'.repeat(64)}i0`, satpoint: `${source.outpoint.txid}:0:0` });
    if (reason === 'rare') source.facts!.satRanges![0]!.rarity = 'uncommon';
    if (reason === 'unknown') source.facts!.satRanges = null;
    if (reason === 'wrong_role') source.lane = 'payment';
    if (reason === 'pending') { source.height = null; evidence.confirmations = 0; }
    if (reason === 'frozen') source.flags.userFrozen = true;
    if (reason === 'reserved') (request.context.reservedOutpoints as Set<string>).add(`${source.outpoint.txid}:0`);
    // Available second source may be used, but cannot stand in for all 3000 units.
    expect(() => buildRuneTransferPlan(rebind({ ...request, amount: '3000' }))).toThrow('available');
  });
  it('requires clean fee funding even when a carrier has ample sats and returns its surplus', () => {
    const request = fixture();
    const source = request.utxos[0]!; source.valueSats = 10000n;
    source.facts!.satRanges![0]!.end = '100010001';
    request.evidence.get(`${source.outpoint.txid}:0`)!.valueSats = '10000';
    const plan = buildRuneTransferPlan(rebind(request));
    const cleanValue = plan.inputs.filter(input => input.derivation!.lane === 'payment').reduce((sum, input) => sum + input.valueSats, 0n);
    expect(cleanValue >= plan.feeSats).toBe(true);
    expect(() => assertRuneTransferPlan(mutated(plan, copy => { copy.inputs = copy.inputs.filter(input => input.derivation!.lane === 'ordinals'); }), request)).toThrow('clean Bitcoin');
    expect(plan.outputs.find(output => output.role === 'payment_change')!.valueSats).toBe(10000n - 1092n + cleanValue - plan.feeSats);
    const noFunding = { ...request, utxos: request.utxos.slice(0, 2), evidence: new Map([...request.evidence].filter(([key]) => key !== `${'5'.repeat(64)}:0`)) };
    expect(() => buildRuneTransferPlan(rebind(noFunding))).toThrow('clean Bitcoin');
  });
  it('independently rejects a partial transfer relabeled as Max', () => {
    const request = fixture(); const plan = buildRuneTransferPlan(request);
    expect(() => assertRuneTransferPlan(mutated(plan, copy => { copy.sendMax = true; }), request)).toThrow('Max');
  });
  it('preserves ordinary protected funding exclusions', () => {
    const request = fixture(); request.utxos[2]!.flags.userFrozen = true;
    expect(() => buildRuneTransferPlan(request)).toThrow('clean Bitcoin');
  });
  it('rejects missing evidence and incomplete scans rather than showing zero', () => {
    const request = fixture();
    expect(() => buildRuneTransferPlan({ ...request, evidence: new Map() })).toThrow();
    expect(() => buildRuneTransferPlan({ ...request, context: { ...request.context, scanComplete: false } })).toThrow();
  });
  it('rejects stale plans, changed account/tip, reservations and disappeared inputs', () => {
    const request = fixture(); const plan = buildRuneTransferPlan(request);
    for (const current of [
      { ...request, context: { ...request.context, nowMs: plan.expiresAt + 1 } },
      { ...request, context: { ...request.context, nowMs: NaN } },
      { ...request, context: { ...request.context, tip: { ...tip, hash: 'f'.repeat(64) } } },
      { ...request, publicAccount: publicAccountFromSeed(seed, 'signet', 1) },
      { ...request, context: { ...request.context, reservedOutpoints: new Set([`${plan.inputs[0]!.txid}:0`]) } },
      { ...request, utxos: request.utxos.slice(1) },
      { ...request, freshness: { ...request.freshness, heartbeatFresh: false } },
    ]) expect(() => signRuneTransferPlan(plan, seed, size => new Uint8Array(size), current)).toThrow();
  });
  it('rejects changed PSBT, recipient allocations, fee and final sequence even with a recomputed hash', () => {
    const request = fixture(); const plan = buildRuneTransferPlan(request);
    for (const mutate of [
      (copy: RuneTransferPlan) => { copy.psbtHex += '00'; },
      (copy: RuneTransferPlan) => { copy.outputs[0]!.scriptPubKey = '6a5d027e00'; },
      (copy: RuneTransferPlan) => { copy.outputs[0]!.scriptPubKey = '6a5d0180'; },
      (copy: RuneTransferPlan) => { copy.outputs[1]!.valueSats += 1n; },
      (copy: RuneTransferPlan) => { copy.amount = '401'; },
      (copy: RuneTransferPlan) => { copy.feeSats += 1n; },
      (copy: RuneTransferPlan) => { copy.inputs[0]!.sequence = 0xfffffffd; },
      (copy: RuneTransferPlan) => { copy.inputs[0]!.sighash = 131; },
      (copy: RuneTransferPlan) => { copy.inputs.push(copy.inputs[0]!); },
    ]) expect(() => signRuneTransferPlan(mutated(plan, mutate), seed, size => new Uint8Array(size), request)).toThrow();
  });
  it('independently verifies final serialized signatures and exact output bytes', () => {
    const request = fixture(); const plan = buildRuneTransferPlan(request);
    const signed = signRuneTransferPlan(plan, seed, size => new Uint8Array(size), request);
    const invalid = rawBytes(signed.transactionHex); invalid[invalid.length - 10] = invalid[invalid.length - 10]! ^ 1;
    expect(() => validateRuneTransferRaw(plan, hex(invalid), request)).toThrow();
    const tx = Transaction.fromRaw(rawBytes(signed.transactionHex), { allowUnknownOutputs: true });
    const output = tx.getOutput(1); tx.updateOutput(1, { ...output, amount: output.amount! + 1n }, true);
    expect(() => validateRuneTransferRaw(plan, hex(tx.toBytes(true, true)), request)).toThrow();
    expect(() => validateRuneTransferRaw(plan, signed.transactionHex + '00', request)).toThrow();
  });
  it('allows a reviewed plan only with newly verified evidence after the 30-second authority expires', () => {
    const request = fixture(); const plan = buildRuneTransferPlan(request);
    const later = { ...request, context: { ...request.context, nowMs: request.context.nowMs + 60000 } };
    expect(() => signRuneTransferPlan(plan, seed, size => new Uint8Array(size), later)).toThrow('authority');
    const refreshed = rebind(later);
    expect(() => signRuneTransferPlan(plan, seed, size => new Uint8Array(size), refreshed)).not.toThrow();
    refreshed.context.nowMs = plan.expiresAt + 1;
    expect(() => signRuneTransferPlan(plan, seed, size => new Uint8Array(size), rebind(refreshed))).toThrow('freshness');
  });
  it('never derives the requested account from a different signing seed', () => {
    const request = fixture(); const plan = buildRuneTransferPlan(request);
    expect(() => signRuneTransferPlan(plan, new Uint8Array(64).fill(3), size => new Uint8Array(size), request)).toThrow('account');
  });
});
