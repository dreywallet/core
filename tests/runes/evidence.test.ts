import { describe, expect, it } from 'vitest';
import { assertBoundRuneEvidence, bindRuneEvidence, projectRuneHoldings, runeInputUnavailable, runeOutputsResponseSchema, runeIdSchema, runeAtomicSchema, type RuneOutputsResponse } from '../../src/domain/runes/evidence';
import type { WalletUtxo } from '../../src/domain/classification/types';
const hash = 'a'.repeat(64);
const accountId = `acct_regtest_${hash}`;
const tip = { height: 20, hash };
const now = Date.parse('2026-09-09T00:00:00Z');
function fixture() {
  const utxo: WalletUtxo = { outpoint: { txid: hash, vout: 1 }, valueSats: 10000n,
    scriptPubKey: `5120${hash}`, accountId, account: 0, lane: 'ordinals', chain: 0,
    addressIndex: 0, height: 20, walletCreatedChange: false,
    flags: { userFrozen: false, dustQuarantined: false },
    facts: { primaryClass: 'runic_or_unsupported', confidence: 'authoritative', unsupportedAssetDetected: true,
      inscriptions: [], satRanges: [{ start: '1', end: '10001', rarity: 'common' }],
      classifiedTip: tip, classificationRevision: 'r1' } };
  const response: RuneOutputsResponse = { instanceId: 'local', network: 'regtest', protocolVersion: 2,
    requestNonce: 'public-test', timestamp: new Date(now).toISOString(), coreTip: tip, indexTip: tip,
    classificationRevision: 'r1', capabilities: ['rune_detection'], signature: 'public-test',
    runeProtocol: 'ord-0.27.1/native-v1', unknownOutpoints: [], outputs: [{ ...utxo.outpoint,
      scriptPubKey: utxo.scriptPubKey, valueSats: '10000', confirmations: 1, complete: true,
      balances: [{ id: '10:1', name: 'TEST•RUNE', amount: '9007199254740993', divisibility: 8, symbol: null }] }] };
  const context = { network: 'regtest' as const, accountId, instanceId: 'local', classificationRevision: 'r1',
    tip, nowMs: now, scanComplete: true, reservedOutpoints: new Set<string>() };
  return { utxo, response, context };
}
describe('complete Rune evidence', () => {
  it('preserves exact quantities above safe-number range and hides no constrained balance', () => {
    const { utxo, response, context } = fixture();
    const evidence = bindRuneEvidence([utxo], [response], context);
    expect(projectRuneHoldings([utxo], evidence, new Set())[0]?.available).toBe('9007199254740993');
    utxo.lane = 'payment';
    const holding = projectRuneHoldings([utxo], evidence, new Set())[0]!;
    expect(holding.available).toBe('0');
    expect(holding.total).toBe('9007199254740993');
    expect(holding.constrained[0]?.reason).toBe('wrong_role');
  });
  it.each(['missing', 'duplicate', 'wrong_script', 'wrong_value', 'wrong_account', 'stale', 'reorg', 'unknown', 'incomplete'])('rejects %s evidence', (mutation) => {
    const { utxo, response, context } = fixture();
    if (mutation === 'missing') response.outputs = [];
    if (mutation === 'duplicate') response.outputs.push(response.outputs[0]!);
    if (mutation === 'wrong_script') response.outputs[0]!.scriptPubKey = '0014' + 'b'.repeat(40);
    if (mutation === 'wrong_value') response.outputs[0]!.valueSats = '9999';
    if (mutation === 'wrong_account') utxo.accountId = `acct_regtest_${'b'.repeat(64)}`;
    if (mutation === 'stale') context.nowMs += 30001;
    if (mutation === 'reorg') context.tip = { height: 20, hash: 'b'.repeat(64) };
    if (mutation === 'unknown') { response.outputs = []; response.unknownOutpoints = [utxo.outpoint]; }
    if (mutation === 'incomplete') context.scanComplete = false;
    expect(() => bindRuneEvidence([utxo], [response], context)).toThrow();
  });
  it.each(['mixed', 'inscription', 'rare', 'null_ranges', 'reserved', 'frozen', 'pending'])('excludes %s without removing total', (mutation) => {
    const { utxo, response } = fixture(); const output = response.outputs[0]!; const reserved = new Set<string>();
    if (mutation === 'mixed') output.balances.push({ ...output.balances[0]!, id: '10:2' });
    if (mutation === 'inscription') utxo.facts!.inscriptions = [{ inscriptionId: `${hash}i0`, satpoint: `${hash}:1:0` }];
    if (mutation === 'rare') utxo.facts!.satRanges![0]!.rarity = 'rare';
    if (mutation === 'null_ranges') utxo.facts!.satRanges = null;
    if (mutation === 'reserved') reserved.add(`${hash}:1`);
    if (mutation === 'frozen') utxo.flags.userFrozen = true;
    if (mutation === 'pending') utxo.height = null;
    expect(runeInputUnavailable(utxo, output, '10:1', reserved)).not.toBeNull();
  });
  it('validates canonical numeric boundaries and prevents incomplete balances masquerading as complete', () => {
    for (const id of ['01:1', '0:1', '1:4294967296', '18446744073709551616:0']) expect(runeIdSchema.safeParse(id).success).toBe(false);
    expect(runeIdSchema.parse('18446744073709551615:4294967295')).toBeTruthy();
    expect(runeAtomicSchema.parse(((1n << 128n) - 1n).toString())).toBeTruthy();
    expect(runeAtomicSchema.safeParse((1n << 128n).toString()).success).toBe(false);
    const { response } = fixture(); response.outputs[0]!.complete = false;
    expect(runeOutputsResponseSchema.safeParse(response).success).toBe(false);
  });
});

describe('Rune authority boundary regression checks', () => {
  it('rejects invalid numeric syntax without throwing from safeParse', () => {
    for (const value of ['abc', '1e4', '1.1', '1:abc', 'a'.repeat(10000)]) {
      expect(runeIdSchema.safeParse(value).success).toBe(false);
      expect(runeAtomicSchema.safeParse(value).success).toBe(false);
    }
  });
  it('cannot mint timeless authority using a non-finite local clock', () => {
    const { utxo, response, context } = fixture();
    for (const nowMs of [NaN, Infinity, -Infinity, 1.5]) {
      expect(() => bindRuneEvidence([utxo], [response], { ...context, nowMs })).toThrow();
    }
  });
  it('requires a signed capability response even for an empty wallet', () => {
    const { response, context } = fixture(); response.outputs = [];
    expect(() => bindRuneEvidence([], [], context)).toThrow();
    expect(bindRuneEvidence([], [response], context).size).toBe(0);
  });
  it('expires and rejects forged, mutated, or clock-reversed authority', () => {
    const { utxo, response, context } = fixture();
    const evidence = bindRuneEvidence([utxo], [response], context);
    expect(() => assertBoundRuneEvidence(evidence, context)).not.toThrow();
    expect(() => assertBoundRuneEvidence(evidence, { ...context, nowMs: now + 30001 })).toThrow();
    expect(() => assertBoundRuneEvidence(evidence, { ...context, nowMs: now - 1 })).toThrow();
    expect(() => assertBoundRuneEvidence(new Map(evidence), context)).toThrow();
    evidence.get(`${utxo.outpoint.txid}:1`)!.balances[0]!.amount = '1';
    expect(() => assertBoundRuneEvidence(evidence, context)).toThrow();
  });
  it('rejects malformed sat ranges even when their signed sum matches the carrier', () => {
    const { utxo, response } = fixture();
    utxo.facts!.satRanges = [{ start: '0', end: '10001', rarity: 'common' }, { start: '2', end: '1', rarity: 'common' }];
    expect(runeInputUnavailable(utxo, response.outputs[0]!, '10:1', new Set())).toBe('mixed_assets');
  });
});
