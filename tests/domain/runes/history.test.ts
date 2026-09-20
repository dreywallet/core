import { describe, expect, it } from 'vitest';
import { runeHistoryRequestSchema, runeHistoryResponseSchema, runeVerifiedEffectSchema } from '../../../src/domain/runes/evidence';
const id = '1'.repeat(64); const other = '2'.repeat(64);
const request = { network: 'regtest', scriptHashes: [id], transactions: [{ txid: id, wtxid: other, transactionHex: '00' }] };
const response = { instanceId: 'fixture', network: 'regtest', protocolVersion: 2, requestNonce: 'fixture', timestamp: '2026-09-09T00:00:00.000Z', coreTip: { height: 10, hash: id }, indexTip: { height: 10, hash: id }, classificationRevision: 'r', capabilities: [], signature: 'fixture', runeProtocol: 'ord-0.27.1/native-v1', requestedScriptHashes: [id], historyComplete: false, receipts: [], effects: [], reconciliation: [{ txid: id, wtxid: other, status: 'indeterminate', confirmedSpenderTxid: null, conflictedAncestorTxid: null }] };
describe('Rune history wire bounds and proof partition', () => {
  it('accepts explicit unknown effects without inventing balances', () => { expect(runeHistoryResponseSchema.parse(response).historyComplete).toBe(false); });
  it('bounds raw bytes, transaction count and distinct script hashes', () => {
    expect(runeHistoryRequestSchema.safeParse(request).success).toBe(true);
    for (const changed of [{ ...request, scriptHashes: [id, id] }, { ...request, transactions: Array(9).fill(request.transactions[0]) },
      { ...request, transactions: [{ ...request.transactions[0], transactionHex: '00'.repeat(100001) }] }]) expect(runeHistoryRequestSchema.safeParse(changed).success).toBe(false);
  });
  it('requires a confirmed spender identity for conflicts', () => {
    expect(runeHistoryResponseSchema.safeParse({ ...response, reconciliation: [{ ...response.reconciliation[0], status: 'conflicted' }] }).success).toBe(false);
    expect(runeHistoryResponseSchema.safeParse({ ...response, reconciliation: [{ ...response.reconciliation[0], confirmedSpenderTxid: id }] }).success).toBe(false);
    expect(runeHistoryResponseSchema.safeParse({ ...response, reconciliation: [{ ...response.reconciliation[0], status: 'conflicted', confirmedSpenderTxid: id, conflictedAncestorTxid: other }] }).success).toBe(true);
  });
  it('rejects duplicate identities and incoherent chain tips', () => {
    expect(runeHistoryResponseSchema.safeParse({ ...response, reconciliation: Array(2).fill(response.reconciliation[0]) }).success).toBe(false);
    expect(runeHistoryResponseSchema.safeParse({ ...response, indexTip: { height: 10, hash: other } }).success).toBe(false);
  });
  it('preserves exact input/output amounts and active-chain anchor', () => {
    const effect = { txid: id, wtxid: other, anchor: { height: 10, hash: id }, rune: { id: '100:1', name: 'EXAMPLE', divisibility: 0, symbol: null },
      inputs: [{ txid: other, vout: 0, scriptPubKey: '51', amount: '100000000000000000000' }], outputs: [{ vout: 1, scriptPubKey: '51', amount: '100000000000000000000' }] };
    expect(runeVerifiedEffectSchema.parse(effect)).toEqual(effect);
    expect(runeVerifiedEffectSchema.safeParse({ ...effect, anchor: undefined }).success).toBe(false);
  });
});


it('rejects ambiguous native effect allocations before history projection', () => {
  const effect = { txid: id, wtxid: other, anchor: { height: 10, hash: id }, rune: { id: '100:1', name: 'EXAMPLE', divisibility: 0, symbol: null },
    inputs: [{ txid: other, vout: 0, scriptPubKey: '51', amount: '100' }], outputs: [{ vout: 1, scriptPubKey: '51', amount: '100' }] };
  for (const changed of [{ ...effect, inputs: [...effect.inputs, ...effect.inputs] }, { ...effect, outputs: [...effect.outputs, ...effect.outputs] },
    { ...effect, outputs: [{ ...effect.outputs[0], vout: 2 }] }, { ...effect, outputs: [{ ...effect.outputs[0], amount: '0' }] }]) {
    expect(runeVerifiedEffectSchema.safeParse(changed).success).toBe(false);
  }
  const history = { ...response, effects: [{ ...effect, status: 'confirmed', timestamp: null }] };
  expect(runeHistoryResponseSchema.safeParse(history).success).toBe(true);
  for (const changed of [{ ...effect, outputs: [{ ...effect.outputs[0], amount: '101' }] }, { ...effect, anchor: { ...effect.anchor, height: 11 } },
    { ...effect, inputs: [{ ...effect.inputs[0], amount: '340282366920938463463374607431768211455' }, { ...effect.inputs[0], vout: 1, amount: '1' }] }]) {
    expect(runeHistoryResponseSchema.safeParse({ ...history, effects: [{ ...changed, status: 'confirmed', timestamp: null }] }).success).toBe(false);
  }
});
