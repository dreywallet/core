import { z } from 'zod';
import { signedEnvelopeFieldsSchema, outpointSchema, hexIdSchema } from '../gateway/contract';
import { outpointKey, type WalletUtxo } from '../classification/types';
import { parseRuneAtomic, parseRuneId } from './amounts';

const U128_MAX = (1n << 128n) - 1n;
export const runeAtomicSchema = z.string().max(39).refine((value) => {
  try { parseRuneAtomic(value); return true; } catch { return false; }
}, 'invalid atomic Rune quantity');
export const runeIdSchema = z.string().max(31).refine((value) => {
  try { parseRuneId(value); return true; } catch { return false; }
}, 'invalid Rune ID');
export const runeBalanceSchema = z.object({
  id: runeIdSchema,
  name: z.string().min(1).max(128).regex(/^[A-Z]+(?:•[A-Z]+)*$/u),
  amount: runeAtomicSchema.refine((value) => value !== '0'),
  divisibility: z.number().int().min(0).max(38),
  symbol: z.string().max(2).nullable(),
}).strict();
export type RuneBalance = z.infer<typeof runeBalanceSchema>;
export const runeOutputSchema = outpointSchema.extend({
  scriptPubKey: z.string().min(2).max(20000).regex(/^(?:[0-9a-f]{2})+$/u),
  valueSats: z.string().max(16).regex(/^[1-9][0-9]*$/u),
  confirmations: z.number().int().nonnegative().safe(),
  complete: z.boolean(),
  balances: z.array(runeBalanceSchema).max(128),
}).strict().superRefine((output, ctx) => {
  if (new Set(output.balances.map((balance) => balance.id)).size !== output.balances.length ||
      (!output.complete && output.balances.length !== 0)) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, message: 'invalid Rune evidence partition' });
  }
});
export type RuneOutput = z.infer<typeof runeOutputSchema>;
export const runeOutputsRequestSchema = z.object({
  network: z.enum(['mainnet', 'signet', 'regtest']),
  outpoints: z.array(outpointSchema).max(200),
}).strict().refine((request) => new Set(request.outpoints.map(outpointKey)).size === request.outpoints.length);
export type RuneOutputsRequest = z.infer<typeof runeOutputsRequestSchema>;
export const runeOutputsResponseSchema = signedEnvelopeFieldsSchema.extend({
  protocolVersion: z.literal(2),
  runeProtocol: z.literal('ord-0.27.1/native-v1'),
  outputs: z.array(runeOutputSchema).max(200),
  unknownOutpoints: z.array(outpointSchema).max(200),
}).strict().superRefine((response, ctx) => {
  const keys = [...response.outputs, ...response.unknownOutpoints].map(outpointKey);
  if (keys.length > 200 || new Set(keys).size !== keys.length ||
      response.coreTip.hash !== response.indexTip.hash || response.coreTip.height !== response.indexTip.height) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, message: 'incoherent Rune evidence' });
  }
});
export type RuneOutputsResponse = z.infer<typeof runeOutputsResponseSchema>;
export interface RuneEvidenceContext {
  network: 'mainnet' | 'signet' | 'regtest';
  accountId: string;
  instanceId: string;
  classificationRevision: string;
  tip: { height: number; hash: string };
  nowMs: number;
  scanComplete: boolean;
  reservedOutpoints: ReadonlySet<string>;
}
export type RuneUnavailableReason = 'wrong_role' | 'pending' | 'reserved' | 'frozen' | 'mixed_assets' | 'incomplete';
export interface RuneHolding extends RuneBalance {
  total: string;
  available: string;
  reserved: string;
  constrained: Array<{ reason: RuneUnavailableReason; amount: string }>;
}
const bindings = new WeakMap<object, { identity: string; boundAt: number; expiresAt: number; contents: string }>();
function evidenceIdentity(context: RuneEvidenceContext): string {
  return JSON.stringify([context.network, context.accountId, context.instanceId,
    context.classificationRevision, context.tip.height, context.tip.hash]);
}
/** A verified map is ephemeral authority; reconstruct it from signed responses
 * after restart or expiry. Mutation also invalidates its binding. */
export function assertBoundRuneEvidence(evidence: ReadonlyMap<string, RuneOutput>, context: RuneEvidenceContext): void {
  const binding = bindings.get(evidence);
  if (!binding || !context.scanComplete || binding.identity !== evidenceIdentity(context) ||
      !Number.isSafeInteger(context.nowMs) || context.nowMs < binding.boundAt || context.nowMs > binding.expiresAt ||
      JSON.stringify([...evidence]) !== binding.contents) throw new Error('Rune evidence authority expired or changed');
}
/** Only call after envelope signature verification. Joins every requested output,
 * including non-runic outputs, so truncated evidence cannot authorize selection. */
export function bindRuneEvidence(
  utxos: readonly WalletUtxo[], responses: readonly RuneOutputsResponse[], context: RuneEvidenceContext,
): ReadonlyMap<string, RuneOutput> {
  if (!context.scanComplete || !Number.isSafeInteger(context.nowMs) ||
      !context.accountId.startsWith(`acct_${context.network}_`) || utxos.length > 10_000 ||
      responses.length < 1 || responses.length > 50) throw new Error('incomplete Rune scan');
  const expected = new Map(utxos.map((utxo) => [outpointKey(utxo.outpoint), utxo]));
  if (expected.size !== utxos.length || utxos.some((utxo) => utxo.accountId !== context.accountId)) throw new Error('Rune account mismatch');
  const result = new Map<string, RuneOutput>();
  for (const raw of responses) {
    const response = runeOutputsResponseSchema.parse(raw);
    const age = context.nowMs - Date.parse(response.timestamp);
    if (age < -30_000 || age > 30_000 || response.network !== context.network ||
        response.instanceId !== context.instanceId || response.classificationRevision !== context.classificationRevision ||
        response.coreTip.hash !== context.tip.hash || response.coreTip.height !== context.tip.height ||
        response.unknownOutpoints.length !== 0) throw new Error('stale or incomplete Rune evidence');
    for (const output of response.outputs) {
      const key = outpointKey(output); const utxo = expected.get(key);
      if (!utxo || result.has(key) || output.scriptPubKey !== utxo.scriptPubKey ||
          BigInt(output.valueSats) !== utxo.valueSats || !output.complete ||
          (utxo.height === null ? output.confirmations !== 0 : output.confirmations !== context.tip.height - utxo.height + 1)) {
        throw new Error('Rune output binding mismatch');
      }
      if (utxo.height !== null && (utxo.facts === null || utxo.facts.confidence !== 'authoritative' ||
          utxo.facts.classifiedTip.hash !== context.tip.hash || utxo.facts.classifiedTip.height !== context.tip.height ||
          utxo.facts.classificationRevision !== context.classificationRevision ||
          utxo.facts.unsupportedAssetDetected !== (output.balances.length > 0))) throw new Error('Rune classification mismatch');
      result.set(key, output);
    }
  }
  if (result.size !== expected.size) throw new Error('incomplete Rune evidence');
  bindings.set(result, { identity: evidenceIdentity(context), boundAt: context.nowMs,
    expiresAt: Math.min(context.nowMs + 30_000, ...responses.map((response) => Date.parse(response.timestamp) + 30_000)),
    contents: JSON.stringify([...result]) });
  return result;
}
export function runeInputUnavailable(
  utxo: WalletUtxo, evidence: RuneOutput, runeId: string, reserved: ReadonlySet<string>,
): RuneUnavailableReason | null {
  if (!evidence.complete || !utxo.facts || utxo.facts.confidence !== 'authoritative') return 'incomplete';
  if (utxo.height === null || evidence.confirmations < 1) return 'pending';
  if (reserved.has(outpointKey(utxo.outpoint))) return 'reserved';
  if (utxo.flags.userFrozen || utxo.flags.dustQuarantined) return 'frozen';
  if (utxo.lane !== 'ordinals') return 'wrong_role';
  const facts = utxo.facts;
  if (evidence.balances.length !== 1 || evidence.balances[0]?.id !== runeId ||
      facts.primaryClass !== 'runic_or_unsupported' || !facts.unsupportedAssetDetected ||
      facts.inscriptions.length !== 0 || facts.satRanges === null || facts.satRanges.length === 0 ||
      facts.satRanges.some((range) => range.rarity !== 'common' || !/^(0|[1-9][0-9]*)$/u.test(range.start) ||
        !/^(0|[1-9][0-9]*)$/u.test(range.end) || BigInt(range.end) <= BigInt(range.start)) ||
      facts.satRanges.reduce((total, range) => total + BigInt(range.end) - BigInt(range.start), 0n) !== utxo.valueSats) return 'mixed_assets';
  return null;
}
export function projectRuneHoldings(
  utxos: readonly WalletUtxo[], evidence: ReadonlyMap<string, RuneOutput>, reserved: ReadonlySet<string>,
): RuneHolding[] {
  const holdings = new Map<string, RuneHolding>();
  for (const utxo of utxos) {
    const output = evidence.get(outpointKey(utxo.outpoint));
    if (!output) throw new Error('missing Rune output');
    for (const balance of output.balances) {
      let holding = holdings.get(balance.id);
      if (!holding) {
        holding = { ...balance, total: '0', available: '0', reserved: '0', constrained: [] };
        holdings.set(balance.id, holding);
      }
      if (holding.name !== balance.name || holding.divisibility !== balance.divisibility || holding.symbol !== balance.symbol) throw new Error('Rune metadata disagreement');
      const total = BigInt(holding.total) + BigInt(balance.amount);
      if (total > U128_MAX) throw new Error('Rune balance overflow');
      holding.total = total.toString(); holding.amount = holding.total;
      const reason = runeInputUnavailable(utxo, output, balance.id, reserved);
      if (reason === null) holding.available = (BigInt(holding.available) + BigInt(balance.amount)).toString();
      else {
        if (reason === 'reserved') holding.reserved = (BigInt(holding.reserved) + BigInt(balance.amount)).toString();
        const item = holding.constrained.find((item) => item.reason === reason);
        if (item) item.amount = (BigInt(item.amount) + BigInt(balance.amount)).toString();
        else holding.constrained.push({ reason, amount: balance.amount });
      }
    }
  }
  return [...holdings.values()].sort((a, b) => a.name.localeCompare(b.name) || a.id.localeCompare(b.id));
}
// Explicitly exported for request/response identity consumers.
export const runeTxidSchema = hexIdSchema;

const runeTransactionIdentitySchema = z.object({
  txid: hexIdSchema, wtxid: hexIdSchema,
  transactionHex: z.string().max(200000).regex(/^(?:[0-9a-f]{2})+$/u),
}).strict();
export const runeHistoryRequestSchema = z.object({
  network: z.enum(['mainnet', 'signet', 'regtest']),
  scriptHashes: z.array(hexIdSchema).min(1).max(200),
  transactions: z.array(runeTransactionIdentitySchema).max(8),
}).strict().refine((request) => new Set(request.scriptHashes).size === request.scriptHashes.length &&
  new Set(request.transactions.map((tx) => tx.txid)).size === request.transactions.length);
export type RuneHistoryRequest = z.infer<typeof runeHistoryRequestSchema>;
export const runeVerifiedEffectSchema = z.object({
  anchor: z.object({ height: z.number().int().nonnegative().safe(), hash: hexIdSchema }).strict(),
  txid: hexIdSchema, wtxid: hexIdSchema,
  rune: runeBalanceSchema.omit({ amount: true }),
  inputs: z.array(outpointSchema.extend({ scriptPubKey: z.string().max(20000).regex(/^(?:[0-9a-f]{2})+$/u), amount: runeAtomicSchema })).min(1).max(128)
    .refine((inputs) => new Set(inputs.map(outpointKey)).size === inputs.length),
  outputs: z.array(z.object({ vout: z.number().int().min(1).max(2), scriptPubKey: z.string().max(20000).regex(/^(?:[0-9a-f]{2})+$/u), amount: runeAtomicSchema.refine((amount) => amount !== '0') })).min(1).max(2)
    .refine((outputs) => outputs.some((output) => output.vout === 1) && new Set(outputs.map((output) => output.vout)).size === outputs.length),
}).strict();
export type RuneVerifiedEffect = z.infer<typeof runeVerifiedEffectSchema>;
export const runeHistoryResponseSchema = signedEnvelopeFieldsSchema.extend({
  protocolVersion: z.literal(2), runeProtocol: z.literal('ord-0.27.1/native-v1'),
  requestedScriptHashes: z.array(hexIdSchema).min(1).max(200),
  historyComplete: z.boolean(),
  receipts: z.array(outpointSchema.extend({ rune: runeBalanceSchema, scriptPubKey: z.string().max(20000).regex(/^(?:[0-9a-f]{2})+$/u), timestamp: z.string().datetime().nullable() })).max(1000),
  effects: z.array(runeVerifiedEffectSchema.extend({ status: z.enum(['confirmed', 'pending']), timestamp: z.string().datetime().nullable() })).max(1000),
  reconciliation: z.array(z.object({ txid: hexIdSchema, wtxid: hexIdSchema,
    status: z.enum(['confirmed', 'pending', 'conflicted', 'indeterminate']), confirmedSpenderTxid: hexIdSchema.nullable(), conflictedAncestorTxid: hexIdSchema.nullable(),
  }).strict()).max(8),
}).strict().superRefine((response, ctx) => {
  if (new Set(response.requestedScriptHashes).size !== response.requestedScriptHashes.length ||
      new Set(response.effects.map((effect) => effect.txid)).size !== response.effects.length ||
      new Set(response.receipts.map((receipt) => `${outpointKey(receipt)}:${receipt.rune.id}`)).size !== response.receipts.length ||
      new Set(response.reconciliation.map((tx) => tx.txid)).size !== response.reconciliation.length ||
      response.reconciliation.some((tx) => (tx.status === 'conflicted') !== (tx.confirmedSpenderTxid !== null) || (tx.status !== 'conflicted' && tx.conflictedAncestorTxid !== null)) ||
      response.effects.some((effect) => {
        try {
          const input = effect.inputs.reduce((sum, item) => sum + parseRuneAtomic(item.amount), 0n);
          const output = effect.outputs.reduce((sum, item) => sum + parseRuneAtomic(item.amount), 0n);
          return input > U128_MAX || input !== output || effect.anchor.height > response.coreTip.height;
        } catch { return true; }
      }) ||
      response.coreTip.hash !== response.indexTip.hash || response.coreTip.height !== response.indexTip.height) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, message: 'incoherent Rune history evidence' });
  }
});
export type RuneHistoryResponse = z.infer<typeof runeHistoryResponseSchema>;
