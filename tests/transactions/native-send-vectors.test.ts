import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import type { WalletUtxo } from '../../src/domain/classification/types';
import {
  buildNativeSendCandidate,
  resolvePayableAddress,
  type NativeSendCandidateOutcome,
} from '../../src/domain/transactions/native-send';
import type { Network } from '../../src/domain/keys/derivation';
import type { PlanDerivation } from '../../src/domain/transactions/plan';
import { buildPsbtHex } from '../../src/domain/transactions/signing';

interface VectorCase {
  name: string;
  values: Array<[string, string, string?]>;
  amountSats: string;
  sendMax: boolean;
  labels?: Record<string, string>;
  selectedOutpoints?: string[];
  expected: unknown;
}

const fixture = JSON.parse(readFileSync(
  join(import.meta.dirname, '..', '..', 'vectors', 'native-send-v1.json'),
  'utf8',
)) as {
  vectorVersion: number;
  network: Network;
  accountId: string;
  recipientAddress: string;
  inputTemplate: { scriptPubKey: string; derivation: PlanDerivation };
  changeOutput: {
    address: string;
    scriptPubKey: string;
    role: 'payment_change';
    derivation: PlanDerivation & { lane: 'payment'; chain: 1 };
  };
  addressOutcomes: Record<string, { address: string; network: Network; expected: unknown }>;
  cases: VectorCase[];
};

const eligibility = {
  freshness: { commonTip: true, heartbeatFresh: true, revisionActive: true, spendEligible: true },
  activeRevision: 'native-send-vector-revision',
  lockedOutpoints: new Set<string>(),
};

function coin(nibble: string, valueSats: bigint, protectedInput: boolean): WalletUtxo {
  return {
    outpoint: { txid: nibble.repeat(64), vout: 0 }, valueSats,
    scriptPubKey: fixture.inputTemplate.scriptPubKey, accountId: fixture.accountId,
    account: 0, lane: 'payment', chain: 0,
    addressIndex: 0, height: 1, walletCreatedChange: false,
    facts: {
      primaryClass: protectedInput ? 'inscribed' : 'cardinal_clean',
      inscriptions: protectedInput
        ? [{ inscriptionId: `${'e'.repeat(64)}i0`, satpoint: `${nibble.repeat(64)}:0:0` }]
        : [],
      satRanges: null, unsupportedAssetDetected: false, confidence: 'authoritative',
      classifiedTip: { height: 10, hash: 'f'.repeat(64) },
      classificationRevision: 'native-send-vector-revision',
    },
    flags: { userFrozen: false, dustQuarantined: false },
  };
}

function derivation(utxo: WalletUtxo): PlanDerivation {
  expect(utxo.scriptPubKey).toBe(fixture.inputTemplate.scriptPubKey);
  return fixture.inputTemplate.derivation;
}

function serialize(outcome: NativeSendCandidateOutcome) {
  if (!outcome.ok) return outcome;
  const psbtHex = buildPsbtHex(outcome.candidate.inputs, outcome.candidate.outputs);
  return {
    ok: true,
    candidate: {
      accountId: outcome.candidate.accountId,
      account: outcome.candidate.account,
      inputs: outcome.candidate.inputs.map((input) => ({
        outpoint: `${input.txid}:${input.vout}`, valueSats: input.valueSats.toString(),
        sequence: input.sequence, sighash: input.sighash, ownership: input.ownership,
        path: input.derivation?.path ?? null, primaryClass: input.classification.primaryClass,
      })),
      outputs: outcome.candidate.outputs.map((output) => ({
        address: output.address, scriptPubKey: output.scriptPubKey,
        valueSats: output.valueSats.toString(), role: output.role,
      })),
      feeSats: outcome.candidate.feeSats.toString(), vsize: outcome.candidate.vsize.toString(),
      protectedSatFlow: outcome.candidate.protectedSatFlow, rbf: outcome.candidate.rbf,
      parentTxid: outcome.candidate.parentTxid, replacesTxid: outcome.candidate.replacesTxid,
      psbtHex,
      psbtHash: createHash('sha256').update(Buffer.from(psbtHex, 'hex')).digest('hex'),
    },
  };
}

describe('M2m native-send compatibility vectors', () => {
  it('pins every address-domain outcome', () => {
    expect(fixture.vectorVersion).toBe(1);
    for (const vector of Object.values(fixture.addressOutcomes)) {
      expect(resolvePayableAddress(vector.address, vector.network)).toEqual(vector.expected);
    }
  });

  for (const vector of fixture.cases) {
    it(`replays ${vector.name}`, () => {
      const resolved = resolvePayableAddress(fixture.recipientAddress, fixture.network);
      if (!resolved.ok) throw new Error('vector recipient did not resolve');
      const outcome = buildNativeSendCandidate({
        recipient: resolved.value,
        amountSats: BigInt(vector.amountSats),
        sendMax: vector.sendMax,
        accountId: fixture.accountId,
        account: 0,
        utxos: vector.values.map(([nibble, value, kind]) =>
          coin(nibble, BigInt(value), kind === 'protected')),
        eligibility,
        feeRate: 2_000n,
        changeOutput: fixture.changeOutput,
        deriveInput: derivation,
        ...(vector.labels ? { labelGroupByOutpoint: new Map(Object.entries(vector.labels)) } : {}),
        ...(vector.selectedOutpoints
          ? { selectedOutpoints: new Set(vector.selectedOutpoints) }
          : {}),
      });
      expect(serialize(outcome)).toEqual(vector.expected);
    });
  }
});
