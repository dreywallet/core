import { beforeAll, describe, expect, it } from 'vitest';
import { deriveAccountNode, deriveAddress } from '../../src/domain/keys/derivation';
import { mnemonicToSeed } from '../../src/domain/keys/mnemonic';
import { scriptPubKeyHex } from '../../src/domain/keys/script-hash';
import { installTestCryptoProvider } from '../helpers/install-crypto-provider';
import {
  analyzePsbtHex,
  decodeSighash,
  type TransactionAnalysisContext,
} from '../../src/domain/transactions/analysis';
import { buildPsbtHex } from '../../src/domain/transactions/signing';

const seed = mnemonicToSeed('abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about');

beforeAll(async () => { await installTestCryptoProvider(); });

function fixture(overrides: { revision?: string; primaryClass?: 'cardinal_clean' | 'inscribed'; sequence?: number } = {}) {
  const account = deriveAccountNode(seed, 'payment', 'signet', 0);
  try {
    const receive = deriveAddress(account, 'payment', 'signet', 0, 0);
    const change = deriveAddress(account, 'payment', 'signet', 1, 0);
    const input = {
      txid: '1'.repeat(64), vout: 0, valueSats: 100_000n,
      scriptPubKey: scriptPubKeyHex(receive.publicKeyHex, 'payment', 'signet'),
      sequence: overrides.sequence ?? 0xfffffffd, sighash: 1 as const,
      derivation: { account: 0, lane: 'payment' as const, chain: 0 as const, index: 0,
        path: receive.path, publicKeyHex: receive.publicKeyHex },
      classification: {
        primaryClass: overrides.primaryClass ?? 'cardinal_clean',
        inscriptions: overrides.primaryClass === 'inscribed'
          ? [{ inscriptionId: 'i0', satpoint: `${'1'.repeat(64)}:0:0` }]
          : [],
        satRanges: null, unsupportedAssetDetected: false, confidence: 'authoritative' as const,
        classifiedTip: { height: 1, hash: '2'.repeat(64) },
        classificationRevision: overrides.revision ?? 'rev-1',
      },
    };
    const output = {
      valueSats: 99_000n,
      scriptPubKey: scriptPubKeyHex(change.publicKeyHex, 'payment', 'signet'),
      address: change.address, role: 'payment_change' as const,
      derivation: { account: 0, lane: 'payment' as const, chain: 1 as const, index: 0,
        path: change.path, publicKeyHex: change.publicKeyHex },
    };
    const source = {
      backend: 'gateway', instanceId: 'fixture', classificationRevision: 'rev-1',
      coreTip: { height: 1, hash: '2'.repeat(64) }, indexTip: { height: 1, hash: '2'.repeat(64) },
      feeQuoteTimestamp: null, mempoolState: null,
    };
    return {
      psbtHex: buildPsbtHex([input], [output]),
      context: { network: 'signet' as const, account: 0, kind: 'native_send' as const, source,
        inputs: [input], outputs: [output], protectedSatFlow: [], feeSats: 1_000n,
        vsize: 110n, feeRateSatPerKvB: 5_000n, rbf: true },
    };
  } finally {
    account.wipePrivateData();
  }
}

describe('M7H transaction analysis', () => {
  it('decodes the complete output-mask and ANYONECANPAY matrix', () => {
    expect([
      decodeSighash(0x00, 1, 3), decodeSighash(0x01, 1, 3),
      decodeSighash(0x02, 1, 3), decodeSighash(0x03, 1, 3),
      decodeSighash(0x80, 1, 3), decodeSighash(0x81, 1, 3),
      decodeSighash(0x82, 1, 3), decodeSighash(0x83, 1, 3),
    ].map(({ outputMode, anyoneCanPay, committedOutputIndexes, validEncoding }) =>
      ({ outputMode, anyoneCanPay, committedOutputIndexes, validEncoding }))).toEqual([
      { outputMode: 'default', anyoneCanPay: false, committedOutputIndexes: 'all', validEncoding: true },
      { outputMode: 'all', anyoneCanPay: false, committedOutputIndexes: 'all', validEncoding: true },
      { outputMode: 'none', anyoneCanPay: false, committedOutputIndexes: [], validEncoding: true },
      { outputMode: 'single', anyoneCanPay: false, committedOutputIndexes: [1], validEncoding: true },
      { outputMode: 'default', anyoneCanPay: true, committedOutputIndexes: 'all', validEncoding: true },
      { outputMode: 'all', anyoneCanPay: true, committedOutputIndexes: 'all', validEncoding: true },
      { outputMode: 'none', anyoneCanPay: true, committedOutputIndexes: [], validEncoding: true },
      { outputMode: 'single', anyoneCanPay: true, committedOutputIndexes: [1], validEncoding: true },
    ]);
    expect(decodeSighash(0x04, 0, 0).validEncoding).toBe(false);
  });

  it('returns a deeply immutable canonical analysis for a safe plan', () => {
    const value = fixture();
    const first = analyzePsbtHex(value.psbtHex, value.context);
    const second = analyzePsbtHex(value.psbtHex, value.context);
    expect(first).toEqual(second);
    expect(first.ok).toBe(true);
    if (!first.ok) return;
    expect(first.analysis.hardViolations).toEqual([]);
    expect(Object.isFrozen(first.analysis)).toBe(true);
    expect(Object.isFrozen(first.analysis.inputs[0]?.classification)).toBe(true);
    expect(Object.isFrozen(value.context.source)).toBe(false);
    expect(Object.isFrozen(value.context.inputs[0]?.classification)).toBe(false);
  });

  it('hard-rejects asset-bearing, stale-classification, and declared-RBF mismatches', () => {
    const unsafe = fixture({ primaryClass: 'inscribed' });
    const unsafeResult = analyzePsbtHex(unsafe.psbtHex, unsafe.context);
    expect(unsafeResult.ok && unsafeResult.analysis.hardViolations.map(({ code }) => code))
      .toContain('unsafe_input_classification');

    const stale = fixture({ revision: 'rev-old' });
    const staleResult = analyzePsbtHex(stale.psbtHex, stale.context);
    expect(staleResult.ok && staleResult.analysis.hardViolations.map(({ code }) => code))
      .toContain('classification_revision_mismatch');

    const final = fixture({ sequence: 0xffffffff });
    const rbfResult = analyzePsbtHex(final.psbtHex, final.context);
    expect(rbfResult.ok && rbfResult.analysis.hardViolations.map(({ code }) => code))
      .toContain('rbf_mismatch');
  });

  it('never permits native plans to opt out of wallet ownership proof', () => {
    const value = fixture();
    const lied = structuredClone(value.context) as TransactionAnalysisContext;
    lied.inputs[0]!.ownership = 'external';
    lied.inputs[0]!.derivation = null;
    const result = analyzePsbtHex(value.psbtHex, lied);
    expect(result.ok && result.analysis.hardViolations.map(({ code }) => code))
      .toContain('ownership_mismatch');
  });
});
