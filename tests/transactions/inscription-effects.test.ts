import { beforeAll, describe, expect, it } from 'vitest';
import { Transaction } from '@scure/btc-signer';
import { deriveAccountNode, deriveAddress } from '../../src/domain/keys/derivation';
import { mnemonicToSeed } from '../../src/domain/keys/mnemonic';
import { scriptPubKeyHex } from '../../src/domain/keys/script-hash';
import { analyzePsbtHex } from '../../src/domain/transactions/analysis';
import { estimateVsize } from '../../src/domain/transactions/fees';
import { bytesToHex } from '../../src/domain/vault/encoding';
import { installTestCryptoProvider } from '../helpers/install-crypto-provider';

const seed = mnemonicToSeed(
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
);
const IDS = [`${'a1'.repeat(32)}i0`, `${'b2'.repeat(32)}i0`, `${'c3'.repeat(32)}i0`];

beforeAll(() => installTestCryptoProvider());

function mixedFlow(overrides: {
  badFlow?: boolean;
  externalInput?: boolean;
  partial?: 'qualified' | 'unqualified';
  feeSats?: bigint;
  guaranteedOutputIndexes?: number[];
  firstSatpoint?: string;
} = {}) {
  const feeSats = overrides.feeSats ?? 1_000n;
  const account = deriveAccountNode(seed, 'ordinals', 'signet', 0);
  const inputAddress = deriveAddress(account, 'ordinals', 'signet', 0, 0);
  const retainedAddress = deriveAddress(account, 'ordinals', 'signet', 1, 0);
  const externalAddress = deriveAddress(account, 'ordinals', 'signet', 0, 9);
  account.wipePrivateData();
  const inputScript = scriptPubKeyHex(inputAddress.publicKeyHex, 'ordinals', 'signet');
  const externalScript = scriptPubKeyHex(externalAddress.publicKeyHex, 'ordinals', 'signet');
  const retainedScript = scriptPubKeyHex(retainedAddress.publicKeyHex, 'ordinals', 'signet');
  const txid = '11'.repeat(32);
  const input = {
    txid,
    vout: 0,
    valueSats: 30_000n,
    scriptPubKey: inputScript,
    sequence: 0xfffffffd,
    sighash: 0 as const,
    ownership: overrides.externalInput ? 'external' as const : 'wallet' as const,
    derivation: overrides.externalInput ? null : {
      account: 0, lane: 'ordinals' as const, chain: 0 as const, index: 0,
      path: inputAddress.path, publicKeyHex: inputAddress.publicKeyHex,
    },
    classification: {
      primaryClass: 'mixed' as const,
      inscriptions: IDS.map((inscriptionId, index) => ({
        inscriptionId,
        satpoint: index === 0 && overrides.firstSatpoint !== undefined
          ? overrides.firstSatpoint
          : `${txid}:0:${index < 2 ? 0 : 10000}`,
      })),
      satRanges: null,
      unsupportedAssetDetected: false,
      confidence: 'authoritative' as const,
      classifiedTip: { height: 1, hash: '22'.repeat(32) },
      classificationRevision: 'rev-1',
    },
  };
  const outputs = [
    {
      valueSats: 10_000n,
      scriptPubKey: externalScript,
      address: externalAddress.address,
      role: 'postage' as const,
    },
    {
      valueSats: 30_000n - 10_000n - feeSats,
      scriptPubKey: retainedScript,
      address: retainedAddress.address,
      role: 'ordinal_change' as const,
      derivation: {
        account: 0, lane: 'ordinals' as const, chain: 1 as const, index: 0,
        path: retainedAddress.path, publicKeyHex: retainedAddress.publicKeyHex,
      },
    },
  ];
  const tx = new Transaction({ lowR: true });
  tx.addInput({
    txid,
    index: 0,
    sequence: input.sequence,
    witnessUtxo: { script: Uint8Array.from(Buffer.from(inputScript, 'hex')), amount: input.valueSats },
    sighashType: 0,
  });
  for (const output of outputs) {
    tx.addOutput({ script: Uint8Array.from(Buffer.from(output.scriptPubKey, 'hex')), amount: output.valueSats });
  }
  const flows = [
    { inputIndex: 0, inputOffset: 0n, outputIndex: 0, outputOffset: 0n, inscriptionId: IDS[0]! },
    { inputIndex: 0, inputOffset: 0n, outputIndex: 0, outputOffset: 0n, inscriptionId: IDS[1]! },
    { inputIndex: 0, inputOffset: 10_000n, outputIndex: 1, outputOffset: 0n,
      inscriptionId: overrides.badFlow ? IDS[0]! : IDS[2]! },
  ];
  const source = {
    backend: 'gateway', instanceId: 'fixture', classificationRevision: 'rev-1',
    coreTip: { height: 1, hash: '22'.repeat(32) }, indexTip: { height: 1, hash: '22'.repeat(32) },
    feeQuoteTimestamp: null, mempoolState: null,
  };
  return analyzePsbtHex(bytesToHex(tx.toPSBT()), {
    network: 'signet', account: 0,
    kind: overrides.partial ? 'marketplace_psbt' : 'provider_ordinal_transfer', source,
    inputs: [input], outputs, protectedSatFlow: flows, feeSats,
    vsize: estimateVsize([inputScript], outputs.map((output) => output.scriptPubKey)),
    feeRateSatPerKvB: 10_000n, rbf: true,
    ...(overrides.partial ? { marketplace: {
      allowedSighashesByInput: { 0: [0] },
      allowTaprootScriptPathInputIndexes: [],
      permittedProtectedInputIndexes: [0],
      commitment: {
        mode: 'partial' as const,
        selectedInputIndexes: [0],
        // The qualified case commits to both outputs. This fixture retains an
        // inscription in output 1 as well as sending two from output 0, and
        // under a partial commitment an uncommitted destination is rewritable
        // by the counterparty whichever way the inscription moves -- so [0]
        // alone described an unsafe transaction, not a qualified one.
        guaranteedOutputIndexes: overrides.guaranteedOutputIndexes ??
          (overrides.partial === 'qualified' ? [0, 1] : [1]),
        guaranteedProceedsSats: 0n,
        walletFeeExposureSats: 1_000n,
        uncommittedDimensions: ['external_inputs'],
      },
    } } : {}),
  });
}

function fifoFixture(options: {
  protectedValueSats: bigint;
  inscriptionOffsets: bigint[];
  outputValues: bigint[];
  cardinalValueSats?: bigint;
  cardinalFirst?: boolean;
  omitProtectedWitness?: boolean;
  protectedWitnessValueSats?: bigint;
}) {
  const account = deriveAccountNode(seed, 'ordinals', 'signet', 0);
  const protectedAddress = deriveAddress(account, 'ordinals', 'signet', 0, 0);
  const cardinalAddress = deriveAddress(account, 'ordinals', 'signet', 0, 1);
  const changeAddress = deriveAddress(account, 'ordinals', 'signet', 1, 0);
  const externalAddress = deriveAddress(account, 'ordinals', 'signet', 0, 9);
  account.wipePrivateData();

  const protectedScript = scriptPubKeyHex(protectedAddress.publicKeyHex, 'ordinals', 'signet');
  const cardinalScript = scriptPubKeyHex(cardinalAddress.publicKeyHex, 'ordinals', 'signet');
  const changeScript = scriptPubKeyHex(changeAddress.publicKeyHex, 'ordinals', 'signet');
  const externalScript = scriptPubKeyHex(externalAddress.publicKeyHex, 'ordinals', 'signet');
  const protectedTxid = '33'.repeat(32);
  const cardinalTxid = '44'.repeat(32);
  const classification = (primaryClass: 'cardinal_clean' | 'inscribed') => ({
    primaryClass,
    inscriptions: primaryClass === 'inscribed'
      ? options.inscriptionOffsets.map((offset, index) => ({
        inscriptionId: IDS[index]!, satpoint: `${protectedTxid}:0:${offset.toString()}`,
      }))
      : [],
    satRanges: null,
    unsupportedAssetDetected: false,
    confidence: 'authoritative' as const,
    classifiedTip: { height: 1, hash: '22'.repeat(32) },
    classificationRevision: 'rev-1',
  });
  const protectedInput = {
    txid: protectedTxid,
    vout: 0,
    valueSats: options.protectedValueSats,
    scriptPubKey: protectedScript,
    sequence: 0xfffffffd,
    sighash: 0 as const,
    ownership: 'wallet' as const,
    derivation: {
      account: 0, lane: 'ordinals' as const, chain: 0 as const, index: 0,
      path: protectedAddress.path, publicKeyHex: protectedAddress.publicKeyHex,
    },
    classification: classification('inscribed'),
  };
  const cardinalInput = options.cardinalValueSats === undefined ? null : {
    txid: cardinalTxid,
    vout: 0,
    valueSats: options.cardinalValueSats,
    scriptPubKey: cardinalScript,
    sequence: 0xfffffffd,
    sighash: 0 as const,
    ownership: 'wallet' as const,
    derivation: {
      account: 0, lane: 'ordinals' as const, chain: 0 as const, index: 1,
      path: cardinalAddress.path, publicKeyHex: cardinalAddress.publicKeyHex,
    },
    classification: classification('cardinal_clean'),
  };
  const inputs = cardinalInput === null
    ? [protectedInput]
    : options.cardinalFirst ? [cardinalInput, protectedInput] : [protectedInput, cardinalInput];
  const outputs = options.outputValues.map((valueSats, index) => index === 0 ? {
    valueSats,
    scriptPubKey: externalScript,
    address: externalAddress.address,
    role: 'postage' as const,
  } : {
    valueSats,
    scriptPubKey: changeScript,
    address: changeAddress.address,
    role: 'ordinal_change' as const,
    derivation: {
      account: 0, lane: 'ordinals' as const, chain: 1 as const, index: 0,
      path: changeAddress.path, publicKeyHex: changeAddress.publicKeyHex,
    },
  });

  const tx = new Transaction({ lowR: true });
  for (const input of inputs) {
    const omitWitness = input === protectedInput && options.omitProtectedWitness === true;
    tx.addInput({
      txid: input.txid,
      index: input.vout,
      sequence: input.sequence,
      sighashType: input.sighash,
      ...(!omitWitness ? { witnessUtxo: {
        script: Uint8Array.from(Buffer.from(input.scriptPubKey, 'hex')),
        amount: input === protectedInput
          ? options.protectedWitnessValueSats ?? input.valueSats
          : input.valueSats,
      } } : {}),
    });
  }
  for (const output of outputs) {
    tx.addOutput({ script: Uint8Array.from(Buffer.from(output.scriptPubKey, 'hex')), amount: output.valueSats });
  }

  const protectedInputIndex = inputs.indexOf(protectedInput);
  const inputStart = inputs.slice(0, protectedInputIndex)
    .reduce((sum, input) => sum + input.valueSats, 0n);
  const protectedSatFlow = options.inscriptionOffsets.flatMap((inputOffset, index) => {
    const absolutePosition = inputStart + inputOffset;
    let outputStart = 0n;
    for (let outputIndex = 0; outputIndex < outputs.length; outputIndex += 1) {
      const output = outputs[outputIndex]!;
      if (absolutePosition >= outputStart && absolutePosition < outputStart + output.valueSats) {
        return [{
          inputIndex: protectedInputIndex,
          inputOffset,
          outputIndex,
          outputOffset: absolutePosition - outputStart,
          inscriptionId: IDS[index]!,
        }];
      }
      outputStart += output.valueSats;
    }
    return [];
  });
  const inputTotal = inputs.reduce((sum, input) => sum + input.valueSats, 0n);
  const outputTotal = outputs.reduce((sum, output) => sum + output.valueSats, 0n);
  const source = {
    backend: 'gateway', instanceId: 'fixture', classificationRevision: 'rev-1',
    coreTip: { height: 1, hash: '22'.repeat(32) }, indexTip: { height: 1, hash: '22'.repeat(32) },
    feeQuoteTimestamp: null, mempoolState: null,
  };
  return analyzePsbtHex(bytesToHex(tx.toPSBT()), {
    network: 'signet', account: 0, kind: 'provider_ordinal_transfer', source,
    inputs, outputs, protectedSatFlow, feeSats: inputTotal - outputTotal,
    vsize: estimateVsize(inputs.map((input) => input.scriptPubKey),
      outputs.map((output) => output.scriptPubKey)),
    feeRateSatPerKvB: 10_000n, rbf: true,
  });
}

describe('M9P canonical inscription effects', () => {
  it('preserves co-located IDs and independently classifies a distinct FIFO offset', () => {
    const result = mixedFlow();
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.analysis.hardViolations).toEqual([]);
    expect(result.analysis.assetEffects.inscriptions.map((effect) => ({
      id: effect.inscriptionId,
      movement: effect.movement,
      group: effect.coLocationGroup,
      outputIndex: effect.outputIndex,
    }))).toEqual([
      { id: IDS[0], movement: 'sent', group: `${'11'.repeat(32)}:0:0`, outputIndex: 0 },
      { id: IDS[1], movement: 'sent', group: `${'11'.repeat(32)}:0:0`, outputIndex: 0 },
      { id: IDS[2], movement: 'retained', group: `${'11'.repeat(32)}:0:10000`, outputIndex: 1 },
    ]);
    expect(result.analysis.assetEffects.effectSetHash).toMatch(/^[0-9a-f]{64}$/u);
  });

  it('fails closed on duplicate, missing, or substituted protected flows', () => {
    const result = mixedFlow({ badFlow: true });
    expect(result.ok && result.analysis.hardViolations.map((finding) => finding.code))
      .toContain('inscription_effect_mismatch');
  });

  it('uses the canonical transaction satpoint parser during analysis', () => {
    const result = mixedFlow({ firstSatpoint: `${'11'.repeat(32)}:0:` });
    expect(result.ok && result.analysis.hardViolations).toContainEqual({
      code: 'inscription_effect_mismatch',
      inputIndex: 0,
    });
  });

  it('classifies external input delivery to verified ordinals ownership as received', () => {
    const result = mixedFlow({ externalInput: true });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.analysis.hardViolations).toEqual([]);
    expect(result.analysis.assetEffects.inscriptions.map((effect) => ({
      id: effect.inscriptionId,
      movement: effect.movement,
    }))).toEqual([{ id: IDS[2], movement: 'received' }]);
  });

  it('qualifies only output-committed recognized partial marketplace sends', () => {
    const qualified = mixedFlow({ partial: 'qualified' });
    expect(qualified.ok).toBe(true);
    if (qualified.ok) {
      expect(qualified.analysis.hardViolations).toEqual([]);
      expect(qualified.analysis.assetEffects.inscriptions.slice(0, 2)
        .every((effect) => effect.qualifiedPartialAuthorization)).toBe(true);
    }
    const unqualified = mixedFlow({ partial: 'unqualified' });
    expect(unqualified.ok && unqualified.analysis.hardViolations.map((finding) => finding.code))
      .toContain('inscription_effect_mismatch');
  });

  it('refuses a partial commitment that retains an inscription in an uncommitted output', () => {
    // A seller signing SINGLE|ACP commits to one output. A second inscription at
    // a higher sat offset flows by FIFO into a later wallet-owned output the
    // signature does not cover, so the counterparty can redirect it while the
    // signature stays valid. Reporting that as a safe retention is the bug.
    const uncommitted = mixedFlow({ partial: 'qualified', guaranteedOutputIndexes: [0] });
    expect(uncommitted.ok).toBe(true);
    if (uncommitted.ok) {
      expect(uncommitted.analysis.hardViolations).toContainEqual({
        code: 'inscription_effect_mismatch', inputIndex: 0, outputIndex: 1,
      });
    }

    // Committing to that output is what makes the same movement legitimate.
    const committed = mixedFlow({ partial: 'qualified', guaranteedOutputIndexes: [0, 1] });
    expect(committed.ok && committed.analysis.hardViolations).toEqual([]);
  });

  it('does not call postage a high relative fee', () => {
    // Postage carries the inscription; it is not the principal being sent. At a
    // 2,500-sat fee against 10,000 sats of postage the ratio trips, and it would
    // fire on ordinary transfers if the kind were not excluded.
    const ordinal = mixedFlow({ feeSats: 2_500n });
    expect(ordinal.ok).toBe(true);
    if (ordinal.ok) {
      expect(ordinal.analysis.hardViolations).toEqual([]);
      expect(ordinal.analysis.warnings.map((warning) => warning.code))
        .not.toContain('high_relative_fee');
    }
  });

  it('accepts the final output sat and hard-stops the first fee-tail sat', () => {
    const finalOutputSat = fifoFixture({
      protectedValueSats: 12_000n, inscriptionOffsets: [9_999n], outputValues: [10_000n],
    });
    expect(finalOutputSat.ok).toBe(true);
    if (finalOutputSat.ok) {
      expect(finalOutputSat.analysis.hardViolations).toEqual([]);
      expect(finalOutputSat.analysis.assetEffects.inscriptions[0]).toMatchObject({
        inputOffset: 9_999n, outputIndex: 0, outputOffset: 9_999n,
      });
    }

    const firstFeeSat = fifoFixture({
      protectedValueSats: 12_000n, inscriptionOffsets: [10_000n], outputValues: [10_000n],
    });
    expect(firstFeeSat.ok && firstFeeSat.analysis.hardViolations.map(({ code }) => code))
      .toEqual(expect.arrayContaining(['protected_asset_misuse', 'inscription_effect_mismatch']));
  });

  it('maps multiple inscriptions independently across an output boundary', () => {
    const result = fifoFixture({
      protectedValueSats: 12_000n,
      inscriptionOffsets: [9_999n, 10_000n],
      outputValues: [10_000n, 1_000n],
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.analysis.hardViolations).toEqual([]);
    expect(result.analysis.assetEffects.inscriptions.map((effect) => ({
      id: effect.inscriptionId, outputIndex: effect.outputIndex, outputOffset: effect.outputOffset,
    }))).toEqual([
      { id: IDS[0], outputIndex: 0, outputOffset: 9_999n },
      { id: IDS[1], outputIndex: 1, outputOffset: 0n },
    ]);
  });

  it('accounts for mixed-input ordering when deriving absolute sat positions', () => {
    const protectedFirst = fifoFixture({
      protectedValueSats: 10_000n, cardinalValueSats: 5_000n, cardinalFirst: false,
      inscriptionOffsets: [0n], outputValues: [10_000n, 4_000n],
    });
    const cardinalFirst = fifoFixture({
      protectedValueSats: 10_000n, cardinalValueSats: 5_000n, cardinalFirst: true,
      inscriptionOffsets: [0n], outputValues: [10_000n, 4_000n],
    });
    expect(protectedFirst.ok && protectedFirst.analysis.hardViolations).toEqual([]);
    expect(cardinalFirst.ok && cardinalFirst.analysis.hardViolations).toEqual([]);
    expect(protectedFirst.ok && protectedFirst.analysis.assetEffects.inscriptions[0]?.outputOffset).toBe(0n);
    expect(cardinalFirst.ok && cardinalFirst.analysis.assetEffects.inscriptions[0]?.outputOffset).toBe(5_000n);
  });

  it('fails closed when protected-input prevout metadata is absent or mismatched', () => {
    const absent = fifoFixture({
      protectedValueSats: 12_000n, inscriptionOffsets: [0n], outputValues: [10_000n],
      omitProtectedWitness: true,
    });
    expect(!absent.ok || absent.analysis.hardViolations.length > 0).toBe(true);
    if (absent.ok) {
      expect(absent.analysis.hardViolations.map(({ code }) => code)).toContain('prevout_mismatch');
    }

    const mismatched = fifoFixture({
      protectedValueSats: 12_000n, inscriptionOffsets: [0n], outputValues: [10_000n],
      protectedWitnessValueSats: 11_999n,
    });
    expect(mismatched.ok && mismatched.analysis.hardViolations.map(({ code }) => code))
      .toContain('prevout_mismatch');
  });
});
