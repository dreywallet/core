import { describe, expect, it } from 'vitest';
import { SigHash, Transaction } from '@scure/btc-signer';
import { validateProviderPsbtSighashDeclarations } from '../../src/domain/transactions/provider-psbt-sighash';
import { bytesToBase64, hexToBytes } from '../../src/domain/vault/encoding';

const PAYMENT = `0014${'11'.repeat(20)}`;
const TAPROOT = `5120${'22'.repeat(32)}`;

function psbt(inputs: Array<{ script: string; sighash?: number }>, outputCount = inputs.length): string {
  const tx = new Transaction({ lowR: true });
  inputs.forEach((input, index) => tx.addInput({
    txid: index.toString(16).padStart(64, '0'),
    index: 0,
    witnessUtxo: { amount: 10_000n, script: hexToBytes(input.script) },
    ...(input.sighash === undefined ? {} : { sighashType: input.sighash }),
  }));
  for (let index = 0; index < outputCount; index += 1) {
    tx.addOutput({ amount: 9_000n, script: hexToBytes(PAYMENT) });
  }
  return bytesToBase64(tx.toPSBT());
}

describe('provider PSBT callback sighash declarations', () => {
  it('checks declarations and returns exact commitment facts in declaration order', () => {
    const analyses = validateProviderPsbtSighashDeclarations({
      psbtBase64: psbt([
        { script: PAYMENT, sighash: SigHash.ALL_ANYONECANPAY },
        { script: PAYMENT, sighash: SigHash.SINGLE },
      ]),
      declarations: [
        { signingIndexes: [1], sigHash: SigHash.SINGLE },
        { signingIndexes: [0], sigHash: SigHash.ALL_ANYONECANPAY },
      ],
    });
    expect(analyses.map((analysis) => analysis.inputIndex)).toEqual([1, 0]);
    expect(analyses[0]).toMatchObject({
      rawSighash: SigHash.SINGLE,
      explicitSighash: true,
      declaredSighash: SigHash.SINGLE,
      committedOutputIndexes: [1],
    });
    expect(analyses[1]).toMatchObject({
      rawSighash: SigHash.ALL_ANYONECANPAY,
      anyoneCanPay: true,
      committedInputIndexes: [0],
    });
  });

  it('resolves consensus defaults when the PSBT omits sighashType', () => {
    const analyses = validateProviderPsbtSighashDeclarations({
      psbtBase64: psbt([{ script: PAYMENT }, { script: TAPROOT }]),
      declarations: [{ signingIndexes: [0], sigHash: SigHash.ALL }, { signingIndexes: [1] }],
    });
    expect(analyses).toMatchObject([
      { rawSighash: SigHash.ALL, explicitSighash: false, declaredSighash: SigHash.ALL },
      { rawSighash: SigHash.DEFAULT, explicitSighash: false, declaredSighash: undefined },
    ]);
  });

  it('rejects mismatches, duplicate or invalid indexes, and malformed SINGLE', () => {
    const ordinary = psbt([{ script: PAYMENT, sighash: SigHash.ALL }]);
    expect(() => validateProviderPsbtSighashDeclarations({
      psbtBase64: ordinary,
      declarations: [{ signingIndexes: [0], sigHash: SigHash.SINGLE }],
    })).toThrow(/differs from the PSBT input/u);
    expect(() => validateProviderPsbtSighashDeclarations({
      psbtBase64: ordinary,
      declarations: [{ signingIndexes: [0] }, { signingIndexes: [0] }],
    })).toThrow(/invalid or duplicated/u);
    expect(() => validateProviderPsbtSighashDeclarations({
      psbtBase64: ordinary,
      declarations: [{ signingIndexes: [1] }],
    })).toThrow(/invalid or duplicated/u);

    const malformedSingle = psbt([
      { script: PAYMENT, sighash: SigHash.ALL },
      { script: PAYMENT, sighash: SigHash.SINGLE },
    ], 1);
    expect(() => validateProviderPsbtSighashDeclarations({
      psbtBase64: malformedSingle,
      declarations: [{ signingIndexes: [1], sigHash: SigHash.SINGLE }],
    })).toThrow(/SINGLE without a corresponding output/u);
  });
});
