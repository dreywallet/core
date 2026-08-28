import { describe, expect, it } from 'vitest';
import {
  analyzePsbtInputCommitment,
  PsbtCommitmentError,
} from '../../src/domain/transactions/psbt-commitment';

describe('per-input PSBT commitment analysis', () => {
  it('reports fixed DEFAULT and ALL commitments', () => {
    for (const rawSighash of [0, 1]) {
      expect(analyzePsbtInputCommitment({
        rawSighash, inputIndex: 1, inputCount: 3, outputCount: 2,
      })).toMatchObject({
        rawSighash,
        committedInputIndexes: 'all',
        mutableInputIndexes: [],
        committedOutputIndexes: 'all',
        mutableOutputIndexes: [],
        fee: 'fixed',
      });
    }
  });

  it('reports input and output mutability for NONE, SINGLE, and ANYONECANPAY', () => {
    expect(analyzePsbtInputCommitment({
      rawSighash: 2, inputIndex: 1, inputCount: 3, outputCount: 3,
    })).toMatchObject({
      outputMode: 'none', committedInputIndexes: 'all', mutableInputIndexes: [],
      committedOutputIndexes: [], mutableOutputIndexes: [0, 1, 2], fee: 'mutable',
    });
    expect(analyzePsbtInputCommitment({
      rawSighash: 3, inputIndex: 1, inputCount: 3, outputCount: 3,
    })).toMatchObject({
      outputMode: 'single', committedInputIndexes: 'all', mutableInputIndexes: [],
      committedOutputIndexes: [1], mutableOutputIndexes: [0, 2], fee: 'mutable',
    });
    expect(analyzePsbtInputCommitment({
      rawSighash: 0x81, inputIndex: 1, inputCount: 3, outputCount: 2,
    })).toMatchObject({
      anyoneCanPay: true, committedInputIndexes: [1], mutableInputIndexes: [0, 2],
      committedOutputIndexes: 'all', mutableOutputIndexes: [], fee: 'mutable',
    });
    expect(analyzePsbtInputCommitment({
      rawSighash: 0x83, inputIndex: 1, inputCount: 3, outputCount: 3,
    })).toMatchObject({
      anyoneCanPay: true, committedInputIndexes: [1], mutableInputIndexes: [0, 2],
      committedOutputIndexes: [1], mutableOutputIndexes: [0, 2], fee: 'mutable',
    });
  });

  it('rejects invalid shapes, reserved encodings, and SINGLE without its output', () => {
    for (const candidate of [
      { rawSighash: 1, inputIndex: -1, inputCount: 1, outputCount: 1 },
      { rawSighash: 1, inputIndex: 1, inputCount: 1, outputCount: 1 },
      { rawSighash: 1, inputIndex: 0, inputCount: 0, outputCount: 1 },
      { rawSighash: 1, inputIndex: 0, inputCount: 1, outputCount: -1 },
    ]) {
      expect(() => analyzePsbtInputCommitment(candidate)).toThrowError(
        expect.objectContaining<Partial<PsbtCommitmentError>>({ code: 'invalid_shape' }),
      );
    }
    for (const rawSighash of [-1, 0x04, 0x80, 0x84, 0x100]) {
      expect(() => analyzePsbtInputCommitment({
        rawSighash, inputIndex: 0, inputCount: 1, outputCount: 1,
      })).toThrowError(expect.objectContaining<Partial<PsbtCommitmentError>>({ code: 'invalid_sighash' }));
    }
    for (const rawSighash of [3, 0x83]) {
      expect(() => analyzePsbtInputCommitment({
        rawSighash, inputIndex: 1, inputCount: 2, outputCount: 1,
      })).toThrowError(expect.objectContaining<Partial<PsbtCommitmentError>>({ code: 'single_missing_output' }));
    }
  });
});
