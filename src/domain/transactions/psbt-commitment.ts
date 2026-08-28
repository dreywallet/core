export type SighashOutputMode = 'default' | 'all' | 'none' | 'single';

export interface SighashAnalysis {
  raw: number;
  outputMode: SighashOutputMode;
  anyoneCanPay: boolean;
  committedOutputIndexes: number[] | 'all';
  validEncoding: boolean;
}

export type PsbtCommitmentErrorCode =
  | 'invalid_shape'
  | 'invalid_sighash'
  | 'single_missing_output';

export class PsbtCommitmentError extends Error {
  constructor(readonly code: PsbtCommitmentErrorCode, message: string) {
    super(message);
    this.name = 'PsbtCommitmentError';
  }
}

export interface PsbtInputCommitmentAnalysis {
  inputIndex: number;
  rawSighash: number;
  outputMode: SighashOutputMode;
  anyoneCanPay: boolean;
  committedInputIndexes: number[] | 'all';
  mutableInputIndexes: number[];
  committedOutputIndexes: number[] | 'all';
  mutableOutputIndexes: number[];
  fee: 'fixed' | 'mutable';
}

function indexes(length: number): number[] {
  return Array.from({ length }, (_value, index) => index);
}

/** Decode the consensus sighash mask without applying a signing policy. */
export function decodeSighash(raw: number, inputIndex: number, outputCount: number): SighashAnalysis {
  const anyoneCanPay = (raw & 0x80) !== 0;
  const base = raw & 0x03;
  // 0x80 is reserved: ANYONECANPAY cannot be combined with Taproot DEFAULT.
  const validEncoding = Number.isInteger(raw) && raw >= 0 && raw <= 0xff &&
    (raw & ~0x83) === 0 && raw !== 0x80;
  const outputMode: SighashOutputMode = base === 0 ? 'default' : base === 1 ? 'all' : base === 2 ? 'none' : 'single';
  const committedOutputIndexes =
    outputMode === 'default' || outputMode === 'all'
      ? 'all'
      : outputMode === 'none'
        ? []
        : inputIndex < outputCount
          ? [inputIndex]
          : [];
  return { raw, outputMode, anyoneCanPay, committedOutputIndexes, validEncoding };
}

/**
 * Describe exactly what one prospective signature commits to. Unlike the
 * compatibility decoder above, this is a policy boundary: malformed shapes,
 * reserved encodings, and SINGLE without its corresponding output are errors.
 */
export function analyzePsbtInputCommitment(input: {
  rawSighash: number;
  inputIndex: number;
  inputCount: number;
  outputCount: number;
}): PsbtInputCommitmentAnalysis {
  if (!Number.isSafeInteger(input.inputCount) || input.inputCount <= 0 ||
      !Number.isSafeInteger(input.outputCount) || input.outputCount < 0 ||
      !Number.isSafeInteger(input.inputIndex) || input.inputIndex < 0 ||
      input.inputIndex >= input.inputCount) {
    throw new PsbtCommitmentError('invalid_shape', 'PSBT commitment indexes are invalid');
  }
  const decoded = decodeSighash(input.rawSighash, input.inputIndex, input.outputCount);
  if (!decoded.validEncoding) {
    throw new PsbtCommitmentError('invalid_sighash', 'PSBT input uses an invalid sighash encoding');
  }
  if (decoded.outputMode === 'single' && decoded.committedOutputIndexes.length === 0) {
    throw new PsbtCommitmentError(
      'single_missing_output',
      'PSBT input uses SINGLE without a corresponding output',
    );
  }

  const allInputs = indexes(input.inputCount);
  const allOutputs = indexes(input.outputCount);
  const committedInputIndexes = decoded.anyoneCanPay ? [input.inputIndex] : 'all';
  const mutableInputIndexes = decoded.anyoneCanPay
    ? allInputs.filter((index) => index !== input.inputIndex)
    : [];
  const committedOutputIndexes = decoded.committedOutputIndexes;
  const committedOutputSet = committedOutputIndexes === 'all'
    ? new Set(allOutputs)
    : new Set(committedOutputIndexes);
  const mutableOutputIndexes = allOutputs.filter((index) => !committedOutputSet.has(index));

  return {
    inputIndex: input.inputIndex,
    rawSighash: input.rawSighash,
    outputMode: decoded.outputMode,
    anyoneCanPay: decoded.anyoneCanPay,
    committedInputIndexes,
    mutableInputIndexes,
    committedOutputIndexes,
    mutableOutputIndexes,
    fee: decoded.anyoneCanPay || decoded.committedOutputIndexes !== 'all' ? 'mutable' : 'fixed',
  };
}
