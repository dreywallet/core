import { RawTx, Transaction } from '@scure/btc-signer';
import { base64ToBytes, bytesToBase64, bytesToHex } from '../vault/encoding';
import {
  analyzePsbtInputCommitment,
  type PsbtInputCommitmentAnalysis,
} from './psbt-commitment';
import { assertProviderPsbtItemCounts } from './provider-psbt-limits';

export interface ProviderPsbtSighashDeclaration {
  signingIndexes: readonly number[];
  sigHash?: number | undefined;
}

export interface ProviderPsbtDeclaredInputCommitment extends PsbtInputCommitmentAnalysis {
  /** True when the PSBT input carries an explicit sighashType field. */
  explicitSighash: boolean;
  /** The callback declaration, when one was supplied. */
  declaredSighash: number | undefined;
}

function previousScript(tx: Transaction, inputIndex: number): string {
  const input = tx.getInput(inputIndex);
  let script = input.witnessUtxo?.script;
  if (input.nonWitnessUtxo) {
    const previous = Transaction.fromRaw(RawTx.encode(input.nonWitnessUtxo));
    if (!input.txid || previous.id !== bytesToHex(input.txid)) {
      throw new Error('PSBT non-witness transaction id mismatch');
    }
    const output = input.index === undefined ? undefined : previous.getOutput(input.index);
    if (!output?.script || output.amount === undefined) {
      throw new Error('PSBT non-witness prevout is missing');
    }
    if (input.witnessUtxo && (input.witnessUtxo.amount !== output.amount ||
        bytesToHex(input.witnessUtxo.script) !== bytesToHex(output.script))) {
      throw new Error('PSBT witness and non-witness prevouts disagree');
    }
    script = output.script;
  }
  if (!script) throw new Error('PSBT input is missing its previous output');
  return bytesToHex(script);
}

function resolvedSighash(tx: Transaction, inputIndex: number): {
  rawSighash: number;
  explicitSighash: boolean;
} {
  const explicit = tx.getInput(inputIndex).sighashType;
  if (explicit !== undefined) return { rawSighash: explicit, explicitSighash: true };
  const scriptPubKey = previousScript(tx, inputIndex);
  if (/^5120[0-9a-f]{64}$/u.test(scriptPubKey)) {
    return { rawSighash: 0, explicitSighash: false };
  }
  if (/^00(?:14[0-9a-f]{40}|20[0-9a-f]{64})$/u.test(scriptPubKey)) {
    return { rawSighash: 1, explicitSighash: false };
  }
  throw new Error('PSBT input has no supported default sighash');
}

/**
 * Validate callback-level signing declarations against the sighashes the PSBT
 * will actually use, then return the same exact commitment facts used by group
 * topology policy. This helper intentionally has no origin or marketplace
 * knowledge so adapters cannot silently discard a Sats Connect sigHash.
 */
export function validateProviderPsbtSighashDeclarations(input: {
  psbtBase64: string;
  declarations: readonly ProviderPsbtSighashDeclaration[];
}): ProviderPsbtDeclaredInputCommitment[] {
  const bytes = base64ToBytes(input.psbtBase64);
  if (bytesToBase64(bytes) !== input.psbtBase64) throw new Error('non-canonical PSBT base64');
  const tx = Transaction.fromPSBT(bytes, {
    lowR: true,
    allowUnknownInputs: true,
    allowUnknownOutputs: true,
  });
  assertProviderPsbtItemCounts(tx);
  if (input.declarations.length === 0) throw new Error('PSBT sighash declarations must be nonempty');

  const seen = new Set<number>();
  const analyses: ProviderPsbtDeclaredInputCommitment[] = [];
  for (const declaration of input.declarations) {
    if (declaration.signingIndexes.length === 0) {
      throw new Error('PSBT sighash declaration indexes must be nonempty');
    }
    for (const inputIndex of declaration.signingIndexes) {
      if (!Number.isSafeInteger(inputIndex) || inputIndex < 0 || inputIndex >= tx.inputsLength ||
          seen.has(inputIndex)) {
        throw new Error('PSBT sighash declaration index is invalid or duplicated');
      }
      seen.add(inputIndex);
      const actual = resolvedSighash(tx, inputIndex);
      if (declaration.sigHash !== undefined && declaration.sigHash !== actual.rawSighash) {
        throw new Error('PSBT sighash declaration differs from the PSBT input');
      }
      analyses.push({
        ...analyzePsbtInputCommitment({
          rawSighash: actual.rawSighash,
          inputIndex,
          inputCount: tx.inputsLength,
          outputCount: tx.outputsLength,
        }),
        explicitSighash: actual.explicitSighash,
        declaredSighash: declaration.sigHash,
      });
    }
  }
  return analyses;
}

/** Assertion-named alias for worker request-normalization call sites. */
export const assertProviderPsbtSighashDeclarations = validateProviderPsbtSighashDeclarations;
