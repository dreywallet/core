import { schnorr, secp256k1 } from '@noble/curves/secp256k1';
import { SigHash, Transaction } from '@scure/btc-signer';
import { hash160 } from '@scure/btc-signer/utils';

import { bytesToHex, hexToBytes } from '../vault/encoding';
import type { CommunityVaultSaleBuyerInputV1 } from './sale-contracts';

export function assertCommunityVaultBuyerInput(input: CommunityVaultSaleBuyerInputV1): void {
  const kind = /^0014[0-9a-f]{40}$/u.test(input.scriptPubKeyHex) ? 'p2wpkh'
    : /^5120[0-9a-f]{64}$/u.test(input.scriptPubKeyHex) ? 'p2tr' : null;
  if (kind !== input.scriptKind || BigInt(input.valueSats) <= 0n ||
      (kind === 'p2wpkh' ? input.sighashType !== SigHash.ALL : input.sighashType !== SigHash.DEFAULT)) {
    throw new Error('Community Vault buyer input is not clean whole-transaction funding');
  }
}

export function communityVaultBuyerSpendInput(input: CommunityVaultSaleBuyerInputV1) {
  assertCommunityVaultBuyerInput(input);
  return {
    txid: input.txid,
    vout: input.vout,
    valueSats: input.valueSats,
    scriptPubKeyHex: input.scriptPubKeyHex,
    sequence: input.sequence,
  };
}

export function verifyCommunityVaultBuyerInput(input: {
  tx: Transaction;
  buyerInput: CommunityVaultSaleBuyerInputV1;
  inputIndex: number;
  spendInputs: readonly { scriptPubKeyHex: string; valueSats: string }[];
}): void {
  assertCommunityVaultBuyerInput(input.buyerInput);
  const expected = input.buyerInput;
  const witness = input.tx.getInput(input.inputIndex).finalScriptWitness ?? [];
  if (expected.scriptKind === 'p2wpkh') {
    const signature = witness[0];
    const publicKey = witness[1];
    const keyHash = expected.scriptPubKeyHex.slice(4);
    if (witness.length !== 2 || !signature || signature.length < 2 || !publicKey ||
        signature.at(-1) !== expected.sighashType || bytesToHex(hash160(publicKey)) !== keyHash) {
      throw new Error(`Community Vault buyer input ${input.inputIndex} is not exactly funded`);
    }
    const message = input.tx.preimageWitnessV0(
      input.inputIndex,
      hexToBytes(`76a914${keyHash}88ac`),
      expected.sighashType,
      BigInt(expected.valueSats),
    );
    if (!secp256k1.verify(signature.slice(0, -1), message, publicKey, {
      format: 'der', prehash: false, lowS: true,
    })) throw new Error(`Community Vault buyer input ${input.inputIndex} signature is invalid`);
    return;
  }
  const signature = witness[0];
  if (witness.length !== 1 || !signature || (signature.length !== 64 && signature.length !== 65)) {
    throw new Error(`Community Vault buyer input ${input.inputIndex} is not exactly funded`);
  }
  const sighash = signature.length === 64 ? SigHash.DEFAULT : signature[64]!;
  if (sighash !== expected.sighashType) {
    throw new Error(`Community Vault buyer input ${input.inputIndex} sighash differs`);
  }
  const message = input.tx.preimageWitnessV1(
    input.inputIndex,
    input.spendInputs.map((item) => hexToBytes(item.scriptPubKeyHex)),
    sighash,
    input.spendInputs.map((item) => BigInt(item.valueSats)),
  );
  if (!schnorr.verify(signature.slice(0, 64), message, hexToBytes(expected.scriptPubKeyHex).slice(2))) {
    throw new Error(`Community Vault buyer input ${input.inputIndex} signature is invalid`);
  }
}
