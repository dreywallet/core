import {
  NETWORK,
  OP,
  p2tr,
  Script,
  ScriptNum,
  SigHash,
  TAPROOT_UNSPENDABLE_KEY,
  type Transaction,
} from '@scure/btc-signer';
import { bytesToHex, hexToBytes } from '../vault/encoding';
import { COMMUNITY_VAULT_NUMS_INTERNAL_KEY } from '../community-vault/contracts';

export const ORDNET_FOUNDRY_MAX_FEE_RESERVE_SATS = 100_000n;
export const ORDNET_FOUNDRY_PRESALE_POLICY_VERSION = 1 as const;

export interface VerifiedOrdnetFoundryWithdrawal {
  recipientPublicKey: string;
  unlockAt: number;
  feeReserveSats: bigint;
  disableTweakSigner: true;
}

function foundryLeaf(unlockAt: number, recipientPublicKey: string): Uint8Array {
  return Script.encode([
    ScriptNum(5, true).encode(BigInt(unlockAt)),
    OP.CHECKLOCKTIMEVERIFY,
    OP.DROP,
    hexToBytes(recipientPublicKey),
    OP.CHECKSIG,
  ]);
}

/**
 * Verify ord.net Foundry's canonical presale withdrawal from first principles.
 * This deliberately does not accept arbitrary CLTV Taproot scripts.
 */
export function verifyOrdnetFoundryTimelockPath(
  tx: Transaction,
  selectedInputIndexes: readonly number[],
  recipientPublicKey: string,
): VerifiedOrdnetFoundryWithdrawal {
  if (!/^[0-9a-f]{64}$/u.test(recipientPublicKey)) {
    throw new Error('invalid Foundry recipient x-only public key');
  }
  if (bytesToHex(TAPROOT_UNSPENDABLE_KEY) !== COMMUNITY_VAULT_NUMS_INTERNAL_KEY) {
    throw new Error('signing library NUMS key differs from the pinned Foundry key');
  }
  if (tx.version !== 2 || tx.inputsLength !== 2 || tx.outputsLength !== 1 ||
      selectedInputIndexes.length !== 2 || selectedInputIndexes[0] !== 0 || selectedInputIndexes[1] !== 1 ||
      tx.lockTime < 500_000_000 || tx.lockTime > 0xffff_ffff) {
    throw new Error('Foundry withdrawal transaction shape or locktime differs from the pinned template');
  }

  const script = foundryLeaf(tx.lockTime, recipientPublicKey);
  const expectedTimelock = p2tr(TAPROOT_UNSPENDABLE_KEY, { script }, NETWORK, true);
  const expectedRecipient = p2tr(hexToBytes(recipientPublicKey), undefined, NETWORK);
  const expectedLeaf = expectedTimelock.tapLeafScript?.[0];
  if (!expectedLeaf || expectedTimelock.tapLeafScript?.length !== 1 ||
      expectedLeaf[0].merklePath.length !== 0 || expectedTimelock.leaves.length !== 1) {
    throw new Error('Foundry verifier could not construct the pinned Taproot tree');
  }

  for (let index = 0; index < 2; index += 1) {
    const input = tx.getInput(index);
    const leaf = input.tapLeafScript?.[0];
    if (!input.witnessUtxo || input.sequence !== 0xffff_fffd ||
        (input.sighashType ?? SigHash.DEFAULT) !== SigHash.DEFAULT ||
        bytesToHex(input.witnessUtxo.script) !== bytesToHex(expectedTimelock.script) ||
        input.tapLeafScript?.length !== 1 || !leaf || leaf[0].merklePath.length !== 0 ||
        (leaf[0].version & 0xfe) !== 0xc0 ||
        bytesToHex(leaf[0].internalKey) !== COMMUNITY_VAULT_NUMS_INTERNAL_KEY ||
        bytesToHex(leaf[1]) !== bytesToHex(expectedLeaf[1])) {
      throw new Error('Foundry withdrawal input differs from the pinned CLTV path');
    }
  }

  const inscriptionInput = tx.getInput(0).witnessUtxo!;
  const feeInput = tx.getInput(1).witnessUtxo!;
  const output = tx.getOutput(0);
  if (output.amount === undefined || !output.script ||
      output.amount !== inscriptionInput.amount ||
      bytesToHex(output.script) !== bytesToHex(expectedRecipient.script) ||
      feeInput.amount <= 0n || feeInput.amount > ORDNET_FOUNDRY_MAX_FEE_RESERVE_SATS ||
      tx.fee !== feeInput.amount) {
    throw new Error('Foundry withdrawal destination, inscription value, or fee reserve differs');
  }

  return {
    recipientPublicKey,
    unlockAt: tx.lockTime,
    feeReserveSats: feeInput.amount,
    disableTweakSigner: true,
  };
}
