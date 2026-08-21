/**
 * Strict BIP322 "simple" message signing for Drey's native SegWit accounts.
 *
 * The returned signature is the consensus-encoded witness stack, base64
 * encoded and prefixed with `smp` as required by BIP322 v1.0.0+. Only the two
 * account scripts Drey actually derives today are supported: BIP84 P2WPKH and
 * BIP86 Taproot key path. P2WSH, legacy/full signatures, proof-of-funds, and
 * Taproot script paths deliberately remain unsupported.
 */
import {
  Address,
  OutScript,
  RawWitness,
  Script,
  SigHash,
  Transaction,
  p2tr,
  p2wpkh,
} from '@scure/btc-signer';
import {
  concatBytes,
  equalBytes,
  hash160,
  pubECDSA,
  sha256,
  sha256x2,
} from '@scure/btc-signer/utils';
import { schnorr, secp256k1 } from '@noble/curves/secp256k1';
import { bitcoinNetwork, type AddressKind, type Network } from '../keys/derivation';
import { base64ToBytes, bytesToBase64, bytesToHex } from '../vault/encoding';

export const BIP322_SIMPLE_PREFIX = 'smp';
export const BIP322_MAX_MESSAGE_BYTES = 4_096;

const TAG = new TextEncoder().encode('BIP0322-signed-message');
const TAG_HASH = sha256(TAG);
const ZERO_TXID = '00'.repeat(32);
const OP_RETURN = new Uint8Array([0x6a]);

export interface Bip322SimpleSignInput {
  message: string;
  privateKey: Uint8Array;
  addressKind: AddressKind;
  /** CSPRNG seam used only for BIP340 auxiliary randomness. */
  random: (length: number) => Uint8Array;
}

export interface Bip322VirtualHashes {
  messageHash: string;
  toSpendTxid: string;
  toSignTxid: string;
}

function assertWellFormedUnicode(message: string): void {
  for (let index = 0; index < message.length; index += 1) {
    const unit = message.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = message.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) throw new Error('BIP322 message contains invalid UTF-16');
      index += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      throw new Error('BIP322 message contains invalid UTF-16');
    }
  }
}

/** Drey §21.2 message policy. The returned bytes are signed exactly as-is. */
export function validateBip322Message(message: string): Uint8Array {
  assertWellFormedUnicode(message);
  for (const character of message) {
    const codePoint = character.codePointAt(0)!;
    const allowedWhitespace = codePoint === 0x09 || codePoint === 0x0a || codePoint === 0x0d;
    if ((!allowedWhitespace && codePoint < 0x20) || (codePoint >= 0x7f && codePoint <= 0x9f)) {
      throw new Error('BIP322 message contains a disallowed control character');
    }
  }
  const bytes = new TextEncoder().encode(message);
  if (bytes.length > BIP322_MAX_MESSAGE_BYTES) throw new Error('BIP322 message is too large');
  return bytes;
}

/** BIP340-tagged `BIP0322-signed-message` hash over raw message bytes. */
export function bip322MessageHash(message: Uint8Array): Uint8Array {
  return sha256(concatBytes(TAG_HASH, TAG_HASH, message));
}

function txid(tx: Transaction): string {
  return bytesToHex(sha256x2(tx.unsignedTx).reverse());
}

function makeVirtualTransactions(message: Uint8Array, challenge: Uint8Array): {
  messageHash: Uint8Array;
  toSpendTxid: string;
  toSign: Transaction;
} {
  const messageHash = bip322MessageHash(message);
  const toSpend = new Transaction({ version: 0, allowUnknownInputs: true });
  // Add the output first because a finalScriptSig marks the input signed and
  // @scure correctly prevents subsequent unsigned-transaction mutation.
  toSpend.addOutput({ script: challenge, amount: 0n });
  toSpend.addInput({
    txid: ZERO_TXID,
    index: 0xffffffff,
    sequence: 0,
    finalScriptSig: Script.encode([0, messageHash]),
  });
  // Unlike a PSBT unsigned transaction, to_spend's txid commits to its
  // required scriptSig. Transaction.id serializes that finalized input.
  const toSpendTxid = toSpend.id;

  const toSign = new Transaction({ version: 0, lowR: true, allowUnknownOutputs: true });
  toSign.addInput({
    txid: toSpendTxid,
    index: 0,
    sequence: 0,
    witnessUtxo: { script: challenge, amount: 0n },
  });
  toSign.addOutput({ script: OP_RETURN, amount: 0n });
  return { messageHash, toSpendTxid, toSign };
}

/** Exposes the official vector intermediates without exposing signing data. */
export function bip322VirtualHashes(message: string, address: string, network: Network): Bip322VirtualHashes {
  const messageBytes = validateBip322Message(message);
  const codec = Address(bitcoinNetwork(network));
  const challenge = OutScript.encode(codec.decode(address));
  const virtual = makeVirtualTransactions(messageBytes, challenge);
  return {
    messageHash: bytesToHex(virtual.messageHash),
    toSpendTxid: virtual.toSpendTxid,
    toSignTxid: txid(virtual.toSign),
  };
}

/**
 * Sign a Drey-derived BIP84 or BIP86 account key using BIP322 simple.
 * The caller retains ownership of `privateKey` and must zeroize it.
 */
export function signBip322Simple(input: Bip322SimpleSignInput): string {
  const message = validateBip322Message(input.message);
  const publicKey = pubECDSA(input.privateKey);
  const payment = input.addressKind === 'payment';
  const challenge = payment
    ? p2wpkh(publicKey).script
    : p2tr(publicKey.slice(1)).script;
  const { toSign } = makeVirtualTransactions(message, challenge);

  if (payment) {
    toSign.updateInput(0, { sighashType: SigHash.ALL });
    toSign.signIdx(input.privateKey, 0, [SigHash.ALL]);
  } else {
    const auxRand = input.random(32);
    if (auxRand.length !== 32) throw new Error('BIP322 Taproot auxiliary randomness must be 32 bytes');
    toSign.updateInput(0, { sighashType: SigHash.DEFAULT, tapInternalKey: publicKey.slice(1) });
    toSign.signIdx(input.privateKey, 0, [SigHash.DEFAULT], auxRand);
  }
  toSign.finalizeIdx(0);
  const witness = toSign.getInput(0).finalScriptWitness;
  if (!witness) throw new Error('BIP322 signer produced no witness');
  return `${BIP322_SIMPLE_PREFIX}${bytesToBase64(RawWitness.encode(witness))}`;
}

function decodeSimpleWitness(signature: string): Uint8Array[] | null {
  if (!signature.startsWith(BIP322_SIMPLE_PREFIX)) return null;
  const encoded = signature.slice(BIP322_SIMPLE_PREFIX.length);
  try {
    const bytes = base64ToBytes(encoded);
    if (bytesToBase64(bytes) !== encoded) return null;
    return RawWitness.decode(bytes);
  } catch {
    return null;
  }
}

/** Cryptographic verifier for the two simple signature forms Drey emits. */
export function verifyBip322Simple(
  message: string,
  address: string,
  network: Network,
  signature: string,
): boolean {
  try {
    const messageBytes = validateBip322Message(message);
    const codec = Address(bitcoinNetwork(network));
    const challenge = OutScript.encode(codec.decode(address));
    const decoded = OutScript.decode(challenge);
    const witness = decodeSimpleWitness(signature);
    if (!witness) return false;
    const { toSign } = makeVirtualTransactions(messageBytes, challenge);

    if (decoded.type === 'wpkh') {
      if (witness.length !== 2) return false;
      const signatureWithType = witness[0];
      const publicKey = witness[1];
      if (!signatureWithType || signatureWithType.length < 2 || !publicKey ||
          signatureWithType[signatureWithType.length - 1] !== SigHash.ALL ||
          !equalBytes(hash160(publicKey), decoded.hash)) return false;
      const scriptCode = OutScript.encode({ type: 'pkh', hash: decoded.hash });
      const hash = toSign.preimageWitnessV0(0, scriptCode, SigHash.ALL, 0n);
      return secp256k1.verify(signatureWithType.slice(0, -1), hash, publicKey, {
        format: 'der', prehash: false, lowS: true,
      });
    }

    if (decoded.type === 'tr') {
      if (witness.length !== 1) return false;
      const tapSignature = witness[0];
      if (!tapSignature || (tapSignature.length !== 64 && tapSignature.length !== 65)) return false;
      const sighash = tapSignature.length === 64 ? SigHash.DEFAULT : tapSignature[64]!;
      if (sighash !== SigHash.DEFAULT && sighash !== SigHash.ALL) return false;
      const hash = toSign.preimageWitnessV1(0, [challenge], sighash, [0n]);
      return schnorr.verify(tapSignature.slice(0, 64), hash, decoded.pubkey);
    }

    return false;
  } catch {
    return false;
  }
}
