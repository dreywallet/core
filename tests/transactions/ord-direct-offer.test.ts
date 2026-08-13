import { Address, OutScript, SigHash, TEST_NETWORK, Transaction } from '@scure/btc-signer';
import { describe, expect, it } from 'vitest';
import { bytesToBase64, bytesToHex } from '../../src/domain/vault/encoding';
import {
  assertOrdDirectOfferFundingAvailable,
  beginOrdDirectOfferCancellation,
  createOrdDirectOfferRecord,
  ORD_DIRECT_OFFERS_PRODUCTION_ENABLED,
  reconcileOrdDirectOffer,
  validateOrdDirectOfferForAcceptance,
} from '../../src/domain/transactions/ord-direct-offer';

const sellerAddress = Address(TEST_NETWORK).encode({ type: 'wpkh', hash: new Uint8Array(20).fill(1) });
const buyerAddress = Address(TEST_NETWORK).encode({ type: 'tr', pubkey: new Uint8Array(32).fill(2) });
const sellerScript = bytesToHex(OutScript.encode(Address(TEST_NETWORK).decode(sellerAddress)));
const buyerScript = bytesToHex(OutScript.encode(Address(TEST_NETWORK).decode(buyerAddress)));
const sellerTxid = 'a'.repeat(64);
const buyerTxid = 'b'.repeat(64);
const inscriptionId = `${'c'.repeat(64)}i0`;

function fixture(overrides?: {
  sellerOutputSats?: bigint;
  inscriptionOutputSats?: bigint;
  specifiedSighash?: boolean;
}): string {
  const tx = new Transaction({ lowR: true, version: 2, lockTime: 0 });
  tx.addInput({ txid: sellerTxid, index: 0,
    witnessUtxo: { script: Uint8Array.from(Buffer.from(sellerScript, 'hex')), amount: 10_000n },
    sequence: 0xffff_fffd,
    ...(overrides?.specifiedSighash ? { sighashType: SigHash.SINGLE_ANYONECANPAY } : {}),
  });
  tx.addInput({ txid: buyerTxid, index: 1,
    witnessUtxo: { script: Uint8Array.from(Buffer.from(sellerScript, 'hex')), amount: 31_000n },
    ...(overrides?.specifiedSighash ? { sighashType: SigHash.ALL } : {}),
  });
  tx.addOutput({ script: Uint8Array.from(Buffer.from(buyerScript, 'hex')),
    amount: overrides?.inscriptionOutputSats ?? 10_000n });
  tx.addOutput({ script: Uint8Array.from(Buffer.from(sellerScript, 'hex')),
    amount: overrides?.sellerOutputSats ?? 30_000n });
  tx.updateInput(1, { finalScriptWitness: [new Uint8Array([1]), new Uint8Array([2])] });
  return bytesToBase64(tx.toPSBT());
}

const expected = {
  network: 'signet' as const,
  inscriptionId,
  sellerOutpoint: { txid: sellerTxid, vout: 0 },
  sellerPrevout: { valueSats: 10_000n, scriptPubKey: sellerScript },
  sellerPayoutAddress: sellerAddress,
  amountSats: 20_000n,
  inscriptionDestinationAddress: buyerAddress,
};

describe('disabled ord direct-offer v1 policy', () => {
  it('fails closed at every callable offer entry point while production is gated', () => {
    expect(ORD_DIRECT_OFFERS_PRODUCTION_ENABLED).toBe(false);
    expect(() => validateOrdDirectOfferForAcceptance(fixture(), expected))
      .toThrow(/disabled/u);
  });

  it('keeps malformed and legacy-sighash fixtures behind the same production gate', () => {
    for (const psbt of [
      fixture({ inscriptionOutputSats: 9_999n }),
      fixture({ sellerOutputSats: 29_999n }),
      fixture({ specifiedSighash: true }),
    ]) {
      expect(() => validateOrdDirectOfferForAcceptance(psbt, expected)).toThrow(/disabled/u);
    }
  });

  it('tracks reservation-backed cancellation only after a conflicting spend is observed', () => {
    const record = createOrdDirectOfferRecord({ role: 'buyer', inscriptionId, amountSats: 20_000n,
      unsignedTransactionId: 'd'.repeat(64), fundingOutpoints: [{ txid: buyerTxid, vout: 1 }],
      createdAt: 1, offerId: 'e'.repeat(64) });
    expect(() => assertOrdDirectOfferFundingAvailable([record], [{ txid: buyerTxid, vout: 1 }]))
      .toThrow(/reserved/u);
    const pending = beginOrdDirectOfferCancellation(record, record.fundingOutpoints);
    expect(pending.status).toBe('cancel_pending');
    expect(reconcileOrdDirectOffer({ record: pending, acceptedTransactionObserved: false,
      conflictingFundingSpendObserved: false }).status).toBe('cancel_pending');
    expect(reconcileOrdDirectOffer({ record: pending, acceptedTransactionObserved: false,
      conflictingFundingSpendObserved: true }).status).toBe('cancelled');
  });
});
