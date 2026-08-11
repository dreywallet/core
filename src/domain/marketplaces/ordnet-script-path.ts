import { NETWORK, p2tr, p2tr_ns, type Transaction } from '@scure/btc-signer';
import { bytesToHex, hexToBytes } from '../vault/encoding';

/** Pinned by the ord.net sale-construction document accessed 2026-07-22. */
export const ORDNET_SALE_PUBLIC_KEY = 'd2dc3222298e2a5f4e1c7d702fae2bcf7821cc0a095a478b95c62195b0df7398';

export interface VerifiedOrdnetScriptPath {
  sellerPublicKey: string;
  ordnetPublicKey: typeof ORDNET_SALE_PUBLIC_KEY;
  leafVersion: 0xc0;
  disableTweakSigner: true;
}

/**
 * Verify tr(seller, multi_a(2,seller,ordnet)) from first principles using the
 * parsed control block and the pinned marketplace key. No page metadata is
 * trusted to supply either key or the output program.
 */
export function verifyOrdnetSaleScriptPath(
  tx: Transaction,
  inputIndex: number,
  sellerPublicKey: string,
): VerifiedOrdnetScriptPath {
  if (!/^[0-9a-f]{64}$/u.test(sellerPublicKey)) throw new Error('invalid seller x-only public key');
  const input = tx.getInput(inputIndex);
  if (!input.witnessUtxo?.script || input.tapLeafScript?.length !== 1) {
    throw new Error('ord.net script path requires one exact Taproot leaf');
  }
  const [controlBlock, scriptWithVersion] = input.tapLeafScript[0]!;
  if (controlBlock.merklePath.length !== 0 || (controlBlock.version & 0xfe) !== 0xc0 ||
      bytesToHex(controlBlock.internalKey) !== sellerPublicKey || scriptWithVersion.at(-1) !== 0xc0) {
    throw new Error('ord.net control block differs from the pinned template');
  }
  const expected = p2tr(
    hexToBytes(sellerPublicKey),
    { script: p2tr_ns(2, [hexToBytes(sellerPublicKey), hexToBytes(ORDNET_SALE_PUBLIC_KEY)])[0]!.script },
    NETWORK,
    true,
  );
  if (bytesToHex(expected.script) !== bytesToHex(input.witnessUtxo.script) ||
      expected.tapLeafScript?.length !== 1 ||
      bytesToHex(expected.tapLeafScript[0]![1]) !== bytesToHex(scriptWithVersion)) {
    throw new Error('ord.net Taproot output or multi_a leaf differs from the pinned template');
  }
  return {
    sellerPublicKey,
    ordnetPublicKey: ORDNET_SALE_PUBLIC_KEY,
    leafVersion: 0xc0,
    disableTweakSigner: true,
  };
}
