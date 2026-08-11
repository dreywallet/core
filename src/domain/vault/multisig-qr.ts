/**
 * QR application transport for Vault pairing and signing.
 *
 * PSBTs use the current Blockchain Commons registry type `ur:psbt` and its
 * untagged CBOR byte-string body. The deprecated `ur:crypto-psbt` spelling is
 * accepted for interoperability but never emitted. Authenticated Drey context
 * uses the registry-reserved user namespace `ur:x-drey-vault`; it is explicitly
 * proprietary and supplements, rather than replaces, the separately scanned
 * standards-valid PSBT.
 */
import { Transaction } from '@scure/btc-signer';
import { decodeCborBytes, encodeCborBytes } from '../ur/cbor-bytes';
import {
  FixedRateUrEncoder,
  type FixedRateUrEncoderOptions,
} from '../ur/fixed-rate';
import { UrTransportError } from '../ur/errors';
import type { VaultPairingEnvelopeV1, VaultPsbtApprovalEnvelopeV1 } from './multisig-contracts';
import {
  parseVaultPairingEnvelope,
  parseVaultPsbtApprovalEnvelope,
  serializeVaultPairingEnvelope,
  serializeVaultPsbtApprovalEnvelope,
} from './multisig-encoding';
import { bytesToHex, hexToBytes } from './encoding';

export const VAULT_PSBT_UR_TYPE = 'psbt' as const;
export const VAULT_LEGACY_PSBT_UR_TYPE = 'crypto-psbt' as const;
export const DREY_VAULT_CONTEXT_UR_TYPE = 'x-drey-vault' as const;

const PAIRING_CONTEXT = 1;
const APPROVAL_CONTEXT = 2;

function assertPsbt(bytes: Uint8Array): void {
  if (bytes.length < 5 || bytes[0] !== 0x70 || bytes[1] !== 0x73 || bytes[2] !== 0x62 ||
      bytes[3] !== 0x74 || bytes[4] !== 0xff) {
    throw new UrTransportError('invalid-cbor', 'PSBT payload has no BIP174 magic');
  }
  try {
    Transaction.fromPSBT(bytes);
  } catch {
    throw new UrTransportError('invalid-cbor', 'PSBT payload is malformed');
  }
}

export function encodeVaultPsbtCbor(psbtHex: string): Uint8Array {
  const psbt = hexToBytes(psbtHex);
  assertPsbt(psbt);
  return encodeCborBytes(psbt);
}

export function decodeVaultPsbtCbor(type: string, cborMessage: Uint8Array): string {
  const normalized = type.toLowerCase();
  if (normalized !== VAULT_PSBT_UR_TYPE && normalized !== VAULT_LEGACY_PSBT_UR_TYPE) {
    throw new UrTransportError('invalid-type', 'expected ur:psbt');
  }
  const psbt = decodeCborBytes(cborMessage);
  assertPsbt(psbt);
  return bytesToHex(psbt);
}

export function vaultPsbtUrEncoder(
  psbtHex: string,
  options: FixedRateUrEncoderOptions = {},
): FixedRateUrEncoder {
  return new FixedRateUrEncoder(VAULT_PSBT_UR_TYPE, encodeVaultPsbtCbor(psbtHex), options);
}

function encodeContext(kind: number, payload: Uint8Array): Uint8Array {
  if (payload.length > 0xffff_ffff) throw new UrTransportError('limit-exceeded', 'Vault context exceeds uint32');
  const wrapped = encodeCborBytes(payload);
  const encoded = new Uint8Array(3 + wrapped.length);
  encoded.set([0x83, 0x01, kind]);
  encoded.set(wrapped, 3);
  return encoded;
}

function decodeContext(cbor: Uint8Array): { kind: number; payload: Uint8Array } {
  if (cbor.length < 4 || cbor[0] !== 0x83 || cbor[1] !== 0x01 ||
      (cbor[2] !== PAIRING_CONTEXT && cbor[2] !== APPROVAL_CONTEXT)) {
    throw new UrTransportError('invalid-cbor', 'unsupported Drey Vault context');
  }
  return { kind: cbor[2]!, payload: decodeCborBytes(cbor.slice(3)) };
}

export type DecodedVaultQrContext =
  | { kind: 'pairing'; envelope: VaultPairingEnvelopeV1 }
  | { kind: 'approval'; envelope: VaultPsbtApprovalEnvelopeV1 };

export function encodeVaultPairingContextCbor(envelope: VaultPairingEnvelopeV1): Uint8Array {
  return encodeContext(PAIRING_CONTEXT, serializeVaultPairingEnvelope(envelope));
}

export function encodeVaultApprovalContextCbor(envelope: VaultPsbtApprovalEnvelopeV1): Uint8Array {
  return encodeContext(APPROVAL_CONTEXT, serializeVaultPsbtApprovalEnvelope(envelope));
}

export function decodeVaultContextCbor(type: string, cborMessage: Uint8Array): DecodedVaultQrContext {
  if (type.toLowerCase() !== DREY_VAULT_CONTEXT_UR_TYPE) {
    throw new UrTransportError('invalid-type', `expected ur:${DREY_VAULT_CONTEXT_UR_TYPE}`);
  }
  const decoded = decodeContext(cborMessage);
  return decoded.kind === PAIRING_CONTEXT
    ? { kind: 'pairing', envelope: parseVaultPairingEnvelope(decoded.payload) }
    : { kind: 'approval', envelope: parseVaultPsbtApprovalEnvelope(decoded.payload) };
}

export function vaultPairingContextUrEncoder(
  envelope: VaultPairingEnvelopeV1,
  options: FixedRateUrEncoderOptions = {},
): FixedRateUrEncoder {
  return new FixedRateUrEncoder(
    DREY_VAULT_CONTEXT_UR_TYPE,
    encodeVaultPairingContextCbor(envelope),
    options,
  );
}

export function vaultApprovalContextUrEncoder(
  envelope: VaultPsbtApprovalEnvelopeV1,
  options: FixedRateUrEncoderOptions = {},
): FixedRateUrEncoder {
  return new FixedRateUrEncoder(
    DREY_VAULT_CONTEXT_UR_TYPE,
    encodeVaultApprovalContextCbor(envelope),
    options,
  );
}
