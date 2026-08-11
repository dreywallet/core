import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { beforeAll, describe, expect, it } from 'vitest';
import type { VaultPairingEnvelopeV1, VaultPsbtApprovalEnvelopeV1 } from '../../src/domain/vault/multisig-contracts';
import {
  decodeVaultContextCbor,
  decodeVaultPsbtCbor,
  encodeVaultApprovalContextCbor,
  encodeVaultPairingContextCbor,
  encodeVaultPsbtCbor,
  vaultPsbtUrEncoder,
} from '../../src/domain/vault/multisig-qr';
import { bytesToHex } from '../../src/domain/vault/encoding';
import { installTestCryptoProvider } from '../helpers/install-crypto-provider';

beforeAll(installTestCryptoProvider);

const vectors = JSON.parse(readFileSync(
  join(import.meta.dirname, '..', '..', 'vectors', 'vault-contracts-v1.json'),
  'utf8',
)) as { records: { mainnet: { partialInput: { psbtHex: string }; pairing: VaultPairingEnvelopeV1; approval: VaultPsbtApprovalEnvelopeV1 } } };

describe('Vault QR application transport', () => {
  it('matches the published untagged CBOR byte-string representation for ur:psbt', () => {
    const psbtHex = vectors.records.mainnet.partialInput.psbtHex;
    const cbor = encodeVaultPsbtCbor(psbtHex);
    expect(bytesToHex(cbor).startsWith('59')).toBe(true);
    expect(decodeVaultPsbtCbor('psbt', cbor)).toBe(psbtHex);
    expect(decodeVaultPsbtCbor('crypto-psbt', cbor)).toBe(psbtHex);
    expect(vaultPsbtUrEncoder(psbtHex).frames[0]).toMatch(/^ur:psbt\//u);
  });

  it('uses the reserved proprietary x-* namespace for authenticated context', () => {
    const pairing = encodeVaultPairingContextCbor(vectors.records.mainnet.pairing);
    expect(decodeVaultContextCbor('x-drey-vault', pairing)).toEqual({
      kind: 'pairing', envelope: vectors.records.mainnet.pairing,
    });
    const approval = encodeVaultApprovalContextCbor(vectors.records.mainnet.approval);
    expect(decodeVaultContextCbor('x-drey-vault', approval)).toEqual({
      kind: 'approval', envelope: vectors.records.mainnet.approval,
    });
  });

  it('rejects wrong types, malformed PSBTs, and mislabeled context', () => {
    const psbtHex = vectors.records.mainnet.partialInput.psbtHex;
    const cbor = encodeVaultPsbtCbor(psbtHex);
    expect(() => decodeVaultPsbtCbor('x-drey-vault', cbor)).toThrow();
    expect(() => decodeVaultPsbtCbor('psbt', Uint8Array.of(0x45, 1, 2, 3, 4, 5))).toThrow();
    expect(() => decodeVaultContextCbor('psbt', encodeVaultPairingContextCbor(vectors.records.mainnet.pairing))).toThrow();
  });
});
