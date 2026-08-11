import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  derivePublicAccountAddress,
  publicAccountDefinitionSchema,
  type PublicAccountDefinitionV1,
} from '../../src/domain/accounts/public-account';
import {
  decodeAccountDescriptor,
  encodeAccountDescriptor,
} from '../../src/domain/accounts/public-account-interchange';
import { bytesToHex, hexToBytes } from '../../src/domain/vault/encoding';
import { feeForVsize, parseCustomFeeRate } from '../../src/domain/transactions/fees';

interface PublicAccountVector {
  vectorVersion: number;
  accounts: Record<'mainnet' | 'signet', {
    definition: PublicAccountDefinitionV1;
    accountDescriptorCborHex: string;
    addresses: Array<{
      lane: 'payment' | 'ordinals';
      chain: 0 | 1;
      index: number;
      address: string;
      path: string;
      publicKeyHex: string;
      scriptPubKeyHex: string;
    }>;
  }>;
  customFees: Array<{
    input: string;
    normalizedSatPerVb: string;
    satPerKvB: string;
    vsize: string;
    feeSats: string;
  }>;
}

const vector = JSON.parse(readFileSync(
  join(import.meta.dirname, '..', '..', 'vectors', 'public-account-v1.json'),
  'utf8',
)) as PublicAccountVector;

describe('public account and fractional fee golden vectors', () => {
  it.each(['mainnet', 'signet'] as const)('replays every %s descriptor address', (network) => {
    expect(vector.vectorVersion).toBe(1);
    const record = vector.accounts[network];
    const definition = publicAccountDefinitionSchema.parse(record.definition);
    expect(bytesToHex(encodeAccountDescriptor(definition))).toBe(record.accountDescriptorCborHex);
    expect(decodeAccountDescriptor(
      hexToBytes(record.accountDescriptorCborHex),
      'account-descriptor',
      network,
    ).definition).toEqual(definition);
    for (const expected of record.addresses) {
      expect(derivePublicAccountAddress(
        definition,
        expected.lane,
        expected.chain,
        expected.index,
      )).toMatchObject(expected);
    }
  });

  it('replays exact custom-rate parsing and transaction fee ceilings', () => {
    for (const expected of vector.customFees) {
      const parsed = parseCustomFeeRate(expected.input);
      expect(parsed).toEqual({
        normalizedSatPerVb: expected.normalizedSatPerVb,
        satPerKvB: BigInt(expected.satPerKvB),
      });
      expect(feeForVsize(BigInt(expected.vsize), parsed.satPerKvB).toString())
        .toBe(expected.feeSats);
    }
  });
});
