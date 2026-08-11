import { HDKey } from '@scure/bip32';
import { describe, expect, it } from 'vitest';
import {
  bitcoinCoreDescriptorJson,
  decodeAccountDescriptor,
  definitionFromAccountKeys,
  encodeAccountDescriptor,
  parsePublicAccountText,
  publicAccountKeyExpressions,
  PublicAccountInterchangeError,
} from '../../src/domain/accounts/public-account-interchange';
import { descriptorChecksum } from '../../src/domain/keys/descriptor-checksum';
import { bip32Versions } from '../../src/domain/keys/extended-key';
import { publicAccountFromSeed } from '../../src/domain/accounts/public-account';

const SEED = Uint8Array.from({ length: 32 }, (_, index) => index + 11);

function codeOf(run: () => unknown): string | undefined {
  try {
    run();
    return undefined;
  } catch (error) {
    return error instanceof PublicAccountInterchangeError ? error.code : undefined;
  }
}

describe('public account interchange', () => {
  it.each(['mainnet', 'signet'] as const)('round-trips current account-descriptor dCBOR on %s', (network) => {
    const definition = publicAccountFromSeed(SEED, network, 7);
    const encoded = encodeAccountDescriptor(definition);
    const decoded = decodeAccountDescriptor(encoded, 'account-descriptor', network);
    expect(decoded).toEqual({ format: 'account-descriptor-v2', definition });
    expect(encodeAccountDescriptor(decoded.definition)).toEqual(encoded);
  });

  it('round-trips Bitcoin Core JSON and does not need a proprietary Drey document', () => {
    const definition = publicAccountFromSeed(SEED, 'mainnet', 3);
    const json = bitcoinCoreDescriptorJson(definition);
    expect(JSON.parse(json)).toHaveLength(4);
    expect(parsePublicAccountText(json, 'mainnet')).toEqual({
      format: 'bitcoin-core-json',
      definition,
    });
  });

  it('normalizes BIP389 receive/change multipath descriptors', () => {
    const definition = publicAccountFromSeed(SEED, 'signet', 2);
    const combined = (receive: string) => {
      const payload = receive.slice(0, -9).replace('/0/*)', '/<0;1>/*)');
      return `${payload}#${descriptorChecksum(payload)}`;
    };
    expect(parsePublicAccountText([
      combined(definition.lanes.payment.receiveDescriptor),
      combined(definition.lanes.ordinals.receiveDescriptor),
    ].join('\n'), 'signet').definition).toEqual(definition);
  });

  it('creates the same account from the two explicit public account keys', () => {
    const definition = publicAccountFromSeed(SEED, 'signet', 19);
    const expressions = publicAccountKeyExpressions(definition);
    expect(expressions.payment).toMatch(/^\[[0-9a-f]{8}\/84h\/1h\/19h\]tpub/u);
    expect(expressions.ordinals).toMatch(/^\[[0-9a-f]{8}\/86h\/1h\/19h\]tpub/u);
    expect(definitionFromAccountKeys({
      network: 'signet',
      masterFingerprintHex: definition.lanes.payment.origin.masterFingerprintHex,
      accountIndex: 19,
      paymentAccountXpub: definition.lanes.payment.origin.accountXpub,
      ordinalsAccountXpub: definition.lanes.ordinals.origin.accountXpub,
    })).toEqual(definition);
    expect(parsePublicAccountText(`${expressions.payment}\n${expressions.ordinals}`, 'signet')).toEqual({
      format: 'account-key-expressions',
      definition,
    });
  });

  it('returns actionable closed-policy errors and refuses private material', () => {
    const definition = publicAccountFromSeed(SEED, 'signet', 0);
    expect(codeOf(() => parsePublicAccountText(
      definition.lanes.payment.receiveDescriptor,
      'signet',
    ))).toBe('missing-payment');
    expect(codeOf(() => parsePublicAccountText([
      definition.lanes.payment.receiveDescriptor,
      definition.lanes.payment.changeDescriptor,
    ].join('\n'), 'signet'))).toBe('missing-ordinals');
    expect(codeOf(() => parsePublicAccountText(bitcoinCoreDescriptorJson(definition), 'mainnet')))
      .toBe('wrong-network');

    const root = HDKey.fromMasterSeed(SEED, bip32Versions('signet'));
    expect(codeOf(() => parsePublicAccountText(`wpkh(${root.privateExtendedKey}/0/*)#aaaaaaaa`, 'signet')))
      .toBe('private-material');
    root.wipePrivateData();
  });

  it('rejects noncanonical CBOR, duplicate account lanes, and oversized documents', () => {
    const definition = publicAccountFromSeed(SEED, 'mainnet', 0);
    const encoded = encodeAccountDescriptor(definition);
    expect(codeOf(() => decodeAccountDescriptor(
      Uint8Array.of(0xb8, 0x02, ...encoded.slice(1)),
      'account-descriptor',
      'mainnet',
    ))).toBe('invalid-format');
    expect(codeOf(() => parsePublicAccountText('x'.repeat(65_537), 'mainnet')))
      .toBe('limit-exceeded');
  });
});
