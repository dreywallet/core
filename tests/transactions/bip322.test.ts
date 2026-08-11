import { describe, expect, it } from 'vitest';
import { NETWORK, TEST_NETWORK, WIF, p2tr, p2wpkh } from '@scure/btc-signer';
import { pubECDSA } from '@scure/btc-signer/utils';
import {
  BIP322_MAX_MESSAGE_BYTES,
  bip322MessageHash,
  bip322VirtualHashes,
  signBip322Simple,
  validateBip322Message,
  verifyBip322Simple,
} from '../../src/domain/transactions/bip322';
import { bytesToHex } from '../../src/domain/vault/encoding';

// Current official vectors:
// https://github.com/bitcoin/bips/tree/master/bip-0322
const P2WPKH = {
  message: '2V6TUTMSH4VQ3Z7WZWKYD7DFNH',
  wif: 'KySmn2yeCukjHXnSu3M6vX7tNok4weu1FKbNEuVvm2b3ZidKhB4L',
  address: 'bc1qqthe0hz8klx90e7stf6shclhsvqd5ly96pn53v',
  signature: 'smpAkgwRQIhALC6hdfxNy1n45d7UXSskRBdfZW0Al259E1kDMpipdYkAiAJPfZqb+WurZuf1apU5xeE6Igui9dvt5tihQLDvxlY1AEhAqbnruyo677ktQjio7XOchO3w51Dh9AbRVngha5jtNfT',
} as const;

const P2TR = {
  message: 'PURVOQ544B6HUATVBJZN5EZJUU',
  wif: 'L5XqN6ckPPsDiTbRxcsthwiWpDBfWLo4uquUEydsPt8rSMoTpqpc',
  address: 'bc1pcquvhrqv0q68t4m0hfq6tpn006qrskyc7yrqnp2uyrf2emg3wynsdjyk38',
  signature: 'smpAUB6B2Rbupzua8LTQIF06516wzl+cwKy1be8RgoiW0riyXdKwe6GTz/5Hnb37m67pJwIKCh+D5jDueG6KpvYpmu8',
} as const;

describe('BIP322 simple', () => {
  it('matches the official message and virtual-transaction hash vectors', () => {
    expect(bip322VirtualHashes(
      'Hello World',
      'bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l',
      'mainnet',
    )).toEqual({
      messageHash: 'f0eb03b1a75ac6d9847f55c624a99169b5dccba2a31f5b23bea77ba270de0a7a',
      toSpendTxid: 'b79d196740ad5217771c1098fc4a4b51e0535c32236c71f1ea4d61a2d603352b',
      toSignTxid: '88737ae86f2077145f93cc4b153ae9a1cb8d56afa511988c149c5c8c9d93bddf',
    });
    expect(bytesToHex(bip322MessageHash(new TextEncoder().encode(''))))
      .toBe('c90c269c4f8fcbe6880f72a721ddfbf1914268a794cbb21cfafee13770ae19f1');
  });

  it('verifies current official P2WPKH and P2TR simple signatures', () => {
    expect(verifyBip322Simple(P2WPKH.message, P2WPKH.address, 'mainnet', P2WPKH.signature)).toBe(true);
    expect(verifyBip322Simple(P2TR.message, P2TR.address, 'mainnet', P2TR.signature)).toBe(true);
    expect(verifyBip322Simple(`wrong ${P2WPKH.message}`, P2WPKH.address, 'mainnet', P2WPKH.signature)).toBe(false);
    expect(verifyBip322Simple(P2TR.message, P2WPKH.address, 'mainnet', P2TR.signature)).toBe(false);
  });

  it('signs P2WPKH and P2TR with the required current simple prefix', () => {
    const paymentKey = WIF(NETWORK).decode(P2WPKH.wif);
    const ordinalKey = WIF(NETWORK).decode(P2TR.wif);
    try {
      const paymentAddress = p2wpkh(pubECDSA(paymentKey), NETWORK).address;
      const ordinalAddress = p2tr(pubECDSA(ordinalKey).slice(1), undefined, NETWORK).address;
      const paymentSignature = signBip322Simple({
        message: P2WPKH.message,
        privateKey: paymentKey,
        addressKind: 'payment',
        random: (length) => new Uint8Array(length),
      });
      const ordinalSignature = signBip322Simple({
        message: P2TR.message,
        privateKey: ordinalKey,
        addressKind: 'ordinals',
        random: (length) => new Uint8Array(length),
      });
      expect(paymentSignature.startsWith('smp')).toBe(true);
      expect(ordinalSignature.startsWith('smp')).toBe(true);
      expect(verifyBip322Simple(P2WPKH.message, paymentAddress!, 'mainnet', paymentSignature)).toBe(true);
      expect(verifyBip322Simple(P2TR.message, ordinalAddress!, 'mainnet', ordinalSignature)).toBe(true);
    } finally {
      paymentKey.fill(0);
      ordinalKey.fill(0);
    }
  });

  it('verifies both supported account scripts on signet', () => {
    const paymentKey = WIF(NETWORK).decode(P2WPKH.wif);
    const ordinalKey = WIF(NETWORK).decode(P2TR.wif);
    try {
      const cases = [
        {
          kind: 'payment' as const,
          key: paymentKey,
          address: p2wpkh(pubECDSA(paymentKey), TEST_NETWORK).address!,
        },
        {
          kind: 'ordinals' as const,
          key: ordinalKey,
          address: p2tr(pubECDSA(ordinalKey).slice(1), undefined, TEST_NETWORK).address!,
        },
      ];
      for (const item of cases) {
        const signature = signBip322Simple({
          message: 'Drey signet BIP322', privateKey: item.key,
          addressKind: item.kind, random: (length) => new Uint8Array(length),
        });
        expect(verifyBip322Simple('Drey signet BIP322', item.address, 'signet', signature)).toBe(true);
        expect(verifyBip322Simple('Drey signet BIP322', item.address, 'mainnet', signature)).toBe(false);
      }
    } finally {
      paymentKey.fill(0);
      ordinalKey.fill(0);
    }
  });

  it('requires the current prefix and rejects malformed or mutated witnesses', () => {
    expect(verifyBip322Simple(P2TR.message, P2TR.address, 'mainnet', P2TR.signature.slice(3))).toBe(false);
    expect(verifyBip322Simple(P2TR.message, P2TR.address, 'mainnet', 'smpnot-base64')).toBe(false);
    expect(verifyBip322Simple(P2TR.message, P2TR.address, 'mainnet', `${P2TR.signature.slice(0, -1)}A`)).toBe(false);
  });

  it('enforces Drey UTF-8 byte, NUL, control, and malformed-Unicode policy', () => {
    expect(validateBip322Message('line 1\n\tline 2')).toEqual(new TextEncoder().encode('line 1\n\tline 2'));
    expect(validateBip322Message('a'.repeat(BIP322_MAX_MESSAGE_BYTES))).toHaveLength(BIP322_MAX_MESSAGE_BYTES);
    expect(() => validateBip322Message('a'.repeat(BIP322_MAX_MESSAGE_BYTES + 1))).toThrow(/too large/u);
    expect(() => validateBip322Message('😀'.repeat(BIP322_MAX_MESSAGE_BYTES / 4 + 1))).toThrow(/too large/u);
    expect(() => validateBip322Message('nul\0byte')).toThrow(/control/u);
    expect(() => validateBip322Message('delete\u007f')).toThrow(/control/u);
    expect(() => validateBip322Message('\ud800')).toThrow(/UTF-16/u);
  });
});
