import { Address, TEST_NETWORK } from '@scure/btc-signer';
import { describe, expect, it } from 'vitest';
import {
  BIP321_LIMITS,
  bip321AmountToSats,
  buildBip321,
  parseBip321,
  selectBip321OnchainFallback,
} from '../../src/domain/payments/bip321';
import { buildBip21, parseBip21 } from '../../src/domain/payments/bip21';

const MAINNET = 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4';
const SIGNET = Address(TEST_NETWORK).encode({ type: 'wpkh', hash: new Uint8Array(20).fill(7) });

describe('BIP 321 generation', () => {
  it('preserves canonical ordinary address/amount/label/message generation', () => {
    expect(buildBip321({ address: MAINNET })).toBe(`bitcoin:${MAINNET}`);
    expect(buildBip321({
      address: MAINNET,
      amountSats: 250_000n,
      label: 'café & tips',
      message: 'For lunch',
    })).toBe(
      `bitcoin:${MAINNET}?amount=0.0025&label=caf%C3%A9%20%26%20tips&message=For%20lunch`,
    );
  });

  it('keeps the deprecated BIP 21 import as a generation/parser compatibility shim', () => {
    const uri = buildBip21({ address: MAINNET, amountSats: 1n });
    expect(uri).toBe(`bitcoin:${MAINNET}?amount=0.00000001`);
    expect(parseBip21(uri)).toEqual(parseBip321(uri));
  });

  it('bounds generated fields and rejects invalid path bodies', () => {
    expect(() => buildBip321({ address: '' })).toThrow(/address/u);
    expect(() => buildBip321({ address: `${MAINNET}?x` })).toThrow(/address/u);
    expect(() => buildBip321({ address: MAINNET, label: 'é'.repeat(129) })).toThrow(/256/u);
    expect(() => buildBip321({ address: MAINNET, message: 'm'.repeat(1025) })).toThrow(/1024/u);
  });
});

describe('BIP 321 parsing', () => {
  it('accepts mixed-case schemes and keys while preserving value/address case', () => {
    expect(parseBip321(
      `BITCOIN:${MAINNET.toUpperCase()}?AmOuNt=00.00100000&LaBeL=Luke&MeSsAgE=Hello`,
    )).toEqual({
      onchainFallback: { kind: 'onchain', source: 'path', address: MAINNET.toUpperCase() },
      alternatives: [],
      amountSats: 100_000n,
      label: 'Luke',
      message: 'Hello',
    });
  });

  it('accepts understood required metadata aliases', () => {
    expect(parseBip321(
      `bitcoin:${MAINNET}?REQ-AMOUNT=1.00&req-label=Receiver&Req-Message=Invoice`,
    )).toMatchObject({ amountSats: 100_000_000n, label: 'Receiver', message: 'Invoice' });
  });

  it('preserves duplicate supported and future alternatives independently and in order', () => {
    expect(parseBip321(
      'bitcoin:?LIGHTNING=ln-one&lightning=ln-two&bc=bc1future&Future=one&future=two',
    )).toEqual({
      alternatives: [
        { key: 'lightning', value: 'ln-one' },
        { key: 'lightning', value: 'ln-two' },
        { key: 'bc', value: 'bc1future' },
        { key: 'future', value: 'one' },
        { key: 'future', value: 'two' },
      ],
    });
  });

  it('allows empty paths only with a non-empty payment alternative', () => {
    expect(parseBip321('bitcoin:?sp=sp1placeholder')).toEqual({
      alternatives: [{ key: 'sp', value: 'sp1placeholder' }],
    });
    for (const invalid of [
      'bitcoin:',
      'bitcoin:?',
      'bitcoin:?amount=1',
      'bitcoin:?label=Only%20metadata',
      'bitcoin:?message=Only%20metadata&pop=callback%3A',
      'bitcoin:?lightning=',
    ]) {
      expect(() => parseBip321(invalid), invalid).toThrow(/no payment instructions/u);
    }
  });

  it('enforces singleton amount/label/message/pop across case and req aliases', () => {
    for (const duplicate of [
      'amount=1&AMOUNT=1',
      'amount=1&req-amount=1',
      'label=a&LABEL=b',
      'message=a&req-message=b',
      'pop=callback%3A&PoP=callback%3A',
    ]) {
      expect(() => parseBip321(`bitcoin:${MAINNET}?${duplicate}`), duplicate).toThrow(/duplicate/u);
    }
  });

  it('rejects every unsupported required parameter and always rejects req-pop', () => {
    for (const required of [
      'req-x=1',
      'REQ-LIGHTNING=ln',
      'req-sp=sp1x',
      'req-pop=callback%3A',
    ]) {
      expect(() => parseBip321(`bitcoin:${MAINNET}?${required}`), required)
        .toThrow(/unsupported required/u);
    }
  });

  it('strictly validates then discards optional pop without exposing a callback', () => {
    const parsed = parseBip321(`bitcoin:${MAINNET}?pop=callback%3A&label=Receiver`);
    expect(parsed).toEqual({
      onchainFallback: { kind: 'onchain', source: 'path', address: MAINNET },
      alternatives: [],
      label: 'Receiver',
    });
    expect(JSON.stringify(parsed)).not.toContain('callback');
    expect(() => parseBip321(`bitcoin:${MAINNET}?pop=%`)).toThrow(/percent/u);
  });

  it('rejects malformed percent encoding, invalid UTF-8, controls, fragments, and separators', () => {
    for (const invalid of [
      `bitcoin:${MAINNET}?label=%`,
      `bitcoin:${MAINNET}?label=%GG`,
      `bitcoin:${MAINNET}?label=%C3%28`,
      `bitcoin:${MAINNET}?label=line%0Abreak`,
      `bitcoin:${MAINNET}?label=raw value`,
      `bitcoin:${MAINNET}?message=a=b`,
      `bitcoin:${MAINNET}?label=x#fragment`,
    ]) {
      expect(() => parseBip321(invalid), invalid).toThrow(RangeError);
    }
  });

  it('parses amounts exactly without floating point or rounding', () => {
    expect(bip321AmountToSats('000')).toBe(0n);
    expect(bip321AmountToSats('50.00')).toBe(5_000_000_000n);
    expect(bip321AmountToSats('21000000')).toBe(2_100_000_000_000_000n);
    for (const invalid of [
      '', '.5', '1.', '-1', '+1', '1e-8', '1,000', '0.000000001',
      '21000000.00000001', '21000001',
    ]) {
      expect(() => bip321AmountToSats(invalid), invalid).toThrow(RangeError);
    }
  });

  it('enforces every encoded and decoded size/count bound', () => {
    expect(() => parseBip321(`bitcoin:${'a'.repeat(129)}`)).toThrow(/128/u);
    expect(() => parseBip321(`bitcoin:${MAINNET}?${'k'.repeat(65)}=v`)).toThrow(/64/u);
    expect(() => parseBip321(`bitcoin:${MAINNET}?amount=${'1'.repeat(33)}`)).toThrow(/32/u);
    expect(() => parseBip321(`bitcoin:${MAINNET}?label=${'a'.repeat(257)}`)).toThrow(/256/u);
    expect(() => parseBip321(`bitcoin:${MAINNET}?message=${'a'.repeat(1025)}`)).toThrow(/1024/u);
    expect(() => parseBip321(`bitcoin:${MAINNET}?future=${'a'.repeat(4097)}`)).toThrow(/4096/u);
    expect(() => parseBip321(
      `bitcoin:${MAINNET}?${Array.from({ length: 65 }, (_, i) => `x${i}=1`).join('&')}`,
    )).toThrow(/64 parameters/u);
    expect(() => parseBip321(`bitcoin:${MAINNET}?x=${'a'.repeat(BIP321_LIMITS.uriBytes)}`))
      .toThrow(/8192/u);
    expect(() => parseBip321(`bitcoin:${MAINNET}?label=${'%C3%A9'.repeat(129)}`))
      .toThrow(/256/u);
  });
});

describe('BIP 321 fallback selection', () => {
  it('selects only a valid path fallback for the configured network', () => {
    expect(selectBip321OnchainFallback(
      parseBip321(`bitcoin:${SIGNET}?lightning=ln-unsupported`),
      'signet',
    )).toMatchObject({ ok: true, value: { address: SIGNET, scriptKind: 'p2wpkh' } });
  });

  it('distinguishes unsupported-only, wrong-network, invalid, and unsupported output types', () => {
    expect(selectBip321OnchainFallback(parseBip321('bitcoin:?lightning=ln'), 'signet'))
      .toEqual({ ok: false, reason: 'no_supported_payment_method' });
    expect(selectBip321OnchainFallback(parseBip321(`bitcoin:${MAINNET}`), 'signet'))
      .toEqual({ ok: false, reason: 'wrong_network' });
    expect(selectBip321OnchainFallback(parseBip321('bitcoin:notanaddress'), 'signet'))
      .toEqual({ ok: false, reason: 'invalid_address' });
    expect(selectBip321OnchainFallback(parseBip321('bitcoin:BC1SW50QGDZ25J'), 'mainnet'))
      .toEqual({ ok: false, reason: 'unsupported_output_type' });
  });
});
