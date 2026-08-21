/**
 * spec §24.1: BIP84 and BIP86 mainnet/signet derivation. Mainnet vectors are
 * the published BIP84/BIP86 test vectors (same constants the §5.3 prototype
 * proved against both stacks); signet has no published vectors, so those tests
 * pin prefix, determinism, and mainnet inequality.
 */
import { describe, expect, it } from 'vitest';
import { mnemonicToSeed } from '../../src/domain/keys/mnemonic';
import {
  BIP32_MAX_INDEX,
  accountPath,
  deriveAccountNode,
  deriveAddress,
  stableExternalAddress,
} from '../../src/domain/keys/derivation';

const MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
// BIP84 vector: m/84'/0'/0'/0/0
const BIP84_ADDR0 = 'bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu';
// BIP86 vector: m/86'/0'/0'/0/0
const BIP86_ADDR0 = 'bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr';

const seed = mnemonicToSeed(MNEMONIC);

describe('accountPath', () => {
  it('builds the four spec §8.1 account paths', () => {
    expect(accountPath('payment', 'mainnet', 0)).toBe("m/84'/0'/0'");
    expect(accountPath('ordinals', 'mainnet', 3)).toBe("m/86'/0'/3'");
    expect(accountPath('payment', 'signet', 1)).toBe("m/84'/1'/1'");
    expect(accountPath('ordinals', 'signet', 0)).toBe("m/86'/1'/0'");
    expect(accountPath('payment', 'regtest', 0)).toBe("m/84'/1'/0'");
  });

  it('rejects negative or fractional account indexes', () => {
    expect(() => accountPath('payment', 'mainnet', -1)).toThrow();
    expect(() => accountPath('payment', 'mainnet', 1.5)).toThrow();
  });

  it('accepts the last BIP32 account index and rejects hardened/unsafe values', () => {
    expect(accountPath('payment', 'mainnet', BIP32_MAX_INDEX)).toBe(
      "m/84'/0'/2147483647'",
    );
    expect(() => accountPath('payment', 'mainnet', BIP32_MAX_INDEX + 1)).toThrow();
    expect(() => accountPath('payment', 'mainnet', Number.MAX_SAFE_INTEGER + 1)).toThrow();
  });
});

describe('mainnet vectors', () => {
  it('derives the BIP84 vector address', () => {
    const info = stableExternalAddress(seed, 'payment', 'mainnet', 0);
    expect(info.address).toBe(BIP84_ADDR0);
    expect(info.path).toBe("m/84'/0'/0'/0/0");
  });

  it('derives the BIP86 vector address', () => {
    const info = stableExternalAddress(seed, 'ordinals', 'mainnet', 0);
    expect(info.address).toBe(BIP86_ADDR0);
    expect(info.path).toBe("m/86'/0'/0'/0/0");
  });
});

describe('signet derivation', () => {
  it('derives tb1q payment and tb1p ordinal addresses, distinct from mainnet', () => {
    const payment = stableExternalAddress(seed, 'payment', 'signet', 0);
    const ordinals = stableExternalAddress(seed, 'ordinals', 'signet', 0);
    expect(payment.address.startsWith('tb1q')).toBe(true);
    expect(ordinals.address.startsWith('tb1p')).toBe(true);
    expect(payment.path).toBe("m/84'/1'/0'/0/0");
    expect(payment.address).not.toBe(BIP84_ADDR0);
    expect(ordinals.address).not.toBe(BIP86_ADDR0);
  });

  it('is deterministic', () => {
    expect(stableExternalAddress(seed, 'payment', 'signet', 0)).toEqual(
      stableExternalAddress(seed, 'payment', 'signet', 0),
    );
  });
});

describe('regtest derivation', () => {
  it('uses test coin type 1 with the distinct bcrt address encoding', () => {
    const payment = stableExternalAddress(seed, 'payment', 'regtest', 0);
    const ordinals = stableExternalAddress(seed, 'ordinals', 'regtest', 0);
    expect(payment.address.startsWith('bcrt1q')).toBe(true);
    expect(ordinals.address.startsWith('bcrt1p')).toBe(true);
    expect(payment.path).toBe("m/84'/1'/0'/0/0");
    expect(payment.address).not.toBe(stableExternalAddress(seed, 'payment', 'signet', 0).address);
  });
});

describe('address derivation details', () => {
  it('stable external address is chain 0 index 0 of the account node', () => {
    const node = deriveAccountNode(seed, 'payment', 'mainnet', 0);
    expect(deriveAddress(node, 'payment', 'mainnet', 0, 0).address).toBe(BIP84_ADDR0);
  });

  it('change chain and higher indexes derive distinct addresses', () => {
    const node = deriveAccountNode(seed, 'payment', 'mainnet', 0);
    const external0 = deriveAddress(node, 'payment', 'mainnet', 0, 0);
    const external1 = deriveAddress(node, 'payment', 'mainnet', 0, 1);
    const change0 = deriveAddress(node, 'payment', 'mainnet', 1, 0);
    expect(new Set([external0.address, external1.address, change0.address]).size).toBe(3);
    expect(change0.path).toBe("m/84'/0'/0'/1/0");
  });

  it('accounts beyond 0 derive distinct addresses', () => {
    expect(stableExternalAddress(seed, 'payment', 'mainnet', 1).address).not.toBe(BIP84_ADDR0);
  });

  it('rejects nodes that are not hardened account-level keys', async () => {
    const { HDKey } = await import('@scure/bip32');
    const root = HDKey.fromMasterSeed(seed); // depth 0
    expect(() => deriveAddress(root, 'payment', 'mainnet', 0, 0)).toThrow(/account-level/u);

    const nonHardened = root.derive('m/84/0/0'); // depth 3 but not hardened
    expect(() => deriveAddress(nonHardened, 'payment', 'mainnet', 0, 0)).toThrow(/account-level/u);

    const tooDeep = deriveAccountNode(seed, 'payment', 'mainnet', 0).deriveChild(0); // depth 4
    expect(() => deriveAddress(tooDeep, 'payment', 'mainnet', 0, 0)).toThrow(/account-level/u);
  });

  it('reports the correct account index in the path for higher accounts', () => {
    const info = stableExternalAddress(seed, 'ordinals', 'mainnet', 5);
    expect(info.path).toBe("m/86'/0'/5'/0/0");
  });

  it('never interprets an address index as a hardened child', () => {
    const node = deriveAccountNode(seed, 'payment', 'mainnet', 0);
    expect(deriveAddress(node, 'payment', 'mainnet', 0, BIP32_MAX_INDEX).path).toBe(
      "m/84'/0'/0'/0/2147483647",
    );
    expect(() => deriveAddress(node, 'payment', 'mainnet', 0, BIP32_MAX_INDEX + 1)).toThrow();
    expect(() => deriveAddress(node, 'payment', 'mainnet', 0, Number.NaN)).toThrow();
  });
});
