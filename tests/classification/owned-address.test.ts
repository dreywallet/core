import { HDKey } from '@scure/bip32';
import { Address, NETWORK, OutScript, TEST_NETWORK } from '@scure/btc-signer';
import { describe, expect, it } from 'vitest';
import {
  createOwnedAddressResolver,
  ownedAddressFromUtxo,
  ownedAddressRole,
  summarizeRecoveredAddresses,
} from '../../src/domain/classification/owned-address';
import type { WalletUtxo } from '../../src/domain/classification/types';
import {
  deriveAccountNode,
  deriveAddress,
} from '../../src/domain/keys/derivation';
import {
  deriveLegacyAddress,
  legacyAccountPath,
  xverseManifest,
} from '../../src/domain/keys/legacy-manifests';
import { mnemonicToSeed } from '../../src/domain/keys/mnemonic';
import { bytesToHex } from '../../src/domain/vault/encoding';

const MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const seed = mnemonicToSeed(MNEMONIC);
const ACCOUNT_A = `acct_mainnet_${'a'.repeat(64)}`;
const ACCOUNT_B = `acct_mainnet_${'b'.repeat(64)}`;

function utxo(overrides: Partial<WalletUtxo> = {}): WalletUtxo {
  return {
    outpoint: { txid: 'a'.repeat(64), vout: 0 },
    valueSats: 10_000n,
    scriptPubKey: `0014${'1'.repeat(40)}`,
    accountId: ACCOUNT_A,
    account: 0,
    lane: 'payment',
    chain: 0,
    addressIndex: 0,
    height: 1,
    walletCreatedChange: false,
    facts: null,
    flags: { userFrozen: false, dustQuarantined: false },
    ...overrides,
  };
}

function standardScript(
  lane: WalletUtxo['lane'],
  network: 'mainnet' | 'signet',
  chain: 0 | 1,
  index: number,
): string {
  const address = deriveAddress(
    deriveAccountNode(seed, lane, network, 0),
    lane,
    network,
    chain,
    index,
  ).address;
  const codec = Address(network === 'mainnet' ? NETWORK : TEST_NETWORK);
  return bytesToHex(OutScript.encode(codec.decode(address)));
}

describe('owned-address presentation metadata', () => {
  it('classifies only higher stable external indexes as recovered', () => {
    expect(ownedAddressRole(utxo({ chain: 0, addressIndex: 0 }), 'stable')).toBe('primary');
    expect(ownedAddressRole(utxo({ chain: 0, addressIndex: 1 }), 'stable')).toBe('recovered');
    expect(ownedAddressRole(utxo({ chain: 1, addressIndex: 18 }), 'stable')).toBe('change');
  });

  it('round-trips native SegWit and Taproot scripts on mainnet and signet', () => {
    const cases = [
      {
        lane: 'payment' as const,
        network: 'mainnet' as const,
        chain: 0 as const,
        index: 0,
        prefix: 'bc1q',
        role: 'primary' as const,
      },
      {
        lane: 'ordinals' as const,
        network: 'mainnet' as const,
        chain: 0 as const,
        index: 1,
        prefix: 'bc1p',
        role: 'recovered' as const,
      },
      {
        lane: 'payment' as const,
        network: 'signet' as const,
        chain: 1 as const,
        index: 0,
        prefix: 'tb1q',
        role: 'change' as const,
      },
      {
        lane: 'ordinals' as const,
        network: 'signet' as const,
        chain: 0 as const,
        index: 1,
        prefix: 'tb1p',
        role: 'recovered' as const,
      },
    ];
    for (const testCase of cases) {
      const ownership = ownedAddressFromUtxo(utxo({
        lane: testCase.lane,
        chain: testCase.chain,
        addressIndex: testCase.index,
        scriptPubKey: standardScript(
          testCase.lane,
          testCase.network,
          testCase.chain,
          testCase.index,
        ),
      }), testCase.network);
      expect(ownership.address.startsWith(testCase.prefix)).toBe(true);
      expect(ownership).toMatchObject({
        lane: testCase.lane,
        role: testCase.role,
      });
    }
  });

  it('encodes a recovered nested-SegWit payment script without claiming its source', () => {
    const entry = xverseManifest('signet').entries.find(
      (candidate) => candidate.id === 'xverse-nested-payment',
    );
    expect(entry).toBeDefined();
    const node = HDKey.fromMasterSeed(seed).derive(legacyAccountPath(entry!, 'signet'));
    const legacy = deriveLegacyAddress(node, entry!, 'signet', 0, 1);
    expect(ownedAddressFromUtxo(utxo({
      scriptPubKey: legacy.scriptPubKeyHex,
      addressIndex: 1,
    }), 'signet')).toEqual({
      address: legacy.address,
      lane: 'payment',
      role: 'recovered',
    });
    expect(legacy.address.startsWith('2')).toBe(true);
  });

  it('rejects malformed or unsupported cached scripts as stale', () => {
    expect(() => ownedAddressFromUtxo(utxo({ scriptPubKey: '00' }), 'mainnet')).toThrow();
    expect(() => ownedAddressFromUtxo(utxo({ scriptPubKey: 'zz' }), 'mainnet')).toThrow();
  });

  it('reuses one script derivation across a large synthetic gallery and rejects contradictions', () => {
    const scriptPubKey = standardScript('ordinals', 'signet', 0, 1);
    const resolve = createOwnedAddressResolver('signet');
    const entries = Array.from({ length: 4_096 }, (_unused, index) => utxo({
      outpoint: { txid: index.toString(16).padStart(64, '0'), vout: index },
      lane: 'ordinals',
      addressIndex: 1,
      scriptPubKey,
    }));
    const ownership = entries.map(resolve);
    expect(new Set(ownership).size).toBe(1);
    expect(ownership[0]).toMatchObject({ lane: 'ordinals', role: 'recovered' });
    expect(summarizeRecoveredAddresses(entries)).toEqual([
      { accountId: ACCOUNT_A, account: 0, payment: 0, ordinals: 1 },
    ]);
    expect(() => resolve(utxo({
      lane: 'payment',
      addressIndex: 1,
      scriptPubKey,
    }))).toThrow(/inconsistent/u);
  });

  it('counts each recovered script once per account and lane, in account order', () => {
    const payment = standardScript('payment', 'mainnet', 0, 1);
    const ordinals = standardScript('ordinals', 'mainnet', 0, 1);
    const recovered = [
      utxo({ accountId: ACCOUNT_B, account: 4, lane: 'ordinals', addressIndex: 1,
        scriptPubKey: ordinals }),
      utxo({ account: 1, lane: 'payment', addressIndex: 1, scriptPubKey: payment }),
      utxo({
        outpoint: { txid: 'b'.repeat(64), vout: 1 },
        account: 1,
        lane: 'payment',
        addressIndex: 1,
        scriptPubKey: payment,
      }),
      utxo({
        account: 1,
        lane: 'payment',
        chain: 1,
        addressIndex: 1,
        scriptPubKey: standardScript('payment', 'mainnet', 1, 1),
      }),
    ];
    expect(summarizeRecoveredAddresses(recovered)).toEqual([
      { accountId: ACCOUNT_A, account: 1, payment: 1, ordinals: 0 },
      { accountId: ACCOUNT_B, account: 4, payment: 0, ordinals: 1 },
    ]);
    expect(summarizeRecoveredAddresses(recovered.slice(0, 1))).toEqual([
      { accountId: ACCOUNT_B, account: 4, payment: 0, ordinals: 1 },
    ]);
    expect(summarizeRecoveredAddresses([])).toEqual([]);
  });

  it('keeps same-index public accounts separate and requires stable identity', () => {
    const scriptA = standardScript('payment', 'mainnet', 0, 1);
    const scriptB = standardScript('payment', 'mainnet', 0, 2);
    expect(summarizeRecoveredAddresses([
      utxo({ accountId: ACCOUNT_B, account: 0, addressIndex: 1, scriptPubKey: scriptB }),
      utxo({ accountId: ACCOUNT_A, account: 0, addressIndex: 1, scriptPubKey: scriptA }),
    ])).toEqual([
      { accountId: ACCOUNT_A, account: 0, payment: 1, ordinals: 0 },
      { accountId: ACCOUNT_B, account: 0, payment: 1, ordinals: 0 },
    ]);
    expect(() => summarizeRecoveredAddresses([
      utxo({ accountId: undefined, addressIndex: 1, scriptPubKey: scriptA }),
    ])).toThrow('lacks stable public account identity');
    expect(() => summarizeRecoveredAddresses([
      utxo({ accountId: ACCOUNT_A, account: 0, addressIndex: 1, scriptPubKey: scriptA }),
      utxo({ accountId: ACCOUNT_A, account: 1, addressIndex: 1, scriptPubKey: scriptB }),
    ])).toThrow('inconsistent account index');
  });
});
