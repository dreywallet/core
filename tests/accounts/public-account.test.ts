import { HDKey } from '@scure/bip32';
import { describe, expect, it } from 'vitest';
import {
  canonicalPublicDescriptor,
  derivePublicAccountAddress,
  parsePublicAccountDescriptors,
  parsePublicDescriptor,
  publicAccountDefinitionSchema,
  publicAccountFromSeed,
  publicAccountsMatch,
} from '../../src/domain/accounts/public-account';
import { descriptorChecksum } from '../../src/domain/keys/descriptor-checksum';
import { accountPath, deriveAccountNode, deriveAddress } from '../../src/domain/keys/derivation';
import { bip32Versions } from '../../src/domain/keys/extended-key';

const SEED = Uint8Array.from({ length: 32 }, (_, index) => index + 1);

function withChecksum(payload: string): string {
  return `${payload}#${descriptorChecksum(payload)}`;
}

function descriptors(network: 'mainnet' | 'signet' = 'signet', accountIndex = 0) {
  const definition = publicAccountFromSeed(SEED, network, accountIndex);
  return {
    definition,
    input: {
      network,
      paymentReceiveDescriptor: definition.lanes.payment.receiveDescriptor,
      paymentChangeDescriptor: definition.lanes.payment.changeDescriptor,
      ordinalsReceiveDescriptor: definition.lanes.ordinals.receiveDescriptor,
      ordinalsChangeDescriptor: definition.lanes.ordinals.changeDescriptor,
    },
  } as const;
}

describe('closed public account descriptors', () => {
  it.each(['mainnet', 'signet'] as const)(
    'derives the same %s addresses as the corresponding software account',
    (network) => {
      const { definition, input } = descriptors(network, 7);
      expect(parsePublicAccountDescriptors(input)).toEqual(definition);
      expect(publicAccountDefinitionSchema.parse(definition)).toEqual(definition);
      expect(definition.accountId).toMatch(new RegExp(`^acct_${network}_`, 'u'));

      for (const lane of ['payment', 'ordinals'] as const) {
        const software = deriveAccountNode(SEED, lane, network, 7);
        try {
          for (const chain of [0, 1] as const) {
            for (const index of [0, 1, 21]) {
              const expected = deriveAddress(software, lane, network, chain, index);
              const watched = derivePublicAccountAddress(definition, lane, chain, index);
              expect(watched).toMatchObject({
                accountId: definition.accountId,
                accountIndex: 7,
                lane,
                chain,
                index,
                address: expected.address,
                path: expected.path,
                publicKeyHex: expected.publicKeyHex,
              });
            }
          }
        } finally {
          software.wipePrivateData();
        }
      }
    },
  );

  it('keeps signer attachment equality exact across every public field', () => {
    const { definition } = descriptors();
    expect(publicAccountsMatch(definition, structuredClone(definition))).toBe(true);
    const changed = structuredClone(definition);
    changed.lanes.payment.origin.masterFingerprintHex = '00000000';
    expect(publicAccountsMatch(definition, changed)).toBe(false);
  });

  it('does not let unverifiable fingerprint aliases create a second storage identity', () => {
    const { definition, input } = descriptors();
    const replaceFingerprint = (descriptor: string) => {
      const payload = descriptor.slice(0, -9).replace(
        definition.lanes.payment.origin.masterFingerprintHex,
        '00000000',
      );
      return withChecksum(payload);
    };
    const alias = parsePublicAccountDescriptors({
      network: input.network,
      paymentReceiveDescriptor: replaceFingerprint(input.paymentReceiveDescriptor),
      paymentChangeDescriptor: replaceFingerprint(input.paymentChangeDescriptor),
      ordinalsReceiveDescriptor: replaceFingerprint(input.ordinalsReceiveDescriptor),
      ordinalsChangeDescriptor: replaceFingerprint(input.ordinalsChangeDescriptor),
    });
    expect(alias.accountId).toBe(definition.accountId);
    expect(publicAccountsMatch(alias, definition)).toBe(false);
  });

  it('requires checksums and rejects checksum mutation', () => {
    const { input } = descriptors();
    const descriptor = input.paymentReceiveDescriptor;
    expect(() => parsePublicDescriptor(descriptor.slice(0, -9), 'signet')).toThrow('checksummed');
    const replacement = descriptor.endsWith('q') ? 'p' : 'q';
    expect(() => parsePublicDescriptor(`${descriptor.slice(0, -1)}${replacement}`, 'signet'))
      .toThrow('checksum');
  });

  it('rejects wrong-network, mixed-network, and mismatched origin metadata', () => {
    const signet = descriptors('signet').input;
    const mainnet = descriptors('mainnet').input;
    expect(() => parsePublicDescriptor(signet.paymentReceiveDescriptor, 'mainnet')).toThrow('network');
    expect(() => parsePublicAccountDescriptors({
      ...signet,
      ordinalsReceiveDescriptor: mainnet.ordinalsReceiveDescriptor,
    })).toThrow('network');

    const foreign = descriptors('signet', 1).input;
    expect(() => parsePublicAccountDescriptors({
      ...signet,
      ordinalsReceiveDescriptor: foreign.ordinalsReceiveDescriptor,
      ordinalsChangeDescriptor: foreign.ordinalsChangeDescriptor,
    })).toThrow('account indexes');
  });

  it('rejects private extended keys and non-account-level public keys', () => {
    const { input } = descriptors();
    const root = HDKey.fromMasterSeed(SEED, bip32Versions('signet'));
    const account = root.derive(accountPath('payment', 'signet', 0));
    try {
      const xpub = account.publicExtendedKey;
      const xprv = account.privateExtendedKey;
      const privateDescriptor = withChecksum(
        input.paymentReceiveDescriptor.slice(0, -9).replace(xpub, xprv),
      );
      expect(() => parsePublicDescriptor(privateDescriptor, 'signet')).toThrow('public');

      const rootXpub = HDKey.fromExtendedKey(root.publicExtendedKey, bip32Versions('signet'));
      const shallowDescriptor = withChecksum(
        input.paymentReceiveDescriptor.slice(0, -9).replace(xpub, rootXpub.publicExtendedKey),
      );
      expect(() => parsePublicDescriptor(shallowDescriptor, 'signet')).toThrow('account-level');
    } finally {
      account.wipePrivateData();
      root.wipePrivateData();
    }
  });

  it.each([
    ['pkh', 'wpkh'],
    ['sh(wpkh', 'wpkh'],
    ['wsh', 'wpkh'],
    ['combo', 'wpkh'],
    ['multi', 'wpkh'],
  ] as const)('rejects unsupported %s descriptor fragments', (replacement, original) => {
    const { input } = descriptors();
    const payload = input.paymentReceiveDescriptor.slice(0, -9).replace(original, replacement);
    expect(() => parsePublicDescriptor(withChecksum(payload), 'signet')).toThrow('unsupported');
  });

  it('rejects fixed, non-ranged, hardened-wildcard, and swapped branch descriptors', () => {
    const { input } = descriptors();
    const receivePayload = input.paymentReceiveDescriptor.slice(0, -9);
    for (const suffix of ['/0/0', '/0/*h', '/*']) {
      const mutated = receivePayload.replace('/0/*', suffix);
      expect(() => parsePublicDescriptor(withChecksum(mutated), 'signet')).toThrow('unsupported');
    }
    expect(() => parsePublicAccountDescriptors({
      ...input,
      paymentReceiveDescriptor: input.paymentChangeDescriptor,
    })).toThrow('swapped');
  });

  it('rejects a purpose/script mismatch and non-canonical origin spelling', () => {
    const { input } = descriptors();
    const payload = input.paymentReceiveDescriptor.slice(0, -9);
    expect(() => parsePublicDescriptor(withChecksum(payload.replace('/84h/', '/86h/')), 'signet'))
      .toThrow('purpose');
    expect(() => parsePublicDescriptor(withChecksum(payload.replace('/84h/', "/84'/")), 'signet'))
      .toThrow('unsupported');
  });

  it('generates canonical public-only descriptors from explicit origins', () => {
    const { definition } = descriptors('mainnet', 3);
    const origin = definition.lanes.payment.origin;
    expect(canonicalPublicDescriptor('payment', 'mainnet', 3, origin, 0))
      .toBe(definition.lanes.payment.receiveDescriptor);
  });
});
