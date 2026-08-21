import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { beforeAll, describe, expect, it } from 'vitest';
import { installTestCryptoProvider } from '../helpers/install-crypto-provider';
import {
  descriptorChecksum,
  type VaultPolicyIdentityV1,
  type VaultPolicyRecordV1,
} from '../../src/domain/vault/multisig-contracts';
import {
  assertVaultDescriptorPolicy,
  assertVaultOwnership,
  deriveVaultOutput,
  generateVaultDescriptors,
  generateVaultPolicyIdentity,
  parseCanonicalVaultDescriptor,
  parseCanonicalVaultPolicyDescriptors,
  validateVaultPolicyRecordDescriptors,
  vaultDerivedOutputSchema,
  verifyVaultOwnership,
  type VaultDerivedOutputV1,
} from '../../src/domain/vault/multisig-descriptors';

interface B0Record {
  policy: VaultPolicyIdentityV1;
  policyRecord: VaultPolicyRecordV1;
}

interface B1Record {
  network: 'mainnet' | 'signet';
  policyId: string;
  birthdayHeight: number;
  receiveDescriptor: string;
  changeDescriptor: string;
  outputs: VaultDerivedOutputV1[];
}

const b0 = JSON.parse(
  readFileSync(join(import.meta.dirname, '..', '..', 'vectors', 'vault-contracts-v1.json'), 'utf8'),
) as { records: { mainnet: B0Record; signet: B0Record } };
const b1 = JSON.parse(
  readFileSync(join(import.meta.dirname, '..', '..', 'vectors', 'vault-descriptors-v1.json'), 'utf8'),
) as {
  vectorVersion: number;
  externalReference: { implementation: string; offlineRpcs: string[] };
  records: { mainnet: B1Record; signet: B1Record };
};

beforeAll(() => installTestCryptoProvider());

function payload(descriptor: string): string {
  return descriptor.slice(0, -9);
}

function checksummed(value: string): string {
  return `${value}#${descriptorChecksum(value)}`;
}

function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

function keyExpressions(descriptor: string): string[] {
  const value = payload(descriptor);
  return value.slice('wsh(sortedmulti(2,'.length, -2).split(',');
}

function descriptorFromKeys(keys: readonly string[]): string {
  return checksummed(`wsh(sortedmulti(2,${keys.join(',')}))`);
}

describe('ADR 0007 B1 canonical Vault descriptors', () => {
  it.each(['mainnet', 'signet'] as const)(
    'generates and parses the identical established B0 %s policy identity',
    (network) => {
      const established = b0.records[network].policy;
      const generated = generateVaultPolicyIdentity(network, established.signers);
      expect(generated).toEqual(established);
      expect(generateVaultDescriptors(established)).toEqual({
        version: 1,
        network,
        policyId: established.policyId,
        receiveDescriptor: established.receiveDescriptor,
        changeDescriptor: established.changeDescriptor,
      });
      expect(parseCanonicalVaultPolicyDescriptors(
        established.receiveDescriptor,
        established.changeDescriptor,
      )).toEqual(established);
      expect(() => assertVaultDescriptorPolicy(established)).not.toThrow();

      const record = validateVaultPolicyRecordDescriptors(b0.records[network].policyRecord);
      expect(record).toEqual(b0.records[network].policyRecord);
      expect(record.metadata.birthdayHeight).toBe(b1.records[network].birthdayHeight);
      expect(record.identity.policyId).toBe(b1.records[network].policyId);
    },
  );

  it('binds test-key descriptors to regtest policy identity and bcrt outputs', () => {
    const signet = b0.records.signet.policy;
    const signers = signet.signers.map((signer) => ({ ...signer, network: 'regtest' as const }));
    const policy = generateVaultPolicyIdentity('regtest', signers);
    expect(policy.policyId).not.toBe(signet.policyId);
    expect(policy.receiveDescriptor).toBe(signet.receiveDescriptor);
    expect(parseCanonicalVaultPolicyDescriptors(
      policy.receiveDescriptor,
      policy.changeDescriptor,
      'regtest',
    )).toEqual(policy);
    expect(() => assertVaultDescriptorPolicy(policy)).not.toThrow();
    expect(deriveVaultOutput(policy, 'receive', 0).address.startsWith('bcrt1q')).toBe(true);
  });

  it.each(['mainnet', 'signet'] as const)(
    'pins stable %s @scure outputs cross-checked by Bitcoin Core',
    (network) => {
      expect(b1.vectorVersion).toBe(1);
      expect(b1.externalReference.implementation).toBe('Bitcoin Core v30.2.0');
      expect(b1.externalReference.offlineRpcs).toEqual([
        'getdescriptorinfo', 'deriveaddresses', 'createmultisig', 'validateaddress',
      ]);
      const policy = b0.records[network].policy;
      const vector = b1.records[network];
      expect(vector.receiveDescriptor).toBe(policy.receiveDescriptor);
      expect(vector.changeDescriptor).toBe(policy.changeDescriptor);
      for (const expected of vector.outputs) {
        const first = deriveVaultOutput(policy, expected.branch, expected.index);
        const regenerated = deriveVaultOutput(policy, expected.branch, expected.index);
        expect(first).toEqual(expected);
        expect(regenerated).toEqual(expected);
        expect(assertVaultOwnership(policy, expected)).toEqual(expected);
        expect(verifyVaultOwnership(policy, expected)).toBe(true);
        expect(expected.address.startsWith(network === 'mainnet' ? 'bc1q' : 'tb1q')).toBe(true);
        expect(expected.scriptPubKeyHex).toMatch(/^0020[0-9a-f]{64}$/u);
      }
    },
  );

  it('keeps logical A/B/C source order separate from BIP67 script order', () => {
    const output = b1.records.mainnet.outputs[0]!;
    expect(output.logicalKeys.map((key) => key.role)).toEqual(['desktop-a', 'mobile-b', 'recovery-c']);
    const sorted = [...output.logicalKeys.map((key) => key.publicKeyHex)].sort();
    expect(output.bip67SortedPublicKeysHex).toEqual(sorted);
    expect(output.witnessScriptHex).toBe(
      `52${sorted.map((key) => `21${key}`).join('')}53ae`,
    );
  });

  it('rejects missing, invalid, retained, and non-canonical checksums/normalizations', () => {
    const descriptor = b0.records.mainnet.policy.receiveDescriptor;
    expect(() => parseCanonicalVaultDescriptor(payload(descriptor))).toThrow('checksummed');
    expect(() => parseCanonicalVaultDescriptor(`${payload(descriptor)}#aaaaaaaa`)).toThrow('checksum mismatch');
    expect(() => parseCanonicalVaultDescriptor(`${descriptor}x`)).toThrow();
    expect(() => parseCanonicalVaultDescriptor(checksummed(`${payload(descriptor)} `))).toThrow('fragment');
    expect(() => parseCanonicalVaultDescriptor(checksummed(
      payload(descriptor).replace('/48h/0h/0h/2h', "/48'/0'/0'/2'"),
    ))).toThrow('key expression');
    expect(() => parseCanonicalVaultDescriptor(checksummed(
      payload(descriptor).replace('/0/*', '/0h/*'),
    ))).toThrow('key expression');
    expect(() => parseCanonicalVaultDescriptor(checksummed(
      payload(descriptor).replace('/0/*', '/0/0'),
    ))).toThrow('key expression');
    expect(() => parseCanonicalVaultDescriptor(checksummed(
      payload(descriptor).replace('/0/*', '/0/*h'),
    ))).toThrow('key expression');
  });

  it('rejects every descriptor fragment and key family outside compile-time policy v1', () => {
    const descriptor = b0.records.mainnet.policy.receiveDescriptor;
    const base = payload(descriptor);
    const firstKey = keyExpressions(descriptor)[0]!;
    const unsupported = [
      `sh(${base})`,
      base.replace('wsh(sortedmulti(2,', 'wsh(multi(2,'),
      base.replace('wsh(sortedmulti(2,', 'wsh(sortedmulti(3,'),
      `tr(${firstKey})`,
      `wsh(and_v(v:pk(${firstKey}),older(10)))`,
    ];
    for (const value of unsupported) {
      expect(() => parseCanonicalVaultDescriptor(checksummed(value))).toThrow();
    }

    const uncompressed = `04${'11'.repeat(64)}`;
    const privateKeyExpression = firstKey.replace(/xpub[1-9A-HJ-NP-Za-km-z]+/u, `xprv${'1'.repeat(107)}`);
    expect(() => parseCanonicalVaultDescriptor(descriptorFromKeys([
      firstKey.replace(/xpub[1-9A-HJ-NP-Za-km-z]+/u, uncompressed),
      ...keyExpressions(descriptor).slice(1),
    ]))).toThrow('key expression');
    expect(() => parseCanonicalVaultDescriptor(descriptorFromKeys([
      privateKeyExpression,
      ...keyExpressions(descriptor).slice(1),
    ]))).toThrow();
  });

  it('rejects reordered policy sources, duplicate/substituted keys, wrong origins, networks, and branches', () => {
    const mainnet = b0.records.mainnet.policy;
    const signet = b0.records.signet.policy;
    const receiveKeys = keyExpressions(mainnet.receiveDescriptor);
    const changeKeys = keyExpressions(mainnet.changeDescriptor);

    expect(() => parseCanonicalVaultDescriptor(descriptorFromKeys([
      receiveKeys[0]!, receiveKeys[0]!, receiveKeys[2]!,
    ]))).toThrow('duplicate');
    expect(() => parseCanonicalVaultPolicyDescriptors(
      mainnet.receiveDescriptor,
      mainnet.receiveDescriptor,
    )).toThrow('swapped or duplicated');
    expect(() => parseCanonicalVaultPolicyDescriptors(
      mainnet.receiveDescriptor,
      signet.changeDescriptor,
    )).toThrow('one complete policy');
    expect(() => parseCanonicalVaultDescriptor(descriptorFromKeys([
      receiveKeys[0]!, changeKeys[1]!, receiveKeys[2]!,
    ]))).toThrow('mixed Vault descriptor branches');

    const reorderedPolicy = {
      ...mainnet,
      receiveDescriptor: descriptorFromKeys([receiveKeys[1]!, receiveKeys[0]!, receiveKeys[2]!]),
      changeDescriptor: descriptorFromKeys([changeKeys[1]!, changeKeys[0]!, changeKeys[2]!]),
    };
    expect(() => assertVaultDescriptorPolicy(reorderedPolicy)).toThrow();

    expect(() => parseCanonicalVaultDescriptor(checksummed(
      payload(mainnet.receiveDescriptor).replace('/48h/0h/0h/2h', '/48h/0h/1h/2h'),
    ))).toThrow('key expression');
    expect(() => parseCanonicalVaultDescriptor(checksummed(
      payload(mainnet.receiveDescriptor).replace(mainnet.signers[0].accountXpub, signet.signers[0].accountXpub),
    ))).toThrow('network-appropriate');
  });

  it('rejects malformed and out-of-range public child derivations', () => {
    const policy = b0.records.signet.policy;
    expect(() => deriveVaultOutput(policy, 'receive', -1)).toThrow('invalid Vault derivation index');
    expect(() => deriveVaultOutput(policy, 'receive', 0x8000_0000)).toThrow('invalid Vault derivation index');
    expect(() => deriveVaultOutput(policy, 'receive', 1.5)).toThrow('invalid Vault derivation index');
    expect(() => deriveVaultOutput(policy, 'future' as 'receive', 0)).toThrow();
  });
});

describe('ADR 0007 B1 complete-policy ownership', () => {
  it('rejects reordered, duplicated, substituted, foreign-network, wrong-branch, and wrong-index keys', () => {
    const policy = b0.records.mainnet.policy;
    const valid = b1.records.mainnet.outputs[0]!;
    const foreign = b1.records.signet.outputs[0]!;

    const reordered = clone(valid);
    [reordered.logicalKeys[0], reordered.logicalKeys[1]] = [reordered.logicalKeys[1], reordered.logicalKeys[0]];
    expect(verifyVaultOwnership(policy, reordered)).toBe(false);

    const duplicate = clone(valid);
    duplicate.logicalKeys[1] = clone(duplicate.logicalKeys[0]);
    expect(verifyVaultOwnership(policy, duplicate)).toBe(false);

    const substituted = clone(valid);
    substituted.logicalKeys[0] = clone(foreign.logicalKeys[0]);
    expect(verifyVaultOwnership(policy, substituted)).toBe(false);

    expect(verifyVaultOwnership(policy, { ...valid, network: 'signet' })).toBe(false);
    expect(verifyVaultOwnership(policy, { ...valid, branch: 'change' })).toBe(false);
    expect(verifyVaultOwnership(policy, { ...valid, index: 1 })).toBe(false);
    expect(verifyVaultOwnership(policy, { ...valid, policyId: 'ff'.repeat(32) })).toBe(false);
  });

  it('rejects any incomplete or mutated script, key, address, or unknown ownership field', () => {
    const policy = b0.records.signet.policy;
    const valid = b1.records.signet.outputs[0]!;
    expect(verifyVaultOwnership(policy, {
      ...valid,
      logicalKeys: [valid.logicalKeys[0]],
    })).toBe(false);
    expect(verifyVaultOwnership(policy, {
      ...valid,
      logicalKeys: valid.logicalKeys.map((key, index) => index === 0
        ? { ...key, masterFingerprintHex: 'ffffffff' }
        : key),
    })).toBe(false);
    expect(verifyVaultOwnership(policy, {
      ...valid,
      bip67SortedPublicKeysHex: [...valid.bip67SortedPublicKeysHex].reverse(),
    })).toBe(false);
    expect(verifyVaultOwnership(policy, {
      ...valid,
      witnessScriptHex: `${valid.witnessScriptHex.slice(0, -2)}00`,
    })).toBe(false);
    expect(verifyVaultOwnership(policy, {
      ...valid,
      scriptPubKeyHex: `${valid.scriptPubKeyHex.slice(0, -2)}00`,
    })).toBe(false);
    expect(verifyVaultOwnership(policy, { ...valid, address: b1.records.mainnet.outputs[0]!.address })).toBe(false);
    expect(verifyVaultOwnership(policy, { ...valid, remotePolicyOverride: true })).toBe(false);
  });

  it('rejects uncompressed, private-shaped, and malformed ownership keys before comparison', () => {
    const policy = b0.records.signet.policy;
    const valid = clone(b1.records.signet.outputs[0]!);
    const uncompressed = clone(valid);
    uncompressed.logicalKeys[0].publicKeyHex = `04${'11'.repeat(64)}`;
    expect(vaultDerivedOutputSchema.safeParse(uncompressed).success).toBe(false);
    const privateShaped = clone(valid);
    privateShaped.logicalKeys[0].publicKeyHex = '11'.repeat(32);
    expect(vaultDerivedOutputSchema.safeParse(privateShaped).success).toBe(false);
    const malformed = clone(valid);
    malformed.logicalKeys[0].publicKeyHex = '03zz';
    expect(verifyVaultOwnership(policy, malformed)).toBe(false);
  });
});
