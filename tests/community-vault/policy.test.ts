import fc from 'fast-check';
import { beforeAll, describe, expect, it } from 'vitest';
import { TAPROOT_UNSPENDABLE_KEY } from '@scure/btc-signer';
import { installTestCryptoProvider } from '../helpers/install-crypto-provider';
import { bytesToHex } from '../../src/domain/vault/encoding';
import {
  assertCommunityVaultPolicy,
  createCommunityVaultPolicy,
  createCommunityVaultRecoveryKit,
  parseCommunityVaultPolicy,
  recoverCommunityVaultPolicy,
  serializeCommunityVaultPolicy,
} from '../../src/domain/community-vault/policy';
import {
  COMMUNITY_VAULT_NUMS_INTERNAL_KEY,
  COMMUNITY_VAULT_THRESHOLD,
} from '../../src/domain/community-vault/contracts';
import { decodeCommunityVaultPolicyScript } from '../../src/domain/community-vault/psbt';
import { fixtureOwners, fixturePolicy } from './helpers';

beforeAll(() => installTestCryptoProvider());

describe('Community Vault v1 policy', () => {
  it('constructs one exact 69-of-100 Taproot leaf with the BIP341 NUMS internal key', () => {
    const { policy } = fixturePolicy();
    expect(policy.network).toBe('mainnet');
    expect(policy.threshold).toBe(COMMUNITY_VAULT_THRESHOLD);
    expect(policy.unitCount).toBe(100);
    expect(policy.internalKeyHex).toBe(COMMUNITY_VAULT_NUMS_INTERNAL_KEY);
    expect(bytesToHex(TAPROOT_UNSPENDABLE_KEY)).toBe(COMMUNITY_VAULT_NUMS_INTERNAL_KEY);
    expect(policy.controlBlockHex).toHaveLength(66);
    expect(policy.address).toMatch(/^bc1p/u);
    expect(policy.descriptor).toContain('multi_a(69,');
    expect(decodeCommunityVaultPolicyScript(policy)).toEqual({
      threshold: 69,
      publicKeysHex: policy.units.map((unit) => unit.publicKeyHex),
    });
  });

  it('round-trips the policy and recovery kit to the exact descriptor, address, and commitment', () => {
    const { policy } = fixturePolicy();
    const bytes = serializeCommunityVaultPolicy(policy);
    const recovered = parseCommunityVaultPolicy(bytes);
    expect(recovered).toEqual(policy);
    const kit = createCommunityVaultRecoveryKit(policy);
    expect(recoverCommunityVaultPolicy(kit)).toEqual(policy);
    expect(kit.policyBytesHex).toBe(bytesToHex(bytes));
  });

  it('rejects retained commitments after cap-table, key, descriptor, or recovery-byte mutation', () => {
    const { policy } = fixturePolicy();
    for (const mutate of [
      (draft: typeof policy) => { draft.owners[0]!.payoutAddress = draft.owners[1]!.payoutAddress; },
      (draft: typeof policy) => { draft.units[0]!.publicKeyHex = draft.units[1]!.publicKeyHex; },
      (draft: typeof policy) => { draft.descriptor = draft.descriptor.replace('multi_a(69,', 'multi_a(68,'); },
      (draft: typeof policy) => { draft.capTableHash = 'ff'.repeat(32); },
      (draft: typeof policy) => { draft.policyId = 'ee'.repeat(32); },
    ]) {
      const draft = structuredClone(policy);
      mutate(draft);
      expect(() => assertCommunityVaultPolicy(draft)).toThrow();
    }
    const bytes = serializeCommunityVaultPolicy(policy);
    bytes[bytes.length - 1] = bytes[bytes.length - 1]! ^ 1;
    expect(() => parseCommunityVaultPolicy(bytes)).toThrow();
  });

  it('enforces Anchored 33/67 and Open 20-unit concentration rules', () => {
    expect(() => fixturePolicy('anchored', [33, 17, 17, 17, 16])).not.toThrow();
    const { owners } = fixtureOwners([32, 17, 17, 17, 17]);
    expect(() => createCommunityVaultPolicy({
      version: 1, policyVersion: 1, network: 'mainnet', campaignId: 'bad-anchor',
      inscriptionId: `${'22'.repeat(32)}i0`, currentOutpoint: { txid: '22'.repeat(32), vout: 0 },
      mode: 'anchored', eligibility: 'anyone', creatorOwnerId: 'owner-0', termsVersion: 'terms-v1',
      capTableVersion: 1, owners,
    })).toThrow(/creator 33/u);
    expect(() => fixturePolicy('open', [21, 20, 20, 20, 19])).toThrow(/limits every recognized identity/u);
  });

  it('is canonical across transport ordering and round-trips randomized valid Open cap tables', () => {
    fc.assert(fc.property(fc.shuffledSubarray([0, 1, 2, 3, 4, 5, 6], { minLength: 7, maxLength: 7 }), (order) => {
      const { owners } = fixtureOwners([20, 20, 20, 8, 1, 11, 20]);
      const base = createCommunityVaultPolicy({
        version: 1, policyVersion: 1, network: 'mainnet', campaignId: 'property-open',
        inscriptionId: `${'33'.repeat(32)}i0`, currentOutpoint: { txid: '33'.repeat(32), vout: 1 },
        mode: 'open', eligibility: 'anyone', creatorOwnerId: 'owner-0', termsVersion: 'terms-v1',
        capTableVersion: 1, owners,
      });
      const reordered = createCommunityVaultPolicy({
        version: 1, policyVersion: 1, network: 'mainnet', campaignId: base.campaignId,
        inscriptionId: base.inscriptionId, currentOutpoint: { ...base.currentOutpoint }, mode: base.mode,
        eligibility: base.eligibility, creatorOwnerId: base.creatorOwnerId, termsVersion: base.termsVersion,
        capTableVersion: base.capTableVersion, owners: order.map((index) => structuredClone(owners[index]!)),
      });
      expect(reordered.policyId).toBe(base.policyId);
      expect(parseCommunityVaultPolicy(serializeCommunityVaultPolicy(reordered))).toEqual(base);
    }), { numRuns: 5 });
  }, 20_000);
});
