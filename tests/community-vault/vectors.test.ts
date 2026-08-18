import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { beforeAll, describe, expect, it } from 'vitest';
import { installTestCryptoProvider } from '../helpers/install-crypto-provider';
import { parseCommunityVaultPolicy } from '../../src/domain/community-vault/policy';
import {
  finalizeCommunityVaultPsbt,
  validateCommunityVaultPsbt,
  verifyFinalizedCommunityVaultTransaction,
} from '../../src/domain/community-vault/psbt';
import { hexToBytes } from '../../src/domain/vault/encoding';
import type { CommunityVaultPolicyV1, CommunityVaultSpendPlanV1 } from '../../src/domain/community-vault/contracts';

beforeAll(() => installTestCryptoProvider());

interface Vector {
  vectorVersion: number;
  warning: string;
  policy: CommunityVaultPolicyV1;
  policyBytesHex: string;
  plan: CommunityVaultSpendPlanV1;
  unsignedPsbtHex: string;
  preparedPsbtHex: string;
  signed68PsbtHex: string;
  signed69PsbtHex: string;
  finalized: ReturnType<typeof finalizeCommunityVaultPsbt>;
}

const vector = JSON.parse(readFileSync(
  join(import.meta.dirname, '..', '..', 'vectors', 'community-vault-v1.json'), 'utf8',
)) as Vector;

describe('Community Vault v1 deterministic mainnet vectors', () => {
  it('reproduces policy recovery and exact 68/69 finalization behavior', () => {
    expect(vector.vectorVersion).toBe(1);
    expect(vector.warning).toContain('NEVER-FUNDED MAINNET-FORMAT');
    expect(parseCommunityVaultPolicy(hexToBytes(vector.policyBytesHex))).toEqual(vector.policy);
    expect(validateCommunityVaultPsbt(vector.policy, vector.plan, vector.unsignedPsbtHex).signedUnits).toEqual([]);
    expect(validateCommunityVaultPsbt(vector.policy, vector.plan, vector.preparedPsbtHex).signedUnits).toEqual([]);
    expect(validateCommunityVaultPsbt(vector.policy, vector.plan, vector.signed68PsbtHex).signedUnits).toHaveLength(68);
    expect(() => finalizeCommunityVaultPsbt(vector.policy, vector.plan, vector.signed68PsbtHex)).toThrow(/at least 69/u);
    expect(finalizeCommunityVaultPsbt(vector.policy, vector.plan, vector.signed69PsbtHex)).toEqual(vector.finalized);
    expect(verifyFinalizedCommunityVaultTransaction({
      policy: vector.policy, plan: vector.plan, transactionHex: vector.finalized.transactionHex,
    })).toEqual(vector.finalized);
  });
});
