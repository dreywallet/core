import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { beforeAll, describe, expect, it } from 'vitest';
import type { VaultPolicyIdentityV1, VaultUnsignedPlanV1 } from '../../src/domain/vault/multisig-contracts';
import {
  completeVaultBroadcast,
  consumeVaultBroadcastAttempt,
  prepareVaultBroadcast,
  validateVaultBroadcastLifecycle,
  vaultBroadcastRecoveryPosture,
} from '../../src/domain/vault/multisig-lifecycle';
import { installTestCryptoProvider } from '../helpers/install-crypto-provider';

beforeAll(installTestCryptoProvider);

const vectors = JSON.parse(readFileSync(
  join(import.meta.dirname, '..', '..', 'vectors', 'vault-psbt-v1.json'),
  'utf8',
)) as { records: { mainnet: { plan: VaultUnsignedPlanV1; quorums: Record<string, { transactionHex: string }> } } };
const contracts = JSON.parse(readFileSync(
  join(import.meta.dirname, '..', '..', 'vectors', 'vault-contracts-v1.json'),
  'utf8',
)) as { records: { mainnet: { policy: VaultPolicyIdentityV1 } } };

function fixture() {
  const record = vectors.records.mainnet;
  return { policy: contracts.records.mainnet.policy, plan: record.plan, transactionHex: record.quorums['A+B']!.transactionHex };
}

describe('Vault durable broadcast lifecycle', () => {
  it('persists exact finalized bytes before consuming one dispatch attempt', () => {
    const base = fixture();
    const prepared = prepareVaultBroadcast({ ...base, coordinator: 'mobile', preparedAtMs: '1785542403000' });
    expect(vaultBroadcastRecoveryPosture(prepared)).toBe('safe-to-dispatch-once');
    const consumed = consumeVaultBroadcastAttempt({
      policy: base.policy, plan: base.plan, record: prepared,
      attemptIdHex: 'ab'.repeat(16), consumedAtMs: '1785542404000',
    });
    expect(vaultBroadcastRecoveryPosture(consumed)).toBe('reconcile-only');
    expect(() => consumeVaultBroadcastAttempt({
      policy: base.policy, plan: base.plan, record: consumed,
      attemptIdHex: 'cd'.repeat(16), consumedAtMs: '1785542405000',
    })).toThrow('already consumed');
  });

  it('records a terminal or indeterminate outcome without permitting replay', () => {
    const base = fixture();
    const prepared = prepareVaultBroadcast({ ...base, coordinator: 'extension', preparedAtMs: '1785542403000' });
    const consumed = consumeVaultBroadcastAttempt({
      policy: base.policy, plan: base.plan, record: prepared,
      attemptIdHex: 'ef'.repeat(16), consumedAtMs: '1785542404000',
    });
    const terminal = completeVaultBroadcast({
      policy: base.policy, plan: base.plan, record: consumed,
      status: 'indeterminate', detail: 'no verified response', observedAtMs: '1785542405000',
    });
    expect(vaultBroadcastRecoveryPosture(terminal)).toBe('terminal');
    expect(() => completeVaultBroadcast({
      policy: base.policy, plan: base.plan, record: terminal,
      status: 'accepted', detail: null, observedAtMs: '1785542406000',
    })).toThrow();
  });

  it('rejects changed bytes and changed plan bindings on rehydration', () => {
    const base = fixture();
    const prepared = prepareVaultBroadcast({ ...base, coordinator: 'extension', preparedAtMs: '1785542403000' });
    expect(() => validateVaultBroadcastLifecycle({
      policy: base.policy, plan: base.plan,
      record: { ...prepared, transactionHex: `${prepared.transactionHex.slice(0, 20)}ff${prepared.transactionHex.slice(22)}` },
    })).toThrow();
    expect(() => validateVaultBroadcastLifecycle({
      policy: base.policy, plan: base.plan,
      record: { ...prepared, planDigest: 'ff'.repeat(32) },
    })).toThrow();
  });
});
