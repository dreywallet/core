import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { beforeAll, describe, expect, it } from 'vitest';
import type { VaultPlanRequestBase } from '../../src/domain/vault/multisig-planning';
import { buildVaultCardinalWithdrawal } from '../../src/domain/vault/multisig-planning';
import { decodeVaultContextCbor, decodeVaultPsbtCbor } from '../../src/domain/vault/multisig-qr';
import { hexToBytes } from '../../src/domain/vault/encoding';
import { validateVaultBroadcastLifecycle } from '../../src/domain/vault/multisig-lifecycle';
import type { VaultPolicyIdentityV1 } from '../../src/domain/vault/multisig-contracts';
import type { VaultEvidenceSourceV1, VaultUtxoV1 } from '../../src/domain/vault/multisig-evidence';
import { installTestCryptoProvider } from '../helpers/install-crypto-provider';

beforeAll(installTestCryptoProvider);

type CoordinatorRecord = {
  input: {
    policy: VaultPolicyIdentityV1;
    source: VaultEvidenceSourceV1;
    utxos: VaultUtxoV1[];
    request: VaultPlanRequestBase & { amountSats: string };
  };
  expected: {
    plan: ReturnType<typeof buildVaultCardinalWithdrawal>['plan'];
    evidence: ReturnType<typeof buildVaultCardinalWithdrawal>['evidence'];
    unsignedPsbtHex: string;
    psbtCborHex: string;
    pairingContextCborHex: string;
    approvalRequestContextCborHex: string;
    lifecycle: { terminal: Parameters<typeof validateVaultBroadcastLifecycle>[0]['record'] };
  };
};

const vectors = JSON.parse(readFileSync(
  join(import.meta.dirname, '..', '..', 'vectors', 'vault-coordinator-v1.json'),
  'utf8',
)) as { records: Record<'mainnet' | 'signet', CoordinatorRecord> };

describe('symmetric coordinator golden vectors', () => {
  for (const network of ['mainnet', 'signet'] as const) {
    it(`rebuilds identical ${network} policy-bound plan, PSBT, QR, and terminal bytes`, () => {
      const vector = vectors.records[network];
      const rebuilt = buildVaultCardinalWithdrawal(vector.input.request);
      expect(rebuilt.plan).toEqual(vector.expected.plan);
      expect(rebuilt.evidence).toEqual(vector.expected.evidence);
      expect(rebuilt.psbtHex).toBe(vector.expected.unsignedPsbtHex);
      expect(decodeVaultPsbtCbor('psbt', hexToBytes(vector.expected.psbtCborHex))).toBe(rebuilt.psbtHex);
      expect(decodeVaultContextCbor(
        'x-drey-vault', hexToBytes(vector.expected.pairingContextCborHex),
      ).kind).toBe('pairing');
      expect(decodeVaultContextCbor(
        'x-drey-vault', hexToBytes(vector.expected.approvalRequestContextCborHex),
      )).toMatchObject({ kind: 'approval', envelope: { planDigest: rebuilt.plan.planDigest } });
      expect(validateVaultBroadcastLifecycle({
        policy: vector.input.policy,
        plan: rebuilt.plan,
        record: vector.expected.lifecycle.terminal,
      }).phase).toBe('terminal');
    });
  }
});
