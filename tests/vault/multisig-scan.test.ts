import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { beforeAll, describe, expect, it } from 'vitest';
import type { GatewayClient } from '../../src/gateway-client';
import type { WalletScanSnapshotResponse } from '../../src/domain/gateway/contract';
import type { VaultPolicyIdentityV1 } from '../../src/domain/vault/multisig-contracts';
import { scanVaultPolicy, vaultScriptHashes } from '../../src/domain/vault/multisig-scan';
import { installTestCryptoProvider } from '../helpers/install-crypto-provider';

beforeAll(() => installTestCryptoProvider());

const vectors = JSON.parse(readFileSync(
  join(import.meta.dirname, '..', '..', 'vectors', 'vault-contracts-v1.json'),
  'utf8',
)) as { records: { mainnet: { policy: VaultPolicyIdentityV1 } } };

describe('Vault policy scanning', () => {
  it('reports the coherent retry source rather than the discarded first attempt', async () => {
    const policy = vectors.records.mainnet.policy;
    const activeHash = vaultScriptHashes(policy, 0, 18, 19)[0]!.scriptHash;
    const revisions = ['rev-a', 'rev-b', 'rev-b', 'rev-b'];
    let calls = 0;
    const gateway = {
      fetchSnapshot: async (request: { scriptHashes: string[] }) => {
        const revision = revisions[calls++] ?? 'rev-b';
        const value: WalletScanSnapshotResponse = {
          instanceId: `instance-${revision}`,
          network: 'mainnet',
          protocolVersion: 1,
          requestNonce: '00'.repeat(16),
          timestamp: '2026-08-30T00:00:00.000Z',
          coreTip: { height: 900_000, hash: revision === 'rev-a' ? 'aa'.repeat(32) : 'bb'.repeat(32) },
          indexTip: { height: 900_000, hash: revision === 'rev-a' ? 'aa'.repeat(32) : 'bb'.repeat(32) },
          classificationRevision: revision,
          capabilities: [],
          signature: 'aa',
          requestedScriptHashes: request.scriptHashes,
          utxos: [],
          history: [],
          activeScriptHashes: request.scriptHashes.includes(activeHash) ? [activeHash] : [],
          historyCoverage: { status: 'complete', limitedScriptHashes: [] },
        };
        return { ok: true as const, value, verifiedAtMs: 0 };
      },
      classifyOutpoints: async () => { throw new Error('no outpoints should require classification'); },
    } as unknown as GatewayClient;

    const outcome = await scanVaultPolicy({ policy, network: 'mainnet', gateway });
    expect(outcome.result).toMatchObject({ ok: true, revision: 'rev-b' });
    expect(outcome.source).toMatchObject({
      instanceId: 'instance-rev-b',
      classificationRevision: 'rev-b',
      coreTip: { hash: 'bb'.repeat(32) },
    });
    expect(calls).toBe(4);
  });
});
