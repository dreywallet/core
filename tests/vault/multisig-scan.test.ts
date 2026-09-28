import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { beforeAll, describe, expect, it } from 'vitest';
import type { GatewayClient } from '../../src/gateway-client';
import type { WalletScanSnapshotResponse } from '../../src/domain/gateway/contract';
import type { VaultPolicyIdentityV1 } from '../../src/domain/vault/multisig-contracts';
import { scanVaultPolicy, VAULT_SCAN_INDEX_CEILING, vaultScriptHashes } from '../../src/domain/vault/multisig-scan';
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

  it('widens past the default bound so change at high indexes is not left out', async () => {
    const policy = vectors.records.mainnet.policy;
    // Thirty-one Desktop withdrawals: change at even indexes 0..60, beyond the
    // default 40-index bound. Mobile's odd indexes are unused.
    const active = new Set(Array.from({ length: 31 }, (_, i) =>
      vaultScriptHashes(policy, 1, i * 2, i * 2 + 1)[0]!.scriptHash));
    const requested = new Set<string>();
    const gateway = {
      fetchSnapshot: async (request: { scriptHashes: string[] }) => {
        request.scriptHashes.forEach((hash) => requested.add(hash));
        const value: WalletScanSnapshotResponse = {
          instanceId: 'instance', network: 'mainnet', protocolVersion: 1,
          requestNonce: '00'.repeat(16), timestamp: '2026-08-30T00:00:00.000Z',
          coreTip: { height: 900_000, hash: 'bb'.repeat(32) },
          indexTip: { height: 900_000, hash: 'bb'.repeat(32) },
          classificationRevision: 'rev', capabilities: [], signature: 'aa',
          requestedScriptHashes: request.scriptHashes, utxos: [], history: [],
          activeScriptHashes: request.scriptHashes.filter((hash) => active.has(hash)),
          historyCoverage: { status: 'complete', limitedScriptHashes: [] },
        };
        return { ok: true as const, value, verifiedAtMs: 0 };
      },
      classifyOutpoints: async () => { throw new Error('no outpoints should require classification'); },
    } as unknown as GatewayClient;

    const outcome = await scanVaultPolicy({ policy, network: 'mainnet', gateway });
    expect(outcome.result).toMatchObject({ ok: true, boundaryPrompt: false });
    for (const hash of active) expect(requested.has(hash)).toBe(true);
    // The gap past the last change (60 + 1 + 20) was covered too.
    expect(requested.has(vaultScriptHashes(policy, 1, 80, 81)[0]!.scriptHash)).toBe(true);
  });

  it('stops widening at the ceiling when a gateway reports every address as used', async () => {
    const policy = vectors.records.mainnet.policy;
    const hashesAt = new Map(vaultScriptHashes(policy, 1, 0, VAULT_SCAN_INDEX_CEILING)
      .map((entry) => [entry.scriptHash, entry.index]));
    let highest = -1;
    const gateway = {
      fetchSnapshot: async (request: { scriptHashes: string[] }) => {
        for (const hash of request.scriptHashes) highest = Math.max(highest, hashesAt.get(hash) ?? -1);
        const value: WalletScanSnapshotResponse = {
          instanceId: 'instance', network: 'mainnet', protocolVersion: 1,
          requestNonce: '00'.repeat(16), timestamp: '2026-08-30T00:00:00.000Z',
          coreTip: { height: 900_000, hash: 'bb'.repeat(32) },
          indexTip: { height: 900_000, hash: 'bb'.repeat(32) },
          classificationRevision: 'rev', capabilities: [], signature: 'aa',
          requestedScriptHashes: request.scriptHashes, utxos: [], history: [],
          activeScriptHashes: request.scriptHashes,
          historyCoverage: { status: 'complete', limitedScriptHashes: [] },
        };
        return { ok: true as const, value, verifiedAtMs: 0 };
      },
      classifyOutpoints: async () => { throw new Error('no outpoints should require classification'); },
    } as unknown as GatewayClient;

    const outcome = await scanVaultPolicy({ policy, network: 'mainnet', gateway });
    // Still flagged: the caller learns the scan hit its bound rather than completing.
    expect(outcome.result).toMatchObject({ ok: true, boundaryPrompt: true });
    expect(highest).toBe(VAULT_SCAN_INDEX_CEILING - 1);
  }, 20_000);
});
