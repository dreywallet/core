import { beforeAll, beforeEach, describe, expect, it } from 'vitest';
import {
  appendPermissionEvent,
  createPermissionOpaqueId,
  hasExactPermission,
  hasExactPermissionSet,
  loadPermissionJournal,
  normalizePermissionScope,
  permissionScopeSchema,
  PermissionJournalError,
  reducePermissionEvents,
  type PermissionGrantEvent,
  type PermissionJournalEvent,
  type PermissionRevokeEvent,
  type PermissionRevokeScopeEvent,
  type PermissionStorageArea,
} from '../../src/domain/provider/permission-journal';
import { installTestCryptoProvider } from '../helpers/install-crypto-provider';
import { getSodium } from '../helpers/sodium';
import { base64ToBytes, bytesToBase64 } from '../../src/domain/vault/encoding';

class CrashableArea implements PermissionStorageArea {
  readonly values = new Map<string, unknown>();
  failSetKey: string | null = null;
  failRemoveKey: string | null = null;

  async get(keys: string | string[]): Promise<Record<string, unknown>> {
    const result: Record<string, unknown> = {};
    for (const key of Array.isArray(keys) ? keys : [keys]) {
      if (this.values.has(key)) result[key] = structuredClone(this.values.get(key));
    }
    return result;
  }

  async set(items: Record<string, unknown>): Promise<void> {
    if (this.failSetKey !== null && this.failSetKey in items) throw new Error('simulated set crash');
    for (const [key, value] of Object.entries(items)) this.values.set(key, structuredClone(value));
  }

  async remove(keys: string | string[]): Promise<void> {
    const keyList = Array.isArray(keys) ? keys : [keys];
    if (this.failRemoveKey !== null && keyList.includes(this.failRemoveKey)) {
      throw new Error('simulated remove crash');
    }
    for (const key of keyList) this.values.delete(key);
  }
}

const STORAGE_KEY = 'provider-permissions:vault-a';
const VAULT_ID = 'vault-a';
const GRANT_ID = '10000000000000000000000000000001';
const GRANT_EVENT_ID = '20000000000000000000000000000002';
const REVOKE_EVENT_ID = '30000000000000000000000000000003';

function grant(
  categories: PermissionGrantEvent['scope']['categories'] = ['account_identity', 'addresses'],
): PermissionGrantEvent {
  return {
    version: 1,
    kind: 'grant',
    eventId: GRANT_EVENT_ID,
    resourceId: GRANT_ID,
    occurredAtMs: 1_000,
    scope: {
      origin: 'https://site.example',
      network: 'mainnet',
      vaultId: VAULT_ID,
      account: 0,
      categories,
    },
  };
}

function revoke(): PermissionRevokeEvent {
  return {
    version: 1,
    kind: 'revoke',
    eventId: REVOKE_EVENT_ID,
    targetResourceId: GRANT_ID,
    occurredAtMs: 2_000,
    reason: 'user_revoked',
  };
}

function revokeScope(): PermissionRevokeScopeEvent {
  return {
    version: 1,
    kind: 'revoke_scope',
    eventId: REVOKE_EVENT_ID,
    occurredAtMs: 2_000,
    origin: 'https://site.example',
    network: 'mainnet',
    vaultId: VAULT_ID,
    account: 0,
    reason: 'disconnect',
  };
}

let area: CrashableArea;
let dek: Uint8Array;

beforeAll(async () => {
  await installTestCryptoProvider();
});

beforeEach(() => {
  area = new CrashableArea();
  dek = getSodium().randombytes_buf(32);
});

describe('permission schemas and projection', () => {
  it('canonicalizes an exact scope and rejects broad or ambiguous variants', () => {
    expect(
      normalizePermissionScope({
        origin: 'HTTPS://SITE.EXAMPLE:443/path',
        network: 'mainnet',
        vaultId: VAULT_ID,
        account: 0,
        categories: ['network', 'account_identity', 'network'],
      }),
    ).toEqual({
      origin: 'https://site.example',
      network: 'mainnet',
      vaultId: VAULT_ID,
      account: 0,
      categories: ['account_identity', 'network'],
    });
    expect(permissionScopeSchema.safeParse({ ...grant().scope, account: 0x7fffffff }).success).toBe(true);
    expect(permissionScopeSchema.safeParse({ ...grant().scope, account: 0x80000000 }).success).toBe(false);
    expect(
      permissionScopeSchema.safeParse({ ...grant().scope, origin: 'https://SITE.example' }).success,
    ).toBe(false);
    expect(
      permissionScopeSchema.safeParse({ ...grant().scope, categories: ['addresses', 'addresses'] }).success,
    ).toBe(false);
  });

  it('refuses to append a grant encrypted into another vault journal', async () => {
    await expect(
      appendPermissionEvent({
        area,
        storageKey: STORAGE_KEY,
        dek,
        vaultId: 'vault-b',
        expectedRevision: 0,
        event: grant(),
      }),
    ).rejects.toMatchObject({ code: 'invalid_event' });
  });

  it('keeps revocation tombstones and refuses resource-id reuse', () => {
    const projection = reducePermissionEvents([grant(), revoke()]);
    expect(projection.grants).toEqual([]);
    expect(projection.revokedResourceIds.has(GRANT_ID)).toBe(true);
    const reused: PermissionJournalEvent = {
      ...grant(),
      eventId: '40000000000000000000000000000004',
    };
    expect(() => reducePermissionEvents([grant(), revoke(), reused])).toThrow(PermissionJournalError);
  });

  it('atomically revokes every grant in one exact scope while preserving other accounts', () => {
    const balanceGrant: PermissionGrantEvent = {
      ...grant(['balance']),
      eventId: '40000000000000000000000000000004',
      resourceId: '50000000000000000000000000000005',
    };
    const otherAccount: PermissionGrantEvent = {
      ...grant(['addresses']),
      eventId: '60000000000000000000000000000006',
      resourceId: '70000000000000000000000000000007',
      scope: { ...grant(['addresses']).scope, account: 1 },
    };
    const projection = reducePermissionEvents([grant(), balanceGrant, otherAccount, revokeScope()]);
    expect(projection.grants).toEqual([otherAccount]);
    expect([...projection.revokedResourceIds].sort()).toEqual([GRANT_ID, balanceGrant.resourceId].sort());
  });

  it('creates opaque 128-bit lowercase resource identifiers', () => {
    expect(createPermissionOpaqueId()).toMatch(/^[0-9a-f]{32}$/u);
    expect(createPermissionOpaqueId()).not.toBe(createPermissionOpaqueId());
  });
});

describe('encrypted crash-safe permission journal', () => {
  it('stores no origin, account, or category plaintext and enforces the exact tuple', async () => {
    const saved = await appendPermissionEvent({
      area,
      storageKey: STORAGE_KEY,
      dek,
      vaultId: VAULT_ID,
      expectedRevision: 0,
      event: grant(),
    });
    expect(saved.revision).toBe(1);
    expect(JSON.stringify(area.values.get(STORAGE_KEY))).not.toContain('site.example');
    expect(JSON.stringify(area.values.get(STORAGE_KEY))).not.toContain('account_identity');
    expect(
      hasExactPermission(saved.projection, {
        ...grant().scope,
        categories: ['account_identity'],
      }),
    ).toBe(true);
    expect(hasExactPermission(saved.projection, { ...grant().scope, network: 'signet' })).toBe(false);
    expect(hasExactPermission(saved.projection, { ...grant().scope, account: 1 })).toBe(false);
    expect(
      hasExactPermission(saved.projection, { ...grant().scope, categories: ['balance'] }),
    ).toBe(false);
  });

  it('unions separately approved categories only within one exact scope', async () => {
    const first = await appendPermissionEvent({
      area,
      storageKey: STORAGE_KEY,
      dek,
      vaultId: VAULT_ID,
      expectedRevision: 0,
      event: grant(['account_identity']),
    });
    const secondGrant: PermissionGrantEvent = {
      ...grant(['balance']),
      eventId: '40000000000000000000000000000004',
      resourceId: '50000000000000000000000000000005',
    };
    const second = await appendPermissionEvent({
      area,
      storageKey: STORAGE_KEY,
      dek,
      vaultId: VAULT_ID,
      expectedRevision: first.revision,
      event: secondGrant,
    });
    expect(
      hasExactPermission(second.projection, {
        ...grant().scope,
        categories: ['account_identity', 'balance'],
      }),
    ).toBe(true);
    expect(hasExactPermissionSet(second.projection, {
      ...grant().scope,
      categories: ['account_identity', 'balance'],
    })).toBe(true);
    expect(hasExactPermissionSet(second.projection, {
      ...grant().scope,
      categories: ['account_identity'],
    })).toBe(false);
  });

  it('replays a committed revoke after a worker restart', async () => {
    await appendPermissionEvent({
      area,
      storageKey: STORAGE_KEY,
      dek,
      vaultId: VAULT_ID,
      expectedRevision: 0,
      event: grant(),
    });
    await appendPermissionEvent({
      area,
      storageKey: STORAGE_KEY,
      dek,
      vaultId: VAULT_ID,
      expectedRevision: 1,
      event: revoke(),
    });
    const afterRestart = await loadPermissionJournal(area, STORAGE_KEY, dek, VAULT_ID);
    expect(afterRestart).toMatchObject({ status: 'ok', revision: 2 });
    expect(afterRestart.projection.grants).toEqual([]);
    expect(afterRestart.projection.revokedResourceIds.has(GRANT_ID)).toBe(true);
  });

  it('promotes a staged revoke when termination occurs before canonical commit', async () => {
    await appendPermissionEvent({
      area,
      storageKey: STORAGE_KEY,
      dek,
      vaultId: VAULT_ID,
      expectedRevision: 0,
      event: grant(),
    });
    area.failSetKey = STORAGE_KEY;
    await expect(
      appendPermissionEvent({
        area,
        storageKey: STORAGE_KEY,
        dek,
        vaultId: VAULT_ID,
        expectedRevision: 1,
        event: revoke(),
      }),
    ).rejects.toThrow('simulated set crash');
    expect(area.values.has(`${STORAGE_KEY}:staging`)).toBe(true);

    area.failSetKey = null;
    const recovered = await loadPermissionJournal(area, STORAGE_KEY, dek, VAULT_ID);
    expect(recovered).toMatchObject({ status: 'recovered', revision: 2 });
    expect(recovered.projection.grants).toEqual([]);
    expect(area.values.has(`${STORAGE_KEY}:staging`)).toBe(false);
  });

  it('recovers one staged scope revoke without reviving any of several grants', async () => {
    await appendPermissionEvent({
      area,
      storageKey: STORAGE_KEY,
      dek,
      vaultId: VAULT_ID,
      expectedRevision: 0,
      event: grant(['account_identity']),
    });
    await appendPermissionEvent({
      area,
      storageKey: STORAGE_KEY,
      dek,
      vaultId: VAULT_ID,
      expectedRevision: 1,
      event: {
        ...grant(['balance']),
        eventId: '40000000000000000000000000000004',
        resourceId: '50000000000000000000000000000005',
      },
    });
    area.failSetKey = STORAGE_KEY;
    await expect(
      appendPermissionEvent({
        area,
        storageKey: STORAGE_KEY,
        dek,
        vaultId: VAULT_ID,
        expectedRevision: 2,
        event: revokeScope(),
      }),
    ).rejects.toThrow('simulated set crash');

    area.failSetKey = null;
    const recovered = await loadPermissionJournal(area, STORAGE_KEY, dek, VAULT_ID);
    expect(recovered).toMatchObject({ status: 'recovered', revision: 3 });
    expect(recovered.projection.grants).toEqual([]);
    expect([...recovered.projection.revokedResourceIds].sort()).toEqual([
      GRANT_ID,
      '50000000000000000000000000000005',
    ].sort());
  });

  it('cleans an already committed stage after termination during cleanup', async () => {
    area.failRemoveKey = `${STORAGE_KEY}:staging`;
    await expect(
      appendPermissionEvent({
        area,
        storageKey: STORAGE_KEY,
        dek,
        vaultId: VAULT_ID,
        expectedRevision: 0,
        event: grant(),
      }),
    ).rejects.toThrow('simulated remove crash');
    expect(area.values.has(STORAGE_KEY)).toBe(true);
    area.failRemoveKey = null;
    const recovered = await loadPermissionJournal(area, STORAGE_KEY, dek, VAULT_ID);
    expect(recovered).toMatchObject({ status: 'ok', revision: 1 });
    expect(recovered.projection.grants).toHaveLength(1);
    expect(area.values.has(`${STORAGE_KEY}:staging`)).toBe(false);
  });

  it('fails closed for ciphertext tampering, a wrong vault, or the wrong DEK', async () => {
    await appendPermissionEvent({
      area,
      storageKey: STORAGE_KEY,
      dek,
      vaultId: VAULT_ID,
      expectedRevision: 0,
      event: grant(),
    });
    expect(
      await loadPermissionJournal(area, STORAGE_KEY, getSodium().randombytes_buf(32), VAULT_ID),
    ).toMatchObject({ status: 'corrupt', revision: 0, projection: { grants: [] } });
    expect(await loadPermissionJournal(area, STORAGE_KEY, dek, 'vault-b')).toMatchObject({
      status: 'corrupt',
      projection: { grants: [] },
    });

    const record = structuredClone(area.values.get(STORAGE_KEY)) as {
      entries: Array<{ ciphertextB64: string }>;
    };
    const ciphertext = base64ToBytes(record.entries[0]!.ciphertextB64);
    ciphertext[0] = (ciphertext[0] ?? 0) ^ 0x01;
    record.entries[0]!.ciphertextB64 = bytesToBase64(ciphertext);
    area.values.set(STORAGE_KEY, record);
    expect(await loadPermissionJournal(area, STORAGE_KEY, dek, VAULT_ID)).toMatchObject({
      status: 'corrupt',
      projection: { grants: [] },
    });
  });

  it('rejects stale concurrent writers and makes duplicate event retries idempotent', async () => {
    const first = await appendPermissionEvent({
      area,
      storageKey: STORAGE_KEY,
      dek,
      vaultId: VAULT_ID,
      expectedRevision: 0,
      event: grant(),
    });
    const retried = await appendPermissionEvent({
      area,
      storageKey: STORAGE_KEY,
      dek,
      vaultId: VAULT_ID,
      expectedRevision: 1,
      event: grant(),
    });
    expect(retried.revision).toBe(first.revision);

    await expect(
      appendPermissionEvent({
        area,
        storageKey: STORAGE_KEY,
        dek,
        vaultId: VAULT_ID,
        expectedRevision: 0,
        event: revoke(),
      }),
    ).rejects.toMatchObject({ code: 'stale_revision' });
  });

  it('discards an unrelated staged record instead of replacing canonical authority', async () => {
    await appendPermissionEvent({
      area,
      storageKey: STORAGE_KEY,
      dek,
      vaultId: VAULT_ID,
      expectedRevision: 0,
      event: grant(),
    });
    const unrelated = structuredClone(area.values.get(STORAGE_KEY)) as {
      revision: number;
      entries: Array<{ eventId: string }>;
    };
    unrelated.entries[0]!.eventId = '90000000000000000000000000000009';
    area.values.set(`${STORAGE_KEY}:staging`, unrelated);

    const loaded = await loadPermissionJournal(area, STORAGE_KEY, dek, VAULT_ID);
    expect(loaded).toMatchObject({ status: 'ok', revision: 1 });
    expect(loaded.projection.grants).toHaveLength(1);
    expect(area.values.has(`${STORAGE_KEY}:staging`)).toBe(false);
  });
});
