import { describe, expect, it } from 'vitest';
import {
  legacyStoredUtxoSchema,
  migrateLegacyStoredUtxos,
  storedUtxoSchema,
  storedUtxosSchema,
  storedHistoryReadSchema,
  storedHistoryRecordSchema,
} from '../../src/scan/cache-schemas';

const legacy = {
  outpoint: { txid: 'a'.repeat(64), vout: 0 },
  valueSats: 10_000n,
  scriptPubKey: `0014${'1'.repeat(40)}`,
  account: 0,
  lane: 'payment' as const,
  chain: 0 as const,
  addressIndex: 0,
  height: 1,
  walletCreatedChange: false,
  facts: null,
  flags: { userFrozen: false, dustQuarantined: false },
};

describe('stable account identity cache migration', () => {
  it('reads legacy rows but refuses to validate them as current writes', () => {
    expect(legacyStoredUtxoSchema.parse(legacy)).toEqual(legacy);
    expect(storedUtxosSchema.parse([legacy])).toEqual([legacy]);
    expect(storedUtxoSchema.safeParse(legacy).success).toBe(false);
  });

  it('requires an explicit unambiguous identity migration before selection', () => {
    const accountId = `acct_signet_${'a'.repeat(64)}`;
    expect(migrateLegacyStoredUtxos([legacy], (row) => row.account === 0 ? accountId : null))
      .toEqual([{ ...legacy, accountId }]);
    expect(() => migrateLegacyStoredUtxos([legacy], () => null)).toThrow('cannot be resolved');
  });
});

describe('versioned history cache migration', () => {
  it('reads legacy arrays as complete and preserves explicit partial coverage', () => {
    expect(storedHistoryReadSchema.parse([])).toEqual({
      version: 2,
      entries: [],
      coverage: { status: 'complete', limitedScriptHashes: [] },
    });
    const partial = {
      version: 2 as const,
      entries: [],
      coverage: { status: 'partial' as const, limitedScriptHashes: ['b'.repeat(64)] },
    };
    expect(storedHistoryRecordSchema.parse(partial)).toEqual(partial);
    expect(storedHistoryReadSchema.parse(partial)).toEqual(partial);
  });
});
