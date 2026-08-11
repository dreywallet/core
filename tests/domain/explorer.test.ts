import { describe, expect, it } from 'vitest';
import { mempoolTransactionUrl } from '../../src/domain/explorer';

describe('mempool transaction explorer URLs', () => {
  it('uses the mainnet transaction route', () => {
    expect(mempoolTransactionUrl('mainnet', 'a'.repeat(64))).toBe(
      `https://mempool.space/tx/${'a'.repeat(64)}`,
    );
  });

  it('uses the signet transaction route', () => {
    expect(mempoolTransactionUrl('signet', 'b'.repeat(64))).toBe(
      `https://mempool.space/signet/tx/${'b'.repeat(64)}`,
    );
  });
});
