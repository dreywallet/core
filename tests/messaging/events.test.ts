import { describe, expect, it } from 'vitest';
import {
  isScanProgressEvent,
  isSessionStateChangedEvent,
  isWalletDataChangedEvent,
} from '../../src/messaging/events';

describe('worker UI events', () => {
  it('accepts only supported coarse wallet invalidations', () => {
    for (const reason of ['transaction', 'utxo', 'account', 'config', 'permissions']) {
      expect(isWalletDataChangedEvent({
        type: 'squirrel:wallet-data-changed',
        reason,
      })).toBe(true);
    }
    expect(isWalletDataChangedEvent({
      type: 'squirrel:wallet-data-changed',
      reason: 'secret',
    })).toBe(false);
    expect(isWalletDataChangedEvent({ type: 'squirrel:wallet-data-changed' })).toBe(false);
    expect(isWalletDataChangedEvent(null)).toBe(false);
  });

  it('does not confuse wallet, scan, and session notifications', () => {
    const scan = { type: 'squirrel:scan-progress' };
    const session = { type: 'squirrel:session-state-changed', locked: true };
    expect(isScanProgressEvent(scan)).toBe(true);
    expect(isWalletDataChangedEvent(scan)).toBe(false);
    expect(isSessionStateChangedEvent(session)).toBe(true);
    expect(isWalletDataChangedEvent(session)).toBe(false);
  });
});
