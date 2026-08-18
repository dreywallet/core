import { describe, expect, it } from 'vitest';
import {
  ACCOUNT_GAP_LIMIT,
  standardAccountAddState,
} from '../../src/domain/accounts/limits';

describe('standard account gap policy', () => {
  it('allows five consecutive empty accounts, including account zero', () => {
    expect(ACCOUNT_GAP_LIMIT).toBe(5);
    expect(standardAccountAddState([0], [], false)).toEqual({
      kind: 'available',
      nextAccount: 1,
      trailingEmptyAccounts: 1,
      limit: 5,
      requiresAcknowledgement: true,
    });
    expect(standardAccountAddState([0, 1, 2, 3, 4], [], true)).toEqual({
      kind: 'empty_limit',
      firstEmptyAccount: 0,
      lastEmptyAccount: 4,
      limit: 5,
    });
  });

  it('resets the trailing buffer after any confirmed account', () => {
    expect(standardAccountAddState([0, 1, 2, 3, 4], [2], true)).toEqual({
      kind: 'available',
      nextAccount: 5,
      trailingEmptyAccounts: 2,
      limit: 5,
      requiresAcknowledgement: false,
    });
    expect(standardAccountAddState([0, 1, 2, 3, 4, 5, 6, 7], [2], true)).toEqual({
      kind: 'empty_limit',
      firstEmptyAccount: 3,
      lastEmptyAccount: 7,
      limit: 5,
    });
  });
});
