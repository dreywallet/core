import { describe, expect, it } from 'vitest';
import { recommendAcceleration } from '../../src/domain/transactions/acceleration-recommendation';

describe('acceleration recommendation', () => {
  it('selects exactly one safe next action', () => {
    expect(recommendAcceleration({ confirmationState: 'mempool', replaceable: true,
      hasSpendableWalletOutput: true })).toEqual({ recommendedAcceleration: 'rbf', accelerationUnavailableReason: null });
    expect(recommendAcceleration({ confirmationState: 'mempool', replaceable: false,
      hasSpendableWalletOutput: true })).toEqual({ recommendedAcceleration: 'cpfp', accelerationUnavailableReason: null });
    expect(recommendAcceleration({ confirmationState: 'mempool', replaceable: false,
      hasSpendableWalletOutput: false }).recommendedAcceleration).toBeNull();
    expect(recommendAcceleration({ confirmationState: 'confirmed', replaceable: true,
      hasSpendableWalletOutput: true }).recommendedAcceleration).toBeNull();
  });
});
