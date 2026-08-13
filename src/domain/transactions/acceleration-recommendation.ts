export type AccelerationRecommendation = {
  recommendedAcceleration: 'rbf' | 'cpfp' | null;
  accelerationUnavailableReason: string | null;
};

/** Project one next action from durable transaction facts; this makes no confirmation promise. */
export function recommendAcceleration(input: {
  confirmationState: 'confirmed' | 'mempool' | 'replaced' | 'conflicted' | 'indeterminate' | 'rejected';
  replaceable: boolean;
  hasSpendableWalletOutput: boolean;
}): AccelerationRecommendation {
  if (input.confirmationState !== 'mempool') {
    return {
      recommendedAcceleration: null,
      accelerationUnavailableReason: input.confirmationState === 'confirmed'
        ? 'Transaction is already confirmed.'
        : 'Transaction state must be reconciled before acceleration.',
    };
  }
  if (input.replaceable) return { recommendedAcceleration: 'rbf', accelerationUnavailableReason: null };
  if (input.hasSpendableWalletOutput) return { recommendedAcceleration: 'cpfp', accelerationUnavailableReason: null };
  return {
    recommendedAcceleration: null,
    accelerationUnavailableReason: 'No safe fee-bump method is available for this transaction.',
  };
}
