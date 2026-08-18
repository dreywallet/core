export const PROVIDER_MAX_PSBT_INPUTS = 200;
export const PROVIDER_MAX_PSBT_OUTPUTS = 2_000;

export function assertProviderPsbtItemCounts(
  transaction: { inputsLength: number; outputsLength: number },
): void {
  if (transaction.inputsLength > PROVIDER_MAX_PSBT_INPUTS) {
    throw new Error(`PSBT input count exceeds ${PROVIDER_MAX_PSBT_INPUTS}`);
  }
  if (transaction.outputsLength > PROVIDER_MAX_PSBT_OUTPUTS) {
    throw new Error(`PSBT output count exceeds ${PROVIDER_MAX_PSBT_OUTPUTS}`);
  }
}
