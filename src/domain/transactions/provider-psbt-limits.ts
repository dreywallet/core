export const PROVIDER_MAX_PSBT_INPUTS = 200;
export const PROVIDER_MAX_PSBT_OUTPUTS = 2_000;
/** ord.net documents at most 41 entries. */
export const PROVIDER_MAX_PSBT_BATCH_ITEMS = 41;
export const PROVIDER_MAX_PSBT_BATCH_BASE64_CHARS = 1_500_000;
/** Sats Connect exposes at most one payment and one ordinals selection per PSBT. */
export const PROVIDER_MAX_PSBT_INPUT_SELECTIONS = 2;
/** Ten bounded criteria-offer parents may each select up to fifty payment inputs. */
export const PROVIDER_MAX_PSBT_BATCH_INPUTS = 500;
export const PROVIDER_MAX_PSBT_BATCH_SELECTED_INPUTS = 500;
export const PROVIDER_MAX_LINKED_PSBT_GROUP_INPUTS = PROVIDER_MAX_PSBT_BATCH_INPUTS;
export const PROVIDER_MAX_LINKED_PSBT_GROUP_SELECTED_INPUTS = PROVIDER_MAX_PSBT_BATCH_SELECTED_INPUTS;

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
