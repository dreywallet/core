/**
 * §14.4 local UTXO labels ("Local label or cluster").
 *
 * Labels are local user annotations and nothing more: they never leave the
 * device, are never sent to the gateway (§22.1 forbids labels in server logs),
 * and carry no authority over §11.2 eligibility. A label may narrow which
 * inputs an automatic selection prefers (§14.1); it may never make an
 * ineligible input spendable.
 *
 * Pure domain module: no browser APIs, no network.
 */
import { z } from 'zod';

export const UTXO_LABEL_TEXT_MAX = 64;

/** Provenance a user actually knows at receive time, in plain language. */
export const utxoLabelPresetSchema = z.enum([
  'exchange_withdrawal',
  'peer_payment',
  'purchase',
  'savings',
  'mining',
]);
export type UtxoLabelPreset = z.infer<typeof utxoLabelPresetSchema>;

export const utxoLabelSchema = z
  .object({
    preset: utxoLabelPresetSchema.nullable(),
    text: z.string().min(1).max(UTXO_LABEL_TEXT_MAX).nullable(),
  })
  .strict()
  .refine((label) => label.preset !== null || label.text !== null, {
    message: 'label must carry a preset or text',
  });
export type UtxoLabel = z.infer<typeof utxoLabelSchema>;

/**
 * Two UTXOs belong to the same group when this key matches.
 *
 * Both parts participate: coins withdrawn from two different exchanges are
 * distinct clusters even though they share a preset, because merging them in
 * one transaction publicly links the two accounts. Free text is trimmed and
 * case-folded so "Kraken" and "kraken " do not split a group by accident.
 */
export function labelGroupKey(label: UtxoLabel): string {
  const preset = label.preset ?? '';
  const text = label.text === null ? '' : label.text.trim().toLowerCase();
  return `${preset}|${text}`;
}
