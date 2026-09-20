import { z } from 'zod';
import { broadcastRequestSchema } from '../gateway/contract';
import { runeAtomicSchema, runeIdSchema } from './evidence';
export const runeBroadcastIntentSchema = z.object({
  runeId: runeIdSchema,
  amount: runeAtomicSchema.refine((value) => value !== '0'),
  recipientScript: z.string().min(2).max(20000).regex(/^(?:[0-9a-f]{2})+$/u),
  tokenChangeScript: z.string().min(2).max(20000).regex(/^(?:[0-9a-f]{2})+$/u).nullable(),
}).strict();
export const runeBroadcastRequestSchema = z.union([
  broadcastRequestSchema.options[0].extend({ runeIntent: runeBroadcastIntentSchema }).strict(),
  broadcastRequestSchema.options[1].extend({ runeIntent: runeBroadcastIntentSchema }).strict(),
]);
export type RuneBroadcastRequest = z.infer<typeof runeBroadcastRequestSchema>;
