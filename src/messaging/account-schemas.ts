import { z } from 'zod';
import {
  parsePublicAccountDescriptors,
  publicAccountDefinitionSchema,
} from '../domain/accounts/public-account';
import { accountSigningSourceSchema } from '../domain/accounts/signing-source';

export const publicAccountDescriptorImportShape = {
  network: z.enum(['mainnet', 'signet']),
  paymentReceiveDescriptor: z.string().min(1).max(512),
  paymentChangeDescriptor: z.string().min(1).max(512),
  ordinalsReceiveDescriptor: z.string().min(1).max(512),
  ordinalsChangeDescriptor: z.string().min(1).max(512),
} as const;

export const publicAccountDescriptorImportSchema = z.object(publicAccountDescriptorImportShape)
  .strict().superRefine((value, context) => {
  try {
    parsePublicAccountDescriptors(value);
  } catch (error) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      message: error instanceof Error ? error.message : 'invalid public account descriptors',
    });
  }
});

/** Encrypted public definition record; contains no signing attachment. */
export const publicAccountDefinitionRecordSchema = z.object({
  version: z.literal(1),
  definition: publicAccountDefinitionSchema,
}).strict();

/** Separately encrypted signer binding; `none` is an explicit watch-only account. */
export const accountSigningBindingSchema = z.object({
  version: z.literal(1),
  accountId: z.string().regex(/^acct_(?:mainnet|signet)_[0-9a-f]{64}$/u),
  signingSource: accountSigningSourceSchema,
}).strict();

/** Validate separately sealed records as one logical account after decryption. */
export function parsePublicAccountRecordPair(
  definitionRecordInput: unknown,
  signingBindingInput: unknown,
): {
  definitionRecord: PublicAccountDefinitionRecord;
  signingBinding: AccountSigningBinding;
} {
  const definitionRecord = publicAccountDefinitionRecordSchema.parse(definitionRecordInput);
  const signingBinding = accountSigningBindingSchema.parse(signingBindingInput);
  if (signingBinding.accountId !== definitionRecord.definition.accountId) {
    throw new Error('public account definition and signing binding differ');
  }
  return { definitionRecord, signingBinding };
}

export type PublicAccountDescriptorImport = z.infer<typeof publicAccountDescriptorImportSchema>;
export type PublicAccountDefinitionRecord = z.infer<typeof publicAccountDefinitionRecordSchema>;
export type AccountSigningBinding = z.infer<typeof accountSigningBindingSchema>;
