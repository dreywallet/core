import { describe, expect, it } from 'vitest';
import { publicAccountFromSeed } from '../../src/domain/accounts/public-account';
import {
  accountSigningBindingSchema,
  parsePublicAccountRecordPair,
  publicAccountDefinitionRecordSchema,
  publicAccountDescriptorImportSchema,
} from '../../src/messaging/account-schemas';
import { migrateLegacySoftwareAccountV1 } from '../../src/domain/accounts/signing-source';

const seed = Uint8Array.from({ length: 32 }, (_, index) => index + 3);

describe('portable public-account storage boundaries', () => {
  it('validates the complete descriptor set at the import boundary', () => {
    const definition = publicAccountFromSeed(seed, 'signet', 0);
    const imported = {
      network: definition.network,
      paymentReceiveDescriptor: definition.lanes.payment.receiveDescriptor,
      paymentChangeDescriptor: definition.lanes.payment.changeDescriptor,
      ordinalsReceiveDescriptor: definition.lanes.ordinals.receiveDescriptor,
      ordinalsChangeDescriptor: definition.lanes.ordinals.changeDescriptor,
    };
    expect(publicAccountDescriptorImportSchema.parse(imported)).toEqual(imported);
    expect(publicAccountDescriptorImportSchema.safeParse({
      ...imported,
      paymentChangeDescriptor: imported.paymentReceiveDescriptor,
    }).success).toBe(false);
  });

  it('keeps public definitions and signer bindings in separate versioned records', () => {
    const definition = publicAccountFromSeed(seed, 'mainnet', 7);
    expect(publicAccountDefinitionRecordSchema.parse({ version: 1, definition }))
      .toEqual({ version: 1, definition });
    expect(accountSigningBindingSchema.parse({
      version: 1,
      accountId: definition.accountId,
      signingSource: { version: 1, kind: 'none' },
    })).toEqual({
      version: 1,
      accountId: definition.accountId,
      signingSource: { version: 1, kind: 'none' },
    });
    expect(parsePublicAccountRecordPair(
      { version: 1, definition },
      {
        version: 1,
        accountId: definition.accountId,
        signingSource: { version: 1, kind: 'none' },
      },
    )).toMatchObject({
      definitionRecord: { definition },
      signingBinding: { accountId: definition.accountId },
    });
    expect(() => parsePublicAccountRecordPair(
      { version: 1, definition },
      {
        version: 1,
        accountId: definition.accountId.replace(/.$/u, '0'),
        signingSource: { version: 1, kind: 'none' },
      },
    )).toThrow('definition and signing binding differ');
    expect(publicAccountDefinitionRecordSchema.safeParse({
      version: 1,
      definition,
      signingSource: { version: 1, kind: 'software', vaultId: 'vault-1' },
    }).success).toBe(false);
  });

  it('migrates legacy software account zero deterministically without using its index as identity', () => {
    const first = migrateLegacySoftwareAccountV1(seed, 'signet', 0, 'vault-1');
    const second = migrateLegacySoftwareAccountV1(seed, 'signet', 0, 'vault-1');
    expect(second).toEqual(first);
    expect(first.binding.accountId).toBe(first.definition.accountId);

    const importedSameIndex = publicAccountFromSeed(
      Uint8Array.from({ length: 32 }, (_, index) => 200 - index),
      'signet',
      0,
    );
    expect(importedSameIndex.derivationAccountIndex).toBe(first.definition.derivationAccountIndex);
    expect(importedSameIndex.accountId).not.toBe(first.definition.accountId);
  });
});
