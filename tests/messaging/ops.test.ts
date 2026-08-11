import { describe, expect, it } from 'vitest';
import { OP_SCHEMAS } from '../../src/messaging/ops';
import { publicAccountFromSeed } from '../../src/domain/accounts/public-account';

const VALID_MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const ACCOUNT_ID = `acct_signet_${'a'.repeat(64)}`;

describe('op registry', () => {
  it('exposes exactly the trusted implemented RPC surface', () => {
    expect(Object.keys(OP_SCHEMAS).sort()).toEqual(
      [
        'gateway.status',
        'price.quote',
        'session.status',
        'session.snapshot',
        'vault.changePassword',
        'vault.create',
        'vault.list',
        'vault.lock',
        'vault.restore',
        'vault.remove',
        'vault.switch',
        'vault.unlock',
        'vault.revealMnemonic',
        'vault.verifyBackup',
        'backup.status',
        'address.receive',
        'paymentInstruction.resolve',
        'message.sign',
        'addressBook.list',
        'addressBook.add',
        'addressBook.rename',
        'addressBook.remove',
        'addressBook.import',
        'addressBook.dismissRecent',
        'addressBook.clearRecent',
        'config.get',
        'config.set',
        'account.active.get',
        'account.active.set',
        'account.add',
        'account.public.export',
        'account.list',
        'account.remove',
        'account.visibility.set',
        'account.watch.import',
        'provider.sites.list',
        'provider.sites.revoke',
        'wallet.home',
        'activity.list',
        'activity.inscriptionPreview',
        'activity.inscriptionPreviewBatch',
        'scan.start',
        'scan.status',
        'scan.cancel',
        'scan.extend',
        'utxo.setFrozen',
        'utxo.setLabel',
        'fees.quote',
        'gallery.list',
        'gallery.cached',
        'gallery.update',
        'gallery.media.open',
        'gallery.media.lease',
        'utxo.list',
        'transaction.plan',
        'transaction.review',
        'transaction.approve',
        'transaction.cancel',
        'transaction.status',
      ].sort(),
    );
  });

  it('bounds and session-gates BIP 321 recipient resolution', () => {
    const spec = OP_SCHEMAS['paymentInstruction.resolve'];
    const request = {
      input: 'bitcoin:tb1qexample?amount=0.00001',
      expectedVaultId: 'vault-1',
      expectedSessionId: '00000000-0000-4000-8000-000000000001',
    };
    expect(spec.requiresUnlock).toBe(true);
    expect(spec.handlerEnforcesUnlock).toBe(true);
    expect(spec.request.safeParse(request).success).toBe(true);
    expect(spec.request.safeParse({ ...request, input: 'a'.repeat(8193) }).success).toBe(false);
    expect(spec.response.safeParse({
      address: 'tb1qexample', amountSats: '1000', label: 'Receiver', message: 'Invoice',
    }).success).toBe(true);
    expect(spec.response.safeParse({
      address: 'tb1qexample', amountSats: 1000, label: null, message: null,
    }).success).toBe(false);
  });

  it('bounds manual BIP-322 messages and requires password reauthentication', () => {
    const spec = OP_SCHEMAS['message.sign'];
    const request = {
      accountId: ACCOUNT_ID,
      addressKind: 'payment',
      message: 'I control this address.',
      password: 'test password',
      expectedVaultId: 'vault-1',
      expectedSessionId: '00000000-0000-4000-8000-000000000001',
    };
    expect(spec.requiresUnlock).toBe(true);
    expect(spec.handlerEnforcesUnlock).toBe(true);
    expect(spec.request.safeParse(request).success).toBe(true);
    expect(spec.request.safeParse({ ...request, password: '' }).success).toBe(false);
    expect(spec.request.safeParse({ ...request, message: 'a'.repeat(4097) }).success).toBe(false);
    expect(spec.response.safeParse({
      protocol: 'BIP-322',
      address: 'bc1qexample',
      signature: 'smp-example',
      messageHashHex: 'a'.repeat(64),
    }).success).toBe(true);
  });

  it('keeps address-book mutations session-bound and bounded', () => {
    const session = {
      expectedVaultId: 'vault-1',
      expectedSessionId: '00000000-0000-4000-8000-000000000001',
    };
    expect(OP_SCHEMAS['addressBook.add'].request.safeParse({
      label: 'Alice', address: 'bc1qexample', ...session,
    }).success).toBe(true);
    expect(OP_SCHEMAS['addressBook.add'].request.safeParse({
      label: 'Alice\u202e', address: 'bc1qexample', ...session,
    }).success).toBe(false);
    for (const op of [
      'addressBook.list',
      'addressBook.add',
      'addressBook.rename',
      'addressBook.remove',
      'addressBook.import',
      'addressBook.dismissRecent',
      'addressBook.clearRecent',
    ] as const) {
      expect(OP_SCHEMAS[op].requiresUnlock, op).toBe(true);
      expect(OP_SCHEMAS[op].handlerEnforcesUnlock, op).toBe(true);
    }
    expect(OP_SCHEMAS['addressBook.import'].request.safeParse({
      recipients: [{ label: 'Alice', address: 'bc1qexample' }], ...session,
    }).success).toBe(true);
    expect(OP_SCHEMAS['addressBook.import'].request.safeParse({
      recipients: Array.from({ length: 251 }, () => ({ label: 'Alice', address: 'bc1qexample' })),
      ...session,
    }).success).toBe(false);
  });

  it('locked-privacy-gates every gallery and media op', () => {
    for (const op of [
      'gallery.list',
      'gallery.cached',
      'gallery.update',
      'gallery.media.open',
      'gallery.media.lease',
    ] as const) {
      expect(OP_SCHEMAS[op].requiresUnlock, op).toBe(true);
    }
  });

  it('keeps every portable RPC away from the dedicated approval surface', () => {
    for (const [op, spec] of Object.entries(OP_SCHEMAS)) {
      expect(spec.allowedSenders, op).not.toContain('approval');
    }
    expect(OP_SCHEMAS['gallery.cached'].allowedSenders).toEqual([
      'popup', 'sidepanel', 'fullpage',
    ]);
  });

  it('defaults portable account fields in older session snapshots', () => {
    const parsed = OP_SCHEMAS['session.snapshot'].response.parse({
      vaults: [],
      quarantinedVaultCount: 0,
      locked: true,
      activeVaultId: null,
      sessionId: null,
      deadline: null,
      highSecurityMode: false,
      backupVerified: false,
      capabilities: {
        signMethod: 'none',
        canBuildUnsignedPsbt: false,
        canSignPsbt: false,
        canSignBip322: false,
        canRevealSeed: false,
        canExportPublicAccount: false,
        canVerifyAddress: false,
      },
    });
    expect(parsed.activeRecoveredAddressCount).toBe(0);
    expect(parsed.accountAddRequirement).toBeNull();
    expect(OP_SCHEMAS['session.snapshot'].response.safeParse({
      ...parsed,
      accountAddRequirement: { fundAccount: 2, nextAccount: 3 },
    }).success).toBe(true);
  });

  it('requires ownership on verified gallery items while defaulting the new count', () => {
    const item = {
      inscriptionId: `${'a'.repeat(64)}i0`,
      state: 'visible',
      number: 1,
      contentType: 'image/png',
      contentLength: 1,
      satpoint: `${'b'.repeat(64)}:0:0`,
      outpoint: { txid: 'b'.repeat(64), vout: 0 },
      confirmations: 1,
      parent: null,
      delegate: null,
      reinscription: false,
      cursed: false,
      classificationRevision: 'rev-1',
      rareSats: [],
      ownership: {
        address: 'tb1ptest',
        lane: 'ordinals',
        role: 'recovered',
      },
      preview: { kind: 'placeholder', reason: 'unavailable' },
      mediaAvailable: false,
    };
    const response = OP_SCHEMAS['gallery.list'].response;
    const parsed = response.parse({ accountId: ACCOUNT_ID, items: [item], refreshedAt: 1 });
    expect(parsed.recoveredAddressCount).toBe(0);
    expect(parsed.items[0]?.ownership).toEqual(item.ownership);
    expect(response.safeParse({
      accountId: ACCOUNT_ID, items: [{ ...item, ownership: null }],
      refreshedAt: 1,
    }).success).toBe(false);
    const { ownership, ...withoutOwnership } = item;
    expect(ownership).toEqual(parsed.items[0]?.ownership);
    expect(response.safeParse({ accountId: ACCOUNT_ID, items: [withoutOwnership], refreshedAt: 1 }).success)
      .toBe(false);
  });

  it('binds activity previews to an unlocked wallet transaction and inscription', () => {
    const spec = OP_SCHEMAS['activity.inscriptionPreview'];
    const request = {
      accountId: ACCOUNT_ID,
      txid: 'a'.repeat(64),
      inscriptionId: `${'b'.repeat(64)}i0`,
      expectedVaultId: 'vault-1',
      expectedSessionId: '00000000-0000-4000-8000-000000000001',
    };
    expect(spec.requiresUnlock).toBe(true);
    expect(spec.allowedSenders).toEqual(['popup', 'sidepanel', 'fullpage']);
    expect(spec.request.safeParse(request).success).toBe(true);
    expect(spec.request.safeParse({ ...request, txid: 'not-a-txid' }).success).toBe(false);
    expect(spec.request.safeParse({ ...request, inscriptionId: `${'c'.repeat(64)}:0` }).success).toBe(false);
    expect(spec.response.safeParse({
      inscriptionId: request.inscriptionId,
      preview: { kind: 'placeholder', reason: 'unavailable' },
    }).success).toBe(true);
  });

  it('session-gates and bounds account activity pages', () => {
    const spec = OP_SCHEMAS['activity.list'];
    const request = {
      accountId: ACCOUNT_ID,
      expectedVaultId: 'vault-1',
      expectedSessionId: '00000000-0000-4000-8000-000000000001',
    };
    expect(spec.requiresUnlock).toBe(true);
    expect(spec.allowedSenders).toEqual(['popup', 'sidepanel', 'fullpage']);
    expect(spec.request.safeParse(request).success).toBe(true);
    expect(spec.request.safeParse({
      ...request,
      cursor: { version: 1, revision: 'a'.repeat(64), offset: 25 },
    }).success).toBe(true);
    expect(spec.request.safeParse({
      ...request,
      cursor: { version: 1, revision: 'a'.repeat(64), offset: 26 },
    }).success).toBe(false);
    expect(spec.response.safeParse({
      accountId: ACCOUNT_ID,
      items: [],
      nextCursor: null,
      reset: false,
    }).success).toBe(true);
  });

  it('bounds and deduplicates activity preview batches', () => {
    const spec = OP_SCHEMAS['activity.inscriptionPreviewBatch'];
    const item = {
      txid: 'a'.repeat(64),
      inscriptionId: `${'b'.repeat(64)}i0`,
    };
    const request = {
      accountId: ACCOUNT_ID,
      items: [item],
      expectedVaultId: 'vault-1',
      expectedSessionId: '00000000-0000-4000-8000-000000000001',
    };
    expect(spec.requiresUnlock).toBe(true);
    expect(spec.allowedSenders).toEqual(['popup', 'sidepanel', 'fullpage']);
    expect(spec.request.safeParse(request).success).toBe(true);
    expect(spec.request.safeParse({ ...request, items: [item, item] }).success).toBe(false);
    expect(spec.request.safeParse({
      ...request,
      items: Array.from({ length: 9 }, (_unused, index) => ({
        ...item,
        inscriptionId: `${index.toString(16).padStart(64, '0')}i0`,
      })),
    }).success).toBe(false);
  });

  it('locked-privacy-gates every M7 transaction op', () => {
    for (const op of [
      'fees.quote',
      'utxo.list',
      'transaction.plan',
      'transaction.review',
      'transaction.approve',
      'transaction.cancel',
      'transaction.status',
    ] as const) {
      expect(OP_SCHEMAS[op].requiresUnlock, op).toBe(true);
    }
  });

  it('carries exact sub-sat fee rates to UTXO economics in sat/kvB', () => {
    const request = OP_SCHEMAS['utxo.list'].request;
    const session = {
      accountId: ACCOUNT_ID,
      expectedVaultId: 'vault-1',
      expectedSessionId: '00000000-0000-4000-8000-000000000001',
    };
    expect(request.safeParse({ feeRateSatPerKvB: 471, ...session }).success).toBe(true);
    expect(request.safeParse({ feeRateSatPerKvB: 471.5, ...session }).success).toBe(false);
    expect(request.safeParse({ feeRateSatPerKvB: 10_000_001, ...session }).success).toBe(false);
    expect(request.safeParse({ feeRateSatPerVb: 1, ...session }).success).toBe(false);
  });

  it('accepts exact fractional custom-fee text and rejects lossy or ambiguous forms', () => {
    const request = OP_SCHEMAS['transaction.plan'].request;
    const base = {
      kind: 'native_send',
      accountId: `acct_signet_${'a'.repeat(64)}`,
      account: 0,
      recipient: 'tb1qrecipient',
      amountSats: '1000',
      sendMax: false,
      expectedVaultId: 'vault-1',
      expectedSessionId: '00000000-0000-4000-8000-000000000001',
    } as const;
    expect(request.safeParse({ ...base, fee: { type: 'custom', rateSatPerVb: '1.25' } }).success)
      .toBe(true);
    for (const rateSatPerVb of ['0.999', '1.0000', '1e3', '01.25', '10000.001']) {
      expect(request.safeParse({ ...base, fee: { type: 'custom', rateSatPerVb } }).success)
        .toBe(false);
    }
    expect(request.safeParse({ ...base, fee: { type: 'custom', satPerVb: 1.25 } }).success)
      .toBe(false);
  });

  it('locked-privacy-gates every M6 op (§7.5)', () => {
    for (const op of [
      'wallet.home',
      'activity.list',
      'scan.start',
      'scan.status',
      'scan.cancel',
      'scan.extend',
      'utxo.setFrozen',
    ] as const) {
      expect(OP_SCHEMAS[op].requiresUnlock, op).toBe(true);
    }
  });

  it('selects accounts only by stable public identity', () => {
    const request = OP_SCHEMAS['account.active.set'].request;
    const active = {
      expectedVaultId: 'vault-1',
      expectedSessionId: '00000000-0000-4000-8000-000000000001',
    };
    expect(request.safeParse({ accountId: ACCOUNT_ID, ...active }).success).toBe(true);
    expect(request.safeParse({ account: 0, ...active }).success).toBe(false);
    expect(request.safeParse({ accountId: 'acct_signet_short', ...active }).success).toBe(false);
  });

  it('defines worker-authoritative account visibility operations', () => {
    const session = {
      expectedVaultId: 'vault-1',
      expectedSessionId: '00000000-0000-4000-8000-000000000001',
    };
    expect(OP_SCHEMAS['account.list'].request.safeParse(session).success).toBe(true);
    expect(OP_SCHEMAS['account.visibility.set'].request.safeParse({
      ...session, accountId: ACCOUNT_ID, hidden: true,
    }).success).toBe(true);
    expect(OP_SCHEMAS['account.list'].response.safeParse({
      accounts: [{
        accountId: ACCOUNT_ID, account: 0, name: 'Primary', signingSource: 'software',
        active: true, hidden: false, hasHistory: true,
        canHide: false, hideBlocker: 'active',
      }],
    }).success).toBe(true);
  });

  it('validates all four watch descriptors before the import reaches a worker', () => {
    const definition = publicAccountFromSeed(
      Uint8Array.from({ length: 32 }, (_, index) => index + 1),
      'signet',
      0,
    );
    const request = {
      name: 'Cold watch',
      network: 'signet' as const,
      paymentReceiveDescriptor: definition.lanes.payment.receiveDescriptor,
      paymentChangeDescriptor: definition.lanes.payment.changeDescriptor,
      ordinalsReceiveDescriptor: definition.lanes.ordinals.receiveDescriptor,
      ordinalsChangeDescriptor: definition.lanes.ordinals.changeDescriptor,
      expectedVaultId: 'vault-1',
      expectedSessionId: '00000000-0000-4000-8000-000000000001',
    };
    const schema = OP_SCHEMAS['account.watch.import'].request;
    expect(schema.safeParse(request).success).toBe(true);
    expect(schema.safeParse({
      ...request,
      paymentChangeDescriptor: request.paymentReceiveDescriptor,
    }).success).toBe(false);
  });

  it('locked-privacy-gates every M4 read/secret op (§7.5)', () => {
    for (const op of [
      'vault.revealMnemonic',
      'vault.verifyBackup',
      'backup.status',
      'address.receive',
      'config.set',
    ] as const) {
      expect(OP_SCHEMAS[op].requiresUnlock, op).toBe(true);
    }
    expect(OP_SCHEMAS['config.get'].requiresUnlock).toBe(false);
  });

  it('gateway.status answers while locked and binds no session (§7.5 security checks)', () => {
    const spec = OP_SCHEMAS['gateway.status'];
    expect(spec.requiresUnlock).toBe(false);
    expect(spec.request.safeParse({}).success).toBe(true);
    expect(spec.request.safeParse({ forceRefresh: true }).success).toBe(true);
    expect(spec.request.safeParse({ expectedVaultId: 'v' }).success).toBe(false); // strict, no session fields
    // Response is wallet-data-free and strict.
    const view = {
      state: 'degraded',
      network: 'signet',
      mode: 'standard_ordinals_safety',
      missingProtections: ['sat_index'],
      tipHeight: 100,
      verifiedAtMs: 1,
      ageMs: 0,
      lastReason: null,
    };
    expect(spec.response.safeParse(view).success).toBe(true);
    expect(spec.response.safeParse({ ...view, balanceSats: '1' }).success).toBe(false);
  });

  it('keeps the display-only price quote wallet-data-free and available while locked', () => {
    const spec = OP_SCHEMAS['price.quote'];
    expect(spec.requiresUnlock).toBe(false);
    expect(spec.request.safeParse({}).success).toBe(true);
    expect(spec.request.safeParse({ expectedVaultId: 'v' }).success).toBe(false);
    expect(spec.response.safeParse(null).success).toBe(true);
  });

  it('requires three distinct in-range positions for verifyBackup', () => {
    const req = OP_SCHEMAS['vault.verifyBackup'].request;
    const active = {
      expectedVaultId: 'vault-1',
      expectedSessionId: '00000000-0000-4000-8000-000000000001',
    };
    const word = (index: number): { index: number; word: string } => ({ index, word: 'abandon' });
    expect(req.safeParse({ words: [word(0), word(5), word(11)], ...active }).success).toBe(true);
    expect(req.safeParse({ words: [word(0), word(0), word(11)], ...active }).success).toBe(false); // dup
    expect(req.safeParse({ words: [word(0), word(5)], ...active }).success).toBe(false); // too few
    expect(req.safeParse({ words: [word(0), word(5), word(12)], ...active }).success).toBe(false); // range
  });

  it('constrains config.set idle timeouts to the §7.4 options', () => {
    const req = OP_SCHEMAS['config.set'].request;
    const active = {
      expectedVaultId: 'vault-1',
      expectedSessionId: '00000000-0000-4000-8000-000000000001',
    };
    expect(req.safeParse({ idleTimeoutMs: 3_600_000, ...active }).success).toBe(true);
    expect(req.safeParse({ idleTimeoutMs: 43_200_000, ...active }).success).toBe(true);
    expect(req.safeParse({ idleTimeoutMs: 86_400_000, ...active }).success).toBe(true);
    expect(req.safeParse({ idleTimeoutMs: 604_800_000, ...active }).success).toBe(true);
    expect(req.safeParse({ idleTimeoutMs: 5, ...active }).success).toBe(false);
  });

  it('shape-checks the sanctioned reveal response and nothing more', () => {
    const res = OP_SCHEMAS['vault.revealMnemonic'].response;
    expect(res.safeParse({ mnemonic: VALID_MNEMONIC }).success).toBe(true);
    expect(res.safeParse({ mnemonic: VALID_MNEMONIC, entropyHex: 'ff' }).success).toBe(false);
  });

  it('excludes the content-bridge from every op', () => {
    for (const spec of Object.values(OP_SCHEMAS)) {
      expect(spec.allowedSenders).not.toContain('content-bridge');
    }
  });

  it('validates and strictly rejects create payloads', () => {
    const req = OP_SCHEMAS['vault.create'].request;
    const operationId = '11111111-1111-4111-8111-111111111111';
    expect(req.safeParse({ name: 'Main', password: 'pw', operationId }).success).toBe(true);
    expect(req.safeParse({ name: 'Main' }).success).toBe(false); // missing password
    expect(req.safeParse({ name: 'Main', password: 'pw' }).success).toBe(false); // idempotency is mandatory
    expect(req.safeParse({ name: 'Main', password: 'pw', operationId, extra: 1 }).success).toBe(false); // strict
  });

  it('checksum-validates the restore mnemonic', () => {
    const req = OP_SCHEMAS['vault.restore'].request;
    const operationId = '11111111-1111-4111-8111-111111111111';
    expect(req.safeParse({ name: 'R', password: 'pw', mnemonic: VALID_MNEMONIC, operationId }).success).toBe(true);
    expect(req.safeParse({ name: 'R', password: 'pw', mnemonic: 'not a real mnemonic', operationId }).success).toBe(
      false,
    );
  });

  it('strictly rejects unknown response fields (no-leak backstop)', () => {
    const res = OP_SCHEMAS['session.status'].response;
    expect(
      res.safeParse({ locked: true, activeVaultId: null, sessionId: null, deadline: null, highSecurityMode: false })
        .success,
    ).toBe(true);
    expect(
      res.safeParse({
        locked: true,
        activeVaultId: null,
        sessionId: null,
        deadline: null,
        highSecurityMode: false,
        seed: 'x',
      }).success,
    ).toBe(false);
  });
});
