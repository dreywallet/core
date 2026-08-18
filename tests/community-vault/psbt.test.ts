import { beforeAll, describe, expect, it } from 'vitest';
import { SigHash, Transaction } from '@scure/btc-signer';
import { installTestCryptoProvider } from '../helpers/install-crypto-provider';
import { bytesToHex, hexToBytes } from '../../src/domain/vault/encoding';
import {
  approveCommunityVaultSpend,
  combineCommunityVaultPsbts,
  finalizeCommunityVaultPsbt,
  validateCommunityVaultPsbt,
  verifyFinalizedCommunityVaultTransaction,
} from '../../src/domain/community-vault/psbt';
import { deterministicAux, fixtureFundedPsbt, fixturePolicy, fixtureSpendPlan } from './helpers';

beforeAll(() => installTestCryptoProvider());

function approveOwners(count: number) {
  const { policy, roots } = fixturePolicy();
  const plan = fixtureSpendPlan(policy);
  let psbtHex = fixtureFundedPsbt(policy, plan);
  const random = deterministicAux();
  for (let index = 0; index < count; index += 1) {
    psbtHex = approveCommunityVaultSpend({
      policy, plan, psbtHex, ownerId: `owner-${index}`, signerRoot: roots[index]!,
      nowMs: '1800000000100', random,
    }).psbtHex;
  }
  return { policy, roots, plan, psbtHex };
}

describe('Community Vault v1 BIP371 PSBT', () => {
  it('adds every unit signature owned by one owner under one approval', () => {
    const { policy, roots } = fixturePolicy();
    const plan = fixtureSpendPlan(policy);
    const initial = fixtureFundedPsbt(policy, plan);
    const approved = approveCommunityVaultSpend({
      policy, plan, psbtHex: initial, ownerId: 'owner-0', signerRoot: roots[0]!,
      nowMs: '1800000000100', random: deterministicAux(),
    });
    expect(approved.addedUnits).toEqual(Array.from({ length: 20 }, (_, index) => index));
    expect(approved.signedUnits).toHaveLength(20);
    expect(Transaction.fromPSBT(hexToBytes(approved.psbtHex)).getInput(0).tapScriptSig).toHaveLength(20);
  });

  it('rejects 68 signatures and finalizes the same mainnet-format fixture at 69', () => {
    const at68 = approveOwners(4);
    expect(validateCommunityVaultPsbt(at68.policy, at68.plan, at68.psbtHex).signedUnits).toHaveLength(68);
    expect(() => finalizeCommunityVaultPsbt(at68.policy, at68.plan, at68.psbtHex)).toThrow(/at least 69/u);
    const at69 = approveCommunityVaultSpend({
      policy: at68.policy, plan: at68.plan, psbtHex: at68.psbtHex,
      ownerId: 'owner-4', signerRoot: at68.roots[4]!, nowMs: '1800000000100', random: deterministicAux(),
    });
    expect(at69.signedUnits).toHaveLength(69);
    const finalized = finalizeCommunityVaultPsbt(at68.policy, at68.plan, at69.psbtHex);
    expect(finalized.signedUnits).toHaveLength(69);
    expect(finalized.weight).toBeLessThanOrEqual(400_000);
    expect(finalized.witnessBytes).toBeLessThanOrEqual(9_000);
    expect(verifyFinalizedCommunityVaultTransaction({
      policy: at68.policy, plan: at68.plan, transactionHex: finalized.transactionHex,
    })).toEqual(finalized);
  }, 20_000);

  it('rejects all 67 non-creator units in Anchored mode', () => {
    const { policy, roots } = fixturePolicy('anchored', [33, 17, 17, 17, 16]);
    const plan = fixtureSpendPlan(policy);
    const base = fixtureFundedPsbt(policy, plan);
    const random = deterministicAux();
    const partials = roots.slice(1).map((root, index) => approveCommunityVaultSpend({
      policy, plan, psbtHex: base, ownerId: `owner-${index + 1}`, signerRoot: root,
      nowMs: '1800000000100', random,
    }).psbtHex);
    const combined = combineCommunityVaultPsbts(policy, plan, partials);
    expect(combined.signedUnits).toHaveLength(67);
    expect(() => finalizeCommunityVaultPsbt(policy, plan, combined.psbtHex)).toThrow(/at least 69/u);
  });

  it('rejects hidden key paths, altered leaves, derivations, outputs, and non-default signatures', () => {
    const { policy } = fixturePolicy();
    const plan = fixtureSpendPlan(policy);
    const mutate = (change: (tx: Transaction) => void) => {
      const tx = Transaction.fromPSBT(hexToBytes(fixtureFundedPsbt(policy, plan)), { PSBTVersion: 0 });
      change(tx);
      return bytesToHex(tx.toPSBT(0));
    };
    expect(() => validateCommunityVaultPsbt(policy, plan, mutate((tx) => tx.updateInput(0, {
      tapInternalKey: hexToBytes(policy.units[0]!.publicKeyHex),
    }, true)))).toThrow(/hidden, altered, key-path/u);
    expect(() => validateCommunityVaultPsbt(policy, plan, mutate((tx) => tx.updateInput(0, {
      tapMerkleRoot: hexToBytes('aa'.repeat(32)),
    }, true)))).toThrow(/hidden, altered, key-path/u);
    expect(() => validateCommunityVaultPsbt(policy, plan, mutate((tx) => {
      const derivations = tx.getInput(0).tapBip32Derivation!;
      derivations[0]![1].der.path[0] = 99;
      tx.updateInput(0, { tapBip32Derivation: derivations }, true);
    }))).toThrow();
    expect(() => validateCommunityVaultPsbt(policy, plan, mutate((tx) => tx.updateInput(0, {
      sighashType: SigHash.ALL,
    }, true)))).toThrow(/hidden, altered, key-path/u);
    const changedPlan = structuredClone(plan);
    changedPlan.outputs[0]!.valueSats = '8999';
    expect(() => validateCommunityVaultPsbt(policy, changedPlan, fixtureFundedPsbt(policy, plan))).toThrow();
  });

  it('rejects signature and witness mutation after serialization', () => {
    const at68 = approveOwners(4);
    const at69 = approveCommunityVaultSpend({
      policy: at68.policy, plan: at68.plan, psbtHex: at68.psbtHex,
      ownerId: 'owner-4', signerRoot: at68.roots[4]!, nowMs: '1800000000100', random: deterministicAux(),
    });
    const partial = Transaction.fromPSBT(hexToBytes(at69.psbtHex), { PSBTVersion: 0 });
    const signatures = partial.getInput(0).tapScriptSig!;
    const signatureHex = bytesToHex(signatures[0]![1]);
    const changedSignatureHex = `${signatureHex.startsWith('00') ? '01' : '00'}${signatureHex.slice(2)}`;
    const mutatedPsbt = at69.psbtHex.replace(signatureHex, changedSignatureHex);
    expect(mutatedPsbt).not.toBe(at69.psbtHex);
    expect(() => validateCommunityVaultPsbt(at68.policy, at68.plan, mutatedPsbt)).toThrow(/invalid/u);

    const finalized = finalizeCommunityVaultPsbt(at68.policy, at68.plan, at69.psbtHex);
    const raw = Transaction.fromRaw(hexToBytes(finalized.transactionHex));
    const witness = raw.getInput(0).finalScriptWitness!;
    const signature = witness.find((item) => item.length === 64)!;
    const rawSignatureHex = bytesToHex(signature);
    const changedRawSignatureHex = `${rawSignatureHex.startsWith('00') ? '01' : '00'}${rawSignatureHex.slice(2)}`;
    const mutatedRaw = finalized.transactionHex.replace(rawSignatureHex, changedRawSignatureHex);
    expect(mutatedRaw).not.toBe(finalized.transactionHex);
    expect(() => verifyFinalizedCommunityVaultTransaction({
      policy: at68.policy, plan: at68.plan, transactionHex: mutatedRaw,
    })).toThrow(/invalid finalized/u);
  });
});
