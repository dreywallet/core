/**
 * The standalone recovery package (ADR 0007 §6, Workstream C7).
 *
 * These tests drive the same modules the shipped artifact bundles, against the
 * committed public fixture roots on signet and mainnet *vector* data. No live
 * network, no gateway, and no funded key is involved: the mnemonics behind
 * these roots are public by design and must never hold value.
 *
 * The two required drills — A+C and B+C — are exercised explicitly rather than
 * through a generic "any two roles" loop, because core's finalizer
 * deterministically prefers A+B whenever all three signatures are present, so a
 * loop that signed with everything would silently never test either drill.
 */
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { HDKey } from '@scure/bip32';
import { NETWORK, TEST_NETWORK, p2wpkh } from '@scure/btc-signer';
import { beforeAll, describe, expect, it } from 'vitest';
import { installTestCryptoProvider } from '../helpers/install-crypto-provider';
import { bytesToHex } from '../../src/domain/vault/encoding';
import {
  VAULT_RECOVERY_KIT_TEXT_V1,
  VAULT_ROLES,
  bip32Versions,
  vaultRecoveryKitSchema,
  type VaultRecoveryKitV1,
  type VaultPolicyIdentityV1,
  type VaultSignerOriginV1,
  type VaultSignerRole,
  type VaultUnsignedPlanV1,
} from '../../src/domain/vault/multisig-contracts';
import {
  canonicalVaultPlanBytes,
  serializeVaultRecoveryKit,
} from '../../src/domain/vault/multisig-encoding';
import { constructVaultPsbt } from '../../src/domain/vault/multisig-psbt';
import { mnemonicToSeed } from '../../src/domain/keys/mnemonic';
import { vaultAccountOriginPath } from '../../src/domain/vault/multisig-contracts';
import {
  deriveVaultOutput,
  generateVaultPolicyIdentity,
} from '../../src/domain/vault/multisig-descriptors';
import { verifyKitHex, deriveLadder, locateScript } from '../../recovery/src/kit';
import {
  MIN_CHANGE_SATS,
  STANDALONE_SOURCE_SENTINEL,
  buildRecoveryPlan,
  resolveInputs,
} from '../../recovery/src/plan';
import { reviewFacts, renderReview } from '../../recovery/src/display';
import { combineResults, finalize, signAsRole } from '../../recovery/src/signing';
import { writeTransactionHexFile } from '../../recovery/src/cli';

beforeAll(() => installTestCryptoProvider());

type Net = 'mainnet' | 'signet';
const sha256 = (value: string): Uint8Array => new Uint8Array(createHash('sha256').update(value).digest());

/**
 * Canonical BIP39 test vectors. Their words are published in the standard
 * itself, so nothing derived from them may ever hold value — which is exactly
 * why they are safe to commit and to sign with here.
 *
 * The tool derives roots from words, so the policy under test must be built
 * from these same words rather than from a synthetic seed; otherwise the test
 * would sign for a policy nobody holds and prove nothing.
 */
const MNEMONICS: Record<VaultSignerRole, string> = {
  'desktop-a': 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
  'mobile-b': 'legal winner thank year wave sausage worth useful legal winner thank yellow',
  'recovery-c': 'letter advice cage absurd amount doctor acoustic avoid letter advice cage above',
};

function fixtureSeed(network: Net, label: string): Uint8Array {
  return sha256(`PUBLIC DISPOSABLE C7 FIXTURE ONLY:${network}:${label}`);
}

function originFor(network: Net, role: VaultSignerRole): VaultSignerOriginV1 {
  const root = HDKey.fromMasterSeed(mnemonicToSeed(MNEMONICS[role]), bip32Versions(network));
  try {
    const originPath = vaultAccountOriginPath(network);
    return {
      version: 1, role, network,
      masterFingerprintHex: root.fingerprint.toString(16).padStart(8, '0'),
      originPath,
      accountXpub: root.derive(originPath).publicExtendedKey,
    };
  } finally {
    root.wipePrivateData();
  }
}

const CREATED = 1_785_542_400_000n;

interface Harness {
  network: Net;
  kitHex: string;
  identity: ReturnType<typeof generateVaultPolicyIdentity>;
}

function harness(network: Net): Harness {
  const signers = VAULT_ROLES.map((role) => originFor(network, role)) as
    [VaultSignerOriginV1, VaultSignerOriginV1, VaultSignerOriginV1];
  const identity = generateVaultPolicyIdentity(network, signers);
  const kit: VaultRecoveryKitV1 = vaultRecoveryKitSchema.parse({
    version: 1, network, policyVersion: 1, policyId: identity.policyId, signers,
    receiveDescriptor: identity.receiveDescriptor, changeDescriptor: identity.changeDescriptor,
    createdAtMs: CREATED.toString(), birthdayHeight: null,
    vaultLabel: 'C7 fixture Vault',
    signerLabels: ['Desktop A', 'Mobile B', 'Recovery C'],
    firstReceiveAddress: deriveVaultOutput(identity, 'receive', 0).address,
    compatibilityRequirements: [...VAULT_RECOVERY_KIT_TEXT_V1.compatibilityRequirements],
    minimumReaderVersion: 1,
    standaloneToolSourceDigest: bytesToHex(sha256('fixture-source')),
    standaloneToolArtifactDigest: bytesToHex(sha256('fixture-artifact')),
    recoveryInstructions: VAULT_RECOVERY_KIT_TEXT_V1.recoveryInstructions,
    rotationInstructions: VAULT_RECOVERY_KIT_TEXT_V1.rotationInstructions,
    recoveryInstructionsVersion: 1,
  });
  return { network, kitHex: bytesToHex(serializeVaultRecoveryKit(kit)), identity };
}

/** A destination outside the Vault: an ordinary P2WPKH the fixture controls. */
function exitAddress(network: Net): string {
  const root = HDKey.fromMasterSeed(fixtureSeed(network, 'recovery-destination'), bip32Versions(network));
  const child = root.derive(`m/84'/${network === 'mainnet' ? 0 : 1}'/0'/0/0`);
  const address = p2wpkh(child.publicKey!, network === 'mainnet' ? NETWORK : TEST_NETWORK).address!;
  root.wipePrivateData();
  return address;
}

function utxosFor(h: Harness, entries: readonly { branch: 'receive' | 'change'; index: number; sats: string }[]) {
  return entries.map((entry, position) => {
    const derived = deriveVaultOutput(h.identity, entry.branch, entry.index);
    return {
      txid: bytesToHex(sha256(`${h.network}:synthetic-utxo:${position}`)),
      vout: position,
      valueSats: entry.sats,
      scriptPubKeyHex: derived.scriptPubKeyHex,
    };
  });
}

describe('the standalone recovery package', () => {
  it('writes a relay-ready transaction body with no trailing newline', () => {
    const directory = mkdtempSync(join(tmpdir(), 'drey-recovery-'));
    const target = join(directory, 'tx.hex');
    try {
      writeTransactionHexFile(target, '02000000');
      expect(readFileSync(target)).toEqual(Buffer.from('02000000', 'ascii'));
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  describe('reads a public kit without believing any of it', () => {
    it('regenerates the policy, descriptors, and first address from the signer origins alone', () => {
      for (const network of ['mainnet', 'signet'] as const) {
        const h = harness(network);
        const verified = verifyKitHex(h.kitHex);
        expect(verified.identity.policyId).toBe(h.identity.policyId);
        expect(verified.identity.receiveDescriptor).toBe(h.identity.receiveDescriptor);
        expect(verified.kit.firstReceiveAddress)
          .toBe(deriveVaultOutput(verified.identity, 'receive', 0).address);
      }
    });

    it('refuses a kit whose stated policy ID does not follow from its signers', () => {
      const h = harness('signet');
      // Flip one hex digit of the embedded policy ID.
      const target = h.identity.policyId;
      const tampered = h.kitHex.replace(target, target.slice(0, -1) + (target.endsWith('a') ? 'b' : 'a'));
      expect(tampered).not.toBe(h.kitHex);
      expect(() => verifyKitHex(tampered)).toThrow();
    });

    it('accepts hex with whitespace and rejects anything that is not hex', () => {
      const h = harness('signet');
      expect(() => verifyKitHex(`  ${h.kitHex.slice(0, 40)}\n${h.kitHex.slice(40)}  `)).not.toThrow();
      expect(() => verifyKitHex('not hex at all')).toThrow(/hex/u);
    });

    it('derives a ladder that agrees with the policy at every index', () => {
      const h = harness('mainnet');
      const ladder = deriveLadder(h.identity, 'receive', 0, 19);
      expect(ladder).toHaveLength(20);
      for (const entry of ladder) {
        expect(entry.address).toBe(deriveVaultOutput(h.identity, 'receive', entry.index).address);
      }
      expect(locateScript(h.identity, ladder[7]!.scriptPubKeyHex, 20)).toEqual({
        branch: 'receive', index: 7, witnessScriptHex: ladder[7]!.witnessScriptHex,
      });
    });
  });

  describe('builds a recovery spend from an untrusted UTXO set', () => {
    it('refuses an outpoint the policy cannot regenerate', () => {
      const h = harness('signet');
      expect(() => resolveInputs(h.identity, [{
        txid: bytesToHex(sha256('foreign')), vout: 0, valueSats: '50000',
        scriptPubKeyHex: '0014' + '11'.repeat(20),
      }])).toThrow(/not owned by this Vault policy/u);
    }, 10_000);

    it('refuses a duplicate outpoint rather than silently spending it once', () => {
      const h = harness('signet');
      const [utxo] = utxosFor(h, [{ branch: 'receive', index: 0, sats: '50000' }]);
      expect(() => resolveInputs(h.identity, [utxo!, utxo!])).toThrow(/duplicate outpoint/u);
    });

    it('refuses a destination that is inside the same Vault', () => {
      const h = harness('signet');
      const inputs = resolveInputs(h.identity, utxosFor(h, [{ branch: 'receive', index: 0, sats: '50000' }]));
      expect(() => buildRecoveryPlan({
        identity: h.identity, inputs,
        destinationAddress: deriveVaultOutput(h.identity, 'receive', 5).address,
        feeRateSatPerVb: 3n, nowMs: CREATED,
      })).toThrow(/belongs to this same Vault policy/u);
    });

    it('refuses dust change instead of absorbing it into the fee', () => {
      const h = harness('signet');
      const inputs = resolveInputs(h.identity, utxosFor(h, [{ branch: 'receive', index: 0, sats: '50000' }]));
      const built = buildRecoveryPlan({
        identity: h.identity, inputs, destinationAddress: exitAddress('signet'),
        feeRateSatPerVb: 3n, nowMs: CREATED,
      });
      const almostEverything = BigInt(built.plan.amountSats) - (MIN_CHANGE_SATS - 100n);
      expect(() => buildRecoveryPlan({
        identity: h.identity, inputs, destinationAddress: exitAddress('signet'),
        feeRateSatPerVb: 3n, amountSats: almostEverything, nowMs: CREATED,
      })).toThrow(/below the .* floor/u);
    });

    it('refuses when the fee would consume everything', () => {
      const h = harness('signet');
      const inputs = resolveInputs(h.identity, utxosFor(h, [{ branch: 'receive', index: 0, sats: '400' }]));
      expect(() => buildRecoveryPlan({
        identity: h.identity, inputs, destinationAddress: exitAddress('signet'),
        feeRateSatPerVb: 3n, nowMs: CREATED,
      })).toThrow(/nothing would reach the destination/u);
    });

    it('writes the published sentinels where a gateway would have spoken', () => {
      const h = harness('signet');
      const inputs = resolveInputs(h.identity, utxosFor(h, [{ branch: 'receive', index: 0, sats: '50000' }]));
      const { plan } = buildRecoveryPlan({
        identity: h.identity, inputs, destinationAddress: exitAddress('signet'),
        feeRateSatPerVb: 3n, nowMs: CREATED,
      });
      expect(plan.source.backendInstanceIdHash).toBe(STANDALONE_SOURCE_SENTINEL.backend);
      expect(plan.source.classificationRevisionHash).toBe(STANDALONE_SOURCE_SENTINEL.revision);
      expect(plan.inputs[0]!.classificationEvidenceHash).toBe(STANDALONE_SOURCE_SENTINEL.classification);
      expect(plan.inputs[0]!.classification).toBe('unknown');
      expect(plan.kind).toBe('recovery');
      expect(plan.destination.kind).toBe('recovery-exit');
      expect(plan.broadcastIntent).toBe('return-psbt');
      expect(plan.assetEffects).toEqual([]);
      // The sentinels are not zeros, so an auditor can tell them apart from an
      // unset field at a glance.
      expect(plan.source.backendInstanceIdHash).not.toMatch(/^0+$/u);
    });
  });

  describe('the required drills', () => {
    for (const network of ['mainnet', 'signet'] as const) {
      for (const quorum of [
        ['desktop-a', 'recovery-c'],
        ['mobile-b', 'recovery-c'],
      ] as const) {
        it(`${network}: ${quorum.join(' + ')} sweeps the Vault`, () => {
          const h = harness(network);
          const inputs = resolveInputs(h.identity, utxosFor(h, [
            { branch: 'receive', index: 0, sats: '25000' },
            { branch: 'change', index: 1, sats: '633' },
          ]));
          const { plan } = buildRecoveryPlan({
            identity: h.identity, inputs, destinationAddress: exitAddress(network),
            feeRateSatPerVb: 3n, nowMs: CREATED,
          });
          expect(plan.changeSats).toBe('0');

          const partials = quorum.map((role) => signAsRole({
            identity: h.identity, plan, role, mnemonic: MNEMONICS[role], nowMs: CREATED,
          }));
          // Signing must not depend on the wall clock: nowMs defaults to the
          // plan's own creation time precisely so an offline machine with a
          // wrong clock still produces a valid signature.
          const combined = combineResults(h.identity, plan, partials);
          expect([...combined.roles].sort()).toEqual([...quorum].sort());

          const finalized = finalize(h.identity, plan, combined.psbtHex, CREATED);
          expect(finalized.txid).toMatch(/^[0-9a-f]{64}$/u);
          expect(finalized.transactionHex.length).toBeGreaterThan(0);

          const facts = reviewFacts(h.identity, plan, combined.psbtHex);
          expect(facts.disagreements).toEqual([]);
          expect([...facts.rolesPresent].sort()).toEqual([...quorum].sort());
        });
      }
    }

    it('a plan with change proves the change output back to the policy', () => {
      const h = harness('signet');
      const inputs = resolveInputs(h.identity, utxosFor(h, [{ branch: 'receive', index: 0, sats: '25000' }]));
      const { plan } = buildRecoveryPlan({
        identity: h.identity, inputs, destinationAddress: exitAddress('signet'),
        feeRateSatPerVb: 3n, amountSats: 12_000n, changeIndex: 3, nowMs: CREATED,
      });
      const facts = reviewFacts(h.identity, plan);
      expect(facts.changeProvenOwned).toBe(true);
      expect(facts.changeAddress).toBe(deriveVaultOutput(h.identity, 'change', 3).address);
      expect(facts.disagreements).toEqual([]);
      expect(renderReview(h.identity, plan)).toContain('PROVED — regenerated from this policy');
    });

    it('refuses a second signature from the same logical role', () => {
      const h = harness('signet');
      const inputs = resolveInputs(h.identity, utxosFor(h, [{ branch: 'receive', index: 0, sats: '25000' }]));
      const { plan } = buildRecoveryPlan({
        identity: h.identity, inputs, destinationAddress: exitAddress('signet'),
        feeRateSatPerVb: 3n, nowMs: CREATED,
      });
      const once = signAsRole({
        identity: h.identity, plan, role: 'recovery-c', mnemonic: MNEMONICS['recovery-c'], nowMs: CREATED,
      });
      expect(() => combineResults(h.identity, plan, [once, once])).toThrow();
    });
  });

  describe('the review screen computes rather than echoes', () => {
    it('reports a plan whose stated fee disagrees with its bytes', () => {
      const h = harness('signet');
      const inputs = resolveInputs(h.identity, utxosFor(h, [{ branch: 'receive', index: 0, sats: '25000' }]));
      const { plan } = buildRecoveryPlan({
        identity: h.identity, inputs, destinationAddress: exitAddress('signet'),
        feeRateSatPerVb: 3n, nowMs: CREATED,
      });
      const lying = { ...plan, feeSats: '1', amountSats: '1' };
      const facts = reviewFacts(h.identity, lying);
      expect(facts.disagreements.length).toBeGreaterThan(0);
      expect(facts.feeSats).toBe(BigInt(plan.feeSats));
      expect(renderReview(h.identity, lying)).toContain('DO NOT SIGN');
    });
  });
});

describe('the committed golden vectors', () => {
  const planVectors = JSON.parse(readFileSync(
    join(import.meta.dirname, '..', '..', 'vectors', 'vault-recovery-plan-v1.json'), 'utf8',
  )) as { records: Record<Net, {
    policy: VaultPolicyIdentityV1;
    kitHex: string;
    sentinels: { backend: string; revision: string; classification: string };
    cases: Record<'sweep' | 'withChange', {
      plan: VaultUnsignedPlanV1;
      canonicalPlanHex: string;
      unsignedPsbtHex: string;
      quorums: Record<string, {
        roles: VaultSignerRole[]; combinedPsbtHex: string;
        transactionHex: string; txid: string; wtxid: string; finalizedVsize: number;
      }>;
    }>;
  }> };

  const kitVectors = JSON.parse(readFileSync(
    join(import.meta.dirname, '..', '..', 'vectors', 'vault-recovery-kit-v1.json'), 'utf8',
  )) as { records: Record<Net, {
    text: { compatibilityRequirements: string[]; recoveryInstructions: string; rotationInstructions: string };
    unpublishedDigests: { kit: VaultRecoveryKitV1; kitHex: string };
    publishedDigests: { kit: VaultRecoveryKitV1; kitHex: string };
  }> };

  for (const network of ['mainnet', 'signet'] as const) {
    it(`${network}: the kit vector pins the production prose exactly`, () => {
      const record = kitVectors.records[network];
      // If this fails, someone copy-edited kit text without regenerating the
      // vectors — which would silently change the bytes of every kit minted
      // afterwards.
      expect(record.text.compatibilityRequirements)
        .toEqual([...VAULT_RECOVERY_KIT_TEXT_V1.compatibilityRequirements]);
      expect(record.text.recoveryInstructions).toBe(VAULT_RECOVERY_KIT_TEXT_V1.recoveryInstructions);
      expect(record.text.rotationInstructions).toBe(VAULT_RECOVERY_KIT_TEXT_V1.rotationInstructions);
    });

    it(`${network}: both digest states parse and verify`, () => {
      const record = kitVectors.records[network];
      for (const variant of [record.unpublishedDigests, record.publishedDigests]) {
        const verified = verifyKitHex(variant.kitHex);
        expect(verified.kit).toEqual(variant.kit);
        expect(verified.identity.policyId).toBe(variant.kit.policyId);
      }
      // A kit minted before any package was published carries the sentinel, and
      // a reader must keep accepting those for as long as such a Vault exists.
      expect(record.unpublishedDigests.kit.standaloneToolArtifactDigest).toBe('00'.repeat(32));
      expect(record.publishedDigests.kit.standaloneToolArtifactDigest).not.toMatch(/^0+$/u);
    });

    for (const shape of ['sweep', 'withChange'] as const) {
      it(`${network} ${shape}: the plan vector replays byte for byte`, () => {
        const record = planVectors.records[network];
        const vector = record.cases[shape];
        const { identity } = verifyKitHex(record.kitHex);
        expect(identity).toEqual(record.policy);

        expect(vector.plan.kind).toBe('recovery');
        expect(vector.plan.destination.kind).toBe('recovery-exit');
        expect(vector.plan.source.backendInstanceIdHash).toBe(STANDALONE_SOURCE_SENTINEL.backend);
        expect(record.sentinels).toEqual(STANDALONE_SOURCE_SENTINEL);

        expect(bytesToHex(canonicalVaultPlanBytes(vector.plan))).toBe(vector.canonicalPlanHex);
        expect(constructVaultPsbt(identity, vector.plan)).toBe(vector.unsignedPsbtHex);

        // Exactly the two drills ADR 0007 §6 requires, and no A+B: the
        // finalizer prefers A+B whenever all three are present, so a vector
        // that included it could pass while neither drill actually ran.
        expect(Object.keys(vector.quorums).sort())
          .toEqual(['desktop-a+recovery-c', 'mobile-b+recovery-c']);

        for (const [name, quorum] of Object.entries(vector.quorums)) {
          const partials = quorum.roles.map((role) => signAsRole({
            identity, plan: vector.plan, role, mnemonic: MNEMONICS[role], nowMs: CREATED,
          }));
          const combined = combineResults(identity, vector.plan, partials);
          expect(combined.psbtHex, name).toBe(quorum.combinedPsbtHex);
          const finalized = finalize(identity, vector.plan, combined.psbtHex, CREATED);
          expect(finalized.transactionHex, name).toBe(quorum.transactionHex);
          expect(finalized.txid, name).toBe(quorum.txid);
          expect(finalized.wtxid, name).toBe(quorum.wtxid);
        }
      });
    }

    it(`${network}: the two quorums share a txid but not a wtxid`, () => {
      const cases = planVectors.records[network].cases.sweep.quorums;
      const [first, second] = Object.values(cases);
      // Segwit puts signatures in the witness, so a different quorum spending
      // the same inputs produces the same txid. If these wtxids were equal the
      // vector would not actually be covering two distinct signature sets.
      expect(first!.txid).toBe(second!.txid);
      expect(first!.wtxid).not.toBe(second!.wtxid);
    });
  }
});

describe('the source-digest rule', () => {
  it('is order-independent of the filesystem and separates path from content', async () => {
    const { treeDigest } = await import('../../recovery/digest.mjs');
    const base = join(import.meta.dirname, '..', '..');
    // Sorted path order is part of the rule, so a caller passing the same set
    // in a different order must get the same digest.
    const files = ['package.json', 'tsconfig.json'];
    expect(treeDigest(base, files)).toBe(treeDigest(base, [...files]));
    expect(treeDigest(base, files)).not.toBe(treeDigest(base, [...files].reverse()));
    expect(treeDigest(base, files)).toMatch(/^[0-9a-f]{64}$/u);
  });
});
