/**
 * Golden vectors for the standalone recovery package (ADR 0007 §6, C7).
 *
 * Two files, covering the two things nothing else pins:
 *
 *   vault-recovery-kit-v1   the *production* kit literals and their exact SQVB
 *                           bytes. The existing vault-contracts-v1 recoveryKit
 *                           record uses synthetic digests and placeholder prose,
 *                           so until now no committed artifact would have caught
 *                           a copy-edit to the text a real kit carries.
 *   vault-recovery-plan-v1  the `recovery` / `recovery-exit` plan shape, which
 *                           was schema-legal but had never been serialized,
 *                           signed, combined, or finalized anywhere.
 *
 * The A+C and B+C quorums are enumerated explicitly. `finalizeVaultPsbt`
 * deterministically prefers A+B whenever all three signatures are present, so a
 * generator that simply signed with everything would produce a vector that
 * silently never exercised either of the two drills ADR 0007 §6 actually
 * requires.
 *
 * All fixture material here is derived from published BIP39 test vectors and is
 * public by construction. None of it may ever hold value.
 */
import { createHash } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { HDKey } from '@scure/bip32';
import { NETWORK, TEST_NETWORK, p2wpkh } from '@scure/btc-signer';
import { setCryptoProvider, type CryptoProvider } from '../src/domain/vault/crypto-provider';
import { bytesToHex } from '../src/domain/vault/encoding';
import {
  VAULT_RECOVERY_KIT_TEXT_V1,
  VAULT_ROLES,
  bip32Versions,
  vaultAccountOriginPath,
  vaultRecoveryKitSchema,
  type VaultRecoveryKitV1,
  type VaultSignerOriginV1,
  type VaultSignerRole,
  type RecoveryCBackupCheckChallengeV1,
  type RecoveryCSetupChallengeV1,
} from '../src/domain/vault/multisig-contracts';
import {
  canonicalVaultPlanBytes,
  recoveryCChallengeFingerprint,
  recoveryCSetupChallengeDigest,
  serializeRecoveryCBackupCheckChallenge,
  serializeRecoveryCBackupCheckResponse,
  serializeRecoveryCSetupChallenge,
  serializeRecoveryCSetupResponse,
  serializeVaultRecoveryKit,
} from '../src/domain/vault/multisig-encoding';
import { signVaultProofOfPossession } from '../src/domain/vault/multisig-role';
import {
  recoveryCSetupProofInput,
  signRecoveryCBackupCheck,
} from '../src/domain/vault/recovery-c-ceremony';
import {
  deriveVaultOutput,
  generateVaultPolicyIdentity,
} from '../src/domain/vault/multisig-descriptors';
import { constructVaultPsbt } from '../src/domain/vault/multisig-psbt';
import { mnemonicToSeed } from '../src/domain/keys/mnemonic';
import { buildRecoveryPlan, resolveInputs, STANDALONE_SOURCE_SENTINEL } from './src/plan';
import { combineResults, finalize, signAsRole } from './src/signing';

const sha256 = (bytes: Uint8Array): Uint8Array => new Uint8Array(createHash('sha256').update(bytes).digest());
const hash = (value: string): Uint8Array => sha256(Buffer.from(value, 'utf8'));
const hashHex = (value: string): string => bytesToHex(hash(value));

const provider: CryptoProvider = {
  argon2id: async () => { throw new Error('unused'); },
  xchaEncrypt: () => { throw new Error('unused'); },
  xchaDecrypt: () => { throw new Error('unused'); },
  sha256,
  ed25519Verify: () => { throw new Error('unused'); },
  randomBytes: () => { throw new Error('vectors never use runtime randomness'); },
};
setCryptoProvider(provider);

/** Published BIP39 test vectors. Public by definition; never fund these. */
const MNEMONICS: Record<VaultSignerRole, string> = {
  'desktop-a': 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
  'mobile-b': 'legal winner thank year wave sausage worth useful legal winner thank yellow',
  'recovery-c': 'letter advice cage absurd amount doctor acoustic avoid letter advice cage above',
};

type Net = 'mainnet' | 'signet';
const CREATED = 1_785_542_400_000n;

function originFor<R extends VaultSignerRole>(network: Net, role: R): VaultSignerOriginV1 & { role: R } {
  const seed = mnemonicToSeed(MNEMONICS[role]);
  const root = HDKey.fromMasterSeed(seed, bip32Versions(network));
  try {
    const originPath = vaultAccountOriginPath(network);
    return {
      version: 1, role, network,
      masterFingerprintHex: root.fingerprint.toString(16).padStart(8, '0'),
      originPath,
      accountXpub: root.derive(originPath).publicExtendedKey,
    };
  } finally {
    seed.fill(0);
    root.wipePrivateData();
  }
}

function exitAddress(network: Net): string {
  const root = HDKey.fromMasterSeed(hash(`${network}:C7 recovery destination`), bip32Versions(network));
  const child = root.derive(`m/84'/${network === 'mainnet' ? 0 : 1}'/0'/0/0`);
  return p2wpkh(child.publicKey!, network === 'mainnet' ? NETWORK : TEST_NETWORK).address!;
}

function makeKit(network: Net) {
  const signers = VAULT_ROLES.map((role) => originFor(network, role)) as
    [VaultSignerOriginV1, VaultSignerOriginV1, VaultSignerOriginV1];
  const identity = generateVaultPolicyIdentity(network, signers);
  const base = {
    version: 1 as const, network, policyVersion: 1 as const, policyId: identity.policyId, signers,
    receiveDescriptor: identity.receiveDescriptor, changeDescriptor: identity.changeDescriptor,
    createdAtMs: CREATED.toString(), birthdayHeight: network === 'mainnet' ? 910_000 : 250_000,
    vaultLabel: `${network} public fixture vault`,
    signerLabels: ['Fixture Desktop', 'Fixture Mobile', 'Fixture Recovery'] as [string, string, string],
    firstReceiveAddress: deriveVaultOutput(identity, 'receive', 0).address,
    compatibilityRequirements: [...VAULT_RECOVERY_KIT_TEXT_V1.compatibilityRequirements],
    minimumReaderVersion: 1 as const,
    recoveryInstructions: VAULT_RECOVERY_KIT_TEXT_V1.recoveryInstructions,
    rotationInstructions: VAULT_RECOVERY_KIT_TEXT_V1.rotationInstructions,
    recoveryInstructionsVersion: 1 as const,
  };

  // Both digest states, because both occur in the wild: every kit minted before
  // the first published release carries the all-zero sentinel, and a reader
  // must keep accepting those for as long as such a Vault exists.
  const unpublished: VaultRecoveryKitV1 = vaultRecoveryKitSchema.parse({
    ...base,
    standaloneToolSourceDigest: '00'.repeat(32),
    standaloneToolArtifactDigest: '00'.repeat(32),
  });
  const published: VaultRecoveryKitV1 = vaultRecoveryKitSchema.parse({
    ...base,
    standaloneToolSourceDigest: hashHex('C7 fixture standalone source'),
    standaloneToolArtifactDigest: hashHex('C7 fixture standalone artifact'),
  });

  return {
    identity,
    unpublished: { kit: unpublished, kitHex: bytesToHex(serializeVaultRecoveryKit(unpublished)) },
    published: { kit: published, kitHex: bytesToHex(serializeVaultRecoveryKit(published)) },
  };
}

const QUORUMS = [
  ['desktop-a', 'recovery-c'],
  ['mobile-b', 'recovery-c'],
] as const;

function makePlanCase(
  network: Net,
  identity: ReturnType<typeof generateVaultPolicyIdentity>,
  label: 'sweep' | 'withChange',
) {
  const utxos = [
    {
      txid: hashHex(`${network}:C7 recovery prevout 0`), vout: 0, valueSats: '25000',
      scriptPubKeyHex: deriveVaultOutput(identity, 'receive', 0).scriptPubKeyHex,
    },
    {
      txid: hashHex(`${network}:C7 recovery prevout 1`), vout: 1, valueSats: '633',
      scriptPubKeyHex: deriveVaultOutput(identity, 'change', 1).scriptPubKeyHex,
    },
  ];
  const inputs = resolveInputs(identity, label === 'sweep' ? utxos : [utxos[0]!]);
  const { plan } = buildRecoveryPlan({
    identity, inputs,
    destinationAddress: exitAddress(network),
    feeRateSatPerVb: 3n,
    ...(label === 'withChange' ? { amountSats: 12_000n, changeIndex: 3 } : {}),
    nowMs: CREATED,
    planId: hashHex(`${network}:C7 plan:${label}`).slice(0, 32),
    requestId: hashHex(`${network}:C7 request:${label}`).slice(0, 32),
  });

  const unsignedPsbtHex = constructVaultPsbt(identity, plan);
  const partials = Object.fromEntries(VAULT_ROLES.map((role) => [
    role,
    signAsRole({ identity, plan, role, mnemonic: MNEMONICS[role], nowMs: CREATED }),
  ]));

  const quorums = Object.fromEntries(QUORUMS.map((quorum) => {
    const combined = combineResults(identity, plan, quorum.map((role) => partials[role]!));
    const finalized = finalize(identity, plan, combined.psbtHex, CREATED);
    return [quorum.join('+'), {
      roles: [...quorum],
      combinedPsbtHex: combined.psbtHex,
      transactionHex: finalized.transactionHex,
      txid: finalized.txid,
      wtxid: finalized.wtxid,
      finalizedVsize: finalized.vsize,
    }];
  }));

  return {
    utxoFile: { utxos },
    plan,
    canonicalPlanHex: bytesToHex(canonicalVaultPlanBytes(plan)),
    unsignedPsbtHex,
    partials,
    quorums,
  };
}

const kitRecords: Record<string, unknown> = {};
const planRecords: Record<string, unknown> = {};
const ceremonyRecords: Record<string, unknown> = {};

for (const network of ['mainnet', 'signet'] as const) {
  const { identity, unpublished, published } = makeKit(network);
  kitRecords[network] = {
    policyId: identity.policyId,
    text: {
      compatibilityRequirements: [...VAULT_RECOVERY_KIT_TEXT_V1.compatibilityRequirements],
      recoveryInstructions: VAULT_RECOVERY_KIT_TEXT_V1.recoveryInstructions,
      rotationInstructions: VAULT_RECOVERY_KIT_TEXT_V1.rotationInstructions,
    },
    unpublishedDigests: unpublished,
    publishedDigests: published,
  };
  planRecords[network] = {
    policy: identity,
    kitHex: published.kitHex,
    sentinels: STANDALONE_SOURCE_SENTINEL,
    cases: {
      sweep: makePlanCase(network, identity, 'sweep'),
      withChange: makePlanCase(network, identity, 'withChange'),
    },
  };

  const setupChallenge: RecoveryCSetupChallengeV1 = {
    version: 1, role: 'recovery-c', network,
    sessionIdHex: hashHex(`${network}:Recovery C setup session`).slice(0, 32),
    challengeNonceHex: hashHex(`${network}:Recovery C setup nonce`),
    transcriptHashHex: hashHex(`${network}:Recovery C Desktop A transcript`),
    desktopOrigin: originFor(network, 'desktop-a'),
    createdAtMs: CREATED.toString(), expiresAtMs: (CREATED + 86_400_000n).toString(),
  };
  const recoverySeed = mnemonicToSeed(MNEMONICS['recovery-c']);
  try {
    const recoveryOrigin = originFor(network, 'recovery-c') as VaultSignerOriginV1 & { role: 'recovery-c' };
    const setupResponse = {
      version: 1 as const,
      challengeDigestHex: recoveryCSetupChallengeDigest(setupChallenge),
      origin: recoveryOrigin,
      proof: {
        ...signVaultProofOfPossession(
          recoverySeed,
          recoveryCSetupProofInput(setupChallenge, recoveryOrigin),
          (CREATED + 1n).toString(),
        ),
        role: 'recovery-c' as const,
      },
    };
    const backupChallenge: RecoveryCBackupCheckChallengeV1 = {
      version: 1, role: 'recovery-c', network, policyId: identity.policyId, recoveryOrigin,
      sessionIdHex: hashHex(`${network}:Recovery C backup session`).slice(0, 32),
      challengeNonceHex: hashHex(`${network}:Recovery C backup nonce`),
      standaloneToolVersion: 'drey-vault-recovery-v1',
      standaloneToolSourceDigest: published.kit.standaloneToolSourceDigest,
      standaloneToolArtifactDigest: published.kit.standaloneToolArtifactDigest,
      createdAtMs: CREATED.toString(), expiresAtMs: (CREATED + 86_400_000n).toString(),
    };
    const backupResponse = signRecoveryCBackupCheck(
      recoverySeed, backupChallenge, (CREATED + 1n).toString(),
    );
    ceremonyRecords[network] = {
      setup: {
        challenge: setupChallenge,
        challengeHex: bytesToHex(serializeRecoveryCSetupChallenge(setupChallenge)),
        fingerprint: recoveryCChallengeFingerprint(setupChallenge),
        response: setupResponse,
        responseHex: bytesToHex(serializeRecoveryCSetupResponse(setupResponse)),
      },
      backupCheck: {
        challenge: backupChallenge,
        challengeHex: bytesToHex(serializeRecoveryCBackupCheckChallenge(backupChallenge)),
        fingerprint: recoveryCChallengeFingerprint(backupChallenge),
        response: backupResponse,
        responseHex: bytesToHex(serializeRecoveryCBackupCheckResponse(backupResponse)),
      },
    };
  } finally {
    recoverySeed.fill(0);
  }
}

// Resolved against the repository root rather than the module URL: this file is
// bundled into node_modules/.cache before it runs, so import.meta.url points at
// the build output, not at the source tree the vectors belong to.
const vectorsDir = join(process.cwd(), 'vectors');

writeFileSync(
  join(vectorsDir, 'vault-recovery-kit-v1.json'),
  `${JSON.stringify({ version: 1, records: kitRecords }, null, 2)}\n`,
);
writeFileSync(
  join(vectorsDir, 'vault-recovery-plan-v1.json'),
  `${JSON.stringify({ version: 1, records: planRecords }, null, 2)}\n`,
);
writeFileSync(
  join(vectorsDir, 'recovery-c-ceremony-v1.json'),
  `${JSON.stringify({ version: 1, records: ceremonyRecords }, null, 2)}\n`,
);

process.stdout.write('wrote vault-recovery-kit-v1.json, vault-recovery-plan-v1.json, and recovery-c-ceremony-v1.json\n');
