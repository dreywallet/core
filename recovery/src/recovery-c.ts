import type { Rng } from '../../src/domain/keys/mnemonic';
import { generateMnemonic, restoreMnemonic, validateMnemonic } from '../../src/domain/keys/mnemonic';
import type {
  RecoveryCBackupCheckChallengeV1,
  RecoveryCSetupChallengeV1,
  RecoveryCSetupResponseV1,
  VaultRecoveryKitV1,
  VaultSignerOriginV1,
} from '../../src/domain/vault/multisig-contracts';
import { recoveryCSetupResponseSchema } from '../../src/domain/vault/multisig-contracts';
import {
  parseRecoveryCBackupCheckChallenge,
  parseRecoveryCSetupChallenge,
  recoveryCChallengeFingerprint,
  recoveryCSetupChallengeDigest,
} from '../../src/domain/vault/multisig-encoding';
import { deriveVaultRoleOrigin, signVaultProofOfPossession } from '../../src/domain/vault/multisig-role';
import {
  recoveryCSetupProofInput,
  signRecoveryCBackupCheck,
} from '../../src/domain/vault/recovery-c-ceremony';
import type { VerifiedKit } from './kit';

export interface RecoveryCInteractiveIo {
  readonly inputIsTTY: boolean;
  readonly outputIsTTY: boolean;
  write(line?: string): void;
  readVisible(prompt: string): Promise<string>;
  readHidden(prompt: string): Promise<string>;
}

export function assertRecoveryCInteractive(io: RecoveryCInteractiveIo): void {
  if (!io.inputIsTTY || !io.outputIsTTY) {
    throw new Error(
      'Recovery C creation and word entry require a directly controlled interactive terminal. ' +
      'Redirected input/output, pipes, CI, and unattended execution are refused before any secret is created.',
    );
  }
}

function sameOrigin(left: VaultSignerOriginV1, right: VaultSignerOriginV1): boolean {
  return left.version === right.version && left.role === right.role && left.network === right.network &&
    left.masterFingerprintHex === right.masterFingerprintHex && left.originPath === right.originPath &&
    left.accountXpub === right.accountXpub;
}

function randomIndex(rng: Rng, inclusiveMax: number): number {
  const range = inclusiveMax + 1;
  const ceiling = Math.floor(256 / range) * range;
  for (;;) {
    const draw = rng(1);
    if (draw.length !== 1) throw new Error('rng returned the wrong number of shuffle bytes');
    const value = draw[0]!;
    draw.fill(0);
    if (value < ceiling) return value % range;
  }
}

export function shuffledRecoveryCPositions(rng: Rng): number[] {
  const positions = Array.from({ length: 12 }, (_, index) => index);
  for (let index = positions.length - 1; index > 0; index -= 1) {
    const swap = randomIndex(rng, index);
    [positions[index], positions[swap]] = [positions[swap]!, positions[index]!];
  }
  return positions;
}

function displayWords(io: RecoveryCInteractiveIo, words: readonly string[]): void {
  io.write('');
  io.write('Write these 12 words by hand on durable paper. Do not photograph, print, copy, or save them.');
  io.write('This is one Recovery vote in a 2-of-3 Vault. It is not your Spending Recovery Phrase.');
  io.write('');
  for (let row = 0; row < 4; row += 1) {
    io.write(Array.from({ length: 3 }, (_, column) => {
      const index = row * 3 + column;
      return `${String(index + 1).padStart(2)}. ${words[index]!.padEnd(10)}`;
    }).join('   '));
  }
  io.write('');
}

async function confirmAllWords(
  io: RecoveryCInteractiveIo,
  words: readonly string[],
  rng: Rng,
): Promise<void> {
  let failures = 0;
  for (const position of shuffledRecoveryCPositions(rng)) {
    for (;;) {
      const answer = (await io.readHidden(`Type word ${position + 1}: `)).trim().toLowerCase();
      if (answer === words[position]) break;
      failures += 1;
      if (failures >= 3) {
        throw new Error('three word confirmations were incorrect; no public response was created');
      }
      io.write(`That did not match word ${position + 1}. Check the paper and try again.`);
    }
  }
}

export function readRecoveryCSetupChallenge(bytes: Uint8Array, nowMs: bigint): RecoveryCSetupChallengeV1 {
  const challenge = parseRecoveryCSetupChallenge(bytes);
  if (nowMs > BigInt(challenge.expiresAtMs)) throw new Error('this Recovery C setup challenge has expired');
  return challenge;
}

export async function createRecoveryCResponse(input: {
  challengeBytes: Uint8Array;
  io: RecoveryCInteractiveIo;
  rng: Rng;
  nowMs: bigint;
}): Promise<RecoveryCSetupResponseV1> {
  assertRecoveryCInteractive(input.io);
  const challenge = readRecoveryCSetupChallenge(input.challengeBytes, input.nowMs);
  input.io.write(`Network: ${challenge.network}`);
  input.io.write('Role: Vault Recovery Key C (one vote; it cannot spend alone)');
  input.io.write(`Challenge: ${recoveryCChallengeFingerprint(challenge)}`);
  input.io.write(`Expires: ${new Date(Number(challenge.expiresAtMs)).toISOString()}`);
  input.io.write(`Desktop A fingerprint: ${challenge.desktopOrigin.masterFingerprintHex}`);
  input.io.write('');
  const ready = (await input.io.readVisible(
    'Type CREATE only after networking, logging, screenshots, clipboard tools, swap, and hibernation are disabled: ',
  )).trim();
  if (ready !== 'CREATE') throw new Error('Recovery C creation cancelled before entropy was drawn');

  const generated = generateMnemonic(input.rng);
  const words = generated.mnemonic.split(' ');
  let restoredEntropy: Uint8Array | undefined;
  let seed: Uint8Array | undefined;
  try {
    displayWords(input.io, words);
    await confirmAllWords(input.io, words, input.rng);
    const restored = restoreMnemonic(generated.mnemonic);
    restoredEntropy = restored.entropy;
    seed = restored.seed;
    const origin = deriveVaultRoleOrigin(seed, 'recovery-c', challenge.network);
    const proof = signVaultProofOfPossession(
      seed, recoveryCSetupProofInput(challenge, origin), input.nowMs.toString(),
    );
    return recoveryCSetupResponseSchema.parse({
      version: 1,
      challengeDigestHex: recoveryCSetupChallengeDigest(challenge),
      origin,
      proof,
    });
  } finally {
    generated.entropy.fill(0);
    restoredEntropy?.fill(0);
    seed?.fill(0);
    words.fill('');
  }
}

export function readRecoveryCBackupChallenge(
  bytes: Uint8Array,
  verifiedKit: VerifiedKit,
  toolVersion: string,
  artifactDigest: string,
  nowMs: bigint,
): RecoveryCBackupCheckChallengeV1 {
  const challenge = parseRecoveryCBackupCheckChallenge(bytes);
  const kit: VaultRecoveryKitV1 = verifiedKit.kit;
  const kitRecovery = verifiedKit.identity.signers[2];
  if (nowMs > BigInt(challenge.expiresAtMs)) throw new Error('this Recovery C backup-check challenge has expired');
  if (challenge.network !== verifiedKit.identity.network || challenge.policyId !== verifiedKit.identity.policyId) {
    throw new Error('the backup-check challenge is for a different Vault or network');
  }
  if (!sameOrigin(challenge.recoveryOrigin, kitRecovery)) {
    throw new Error('the backup-check challenge names a different Recovery C origin');
  }
  if (challenge.standaloneToolVersion !== toolVersion ||
      challenge.standaloneToolSourceDigest !== kit.standaloneToolSourceDigest ||
      challenge.standaloneToolArtifactDigest !== kit.standaloneToolArtifactDigest) {
    throw new Error('the backup-check challenge names a different standalone-tool release than the recovery kit');
  }
  if (artifactDigest !== kit.standaloneToolArtifactDigest) {
    throw new Error('this standalone artifact does not match the digest recorded in the recovery kit');
  }
  return challenge;
}

export async function verifyRecoveryCWords(input: {
  challenge: RecoveryCBackupCheckChallengeV1;
  io: RecoveryCInteractiveIo;
  nowMs: bigint;
}) {
  assertRecoveryCInteractive(input.io);
  input.io.write(`Network: ${input.challenge.network}`);
  input.io.write(`Policy: ${input.challenge.policyId}`);
  input.io.write(`Challenge: ${recoveryCChallengeFingerprint(input.challenge)}`);
  input.io.write('Enter the 12 Vault Recovery Key words. They remain hidden while you type.');
  let mnemonic = '';
  let entropy: Uint8Array | undefined;
  let seed: Uint8Array | undefined;
  try {
    mnemonic = (await input.io.readHidden('Recovery Key C words: ')).trim().toLowerCase().replace(/\s+/gu, ' ');
    if (mnemonic.split(' ').length !== 12 || !validateMnemonic(mnemonic)) {
      throw new Error('those are not a checksum-valid 12-word Vault Recovery Key');
    }
    const restored = restoreMnemonic(mnemonic);
    entropy = restored.entropy;
    seed = restored.seed;
    return signRecoveryCBackupCheck(seed, input.challenge, input.nowMs.toString());
  } finally {
    mnemonic = '';
    entropy?.fill(0);
    seed?.fill(0);
  }
}
