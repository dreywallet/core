import { createHash } from 'node:crypto';
import { beforeAll, describe, expect, it } from 'vitest';
import { mnemonicToSeed } from '../../src/domain/keys/mnemonic';
import VECTORS from '../../vectors/recovery-c-ceremony-v1.json';
import type {
  RecoveryCBackupCheckChallengeV1,
  RecoveryCSetupChallengeV1,
  RecoveryCSetupResponseV1,
} from '../../src/domain/vault/multisig-contracts';
import { hexToBytes } from '../../src/domain/vault/encoding';
import { recoveryCSetupResponseSchema } from '../../src/domain/vault/multisig-contracts';
import {
  parseRecoveryCBackupCheckChallenge,
  parseRecoveryCBackupCheckResponse,
  parseRecoveryCSetupChallenge,
  parseRecoveryCSetupResponse,
  recoveryCBackupCheckChallengeDigest,
  recoveryCChallengeFingerprint,
  recoveryCSetupChallengeDigest,
  serializeRecoveryCBackupCheckChallenge,
  serializeRecoveryCBackupCheckResponse,
  serializeRecoveryCSetupChallenge,
  serializeRecoveryCSetupResponse,
} from '../../src/domain/vault/multisig-encoding';
import { deriveVaultRoleOrigin, signVaultProofOfPossession } from '../../src/domain/vault/multisig-role';
import {
  recoveryCSetupProofInput,
  signRecoveryCBackupCheck,
  verifyRecoveryCBackupCheckResponse,
  verifyRecoveryCSetupResponse,
} from '../../src/domain/vault/recovery-c-ceremony';
import { installTestCryptoProvider } from '../helpers/install-crypto-provider';

beforeAll(() => installTestCryptoProvider());

const words = {
  desktop: 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
  recovery: 'letter advice cage absurd amount doctor acoustic avoid letter advice cage above',
  wrong: 'legal winner thank year wave sausage worth useful legal winner thank yellow',
};
const digest = (label: string): string => createHash('sha256').update(label).digest('hex');
const CREATED = 1_785_542_400_000n;
const EXPIRES = CREATED + 86_400_000n;

function seeds() {
  return {
    desktop: mnemonicToSeed(words.desktop),
    recovery: mnemonicToSeed(words.recovery),
    wrong: mnemonicToSeed(words.wrong),
  };
}

function setupChallenge(): RecoveryCSetupChallengeV1 {
  const { desktop } = seeds();
  try {
    return {
      version: 1, role: 'recovery-c', network: 'signet',
      sessionIdHex: digest('setup-session').slice(0, 32),
      challengeNonceHex: digest('setup-nonce'), transcriptHashHex: digest('setup-transcript'),
      desktopOrigin: deriveVaultRoleOrigin(desktop, 'desktop-a', 'signet'),
      createdAtMs: CREATED.toString(), expiresAtMs: EXPIRES.toString(),
    };
  } finally {
    desktop.fill(0);
  }
}

function setupResponse(challenge: RecoveryCSetupChallengeV1): RecoveryCSetupResponseV1 {
  const { recovery } = seeds();
  try {
    const origin = deriveVaultRoleOrigin(recovery, 'recovery-c', challenge.network);
    return recoveryCSetupResponseSchema.parse({
      version: 1, challengeDigestHex: recoveryCSetupChallengeDigest(challenge), origin,
      proof: signVaultProofOfPossession(
        recovery, recoveryCSetupProofInput(challenge, origin), (CREATED + 1n).toString(),
      ),
    });
  } finally {
    recovery.fill(0);
  }
}

function backupChallenge(): RecoveryCBackupCheckChallengeV1 {
  const { recovery } = seeds();
  try {
    return {
      version: 1, role: 'recovery-c', network: 'signet', policyId: digest('policy'),
      recoveryOrigin: deriveVaultRoleOrigin(recovery, 'recovery-c', 'signet'),
      sessionIdHex: digest('backup-session').slice(0, 32), challengeNonceHex: digest('backup-nonce'),
      standaloneToolVersion: 'drey-vault-recovery-v1',
      standaloneToolSourceDigest: digest('source'), standaloneToolArtifactDigest: digest('artifact'),
      createdAtMs: CREATED.toString(), expiresAtMs: EXPIRES.toString(),
    };
  } finally {
    recovery.fill(0);
  }
}

describe('Recovery C setup contracts', () => {
  it('round-trips the bounded challenge and public response byte for byte', () => {
    const challenge = setupChallenge();
    const response = setupResponse(challenge);
    const challengeBytes = serializeRecoveryCSetupChallenge(challenge);
    const responseBytes = serializeRecoveryCSetupResponse(response);
    expect(serializeRecoveryCSetupChallenge(parseRecoveryCSetupChallenge(challengeBytes))).toEqual(challengeBytes);
    expect(serializeRecoveryCSetupResponse(parseRecoveryCSetupResponse(responseBytes))).toEqual(responseBytes);
    expect(verifyRecoveryCSetupResponse(challenge, response, (CREATED + 1n).toString())).toBe(true);
    expect(recoveryCChallengeFingerprint(challenge)).toMatch(/^[0-9a-f]{4}(?:-[0-9a-f]{4}){3}$/u);
  });

  it('rejects truncation, trailing bytes, unknown versions, wrong roles, and oversized records', () => {
    const bytes = serializeRecoveryCSetupChallenge(setupChallenge());
    expect(() => parseRecoveryCSetupChallenge(bytes.slice(0, -1))).toThrow(/truncated/u);
    expect(() => parseRecoveryCSetupChallenge(Uint8Array.from([...bytes, 0]))).toThrow(/trailing/u);
    const unknownVersion = bytes.slice(); unknownVersion[5] = 2;
    expect(() => parseRecoveryCSetupChallenge(unknownVersion)).toThrow(/unknown/u);
    const wrongRole = bytes.slice(); wrongRole[6] = 1;
    expect(() => parseRecoveryCSetupChallenge(wrongRole)).toThrow();
    expect(() => parseRecoveryCSetupChallenge(new Uint8Array(8_000_001))).toThrow(/exceeds/u);
  });

  it('limits setup lifetime to 24 hours and rejects expired or cross-challenge responses', () => {
    const challenge = setupChallenge();
    expect(() => serializeRecoveryCSetupChallenge({
      ...challenge, expiresAtMs: (CREATED + 86_400_001n).toString(),
    })).toThrow(/24 hours/u);
    const response = setupResponse(challenge);
    expect(verifyRecoveryCSetupResponse(challenge, response, (EXPIRES + 1n).toString())).toBe(false);
    const replaced = { ...challenge, challengeNonceHex: digest('replacement') };
    expect(verifyRecoveryCSetupResponse(replaced, response, (CREATED + 1n).toString())).toBe(false);
    const { wrong } = seeds();
    try {
      expect(verifyRecoveryCSetupResponse({
        ...challenge, desktopOrigin: deriveVaultRoleOrigin(wrong, 'desktop-a', 'signet'),
      }, response, (CREATED + 1n).toString())).toBe(false);
      expect(verifyRecoveryCSetupResponse({
        ...challenge, createdAtMs: (CREATED + 1n).toString(),
      }, response, (CREATED + 1n).toString())).toBe(false);
    } finally {
      wrong.fill(0);
    }
  });
});

describe('Recovery C paper restore check', () => {
  it('round-trips and verifies a domain-separated response from the exact C words', () => {
    const challenge = backupChallenge();
    const { recovery } = seeds();
    try {
      const response = signRecoveryCBackupCheck(recovery, challenge, (CREATED + 1n).toString());
      const challengeBytes = serializeRecoveryCBackupCheckChallenge(challenge);
      const responseBytes = serializeRecoveryCBackupCheckResponse(response);
      expect(parseRecoveryCBackupCheckChallenge(challengeBytes)).toEqual(challenge);
      expect(parseRecoveryCBackupCheckResponse(responseBytes)).toEqual(response);
      expect(response.challengeDigestHex).toBe(recoveryCBackupCheckChallengeDigest(challenge));
      expect(verifyRecoveryCBackupCheckResponse(challenge, response, (CREATED + 1n).toString())).toBe(true);
    } finally {
      recovery.fill(0);
    }
  });

  it('rejects valid but wrong words without emitting a response', () => {
    const challenge = backupChallenge();
    const { wrong } = seeds();
    try {
      expect(() => signRecoveryCBackupCheck(wrong, challenge)).toThrow(/do not match Recovery C/u);
    } finally {
      wrong.fill(0);
    }
  });

  it('binds policy, network, origin, release identity, nonce, and expiry', () => {
    const challenge = backupChallenge();
    const { recovery } = seeds();
    try {
      const response = signRecoveryCBackupCheck(recovery, challenge, (CREATED + 1n).toString());
      for (const mutated of [
        { ...challenge, policyId: digest('other-policy') },
        { ...challenge, challengeNonceHex: digest('other-nonce') },
        { ...challenge, standaloneToolArtifactDigest: digest('other-artifact') },
        { ...challenge, expiresAtMs: (EXPIRES - 1n).toString() },
      ]) {
        expect(verifyRecoveryCBackupCheckResponse(mutated, response, (CREATED + 1n).toString())).toBe(false);
      }
      expect(verifyRecoveryCBackupCheckResponse(challenge, response, (EXPIRES + 1n).toString())).toBe(false);
    } finally {
      recovery.fill(0);
    }
  });
});

describe('committed Recovery C ceremony vectors', () => {
  for (const network of ['mainnet', 'signet'] as const) {
    it(`re-parses and verifies the ${network} setup and backup-check bytes`, () => {
      const vector = VECTORS.records[network];
      const setup = parseRecoveryCSetupChallenge(hexToBytes(vector.setup.challengeHex));
      const setupResponse = parseRecoveryCSetupResponse(hexToBytes(vector.setup.responseHex));
      expect(setup).toEqual(vector.setup.challenge);
      expect(setupResponse).toEqual(vector.setup.response);
      expect(recoveryCChallengeFingerprint(setup)).toBe(vector.setup.fingerprint);
      expect(verifyRecoveryCSetupResponse(setup, setupResponse, (BigInt(setup.createdAtMs) + 1n).toString())).toBe(true);

      const backup = parseRecoveryCBackupCheckChallenge(hexToBytes(vector.backupCheck.challengeHex));
      const backupResponse = parseRecoveryCBackupCheckResponse(hexToBytes(vector.backupCheck.responseHex));
      expect(backup).toEqual(vector.backupCheck.challenge);
      expect(backupResponse).toEqual(vector.backupCheck.response);
      expect(recoveryCChallengeFingerprint(backup)).toBe(vector.backupCheck.fingerprint);
      expect(verifyRecoveryCBackupCheckResponse(
        backup, backupResponse, (BigInt(backup.createdAtMs) + 1n).toString(),
      )).toBe(true);
    });
  }
});
