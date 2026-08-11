/**
 * Public Recovery C setup and paper-restore verification.
 *
 * The caller owns every secret byte passed here and must wipe it. All returned
 * values are public, bounded SQVB records suitable for removable media.
 */
import { secp256k1 } from '@noble/curves/secp256k1';
import { bytesToHex, hexToBytes } from './encoding';
import {
  recoveryCBackupCheckChallengeSchema,
  recoveryCBackupCheckResponseSchema,
  recoveryCSetupChallengeSchema,
  recoveryCSetupResponseSchema,
  vaultProofOfPossessionInputSchema,
  type RecoveryCBackupCheckChallengeV1,
  type RecoveryCBackupCheckResponseV1,
  type RecoveryCSetupChallengeV1,
  type RecoveryCSetupResponseV1,
  type VaultProofOfPossessionInputV1,
  type VaultSignerOriginV1,
} from './multisig-contracts';
import {
  recoveryCBackupCheckChallengeDigest,
  recoveryCSetupChallengeDigest,
  verifyVaultProofOfPossession,
} from './multisig-encoding';
import { deriveProofPublicKeyHex, deriveVaultRoleOrigin, vaultSignerRoot } from './multisig-role';

function sameOrigin(left: VaultSignerOriginV1, right: VaultSignerOriginV1): boolean {
  return left.version === right.version && left.role === right.role && left.network === right.network &&
    left.masterFingerprintHex === right.masterFingerprintHex && left.originPath === right.originPath &&
    left.accountXpub === right.accountXpub;
}

export function recoveryCSetupProofInput(
  challenge: RecoveryCSetupChallengeV1,
  origin: VaultSignerOriginV1 & { role: 'recovery-c' },
): VaultProofOfPossessionInputV1 {
  const parsedChallenge = recoveryCSetupChallengeSchema.parse(challenge);
  if (origin.role !== 'recovery-c' || origin.network !== parsedChallenge.network) {
    throw new Error('Recovery C origin does not match the setup challenge role and network');
  }
  return vaultProofOfPossessionInputSchema.parse({
    version: 1, origin,
    sessionIdHex: parsedChallenge.sessionIdHex,
    challengeNonceHex: parsedChallenge.challengeNonceHex,
    // The existing proof record has one 32-byte transcript binding. For this
    // ceremony it is the digest of the complete setup challenge, which itself
    // contains the coordinator transcript, Desktop A origin, network, times,
    // session, and nonce. Signing only the inner coordinator transcript would
    // leave the other public challenge fields replaceable in transit.
    transcriptHashHex: recoveryCSetupChallengeDigest(parsedChallenge),
    expiresAtMs: parsedChallenge.expiresAtMs,
  });
}

export function verifyRecoveryCSetupResponse(
  challenge: RecoveryCSetupChallengeV1,
  response: RecoveryCSetupResponseV1,
  nowMs: string,
): boolean {
  try {
    const parsedChallenge = recoveryCSetupChallengeSchema.parse(challenge);
    const parsedResponse = recoveryCSetupResponseSchema.parse(response);
    if (BigInt(nowMs) > BigInt(parsedChallenge.expiresAtMs)) return false;
    if (parsedResponse.challengeDigestHex !== recoveryCSetupChallengeDigest(parsedChallenge)) return false;
    if (parsedResponse.origin.network !== parsedChallenge.network) return false;
    return verifyVaultProofOfPossession(
      recoveryCSetupProofInput(parsedChallenge, parsedResponse.origin),
      parsedResponse.proof,
      nowMs,
    );
  } catch {
    return false;
  }
}

export function signRecoveryCBackupCheck(
  seed: Uint8Array,
  challenge: RecoveryCBackupCheckChallengeV1,
  nowMs?: string,
): RecoveryCBackupCheckResponseV1 {
  const parsed = recoveryCBackupCheckChallengeSchema.parse(challenge);
  if (nowMs !== undefined && BigInt(nowMs) > BigInt(parsed.expiresAtMs)) {
    throw new Error('Recovery C backup-check challenge has expired');
  }
  const actualOrigin = deriveVaultRoleOrigin(seed, 'recovery-c', parsed.network);
  if (!sameOrigin(actualOrigin, parsed.recoveryOrigin)) {
    throw new Error('these words do not match Recovery C in this Vault recovery kit');
  }

  const root = vaultSignerRoot(seed, parsed.network);
  const account = root.derive(parsed.recoveryOrigin.originPath);
  const child = account.deriveChild(0).deriveChild(0);
  try {
    if (!child.privateKey || !child.publicKey) throw new Error('Recovery C proof child has no key pair');
    const challengeDigestHex = recoveryCBackupCheckChallengeDigest(parsed);
    const signature = secp256k1.sign(hexToBytes(challengeDigestHex), child.privateKey, {
      prehash: false, lowS: true,
    });
    const response = recoveryCBackupCheckResponseSchema.parse({
      version: 1, network: parsed.network, policyId: parsed.policyId, challengeDigestHex,
      proofPublicKeyHex: bytesToHex(child.publicKey), signatureHex: bytesToHex(signature.toCompactRawBytes()),
      scheme: 'recovery-c-backup-check-secp256k1-ecdsa-compact-low-s-v1',
    });
    if (!verifyRecoveryCBackupCheckResponse(parsed, response, nowMs)) {
      throw new Error('fresh Recovery C backup-check signature did not verify');
    }
    return response;
  } finally {
    child.wipePrivateData();
    account.wipePrivateData();
    root.wipePrivateData();
  }
}

export function verifyRecoveryCBackupCheckResponse(
  challenge: RecoveryCBackupCheckChallengeV1,
  response: RecoveryCBackupCheckResponseV1,
  nowMs?: string,
): boolean {
  try {
    const parsedChallenge = recoveryCBackupCheckChallengeSchema.parse(challenge);
    const parsedResponse = recoveryCBackupCheckResponseSchema.parse(response);
    if (nowMs !== undefined && BigInt(nowMs) > BigInt(parsedChallenge.expiresAtMs)) return false;
    if (parsedResponse.network !== parsedChallenge.network || parsedResponse.policyId !== parsedChallenge.policyId) {
      return false;
    }
    if (parsedResponse.challengeDigestHex !== recoveryCBackupCheckChallengeDigest(parsedChallenge)) return false;
    if (parsedResponse.proofPublicKeyHex !== deriveProofPublicKeyHex(parsedChallenge.recoveryOrigin)) return false;
    return secp256k1.verify(
      hexToBytes(parsedResponse.signatureHex),
      hexToBytes(parsedResponse.challengeDigestHex),
      hexToBytes(parsedResponse.proofPublicKeyHex),
      { format: 'compact', prehash: false, lowS: true },
    );
  } catch {
    return false;
  }
}
