import { createHash } from 'node:crypto';
import { beforeAll, describe, expect, it } from 'vitest';
import { mnemonicToSeed } from '../../src/domain/keys/mnemonic';
import type {
  RecoveryCBackupCheckChallengeV1,
  RecoveryCSetupChallengeV1,
} from '../../src/domain/vault/multisig-contracts';
import { serializeRecoveryCSetupChallenge } from '../../src/domain/vault/multisig-encoding';
import { deriveVaultRoleOrigin } from '../../src/domain/vault/multisig-role';
import {
  verifyRecoveryCBackupCheckResponse,
  verifyRecoveryCSetupResponse,
} from '../../src/domain/vault/recovery-c-ceremony';
import {
  createRecoveryCResponse,
  verifyRecoveryCWords,
  type RecoveryCInteractiveIo,
} from '../../recovery/src/recovery-c';
import { installTestCryptoProvider } from '../helpers/install-crypto-provider';

beforeAll(() => installTestCryptoProvider());

const PUBLIC_DESKTOP = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const PUBLIC_RECOVERY = 'letter advice cage absurd amount doctor acoustic avoid letter advice cage above';
const PUBLIC_WRONG = 'legal winner thank year wave sausage worth useful legal winner thank yellow';
const CREATED = 1_785_542_400_000n;
const EXPIRES = CREATED + 86_400_000n;
const digest = (text: string): string => createHash('sha256').update(text).digest('hex');

function challenge(): RecoveryCSetupChallengeV1 {
  const seed = mnemonicToSeed(PUBLIC_DESKTOP);
  try {
    return {
      version: 1, role: 'recovery-c', network: 'signet',
      sessionIdHex: digest('session').slice(0, 32), challengeNonceHex: digest('nonce'),
      transcriptHashHex: digest('transcript'), desktopOrigin: deriveVaultRoleOrigin(seed, 'desktop-a'),
      createdAtMs: CREATED.toString(), expiresAtMs: EXPIRES.toString(),
    };
  } finally {
    seed.fill(0);
  }
}

function deterministicRng() {
  let counter = 0;
  const rng = (length: number): Uint8Array => {
    const bytes = createHash('sha256').update(`public-test-rng:${counter++}`).digest();
    return new Uint8Array(bytes.subarray(0, length));
  };
  return { rng, calls: () => counter };
}

class FixtureIo implements RecoveryCInteractiveIo {
  readonly lines: string[] = [];
  readonly words = new Map<number, string>();
  constructor(
    readonly inputIsTTY = true,
    readonly outputIsTTY = true,
    private readonly visible = 'CREATE',
    private readonly hiddenOverride?: string,
  ) {}
  write(line = ''): void {
    this.lines.push(line);
    for (const match of line.matchAll(/(\d+)\.\s+([a-z]+)/gu)) {
      this.words.set(Number(match[1]), match[2]!);
    }
  }
  async readVisible(): Promise<string> { return this.visible; }
  async readHidden(prompt: string): Promise<string> {
    if (this.hiddenOverride !== undefined) return this.hiddenOverride;
    const position = Number(prompt.match(/word (\d+)/u)?.[1]);
    return this.words.get(position) ?? '';
  }
}

describe('offline Recovery C creation state machine', () => {
  it('refuses non-interactive execution before parsing or drawing entropy', async () => {
    const random = deterministicRng();
    await expect(createRecoveryCResponse({
      challengeBytes: new Uint8Array([1, 2, 3]), io: new FixtureIo(false, true),
      rng: random.rng, nowMs: CREATED,
    })).rejects.toThrow(/before any secret is created/u);
    expect(random.calls()).toBe(0);
  });

  it('allows cancellation before the first entropy draw', async () => {
    const random = deterministicRng();
    await expect(createRecoveryCResponse({
      challengeBytes: serializeRecoveryCSetupChallenge(challenge()), io: new FixtureIo(true, true, 'CANCEL'),
      rng: random.rng, nowMs: CREATED,
    })).rejects.toThrow(/before entropy was drawn/u);
    expect(random.calls()).toBe(0);
  });

  it('confirms all 12 words in shuffled order before returning public bytes', async () => {
    const random = deterministicRng();
    const setup = challenge();
    const io = new FixtureIo();
    const response = await createRecoveryCResponse({
      challengeBytes: serializeRecoveryCSetupChallenge(setup), io, rng: random.rng, nowMs: CREATED + 1n,
    });
    expect(io.words.size).toBe(12);
    expect(verifyRecoveryCSetupResponse(setup, response, (CREATED + 1n).toString())).toBe(true);
    expect(response.origin.role).toBe('recovery-c');
    expect(JSON.stringify(response)).not.toContain([...io.words.values()].join(' '));
  });

  it('aborts after three wrong confirmations and returns no response', async () => {
    const random = deterministicRng();
    await expect(createRecoveryCResponse({
      challengeBytes: serializeRecoveryCSetupChallenge(challenge()), io: new FixtureIo(true, true, 'CREATE', 'wrong'),
      rng: random.rng, nowMs: CREATED,
    })).rejects.toThrow(/three word confirmations/u);
  });
});

describe('hidden paper restore entry', () => {
  function backupChallenge(): RecoveryCBackupCheckChallengeV1 {
    const seed = mnemonicToSeed(PUBLIC_RECOVERY);
    try {
      return {
        version: 1, role: 'recovery-c', network: 'signet', policyId: digest('policy'),
        recoveryOrigin: deriveVaultRoleOrigin(seed, 'recovery-c'),
        sessionIdHex: digest('backup-session').slice(0, 32), challengeNonceHex: digest('backup-nonce'),
        standaloneToolVersion: 'drey-vault-recovery-v1', standaloneToolSourceDigest: digest('source'),
        standaloneToolArtifactDigest: digest('artifact'), createdAtMs: CREATED.toString(),
        expiresAtMs: EXPIRES.toString(),
      };
    } finally {
      seed.fill(0);
    }
  }

  it('signs only after exact 12-word C restoration', async () => {
    const input = backupChallenge();
    const response = await verifyRecoveryCWords({
      challenge: input, io: new FixtureIo(true, true, 'CREATE', PUBLIC_RECOVERY), nowMs: CREATED + 1n,
    });
    expect(verifyRecoveryCBackupCheckResponse(input, response, (CREATED + 1n).toString())).toBe(true);
  });

  it('rejects a checksum-valid but different mnemonic', async () => {
    await expect(verifyRecoveryCWords({
      challenge: backupChallenge(), io: new FixtureIo(true, true, 'CREATE', PUBLIC_WRONG), nowMs: CREATED + 1n,
    })).rejects.toThrow(/do not match Recovery C/u);
  });
});
