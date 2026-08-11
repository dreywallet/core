/**
 * ADR 0007 §6, capability 3: "import two valid roots or combine two
 * standards-compliant partial PSBTs."
 *
 * Both halves matter and they serve different recoveries. Importing roots is
 * the offline case: one machine holds two sets of words and produces a finished
 * transaction without any transport at all. Combining partials is the
 * distributed case: two people, or one person and a hardware device, each sign
 * separately and only PSBTs travel between them.
 *
 * Secrets reach this module by file path or stdin and never by command-line
 * argument. An argument is visible in the process table to every other user on
 * the machine and lands in shell history — an ordinary convenience that would
 * quietly undo the offline ceremony this tool exists to serve.
 */
import { readFileSync } from 'node:fs';
import { HDKey } from '@scure/bip32';
import {
  bip32Versions,
  type VaultPolicyIdentityV1,
  type VaultPartialSignatureResultV1,
  type VaultSignerRole,
  type VaultUnsignedPlanV1,
} from '../../src/domain/vault/multisig-contracts';
import { mnemonicToSeed, validateMnemonic } from '../../src/domain/keys/mnemonic';
import {
  combineVaultPartialSignatureResults,
  combineVaultPsbts,
  createVaultPartialSignatureInput,
  finalizeVaultPsbt,
  signVaultPartialSignature,
  verifyFinalizedVaultTransaction,
} from '../../src/domain/vault/multisig-psbt';

/** Read BIP39 words from a file or from stdin, never from argv. */
export function readMnemonic(source: string): string {
  const raw = source === '-'
    ? readFileSync(0, 'utf8')
    : readFileSync(source, 'utf8');
  const mnemonic = raw.replace(/#.*$/gmu, '').trim().replace(/\s+/gu, ' ').toLowerCase();
  if (mnemonic.length === 0) throw new Error('no BIP39 words were supplied');
  if (!validateMnemonic(mnemonic)) {
    throw new Error(
      'those words are not a checksum-valid BIP39 mnemonic. Check for a typo, a missing word, or a ' +
      'transposition — the checksum catches all three, which is why it is worth re-reading rather than retyping.',
    );
  }
  return mnemonic;
}

/**
 * Run `body` with a role's root key, then wipe it.
 *
 * The wipe is best-effort by nature — Node strings are immutable and the seed
 * has already been copied by the BIP39 implementation — but zeroing the HDKey's
 * own private material still removes the longest-lived copy, and doing it in a
 * `finally` means a throw between derivation and use does not leave it resident.
 */
export function withRoleRoot<T>(
  mnemonic: string,
  network: 'mainnet' | 'signet',
  body: (root: HDKey) => T,
): T {
  const seed = mnemonicToSeed(mnemonic);
  const root = HDKey.fromMasterSeed(seed, bip32Versions(network));
  try {
    return body(root);
  } finally {
    root.wipePrivateData();
    seed.fill(0);
  }
}

export interface SignAsRoleRequest {
  identity: VaultPolicyIdentityV1;
  plan: VaultUnsignedPlanV1;
  role: VaultSignerRole;
  mnemonic: string;
  /** Defaults to the plan's own creation time; see the clock-skew note below. */
  nowMs?: bigint;
  psbtHex?: string;
}

/**
 * Add one logical role's signature.
 *
 * `nowMs` defaults to the plan's `createdAtMs` rather than to the wall clock.
 * An air-gapped machine's clock is routinely wrong by months or years — it has
 * no network time and often no battery-backed one either — and core's freshness
 * check would reject an otherwise perfect signature for it. Defaulting to the
 * plan's own timestamp keeps a correct recovery from failing on a wrong clock,
 * while `--now` remains available when the operator wants real time enforced.
 */
export function signAsRole(request: SignAsRoleRequest): VaultPartialSignatureResultV1 {
  const { identity, plan, role } = request;
  const nowMs = (request.nowMs ?? BigInt(plan.createdAtMs)).toString();
  return withRoleRoot(request.mnemonic, plan.network, (signerRoot) => {
    const input = createVaultPartialSignatureInput({
      policy: identity, plan, role,
      ...(request.psbtHex === undefined ? {} : { psbtHex: request.psbtHex }),
    });
    return signVaultPartialSignature({ policy: identity, request: input, signerRoot, nowMs });
  });
}

export function combineResults(
  identity: VaultPolicyIdentityV1,
  plan: VaultUnsignedPlanV1,
  results: readonly VaultPartialSignatureResultV1[],
) {
  return combineVaultPartialSignatureResults({ policy: identity, plan, results: [...results] });
}

export function combineRawPsbts(
  identity: VaultPolicyIdentityV1,
  plan: VaultUnsignedPlanV1,
  psbtHexes: readonly string[],
) {
  return combineVaultPsbts({ policy: identity, plan, psbtHexes: [...psbtHexes] });
}

export function finalize(
  identity: VaultPolicyIdentityV1,
  plan: VaultUnsignedPlanV1,
  psbtHex: string,
  nowMs?: bigint,
) {
  const finalized = finalizeVaultPsbt({
    policy: identity, plan, psbtHex,
    nowMs: (nowMs ?? BigInt(plan.createdAtMs)).toString(),
  });
  // Re-verify the finished bytes independently of the finalizer that produced
  // them, so the transaction the operator is about to broadcast has been read
  // back against the plan by a separate code path.
  const verified = verifyFinalizedVaultTransaction({
    policy: identity, plan, transactionHex: finalized.transactionHex,
  });
  if (verified.txid !== finalized.txid || verified.wtxid !== finalized.wtxid) {
    throw new Error('the finalized transaction does not verify back against the plan');
  }
  return finalized;
}
