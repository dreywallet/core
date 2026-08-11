/**
 * The Drey Vault standalone recovery tool.
 *
 * This program opens no socket. It has no gateway, no relay, no telemetry, no
 * update check, and no knowledge that Drey exists beyond the format of the kit
 * it reads. That is the point of it: ADR 0007 §6 requires that a Vault can be
 * opened without its provider, and a tool that phones anywhere to do its job
 * cannot demonstrate that.
 *
 * The pipeline is a single JSON session file passed from step to step, which is
 * what makes an air gap practical — the file crosses on removable media and
 * nothing else has to.
 *
 *   plan → (sign, once per role, possibly on different machines) → finalize
 */
import { closeSync, constants, existsSync, fstatSync, openSync, readFileSync, writeFileSync } from 'node:fs';
import { createInterface } from 'node:readline';
import { installNodeCryptoProvider, nodeCryptoProvider, sha256Hex } from './crypto-node';
import { deriveLadder, verifyKitHex, type VerifiedKit } from './kit';
import {
  FEE_RATE_ACKNOWLEDGEMENT_THRESHOLD_SAT_PER_VB,
  buildRecoveryPlan,
  resolveInputs,
  type SuppliedUtxo,
} from './plan';
import { renderReview, reviewFacts } from './display';
import { combineRawPsbts, combineResults, finalize, readMnemonic, signAsRole } from './signing';
import {
  assertRecoveryCInteractive,
  createRecoveryCResponse,
  readRecoveryCBackupChallenge,
  verifyRecoveryCWords,
  type RecoveryCInteractiveIo,
} from './recovery-c';
import { constructVaultPsbt } from '../../src/domain/vault/multisig-psbt';
import {
  VAULT_ROLES,
  type VaultPartialSignatureResultV1,
  type VaultSignerRole,
  type VaultUnsignedPlanV1,
} from '../../src/domain/vault/multisig-contracts';
import {
  serializeRecoveryCBackupCheckResponse,
  serializeRecoveryCSetupResponse,
} from '../../src/domain/vault/multisig-encoding';

export const TOOL_VERSION = 'drey-vault-recovery-v1';

interface Session {
  format: typeof TOOL_VERSION;
  kitHex: string;
  plan: VaultUnsignedPlanV1;
  unsignedPsbtHex: string;
  partials: VaultPartialSignatureResultV1[];
}

type Args = { _: string[]; flags: Map<string, string | true> };

function parseArgs(argv: readonly string[]): Args {
  const positional: string[] = [];
  const flags = new Map<string, string | true>();
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index]!;
    if (!token.startsWith('--')) { positional.push(token); continue; }
    const eq = token.indexOf('=');
    if (eq !== -1) { flags.set(token.slice(2, eq), token.slice(eq + 1)); continue; }
    const next = argv[index + 1];
    if (next !== undefined && !next.startsWith('--')) { flags.set(token.slice(2), next); index += 1; }
    else flags.set(token.slice(2), true);
  }
  return { _: positional, flags };
}

const out = (line = ''): void => { process.stdout.write(`${line}\n`) };

function required(args: Args, name: string): string {
  const value = args.flags.get(name);
  if (typeof value !== 'string' || value.length === 0) throw new Error(`--${name} is required`);
  return value;
}

function optionalBigint(args: Args, name: string): bigint | undefined {
  const value = args.flags.get(name);
  if (typeof value !== 'string') return undefined;
  return BigInt(value);
}

function loadKit(args: Args): VerifiedKit {
  return verifyKitHex(readBoundedPublicFile(required(args, 'kit'), 4_000_000, 'recovery kit').toString('utf8'));
}

function readBoundedPublicFile(path: string, maximumBytes: number, label: string): Buffer {
  const noFollow = 'O_NOFOLLOW' in constants ? constants.O_NOFOLLOW : 0;
  const descriptor = openSync(path, constants.O_RDONLY | noFollow);
  try {
    const details = fstatSync(descriptor);
    if (!details.isFile()) throw new Error(`${label} must be a regular file`);
    if (details.size > maximumBytes) throw new Error(`${label} exceeds the ${maximumBytes}-byte input limit`);
    return readFileSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
}

function loadSession(path: string): Session {
  const session = JSON.parse(readFileSync(path, 'utf8')) as Session;
  if (session.format !== TOOL_VERSION) {
    throw new Error(`unrecognized session file format: ${String(session.format)}`);
  }
  return session;
}

function saveSession(path: string, session: Session): void {
  writeFileSync(path, `${JSON.stringify(session, null, 2)}\n`, { mode: 0o600 });
}

/** Raw transaction files are also valid HTTP request bodies; keep them exact hex. */
export function writeTransactionHexFile(path: string, transactionHex: string): void {
  writeFileSync(path, transactionHex, { mode: 0o600 });
}

async function askLine(question: string): Promise<string> {
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  try {
    return await new Promise<string>((resolve) => rl.question(question, resolve));
  } finally {
    rl.close();
  }
}

async function askHiddenLine(question: string): Promise<string> {
  const input = process.stdin;
  if (!input.isTTY || typeof input.setRawMode !== 'function') {
    throw new Error('hidden Recovery C input requires a directly controlled terminal');
  }
  process.stdout.write(question);
  const wasRaw = input.isRaw;
  const wasPaused = input.isPaused();
  return await new Promise<string>((resolve, reject) => {
    let value = '';
    const cleanup = (): void => {
      input.off('data', onData);
      input.setRawMode(Boolean(wasRaw));
      if (wasPaused) input.pause();
    };
    const onData = (chunk: Buffer | string): void => {
      const bytes = typeof chunk === 'string' ? Buffer.from(chunk) : chunk;
      const wipe = (): void => { bytes.fill(0); };
      for (const byte of bytes) {
        if (byte === 3) {
          wipe();
          cleanup();
          process.stdout.write('\n');
          reject(new Error('Recovery C ceremony cancelled'));
          return;
        }
        if (byte === 10 || byte === 13) {
          wipe();
          cleanup();
          process.stdout.write('\n');
          resolve(value);
          return;
        }
        if (byte === 8 || byte === 127) {
          value = value.slice(0, -1);
        } else if (byte >= 32 && byte <= 126) {
          value += String.fromCharCode(byte);
        }
      }
      wipe();
    };
    input.setRawMode(true);
    input.resume();
    input.on('data', onData);
  });
}

const recoveryCIo: RecoveryCInteractiveIo = {
  get inputIsTTY() { return Boolean(process.stdin.isTTY); },
  get outputIsTTY() { return Boolean(process.stdout.isTTY); },
  write: out,
  readVisible: askLine,
  readHidden: askHiddenLine,
};

function newOutputPath(args: Args): string {
  const path = required(args, 'out');
  if (existsSync(path)) throw new Error(`refusing to overwrite existing file: ${path}`);
  return path;
}

function assertControllingTerminal(): void {
  if (process.env.CI !== undefined && process.env.CI !== '' && process.env.CI !== 'false') {
    throw new Error('Recovery C ceremonies are unavailable in CI and unattended environments');
  }
  const terminalPath = process.platform === 'win32' ? 'CONIN$' : '/dev/tty';
  let descriptor: number | undefined;
  try {
    descriptor = openSync(terminalPath, 'r+');
  } catch {
    throw new Error('Recovery C ceremonies require a verified controlling terminal');
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
}

/**
 * The destination must be confirmed character for character before any key is
 * used. `--confirm-destination` exists so a drill or a test can run unattended;
 * it is checked against the address computed from the transaction bytes, so it
 * is a confirmation either way and never a way to skip one.
 */
async function confirmDestination(args: Args, computed: string): Promise<void> {
  const supplied = args.flags.get('confirm-destination');
  const typed = typeof supplied === 'string'
    ? supplied.trim()
    : (await askLine('\nType the destination address exactly to confirm: ')).trim();
  if (typed !== computed) {
    throw new Error(
      `the address you confirmed does not match the one this transaction pays.\n` +
      `  transaction pays: ${computed}\n  you typed:        ${typed}\nNothing was signed.`,
    );
  }
}

function role(value: string): VaultSignerRole {
  if ((VAULT_ROLES as readonly string[]).includes(value)) return value as VaultSignerRole;
  throw new Error(`--role must be one of ${VAULT_ROLES.join(', ')}`);
}

// ---------------------------------------------------------------- verbs

function cmdVerifySelf(): void {
  const self = readFileSync(process.argv[1]!);
  out(`${TOOL_VERSION}`);
  out(`artifact sha256: ${sha256Hex(self)}`);
  out('');
  out('Compare that digest against the one in the recovery kit you are holding, and');
  out('against the published release notes. If they disagree, stop: you are running');
  out('a different program from the one your kit was created against.');
}

function cmdReadKit(args: Args): void {
  const { kit, identity } = loadKit(args);
  out(`Policy ID          ${identity.policyId}`);
  out(`Network            ${identity.network}`);
  out(`Threshold          2 of 3`);
  out(`Created            ${new Date(Number(kit.createdAtMs)).toISOString()}`);
  out(`Birthday height    ${kit.birthdayHeight ?? 'not recorded'}`);
  out(`Vault label        ${kit.vaultLabel}`);
  out('');
  out('Signers (logical order A, B, C):');
  for (const [index, signer] of identity.signers.entries()) {
    out(`  ${signer.role.padEnd(12)} ${kit.signerLabels[index]}`);
    out(`    fingerprint    ${signer.masterFingerprintHex}   origin ${signer.originPath}`);
    out(`    account xpub   ${signer.accountXpub}`);
  }
  out('');
  out(`Receive descriptor ${identity.receiveDescriptor}`);
  out(`Change descriptor  ${identity.changeDescriptor}`);
  out(`First receive      ${kit.firstReceiveAddress}`);
  out('');
  out(`Standalone tool source digest    ${kit.standaloneToolSourceDigest}`);
  out(`Standalone tool artifact digest  ${kit.standaloneToolArtifactDigest}`);
  if (/^0+$/u.test(kit.standaloneToolArtifactDigest)) {
    out('  (all zero: this kit was produced before a standalone package was published)');
  }
  out('');
  out('Compatibility requirements:');
  for (const line of kit.compatibilityRequirements) out(`  - ${line}`);
  out('');
  out('Recovery instructions:');
  out(`  ${kit.recoveryInstructions}`);
  out('');
  out('Rotation instructions:');
  out(`  ${kit.rotationInstructions}`);
  out('');
  out('Every value above was regenerated from the three signer origins in the kit.');
  out('The policy ID, both descriptors, and the first receive address were recomputed');
  out('and compared, not read out and displayed.');
}

async function cmdCreateRecoveryC(args: Args): Promise<void> {
  assertRecoveryCInteractive(recoveryCIo);
  assertControllingTerminal();
  const target = newOutputPath(args);
  const response = await createRecoveryCResponse({
    challengeBytes: new Uint8Array(readBoundedPublicFile(
      required(args, 'challenge'), 65_536, 'Recovery C setup challenge',
    )),
    io: recoveryCIo,
    rng: (length) => nodeCryptoProvider.randomBytes(length),
    nowMs: BigInt(Date.now()),
  });
  writeFileSync(target, serializeRecoveryCSetupResponse(response), { mode: 0o600, flag: 'wx' });
  out('');
  out(`Wrote the public Recovery C response to ${target}. It contains no recovery words or private key.`);
  out('Remove the media and power off this temporary offline environment before importing the response.');
}

async function cmdVerifyRecoveryC(args: Args): Promise<void> {
  assertRecoveryCInteractive(recoveryCIo);
  assertControllingTerminal();
  const target = newOutputPath(args);
  const verifiedKit = loadKit(args);
  const artifactDigest = sha256Hex(readFileSync(process.argv[1]!));
  const challenge = readRecoveryCBackupChallenge(
    new Uint8Array(readBoundedPublicFile(
      required(args, 'challenge'), 65_536, 'Recovery C backup-check challenge',
    )),
    verifiedKit,
    TOOL_VERSION,
    artifactDigest,
    BigInt(Date.now()),
  );
  const response = await verifyRecoveryCWords({
    challenge, io: recoveryCIo, nowMs: BigInt(Date.now()),
  });
  writeFileSync(target, serializeRecoveryCBackupCheckResponse(response), { mode: 0o600, flag: 'wx' });
  out('');
  out('The paper words recreate the exact Recovery C named by this Vault policy.');
  out(`Wrote the public backup-check response to ${target}. It contains no recovery words or private key.`);
}

function cmdDeriveAddresses(args: Args): void {
  const { identity } = loadKit(args);
  const from = Number(args.flags.get('from') ?? 0);
  const to = Number(args.flags.get('to') ?? 19);
  for (const branch of ['receive', 'change'] as const) {
    out(`${branch} branch:`);
    for (const entry of deriveLadder(identity, branch, from, to)) {
      out(`  ${String(entry.index).padStart(4)}  ${entry.address}`);
    }
    out('');
  }
  out('Cross-check with any descriptor wallet, for example:');
  out(`  bitcoin-cli deriveaddresses "${identity.receiveDescriptor}" "[${from},${to}]"`);
}

async function cmdPlan(args: Args): Promise<void> {
  const { identity } = loadKit(args);
  const utxoFile = JSON.parse(readFileSync(required(args, 'utxos'), 'utf8')) as
    SuppliedUtxo[] | { utxos: SuppliedUtxo[] };
  const supplied = Array.isArray(utxoFile) ? utxoFile : utxoFile.utxos;
  if (!Array.isArray(supplied)) throw new Error('the UTXO file must be an array, or an object with a "utxos" array');

  const feeRateSatPerVb = BigInt(required(args, 'fee-rate'));
  if (feeRateSatPerVb > FEE_RATE_ACKNOWLEDGEMENT_THRESHOLD_SAT_PER_VB) {
    const ack = args.flags.get('i-accept-fee-rate');
    out('');
    out(`WARNING: ${feeRateSatPerVb} sat/vB is above this tool's ${FEE_RATE_ACKNOWLEDGEMENT_THRESHOLD_SAT_PER_VB} sat/vB warning line.`);
    out('That may be exactly right — during a fee spike, or when a recovery cannot wait.');
    out('This tool will not refuse it. It only wants you to have meant it.');
    if (ack !== String(feeRateSatPerVb)) {
      throw new Error(`re-run with --i-accept-fee-rate ${feeRateSatPerVb} to proceed`);
    }
  }

  const inputs = resolveInputs(identity, supplied, Number(args.flags.get('search-depth') ?? 100));
  const built = buildRecoveryPlan({
    identity, inputs,
    destinationAddress: required(args, 'to'),
    feeRateSatPerVb,
    ...(args.flags.has('amount') ? { amountSats: BigInt(required(args, 'amount')) } : {}),
    ...(args.flags.has('change-index') ? { changeIndex: Number(args.flags.get('change-index')) } : {}),
    ...(optionalBigint(args, 'now') === undefined ? {} : { nowMs: optionalBigint(args, 'now')! }),
  });

  const session: Session = {
    format: TOOL_VERSION,
    kitHex: readFileSync(required(args, 'kit'), 'utf8').trim().replace(/\s+/gu, ''),
    plan: built.plan,
    unsignedPsbtHex: constructVaultPsbt(identity, built.plan),
    partials: [],
  };
  saveSession(required(args, 'out'), session);
  out(renderReview(identity, built.plan, session.unsignedPsbtHex));
  out('');
  out(`Wrote ${required(args, 'out')}. Review it, then sign it with two distinct roles.`);
}

function cmdReview(args: Args): void {
  const session = loadSession(required(args, 'session'));
  const { identity } = verifyKitHex(session.kitHex);
  const psbt = session.partials.length > 0
    ? combineResults(identity, session.plan, session.partials).psbtHex
    : session.unsignedPsbtHex;
  out(renderReview(identity, session.plan, psbt));
}

async function cmdSign(args: Args): Promise<void> {
  const sessionPath = required(args, 'session');
  const session = loadSession(sessionPath);
  const { identity } = verifyKitHex(session.kitHex);
  const signerRole = role(required(args, 'role'));

  if (session.partials.some((partial) => partial.roleAdded === signerRole)) {
    throw new Error(`${signerRole} has already signed this plan; two copies of one role are one vote`);
  }

  const facts = reviewFacts(identity, session.plan, session.unsignedPsbtHex);
  if (facts.disagreements.length > 0) {
    throw new Error(`refusing to sign: ${facts.disagreements.join('; ')}`);
  }
  out(renderReview(identity, session.plan, session.unsignedPsbtHex));
  await confirmDestination(args, facts.destinationAddress);

  const mnemonic = readMnemonic(required(args, 'words'));
  const result = signAsRole({
    identity, plan: session.plan, role: signerRole, mnemonic,
    ...(optionalBigint(args, 'now') === undefined ? {} : { nowMs: optionalBigint(args, 'now')! }),
  });
  session.partials.push(result);
  saveSession(sessionPath, session);

  out('');
  out(`Signed as ${signerRole}.`);
  const roles = session.partials.map((partial) => partial.roleAdded);
  out(roles.length >= 2
    ? `Roles present: ${roles.join(' + ')} — quorum reached, ready to finalize.`
    : `Roles present: ${roles.join(', ')} — one more distinct role is needed.`);
}

function cmdCombine(args: Args): void {
  const sessionPath = required(args, 'session');
  const session = loadSession(sessionPath);
  const { identity } = verifyKitHex(session.kitHex);

  // Two sources, deliberately kept apart. `--psbt` is the standards-compliant
  // path: PSBTs from any BIP174 signer, including a hardware device that has
  // never heard of a Drey plan record. With no `--psbt`, the session's own
  // partial-signature results are combined instead.
  const extraPaths = (args.flags.get('psbt') === undefined ? [] : [String(args.flags.get('psbt'))])
    .concat(args._.slice(1));
  const psbtHexes = extraPaths.map((path) => readFileSync(path, 'utf8').trim());
  const combined = psbtHexes.length > 0
    ? combineRawPsbts(identity, session.plan, psbtHexes)
    : combineResults(identity, session.plan, session.partials);

  out(renderReview(identity, session.plan, combined.psbtHex));
  const target = args.flags.get('out');
  if (typeof target === 'string') {
    writeFileSync(target, `${combined.psbtHex}\n`, { mode: 0o600 });
    out(`\nWrote the combined PSBT to ${target}.`);
  }
}

async function cmdFinalize(args: Args): Promise<void> {
  const session = loadSession(required(args, 'session'));
  const { identity } = verifyKitHex(session.kitHex);
  const combined = combineResults(identity, session.plan, session.partials);
  out(renderReview(identity, session.plan, combined.psbtHex));

  const facts = reviewFacts(identity, session.plan, combined.psbtHex);
  await confirmDestination(args, facts.destinationAddress);

  const finalized = finalize(
    identity, session.plan, combined.psbtHex,
    optionalBigint(args, 'now'),
  );
  const target = required(args, 'out');
  writeTransactionHexFile(target, finalized.transactionHex);
  out('');
  out(`txid   ${finalized.txid}`);
  out(`wtxid  ${finalized.wtxid}`);
  out(`Wrote the signed transaction to ${target}.`);
  out('');
  out('This tool does not broadcast. Send those bytes from wherever you like —');
  out('your own node, an Electrum server, a block explorer\'s submit form. The');
  out('transaction is already signed, so whoever relays it learns what it does');
  out('but cannot change any part of it.');
}

function cmdVerifyTx(args: Args): void {
  const session = loadSession(required(args, 'session'));
  const { identity } = verifyKitHex(session.kitHex);
  const transactionHex = readFileSync(required(args, 'tx'), 'utf8').trim();
  const verified = finalize(identity, session.plan, combineResults(identity, session.plan, session.partials).psbtHex);
  if (verified.transactionHex !== transactionHex) {
    throw new Error('the supplied transaction is not the one this plan and these signatures produce');
  }
  out(`Verified. txid ${verified.txid}, wtxid ${verified.wtxid}.`);
}

const USAGE = `${TOOL_VERSION} — open a Drey Vault without Drey.

  verify-self                                    print this artifact's own SHA-256
  create-recovery-c --challenge <file> --out <file>  create and confirm Recovery C offline
  verify-recovery-c --kit <file> --challenge <file> --out <file>
                                                 prove the paper words restore the policy's C
  read-kit         --kit <file>                  verify a public recovery kit and show the policy
  derive-addresses --kit <file> [--from N --to N] regenerate the address ladder
  plan             --kit <file> --utxos <file> --to <address> --fee-rate <sat/vB>
                   --out <session.json> [--amount <sats>] [--change-index N]
  review           --session <session.json>      recompute and display everything
  sign             --session <file> --role <desktop-a|mobile-b|recovery-c> --words <file|->
  combine          --session <file> [--psbt <file> ...] [--out <file>]
  finalize         --session <file> --out <tx.hex>
  verify-tx        --session <file> --tx <tx.hex>

This program never opens a network connection. Obtain the UTXO set and broadcast
the finished transaction with whatever tool you trust; see README.md.`;

export async function main(argv: readonly string[]): Promise<number> {
  installNodeCryptoProvider();
  const args = parseArgs(argv);
  const verb = args._[0];
  try {
    switch (verb) {
      case 'verify-self': cmdVerifySelf(); break;
      case 'create-recovery-c': await cmdCreateRecoveryC(args); break;
      case 'verify-recovery-c': await cmdVerifyRecoveryC(args); break;
      case 'read-kit': cmdReadKit(args); break;
      case 'derive-addresses': cmdDeriveAddresses(args); break;
      case 'plan': await cmdPlan(args); break;
      case 'review': cmdReview(args); break;
      case 'sign': await cmdSign(args); break;
      case 'combine': cmdCombine(args); break;
      case 'finalize': await cmdFinalize(args); break;
      case 'verify-tx': cmdVerifyTx(args); break;
      default: out(USAGE); return verb === undefined || verb === 'help' ? 0 : 2;
    }
    return 0;
  } catch (error) {
    process.stderr.write(`\n${error instanceof Error ? error.message : String(error)}\n\n`);
    return 1;
  }
}
