/**
 * Coordinator-neutral, crash-safe Vault broadcast lifecycle.
 *
 * A platform persists `prepared`, then persists `dispatch-consumed` before the
 * network call. Once consumed, the record can only be reconciled or completed;
 * it can never authorize another send. This deliberately turns a crash in the
 * dispatch window into an indeterminate recovery task instead of a retry.
 */
import { z } from 'zod';
import type { VaultPolicyIdentityV1, VaultSignerRole, VaultUnsignedPlanV1 } from './multisig-contracts';
import { verifyFinalizedVaultTransaction } from './multisig-psbt';

export const VAULT_BROADCAST_TERMINAL_STATUSES = [
  'accepted',
  'already_known',
  'confirmed',
  'conflicted',
  'rejected',
  'indeterminate',
] as const;

export type VaultBroadcastTerminalStatus = (typeof VAULT_BROADCAST_TERMINAL_STATUSES)[number];
export type VaultCoordinatorPlatform = 'extension' | 'mobile';

interface VaultBroadcastIdentityV1 {
  version: 1;
  network: VaultUnsignedPlanV1['network'];
  policyId: string;
  planId: string;
  planDigest: string;
  coordinator: VaultCoordinatorPlatform;
  transactionHex: string;
  txid: string;
  wtxid: string;
  vsize: number;
  roles: [VaultSignerRole, VaultSignerRole];
}

export type VaultBroadcastLifecycleV1 = VaultBroadcastIdentityV1 & (
  | { phase: 'prepared'; preparedAtMs: string; attemptIdHex: null; attemptConsumedAtMs: null; terminal: null }
  | { phase: 'dispatch-consumed'; preparedAtMs: string; attemptIdHex: string; attemptConsumedAtMs: string; terminal: null }
  | {
      phase: 'terminal';
      preparedAtMs: string;
      attemptIdHex: string;
      attemptConsumedAtMs: string;
      terminal: { status: VaultBroadcastTerminalStatus; detail: string | null; observedAtMs: string };
    }
);

const hex = (bytes: number) => z.string().regex(new RegExp(`^[0-9a-f]{${bytes * 2}}$`, 'u'));
const variableHex = z.string().regex(/^(?:[0-9a-f]{2})+$/u);
const decimal = z.string().regex(/^(?:0|[1-9][0-9]*)$/u);
const identity = {
  version: z.literal(1),
  network: z.enum(['mainnet', 'signet', 'regtest']),
  policyId: hex(32),
  planId: hex(16),
  planDigest: hex(32),
  coordinator: z.enum(['extension', 'mobile']),
  transactionHex: variableHex,
  txid: hex(32),
  wtxid: hex(32),
  vsize: z.number().int().positive(),
  roles: z.tuple([z.enum(['desktop-a', 'mobile-b', 'recovery-c']), z.enum(['desktop-a', 'mobile-b', 'recovery-c'])]),
} as const;

export const vaultBroadcastLifecycleSchema: z.ZodType<VaultBroadcastLifecycleV1> = z.discriminatedUnion('phase', [
  z.object({
    ...identity, phase: z.literal('prepared'), preparedAtMs: decimal,
    attemptIdHex: z.null(), attemptConsumedAtMs: z.null(), terminal: z.null(),
  }).strict(),
  z.object({
    ...identity, phase: z.literal('dispatch-consumed'), preparedAtMs: decimal,
    attemptIdHex: hex(16), attemptConsumedAtMs: decimal, terminal: z.null(),
  }).strict(),
  z.object({
    ...identity, phase: z.literal('terminal'), preparedAtMs: decimal,
    attemptIdHex: hex(16), attemptConsumedAtMs: decimal,
    terminal: z.object({
      status: z.enum(VAULT_BROADCAST_TERMINAL_STATUSES), detail: z.string().max(512).nullable(), observedAtMs: decimal,
    }).strict(),
  }).strict(),
]).superRefine((record, ctx) => {
  if (record.roles[0] === record.roles[1]) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['roles'], message: 'two distinct logical roles required' });
  }
  if (record.attemptConsumedAtMs !== null && BigInt(record.attemptConsumedAtMs) < BigInt(record.preparedAtMs)) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['attemptConsumedAtMs'], message: 'attempt predates preparation' });
  }
  if (record.terminal !== null && BigInt(record.terminal.observedAtMs) < BigInt(record.attemptConsumedAtMs!)) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['terminal'], message: 'terminal outcome predates attempt' });
  }
});

function assertBinding(
  policy: VaultPolicyIdentityV1,
  plan: VaultUnsignedPlanV1,
  record: VaultBroadcastLifecycleV1,
): VaultBroadcastLifecycleV1 {
  const parsed = vaultBroadcastLifecycleSchema.parse(record);
  if (plan.broadcastIntent !== 'broadcast' || parsed.network !== policy.network || parsed.network !== plan.network ||
      parsed.policyId !== policy.policyId || parsed.policyId !== plan.policyId || parsed.planId !== plan.planId ||
      parsed.planDigest !== plan.planDigest) {
    throw new Error('Vault broadcast lifecycle policy/plan binding mismatch');
  }
  const exact = verifyFinalizedVaultTransaction({ policy, plan, transactionHex: parsed.transactionHex });
  if (exact.txid !== parsed.txid || exact.wtxid !== parsed.wtxid || exact.vsize !== parsed.vsize ||
      exact.roles.some((role, index) => role !== parsed.roles[index])) {
    throw new Error('Vault broadcast lifecycle exact finalized bytes mismatch');
  }
  return parsed;
}

export function prepareVaultBroadcast(input: {
  policy: VaultPolicyIdentityV1;
  plan: VaultUnsignedPlanV1;
  transactionHex: string;
  coordinator: VaultCoordinatorPlatform;
  preparedAtMs: string;
}): VaultBroadcastLifecycleV1 {
  const exact = verifyFinalizedVaultTransaction(input);
  return assertBinding(input.policy, input.plan, {
    version: 1,
    network: input.plan.network,
    policyId: input.plan.policyId,
    planId: input.plan.planId,
    planDigest: input.plan.planDigest,
    coordinator: input.coordinator,
    transactionHex: exact.transactionHex,
    txid: exact.txid,
    wtxid: exact.wtxid,
    vsize: exact.vsize,
    roles: exact.roles,
    phase: 'prepared',
    preparedAtMs: input.preparedAtMs,
    attemptIdHex: null,
    attemptConsumedAtMs: null,
    terminal: null,
  });
}

/** Persist the returned record before dispatching. This transition is one-way. */
export function consumeVaultBroadcastAttempt(input: {
  policy: VaultPolicyIdentityV1;
  plan: VaultUnsignedPlanV1;
  record: VaultBroadcastLifecycleV1;
  attemptIdHex: string;
  consumedAtMs: string;
}): VaultBroadcastLifecycleV1 {
  const current = assertBinding(input.policy, input.plan, input.record);
  if (current.phase !== 'prepared') throw new Error('Vault broadcast attempt is already consumed');
  return assertBinding(input.policy, input.plan, {
    ...current,
    phase: 'dispatch-consumed',
    attemptIdHex: input.attemptIdHex,
    attemptConsumedAtMs: input.consumedAtMs,
    terminal: null,
  });
}

export function completeVaultBroadcast(input: {
  policy: VaultPolicyIdentityV1;
  plan: VaultUnsignedPlanV1;
  record: VaultBroadcastLifecycleV1;
  status: VaultBroadcastTerminalStatus;
  detail: string | null;
  observedAtMs: string;
}): VaultBroadcastLifecycleV1 {
  const current = assertBinding(input.policy, input.plan, input.record);
  if (current.phase !== 'dispatch-consumed') throw new Error('Vault broadcast outcome requires one consumed attempt');
  return assertBinding(input.policy, input.plan, {
    ...current,
    phase: 'terminal',
    terminal: { status: input.status, detail: input.detail, observedAtMs: input.observedAtMs },
  });
}

export function validateVaultBroadcastLifecycle(input: {
  policy: VaultPolicyIdentityV1;
  plan: VaultUnsignedPlanV1;
  record: VaultBroadcastLifecycleV1;
}): VaultBroadcastLifecycleV1 {
  return assertBinding(input.policy, input.plan, input.record);
}

export function vaultBroadcastRecoveryPosture(record: VaultBroadcastLifecycleV1):
  | 'safe-to-dispatch-once'
  | 'reconcile-only'
  | 'terminal' {
  const parsed = vaultBroadcastLifecycleSchema.parse(record);
  return parsed.phase === 'prepared' ? 'safe-to-dispatch-once'
    : parsed.phase === 'dispatch-consumed' ? 'reconcile-only' : 'terminal';
}
