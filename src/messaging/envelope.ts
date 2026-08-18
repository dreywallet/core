import { z } from 'zod';

// spec.md §5.2: every internal message includes protocol version, request ID,
// sender context, intended operation, and a validated payload. Unknown variants
// are rejected with stable typed error codes.

export const PROTOCOL_VERSION = 1;

export const SenderContext = z.enum([
  'popup',
  'sidepanel',
  'fullpage',
  'onboarding',
  'approval',
  'ledger-page',
  'content-bridge',
  'service-worker',
]);
export type SenderContext = z.infer<typeof SenderContext>;

export const MessageEnvelope = z
  .object({
    protocolVersion: z.literal(PROTOCOL_VERSION),
    requestId: z.string().uuid(),
    sender: SenderContext,
    op: z.string().min(1),
    payload: z.unknown(),
  })
  .strict();
export type MessageEnvelope = z.infer<typeof MessageEnvelope>;

export const ErrorCode = z.enum([
  'ERR_PROTOCOL_MISMATCH',
  'ERR_UNKNOWN_OPERATION',
  'ERR_INVALID_PAYLOAD',
  'ERR_LOCKED',
  'ERR_UNAUTHORIZED_CONTEXT',
  'ERR_INTERNAL',
  // Vault/session-derived codes (M3). The dispatcher maps domain VaultErrorCodes
  // onto these so callers never see the raw domain error type.
  'ERR_WRONG_PASSWORD',
  'ERR_WEAK_PASSWORD',
  'ERR_VAULT_TAMPERED',
  'ERR_UNSUPPORTED_VERSION',
  'ERR_VAULT_NOT_FOUND',
  // M4: the active vault's seed backup has not been verified (spec §7.1 —
  // the vault is not usable until the user proves the written-down mnemonic).
  'ERR_BACKUP_REQUIRED',
  // M7 transaction-domain failures.
  'ERR_DATA_STALE',
  'ERR_INSUFFICIENT_FUNDS',
  'ERR_PLAN_EXPIRED',
  'ERR_PLAN_CHANGED',
  'ERR_FEE_QUOTE_INVALID',
  'ERR_UNSAFE_TRANSACTION',
  'ERR_INSCRIPTION_INSEPARABLE',
  'ERR_CLEAN_FEE_INPUTS_UNAVAILABLE',
  'ERR_NO_SWEEPABLE_EXCESS',
  'ERR_NOT_ACCELERATABLE',
  'ERR_BROADCAST_REJECTED',
  'ERR_BROADCAST_OUTCOME_UNKNOWN',
  // The address decodes but is not a script this wallet can pay to. Distinct
  // from ERR_INVALID_PAYLOAD so the UI can name the address as the problem.
  'ERR_UNSUPPORTED_ADDRESS',
  // BIP 321 parsing and payment-method selection are distinct from an invalid
  // Bitcoin address so the Send surface can explain what failed.
  'ERR_INVALID_PAYMENT_INSTRUCTION',
  'ERR_UNSUPPORTED_PAYMENT_METHOD',
  // The amount is below the recipient script's dust floor. Its own code because
  // the floor is per-address-type -- 294 sats to bech32, 546 to legacy -- so the
  // same amount can be fine for one recipient and unrelayable for the next.
  'ERR_OUTPUT_DUST',
]);
export type ErrorCode = z.infer<typeof ErrorCode>;

export interface ParseOk {
  ok: true;
  envelope: MessageEnvelope;
}
export interface ParseErr {
  ok: false;
  code: ErrorCode;
}

export function parseEnvelope(raw: unknown): ParseOk | ParseErr {
  const result = MessageEnvelope.safeParse(raw);
  if (result.success) return { ok: true, envelope: result.data };
  const version = (raw as { protocolVersion?: unknown } | null)?.protocolVersion;
  if (typeof version === 'number' && version !== PROTOCOL_VERSION) {
    return { ok: false, code: 'ERR_PROTOCOL_MISMATCH' };
  }
  return { ok: false, code: 'ERR_INVALID_PAYLOAD' };
}

/**
 * Builds a well-formed envelope for an outgoing RPC (used by thin clients like
 * the popup). Kept here so the request-ID and protocol-version invariants live
 * in one place. globalThis.crypto.randomUUID is available in both MV3 contexts
 * and Node ≥18, so this stays free of Chrome APIs.
 */
export function makeEnvelope(sender: SenderContext, op: string, payload: unknown): MessageEnvelope {
  return {
    protocolVersion: PROTOCOL_VERSION,
    requestId: globalThis.crypto.randomUUID(),
    sender,
    op,
    payload,
  };
}
