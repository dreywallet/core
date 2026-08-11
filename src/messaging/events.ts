/** Non-secret worker-to-UI notification. Recipients refresh via session.snapshot. */
export const SESSION_STATE_CHANGED_EVENT = 'squirrel:session-state-changed' as const;

export interface SessionStateChangedEvent {
  type: typeof SESSION_STATE_CHANGED_EVENT;
  locked: boolean;
}

export function isSessionStateChangedEvent(value: unknown): value is SessionStateChangedEvent {
  return (
    typeof value === 'object' &&
    value !== null &&
    (value as { type?: unknown }).type === SESSION_STATE_CHANGED_EVENT &&
    typeof (value as { locked?: unknown }).locked === 'boolean'
  );
}

/** Scan progress changed (M6 §8.2). Carries no data; recipients re-poll scan.status. */
export const SCAN_PROGRESS_EVENT = 'squirrel:scan-progress' as const;

export interface ScanProgressEvent {
  type: typeof SCAN_PROGRESS_EVENT;
}

export function isScanProgressEvent(value: unknown): value is ScanProgressEvent {
  return (
    typeof value === 'object' &&
    value !== null &&
    (value as { type?: unknown }).type === SCAN_PROGRESS_EVENT
  );
}

/** Wallet-visible state changed. Carries only a coarse invalidation reason. */
export const WALLET_DATA_CHANGED_EVENT = 'squirrel:wallet-data-changed' as const;

export type WalletDataChangeReason =
  | 'transaction'
  | 'utxo'
  | 'account'
  | 'config'
  | 'permissions';

export interface WalletDataChangedEvent {
  type: typeof WALLET_DATA_CHANGED_EVENT;
  reason: WalletDataChangeReason;
}

export function isWalletDataChangedEvent(value: unknown): value is WalletDataChangedEvent {
  if (typeof value !== 'object' || value === null) return false;
  const candidate = value as { type?: unknown; reason?: unknown };
  return candidate.type === WALLET_DATA_CHANGED_EVENT &&
    ['transaction', 'utxo', 'account', 'config', 'permissions'].includes(String(candidate.reason));
}
