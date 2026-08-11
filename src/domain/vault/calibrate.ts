/**
 * Runtime Argon2id calibration (spec §7.2): benchmark the device at vault
 * creation and pick the smallest parameters at or above the spec floors that
 * land in the 500–1000 ms target, capped at sane maxima. If even the floors
 * exceed the target on a slow device, the floors stand — they are the spec's
 * non-negotiable minima.
 */
import { KDF_ABSOLUTE_BOUNDS, type Argon2idParams } from './record';
import { deriveKek, SALT_BYTES } from './crypto';

export const ARGON2ID_FLOORS = { opsLimit: 3, memLimitBytes: 64 * 2 ** 20 } as const;
// D4 / ADR 0006 (RFC 9106 §4): memory is pinned at the 64 MiB floor — the
// creation-time ceiling that keeps every vault openable on constrained mobile
// devices — and extra time is bought by growing opsLimit instead. Caps must
// stay within KDF_ABSOLUTE_BOUNDS so a freshly calibrated record can never
// fail the stored-record bounds check; the memory parse maximum stays at
// 256 MiB so records created by the pre-D4 memory-first ladder still unlock.
export const ARGON2ID_CAPS = {
  opsLimit: KDF_ABSOLUTE_BOUNDS.opsLimit.max,
  memLimitBytes: 64 * 2 ** 20,
} as const;
export const CALIBRATION_TARGET_MS = { min: 500, max: 1000 } as const;

export interface CalibrationDeps {
  /** Runs one Argon2id derivation with the given params and returns elapsed milliseconds. */
  benchmark: (params: Argon2idParams) => Promise<number>;
}

function params(opsLimit: number, memLimitBytes: number): Argon2idParams {
  return { paramsVersion: 1, algorithm: 'argon2id13', opsLimit, memLimitBytes, parallelism: 1 };
}

export async function calibrateArgon2id(deps: CalibrationDeps): Promise<Argon2idParams> {
  let candidate = params(ARGON2ID_FLOORS.opsLimit, ARGON2ID_FLOORS.memLimitBytes);
  for (;;) {
    const elapsed = await deps.benchmark(candidate);
    if (elapsed >= CALIBRATION_TARGET_MS.min) return candidate;
    if (candidate.opsLimit < ARGON2ID_CAPS.opsLimit) {
      candidate = params(candidate.opsLimit + 1, candidate.memLimitBytes);
    } else {
      return candidate; // capped maximum on an extremely fast device
    }
  }
}

/**
 * Production benchmark: times a real Argon2id run through the installed
 * CryptoProvider. The await sits inside the timing window on purpose — on
 * providers that run the KDF off-thread, wall-clock latency is exactly what
 * the user experiences at unlock.
 */
export function makeKdfBenchmark(
  clock: () => number = () => performance.now(),
): CalibrationDeps['benchmark'] {
  return async (candidate) => {
    const salt = new Uint8Array(SALT_BYTES).fill(0x5a);
    const start = clock();
    await deriveKek('calibration-benchmark-password', salt, candidate);
    return clock() - start;
  };
}
