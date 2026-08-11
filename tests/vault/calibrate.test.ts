/**
 * spec §7.2 calibration: floors are non-negotiable minima, target 500–1000 ms,
 * capped maxima. D4 / ADR 0006: memory is pinned at the 64 MiB floor and time
 * is bought with opsLimit only. Fully deterministic — fake benchmark functions.
 */
import { describe, expect, it } from 'vitest';
import {
  ARGON2ID_CAPS,
  ARGON2ID_FLOORS,
  CALIBRATION_TARGET_MS,
  calibrateArgon2id,
  type CalibrationDeps,
} from '../../src/domain/vault/calibrate';
import { KDF_ABSOLUTE_BOUNDS, kdfParamsWithinBounds } from '../../src/domain/vault/record';
import type { Argon2idParams } from '../../src/domain/vault/record';

// Models a device where one Argon2id run at the floor params costs
// msAtFloors, scaling linearly with memory and iterations.
function fakeDevice(msAtFloors: number): CalibrationDeps['benchmark'] {
  return (params: Argon2idParams) =>
    Promise.resolve(
      msAtFloors *
        (params.memLimitBytes / ARGON2ID_FLOORS.memLimitBytes) *
        (params.opsLimit / ARGON2ID_FLOORS.opsLimit),
    );
}

describe('calibrateArgon2id', () => {
  it('keeps exact floors on a slow device (floors already exceed the target)', async () => {
    const params = await calibrateArgon2id({ benchmark: fakeDevice(2400) });
    expect(params.opsLimit).toBe(ARGON2ID_FLOORS.opsLimit);
    expect(params.memLimitBytes).toBe(ARGON2ID_FLOORS.memLimitBytes);
  });

  it('keeps floors when they already land inside the target window', async () => {
    const params = await calibrateArgon2id({ benchmark: fakeDevice(700) });
    expect(params.opsLimit).toBe(ARGON2ID_FLOORS.opsLimit);
    expect(params.memLimitBytes).toBe(ARGON2ID_FLOORS.memLimitBytes);
  });

  it('grows opsLimit — never memory — on a fast device, landing in the target window', async () => {
    const benchmark = fakeDevice(200); // floors take 200ms → needs ~3x work
    const params = await calibrateArgon2id({ benchmark });
    expect(await benchmark(params)).toBeGreaterThanOrEqual(CALIBRATION_TARGET_MS.min);
    expect(params.memLimitBytes).toBe(ARGON2ID_FLOORS.memLimitBytes); // memory pinned (D4)
    expect(params.opsLimit).toBeGreaterThan(ARGON2ID_FLOORS.opsLimit);
    expect(params.opsLimit).toBeLessThanOrEqual(ARGON2ID_CAPS.opsLimit);
  });

  it('returns the capped maximum on an absurdly fast device', async () => {
    const params = await calibrateArgon2id({ benchmark: () => Promise.resolve(1) });
    expect(params.memLimitBytes).toBe(ARGON2ID_CAPS.memLimitBytes);
    expect(params.opsLimit).toBe(ARGON2ID_CAPS.opsLimit);
  });

  it('never undercuts floors or exceeds caps across a device-speed sweep', async () => {
    for (const ms of [1, 10, 100, 250, 499, 500, 999, 1000, 5000]) {
      const params = await calibrateArgon2id({ benchmark: fakeDevice(ms) });
      expect(params.opsLimit).toBeGreaterThanOrEqual(ARGON2ID_FLOORS.opsLimit);
      expect(params.opsLimit).toBeLessThanOrEqual(ARGON2ID_CAPS.opsLimit);
      expect(params.memLimitBytes).toBe(ARGON2ID_FLOORS.memLimitBytes);
      expect(params.paramsVersion).toBe(1);
      expect(params.parallelism).toBe(1);
    }
  });

  it('caps stay within KDF_ABSOLUTE_BOUNDS so a fresh calibration always parses', () => {
    // The containment invariant behind ADR 0006: any params the ladder can
    // emit must pass the stored-record bounds check, including the extremes.
    expect(ARGON2ID_CAPS.opsLimit).toBeLessThanOrEqual(KDF_ABSOLUTE_BOUNDS.opsLimit.max);
    expect(ARGON2ID_CAPS.memLimitBytes).toBeLessThanOrEqual(KDF_ABSOLUTE_BOUNDS.memLimitBytes.max);
    expect(ARGON2ID_FLOORS.opsLimit).toBeGreaterThanOrEqual(KDF_ABSOLUTE_BOUNDS.opsLimit.min);
    expect(ARGON2ID_FLOORS.memLimitBytes).toBeGreaterThanOrEqual(KDF_ABSOLUTE_BOUNDS.memLimitBytes.min);
    for (const opsLimit of [ARGON2ID_FLOORS.opsLimit, ARGON2ID_CAPS.opsLimit]) {
      expect(
        kdfParamsWithinBounds({
          paramsVersion: 1,
          algorithm: 'argon2id13',
          opsLimit,
          memLimitBytes: ARGON2ID_CAPS.memLimitBytes,
          parallelism: 1,
        }),
      ).toBe(true);
    }
  });

  it('a pre-D4 record calibrated to 256 MiB still passes the parse bounds', () => {
    // Backward compatibility: the memory-first ladder could emit up to
    // 256 MiB / ops 10; those stored records must keep unlocking.
    expect(
      kdfParamsWithinBounds({
        paramsVersion: 1,
        algorithm: 'argon2id13',
        opsLimit: 10,
        memLimitBytes: 256 * 2 ** 20,
        parallelism: 1,
      }),
    ).toBe(true);
  });

  it('rejects the tampered cross-product: high-memory legacy records never exceeded ops 10', () => {
    // No legitimate ladder ever emitted >64 MiB together with >10 ops; the
    // parse bounds must not accept the union of both maxima (256 MiB × 16
    // would raise the tampered-record DoS bound past its pre-D4 level).
    const at = (opsLimit: number, memLimitBytes: number) =>
      kdfParamsWithinBounds({ paramsVersion: 1, algorithm: 'argon2id13', opsLimit, memLimitBytes, parallelism: 1 });
    expect(at(11, 256 * 2 ** 20)).toBe(false);
    expect(at(16, 256 * 2 ** 20)).toBe(false);
    expect(at(11, 64 * 2 ** 20 + 1)).toBe(false);
    expect(at(16, 64 * 2 ** 20)).toBe(true); // post-D4 ladder maximum
    expect(at(10, 256 * 2 ** 20)).toBe(true); // pre-D4 ladder maximum
  });
});
