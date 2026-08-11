/**
 * Guards the §4 fixture-sync convention: the committed copies under
 * tests/fixtures/gateway/ must be byte-identical to the gateway repo's
 * fixtures. Skips (with a note) when no sibling gateway checkout exists,
 * e.g. CI that clones only this repo.
 */
import { existsSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

const extensionRoot = resolve(import.meta.dirname, '..', '..');
const gatewayFixtures = resolve(
  extensionRoot,
  process.env.GATEWAY_REPO ?? '../gateway',
  'fixtures',
);
const localFixtures = join(extensionRoot, 'tests', 'fixtures', 'gateway');

const SYNCED = [
  'status.signed.json',
  'status.wrong-network.json',
  'status.tampered-signature.json',
  'snapshot.clean.signed.json',
  'snapshot.wrong-lane.signed.json',
  'snapshot.stale-revision.signed.json',
  'snapshot.tampered-signature.json',
  'classify.mixed.signed.json',
  'classify.revision-skew.signed.json',
  'inscription-previews.json',
  'inscription.approval-batch.signed.json',
  'inscription.metadata.signed.json',
  'inscription.preview.signed.json',
  'fees.signed.json',
  'broadcast.accepted.signed.json',
  'broadcast.conflicted.signed.json',
  'broadcast.rejected.signed.json',
  'snapshot-scenarios.json',
];

const hasGatewayCheckout = existsSync(gatewayFixtures);

describe('gateway fixture sync', () => {
  it.skipIf(!hasGatewayCheckout)(
    'committed copies are byte-identical to the gateway repo (run `pnpm fixtures:sync`)',
    () => {
      for (const name of SYNCED) {
        const source = readFileSync(join(gatewayFixtures, name));
        const copy = readFileSync(join(localFixtures, name));
        expect(copy.equals(source), `${name} drifted — run \`pnpm fixtures:sync\``).toBe(true);
      }
      const sourceKey = JSON.parse(
        readFileSync(join(gatewayFixtures, 'dev-signing-key.json'), 'utf8'),
      ) as { publicKeyHex: string };
      const copyKey = JSON.parse(
        readFileSync(join(localFixtures, 'dev-public-key.json'), 'utf8'),
      ) as { publicKeyHex: string };
      expect(copyKey.publicKeyHex).toBe(sourceKey.publicKeyHex);
    },
  );

  // The "never pin the dev fixture key as the hosted production key" check is
  // consumer-specific (it reads the extension's channel.ts) and lives in the
  // extension repo, which imports dev-public-key.json via @drey/core/fixtures.

  it('never commits a secret key into the extension repo', () => {
    const copyKey = JSON.parse(
      readFileSync(join(localFixtures, 'dev-public-key.json'), 'utf8'),
    ) as Record<string, unknown>;
    expect(Object.keys(copyKey)).toEqual(['publicKeyHex']);
  });
});
