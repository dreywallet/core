/**
 * Copy the signed gateway contract fixtures (and the dev public key) from the
 * sibling gateway checkout into tests/fixtures/gateway/. The gateway repo is
 * the contract source of truth (spec §4); run `pnpm fixtures:sign` there
 * first, then `pnpm fixtures:sync` here. tests/fixtures/gateway-drift.test.ts
 * fails until the committed copies match the source.
 *
 * Set GATEWAY_REPO to override the default ../gateway location.
 */
import { copyFileSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const extensionRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const gatewayRepo = resolve(extensionRoot, process.env.GATEWAY_REPO ?? '../gateway');
const sourceDir = join(gatewayRepo, 'fixtures');
const targetDir = join(extensionRoot, 'tests', 'fixtures', 'gateway');

export const SYNCED_FIXTURES = [
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

function main() {
  mkdirSync(targetDir, { recursive: true });
  for (const name of SYNCED_FIXTURES) {
    copyFileSync(join(sourceDir, name), join(targetDir, name));
  }
  // The extension only ever commits the public key. The secret key stays in
  // the gateway repo (it is a public dev fixture key either way, but the
  // asymmetry keeps the roles honest).
  const devKey = JSON.parse(readFileSync(join(sourceDir, 'dev-signing-key.json'), 'utf8'));
  writeFileSync(
    join(targetDir, 'dev-public-key.json'),
    `${JSON.stringify({ publicKeyHex: devKey.publicKeyHex }, null, 2)}\n`,
  );
  console.log(`synced ${SYNCED_FIXTURES.length} fixtures + dev-public-key.json from ${sourceDir}`);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main();
}
