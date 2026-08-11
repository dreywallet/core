/**
 * Prove the artifact rebuilds byte-identically, rather than asserting it in
 * prose.
 *
 * Reproducibility is the entire basis of the published artifact digest: if two
 * builds from the same source can differ, then a digest tells a user only that
 * they have *a* build, not that they have *the* build. Rollup output is
 * sensitive to the Node version and to plugin ordering, so this must be a check
 * that runs, not a claim in a README.
 *
 *   node recovery/check-reproducible.mjs
 *
 * Builds twice, compares the bytes, and prints both digests plus the Node
 * version they were produced under — which belongs beside every published
 * digest in RELEASES.md.
 */
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { readFileSync, rmSync } from 'node:fs';
import { ARTIFACT_PATH, sourceDigest } from './digest.mjs';

const build = () => {
  execFileSync('npx', ['vite', 'build', '--config', 'recovery/vite.config.ts'], {
    stdio: 'pipe', cwd: process.cwd(),
  });
  return readFileSync(ARTIFACT_PATH);
};

process.stdout.write('building twice from a clean output directory...\n');
rmSync('recovery/dist', { recursive: true, force: true });
const first = build();
rmSync('recovery/dist', { recursive: true, force: true });
const second = build();

const digestOf = (bytes) => createHash('sha256').update(bytes).digest('hex');
const firstDigest = digestOf(first);
const secondDigest = digestOf(second);

process.stdout.write(`\nnode                          ${process.version}\n`);
process.stdout.write(`standaloneToolSourceDigest    ${sourceDigest(process.cwd())}\n`);
process.stdout.write(`standaloneToolArtifactDigest  ${firstDigest}\n`);
process.stdout.write(`artifact bytes                ${first.length}\n`);

if (firstDigest !== secondDigest) {
  process.stderr.write(
    `\nNOT REPRODUCIBLE\n  build 1  ${firstDigest}\n  build 2  ${secondDigest}\n\n` +
    'Two builds of identical source produced different bytes, so the published artifact\n' +
    'digest cannot be verified by anyone else. Do not publish this release.\n',
  );
  process.exit(1);
}

process.stdout.write('\nreproducible: two builds produced identical bytes.\n');
