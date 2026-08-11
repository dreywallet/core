/**
 * Check a recovery tool artifact against an expected digest.
 *
 * Dependency-free and single-purpose, so it can be copied onto an air-gapped
 * machine beside the artifact and read in full before being run. It answers one
 * question — is this the program my recovery kit names? — and prints nothing
 * that could be mistaken for a different answer.
 *
 *   node recovery/verify.mjs <artifact.mjs> <expected-sha256>
 *
 * If you have no second machine, `shasum -a 256 <artifact.mjs>` gives the same
 * number and needs no Node at all.
 */
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

const [artifactPath, expected] = process.argv.slice(2);

if (!artifactPath || !expected) {
  process.stderr.write('usage: node recovery/verify.mjs <artifact.mjs> <expected-sha256>\n');
  process.exit(2);
}

if (!/^[0-9a-f]{64}$/iu.test(expected)) {
  process.stderr.write('the expected digest must be 64 hex characters (a SHA-256)\n');
  process.exit(2);
}

if (/^0{64}$/u.test(expected)) {
  process.stderr.write(
    'that digest is all zeros, which is the sentinel a recovery kit carries when no standalone\n' +
    'package had been published yet. There is nothing to verify against. Obtain a kit produced\n' +
    'by a newer release, or check the published release notes for the digest of this version.\n',
  );
  process.exit(2);
}

let bytes;
try {
  bytes = readFileSync(artifactPath);
} catch (error) {
  process.stderr.write(`cannot read ${artifactPath}: ${error.message}\n`);
  process.exit(2);
}

const actual = createHash('sha256').update(bytes).digest('hex');

if (actual === expected.toLowerCase()) {
  process.stdout.write(`OK  ${actual}\n`);
  process.stdout.write(`${artifactPath} is the artifact that digest names.\n`);
  process.exit(0);
}

process.stderr.write(
  `MISMATCH\n  expected  ${expected.toLowerCase()}\n  actual    ${actual}\n\n` +
  'Do not use this file. Either it is not the release your kit names, or it has been\n' +
  'altered in transit. Obtain it again from the published release and re-check.\n',
);
process.exit(1);
