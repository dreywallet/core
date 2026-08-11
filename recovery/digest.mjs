/**
 * The two digests a public recovery kit carries.
 *
 * Deliberately dependency-free — `node:crypto`, `node:fs`, `node:path` and
 * nothing else — so that a third party can audit this file in one sitting and
 * re-run it without installing anything. A digest tool that needs a package
 * manager to tell you whether your recovery tool is authentic has moved the
 * trust problem rather than solved it.
 *
 *   source digest    a tree hash over the enumerated source paths below
 *   artifact digest  sha256 of the single built .mjs, nothing else
 *
 * Run from the core repository root:  node recovery/digest.mjs
 */
import { createHash } from 'node:crypto';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, posix, relative, sep } from 'node:path';

/**
 * Exactly what the source digest covers. Enumerated rather than globbed from
 * the working tree, because "everything that happens to be here" is not a
 * reproducible statement — an untracked scratch file would silently change the
 * digest of a released version.
 */
export const SOURCE_ROOTS = ['src', 'recovery/src', 'vectors'];
export const SOURCE_FILES = [
  'package.json',
  'pnpm-lock.yaml',
  'tsconfig.json',
  'recovery/vite.config.ts',
  'recovery/digest.mjs',
  // The open specification is part of the source, not commentary on it.
  // ADR 0007 §6 asks for "open specification, reproducible source, checksums"
  // as one gate. If README.md sat outside the digest, the identical binary
  // could be published beside a rewritten specification — different claims
  // about what the program does, what it refuses, and which capabilities it
  // does not cover — and both digests would still verify. Covering it means a
  // typo fix moves the source digest, which is the correct trade: the digest
  // is only published at a tag.
  'recovery/README.md',
];

/**
 * Excluded from the tree walk. `recovery/dist` is the build output (covered by
 * the artifact digest instead), and `RELEASES.md` records the digest itself, so
 * including either would make the digest depend on its own value.
 */
const EXCLUDED = new Set(['node_modules', '.git', 'dist']);

export const ARTIFACT_PATH = 'recovery/dist/drey-vault-recovery-v1.mjs';

function walk(root, base, out) {
  for (const entry of readdirSync(join(base, root), { withFileTypes: true }).sort(
    (left, right) => (left.name < right.name ? -1 : left.name > right.name ? 1 : 0),
  )) {
    if (EXCLUDED.has(entry.name)) continue;
    const child = join(root, entry.name);
    if (entry.isDirectory()) walk(child, base, out);
    else if (entry.isFile()) out.push(child);
  }
}

/** Every file the source digest covers, as sorted POSIX-relative paths. */
export function sourceFileList(base) {
  const found = [];
  for (const root of SOURCE_ROOTS) {
    if (!statSync(join(base, root), { throwIfNoEntry: false })?.isDirectory()) {
      throw new Error(`source root missing: ${root}`);
    }
    walk(root, base, found);
  }
  for (const file of SOURCE_FILES) {
    if (!statSync(join(base, file), { throwIfNoEntry: false })?.isFile()) {
      throw new Error(`source file missing: ${file}`);
    }
    found.push(file);
  }
  return found
    .map((path) => relative('', path).split(sep).join(posix.sep))
    .sort();
}

/**
 * The tree digest.
 *
 * `sha256( for each file in sorted path order: path ‖ 0x00 ‖ bytes ‖ 0x00 )`.
 * The NUL separators are what stop a rename from being invisible: without them,
 * a file named `ab` containing `c` and one named `a` containing `bc` would hash
 * identically. The same construction is already used by the extension's
 * production packaging script.
 */
export function treeDigest(base, files) {
  const hash = createHash('sha256');
  for (const path of files) {
    hash.update(Buffer.from(path, 'utf8'));
    hash.update(Buffer.from([0]));
    hash.update(readFileSync(join(base, path)));
    hash.update(Buffer.from([0]));
  }
  return hash.digest('hex');
}

export function sourceDigest(base) {
  return treeDigest(base, sourceFileList(base));
}

export function artifactDigest(base) {
  return createHash('sha256').update(readFileSync(join(base, ARTIFACT_PATH))).digest('hex');
}

if (process.argv[1] && process.argv[1].endsWith('digest.mjs')) {
  const base = process.cwd();
  const files = sourceFileList(base);
  const source = treeDigest(base, files);
  process.stdout.write(`source files covered   ${files.length}\n`);
  process.stdout.write(`standaloneToolSourceDigest    ${source}\n`);
  try {
    process.stdout.write(`standaloneToolArtifactDigest  ${artifactDigest(base)}\n`);
  } catch {
    process.stdout.write('standaloneToolArtifactDigest  (not built — run pnpm recovery:build first)\n');
  }
  if (process.argv.includes('--list')) {
    for (const file of files) process.stdout.write(`  ${file}\n`);
  }
}
