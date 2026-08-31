import {
  closeSync,
  constants,
  fsyncSync,
  openSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { randomBytes } from 'node:crypto';
import { basename, dirname, join } from 'node:path';

type FileContents = string | Uint8Array;

function createPrivateFile(path: string, contents: FileContents): void {
  const noFollow = 'O_NOFOLLOW' in constants ? constants.O_NOFOLLOW : 0;
  let descriptor: number;
  try {
    descriptor = openSync(
      path,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | noFollow,
      0o600,
    );
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === 'EEXIST' || code === 'ELOOP') {
      throw new Error(`refusing to overwrite existing file: ${path}`, { cause: error });
    }
    throw error;
  }
  let failure: unknown;
  try {
    writeFileSync(descriptor, contents);
    fsyncSync(descriptor);
  } catch (error) {
    failure = error;
  } finally {
    closeSync(descriptor);
  }
  if (failure !== undefined) {
    try { unlinkSync(path); } catch { /* best-effort cleanup of our exclusive output */ }
    throw failure;
  }
}

/** Create one private output without following or replacing an existing path. */
export function writeNewPrivateFile(path: string, contents: FileContents): void {
  createPrivateFile(path, contents);
}

/**
 * Replace an existing session through a private same-directory temporary file.
 * The final rename replaces a swapped symlink itself rather than following it.
 */
export function replacePrivateFileAtomically(path: string, contents: FileContents): void {
  const directory = dirname(path);
  const name = basename(path);
  let temporary = '';
  for (let attempt = 0; attempt < 16; attempt += 1) {
    temporary = join(
      directory,
      `.${name}.drey-${process.pid}-${randomBytes(8).toString('hex')}.tmp`,
    );
    try {
      createPrivateFile(temporary, contents);
      break;
    } catch (error) {
      if ((error as Error).cause instanceof Error &&
          ((error as Error).cause as NodeJS.ErrnoException).code === 'EEXIST') {
        temporary = '';
        continue;
      }
      throw error;
    }
  }
  if (temporary.length === 0) throw new Error(`could not allocate a private session update beside ${path}`);
  try {
    renameSync(temporary, path);
  } catch (error) {
    try { unlinkSync(temporary); } catch { /* best-effort cleanup of our exclusive temporary file */ }
    throw error;
  }
}
