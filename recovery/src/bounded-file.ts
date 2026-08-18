import { closeSync, constants, fstatSync, openSync, readSync } from 'node:fs';

const READ_CHUNK_BYTES = 64 * 1024;

function readBoundedDescriptor(descriptor: number, maximumBytes: number, label: string): Buffer {
  const chunks: Buffer[] = [];
  let total = 0;
  for (;;) {
    const chunk = Buffer.allocUnsafe(Math.min(READ_CHUNK_BYTES, maximumBytes + 1 - total));
    const count = readSync(descriptor, chunk, 0, chunk.length, null);
    if (count === 0) return Buffer.concat(chunks, total);
    total += count;
    if (total > maximumBytes) throw new Error(`${label} exceeds the ${maximumBytes}-byte input limit`);
    chunks.push(Buffer.from(chunk.subarray(0, count)));
  }
}

export function readBoundedRegularFile(path: string, maximumBytes: number, label: string): Buffer {
  const noFollow = 'O_NOFOLLOW' in constants ? constants.O_NOFOLLOW : 0;
  const descriptor = openSync(path, constants.O_RDONLY | noFollow);
  try {
    const details = fstatSync(descriptor);
    if (!details.isFile()) throw new Error(`${label} must be a regular file`);
    if (details.size > maximumBytes) throw new Error(`${label} exceeds the ${maximumBytes}-byte input limit`);
    return readBoundedDescriptor(descriptor, maximumBytes, label);
  } finally {
    closeSync(descriptor);
  }
}

export function readBoundedStdin(maximumBytes: number, label: string): Buffer {
  return readBoundedDescriptor(0, maximumBytes, label);
}
