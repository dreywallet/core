import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const livingProductFiles = [
  'package.json',
  'recovery/README.md',
  'recovery/src/cli.ts',
  'vectors/vault-recovery-plan-v1.md',
] as const;

describe('Drey product branding', () => {
  it.each(livingProductFiles)('%s contains no legacy display name', (path) => {
    expect(readFileSync(path, 'utf8')).not.toMatch(/\bSqrl\b|\bSQRL\b/u);
  });
});
