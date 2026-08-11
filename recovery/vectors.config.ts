/**
 * Bundles the recovery-vector generator so plain Node can run it. Mirrors
 * `scripts/vault-vector-vite.config.ts`; the generator imports `recovery/src`,
 * which resolves to TypeScript.
 */
export default {
  ssr: { noExternal: true },
  build: {
    emptyOutDir: true,
    outDir: 'node_modules/.cache/drey-recovery-vector-generator',
    target: 'node20',
    ssr: 'recovery/generate-vectors.ts',
    rollupOptions: {
      output: { entryFileNames: 'generate.mjs', inlineDynamicImports: true },
    },
  },
};
