/**
 * The standalone recovery package's build.
 *
 * `noExternal: true` is the whole point: everything — core's domain modules,
 * @scure, @noble, zod — is inlined into one file, so the artifact a user
 * verifies by digest is the artifact that runs. A bundle with external imports
 * would need an `npm install` on the air-gapped machine, and its digest would
 * cover only the part of the program that is not doing the cryptography.
 *
 * Bundling is also not optional here. `@drey/core` is `private: true` and its
 * exports map resolves to raw TypeScript (`"./domain/*": "./src/domain/*.ts"`),
 * so plain Node cannot import it from `node_modules` at all.
 */
export default {
  ssr: { noExternal: true },
  build: {
    emptyOutDir: true,
    outDir: 'recovery/dist',
    target: 'node20',
    ssr: 'recovery/src/main.ts',
    minify: false,
    rollupOptions: {
      output: {
        entryFileNames: 'drey-vault-recovery-v1.mjs',
        // Deterministic output: no hashed chunk names, no code splitting, and
        // no build-time banner. Two builds from the same lockfile must produce
        // byte-identical bytes or the published digest means nothing.
        inlineDynamicImports: true,
      },
    },
  },
};
