export default {
  ssr: { noExternal: true },
  build: {
    emptyOutDir: true,
    outDir: 'node_modules/.cache/drey-vault-vector-generator',
    target: 'node20',
    ssr: 'scripts/generate-vault-contract-vectors.ts',
    rollupOptions: {
      output: { entryFileNames: 'generate.mjs' },
    },
  },
};
