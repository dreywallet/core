export default {
  ssr: { noExternal: true },
  build: {
    emptyOutDir: true,
    outDir: 'node_modules/.cache/drey-community-vault-vector-generator',
    target: 'node20',
    ssr: 'scripts/generate-community-vault-vectors.ts',
    rollupOptions: { output: { entryFileNames: 'generate.mjs' } },
  },
};
