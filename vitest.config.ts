import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';

export default defineConfig({
  resolve: {
    alias: {
      // libsodium-wrappers-sumo 0.7.x ships a broken ESM entry: its .mjs
      // imports ./libsodium-sumo.mjs, which actually lives in the separate
      // libsodium-sumo package. Point module resolution at the intact CJS
      // build. libsodium is a devDependency here (test crypto provider only);
      // core ships with ZERO runtime libsodium — consumers inject their own
      // CryptoProvider.
      'libsodium-wrappers-sumo': fileURLToPath(
        new URL('./node_modules/libsodium-wrappers-sumo/dist/modules-sumo/libsodium-wrappers.js', import.meta.url),
      ),
    },
  },
  test: {
    include: ['tests/**/*.test.ts'],
    exclude: ['node_modules/**'],
    environment: 'node',
  },
});
