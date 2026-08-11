import js from '@eslint/js';
import tseslint from 'typescript-eslint';

// ADR 0001: only the @scure stack may ship; the bitcoinjs-lib ecosystem must not
// appear anywhere in src/. Kept as shared values because flat-config blocks for
// overlapping files replace (not merge) a rule's options — every block that sets
// no-restricted-imports must restate the ban.
const bannedBitcoinPaths = ['bitcoinjs-lib', 'bip32', 'bip39', 'tiny-secp256k1'].map((name) => ({
  name,
  message: `ADR 0001: use the @scure stack; ${name} must not be imported in src/.`,
}));
const bannedBitcoinPatterns = [
  {
    group: ['bitcoinjs-lib/*', 'bip32/*', 'bip39/*', 'tiny-secp256k1/*'],
    message: 'ADR 0001: use the @scure stack; the bitcoinjs-lib ecosystem must not be imported in src/.',
  },
];

// spec.md §4 / core boundary: everything in this package is platform-free.
// No React, no WXT, no chrome/browser globals, no libsodium at runtime —
// crypto arrives only through the injected CryptoProvider port. The libsodium
// ban applies to src/ only; tests/ may use the libsodium devDependency as the
// reference provider.
const coreBoundary = {
  files: ['src/**/*.ts', 'src/**/*.tsx'],
  rules: {
    'no-restricted-imports': [
      'error',
      {
        paths: [
          ...bannedBitcoinPaths,
          {
            name: 'libsodium-wrappers-sumo',
            message: 'core ships no runtime libsodium; use the injected CryptoProvider (port-plan D5).',
          },
        ],
        patterns: [
          { group: ['react', 'react-dom', 'react/*', 'react-dom/*'], message: 'Core modules must not import React (spec §4).' },
          {
            group: ['react-native', 'react-native/*', 'react-native-*', '@react-native/*', 'expo', 'expo-*', '@expo/*'],
            message: 'Core modules must not import React Native or Expo (spec §4) — platform code stays in the consumers.',
          },
          { group: ['wxt', 'wxt/*', '@wxt-dev/*'], message: 'Core modules must not import WXT (spec §4).' },
          {
            group: ['**/entrypoints/**', '**/components/**', '**/adapters/**', '**/background/**', '**/ui/**'],
            message: 'Core modules must not import platform adapters, background, or UI (spec §4).',
          },
          ...bannedBitcoinPatterns,
        ],
      },
    ],
    'no-restricted-globals': [
      'error',
      { name: 'chrome', message: 'Core modules must not touch Chrome APIs (spec §4).' },
      { name: 'browser', message: 'Core modules must not touch browser extension APIs (spec §4).' },
    ],
  },
};

// Tests restate the bitcoin ban (flat-config replacement semantics) but may
// import libsodium as the reference test provider.
const testBoundary = {
  files: ['tests/**/*.ts'],
  rules: {
    'no-restricted-imports': [
      'error',
      { paths: bannedBitcoinPaths, patterns: bannedBitcoinPatterns },
    ],
  },
};

// Node maintenance scripts (fixture sync, vector generation) and the standalone
// recovery package use Node globals. `recovery/**` is a Node CLI, not part of
// the platform-free `src/**` surface, so the no-chrome/no-React boundary above
// does not apply to it — but the bitcoin-library ban does, and it is restated
// here because flat-config blocks replace rather than merge rule options.
const nodeScripts = {
  files: ['scripts/**/*.mjs', 'scripts/**/*.ts', 'recovery/**/*.mjs', 'recovery/**/*.ts'],
  rules: {
    'no-restricted-imports': [
      'error',
      { paths: bannedBitcoinPaths, patterns: bannedBitcoinPatterns },
    ],
  },
  languageOptions: {
    globals: {
      process: 'readonly', console: 'readonly', URL: 'readonly', fetch: 'readonly',
      Buffer: 'readonly', __dirname: 'readonly',
    },
  },
};

export default tseslint.config(
  // recovery/dist is generated: a bundled, unminified copy of source that is
  // already linted, so linting it again reports the dependencies' style, not ours.
  { ignores: ['node_modules/**', 'recovery/dist/**'] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  coreBoundary,
  testBoundary,
  nodeScripts,
);
