# Passkey envelope vectors v1

`passkey-envelope-v1.json` pins the ADR 0007 Workstream A1 passkey-wrapped-DEK
envelope for mainnet and signet. It is public, synthetic conformance data: the
PRF outputs, DEKs, salts, and credential IDs are label-derived bytes, no
WebAuthn credential exists, and nothing here may ever reach production
storage. The RP origin is the stable test-channel extension origin recorded by
the A0 spike (`docs/passkey-a0-identity-and-compatibility.md` in the workspace
root); production envelopes are never manufactured in fixtures.

Regenerate only with `pnpm vectors:generate`. The generator encrypts with
`@noble/ciphers` XChaCha20-Poly1305 while the vitest suite verifies every
vector against the libsodium reference provider, so the file only stays green
while two independent AEAD implementations and the HKDF-SHA256 construction
agree byte-for-byte.

## Construction

```text
prfEvalInput = UTF8("drey-passkey-prf/v1") || 00 || prfSalt(32)
prfOutput    = WebAuthn prf.eval.first result (32 bytes, UV required)
KEK          = HKDF-SHA256(ikm = prfOutput,
                           salt = hkdfSalt(32),
                           info = UTF8(JSON(["drey-passkey-kek", 1, rpOrigin,
                                             vaultId, network, credentialIdB64])),
                           length 32)
AAD          = UTF8(JSON(["drey-passkey-envelope", 1, rpOrigin, vaultId,
                          network, credentialIdB64, prfSaltB64, hkdfSaltB64]))
wrappedDek   = XChaCha20-Poly1305(KEK, nonce(24), AAD) over DEK(32); ct || tag
```

Every Base64 field must be the exact canonical padded encoding — `atob()`'s
forgiving parse would otherwise let one byte string alias as several spellings
— and the box is pinned to exactly a 24-byte nonce and 48 ciphertext bytes
(32-byte DEK plus 16-byte tag), so an envelope that authenticates can only
ever unwrap to a 32-byte DEK.

The DEK is generated independently by the platform CSPRNG; PRF output is
key-wrapping material only and never derives S, A, B, C, a BIP32 child, or any
signing input (spec §7.7). `rpOrigin` is the exact serialized
`chrome-extension://[a-p]{32}` origin because Chromium rewrites an extension's
claimed RP ID to its full origin; any other platform identity requires a new
envelope version. `label` and `createdAtMs` are display metadata outside the
AAD — the `labelMutationStillDecrypts` record proves the boundary and the
schema keeps everything else strict.

## Negative cases

Unknown version, unknown field, mutated KDF label, non-extension RP origin,
tampered ciphertext/nonce/credential-ID/PRF-salt/HKDF-salt, wrong expected
RP/wallet/network, wrong PRF output, truncated PRF output, all-zero PRF
output, a non-canonical Base64 credential-ID alias, and a correctly
authenticated box wrapping a wrong-length plaintext must each fail closed
with the pinned `VaultError` code.
