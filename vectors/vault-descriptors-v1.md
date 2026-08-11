# Vault descriptor and ownership vectors v1

`vault-descriptors-v1.json` pins ADR 0007 Workstream B1. It is public,
deterministic conformance data derived from the separately labelled disposable
B0 roots. Its xpubs, child keys, scripts, and addresses must never be funded or
reused. Mainnet appears only as public interoperability data; this package does
not activate a fundable Vault.

Regenerate the JSON only with `pnpm vectors:generate`. The same command also
regenerates the B0 SQVB fixture, which must remain byte-for-byte stable unless a
separate contract-version decision explicitly changes it.

## Closed descriptor grammar

B1 is not a general descriptor or watch-only import implementation. It accepts
only these two independently checksummed forms, with no whitespace:

```text
wsh(sortedmulti(2,[fA/48h/ch/0h/2h]account_xpub_A/0/*,[fB/48h/ch/0h/2h]account_xpub_B/0/*,[fC/48h/ch/0h/2h]account_xpub_C/0/*))#checksum
wsh(sortedmulti(2,[fA/48h/ch/0h/2h]account_xpub_A/1/*,[fB/48h/ch/0h/2h]account_xpub_B/1/*,[fC/48h/ch/0h/2h]account_xpub_C/1/*))#checksum
```

`ch` is `0h` with standard mainnet `xpub` serialization and `1h` with
test-network `tpub` serialization used by signet. Each extended key must be a
public depth-4 node whose child number is hardened `2h`. Key origins use exactly
`m/48'/coin_type'/0'/2'`; the descriptor normalization uses `h`. The listed
source order is logical Desktop A, Mobile B, Recovery C. Reordering those
sources changes policy identity and is rejected when checked against an
established B0 policy.

The parser requires the BIP380 checksum and then regenerates the descriptor
byte-for-byte. Missing checksums and otherwise valid alternate normalizations
are rejected. `sh`, `tr`, `multi`, Miniscript, thresholds other than 2,
non-ranged keys, raw keys, private keys, hardened child wildcards, flexible
branches, and every unknown fragment are outside policy v1. The generic
watch-only surface remains separate and continues to reject multisig imports.

## Derivation, scripts, and addresses

For each policy, branch, and non-hardened index:

1. Derive all three account xpubs through branch `0` (receive) or `1` (change),
   then the exact requested index. An invalid BIP32 child retry is not silently
   relabelled as the requested index.
2. Require three distinct compressed secp256k1 child keys.
3. Preserve A/B/C order in the ownership record, then independently sort the
   serialized 33-byte keys lexicographically for BIP67.
4. Build exactly `OP_2 <K1> <K2> <K3> OP_3 OP_CHECKMULTISIG`.
5. SHA256 that 105-byte witness script into the native SegWit-v0 P2WSH
   scriptPubKey `OP_0 <32-byte hash>` and encode `bc1q` for mainnet or `tb1q`
   for signet.

The JSON pins receive indexes 0 and 1 plus change indexes 0 and 7 for both
networks. Every regeneration must reproduce the descriptors, B0 `policyId`,
logical and sorted child keys, witness scripts, scriptPubKeys, and addresses.
Birthday height remains associated B0 metadata and is round-tripped without
changing policy identity.

## External interoperability reference

The committed outputs were independently checked offline with Bitcoin Core
v30.2.0, with networking and peer connections disabled:

- `getdescriptorinfo` reproduced descriptor normalization and checksums;
- `deriveaddresses` reproduced the ranged receive/change addresses;
- `createmultisig` over the BIP67-sorted child keys reproduced each witness
  script and P2WSH address; and
- `validateaddress` reproduced every scriptPubKey and confirmed witness version
  0 with a 32-byte witness program.

Bitcoin Core is an audit/reference implementation only. It is not a runtime or
build dependency of `@drey/core`.

## Complete-policy ownership

An ownership claim is accepted only after independently regenerating and
matching all of the following:

- B0 policy ID and network;
- receive/change branch and exact non-hardened index;
- all three logical roles, fingerprints, complete BIP48 origins, account xpubs,
  full child paths, and compressed child keys;
- the BIP67-sorted child-key array;
- the exact witness script and native P2WSH scriptPubKey; and
- the network-appropriate address.

The ownership schema is strict. One-xpub, fingerprint-only, partial, reordered,
duplicated, substituted, foreign-policy/network, wrong-branch/index,
uncompressed/private-shaped, malformed, and unknown-field claims fail closed.
No remote metadata participates in descriptor parsing, derivation, policy
selection, or ownership.

## Deliberate deferrals

PSBT construction, signing, combination, finalization, signature-only mutation
validation, transaction-plan enforcement, coordinator/transport/relay work,
asset invariants, UI, passkey persistence, and public/mainnet activation remain
B2, B3, B4, or later work.
