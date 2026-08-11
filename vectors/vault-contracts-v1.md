# Vault contract binary vectors v1

`vault-contracts-v1.json` pins the ADR 0007 Workstream B0 contract family for
mainnet and signet. It is public, synthetic test data. Its xpubs, public keys,
addresses, signatures, transactions, and PSBTs must never be funded or reused.

Regenerate it only with `pnpm vectors:generate`. The generator creates four
mutually independent disposable fixture roots (Spending S and Vault A/B/C) from
separate labelled inputs in memory, writes no private material, and independently
cross-checks the two domain-separated SHA-256 results through `node:crypto`.

## SQVB fixed-order binary v1

The encoding deliberately reuses core's gateway-signing convention instead of
adding a general serialization dependency or a canonicalization profile:

```text
header       = 53 51 56 42 || record_type:u8 || contract_version:u8
enum/bool    = one assigned u8
u32/u64      = unsigned big-endian
bytes/text   = byte_length:u32 || bytes
array        = element_count:u32 || elements
nullable     = 00, or 01 || value
```

Text is strict UTF-8. Hex object fields decode to their bytes; txids use the
usual display order. Raw transaction and PSBT fields remain byte-exact. Every
decoder requires the expected magic, record type, contract version `1`, known
enum values, bounded lengths, canonical object values, and exact end-of-input.
There are no map keys, implicit defaults, indefinite lengths, alternate integer
forms, extension fields, or downgrade path in v1.

Unsigned values that can exceed JavaScript's safe-integer range are represented
in object contracts as canonical decimal strings and encoded as `u64`. Byte
identities are lowercase hex in objects. Record/object parsers are strict, so an
unknown object field is rejected just as trailing binary bytes are rejected.

## Assigned record types and field order

All nested records are `bytes` containing the complete nested SQVB record,
including its header.

| Type | Record | Fields after header, in order |
| ---: | --- | --- |
| 1 | signer origin | role, network, fingerprint:4, origin path:text, account xpub:text |
| 2 | proof input | signer origin:nested, session ID:16, nonce:32, transcript hash:32, expiry:u64 |
| 3 | proof result | role, input digest:32, `/0/0` compressed pubkey:33, compact low-S signature:64, scheme |
| 4 | policy identity | policy version, network, threshold, signer count, three origins:nested, receive descriptor:text, change descriptor:text |
| 5 | policy record | policy identity:nested, creation:u64, birthday:nullable u32, vault label:text, three signer labels:text |
| 6 | branch derivation | network, policy ID:32, branch, non-hardened index:u32 |
| 7 | unsigned plan | policy version, network, policy ID:32, plan ID:16, request ID:16, creation/expiry:u64, kind, raw unsigned tx:bytes, unique classified prevout inputs and evidence hashes, ordered outputs, typed paired-Spending/new-policy/recovery-exit destination binding, amount/change/fee/rate, finalized-vsize upper bound, sighash, asset effects, source/freshness evidence, RBF/CPFP binding, broadcast intent |
| 8 | partial-signature input | network, policy ID:32, plan ID:16, plan digest:32, expected role, canonical plan:bytes, exact PSBT:bytes, PSBT hash:32 |
| 9 | partial-signature result | network, policy ID:32, plan ID:16, plan digest:32, role added, prior PSBT hash:32, signed PSBT:bytes, signed PSBT hash:32 |
| 10 | recovery kit | policy identity:nested, policy ID:32, public metadata, first receive address:text, compatibility requirements:text array, minimum reader version, standalone source/artifact hashes:32, recovery/rotation instructions:text, instruction version |
| 11 | pairing envelope | network, session ID:16, sender/recipient channel IDs:32, counter:u64, creation/expiry:u64, anti-replay nonce:32, transcript hash:32, known message type, typed nested payload:bytes, payload hash:32 |
| 12 | PSBT approval envelope | network, policy ID:32, plan ID:16, plan digest:32, sender/recipient channel IDs:32, counter:u64, expiry:u64, anti-replay nonce:32, transcript hash:32, stage, typed partial-signature payload:bytes, payload hash:32 |

Network bytes are `0=mainnet`, `1=signet`. Roles are
`0=desktop-a`, `1=mobile-b`, `2=recovery-c`; policy records require that exact
A/B/C order. Branches are `0=receive`, `1=change`. Policy v1 accepts only
threshold 2, three distinct fingerprints/xpubs, native BIP48 account origins,
canonical checksummed receive/change `wsh(sortedmulti(2,...))` descriptors, and
`SIGHASH_ALL` (`1`).

The proof scheme byte `0` means compact 64-byte, low-S secp256k1 ECDSA over the
proof-input digest using the account xpub's non-hardened `/0/0` child. This binds
the complete origin/xpub rather than treating a four-byte fingerprint as proof.

## Identity hashes

The exact domain constructions are:

```text
policyId  = SHA256(UTF8("drey-vault-policy-v1") || 00 || type-4 policy bytes)
planDigest = SHA256(UTF8("drey-vault-plan-v1")  || 00 || type-7 plan bytes)
```

Type-4 policy bytes omit `policyId` and all associated metadata. Creation time,
birthday, vault/signer labels, recovery instructions, first-address display,
tool digests, and other presentation fields therefore cannot change
`policyId`. Type-7 plan bytes omit only `planDigest`; every signing-meaning plan
field is committed.

Exact PSBT and nested-payload hashes also use closed domains:

```text
psbtHash             = SHA256(UTF8("drey-vault-psbt-v1") || 00 || psbtBytes)
pairingPayloadHash   = SHA256(UTF8("drey-vault-pairing-payload-v1") || 00 || payloadBytes)
approvalPayloadHash  = SHA256(UTF8("drey-vault-approval-payload-v1") || 00 || payloadBytes)
proofInputDigest     = SHA256(UTF8("drey-vault-pop-v1") || 00 || type-2 proof-input bytes)
```

## Negative coverage

The JSON pins malformed binary controls for unknown contract versions,
networks, roles, trailing data, and truncation. The test suite additionally
rebuilds negative objects for reordered/duplicate roles, duplicate fingerprints
or xpubs, foreign descriptor keys, wrong network/xpub prefix, wrong BIP48
origin, unknown fields/policies/sighashes/message stages, descriptor or policy
mutation under a retained `policyId`, plan/transaction/evidence mutation under a
retained `planDigest`, PSBT mutation, role substitution, and envelope-binding
mutation. Both positive vector families assert byte-for-byte round trips and
stable identity hashes after parse/serialize cycles.

Descriptor script/address derivation and ownership, PSBT signature-only mutation
validation/combination/finalization, and protected-asset policy enforcement are
deliberately B1/B2/B3. B0 binds their complete public inputs without implementing
those later packages.
