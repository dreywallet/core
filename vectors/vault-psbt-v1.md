# Vault PSBT partial-signing vectors v1

`vault-psbt-v1.json` pins ADR 0007 Workstream B2 for mainnet and
signet. It contains only public, deterministic, disposable fixture data. Its
keys, prevouts, addresses, PSBTs, signatures, and transactions must never be
funded or reused. Mainnet records are conformance data only and do not activate
a fundable mainnet Vault.

Regenerate the JSON only with `pnpm vectors:generate`. B2 uses the established
B0 policy identities and B1 derivations without changing either older vector.
The B0 pre-B2 sample plan recorded a placeholder vsize of `153`; B2 creates a
new plan and `planDigest` with the independently reproduced conservative
native-P2WSH vsize upper bound of `189` and ceiling fee rate of `5292` sat/kvB.
The bound reserves two 72-byte DER+sighash witness signatures per input; the
actual finalized vsize may be smaller. The B0 file and its identity bytes remain
unchanged.

## Closed PSBTv0 profile

The global map contains only the exact unsigned transaction. Every input
contains exactly:

- the complete witness UTXO amount and scriptPubKey;
- the exact B1 105-byte witness script;
- `PSBT_IN_SIGHASH_TYPE = SIGHASH_ALL`;
- one BIP32 derivation for each logical A, B, and C child, including its master
  fingerprint and full `m/48'/coin_type'/0'/2'/branch/index` path; and
- zero to three validated ECDSA partial signatures.

Current-policy Vault change outputs contain their witness script and all three
BIP32 derivations. Other outputs contain no signer metadata. PSBTv2 fields,
global xpubs, non-witness UTXOs, redeem scripts, final fields, hash preimages,
Taproot fields, proprietary keys, unknown keys, and every other map meaning are
rejected. Duplicate keys and missing or extra derivations are rejected before
signing.

The surrounding B0 partial-signature request binds the exact PSBT hash to the
canonical plan bytes, `planDigest`, `policyId`, network, plan/request IDs,
ordered prevouts and outputs, amounts, fees, change, classifications, evidence,
freshness window, destination, and broadcast intent. PSBT metadata never
selects or changes those facts.

## Signing and mutation rule

Before using a private root, the signer reparses the canonical B0 plan and the
serialized PSBT, reconstructs every B1 ownership proof, verifies exact unsigned
transaction bytes and fee/vsize facts, and checks the signing time against both
plan and evidence freshness windows. The root must reproduce the expected
master fingerprint, BIP48 account origin, network-specific account xpub, branch,
index, and child public key.

One operation adds the expected role's valid low-S DER `SIGHASH_ALL` signature
to every input. The serialized result is reparsed. Its unsigned transaction,
prevouts, scripts, derivations, outputs, and all non-signature fields must be
identical, and its cryptographically recovered role set must equal the previous
set plus exactly the requested logical role. A second device copy of the same
root therefore remains one vote.

## Combination and finalization

Combination accepts two or three independently serialized one-role PSBTs only
after each one validates against the same B0 plan and B1 policy. Duplicate roles
are rejected. Rather than trusting a permissive generic PSBT merge, B2 rebuilds
the approved base PSBT and copies only the validated signature entries in
deterministic order.

Finalization requires at least two complete logical roles. If all three signed,
the deterministic quorum is A+B. For every input, signatures are placed in the
BIP67 witness-script key order and the final native-P2WSH witness is exactly:

```text
empty CHECKMULTISIG element | signature 1 | signature 2 | witness script
```

The verifier reparses the final raw transaction, proves that its non-witness
bytes still equal the approved unsigned transaction, requires the same two
logical roles on every input, validates strict DER/low-S encoding and the
appended `0x01` sighash byte, checks each ECDSA signature, and requires the exact
actual vsize not to exceed the approved upper bound. It returns that actual
finalized vsize, so valid shorter DER signatures do not invalidate the plan.

The low-level B2 signing and finalization functions do not enforce asset safety.
They remain public for conformance and provider-independent recovery. Production
coordinators must use only the B3-safe signing/finalization wrappers.

## External interoperability

The committed vectors were checked offline with Bitcoin Core v30.2.0 in a
temporary regtest datadir with peer listening and discovery disabled:

- `decodepsbt` and `analyzepsbt` accepted every unsigned and one-role PSBT;
- `combinepsbt` produced the same decoded signing meaning for A+B, A+C, and B+C;
- `finalizepsbt` produced the exact committed raw transaction for all six
  network/quorum records; and
- `decoderawtransaction` reproduced every txid, wtxid, and `189` vsize.

Bitcoin Core sometimes preserves a different valid PSBT map-entry order, so a
combined PSBT is compared semantically; B2's own output remains byte-stable.
Bitcoin Core is an audit/reference implementation, not a runtime dependency.

## Negative coverage

Tests reject foreign policies, networks, roots, origins, xpubs, branches,
indexes, child keys, witness scripts, scriptPubKeys, and signatures; A+A and
B+B; incomplete or unexpected roles; malformed, high-S, duplicated, or non-ALL
signatures; unknown/proprietary fields; missing or extra derivations; changed
unsigned bytes, inputs, outputs, order, amounts, fee, change, classifications,
freshness evidence, and request identity; sub-quorum finalization; and malformed
or reordered final witnesses.

B3 asset-policy enforcement, B4 release/tagging, coordinators, transport, QR,
relay, browser/native APIs, UI, passkey persistence, consumer pinning, and
public/mainnet activation remain deliberately deferred.
