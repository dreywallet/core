# Vault asset-policy vectors v1

`vault-asset-policy-v1.json` pins ADR 0007 Workstream B3 for mainnet and
signet. It contains public, deterministic, disposable conformance data only.
Its keys, prevouts, addresses, PSBTs, inscriptions, and transactions must never
be funded or reused. Mainnet records are offline vectors and do not activate a
fundable Vault.

Regenerate the JSON only with `pnpm vectors:generate`. The generator also
reproduces B0, B1, and B2; their established files and identities must remain
byte-for-byte unchanged. B3 creates new plans, evidence hashes, PSBTs, and
`planDigest` values under the existing B0 and B2 formats.

## Closed Full Sat Safety evidence

B3 accepts only a strict, version-1 evidence projection with the compile-time
Full Sat Safety capability set:

```text
address_history, inscription_index, mempool_overlay, rarity,
rune_detection, sat_index, unsupported_asset_detection
```

The policy requires one authoritative, complete record for every ordered plan
input. Each record binds the network, input index, exact prevout/value/script,
primary classification, confirmations/change status, local freeze/quarantine
flags, complete inscription offsets, rare/unsupported detection, classification
revision, and classified tip. Unknown fields and alternate capability sets are
rejected.

Each B0 `classificationEvidenceHash` is independently reproduced as:

```text
SHA256(UTF8("drey-vault-classification-evidence-v1") || 00 || SQVE_bytes)
```

`SQVE_bytes` is fixed order: `53 51 56 45`, version/network bytes, big-endian
u32/u64 integers, length-prefixed bytes/text, assigned enum bytes, and explicit
boolean bytes. The hash field itself is omitted. This evidence identity is new
in B3; it does not change the SQVB plan encoding or any established B0 identity.

All Core, index, history, Ord, and per-input classified tips must identify the
same exact block. Backend identity, classification revision, observation and
validity windows must equal the B0 plan source, and the caller-supplied
validation time must be inside both the source and plan windows. Stale,
conflicting, degraded, incomplete, suspicious, frozen, quarantined, mixed,
rare-sat, runic/unsupported, unknown, or unsafe unconfirmed state is read-only.

## Ordinary cardinal movement

Every ordinary BTC input must be fresh authoritative `cardinal_clean` with no
inscriptions, rare sats, or unsupported assets. Every B0 asset effect must be
unprotected cardinal flow. There is no expert/manual/remote override.

The multi-input vectors prove separate clean inputs can fund amount and fees.
The B2 reconstruction still proves exact input/output ordering, prevouts,
scripts, values, fee, change, vsize, fee rate, sighash, and `planDigest`.

## Whole-UTXO inscription movement

The only supported inscription shape is:

```text
input 0    one authoritative inscribed UTXO with exactly one inscription
input 1+   authoritative cardinal_clean fee funding
output 0   the typed destination, containing at least the complete input-0 value
output 1+  current-policy cardinal Vault change only
```

The protected input must remain first and its destination must remain output
zero. FIFO recomputation must place the one protected sat at the same exact
offset. The protected output value and committed postage are identical, and it
must contain the entire original UTXO value. Clean fee inputs may append value
for postage or fees, but no protected sat can split, burn, become fee, move to
change, or have postage silently extracted. Co-located inscriptions, rare sats,
mixed state, Runes, and unsupported assets remain immovable.

## RBF and CPFP

Cardinal RBF requires the complete previous immutable plan. The replacement
must have distinct plan/request IDs and `planDigest`, identify the previous
transaction, preserve prior input order plus any appended clean inputs, preserve
destination and amount, pay a strictly greater absolute fee, remain within the
shared compiled maximum fee rate, remain replaceable, and pass a new B3+B2
validation and two-role signing cycle. An appended input may not spend an output
of the transaction being replaced. Broader incremental-relay and cluster-mempool
policy remains an integration responsibility. Inscription parent RBF remains
unsupported in v1.

CPFP requires the complete parent plan and exactly one input: the parent's exact
current-policy Vault change output, freshly classified as authoritative
`cardinal_clean` wallet-created unconfirmed change. A protected output can never
qualify. `cpfpCandidateOutputIndexes` is informational only; every later child
must obtain a fresh classification and revalidate.

## Signing boundary and negative coverage

The B3 safe create/sign/combine/finalize wrappers call the B3 validator before
using signing material. That validator itself reparses the canonical B0 plan,
recomputes evidence hashes, enforces the rules above, and invokes the B2 PSBT
reconstruction. The returned result binds `policyId`, plan ID, `planDigest`,
exact PSBT hash, movement kind, protected asset/output, and replacement kind.

The JSON includes positive ordinary BTC, multi-input clean funding, whole-UTXO
inscription, RBF, and CPFP records for both networks. Stable negative records
cover stale and conflicting evidence, protected-fee exposure, reordered inputs
and outputs, changed offsets, reduced postage, and unsupported assets. The test
vectors pin deterministic A+B partial results, combined PSBTs, and finalized raw
transactions for every positive case. The test suite additionally uses
property-based mutations to prove that no accepted plan
can change protected placement/postage or admit degraded, incomplete,
suspicious, rare, unsupported, or co-located evidence.

## Deliberate deferrals

Workstream C must require every signer to verify signed gateway evidence
independently, load `previousPlan` from signer-local approved-plan persistence,
apply incremental-relay/cluster-mempool policy with `testmempoolaccept`, and
restrict production coordinator imports to the B3-safe signing/finalization
wrappers. Those consumer controls do not alter the recovery/conformance B2 API.

Coordinator, transport, QR, relay, browser/native APIs, UI, passkeys, mobile
signer/storage/integration, arbitrary destinations, Rune transfer, mixed-UTXO
splitting, batch inscription movement, public/mainnet activation, funding, and
broadcast remain outside B3.
