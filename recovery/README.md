# Drey Vault standalone recovery package

**Open your Vault without Drey.**

This is the program ADR 0007 §6 requires: a versioned, checksummed, reproducible
package that can reconstruct a Drey Vault from its public recovery kit and spend
from it with any two of its three roles — with no Drey gateway, no relay, no
browser extension, and no company.

It opens no network connection. Not to Drey, not to anyone. There is no update
check, no telemetry, and no crash reporting. You supply the list of coins; it
gives you back a signed transaction; you broadcast that transaction from
wherever you like.

**Status:** this command-line package covers four of the five
provider-independent exit capabilities ADR 0007 §6 lists and also owns the
offline creation and paper-restore ceremony for Recovery C. The fifth capability
ships in Drey extension 0.6.0 as the separately bundled, open-source offline
Role A recovery page: it retains the stable `chrome-extension://` WebAuthn RP,
uses a page-local `connect-src 'none'` policy, refuses while the browser reports
networking available, and hands the recovered Role A words to this command-line
package. See [What this package does not do](#what-this-package-does-not-do).

---

## Quick start

### Create Recovery C during Vault setup

Recovery C is a separate 12-word **Vault Recovery Key**. It supplies one vote
in a 2-of-3 Vault and cannot recover or spend anything alone. It is not your
everyday **Spending Recovery Phrase**, and the two must be stored separately.

First verify the exact standalone artifact and prepare a clean temporary
environment. You—not this program—must establish that the computer is offline.
Software failing to reach the network is not proof that networking is absent.
Disable networking, swap, hibernation, crash reporting, shell/terminal logging,
clipboard tools, screenshots, printing, and persistent home storage before
continuing.

The extension exports a small public binary challenge. On the offline computer:

```bash
node drey-vault-recovery-v1.mjs create-recovery-c \
    --challenge recovery-c-setup.sqvb --out recovery-c-response.sqvb
```

The command requires a real controlling terminal and refuses redirected input,
redirected output, CI, or unattended execution before drawing entropy. It shows
the words only on that terminal, confirms all 12 in a cryptographically shuffled
order, and writes only a public signer origin and proof with restrictive file
permissions. Three wrong confirmations abort and produce no response. Import
the response in the same extension setup, remove the media, and power off the
temporary environment. Clearing mutable buffers is best effort; neither this
tool nor JavaScript can promise secure erasure on a general-purpose computer.

After the policy and public kit exist, the extension exports a fresh backup-
check challenge. Start a second clean offline invocation and type the paper
words through hidden terminal input:

```bash
node drey-vault-recovery-v1.mjs verify-recovery-c \
    --kit kit.hex --challenge recovery-c-backup-check.sqvb \
    --out recovery-c-backup-response.sqvb
```

The command checks the exact network, policy, complete Recovery C origin, tool
release digests, and current artifact before accepting the words. Its response
is a public domain-separated signature. It contains no mnemonic, entropy, seed,
xprv, or child private key.

### Recover and exit an existing Vault

```bash
# 1. Check you are running the program your kit names.
node drey-vault-recovery-v1.mjs verify-self

# 2. Read the kit. Everything shown is recomputed, not read out.
node drey-vault-recovery-v1.mjs read-kit --kit kit.hex

# 3. Find your coins. ANY source works — see "Where to get the UTXO list".
node drey-vault-recovery-v1.mjs derive-addresses --kit kit.hex --to 19

# 4. Build the spend.
node drey-vault-recovery-v1.mjs plan \
    --kit kit.hex --utxos utxos.json \
    --to bc1q_your_own_wallet --fee-rate 5 \
    --out recovery-session.json

# 5. Sign with two DIFFERENT roles. These steps can happen on different
#    machines, days apart; only recovery-session.json has to travel.
node drey-vault-recovery-v1.mjs sign --session recovery-session.json \
    --role recovery-c --words c-words.txt
node drey-vault-recovery-v1.mjs sign --session recovery-session.json \
    --role mobile-b --words b-words.txt

# 6. Produce the final transaction.
node drey-vault-recovery-v1.mjs finalize \
    --session recovery-session.json --out tx.hex

# tx.hex is exact raw transaction hex with no trailing line break, so it can
# be used directly as a relay's HTTP request body.

# 7. Broadcast tx.hex however you want.
```

Requires Node 20 or later. Nothing to install.

---

## Verify the package before you trust it

Two digests describe this package, and both appear inside your recovery kit:

| Digest | Covers |
| --- | --- |
| `standaloneToolArtifactDigest` | The SHA-256 of the single `.mjs` file you run. |
| `standaloneToolSourceDigest` | A tree hash over the source it was built from — including this specification. |

**This document is inside the source digest.** That is deliberate: if it were
not, the identical binary could be published beside a rewritten specification —
different claims about what the program does, what it refuses, and which
capabilities it does not cover — and both digests would still verify. ADR 0007
§6 asks for an open specification, reproducible source, and checksums as one
gate, so they are one digest.

The rule that computes the source digest lives in `recovery/digest.mjs`, which
is itself covered. Each release is therefore reproducible from its own tag using
its own rule, and changing the rule cannot retroactively invalidate an older
published digest.

Check the artifact you have against the artifact your kit names:

```bash
shasum -a 256 drey-vault-recovery-v1.mjs
# or
node verify.mjs drey-vault-recovery-v1.mjs <digest-from-your-kit>
```

If they disagree, **stop**. Either it is not the release your kit names, or it
was altered in transit.

If your kit's digests are all zeros, it was created before any standalone
package was published. The kit is still completely valid — the descriptors,
policy ID, and addresses in it are what matter — but you will need to get this
program's digest from the published release notes instead.

### Rebuilding from source

```bash
git clone --branch <tag> https://github.com/dreywallet/core.git
cd core && pnpm install --frozen-lockfile
pnpm recovery:verify     # builds twice, proves the bytes are identical
```

`pnpm recovery:verify` is the reproducibility claim made checkable: it builds
twice from a clean output directory and fails if the bytes differ. Rollup output
can shift with the Node version, so `RELEASES.md` records the exact Node major
each published digest was produced under.

`node recovery/digest.mjs --list` prints both digests and every file the source
digest covers.

---

## Where to get the UTXO list

This tool deliberately has no built-in data source, and that is a design
decision rather than an omission. Here is the reasoning, because you should be
able to check it rather than take it on faith:

- **The scripts are never believed.** Every outpoint you supply is located
  inside the policy's own derivation space. A source cannot make this tool spend
  an input your Vault does not own — it simply will not find it, and will refuse.
- **The amounts are never believed either, and they do not have to be.** BIP143
  commits each input's value to the signature hash. Supply a wrong amount and
  you get a signature no node will accept. A lying source can waste your
  afternoon; it cannot move a satoshi anywhere.

So the only thing a data source can actually do to you is **withhold** — show
you fewer coins than you have. That is an availability problem, and the answer
to an availability problem is to ask someone else. A tool with one built-in
source cannot do that. A tool with none can use every source there is.

Pick whichever you can actually get working today:

| Source | Trust | Privacy | Availability |
| --- | --- | --- | --- |
| **Your own Bitcoin Core** | Best — your own validation, nobody else's word | Best — nothing leaves your machine | Worst — needs a synced node at the moment you need it |
| **A public Electrum server** | The server can withhold; it cannot forge | Poor — one server sees every Vault address, linked | Good — many servers, and you can name your own |
| **A block explorer API** | One company over TLS, no proof | Worst — a single well-known correlator sees the whole Vault | Best — nothing to set up |

**Bitcoin Core** (best privacy; also cross-checks the descriptor):

```bash
bitcoin-cli importdescriptors '[{"desc":"<receive descriptor from your kit>","timestamp":0},
                                {"desc":"<change descriptor from your kit>","timestamp":0}]'
bitcoin-cli listunspent
```

**A block explorer** (fastest; worst privacy):

```bash
node drey-vault-recovery-v1.mjs derive-addresses --kit kit.hex --to 30
# then, for each address that shows a balance:
curl -s https://mempool.space/api/address/<addr>/utxo
```

### The UTXO file

An array, or an object with a `utxos` array. Each entry needs `txid`, `vout`, a
value, and some way to identify the script:

```json
{
  "utxos": [
    { "txid": "9dc0…", "vout": 0, "valueSats": "25000", "address": "bc1q…" },
    { "txid": "bb82…", "vout": 1, "value": 633, "scriptPubKeyHex": "0020…" }
  ]
}
```

`valueSats` (string) or `value` (number, satoshis) both work — a block
explorer's output can usually be pasted in with little editing. `address` or
`scriptPubKeyHex`, whichever you have.

### Broadcasting

Any of these; the transaction is already signed, so whoever relays it learns
what it does but cannot change any part of it:

```bash
bitcoin-cli sendrawtransaction "$(cat tx.hex)"
curl --fail-with-body --data-binary @tx.hex \
    -H 'Content-Type: text/plain' https://mempool.space/api/tx
```

`finalize` deliberately writes no trailing newline: the file is the exact hex
request body expected by raw-transaction relay APIs, not a line-oriented text
record.

---

## The format this package reads

### Recovery C ceremony files

The setup challenge/response and backup-check challenge/response are raw binary
SQVB record types 13–16. They are versioned, fixed-order, length-bounded, reject
unknown fields and trailing bytes, and never contain recovery words or private
key material. Their exact encodings and public golden vectors are documented in
[`../vectors/recovery-c-ceremony-v1.md`](../vectors/recovery-c-ceremony-v1.md).

Treat removable media as hostile: open only the named SQVB file with this tool.
Do not run programs, follow paths, unpack archives, or trust a filename,
extension, MIME type, or autorun action from the media.

### The public recovery kit

A binary **SQVB** record, record type `10`, contract version `1`, presented as
hex. `SQVB` is `53 51 56 42`, followed by the record type and contract version
bytes, then fixed-order fields. The full encoding rules are in
[`../vectors/vault-contracts-v1.md`](../vectors/vault-contracts-v1.md); the
golden bytes are in
[`../vectors/vault-recovery-kit-v1.json`](../vectors/vault-recovery-kit-v1.json).

The kit carries: format version, network, policy version and ID, three
role-labelled signer origins (fingerprint, hardened origin path, account xpub),
both checksummed descriptors, creation and birthday metadata, the first receive
address, compatibility requirements, this package's two digests, and
plain-language recovery and rotation instructions.

**A kit cannot spend.** It contains no seed, no xprv, no passkey material, and
none of role C's words. Sharing it reveals every address the Vault will ever
use. Keep a durable copy: losing every copy can prevent recovery even if two
valid role backups survive. Store it separately from the Recovery Key.

This tool does not believe a word of it. It throws away the stated policy ID and
both descriptors, regenerates all three from the signer origins alone, and
rejects the kit if they disagree — so a tampered kit cannot make you look at, or
fund, an address the policy does not own.

### The policy

```
wsh(sortedmulti(2, <A>, <B>, <C>))
```

Three BIP48 origins at `m/48'/{0,1}'/0'/2'` (`0'` mainnet, `1'` signet), receive
on `/0/*` and change on `/1/*`, keys sorted BIP67 by raw public key inside the
script. `SIGHASH_ALL` only. Any BIP380/BIP383 descriptor wallet can read these
descriptors — you are not dependent on this program to *see* your funds, only to
conveniently spend them.

Two of the three roles sign. Two copies of one role are still one vote.

### The recovery plan

A `kind: 'recovery'` plan with a `recovery-exit` destination — a shape only this
tool produces. The extension cannot mint one (its coordinator refuses any plan
that is not a `withdrawal` to the paired Spending wallet), and it cannot be
pushed back through Drey's asset-safety validator either.

Where a Drey coordinator would record signed gateway evidence, this tool writes
published sentinels:

| Field | Value |
| --- | --- |
| `source.backendInstanceIdHash` | `sha256("drey-vault-standalone-recovery-v1/no-backend")` |
| `source.classificationRevisionHash` | `sha256("drey-vault-standalone-recovery-v1/no-revision")` |
| `inputs[].classificationEvidenceHash` | `sha256("drey-vault-standalone-recovery-v1/no-classification")` |
| `inputs[].classification` | `unknown` |
| `source.coreTip` / `indexTip` height | `0` |

They are distinctive strings rather than zeros for two reasons: an auditor can
tell an offline plan from a gateway plan at a glance, and the classification
sentinel is not the evidence hash of any real record, so a standalone plan
cannot be laundered back into Drey's asset-safe path without finding a SHA-256
preimage.

`assetEffects` is always empty. This tool has no Ordinals data source, so it
cannot honestly assert that anything is cardinal — which is exactly why §6 keeps
inscription movement out of the standalone exit.

---

## Safety properties worth knowing

**No secret ever goes on the command line.** The setup and backup-check
ceremonies accept words only through hidden controlling-terminal input. The
emergency `sign --words` path takes a file path, or `-` for stdin. Command-line
arguments are visible to every other user on the machine through the process
table and land in shell history, so the words themselves are never an argument.

**You must type the destination back.** Before any key is used, `sign` and
`finalize` require you to retype the destination address. It is checked against
the address computed from the transaction bytes — not against anything the plan
claims.

**The review screen computes; it does not echo.** Every figure — fee, fee rate,
amount, destination, change — is recomputed from the raw transaction bytes and
the policy. If a plan's stated fee disagrees with what its bytes actually do,
the screen says so and refuses to sign.

**Change ownership is proved, not asserted.** A change output is only labelled
as returning to your Vault after its script has been regenerated from the policy
and matched. Otherwise you get `*** NOT PROVED — DO NOT SIGN ***`.

**Dust change is refused, never absorbed.** If change would fall below 1,000
sats the tool refuses and tells you to sweep instead. Quietly donating your
change to a miner is how tools lose money on their users' behalf.

**A high fee rate warns; it does not refuse.** Above 50 sat/vB you must pass
`--i-accept-fee-rate <n>` to continue. It stops there deliberately. An absolute
cap that hard-refused would stop you rescuing your own funds during a fee spike
— precisely when moving matters most. (Drey's *pilot* coordinator does have a
hard 25 sat/vB ceiling. That is a bounded experiment declining to spend more
than it is worth. It is not the shape of a rule for a recovery tool, and this
package deliberately does not inherit it.)

**A wrong clock does not break a correct recovery.** An air-gapped machine's
clock is routinely wrong by months. Signing uses the plan's own creation time by
default rather than the wall clock, so a stale system date cannot invalidate an
otherwise perfect signature. Pass `--now <ms>` to enforce real time instead.

Setup and backup-check challenges are different: they are intentionally
single-use and expire, so those commands compare their public expiry with the
offline machine's clock. Set the offline clock from a trusted visible time
source before starting. If it is wrong, no key is accepted online—the extension
will still reject an expired response—but the offline step may need to be
restarted with a fresh challenge.

**RBF is on.** Inputs use sequence `0xfffffffd`, so a recovery that gets stuck at
too low a fee can be replaced rather than stranded.

---

## What this package does not do

Stated plainly, because a recovery tool that overstates itself is worse than one
that does less.

- **This CLI does not unwrap the recoverable Role A envelope.** It cannot: the
  envelope is bound to a WebAuthn credential whose relying party is a
  `chrome-extension://` origin, and no command-line program can obtain that
  assertion. Drey extension 0.6.0 supplies the separately bundled offline page
  with a `connect-src 'none'` CSP. Export the encrypted Role A package ahead of
  need, disconnect every network, open that page from the original production
  Store identity, verify the passkey, and enter the revealed `desktop-a` words
  here like either other role. The page and this CLI are open source and require
  no Drey gateway, relay, production service, or company.
- **It does not move inscriptions.** Doing that safely needs a current,
  independently operated Ordinals data source and the full sat-safety rules.
  Sweeping a Vault that holds an inscription-bearing UTXO with this tool would
  treat that UTXO as ordinary coin. Do not.
- **It does not broadcast, watch, or track.** No sockets, by design.
- **It does not build RBF or CPFP replacements.** Inputs signal RBF, but
  constructing the replacement is not implemented.

---

## Reporting a problem

If this package fails to open a Vault that it should open, that is the most
serious class of bug in the entire system. The descriptors in your kit are
standard: any BIP380/BIP383 descriptor wallet can import them and see your
funds, and Bitcoin Core can sign them given the keys. You are never dependent on
this one program.

## Licence

AGPL-3.0-only, as part of `@drey/core`.
