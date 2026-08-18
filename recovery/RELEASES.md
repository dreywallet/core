# Standalone recovery package — release digest history

**Append-only.** Never edit or remove a published row.

A recovery kit records the digests of the package that existed when the kit was
minted, and it carries those digests for as long as the Vault does. Someone
holding a kit written today may come looking in ten years for the exact artifact
it names. If this file is edited, truncated, or lost, that digest becomes an
unverifiable number and the kit's central claim — *here is the program that can
open me, and here is how to check you have it* — quietly stops being true.

For the same reason, publish each row in more than one place: the annotated git
tag, the GitHub release body, the compiled constant in the extension that mints
kits, and here. No single one of them should be the only copy, and ideally at
least one lives somewhere Drey does not control.

## How to read a row

- **Core tag** — the immutable public revision the artifact was built from.
  `git clone --branch <tag> https://github.com/dreywallet/core.git`
- **Source digest** — goes in a kit's `standaloneToolSourceDigest`. A tree hash
  over the enumerated paths in `recovery/digest.mjs`; reproduce with
  `node recovery/digest.mjs`.
- **Artifact digest** — goes in a kit's `standaloneToolArtifactDigest`. Plain
  SHA-256 of the artifact named by that release. Releases from `v0.4.6` onward
  use `drey-vault-recovery-v1.mjs`; earlier rows used the historical Sqrl name.
- **Node** — the major version the digest was produced under. Rollup output can
  shift across Node versions, so a rebuild that disagrees should first be
  retried on the recorded major before it is treated as a discrepancy.

## Releases

| Version | Core tag | Node | Source digest | Artifact digest |
| --- | --- | --- | --- | --- |
| 1 | `v0.2.11` | 22 | `4dcdadc392e2e3d8a92616ac8f6dbb65c5d74180394b0c2ee48bc0a43ec1fb8c` | `d5cacb5306e7116975108a1d9b154166b125ffe80524fecfd0349bafc7c34cbc` |
| 1 | `v0.2.12` | 22 | `a0d47300ee7e705d50b793ab8ba100b5d64f5dbe4b973b9133ca406b209f39ea` | `d5cacb5306e7116975108a1d9b154166b125ffe80524fecfd0349bafc7c34cbc` |
| 1 | `v0.2.13` | 22 | `0511ec204bedba9990f762813ab7c5ef1804edd93db1ab0a2fcd60dd1cfa2919` | `d5cacb5306e7116975108a1d9b154166b125ffe80524fecfd0349bafc7c34cbc` |
| 1 | `v0.2.14` | 22 | `333e697e12beb386fc2d5adebd86c72a12ee736e26c3bae0bf1e510bfbae606f` | `c6a33924c57a637afdb8da375aeb76de82ece0a5ce66fcad6fe6502d9dd7c925` |
| 1 | `v0.3.0` | 22 | `8b84a4d39d1d0a28a0bcae1a8b06ab1078a9ff0d097b8e77ce7273e872b6eaea` | `c6a33924c57a637afdb8da375aeb76de82ece0a5ce66fcad6fe6502d9dd7c925` |
| 1 | `v0.4.0` | 22 | `fe8d4ba57d744a131bd7d154ef667967cf3d89f439c82698dc32d6ba3aba0dac` | `7eec198a3953cb071fc066c78a051df6ae7a875da96a5379299a8b22aa0e25f5` |
| 1 | `v0.4.1` | 22 | `d26e916e70b32c9db7b0dfd93d6775817fd4aa2ce2d886352b83d546a026c2ca` | `7eec198a3953cb071fc066c78a051df6ae7a875da96a5379299a8b22aa0e25f5` |
| 1 | `v0.4.2` | 22 | `f966fa0b36e7fe8f23ae2778aa5c0bf93ddc7a5a1d70df0a6739266fd8a3209d` | `72a538184951e56b5a3f713d6c0757530a9e2f9ed97c94c908167dd33d58da85` |
| 1 | `v0.4.4` | 25 | `85ed30d807b1a33899685d9c6dc48dc5d0abc38fce20117eb767f56f2a19577e` | `72a538184951e56b5a3f713d6c0757530a9e2f9ed97c94c908167dd33d58da85` |
| 1 | `v0.4.5` | 25 | `4d10aaefef01f9a016eaeac5da63100cf2f6f67e16c1846e3cd4ffa99115db97` | `72a538184951e56b5a3f713d6c0757530a9e2f9ed97c94c908167dd33d58da85` |
| 1 | `v0.4.6` | 25 | `d99ccb8d282c29433a737242f18ba7945cd0498e914150295ac7b6099456c8b8` | `a403c7440ea10364705572b6646580964d22be9ed9d5d41255d07018658ba45e` |
| 1 | `v0.4.7` | 25 | `caecb6b74a020d99cb3c068c47874f47edb4c8c060aa632c21276cf40be0ad71` | `a403c7440ea10364705572b6646580964d22be9ed9d5d41255d07018658ba45e` |
| 1 | `v0.4.8` | 25 | `9c3b4b6f5d0b52add1a98c10f62f812e8bc8bb27b6b4f2452da9b9bf12112605` | `0f4c3da4d958b3c13eda418f980909c5adbe725e6363cf814f64e996c7ba2884` |
| 1 | `v0.5.0` | 25 | `e0d8fee792fff6e760d5ebf86f5f31dabb305030aa78ea60bb14f5ff0c1aa962` | `0f4c3da4d958b3c13eda418f980909c5adbe725e6363cf814f64e996c7ba2884` |
| 1 | `v0.5.1` | 25 | `0947eb5666d2450fe681337a9f2b1430053bd1fdc9ccd5bc667b71a365c6ab42` | `3f682e4c65dc3e959988d7a76535de8aab37c42935d16e30fade69d4aa244c92` |
| 1 | `v0.5.2` | 25 | `1d8f6da1239d01395bb75581779c2f064d2089a20cedc60429045f6e6f5f04d5` | `cdf0cb43f3536a08e4bcbeb4c6383a8f5892e8644e06a445d111fc6947130139` |
| 1 | `v0.5.3` | 25 | `57baf227f67d7d891b3f6339b783b9e31ec9a19242886ad5c5e1f0b4c2034a97` | `cdf0cb43f3536a08e4bcbeb4c6383a8f5892e8644e06a445d111fc6947130139` |
| 1 | `v0.5.4` | 25 | `3a3fdc05f06a8ec8b823dcc8628a11b060a65939c239dad977ce87ec06f0a39c` | `cdf0cb43f3536a08e4bcbeb4c6383a8f5892e8644e06a445d111fc6947130139` |
| 1 | `v0.5.7` | 25 | `497f863b8424c21ad1734949f712f7da746f071745ca58c64ff8115402538148` | `cdf0cb43f3536a08e4bcbeb4c6383a8f5892e8644e06a445d111fc6947130139` |
| 1 | `v0.5.8` | 25 | `54c662b57ce61ed7b2b746dcb87bb788db13f08c0fd9491820b452a2358922ef` | `cdf0cb43f3536a08e4bcbeb4c6383a8f5892e8644e06a445d111fc6947130139` |
| 1 | `v0.5.9` | 25 | `11288841d48ab8ddd0e35669b4b818c98baf5382cc62094f45326538de5ddb55` | `cdf0cb43f3536a08e4bcbeb4c6383a8f5892e8644e06a445d111fc6947130139` |
| 1 | `v0.5.10` | 25 | `8d8d4555f4c6148b1efc461cf6a4fc26968afc04dc89fa107abc981b96ca7021` | `cdf0cb43f3536a08e4bcbeb4c6383a8f5892e8644e06a445d111fc6947130139` |
| 1 | `v0.6.1` | 22 | `492b030d3032c7c8763e5d1b15bedc53fbcb3647388c268087d2af68a85e7d64` | `feb5c00c651b68d47a6853878b512b436bb40af6d6c820dc397deeecccf6d5a2` |
| 1 | `v0.7.1` | 25 | `ad36902318021c39a27704e51a9de660bcf7010bff00883d0de5dc2df0f11a13` | `8014d61936419bee901828b6465c8aab5338466588cc1780e42948c764b1ae2f` |
| 1 | `v0.7.2` | 25 | `887617dfb7cb88a23b481106ae1c7717d68979dd1e5feab6474841bf3b06ebfc` | `8014d61936419bee901828b6465c8aab5338466588cc1780e42948c764b1ae2f` |
| 1 | `v0.7.3` | 25 | `0d4830342405277bf33a6237bf13336ad08e5e0d6a98582ee8d1e35d57ee9656` | `8014d61936419bee901828b6465c8aab5338466588cc1780e42948c764b1ae2f` |
| 1 | `v0.7.5` | 22 | `26004c2fd84e73775be71c59662f0578dc6ee185e1f8730ee143ee1855ed301b` | `8014d61936419bee901828b6465c8aab5338466588cc1780e42948c764b1ae2f` |
| 1 | `v0.7.6` | 22 | `e88869afdfc7487005f41c35942c216c554cc4f69089195f7c4403372809dec1` | `8014d61936419bee901828b6465c8aab5338466588cc1780e42948c764b1ae2f` |
| 1 | `v0.7.7` | 25 | `04f69e9c2019bb15d9e7ac303d2ae3d7de9b58a623d0cb938585080d2eeea22a` | `8014d61936419bee901828b6465c8aab5338466588cc1780e42948c764b1ae2f` |
| 1 | `v0.7.8` | 25 | `7210fd30f1982f294c0097f1fc4cae15d7d8015e113a7f43841f2ed5fe167c49` | `8014d61936419bee901828b6465c8aab5338466588cc1780e42948c764b1ae2f` |
| 1 | `v0.7.9` | 25 | `0d12d3a2b37ebe324e8fb3b9cdc0dd9e9f4c390950e1575cf187d187bead109e` | `8014d61936419bee901828b6465c8aab5338466588cc1780e42948c764b1ae2f` |
| 1 | `v0.7.10` | 25 | `96f0e0c97bca489ccd15141800443223b3b8e9789f052f6cdb83eb39a4a12324` | `8014d61936419bee901828b6465c8aab5338466588cc1780e42948c764b1ae2f` |
| 1 | `v0.7.11` | 22 | `35d85defa3e80a512474f8e2451fe3ed3debd900d66fdd55509b39dda2c52291` | `8014d61936419bee901828b6465c8aab5338466588cc1780e42948c764b1ae2f` |
| 1 | `v0.7.12` | 22 | `21fa4ea87e7f9a8d57991b8ce4221ea373272f60eb45bd3e46fa69c014c899b6` | `8014d61936419bee901828b6465c8aab5338466588cc1780e42948c764b1ae2f` |
| 1 | `v0.7.13` | 25 | `502ea701615a050e70a72f9872f02563e4f4472cfb5663feb068a521249dffa1` | `8014d61936419bee901828b6465c8aab5338466588cc1780e42948c764b1ae2f` |
| 1 | `v0.7.15` | 25 | `b0c21407bd1ba7e64557d1c5fdfaf977064fe6701a7de1943c895c9ba6d28e4d` | `018732e7a8ad19e793c86dbdc13b205c33f8867c8a66ed9f454f89ff32d2cc14` |
| 1 | `v0.7.16` | 25 | `dc2239e38387cad16fc23f292e081e4037977bffa6d215b2185a2cbcce9a0873` | `018732e7a8ad19e793c86dbdc13b205c33f8867c8a66ed9f454f89ff32d2cc14` |
| 1 | `v0.8.0` | 25 | `8ef75e4849a453be766aa9b2acf17b5ab86544f46f9f4b47260b7999c7aea09e` | `7b267183ba5b1d14d2073b54f9f67d9cf17b2f3a1da64ed063a0702ed4d2d82d` |
| 1 | `v0.8.1` | 25 | `5f1ed31524582b9a644626cd3cda7fe3f58daa9ae9472485df6bfbe7331799d5` | `9eba8ce9a9b7d662b96e4808d6d49fdaf8957c988c6f81a99602e1dd4cead271` |
| 1 | `v0.8.2` | 25 | `f5e10ab5d3900fac7b0aaa01e6702adcfd1ee3565b24a0f541401a3296635723` | `9eba8ce9a9b7d662b96e4808d6d49fdaf8957c988c6f81a99602e1dd4cead271` |
| 1 | `v0.8.3` | 25 | `ba3a2f4918d5192132ad8a22dd086bfd1bb592846ae7d8b3e1b6b8553bf60726` | `5a22e477cf6b3cfd63563833df775098cfc009c3b7ca91309c662a0a46f80914` |
| 1 | `v0.9.0` | 25 | `e5825a79f5ca25f27c66de81470b8c0b74735b352f44205ab790535d8a7272c9` | `5a22e477cf6b3cfd63563833df775098cfc009c3b7ca91309c662a0a46f80914` |

Every row so far is tool version **1**. Rows through `v0.2.13` share an artifact
digest because the program itself did not change across them — only what the
source digest covers, and the core revision it was built from. That is the two
digests doing different jobs: the artifact digest answers "am I running the
right program"; the source digest answers "what revision was it built from".
A kit names one row; verify against that row.

`v0.2.13` is a clear example of the distinction. It promoted Vault signer-role
production into `src/domain/vault/multisig-role.ts` and added
`vectors/vault-role-v1.json`, both of which sit inside the source digest and
neither of which the recovery program imports. The source digest moved; the
bytes you run did not.

`v0.2.14` replaces throwing decimal/u64 schema refinements with the shared
non-throwing validator used by the Vault contracts and asset-policy evidence.
The standalone recovery program imports those contracts, so both the source
digest and bundled artifact digest move for this release.

`v0.3.0` adds the platform-free fixed-rate BC-UR transport primitives and
published Blockchain Commons conformance vectors. They are available to the
wallet surfaces but are not imported by the standalone recovery program, so
the source digest moves while the bundled recovery bytes remain identical to
`v0.2.14`.

`v0.4.0` adds stable public-account identity, descriptor parsing, and exact
fee-rate contracts. The recovery bundle imports shared Vault contracts touched
by this release, so both the source and artifact digests move.

`v0.4.1` preserves signed preview metadata when projecting current v4
transaction journals. The recovery program does not import that activity
projection, so the source digest moves while the artifact remains unchanged.

`v0.4.2` writes the finalized transaction file as exact raw hex without a
trailing line feed, so the file can be submitted unchanged as a relay API
request body. The recovery CLI and its open specification both changed, so the
source and artifact digests move.

`v0.4.4` adds the strict public-account interchange boundary and current BCR
account-descriptor transport. The recovery bundle does not import the
interchange module, so its artifact remains unchanged; the source digest moves
because it identifies the complete reviewed core revision.

`v0.4.5` adds password reauthentication that unwraps and immediately destroys
the DEK without decrypting the seed payload. The standalone recovery artifact
does not import that boundary, so its bytes remain unchanged.

`v0.4.6` completes the clean-break Drey rename. The package scope, repository
URL, provider error data, domain-separation labels, Vault contract text,
standalone CLI identity, and artifact filename now use Drey. Existing test
wallets and pre-Drey recovery artifacts are intentionally not migrated; this
private pre-release has only disposable tester state. Both digests move, and
the published artifact is `drey-vault-recovery-v1.mjs`.

`v0.4.7` binds the compile-time marketplace registry to the renamed fixture
manifest digest. The recovery program does not import that registry, so its
artifact bytes remain identical while the source digest moves.

`v0.4.8` adds the complete offline Recovery C setup and paper-restore ceremony:
bounded canonical challenge/response records, full-challenge proof binding,
controlling-terminal-only word generation and hidden restore entry, randomized
all-word confirmation, public golden vectors, and best-effort private-buffer
zeroization. The standalone artifact changes because it now owns both ceremony
commands.

`v0.5.0` promotes scan evidence, canonical cardinal and whole-UTXO inscription
planning, current `ur:psbt` QR interchange, explicitly proprietary authenticated
Vault context, and the one-way broadcast-attempt lifecycle into shared core.
The extension and mobile coordinators therefore consume one tagged policy and
byte-construction implementation. The standalone recovery program does not
import these coordinator modules, so its artifact remains byte-identical while
the reviewed source digest moves.

`v0.5.1` cryptographically authenticates every pairing and approval QR
envelope field with the sender origin's established BIP48 proof key. Channel
identities, counters, nonces, transcripts, expiry, stage, and payload hashes
can no longer be rewritten independently of the signer. The shared binary
encoder is imported by the standalone package, so both recorded digests move.

`v0.5.2` includes the sender's canonical public origin inside that signed
envelope. A fresh pairing peer can therefore verify Desktop A before a policy
exists, while established peers additionally require the embedded origin to
equal the policy role. Both recovery digests move with the shared encoder.

`v0.5.3` records completion of the fifth provider-independent exit capability:
Drey extension 0.6.0's separately bundled offline Role A recovery page retains
the stable WebAuthn RP while a page-local `connect-src 'none'` CSP prohibits
network access. The standalone CLI bytes do not change; its open specification
and the reviewed core version do, so only the source digest moves.

`v0.5.4` partitions the shared Vault change descriptor into disjoint online
coordinator lanes: Desktop A reserves even indexes and Mobile B reserves odd
indexes. The standalone CLI does not coordinate online plans, so its artifact
bytes remain identical while the reviewed source digest moves.

`v0.5.7` adds the shared address book, manual BIP-322 message contracts,
encrypted device-to-device contact transfer, and its atomic import contract.
None is imported by the standalone CLI, so its artifact bytes remain identical
while the reviewed source digest moves.

`v0.5.8` adds online CPFP construction and signer-local recognition of an
unconfirmed Vault change output. The standalone CLI does not accelerate online
transactions, so its artifact bytes remain identical while the reviewed source
digest moves.

`v0.5.9` adds the bounded, platform-free BIP-321 payment-instruction parser and
fallback-selection contract. The standalone CLI does not import payment
instructions, so its artifact bytes remain identical while the reviewed source
digest moves.

`v0.5.10` removes the dedicated extension approval window from the portable
wallet RPC sender set. Approval commands continue over their exact window- and
tab-bound transport, while the broad wallet operation registry is unavailable
to that surface. The standalone CLI does not import messaging operations, so
its artifact bytes remain identical while the reviewed source digest moves.

`v0.6.1` extends the gateway preview contract to the universal m9p-preview-v3
shapes (screenshot-sourced rasters, text excerpts, media badges,
render_pending). The recovery bundle's dependency graph includes the shared
gateway contract module, so both digests move; the recovery program's behavior
is unchanged. Recorded under Node 22, where the `v0.5.10` source digest also
reproduces byte-for-byte.

`v0.6.2` is a version-bump-only release cut so consumers can pin a tag at the
repository head that also carries the release ledger itself. The artifact
bytes are identical to `v0.6.1`; the source digest moves with `package.json`.

`v0.7.3` pins provider-PSBT refusal of an `OP_RETURN` output before signing.
The standalone recovery program does not import that provider boundary, so its
artifact bytes remain identical while the source digest moves with the tagged
package revision.

`v0.7.7` adds the platform-free mobile connection, session, permission, and
provider-foundation contracts shared by the native wallet browser. The
standalone recovery program does not import those modules, so its artifact
bytes remain identical while the reviewed source digest moves.

`v0.7.8` replaces the invalid packaged phishing-policy signature left by the
clean-break domain-tag rename and adds an exact snapshot regression. The
standalone recovery program does not import provider phishing policy, so its
artifact bytes remain identical while the reviewed source digest moves.

`v0.7.10` bounds provider `signPsbt` input selections to the worker's existing
200-input ceiling. The standalone recovery program does not import the provider
registry, so its artifact bytes remain identical while the reviewed source
digest moves.

`v0.7.12` updates the public-mirror company identity, and `v0.7.13` adds
display-only inscription references to the UTXO list contract. The standalone
recovery program imports neither boundary, so its artifact remains identical
while each tagged source digest identifies its complete reviewed revision.

`v0.7.15` adds atomic multi-inscription planning and final-byte policy checks.
`v0.7.16` hardens atomic inscription batch analysis and signing policy. The
standalone recovery program imports the shared transaction plan and signing
boundary, so both releases move the reviewed source digest and bundled artifact
digest.

`v0.8.0` adds native payment batching, deliberate inscription-postage
management, and recovery-metadata contracts. The shared transaction and signing
changes move both the reviewed source digest and the bundled artifact digest.

`v0.8.1` adds the bounded wallet-scan response and versioned history coverage.
The source and bundled artifact digests move with the reviewed core revision.

`v0.8.2` corrects the development lockfile and carries forward the bounded-scan
documentation. The recovery program is unchanged, so its artifact digest stays
the same while the source digest moves with the release version.

`v0.8.3` bounds untrusted recovery inputs and wallet request structures before
expensive processing. The standalone recovery program changes, so both the
reviewed source digest and bundled artifact digest move.

`v0.9.0` adds exact-origin OMB Wiki buyer marketplace policy. The standalone
recovery program does not import marketplace policy, so its artifact remains
identical while the source digest binds the new tagged core revision.

Kits minted before the first row above carry an all-zero digest sentinel, which
is deliberate: inventing a digest would claim a verifiable provider-independent
exit that nobody can check. Those kits remain fully valid — their descriptors,
policy ID, and addresses are what recovery actually depends on — and their
holders obtain this package's digest from the release notes instead.

### The source-digest rule changed after v0.2.11

`v0.2.11`'s source digest was computed before `recovery/README.md` — the open
specification — was covered. From the next release onward it is, so that the
identical binary cannot be published beside a rewritten specification with both
digests still verifying.

This does not invalidate the row above, and no published row is ever
recomputed. `recovery/digest.mjs` is itself inside the digest, so every release
is reproducible from its own tag using the rule that shipped with it. Verifying
`v0.2.11` means cloning `v0.2.11` and running *its* `digest.mjs`, which is what
the instructions have always said.

## Cutting a release

1. `pnpm test && pnpm typecheck && pnpm lint` on a clean worktree.
2. `pnpm recovery:verify` — builds twice and fails unless the bytes are
   identical. Record the Node version it prints.
3. Bump `version` in `package.json`, commit, tag `vX.Y.Z`, push commit and tag.
4. Re-run `node recovery/digest.mjs` **at the tag**, on a clean checkout. The
   source digest covers `package.json`, so it changes with the version bump; the
   digest published must be the one computed at the tagged revision.
5. Append a row here, in its own commit, and attach
   `recovery/dist/drey-vault-recovery-v1.mjs` to the GitHub release.
6. Update the extension's digest constants in a separate reviewed change, and
   pin the extension to this exact core tag. The package that reads kits and the
   coordinator that writes them must agree on the contract encoder, or a kit's
   digest would name a tool built against a different format.
