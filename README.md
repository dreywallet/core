# @drey/core

Platform-free core of the Drey Bitcoin wallet: domain logic, wallet messaging
contracts, the scan engine, the gateway client, and the dApp provider wire
contracts. No UI and no browser or React Native dependencies — the Chrome
extension and the mobile app both build on this package.

Consumers pin an exact release tag rather than a semver range:

```json
"@drey/core": "git+https://github.com/dreywallet/core.git#vX.Y.Z"
```

TypeScript source is consumed directly; there is no build step.

## Bounded account scanning

Core v0.8.1 prefers the signed `/v1/wallet/scan-snapshot` route and falls back
to the legacy snapshot route only when the new route returns 404 during an
additive gateway rollout.

The scan contract treats balances and collectibles differently from Activity:
UTXOs, source identity, classification revision and response integrity must
remain complete and independently verified, while transaction history may be
explicitly partial. Signed active script hashes keep a used zero-balance
address discoverable even when its older history exceeds the service limit.
Partial coverage is versioned in the encrypted cache, survives restart and is
never used to relax spending or classification gates.

## Layout

- `src/domain/` — wallet domain logic (keys, PSBTs, vault multisig, policy)
- `src/messaging/` — typed message contracts between wallet surfaces
- `src/scan/` — chain scan engine and activity projection
- `src/gateway-client.ts` — client for the Drey gateway API
- `src/provider/` — dApp provider wire contracts
- `recovery/` — standalone offline recovery tool; see `recovery/README.md`
- `vectors/`, `tests/` — golden conformance vectors and the test suite

## Recovery tool

`recovery/` is a provider-independent exit: a single reproducible bundled Node
file that signs a sweep transaction from a UTXO-set file, with no network
access. `pnpm recovery:verify` builds it twice and fails unless the bytes
match. Published artifact digests are recorded in `recovery/RELEASES.md`.

## Development

```bash
pnpm install
pnpm test
pnpm typecheck
pnpm lint
```

Some fixture-drift tests compare against a sibling gateway checkout and skip
themselves when one is not present.

## License

AGPL-3.0-only. See `LICENSE`, and `CONTRIBUTING.md` before opening a pull
request.
