# Pinned ord differential reference

This development-only Rust program calls `ordinals::Runestone::decipher` on
exact output scripts from the committed corpus. It never imports Drey's Rune
interpreter. The library source is ord **0.27.1**, immutable Git revision
`1ad3f64dbc05b75e98665f411dbaa415f586e1c0`. Bitcoin is pinned to **0.32.8**, the
version in that revision's own Cargo.lock. This directory's committed lockfile
pins the remaining public build dependencies.

From the core repository, with Rust and Python 3 installed:

```sh
CARGO_TARGET_DIR=/tmp/drey-ord-reference-target cargo build --locked --manifest-path tests/domain/runes/reference/Cargo.toml
python3 tests/domain/runes/reference/check.py /tmp/drey-ord-reference-target/debug/drey-rune-differential
pnpm exec vitest run tests/domain/runes/protocol.test.ts
```

Cargo fetches only public pinned dependencies during the development build.
The reference executable, verification program, and production interpreter make
no network connections. Nothing in this directory is part of `src` or the
standalone recovery artifact.

The 148-case corpus preserves raw scripts and independently computed expected
artifacts, including field consumption, invalid pointers/IDs, malformed script
pushes and varints, unknown flags/tags, supply overflow, minting and etching
recognition, and ordinary transfer edicts. The generated input selection used
seed 2701; the committed exact inputs are authoritative for reproduction, so
verification does not depend on a random-generator implementation. The Python
checker recomputes every expected artifact from those inputs and fails on any
mismatch or absent negative-control coverage. The TypeScript suite independently
compares Drey against these same reference results.

Allocation cases additionally follow the same pinned revision's
`src/index/updater/rune_updater.rs` and have bounded seeded conservation checks;
this parser harness does not claim to execute ord's database-backed updater.
Real-chain allocation behavior must also be verified by the regtest lifecycle.
