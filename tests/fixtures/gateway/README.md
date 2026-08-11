# Gateway contract fixtures (committed copies)

The gateway repo (`../gateway`, its `src/schemas.ts` and
`docs/design/response-signing.md`) is the **source of truth** for the
client/gateway contract (spec §4). The files here are committed copies:

- `status.signed.json` — valid dev-key-signed `/v1/status` body (signet).
- `status.wrong-network.json` — validly signed but `network: "mainnet"`; must
  be rejected by client network policy, not by signature (spec §3.2).
- `status.tampered-signature.json` — signed body with the last signature byte
  flipped; must fail signature verification (spec §6.2).
- `inscription-previews.json` plus the three `inscription.*.signed.json`
  responses — deterministic M9P metadata, inert PNG/placeholder provenance,
  and exact approval-batch bindings.
- `dev-public-key.json` — the dev fixture signing public key (hex). The
  secret key lives only in the gateway repo; the whole keypair is dev-only,
  committed, public, and must never be provisioned to any deployment.

Regenerate upstream with `pnpm fixtures:sign` (gateway repo), then copy here
with `pnpm fixtures:sync` (this repo). **Never hand-edit** — the signature
covers the exact file bytes; these are literal HTTP bodies.
`tests/fixtures/gateway-drift.test.ts` fails when the copies drift from the
sibling checkout.
