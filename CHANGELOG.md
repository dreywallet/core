# Changelog

Notable user-facing changes to `@drey/core` are recorded here. Earlier releases
are available from the private release tags.

## 0.20.8

### Fixed

- Vault scan widening derives each address once and stops at 320 indexes per
  branch, so a gateway reporting every address as used can no longer stall
  the client for seconds.

## 0.20.7

### Fixed

- Vault scans widen past the default 40-index bound while activity is near
  it, so change from many withdrawals (on either coordinator) is no longer
  left out of balances and planning.
- The scan engine requests every burned change index even when they exceed
  one 200-hash snapshot request.
- Community Vault listed acquisitions refuse SIGHASH_DEFAULT on P2WPKH
  inputs, where relay policy rejects it.

### Changed

- Public-account and Vault address derivation reuse recent successful
  validations of identical content, about three times faster.

## 0.20.6

### Fixed

- Keep Rune balances available while any wallet output is unconfirmed. The
  gateway reports every unconfirmed output as incomplete, which previously
  refused the whole account's Rune evidence. Such an output now binds as
  unknown content that can never be selected as a Rune input or fee funding;
  confirmed outputs must still be complete.

### Added

- `RuneEvidenceError` with a bounded, data-free `reason` for each refusal.
- `unconfirmedRuneOutputCount()` so clients can explain Runes that will appear
  after confirmation.

## 0.20.5

### Fixed

- Preserve the Recovered address role for legacy nested-SegWit coins even when
  an older cached record does not carry the newer recovery-only marker.

## 0.20.4

### Fixed

- Bind pending-change claims to their encrypted-cache key and recomputed plan
  hash before they can affect unconfirmed eligibility.
- Label legacy recovery-only addresses as recovered and avoid unsupported fee
  estimation for inputs the wallet cannot plan.

## 0.20.3

### Fixed

- Preserve the Vault coordinator's independent exact-plan recognition for
  unconfirmed change while retaining claim-gated pending-change protection in
  Spending wallets.

## 0.20.2

### Added

- Recognize exact locally-created unconfirmed payment change so a pending send
  can keep its verified change available without trusting unrelated mempool
  outputs.
- Return scanner-verified address and address-role metadata for coin control.
- Discover legacy Xverse nested-SegWit outputs as explicitly recovery-only.

### Changed

- Scan the complete locally burned change-address prefix and skip Xverse scan
  lanes that are byte-identical to standard account-zero lanes.
- Keep unclaimed unconfirmed outputs degraded until confirmed gateway evidence
  or an exact local payment-change claim makes them safe.

## 0.20.1

### Added

- Add bounded, signed native Rune history and reconciliation contracts so
  consumers can present receipts without treating incomplete history as
  spending authority.

### Security

- Bind Rune history to exact transaction identities, anchors, amounts, and
  allocation conservation, and reject malformed runestones and partial batch
  results before they can affect wallet state.

## 0.20.0

### Added

- Add exact native Rune identifiers, quantities, runestone interpretation,
  balances, transfer planning, signing, and independent final-transaction
  validation.

### Security

- Keep Rune carriers separate from clean Bitcoin fee funding, preserve
  protected sat positions and token change, and require fresh bounded evidence
  through planning, signing, and broadcast.

## 0.19.5

### Security

- Reject serialized Community Vault position transfers whose buyer funding or
  change does not belong to the seller-authorized buyer payout identity.

## 0.19.4

### Added

- Support one linked approval for the exact OMB Wiki ord.net listing workflow,
  with independently verified escrow, settlement, and recovery transactions.
- Support canonical ord.net Foundry presale withdrawals for same-wallet and
  split-recipient batches, including tightly scoped future-input handling.
- Advertise ord.net listing and Foundry capabilities only with the complete
  compile-time policies present.

### Security

- Pin the ord.net sale co-signer and Foundry CLTV Taproot constructions while
  protecting inscription offsets, recipients, proceeds, fees, sighashes, and
  no-broadcast behavior without binding harmless adapter metadata.
- Revalidate every linked transaction and every future Foundry input before
  atomically releasing signatures.
