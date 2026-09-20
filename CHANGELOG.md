# Changelog

Notable user-facing changes to `@drey/core` are recorded here. Earlier releases
are available from the private release tags.

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
