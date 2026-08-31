# Changelog

Notable user-facing changes to `@drey/core` are recorded here. Earlier releases
are available from the private release tags.

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
