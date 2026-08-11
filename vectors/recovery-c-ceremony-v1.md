# Recovery C ceremony v1 vectors

`recovery-c-ceremony-v1.json` fixes the canonical SQVB bytes for the public,
removable-media records used by offline Recovery C setup and the later paper
restore check. Every mnemonic used to generate these vectors is a published
BIP39 test vector and must never hold value.

Record types extend the existing `SQVB || type:u8 || version:u8` namespace:

| Type | Record |
| ---: | --- |
| 13 | Recovery C setup challenge |
| 14 | Recovery C setup response |
| 15 | Recovery C backup-check challenge |
| 16 | Recovery C backup-check response |

The setup response proof reuses `VaultProofOfPossessionV1`, with its transcript
field set to `SHA256("drey-recovery-c-setup-challenge-v1" || 0x00 || exact
challenge bytes)`. The response carries that same digest, so the proof binds
every challenge field and a response cannot move between open ceremonies.

The backup response signs
`SHA256("drey-recovery-c-backup-check-challenge-v1" || 0x00 || exact challenge
bytes)` with Recovery C's BIP48 account child `/0/0`, using compact low-S ECDSA.
The challenge binds the policy, complete C origin, network, nonce, expiry, and
standalone source/artifact release identity. Replay prevention remains a
coordinator state transition: a valid signature cannot prove whether its
single-use challenge was already consumed.

The human display fingerprint is the first 64 bits of the applicable complete
challenge digest, rendered as four lowercase hexadecimal groups. It is a
comparison aid only; protocol checks always compare the full 256-bit digest.
