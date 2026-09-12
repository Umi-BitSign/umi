# Registration bridge activation: September 12, 2026

UID 0 and UID 54 are running the temporary registration bridge on the coordinator
server. Both have finalized submissions under the signed bridge policy. The
old Mac Studio writers remain stopped, with their guest services masked.

This is a dated deployment record. For eligibility and miner setup, see
[current miner operation](CURRENT_MINER_OPERATION.md) and the
[bridge specification](REGISTRATION_BRIDGE.md).

## Finalized readback

Observed at 2026-09-12 20:22:32 UTC, using finalized block **9,053,863**:

`0x7c2d5e4392329f0acd4eb7e4407f216676cf6f59d6ddfc78a170c8a6919c8784`

| Validator | Finalized transaction | LastUpdate | Positive-weight UIDs | Qualifying coldkeys |
| --- | --- | ---: | ---: | ---: |
| UID 0 | `9053857-0015` | 9,053,857 | 38 | 30 |
| UID 54 | `9053828-0021` | 9,053,828 | 31 | 23 |

Both validators held permits. Their rows were 6 and 35 blocks old, respectively,
inside the 360-block activity cutoff. Each exact 256-entry raw row matched the
validator's recorded applied submission and finalized `LastUpdate`.

The validators checked health at different times, so their eligible sets differed.
Each row gives the same total raw weight to every passing coldkey group, split
among that group's passing UIDs. The coldkey counts are not counts of verified
people or independent operators.

The public [finalized readback JSON](https://pub-bfe43425f6564cc98cb3ad43b9662ae3.r2.dev/validator-supervisor/registration-bridge/evidence/d6f21030506b000c7ffd42bcb63d02ff78f56f77c3434e29c0ac2a847f571325/finalized-readback.json)
contains the full participant snapshot, both raw rows, signed policies, health
records, and applied worker receipts. Its SHA-256 is:

`d6f21030506b000c7ffd42bcb63d02ff78f56f77c3434e29c0ac2a847f571325`

These are RPC reads pinned to one finalized block, not a portable storage-proof
bundle. The included health observations are local worker records, not
independently signed attestations. No wallet contents or credentials are included.

## Economic effect at that snapshot

The most recent consensus step was **9,053,669**. It followed UID 54's initial
bridge row at `9053626-0010`, but preceded the two expanded rows above.

These **16 UIDs had positive finalized consensus and incentive**:

`6, 10, 11, 13, 14, 15, 16, 18, 19, 20, 21, 33, 223, 232, 251, 255`

The expanded set of 38 did **not** yet have that confirmation. Its effect must
be checked after a later consensus update. Neither a positive raw weight nor a
positive incentive field proves a particular realized payment or future return.
Other validators' rows can also affect the result.

## Signed deployment

- Worker revision: `2ae45d3285f5650919b60199c3b41e6275645e67`.
- Worker profile: `umi-registration-bridge-validator/1`.
- [Signed policy](https://pub-bfe43425f6564cc98cb3ad43b9662ae3.r2.dev/validator-supervisor/registration-bridge/policies/f5e41d0d83f9c478c66d64016845278cb83c9bd5a05b33a2d5c551ae4334bd17/signed-policy.json)
  SHA-256: `f5e41d0d83f9c478c66d64016845278cb83c9bd5a05b33a2d5c551ae4334bd17`.
- Both managed validators accepted shared AMD64 feed sequence **10**, digest
  `25f5688a4b7adece70ab567b92b13a0e71aeb7e54ed3675c33f3e8128ec0039c`.
- Shared ARM64 feed sequence **10** is also published, digest
  `7cd081a6674110c48b6622d5523a0e3fd11d07d3ebf48ec64b7974fec3d7defc`.
- [Release build](https://github.com/Umi-BitSign/umi/actions/runs/34715783721):
  Linux AMD64 and ARM64 passed. The targeted bridge, supervisor, deployment,
  runtime, and publication test run passed **273 tests**.

The corrected worker batches roster storage reads at the same finalized block.
Live checks reproduced and resolved upstream throttling of the earlier
point-read implementation. Invalid finality observations, changing rosters,
and insufficient submission headroom still hold the worker; they do not bypass
validation or cause an invented weight row.

The installed host supervisors retain their compatible signed host release;
their workers follow the shared signed feed. Both installations preserve their
submission journals and directive checkpoints. No coldkey was needed.

The policy keeps the original deadline: no new submissions from block
**9,073,731**, with an earlier submission-safety reserve, and hard sunset at
**9,075,171**. There is no extension of the bootstrap period and no activation
of translation scoring or model-contribution rewards.

The old `/api/v1/bootstrap-service` API describes the retired pilot policy.
It cannot attest to this bridge's activation or current eligibility.
