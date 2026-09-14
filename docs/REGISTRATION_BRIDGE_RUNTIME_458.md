# Registration bridge runtime 458 compatibility

This records the initial runtime-458 repair. The subsequent
[version-independent bridge](REGISTRATION_BRIDGE.md#validator-rollout) removes
both the parser allowlist and the runtime-number submission gate. The rollout
below describes the older pinned release, not a requirement to approve each
future version number.

Finney advanced from runtime spec 455 to 458 on September 14, 2026. The
registration bridge deliberately holds when the finalized runtime differs
from the exact version in its signed policy. A running supervisor therefore
does not imply that it is refreshing weights.

The funding-policy parser accepts an explicitly signed choice of 455 or 458.
It does not discover or adopt a version automatically. A policy signed for 455
still fails on 458; changing that field without a new coordinator signature
also fails. Legacy policy body/1 remains restricted to 455.

## Review scope

The [upstream source comparison](https://github.com/opentensor/subtensor/compare/cae63cfa59d2b15330f335f3d71b9dd8e5707d14...90cfdca294c74e632ce1616dd8b09ca5bb8d1885)
contains security and accounting fixes, but no changes to subnet weight-setting
or epoch implementation files. The `SubtensorModule` storage-definition change
is documentation only; the dispatch-definition change is a comment on basket
staking. The runtime transaction version remains 1. This is a scoped bridge
compatibility review, not an audit of those upstream fixes or proof that an
arbitrary future runtime is compatible.

## Rollout requirements

Compatibility code alone does not restore submissions. Rollout requires:

- A tested worker release and matching host parser.
- A newly signed funding policy selecting runtime 458, with the existing funding
  snapshot, grouping rules, stop block 9,073,731 and hard sunset 9,075,171 retained.
- A signed successor to the current directive, without resetting its history.
- A wallet-free rehearsal against fresh finalized state in the production
  sandbox, followed by one-validator-at-a-time deployment.
- Finalized transaction and row readback for both validators before claiming
  restored weights. Miner incentive recovery requires a separate consensus read.

Keep original journals and locks, including any uncertain transaction. Never
edit a signed policy in place or bypass its runtime or finality checks.
