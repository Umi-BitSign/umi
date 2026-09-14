# Registration bridge runtime 458 compatibility

## Recovery snapshot, September 14, 2026

Both UMI-managed validators finalized rows under the replacement runtime-458
policy. At finalized block `9,067,513`:

| Validator | Finalized weight transaction | Row age | Positive destinations |
| --- | --- | --- | --- |
| UID 0 | `9067513-0015` | 0 blocks | 172 |
| UID 54 | `9067485-0027` | 28 blocks | 172 |

The rows match. Independent graph traversal of their retained health/roster
records reproduces 120 coldkey/IP/funding groups, each with a total raw weight
of `65535`, divided among its passing UIDs. The worker's
`eligible_coldkey_count` of 150 counts coldkeys, not reward groups.
The same finalized snapshot reports 172 non-validator UIDs with positive
consensus and incentive. It does not measure cash received or predict returns.

The [finalized readback and worker records](https://pub-bfe43425f6564cc98cb3ad43b9662ae3.r2.dev/validator-supervisor/registration-bridge/evidence/606404cdf4b883bb125293da328af149857671e684fc56269adefc3e963378ae/finalized-readback.json)
have SHA-256 `606404cdf4b883bb125293da328af149857671e684fc56269adefc3e963378ae`.
These are RPC reads pinned to one finalized block, without storage proofs;
the local health receipts are not independently signed.

The [signed replacement policy](https://pub-bfe43425f6564cc98cb3ad43b9662ae3.r2.dev/validator-supervisor/registration-bridge/policies/8b88a24262678903833ad608e8d81802ee4b4f568c740255f4a77f13b222242b/signed-policy.json)
selects release `809e384cc907f795b08e22fa882a214d7ab3ea53` and runtime 458.
Signed sequence 13 is published on the AMD64 and ARM64 shared feeds. The
release is a compatibility backport onto the previously deployed source; it
does not deploy the pending translation competition. Existing funding links,
eligibility rules and the stop/sunset blocks below are unchanged.

The compatibility PR passed all 18 CI checks. An isolated coordinator test run
passed 215 targeted tests, and both OCI release builds passed. The actual
production sandbox also passed a wallet-free live-roster rehearsal before the
one-validator-at-a-time rollout. Original journals, locks and wallet files
were retained.

This is a dated recovery record. Use the
[current-row diagnostic](REGISTRATION_BRIDGE_HEALTH.md) to check freshness.

## Incident

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
