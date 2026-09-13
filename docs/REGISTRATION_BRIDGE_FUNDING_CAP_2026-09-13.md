# Registration bridge funding cap: September 13, 2026

Both UID 0 and UID 54 have finalized funding-grouped rows, verified against
their applied worker journals at block `9,055,700`.

The new rule connects passing miners by shared coldkey, HTTPS endpoint IP, or
a common recorded pre-registration sender in the signed policy. Every connected
group receives one equal raw-weight budget, divided among its passing UIDs.
It does not ban registrations or change the bridge deadline.

## Finalized readback

Observed at **2026-09-13 02:31:10 UTC**, finalized block **9,055,700**:

`0xc0b9bca699681043cc19b1c8b34434d6a02d70d9c980887311a35b68f60374da`

| Validator | Finalized call | Row age | Passing UIDs | Groups |
| --- | --- | --- | --- | --- |
| UID 0 | `9055683-0011` | 17 blocks | 73 | 28 |
| UID 54 | `9055667-0012` | 33 blocks | 74 | 27 |

Every group has exactly **65,535 total raw weight**. UIDs 71, 74 and 75 share
one budget; UIDs 72, 73, 76 through 87, 91 and 92 share another. Those 19
registrations therefore have 2/28 of UID 0's row and 2/27 of UID 54's row, not
19 budgets. Different health snapshots account for the row differences: UID 223
passed UID 54's probe and connected UIDs 107 and 236, but failed UID 0's probe.

The [public readback](https://pub-bfe43425f6564cc98cb3ad43b9662ae3.r2.dev/validator-supervisor/registration-bridge/evidence/3bec7e1727ec3043773636cd55ce80e088221316ef2fe67a664da904bf02f3bd/finalized-readback.json)
contains both exact rows, public chain values and worker journals with the signed
policy. SHA-256:
`3bec7e1727ec3043773636cd55ce80e088221316ef2fe67a664da904bf02f3bd`.
Policy signatures and funding-report bindings were checked locally, and a
separate graph traversal reproduced both complete rows and equal group budgets.
The RPC readback is pinned to one finalized block; it is not a storage proof.
The local health receipts are not independently signed.

The last consensus update was still block **9,055,469**, before either funding
row. Displayed incentives at this snapshot do not establish the new policy's
economic effect. Weight shares are not a promise of realized payout shares.

## Signed release

- Runtime revision: `06e2210a772f6c37d31f2e2f127a4f12c0d4fd84`.
- Python source-tree SHA-256:
  `ae87a9cc5f08013b2a367adf3699dde6d2b9e8a93e571088fa43f17a12d7b35d`.
- [Signed policy](https://pub-bfe43425f6564cc98cb3ad43b9662ae3.r2.dev/validator-supervisor/registration-bridge/policies/867546df0d3996f45f8d5808aeacb78736412668b62656bd66e315371c4cb423/signed-policy.json):
  `867546df0d3996f45f8d5808aeacb78736412668b62656bd66e315371c4cb423`.
- Reward rule: `equal_live_coldkey_ip_funder_groups/1`.
- Grouping rule:
  `registered_owner_or_https_ip_or_recorded_funder_connected_components/1`.
- [Funding report](https://pub-bfe43425f6564cc98cb3ad43b9662ae3.r2.dev/validator-supervisor/registration-bridge/funding/712d125240a5d5046950ee0c430adeb9f69a6f712a922cf19744bf81a5bd481d/report.json):
  `712d125240a5d5046950ee0c430adeb9f69a6f712a922cf19744bf81a5bd481d`.
- The snapshot binds 87 registrations at finalized block `9,055,538`, also the
  policy's start block. A binding must match UID, hotkey, coldkey and registration
  block; it is ignored after an identity change.
- AMD64 sequence 12:
  `f98cdbc2be73699cffd763707817a4f73609b1b68ba16e7f0d652213757e0181`.
- ARM64 sequence 12:
  `d4939209a6cd513b2a9e2035d2ef3d5f07b945e69afd934e630053061cdb25bd`.

The [native AMD64/ARM64 builds](https://github.com/Umi-BitSign/umi/actions/runs/34731871899)
and [full CI](https://github.com/Umi-BitSign/umi/actions/runs/34731817876) passed.
The 193 focused funding/bridge tests passed locally. The new worker passed a
wallet-free check in the production Podman sandbox at block `9,055,567`.

Both host source trees and their non-editable installed Python packages were
updated, one service at a time. Original locks, directive checkpoints, worker
journals and keys were retained. Both use the shared sequence-12 feed; UID 54
was returned from its candidate feed without resetting its checkpoint.
UID 0 encountered finality-observer and stale-head holds during the rollout.
Its retained receipt was reconciled on retry, without bypassing finality checks
or signing the same attempt again. Both journals are now in `applied` state.

## Automation and limits

One cached Taostats checker serves both validators. It starts API requests at
least 12.5 seconds apart and enforces a persistent 1,000-request lifetime cap.
Completed histories are reused; new registrations are detected automatically.
The key is not distributed to validators or miners. The free-tier API worked;
no validator funds were transferred.

New funding links still need a signed snapshot and directive refresh. Publishing
those refreshes is not automated by this release. Until a binding is published,
unknown registrations retain coldkey/IP grouping. API failure does not erase
an already signed snapshot.

Only complete indexer histories with one non-self sender add a funding edge.
Incomplete or multiple-sender histories do not. No shared-service exclusions
were configured in this first snapshot. Shared exchange withdrawal wallets can
group independent recipients: this cap does not prove common human ownership
or identify the transfer that paid a registration fee. Distinct funding sources
can still evade grouping. See the [rule specification](REGISTRATION_BRIDGE_FUNDING_CAP.md).

No miner-side upgrade is needed. Keep the chain-announced HTTPS `/healthz`
online under the [existing requirements](CURRENT_MINER_OPERATION.md). The
bridge still stops submissions before `9,073,731`, with hard sunset `9,075,171`.
It remains an availability bridge, not the planned 70/30 translation competition.
