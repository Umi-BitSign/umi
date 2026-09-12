# Registration bridge IP cap: September 12, 2026

The bridge now groups passing miners by shared coldkey or HTTPS endpoint IP.
Connections are transitive; changing ports does not create another group.
Each group receives the same total raw weight, split among its passing UIDs.

This replaces the earlier coldkey-only rule prospectively. It does not blacklist
UIDs, burn rewards, change registration or permits, or extend the bootstrap period.
Historical signed policies and submission journals retain their original meaning.

## Both-validator finalized readback

At finalized block **9,054,502**, observed at **2026-09-12 22:31:01 UTC**, both
validators had active rows matching their applied journals under the new policy:

`0x69c1b6a8a694e834abb5204d699ad0fc7d3102b900e25549f8a425ea75582ff9`

| Validator | Finalized call | Row age | Passing UIDs | Groups |
| --- | --- | --- | --- | --- |
| UID 0 | `9054496-0005` | 6 blocks | 61 | 18 |
| UID 54 | `9054465-0023` | 37 blocks | 60 | 17 |

Each group in either row had exactly **65,535 total raw weight**. The different
group counts reflect different health/roster snapshots, not different grouping
rules. The 19-coldkey cluster below had one group budget in each row: 1/18 of
UID 0's row and 1/17 of UID 54's row.

The [public readback](https://pub-bfe43425f6564cc98cb3ad43b9662ae3.r2.dev/validator-supervisor/registration-bridge/evidence/a38ef85667bdfecdf58d43cf5b1941bf16265cf8d68f517ca41ffe2715c27ad5/finalized-readback.json)
contains both exact rows, public chain values and worker journals with the signed
policy. Its SHA-256 is
`a38ef85667bdfecdf58d43cf5b1941bf16265cf8d68f517ca41ffe2715c27ad5`.
The RPC reads were pinned to one finalized block; this file is not a storage
proof, and the health receipts are not independently signed.

The last consensus update was still block **9,054,389**, before either new row.
Displayed incentive at this snapshot therefore did not yet establish the IP
cap's economic effect. Row shares are not a promise of payout shares.

## Canary readback

UID 54 submitted `9054465-0023` under the new policy. At finalized block
**9,054,470**, observed at **2026-09-12 22:24:35 UTC**, its row was five blocks old:

`0x9197a6e9947759d6e832854fa40bc0780e28c5efce3a0a739cae786b02020427`

The row had **60 positive-weight UIDs in 17 connected groups**. Every group had
exactly **65,535 total raw weight**. UIDs **71–87, 91 and 92**, sharing
`178.156.250.12`, therefore had **1/17 (5.88%)** of this row in total.
Their 19 different coldkeys no longer created 19 group budgets.

UID 0 was still on the old policy at that canary snapshot. The cluster retained
44.19% of UID 0's row and 44.58% of summed displayed incentive. A corrected
validator row does not instantly rewrite the previous consensus result or prove
a particular realized payout.

## Signed release

- Runtime source revision: `023ab99869ede537e3f590e5b2fddcc03dbf4554`.
- Python source-tree SHA-256:
  `ab0ce7daa58ad234667a18cd8693c9c92a6d76fb59cd0b5f85a06d147573faca`.
- [Signed policy](https://pub-bfe43425f6564cc98cb3ad43b9662ae3.r2.dev/validator-supervisor/registration-bridge/policies/c2c5b1e2cfca540cfa03773286a35ef40b3004da56d7db17f993aca38d25718b/signed-policy.json):
  `c2c5b1e2cfca540cfa03773286a35ef40b3004da56d7db17f993aca38d25718b`.
- Reward rule: `equal_live_coldkey_ip_groups/1`.
- Grouping rule: `registered_owner_or_https_ip_connected_components/1`.
- Policy valid from block `9,054,360`; submissions stop before `9,073,731`,
  hard sunset `9,075,171`, unchanged from the original bridge.
- AMD64 sequence 11 digest:
  `71a8690b7eea2d1bf0492f5f87ba6b3b88df8524a3b6745b2b6b407939616ec9`.
- ARM64 sequence 11 digest:
  `b7fb1532408bf5986fc6be0065b97fba0345d1a4cd93571e0d6e42b778496882`.

The [native AMD64 and ARM64 builds](https://github.com/Umi-BitSign/umi/actions/runs/34721282153)
passed. The broader runtime/profile/publication regression run passed 272 tests;
191 focused tests passed again after the final documentation edits.
[Full CI](https://github.com/Umi-BitSign/umi/actions/runs/34721915495) passed after
test-fixture and documentation corrections; that follow-up did not change runtime
source. The new worker also passed a wallet-free chain/health check in the
coordinator's production container sandbox.

Both host checkouts and their installed Python packages were updated. Updating
only a checkout is insufficient: these hosts use a non-editable installation.
The rollout retained original locks, directive checkpoints, worker journals and
keys. Source backups were retained. UID 54's initial restart exposed a missing
managed Python directory in staging; it was restored before proceeding. The
other validator remained running during each host intervention.
Both validators now follow the shared sequence-11 feed; UID 54 was returned
from the canary feed without changing its trust settings or accepted checkpoint.

## Limits and miner actions

Keep the existing chain-announced HTTPS `/healthz` online. No miner-side upgrade,
pilot signature, model, or manual opt-in is required for this cap.

IP grouping is not proof of machine or human identity. Independent miners on a
shared IP split one budget. Distinct coldkeys on distinct IPs can still form
multiple groups. Hostnames, reverse DNS and certificate names do not solve that.
The health endpoint is not authenticated to the hotkey, so copying someone else's
endpoint can dilute its group's share.

`eligible_coldkey_count` still counts distinct coldkeys, not connected groups.
The bridge is temporary availability weighting, not translation scoring or model
contribution rewards. The old `/api/v1/bootstrap-service` API describes the
retired pilot policy and cannot attest to this update.
