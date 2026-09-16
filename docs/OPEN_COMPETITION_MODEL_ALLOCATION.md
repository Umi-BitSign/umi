# Unallocated model share: approved launch rule

On September 16, 2026, the operator approved 70% for qualifying endpoint
service and burning the unallocated 30% until a model qualifies for promotion.
This replaces the earlier requirement to have a rewarded model at activation.
The imported baseline remains unrewarded. There is no founding-model exception.
This document and the code change do not activate competition weights.

## Signed allocation and proof checks

Policy `umi-open-competition-policy/3` retains version 2's two-task scoring
profile and requires an explicit `unallocated_model_burn` containing the
destination UID, hotkey and `mode: Burn`. Version 1 and 2 policy bytes and
missing-recipient behavior remain unchanged.

Until there is a promoted contributor, the complete projected row includes
70% for qualifying endpoints, proportional to quality, and 30% for the verified
burn destination. Rounding uses the same exact-rational u16 projection.
Dropping the 30% from the row would redistribute it through normalization.

The registration provider proves `SubnetOwnerHotkey`, `RecycleOrBurn` and both
directions of the destination's UID/hotkey mapping at the same owned finalized
state root. The weight worker rechecks those claims before submission. An owner,
mapping or mode change holds the write. A caller-supplied UID or a JSON snapshot
alone is not a burn proof. The destination cannot also receive endpoint or
contributor rewards in this policy.

`RecycleOrBurn` may be absent from storage when its runtime default is `Burn`.
That requires a verified non-membership proof and decoding through the bound
runtime metadata. A missing RPC value alone is insufficient. Owner and UID
mapping claims still require membership; an optional or `Recycle` default is
rejected.

Subtensor withholds miner incentive directed to its registered subnet-owner
hotkey; in `Burn` mode it burns that incentive. This does not burn the separate
subnet-owner cut or validator dividends. See the
[runtime distribution code](https://github.com/opentensor/subtensor/blob/main/pallets/subtensor/src/coinbase/run_coinbase.rs).
The percentages describe this policy's weight allocation. Consensus, other
validator rows and the chain's burn-related emission adjustment determine the
actual economic result. Do not promise exactly 70% of a previous day's emission.

## First promotion

The approved target is a seven-day first contribution round. Publish the exact
admission and evaluation cutoffs in the signed launch configuration before
opening intake. That schedule and the real-model rehearsal remain launch gates.
Endpoint scoring may run while model submissions are collected.

Review the best-performing qualifying contributed artifact from that round.
An endpoint score alone does not supply model weights or redistribution rights.
Promotion still requires the preserved bundle, rights approval, reconstruction,
paired baseline comparison, minimum quality and per-stratum improvement gates.
If nothing qualifies, the 30% remains burned. No rewards accrue retroactively.

After a qualifying promotion, the 30% goes to the registered contributor under
the existing fresh-evaluation rules. If an awarded contributor later becomes
ineligible, the existing hold remains; this change does not silently revoke an
award or move its share elsewhere. A round without qualifying endpoint evidence
also remains held. Further fallback rules require a separate policy decision.

The adopted [version 1 contribution terms](MODEL_CONTRIBUTION_TERMS.md) are kept
byte-for-byte for existing acceptance hashes. This approved allocation rule is
an explicit signed-policy addition; it grants no additional rights over models.
