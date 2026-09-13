# Registration-bridge health checks

Process health and current weights are separate checks. The retired
`/api/v1/bootstrap-service` response cannot attest to the registration bridge.
An old deployment receipt is historical evidence, not a current LastUpdate.

## Wallet-free chain check

With the repository's Python dependencies installed:

```sh
python -m umi.registration_bridge_status
```

This reads Finney once, using one RPC-reported finalized height for the chain
vectors and rows. It checks the known UID 0 and UID 54 hotkey mappings, permits,
nonzero rows, LastUpdate and the activity cutoff derived from the current factor
and tempo. It also reports how many UIDs have positive consensus and incentive.
No wallet, Taostats key, endpoint health probe or transaction is involved.

Exit 0 means both selected rows are fresh at that read. Exit 2 means an alert
or an unknown result; a timeout or stale RPC timestamp is never reported healthy.
The current activity test treats a row as stale when its age exceeds the cutoff.
A replaced hotkey is an alert even if its new row is fresh.

This diagnostic trusts RPC-reported finality. It does not verify GRANDPA, replay
the signed bridge policy or prove payout receipt. The production workers retain
their separate owned-finality and policy checks. Do not use this command's JSON
to authorize transactions or clear a worker hold.

On the coordinator, inspect bounded logs for each exact service:

```sh
sudo journalctl -u umi-validator@0.service --since '15 min ago' -o cat --no-pager
sudo journalctl -u umi-validator@54.service --since '15 min ago' -o cat --no-pager
```

`exact_row_active` and `weights_rate_limit_not_elapsed` can be normal waits.
Compare LastUpdate with the chain head before treating either as a fault.
`exact_bridge_row_finalized` records a worker-confirmed renewal. A miner becoming
validator-permitted is excluded individually by the registration bridge; it
does not invoke the retired frozen-pilot eligibility loop.

If rows become stale, retain the reason codes, current chain read and durable
attempt history. Diagnose the hold before stopping anything. Do not delete a
journal, bypass finality checks, restart old Studio writers or launch a second
writer for the same hotkey as a recovery shortcut.

## Readback after the reported stall, 2026-09-13

At finalized block **9,059,491**, the direct RPC diagnostic found:

| Validator | LastUpdate | Age | Nonzero row entries |
| --- | --- | --- | --- |
| UID 0 | 9,059,458 | 33 blocks | 106 |
| UID 54 | 9,059,459 | 32 blocks | 106 |

The activity cutoff was 360 blocks and the weight rate limit 100 blocks.
There were 105 UIDs with positive consensus and incentive at that snapshot;
new row inclusion and the next consensus update need not occur together.

The local applied journals recorded transactions `9059458-0017` (UID 0) and
`9059459-0011` (UID 54). Their policy digest remained
`867546df0d3996f45f8d5808aeacb78736412668b62656bd66e315371c4cb423`.
Both services remained running, with no restart or policy change during the check.
Recent retained logs included 56 successful renewals and no recurrence of the
old eligible-miner-mapping error. This establishes recovery/current activity at
the stated read; it does not disprove an earlier interruption or promise uptime.
