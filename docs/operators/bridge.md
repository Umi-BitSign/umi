[Documentation](../README.md) / Temporary registration bridge

# Temporary live-miner rewards

The registration bridge replaces the closed two-miner pilot. It checks endpoint
availability, not translation quality. The signed ongoing policy renews until
an explicit replacement or stop; older finite policies keep their original
expiry. Editing source does not extend a signed policy.

The temporary registration-snapshot freeze has been lifted. Current and
re-registered hotkeys can qualify after finalized registration and health checks.
Historical activation blocks, fee quotes and deployment digests are in the
[Git records](../reference/legacy.md); they are not current chain status.

## Eligibility

At a finalized snapshot, consider registered SN78 miners other than UID 0,
validator-permitted UIDs and subnet-owner-associated hotkeys. Probe each
chain-announced `https://IP:PORT/healthz` endpoint:

- HTTP 200 within five seconds and at most 16 KiB.
- System-trusted TLS certificate valid for the announced IP.
- No redirects, private or multicast destinations.

No pilot enrollment, signed readiness marker, opt-in or model upload is needed.
The body need not contain `ok`; a health response proves reachability only.
A hostname-only certificate does not meet the bridge's IP requirement.
Competition hostname support is a separate mechanism.

Recheck finalized registrations after probing. A changed hotkey, coldkey,
registration block, endpoint or permit excludes that entry for the current
row; new owner-associated keys are excluded too. Unchanged passing miners can
still receive weights. Changed registrations need a new health check on a later
pass. Retain both snapshots and original receipts when they differ.
An older worker without this churn-tolerant profile may hold the whole batch.
Never run an older parser over a newer journal.

A failed endpoint excludes that miner. Whole-batch failure, no passing miners,
unusable finality or an unresolved transaction holds submission. There is no
cached-row, self-weight or automatic burn fallback.

## Grouping and allocation

Passing miners sharing a coldkey, HTTPS endpoint IP or a recorded pre-registration
sender in the signed funding snapshot form a connected group. Connections are
transitive; ports are ignored; IPv4-mapped IPv6 and equivalent IPv4 group together.
Failed and excluded entries cannot connect groups. Each group gets equal total
raw weight, divided among its passing UIDs.

Let `m` be the smallest passing-UID count among groups. Each group gets an integer
budget of `65535 * m`. Divide by that group's UID count and distribute remainders
in ascending UID order. All 256 destinations are present; excluded entries are
zero. Each value is at most 65535 and at least one reaches 65535, avoiding an
unexpected max-upscaling change on chain.

Funding assertions bind UID, hotkey, coldkey and registration block, plus source
report and history hashes. A reused UID cannot inherit an old assertion. Only a
complete indexed history with one non-self sender adds a funding edge. Unknown,
incomplete and multiple-sender histories retain coldkey/IP grouping. Shared-service
senders can be excluded before signing. The [cached audit](funding-audit.md) detects
new registrations; adding funding links still requires a new signed snapshot.
Weight-writing validators and miners do not need a Taostats key.

This caps shared resources and senders; it does not prove operator identity or
which transfer paid a fee. Shared hosting, NAT and exchange withdrawal wallets
can group independent miners. Separate IPs, keys and senders can create multiple
groups. Copying another miner's endpoint can dilute that group's share. No /24
cap or UID blacklist is implied. This temporary rule is not a requirement of
the planned translation competition.

## Renewal and compatibility

`lifetime=until_superseded` in policy body version 3 has null submission and
sunset cutoffs. Historical version 1/2 expiry is unchanged. Compatible host and
worker releases and a newly signed directive are required to change profiles.
Signatures, rate limits, current permits, single-writer locks and exact finalized
receipt checks still apply. Keep all journals and update validators individually.

The bridge does not reject a runtime merely for a changed `specVersion`. Its
historical signed version field remains informational and must not be edited.
Actual mechanism count, weight version, commit-reveal settings, UID domain,
rate limit, tempo and activity cutoff are checked. An unsupported storage or
call change can still hold operation.

## Check current rows

With the project's dependencies installed:

```sh
python -m umi.registration_bridge_status
```

This wallet-free diagnostic checks the configured UID 0/54 mappings, permits,
rows and `LastUpdate` at one RPC-reported finalized height. Exit 0 means both
selected rows are fresh; exit 2 means alert or unknown. It does not independently
verify finality, authorize transactions, clear holds or prove payouts. For another
validator, obtain its public hotkey and inspect its own finalized row.

Process health is separate from weight health. `exact_bridge_row_finalized`
records a verified renewal. `exact_row_active` and `weights_rate_limit_not_elapsed`
can be normal waits; compare their block with the activity cutoff. The retired
`/api/v1/bootstrap-service` endpoint cannot attest to current bridge eligibility.

## Unknown submissions

`prior_submission_outcome_unknown` means a retained attempt has no confirmed
successful receipt. The current bridge worker holds indefinitely rather than
sending another transaction. It does not retain signed bytes, nonce and exact
era before submission, so elapsed blocks or matching weights alone do not supply
its missing recovery evidence. Restarting, deleting journals or reinstalling is
not a recovery procedure. Preserve state and obtain the bounded attempt details
from the [validator troubleshooting guide](../PERMANENT_VALIDATOR_SUPERVISOR.md#troubleshooting).

`receipt_returned` is different: a retained finalized receipt can be verified
against the chain and reconciled without another send. Neither state permits a
second writer for the same hotkey. Supervisor `durable_hold:false` describes only
the supervisor's state, not the worker's submission state.

The bridge retains bounded history: 512 MiB and 4,096 files. Monitor growth.
Exhaustion holds writes; deleting history to resume is unsafe. Registration and
healthy endpoints do not guarantee incentives or recovery of operating costs.
