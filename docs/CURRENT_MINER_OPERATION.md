[Documentation](README.md) / Miners

# What SN78 miners should run now

For endpoint competition, use the [current connection guide](miners/connection.md).
An accepted receipt can carry forward while the running miner still needs a
configuration update. That guide owns the release, policy and download details.
The temporary bridge described below remains the current reward mechanism.

## Temporary live-miner rewards

The [registration bridge](operators/bridge.md) replaces the frozen two-miner
pilot rule. It checks registered SN78 miners' HTTPS availability and gives each
qualifying coldkey/IP/funding group an equal total weight, divided among its passing UIDs.
It does not score translations or require a running model.

The temporary registration-snapshot freeze has been lifted. New and re-registered
hotkeys can qualify after finalization and health checks. Check the current
registration quote before paying; registration does not guarantee rewards.

Use the [current-row diagnostic](operators/bridge.md#check-current-rows) for
freshness. Historical deployment reports do not establish current incentives,
and inclusion in a row is not proof of a received payout.

## Miner requirements

- Keep your SN78 hotkey registered and its public IP and port announced on chain.
- Serve `https://ANNOUNCED_IP:ANNOUNCED_PORT/healthz` with HTTP 200 within five
  seconds. The response must be at most 16 KiB, with no redirect.
- Use a system-trusted TLS certificate valid for the announced IP address.
  A certificate for a separate hostname or a self-signed certificate is insufficient.
- Your UID must have no validator permit. UID 0 and subnet-owner-associated
  hotkeys are excluded from miner weights.

A lightweight HTTPS keepalive can pass this check. There is no new pilot issue,
READY FOR CASE signature, opt-in, model upload, or manual enrollment. The timed
pilot is closed. Previous pilot participation is not required.

Validators refresh the roster and health checks before writing. A new or repaired
endpoint can qualify in a later row. A failed endpoint gets zero weight for that
row; it does not block other healthy miners. A whole-batch failure holds the
submission. Chain consensus and other validators' rows determine actual incentives,
so passing a health check does not guarantee an immediate or fixed payout.

## How weights are shared

Passing UIDs sharing a coldkey, HTTPS endpoint IP, or a common recorded
pre-registration sender in the signed funding snapshot form one group.
Connections are transitive and ports are ignored. Each group gets the same
total raw weight, split among its passing UIDs. See the
[funding-cap rule](operators/bridge.md).

This does not prove human or machine identity. Shared hosting or NAT can group
independent miners together. Shared exchange withdrawal wallets can also group
independent recipients. Unknown or multiple-sender funding histories add no
funding link. Different coldkeys, IPs and funding sources can still make multiple
groups, and copying another miner's endpoint can dilute its group.
HTTPS reachability does not prove endpoint ownership or translation quality.

The cached funding checker detects new registrations automatically. Adding new
funding links to rewards still requires a signed snapshot refresh. Until then,
new registrations use the existing coldkey/IP rules and cannot inherit a reused
UID's old funding assertion. Miners do not need a Taostats API key.

The ongoing bridge policy renews weights until an explicit replacement is
activated. This requires the signed version3 lifetime policy; historical
version1/2 policies retain their original cutoffs. A code update alone does not
extend an old signed policy.
See the [signed-policy specification and rollout evidence](operators/bridge.md).

## Open translation-competition intake

The [version 0.2 successor design](../whitepaper/README.md) supports self-service
endpoint participation and a reproducible-model contribution track. Public C5
intake does not replace the bridge or activate competition weights by itself.
Check [public status](https://api.umi.vision/v1/competition/status) and
[readiness](https://api.umi.vision/v1/competition/readiness) for the active
cohort, accepted tracks and current admission state. C5's published phase blocks
are nominal progression targets, not non-extendable deadlines. Liveness delays
retain and extend unfinished work and do not advance it to C6. Acceptance does
not guarantee selection, a score or a reward.
Admitted submissions must remain valid through evaluation close, and the hotkey
must be registered on SN78 in the finalized roster-close snapshot. The
[connection guide](miners/connection.md) identifies accepted predecessor
policies and the configuration needed to serve current requests.

Current C5 intake uses version 3 contribution terms. Earlier receipts do not
accept the new policy or terms; sign and retain a fresh C5 submission and cohort
consent through the live submission path.

Translation requests need the
[protocol miner connected to a working model](miners/model.md#miner-model-integration).
A health-only keepalive cannot answer them. Use the exact live policy and
[submission procedure](reference/commands.md#live-first-round-intake). Keep the
saved `accepted_no_weight` receipt; it establishes admission only, not quality or
earnings.

The [current connection guide](miners/connection.md) provides the signed feed settings,
exact release and tested configuration changes. Assignments follow the finalized
roster and published work authorization. Readiness does not establish a completed
live cohort. Before a miner has a published assignment, even a correctly signed
feed query can return 401. That response alone does not invalidate its receipt. A
coordinator, feed or evaluator infrastructure delay cannot count as miner
failure.

The open-competition endpoint path supports
[hotkey-signed HTTPS hostnames as well as literal IPs](miners/model.md#miner-endpoint-hostnames).
That support does not change the current bridge's IP-certificate requirement or
make a hostname-only keepalive eligible for bridge rewards.

Public C5 endpoint and model intake is open. C5 uses 50% service / 50% model
rewards; C6 accepts only complete
public-model entries and assigns that track 100%; C7-C10 return to 50/50. All use a
baseline-or-better quality requirement for complete accepted model entries.
Exact copies count once; eligible models then compete for one credit in each
occupied fixed five-percentage-point quality band. Read the [model preparation
checklist](contributors/models.md#model-contribution-review) and use the exact
terms named by the signed policy. C4's signed 70/30 allocation and
[version 2 terms](MODEL_CONTRIBUTION_TERMS_V2.md) remain applicable to C4
verification; its unallocated model share is burned and does not accrue. Terms
alone do not approve an individual model's rights or award it a share. Endpoint
service does not require contributing private weights.

## Reading payout dashboards

A submitted weight row, positive finalized miner incentive, validator dividends,
and subnet TAO inflow are different measurements. Check the UID, finalized block,
and field before attributing a displayed payment to this bridge. Registration and
hosting costs are not guaranteed to be recovered.

The old `/api/v1/bootstrap-service` endpoint describes the retired frozen-pilot
policy. It cannot attest to registration-bridge activation or current eligibility.
