# Temporary live-miner rewards

The temporary bridge has replaced the frozen two-miner pilot policy on UMI's
UID 0 and UID 54 validators. Both have finalized rows under the shared-coldkey-or-IP
rule. See the [IP-cap readback](REGISTRATION_BRIDGE_IP_CAP_2026-09-12.md) for the
signed policy and exact rows. At that snapshot, the new rows still awaited a
later consensus update. The [initial activation report](REGISTRATION_BRIDGE_ACTIVATION_2026-09-12.md)
records the earlier coldkey-only policy.

## Eligibility and weights

At each finalized snapshot, the validator considers the registered SN78 UIDs.
It checks each eligible miner's chain-announced public HTTPS `/healthz`
endpoint. Passing miners sharing a coldkey or HTTPS endpoint IP form one group,
including transitive connections. Ports do not create separate groups. Each
group receives the same total weight, divided among its passing UIDs.
UID 0, validator-permitted UIDs,
and subnet-owner-associated hotkeys receive zero
miner weight. There is no pilot requirement, manual opt-in, or model evaluation.

A passing endpoint returns HTTP 200 within five seconds, with a valid system-
trusted TLS certificate and a response no larger than 16 KiB. Redirects and
non-public or multicast destinations are rejected. One failed endpoint excludes
that miner from the current row, without disqualifying the healthy miners.
The validator rechecks the finalized roster after the health probes. A batch
failure or zero passing miners holds submissions instead of inventing a row.

Adding live UIDs under the same coldkey or IP does not create extra group
budgets. This is an infrastructure cap, not proof of independent operators.
Shared-IP miners split one budget; a person using distinct coldkeys and distinct
IPs can still create multiple groups.

A health check proves HTTPS reachability only. It does not authenticate the endpoint
to the hotkey, inspect an `ok` field in the response body, or establish that a
model is running. Reusing the same endpoint across multiple UIDs is possible
under this temporary rule. It does not measure translation quality or establish
useful model work. The chain's `Active` flag is not used as a substitute for an
endpoint check.

The exact row contains all 256 UID destinations, with positive integer weights
for passing miners and `0` for excluded destinations. Let `m` be the smallest
number of passing UIDs in any qualifying group. Each group receives an
integer budget of `65535 * m`. Divide that budget by the group's UID count;
assign any remainder one unit at a time in ascending UID order. Group totals
are exactly equal, every individual weight is at most `65535`, and at least
one weight is `65535`. This avoids changing the row through chain max-upscaling.

Registration, coldkey ownership, and permit changes are taken from finalized
chain state and checked again after the probes. A newly registered UID can enter a
subsequent row; inclusion is not an instantaneous payout guarantee.

Other validators' weights and subnet consensus can affect final incentive
amounts. The chain's miner incentives must be checked after a consensus
update; submitting a transaction alone is insufficient.

## Signed IP-deduplication update

The IP-cap policy selects `equal_live_coldkey_ip_groups/1`, paired with
`registered_owner_or_https_ip_connected_components/1`. Activation requires the
signed policy and a finalized row, not just updated source code. The earlier
coldkey-only policy keeps its original meaning in retained journals.

Under the new rule, passing UIDs sharing a coldkey **or** an HTTPS endpoint IP
form one reward group. Connections are transitive, and ports are ignored.
IPv4-mapped IPv6 addresses are grouped with the equivalent IPv4 address. Each
group receives the same total integer weight, split among its passing UIDs using
the allocation above. Failed endpoints and excluded registrations do not connect
groups. The `eligible_coldkey_count` status field remains a count of distinct
coldkeys, not a count of the resulting reward groups.

This caps the observed same-IP multiplier. It does not identify machines or
people: shared-hosting miners share a budget, and more coldkeys plus more IPs can
still create additional groups. Hostnames, reverse DNS and TLS certificate names
are not machine identities. Since health checks do not authenticate the endpoint
to a hotkey, copying another miner's announced endpoint can dilute that group's
share. No UID blacklist, penalty or burn is introduced.

The [IP-cap deployment record](REGISTRATION_BRIDGE_IP_CAP_2026-09-12.md) records
the signed release and finalized readback. The original deadline below is unchanged.

## Duration

The bridge retains the original bootstrap cutoff: no new submissions from
block `9,073,731`, with hard sunset at `9,075,171`. It may be superseded sooner
by the open-competition release. It does not silently extend the seven-day
bootstrap period.

## Miner actions

Existing eligible registrations need a healthy chain-announced public HTTPS
endpoint. Keep `/healthz` online; no running model is required for that check.
The certificate must be valid for the announced IP address, not just a separate
hostname. A self-signed certificate does not pass this check.
There is no pilot issue, READY FOR CASE signature, or model upload for this
bridge. Do not resume the retired pilot workflow. The later open competition
will have its own published serving and model-contribution requirements.

Registration costs, stake, and token value can change. Equal weights do not
guarantee a particular return or that registration costs will be recovered.

## Validator rollout

The bridge uses an explicit signed policy and the distinct worker profile
`umi-registration-bridge-validator/1`. It does not reinterpret the old pilot
manifest or pretend that registration satisfies a public-pilot proof.

The legacy supervisor needs the corresponding host parser/profile update
before it can accept this worker. Operators must not run two weight writers
for the same hotkey. The UMI-managed UID 0 and UID 54 installations were
updated one at a time, preserving their directive checkpoints and worker
journals. No coldkey was used.

The worker keeps its root filesystem read-only and `/tmp` non-executable.
The hash-checked native finality verifier is copied into a dedicated 64 MiB
in-memory executable staging mount at `/run/umi-finality`. This mount is private
to the worker and is not a host directory or a persistent data volume.

This first rollout targets those two existing UMI installations. A validator
with an old on-chain row but no UMI submission journal is held for reconciliation;
this release does not infer that an untracked previous writer has stopped.
Do not delete journals to bypass a hold or run a second process with the same
hotkey.

The old `/api/v1/bootstrap-service` endpoint describes the retired pilot
policy. Its status is not evidence for registration-bridge activation.
The [bridge activation report](REGISTRATION_BRIDGE_ACTIVATION_2026-09-12.md)
identifies the signed policy, exact validator rows, finalized blocks, and
consensus/incentive readback. It is a dated snapshot, not a live status API.
