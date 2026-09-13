# What SN78 miners should run now

## Temporary live-miner rewards

The [registration bridge](REGISTRATION_BRIDGE.md) replaces the frozen two-miner
pilot rule. It checks registered SN78 miners' HTTPS availability and gives each
qualifying coldkey/IP/funding group an equal total weight, divided among its passing UIDs.
It does not score translations or require a running model.

Both UMI validators, UID 0 and UID 54, have finalized bridge rows. See the
[funding-cap deployment record](REGISTRATION_BRIDGE_FUNDING_CAP_2026-09-13.md)
for the applied policy and exact rows. The earlier
[IP-cap readback](REGISTRATION_BRIDGE_IP_CAP_2026-09-12.md) is historical.
Inclusion in a row is not proof that a miner has already received a payout.

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
[funding-cap rule](REGISTRATION_BRIDGE_FUNDING_CAP.md).

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

The bridge stops new submissions before block `9,073,731`, with hard sunset at
`9,075,171`, unless replaced sooner. It retains the original bootstrap deadline.
See the [signed-policy specification and rollout evidence](REGISTRATION_BRIDGE.md).

## Later translation competition

UMI will publish the miner instructions and signed policy before asking miners
to serve translation requests or enter the model-contribution track. Translation
requests need the [protocol miner connected to a working model](MINER_MODEL_INTEGRATION.md).
A health-only keepalive cannot answer them.

## Reading payout dashboards

A submitted weight row, positive finalized miner incentive, validator dividends,
and subnet TAO inflow are different measurements. Check the UID, finalized block,
and field before attributing a displayed payment to this bridge. Registration and
hosting costs are not guaranteed to be recovered.

The old `/api/v1/bootstrap-service` endpoint describes the retired frozen-pilot
policy. It cannot attest to registration-bridge activation or current eligibility.
