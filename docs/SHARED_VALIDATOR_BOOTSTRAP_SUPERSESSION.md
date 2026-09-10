# SN78 shared-validator bootstrap supersession

Status: signed release artifacts published; awaiting the first finalized matching row

Scope: Finney SN78, MechId 0, `bootstrap_service_binary`

This document replaces the validator authorization, submission, renewal, and
result-upload procedures in the earlier bootstrap documents. The frozen miner
eligibility decision, exact 256-entry row, owner fence, and hard sunset remain
unchanged.

The current bootstrap inputs are one frozen coordinator-signed eligibility
manifest and one coordinator-signed common lease. The lease binds the manifest
and policy hashes, exact UMI revision, required chain tuple, activity cutoff,
renewal margin, and hard sunset. It permits any hotkey that currently holds an
SN78 validator permit to submit the manifest's exact row. The worker checks the
permit and local hotkey mapping against finalized chain state before each write.

The row contains exactly UIDs `0..255`. Each miner selected by the signed
manifest receives raw weight `65535`; every other UID receives `0`. Zero entries
remain in the encoded call. The temporary owner fence remains:

```text
WeightsVersionKey = 4294967296
MinAllowedWeights = 256
CommitRevealWeightsEnabled = false
```

This is a binary endpoint-service row. It does not contain translation scores,
activate UMI translation weights, or satisfy a Section 14 activation gate.

## Shared release channel

Validators use the
[permanent validator supervisor](PERMANENT_VALIDATOR_SUPERVISOR.md); the simple
bootstrap worker is an internal signed-container entrypoint, not a standalone
operator path. They install the supervisor once. Its local
configuration names the operator's existing wallet root, hotkey name, public
hotkey, and platform. A common signed directive uses
`validator_scope: "any_permitted_sn78"` and an empty `validator_hotkeys` list.
The common authorization never overrides the live permit check or the local
wallet binding.

Each accepted update is monotonic and coordinator-signed. It selects an
immutable, hash-pinned release and one canonical input bundle. For this profile,
the bundle schema is
`umi-validator-supervisor-simple-bootstrap-input-bundle/1` and contains exactly
the signed manifest and signed lease. The release profile is
`umi-simple-bootstrap-validator/1`; the supervisor maps it to a fixed entrypoint
and arguments. Directives cannot supply a shell command or arbitrary runner
arguments.

The supervisor selects the signed release for the validator's local platform.
It verifies the directive chain, input bundle, release manifest, source revision,
and OCI digest before starting a worker. A release that fails any check is not
started.

The installed local policy accepts the typed UMI hold, bootstrap, inactive-shadow,
and translation modes. A later signed immutable release can therefore replace the
bootstrap worker on the same channel without another host migration. The fixed
profiles do not give a directive arbitrary command, argument, or mount control.

Enabling this channel delegates release selection to its configured signing
authority. A signed worker can use the isolated validator hotkey for calls that
the chain permits. The container cannot read the coldkey, another wallet, the
supervisor's control state, or host paths outside its fixed mounts. Signatures and
hashes authenticate a release; they do not prove that its code is harmless.

The release channel requires no coldkey, coordinator wallet, private UMI API,
validator-specific transition authorization, or result-upload credential. The
worker receives only the isolated validator hotkey tree needed to sign its own
SN78 calls.

## Submission and renewal

The worker independently verifies the signed inputs and current finalized SN78
state. It anchors the exact manifest hash under its own hotkey, replays the
eligible public pilots, checks their announced endpoints, and submits only the
full row defined above. It verifies the stored row and `LastUpdate` after
finalized inclusion.

The worker renews the same row before the effective 360-block activity cutoff.
It stops before the signed hard sunset. It records uncertain transactions in a
durable local journal and reconciles them from finalized state before another
submission. A foreign validator's different row is reported as a warning; it
does not change this validator's authorized row.

The simple-bootstrap worker hard-pins the manifest hash, policy hash, chain tuple,
and sunset in both code and its signed lease. A later directive cannot extend or
change this bootstrap campaign.

## Public receipt

Finalized chain state is the receipt. For every participating validator, an
auditor can read its current permit, manifest commitment, exact MechId 0 row,
and `LastUpdate`. The observer validates the signed manifest and lease, then
reports every currently permitted validator whose finalized row is the exact
authorized 256-entry row.

No validator-uploaded terminal bundle is required for this shared bootstrap
profile. Local supervisor status and journals are diagnostic records. They do
not replace the finalized chain observation.

Public status may set `service_weights_active: true` only while at least one
currently permitted validator has the exact row active under the signed lease
and required chain tuple. It must continue to report:

```json
{
  "translation_weights_active": false,
  "service_weights_active": true,
  "service_weight_kind": "bootstrap_service_binary",
  "section_14_gate_credit": false
}
```

## Precedence

This document supersedes these earlier procedures:

- target-specific transition authorizations in
  [EMERGENCY_DIRECT_BOOTSTRAP_CUTOVER_V1.md](EMERGENCY_DIRECT_BOOTSTRAP_CUTOVER_V1.md);
- raw CRv4 submission and per-validator terminal publication in
  [BOOTSTRAP_WEIGHT_ADDENDUM.md](BOOTSTRAP_WEIGHT_ADDENDUM.md) and
  [BOOTSTRAP_WEIGHT_OPERATOR.md](BOOTSTRAP_WEIGHT_OPERATOR.md);
- the UID 200 renewal controller in
  [BOOTSTRAP_RENEWAL_OPERATOR.md](BOOTSTRAP_RENEWAL_OPERATOR.md); and
- the validator result-upload intake in
  [BOOTSTRAP_RESULT_INTAKE.md](BOOTSTRAP_RESULT_INTAKE.md).

Those documents remain historical records for the frozen eligibility policy,
owner fence, legacy-state drain, and hard-sunset decision. If an operational
instruction conflicts with this document, this document controls the temporary
shared-validator bootstrap release.
