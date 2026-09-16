# Round coordinator and cutoff signing

The private coordinator prepares rounds from the current admitted roster and
collects cutoff signatures from independently operated evaluators. Each evaluator
rechecks the proposed registration snapshot through its own finalized-state
provider before signing. The coordinator has no wallet.

With the optional [work-signing configuration](OPEN_COMPETITION_WORK_SIGNING.md),
this service also generates endpoint authorizations and evaluation orders and
collects independent signatures before delivery. Optional
[settlement preparation](OPEN_COMPETITION_SETTLEMENT_PREPARATION.md) produces
unsigned proposals from complete retained evidence.
[Settlement delivery](OPEN_COMPETITION_SETTLEMENT_DELIVERY.md) connects those
proposals to independent signers and publishes verified replay packages.
Optional [reviewed promotion delivery](OPEN_COMPETITION_PROMOTION_DELIVERY.md)
applies explicitly approved model reviews to retained independent evidence and
delivers those decisions to evaluators through the same authenticated connection.
The service does not activate the 70/30 policy, change bridge weights or extend
the bridge sunset.

## Operator inputs

Prepare the existing intake store with the reviewed competition policy,
preserved incumbent and accepted submissions. Use a private configuration with
schema `umi-round-coordinator-config/1`:

- `policy_sha256` and `chain`: the same reviewed policy digest and owned-finality
  configuration. Proof collection must finish within 15 seconds.
- `state_directory`: durable coordinator journal, nonce database and process lock.
- `intake_directory`: the existing competition store.
- `plan_directory`: private, canonical `RoundPlan` JSON files, named
  `<suite-digest>.json`.
- `certificate_directory`: private output files named `<round-digest>.cutoff.json`.
- `replay_limits`: explicit `maximum_roster_bytes`, `maximum_evidence_bytes` and
  `maximum_certificate_bytes`. Roster and certificate limits cannot exceed 4 MiB.
- `no_weight: true`.
- Optional `settlement_directory`: private unsigned settlement proposals after
  evidence cutoff. This directory must be separate from all other state and
  delivery paths. See the [settlement guide](OPEN_COMPETITION_SETTLEMENT_PREPARATION.md).
- Optional `settlement_delivery`: signature-collection state, certificate/package
  output, explicit package limits and reviewed release identity. Requires
  `settlement_directory`; see the [delivery guide](OPEN_COMPETITION_SETTLEMENT_DELIVERY.md).
- Optional `work`: separate work state, reviewed per-suite assets, output
  directories, transport-bound finality and an explicit issue margin. See the
  [work-signing guide](OPEN_COMPETITION_WORK_SIGNING.md) and pass its transport
  policy through `--legacy-policy` when enabled.

All directories, including the finality provider's state, must be separate,
absolute and owned by the service user. Directories use mode `0700`; input files
use `0600`. Publish complete files by atomic rename. Symlinks, hardlinks and
group/world-readable inputs are rejected. Do not mount a wallet into this service.

Each plan has schema `umi-round-plan/1`, the committed private `suite` including
its references, and explicit block windows:

```text
not_before_block <= admission_close_by_block
                 < signing_close_block < evaluation_close_block
                 < reveal_block <= evidence_cutoff_block <= valid_through_block
```

Supply reviewed windows long enough for proof collection, independent signatures,
publication and execution. The policy's snapshot-age limit also bounds cutoff
signing. No default block schedule is a production authorization. A delayed plan
expires; the service never rewrites its deadlines or turns delay into miner fault.
Retained preparation is recovered with its original roster and windows after a
crash. Replacing a used plan creates a durable conflict hold.

### Seven-day contribution intake

The first contribution round targets seven days of intake. Its intake opening
and its roster-closing window are different times. `not_before_block` is the
earliest block at which the coordinator may **close the roster**, not the time
at which miners may start submitting. Once that block arrives, the coordinator
may prepare the round on its next successful poll; it does not wait until
`admission_close_by_block`. Set the earliest close at or after the announced
end of intake, with a bounded polling margin before the latest close.

For an intake opening at block `I` and evaluation ending at block `E`, an early
submission must remain valid through `E`. Check both:

```text
policy.maximum_submission_lifetime_blocks >= E - I
submission.valid_through_block >= E
```

The policy's own validity must cover the complete round, including reveal,
evidence cutoff and settlement. A larger lifetime cap does not extend existing
signed submissions. A miner with a shorter submission needs to sign and admit
a higher-sequence replacement before the roster closes. Publish these
requirements before intake; do not silently extend a signature's validity.

At a planning assumption of 12 seconds per block, seven days is 50,400 blocks.
The staged 7,200-block rehearsal lifetime cannot cover that intake plus its
evaluation window for an opening-day submission. Set the launch lifetime and
all cutoffs together. Block cutoffs are authoritative; wall-clock dates are
estimates. These figures are planning examples, not an activated schedule.

Round preparation excludes submissions that expire before evaluation ends,
even if they are still current at roster close. Such an exclusion is not a
failed translation or a zero-quality score. Do not advertise an admission
receipt alone as a guarantee of inclusion in the first round.

```sh
umi-competition --policy /ABSOLUTE/POLICY.json serve-round-coordinator \
  --config /ABSOLUTE/ROUND-COORDINATOR.json
```

The service binds loopback, default `127.0.0.1:8101`. Put authenticated transport
behind HTTPS at `POST /v1/competition/rounds`. The proxy must enforce the 16 KiB
request limit, reject compressed requests, and disable body logging and caching.
Request authentication is the named evaluator hotkey's short-lived signature;
there is no additional upload key. Responses contain no protected references.

## Independent evaluators

Set `round_coordinator_origin` to the credential-free HTTPS origin in each
[continuous evaluator](OPEN_COMPETITION_EVALUATOR.md) configuration. Each worker
uses its existing hotkey and its own finality provider. It compares the complete
exact-block registration snapshot, then rechecks freshness before reserving and
signing the cutoff. Merely trusting the coordinator's RPC response is insufficient.

Reservations and signatures persist in the worker's private `round-signing/`
journal. A failed initial proof leaves no signing reservation. A conflicting
proposal for a reserved sequence or suite is held across restart. Retried votes
reuse their exact signed bytes. The coordinator accepts a late retry only if it
already retained that same vote inside the original signing window.

Discovery pages contain at most four currently signable proposals. Expired rounds
remain stored for exact retry checks but do not precede new rounds in discovery.
New plans and plans whose admission window has opened are processed ahead of
archive maintenance. A failed proposal does not stop a worker attempting the
other proposals in its page.

The cutoff quorum uses distinct policy control groups and excludes evaluator
groups with a submission in that round. Two hotkeys under one administration
remain one group. The first valid certificate is retained unchanged; additional
votes do not rewrite it. The signature authenticates the cutoff statement, not
independently witnessed publication timing or permission to write chain weights.

## Capacity, operations and verification

Defaults are a five-second poll, 1,024 retained rounds, and 1 GiB of logical
journal data. Individual journal records are bounded at 16 MiB; a proposal is
bounded at 4 MiB. Two HTTP requests can occupy the service at once. SQLite
overhead, rollback files, certificates and the plan directory require additional
disk space and filesystem quotas. Capacity exhaustion preserves history and
holds new work. Never delete journals to make an old round current again.

The command emits bounded JSON poll summaries: `round_poll_complete` with an
owned finalized block and counts, or `round_poll_failed`. Exception details,
references and request bodies are not printed. Alert on repeated failures,
held plans, missed windows and capacity exhaustion. Shutdown joins the polling
task before closing the finality provider and releasing the instance lock.

Run coordinator, intake, exchange, dispatcher and evaluator commands under a
service manager with failure restart and rate limits. A terminated owned
observer now exits the parent service even when no work is queued. HTTP shutdown
drains requests before closing providers; journals are retained. A live observer
waiting for a head is not restarted by this check. Freshness and proof checks
continue to reject unusable observations. An active process alone does not prove
that the service has a fresh finalized head.

Tests cover owned snapshot disagreement, signing-window expiry, independent
hotkey signatures, quorum certificates, lost acknowledgments, crash recovery,
conflict retention, archive starvation, request replay and byte limits, and
shutdown cleanup. They use synthetic keys and an in-process HTTP transport.
The connected two-round rehearsal completes a promotion, restarts the coordinator
and both evaluators from their retained journals, and executes the next planned
window against the promoted incumbent. Its miner keeps running and discovers
the new assignments. Both 70/30 settlement packages and the original round's
frozen incumbent remain unchanged on retry. Production still requires a supply
of reviewed plans and protected suites; the coordinator does not create these
inputs or retime missed windows.
They do not establish public TLS operation, protected ASL quality, rights
approval or independent administration of production evaluators.
