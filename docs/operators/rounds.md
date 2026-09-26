[Documentation](../README.md) / Schedule and authorize rounds

# Schedule and authorize rounds

- [Round coordinator and cutoff signing](#open-competition-round-coordinator)
- [Round preparation](#open-competition-round-preparation)
- [Continuous cohorts and schedule amendments](#continuous-cohorts-and-schedule-amendments)
- [Automatic work proposals and independent signing](#open-competition-work-signing)
- [Recoverable cohort admission](#recoverable-cohort-admission)

<a id="open-competition-round-coordinator"></a>

## Round coordinator and cutoff signing

The private coordinator prepares rounds from the current admitted roster and
collects cutoff signatures from independently operated evaluators. Each evaluator
rechecks the proposed registration snapshot through its own finalized-state
provider before signing. The coordinator has no wallet.

With the optional [work-signing configuration](rounds.md#open-competition-work-signing),
this service also generates endpoint authorizations and evaluation orders and
collects independent signatures before delivery. Optional
[settlement preparation](settlement.md#open-competition-settlement-preparation) produces
unsigned proposals from complete retained evidence.
[Settlement delivery](settlement.md#open-competition-settlement-delivery) connects those
proposals to independent signers and publishes verified replay packages.
Optional [reviewed promotion delivery](promotion.md#open-competition-promotion-delivery)
applies explicitly approved model reviews to retained independent evidence and
delivers those decisions to evaluators through the same authenticated connection.
The service does not activate the 70/30 policy, change bridge weights or extend
the bridge sunset.

<a id="open-competition-round-coordinator--operator-inputs"></a>

### Operator inputs

Prepare the existing intake store with the reviewed competition policy,
preserved incumbent and accepted submissions. Use a private configuration with
schema `umi-round-coordinator-config/2`:

- `policy_sha256` and `chain`: the same reviewed policy digest and owned-finality
  configuration. Proof collection must finish within 15 seconds.
- `public_launch`: the exact public launch identity and sorted eligible tracks
  advertised by intake. Version 1 describes one round; version 2 adds continuous
  intake with an explicit `round_stride_blocks`. The store rejects omission or
  unauthorized replacement of its bound identity.
- `state_directory`: durable coordinator journal, nonce database and process lock.
- `intake_directory`: the existing competition store.
- `submission_head_checkpoint_directory`: the exact external checkpoint directory
  used by the intake service and the writer-generation cutover. The coordinator
  will not open the retained intake database without that matching fence.
- `plan_directory`: private, canonical `RoundPlan` JSON files, named
  `<suite-digest>.json`.
- `certificate_directory`: private output files named `<round-digest>.cutoff.json`.
- `replay_limits`: explicit `maximum_roster_bytes`, `maximum_evidence_bytes` and
  `maximum_certificate_bytes`. Roster and certificate limits cannot exceed 4 MiB.
- `no_weight: true`.
- Optional `settlement_directory`: private unsigned settlement proposals after
  evidence cutoff. This directory must be separate from all other state and
  delivery paths. See the [settlement guide](settlement.md#open-competition-settlement-preparation).
- Optional `settlement_delivery`: signature-collection state, certificate/package
  output, explicit package limits and reviewed release identity. Requires
  `settlement_directory`; see the [delivery guide](settlement.md#open-competition-settlement-delivery).
- Optional `work`: separate work state, reviewed per-suite assets, output
  directories, transport-bound finality and an explicit issue margin. See the
  [work-signing guide](rounds.md#open-competition-work-signing) and pass its transport
  policy through `--legacy-policy` when enabled.

All directories, including the finality provider's state and the external
checkpoint, must be separate, absolute and owned by the service user. The
checkpoint must be shared with every process that opens this intake database,
but must not overlap any component state tree. Directories use mode `0700`;
input files use `0600`. Publish complete files by atomic rename. Symlinks,
hardlinks and group/world-readable inputs are rejected. Do not mount a wallet
into this service.

Each plan has schema `umi-round-plan/2`, the committed private `suite` including
its references, the complete `public_schedule`, the sorted `eligible_tracks`,
and duplicated scalar windows that must equal that schedule exactly:

```text
intake_opened_block < not_before_block <= admission_close_by_block
                    < signing_close_block < evaluation_close_block
                    < reveal_block < evidence_cutoff_block < valid_through_block
```

### Continuous cohorts and schedule amendments

A version 2 public launch keeps intake open after the first roster closes.
Its matching intake deployment uses schema `umi-competition-intake-deployment/3`.
For cycle `n`, add `n * round_stride_blocks` to every first-round schedule block
except `intake_opened_block`. That opening remains fixed. Each plan must match
one of these complete derived schedules; changing only a deadline is rejected.
The stride must exceed the first evidence window. Reward validity may overlap
the next cycle so a completed round can remain effective during later scoring.

Each cycle freezes the latest accepted, still-valid submission per hotkey and
track at its finalized registration snapshot. Subsequent admissions and
replacements cannot change an already frozen roster. They are available to the
next cycle; miners must keep any previously selected endpoint/model available
through its evaluation deadline. An unchanged submission can remain eligible
across cycles until it expires, is replaced, or its hotkey loses registration.
The policy interval, admission limits and replacement rate limit still apply.

Public status retains the first schedule and reports `continuous_intake` plus
`next_intake_schedule`. The latter uses the guaranteed cutoff, not the later
coordinator polling margin. Admission receipts remain `accepted_no_weight`:
they do not prove scoring or finalized competition rewards. Continuous intake
also does not create private test cases. Operators must supply each cycle's
fresh reviewed suite, delivery assets and capacity-qualified plan before its
window. A missing or failed coordinator cycle is not a miner failure.

To accelerate an unused version 1 first cohort, publish a
`umi-competition-launch-amendment/1` signed by the current policy's evaluator
quorum. It binds the previous launch digest, the complete continuous replacement,
an effective block and reason `accelerate_first_cohort_continuous_intake`.
It cannot change the policy, tracks, intake opening or accepted submission bytes.
It cannot retime a prepared round or a used suite. Publish the signed miner feed
profile and tested command with operating lead time before the new cutoff.

Stop the intake database writers briefly and back up both the database and its
external checkpoint. With the replacement service configuration, use the
existing migration command's `--launch-amendment` and
`--amendment-observed-block` options alongside `--confirm-quiesced-backup`.
The observed block must come from the owned finalized-registration verifier and
fall between the amendment's effective block and new guaranteed cutoff.
The migration appends the authorization and launch identity, preserves all
receipts, and advances the independent checkpoint. Restart writers with the
replacement identity and without migration options. Verify unchanged receipt
commitments and the public `/v1/competition/launch-amendments` response before
announcing the revised schedule as applied.

An ordinary restart cannot amend the schedule. Do not edit the SQLite binding,
delete a checkpoint, replace a used plan, or change the live policy's reward
rules as part of a schedule amendment.

Supply reviewed windows long enough for proof collection, independent signatures,
publication and execution. The policy's snapshot-age limit also bounds cutoff
signing. No default block schedule is a production authorization. A delayed plan
expires; the service never rewrites its deadlines or turns delay into miner fault.
Retained preparation is recovered with its original roster and windows after a
crash. One public schedule can create only one round. Replacing or reusing it
creates a durable conflict hold.

<a id="open-competition-round-coordinator--seven-day-contribution-intake"></a>

#### First-round endpoint intake

The first endpoint round targets seven days of intake. Model-artifact intake is
not open for this round. Its intake opening
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

For the live first round, endpoint intake was observed at block `9,085,463`.
Block `9,135,843` is the guaranteed participant submission and replacement
deadline for admissions on or after that opening block. The coordinator may
close the roster at any subsequent poll through
the final operator bound, block `9,135,903`. An acceptance after the guaranteed
deadline is not guaranteed first-round inclusion. Evaluation closes at block
`9,156,243`. A submission also requires its hotkey to remain registered on SN78
in the finalized roster-close snapshot.

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

<a id="open-competition-round-coordinator--independent-evaluators"></a>

### Independent evaluators

Set `round_coordinator_origin` to the credential-free HTTPS origin in each
[continuous evaluator](evaluation.md#open-competition-evaluator) configuration. Each worker
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

<a id="open-competition-round-coordinator--capacity-operations-and-verification"></a>

### Capacity, operations and verification

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
drains requests before closing providers; journals are retained. The durable
observer also recovers a silent follow-stream timeout: it reaps the old process
and restarts from the last retained head, with interruptible backoff from one to
30 seconds. Competition providers use a follow-stream timeout of 15 seconds or
half their configured head-age limit, whichever is shorter. This accounts for
publication journals' stricter 60-second freshness check as well as head age and
restart time. Initial bootstrap has its own allowance. Invalid evidence and store
faults remain terminal. Recovery never invents missing ancestry or makes stale heads usable.
An active process alone does not prove that the service has a fresh finalized
head. This describes the source implementation; installed services need the
corresponding qualified release to acquire new recovery behavior.

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


<a id="open-competition-round-preparation"></a>

## Round preparation

These are internal coordinator APIs. They produce unsigned inputs for the
existing cutoff-publication contract. They do not schedule protected data,
collect quorum signatures, publish evaluator orders or authorize weights.

<a id="open-competition-round-preparation--one-finalized-snapshot"></a>

### One finalized snapshot

`FinalizedRegistrationProvider.collect_at(height)` rechecks complete SN78
membership at a recent exact height. A coordinator and an independent evaluator
can therefore compare the same snapshot even when their latest heads differ.

The historical header must already be in the caller's owned finality verifier.
The method verifies its header/evidence binding, pinned runtime, storage proofs
and inverse UID mapping. Both the current head and the requested snapshot must
pass the existing wall-clock freshness checks; the requested height must also
fit the policy's snapshot-age limit. It never accepts a header supplied by the
coordinator as finality evidence.

Historical reads retain their own evidence without replacing the latest intake
snapshot or lowering the persistent head guard. Exact-block reads reprove
membership even if that height was captured earlier. Existing caches remain
usable, and their highest captured block still prevents rollback.

<a id="open-competition-round-preparation--atomic-roster-and-cutoff"></a>

### Atomic roster and cutoff

`CompetitionStore.prepare_round(...)` takes that registration snapshot, the
private evaluation suite, explicit evaluation/reveal/cutoff/expiry blocks and
publication byte limits. In one SQLite transaction it:

- Selects the latest accepted submission for each current hotkey and track.
  A submission must remain valid through evaluation close. An expired
  replacement never revives an older submission.
- Excludes hotkeys no longer registered at the supplied snapshot. Their earlier
  admission records remain intact.
- Reads the preserved, unconflicted incumbent and assigns the next round sequence.
- Fixes the evidence cutoff and freezes the complete selected roster at the
  snapshot block, then retains the unsigned cutoff publication and signed
  submission bodies.

The caller must obtain the snapshot from its owned provider. The store itself
cannot verify finality. Its output remains `chain_submission_authorized: false`
and contains no protected references or evaluator signatures.

A submission racing the freeze is either included in that round or explicitly
rejected at the closed admission boundary. It can be submitted in a later block
for a later round. Concurrent preparations cannot freeze different rosters at
the same boundary.

The suite digest identifies an exact retry. Restarting or retrying later returns
the original preparation, including its original deadlines. Changing those
deadlines for the same suite is rejected. The eventual publisher must check
that sufficient time remains before signing or dispatching; an old preparation
does not become timely because it was retrieved again.

`RoundPreparationCapacity` bounds retained preparations (default 1,024 records
and 1 GiB of preparation bodies). Publication byte limits are checked before
reading a large roster into memory. A storage or byte-limit failure rolls back
the cutoff, round and suite reservation together. It does not remove earlier
preparations. Ordinary admission and existing proof-cache limits still apply.

<a id="open-competition-round-preparation--remaining-integration"></a>

### Remaining integration

The [continuous coordinator](rounds.md#open-competition-round-coordinator) now consumes
private plans, calls these APIs and obtains independent cutoff signatures.
Operators still supply fresh protected suites and reviewed round windows.
The work-signing configuration below connects order signing and delivery to the
exchange. Completed rounds then need signed settlement publication and successor
input materialization. These internal methods do not change the live bridge policy.


<a id="open-competition-work-signing"></a>

## Automatic work proposals and independent signing

The round coordinator can derive endpoint authorizations and evaluation orders
from a retained quorum cutoff. Evaluators discover the proposals, check their
own cutoff reservations and current finalized state, and sign the exact bodies.
The coordinator publishes only after the nominated independent groups agree.
Neither the coordinator nor the exchange has a wallet.

This connects round preparation to the existing dispatcher and evaluator inboxes.
It does not publish settlements, approve model rights, activate rewards, or
change the live registration bridge. The imported baseline still has no
contributor attribution.

<a id="open-competition-work-signing--coordinator-configuration"></a>

### Coordinator configuration

Add `work` to the private `umi-round-coordinator-config/2` configuration:

| Field | Purpose |
| --- | --- |
| `state_directory` | Work intents, signatures, certificates, nonce store and finalized high-water mark |
| `asset_directory` | Private per-suite `RoundWorkAssets` files |
| `order_directory` | Exact signed orders consumed by the evaluator exchange |
| `publication_directory` | Exact signed endpoint authorizations |
| `transport_chain` | A separate owned-finality configuration bound to the same competition policy |
| `legacy_policy_sha256` | Digest of the reviewed endpoint transport policy |
| `minimum_issue_ms` | Explicit signing/publication margin before the transport issue deadline |

All these directories and both observers' state directories must be separate,
absolute, owned by the service user and mode `0700`. Files use mode `0600`.
The transport observer must use the transport policy's actual chain and verifier
pins; its collection timeout cannot exceed 15 seconds. The issue margin is an
integer from 1 through 300,000 ms and must be shorter than the transport policy's
issue allowance when endpoint work is prepared. Choose it to cover observed
signing and delivery latency. An undersized margin does not extend a deadline.

Creating a proposal requires a fresh owned issuance block. Endorsing an existing
proposal instead requires a fresh owned head and verified historical issuance
and announcement blocks from that same provider. The signer reconstructs the
original request unchanged and checks that its original issue window still has
the required margin. A delayed endorsement does not retime issuance, deadlines
or the evaluation window. Stale heads and expired issue windows remain holds.

Each canonical `<suite-digest>.json` asset file has schema
`umi-round-work-assets/1`, `suite_sha256`, the full `incumbent` bundle,
the pinned CPU `runtime`, and one `Video` descriptor per suite case, in the
same order. Video hashes and sizes are checked against the suite projection
and runtime limit. These are reviewed inputs, not values generated by the
service. Keep the private suite and its references in the existing round plan.

For ongoing model promotion, use `umi-round-work-assets/2` with the same fields
except `incumbent`, which must be omitted. This requires the coordinator's
[reviewed promotion delivery](promotion.md#open-competition-promotion-delivery) configuration.
The coordinator reads the manifest from that preserved archive by the exact
incumbent digest frozen in the round. New rounds therefore follow the approved
promotion history without rewriting future asset files or restarting services.
Already frozen rounds keep their original incumbent, including after restart.
No current-head alias or miner-supplied download URL is used.

Missing, noncanonical or mismatched manifests hold work. The coordinator reads
manifest metadata; each evaluator still verifies the model bytes before running
them. Schema v1 remains supported with its explicit incumbent binding. Neither
format approves a model or changes the protected suite or signed deadlines.

```sh
umi-competition --policy /ABSOLUTE/POLICY.json serve-round-coordinator \
  --config /ABSOLUTE/ROUND-COORDINATOR.json \
  --legacy-policy /ABSOLUTE/TRANSPORT-POLICY.json
```

Use the same `order_directory` in the wallet-free
[evaluator exchange](exchange.md#open-competition-exchange). Each evaluator's exchange
client delivers the signed order into its local inbox and the enclosed endpoint
authorization into its dispatcher's publication inbox. The dispatcher's existing
origin proof, discovery grace and request-window checks still apply.

<a id="open-competition-work-signing--evaluator-configuration"></a>

### Evaluator configuration

In each [continuous evaluator](evaluation.md#open-competition-evaluator), configure:

- `round_coordinator_origin`: the credential-free HTTPS origin for both cutoff
  and work discovery.
- `work_signing_chain`: a dedicated transport-bound owned observer, with its
  own separate state directory and collection timeout at most 15 seconds.
- `work_minimum_issue_ms`: the same reviewed issue margin as the coordinator.
- The existing endpoint `legacy_policy_sha256` and `dispatch_directory`, plus
  that exact transport policy passed to `run-evaluator`.
- `exchange_origin` and `assignment_directory` for automatic signed-order and
  endpoint-authorization delivery.

No extra API credential or manual signature upload is needed. The worker uses
only its configured hotkey. Work signing has a separate `work-signing/` journal
inside evaluator state. Its policy, signer, transport policy and issue margin
are bound across restarts. Existing configurations that omit the new fields
remain valid; adding or changing bound inputs is not an in-place journal reset.
Preserve existing state and use the reviewed migration procedure for deployed
services.

<a id="open-competition-work-signing--selection-deadlines-and-recovery"></a>

### Selection, deadlines and recovery

The full signed roster and cutoff accompany each reference-free work plan.
Evaluator selection is deterministic among the cutoff's actual signers: one
representative per control group, excluding groups with a miner submission in
the round. The plan selects exactly the policy's required number of groups.
Every selected group must sign. Another hotkey from our own administration
cannot replace an unavailable independent evaluator.

The work queue prepares all new endpoint statements for a frozen plan together.
Their immutable intents and discovery indexes commit in one transaction after
validation and a final issue-window check. A capacity or indexing failure exposes
none of those new statements. Model orders remain independently preparable.
Exact retries keep original signed bodies and can repair missing indexes without
choosing a new issuance. A partial endpoint batch retained by an older writer
requires explicit recovery; preserve its evidence and do not clear the journal.

Run one upgraded work-queue writer per state directory. The preparation lock
coordinates upgraded instances but does not fence an already-running older
writer. Quiesce the old writer during rollout. Before a new endpoint endorsement,
the signer separately requires the dispatcher's bound timing profile and an
atomic storage reservation for the complete cohort. See
[dispatch capacity and timing](dispatch.md#shared-scheduling-capacity) for the
private journal migration and qualification inputs. The work signer also reserves
the complete cohort in its signing, execution and evaluator journals, plus its
settlement-review store when configured. The private admission manifest binds
the original assignments, byte allowances and native journal identities. Partial
commits remain pending; no new work signature is produced until all receipts
verify and admission completion is retained. Exact retries keep the same manifest.
Capacity increases may be needed for retained history and both scored and void
outcomes. Filesystem space and full-roster runtime still require qualification.

Before its first signature, a worker requires its own retained cutoff intent,
cutoff vote and original suite reservation. It checks the complete roster,
incumbent, runtime and reference-free cases. An endpoint proposal additionally
requires independent proof of its exact original issuance and announcement
blocks through the worker's own transport observer. The worker rederives the
whole request schedule and rejects any mismatch or elapsed issue window.
If that observer missed an issuance header during restart, it may use the
bounded [ancestry recovery](dispatch.md#open-competition-dispatch--evidence-and-recovery)
from its own later verified header. This proves the historical header and chain
timestamp, not local receipt before a deadline. Cutoff votes and suite
reservations must still exist in the worker's original journal.
The protected suite's commitment is checked during coordinator preparation;
its reference-free projection is replayed against the suite after reveal.
An opaque commitment alone cannot prove the hidden references before reveal.

For a model-only round, orders can enter signing after cutoff certification and
whole-cohort admission. In a mixed round, model endorsements wait until the signer
has independently derived and reserved the endpoint assignments and retained its
first endpoint-authorization endorsement. The client
continues reading other work and retries waiting entries on its next pass. Each
endpoint first needs an authorization quorum, then an order quorum. All requests
must fit the frozen evaluation interval. A retained endpoint intent keeps its
original issuance after restart; the service never chooses a later time to make
that same work usable. A missed window is held as coordinator evidence.

The signing slot binds policy, round sequence, submission and statement kind.
Changed bytes create a persistent conflict hold. A failed initial proof creates
no signing reservation. A retained exact signature can be retried after expiry,
but the coordinator accepts a late acknowledgment retry only when that same
signature was already retained. A late first arrival cannot establish quorum.
Certificates are retained before file delivery. Recovery republishes the exact
certificate only while its original window is usable.

The signer holds a process-level lease through verification and vote persistence.
Statement checks, retained-vote reads, assignment derivation and native capacity
commits run outside the event loop. Cancellation waits for the owned operation
to finish before releasing that lease. Finality providers stay on the event loop,
and time used by preparation does not extend the signing window.
A previous retained signature remains replayable under its
original checks; replay does not authorize additional work. Drain older writer
processes before a release which enables these private schema generations.

Historical issuance recovery keeps a process-local LRU cache of hash-checked
headers, bounded to 2,048 entries and 1 MiB of encoded header bytes (stored as
hexadecimal strings). A collection timeout retains completed header reads so
the next attempt can make progress. Every use rehashes the complete path from
an owned observer anchor and counts cached bytes toward the path limit. The
cache supplies no timestamps, storage proofs or finality authority. Timestamp
membership and current-head freshness are checked on every attempt. Restart
may discard this cache; it does not erase durable journals or extend deadlines.

<a id="open-competition-work-signing--http-and-resource-bounds"></a>

### HTTP and resource bounds

Serve `POST /v1/competition/work` behind HTTPS alongside the existing round
route. Enforce a 16 KiB request limit, reject compressed bodies, disable body
logging and caches, and preserve hotkey-signature authentication. Requests use
durably checked short-lived nonces. Responses contain at most four statements,
each bounded at 16 MiB, and never contain suite references. The total response
bound is 64 MiB plus 8 KiB. Requests have bounded read and queue-operation times;
the service admits two work requests at once.

Model execution and cutoff/work polling use separate tasks. An unavailable
coordinator does not interrupt an already accepted CPU job. Shutdown joins those
tasks before closing both observers and releasing the evaluator's process lock.
Poll summaries report held work without printing request bodies or exceptions.

The coordinator's retained-round limit also bounds retained work intents and
certificates in its separate work journal. An endpoint consumes two intents;
a model submission consumes one. Each statement repeats its complete frozen
plan, so provision for actual roster and case counts. Defaults are 1,024 retained
intents and 1 GiB logical work-journal data. Files, observer state, SQLite overhead
and rollback space require separate quotas. Exhaustion holds new work and never
evicts evidence. Monitor capacity before accepting another round.

Tests exercise both tracks through authenticated in-process HTTP, real synthetic
hotkey signatures, exact retries, conflicts, expired publication, lost delivery,
owned-provider disagreement, capacity guards and shutdown failure. They do not
establish public TLS deployment, protected ASL quality or independent production
operators. Settlement publication and the reviewed simultaneous 70/30 activation
remain on the [execution plan](../competition/launch.md).

## Recoverable cohort admission

The opt-in recoverable-cohort implementation has a durable admission queue and
reviewer service. It requires an explicitly authorized cohort and miner consent;
enabling these components does not change a fixed round's signed deadlines. The
complete recovery workflow is not deployed or qualified for unattended rewards.

Phase authority `umi-cohort-recovery-authority/2` keeps a pending phase valid
until certified completion or revocation. Passing a target does not require an
extension signature. Closure still requires authenticated completion and the
full participant opportunity, including compensation for unavailable service.
Version 1 retains its signed extension rules; existing signatures cannot be
reinterpreted as version 2 authority.

Recoverable score replay can also verify every common-result signer's separate
run receipt against the certified preparation/request interval, exact outputs,
resource eligibility and independent control groups. Delayed replay preserves
these checks after the original policy or submission window expires. Receipt
agreement does not establish execution.

The explicit `umi-recoverable-execution-evidence/1` artifact retains the immutable
job, preparation closure, raw sandbox outputs and original execution boundaries.
Its consumer replays complete paired-model runs and comparator runs for endpoint
submissions after certified reveal, without a new deadline. Receipt preparation
checks the proposed common result against the original artifact. The complete
model and endpoint receipt consumer requires exactly one matching artifact per
signer; changed timing, stdout, model/runtime bindings and missing runs are
rejected. Comparator observations alone do not supply endpoint responses.
Failed comparators remain observations requiring review and cannot become
scored zeros.

`umi-recoverable-endpoint-paired-evidence/1` combines a comparator execution
with a quorum-signed bounded attempt order and exact transport transcripts.
Replay checks assignment identity, canonical request bytes, evaluator and miner
signatures, retained response bytes and offline timelock decryption against the
certified request/reveal closures. The immutable case obligation survives a
retry; each attempt uses distinct wire identities. Transport failures remain
infrastructure observations, while authenticated miner errors retain their
original classification. Neither replay nor an attempt order authorizes live
requests or proves original publication time.

`umi-recoverable-evaluation-order/1` binds the complete assigned evaluator set
to the participant, runtime and certified preparation. The ordered outcome
consumer requires every assigned evaluator's receipt for a score, or every
assigned evaluator's signed observations and decision signature for a void.
Independent review preserves each evaluator's exact local observation, and
repeated signing keeps a stable void decision identity. Missing observations
remain pending; agreeing scorable observations cannot become voids. These
benchmark outcomes do not measure serving capacity or create service credit.

The order signer retains one exact selection per round and participant before
signing, including original consent, admission, phase decisions and an owned
finality observation. It reserves bounded vote storage first. Partial quorum,
lost acknowledgements and interrupted signing recover that same selection after
long delays; changed inputs and history/finality rollback are rejected. New
signatures require the currently open request phase and the exact certified
preparation result. A committed vote can be returned offline as historical
evidence. This signer does not select endpoint retries, authorize delivery or
establish one active writer across migrated hosts. Those remain dispatcher and
control-authority requirements.

The coordinator order queue retains that selection before contacting reviewers,
collects independent-group votes and commits one exact certificate before
publication. Each evaluator has a private inbox that retains the assignment
before signing its delivery receipt. Lost votes, receipts and commit replies
recover from those journals after restart. A saved scan cursor prevents stalled
entries from repeatedly starving later work after service restarts. Pending work
has no age limit; capacity and per-operation timeouts are retryable.

New signatures and first delivery require current owned finality and an open
request phase. Both sender and receiver check authenticated history; learned
closure or revocation cannot be rolled back. Historical votes and receipts can
be recovered offline after closure. A delivery receipt acknowledges storage,
not execution or completion. The host must supply bounded authenticated reviewer
and inbox transports, independently verified history/finality, and a migration
fence. These components are not yet installed as a production cohort service.

The evaluator execution worker consumes acknowledged inbox assignments without
a signing key. Its private per-case journal reserves output capacity before
invocation and retains classified stdout before collecting a finish observation.
A failed finality read therefore retries the observation without rerunning the
model. Completed case/role steps are immutable and survive process restart;
complete evidence remains retrievable offline. Missing or interrupted work
stays pending while the certified request phase remains open. Elapsed targets
do not expire the job. Closure or revocation stops new execution.

The CPU sandbox port uses the original pinned rootless runtime and isolated
model/video mounts. Each retained attempt names one exact container and owns
one private scratch directory. Recovery stops an uncertain prior container
before selecting a replacement attempt; it never removes other containers or
retained models, videos and journals. A crash before stdout reaches the journal
can require repeating that computation. Only the first retained classified
output is selected, including a valid miner failure.

The process supervisor must stop and reap the previous worker's entire process
group before recovery; container removal alone cannot fence a still-running
launcher on another host. Host migration needs an independent writer fence.
This port does not implement native macOS recovery. Configure journal record,
byte and attempt capacity for the selected series and recovery reserve; capacity
can be increased without changing accepted assignments. Logical reservations
do not reserve physical disk space. `read_timeout_seconds` bounds individual
history/provider calls; it is adjustable without changing retained assignments.
Local authenticated replay has no elapsed processing deadline. Endpoint transport
retries, installed service recovery and reward integration remain required.

Endpoint origin collection consumes the same acknowledged assignment and
current authenticated phase history. It retains the original authority scope,
then verifies the miner's current registration, UID inverse mapping, Axon and
DNS against owned finality. An elapsed policy/submission target does not discard
accepted work. Closure, revocation, history rollback, invalid proofs and stale
chain observations still prevent use. This check proves the recorded origin;
it does not authorize a translation request.

The recoverable provider uses a separate private cache. Operators can increase
cache capacity and network timeouts without replacing assignments or cached
proofs; chain identity, verifier pins and freshness limits remain bound. Local
authority replay, proof verification and persistence have no overall network
timeout. Individual RPC/finality reads and DNS remain bounded. The worker checks
current authority and freshness again after collection. Live request/retry
selection and installation qualification remain required.

The endpoint response recovery worker preserves the original whole-attempt
selection and each certified single-case replacement under its own immutable
attempt key. `prepare_case` verifies retained parent grants before committing
new work. Complete request intent and queue entries commit together before
response reservations; interrupted reservations resume from that saved intent. A saved cursor survives restart, so an unavailable miner does
not prevent later cases from being checked. Polling uses the original evaluator
key, fresh route-specific authentication and a newly proved public serving origin.
It only calls `POST /v1/translate/response`; it never retransmits inference.

A verified original envelope, including a signed miner failure, is persisted
before acknowledgement and returned offline on subsequent reads. Recovery
records the actual retrieval time. It neither certifies original timely receipt
nor produces a score or closes a scheduler obligation. An absent archive,
pending response, invalid envelope or transient transport failure leaves work
pending. An uncertain attempt requires signed retirement and an independent
retry certificate before a replacement can be admitted. Current authority still governs new network reads; already retained evidence
remains readable after closure. Capacity can grow without replacing selections.

`CohortEndpointGrantDelivery` sends the retained exact assignment and bounded
attempt order to `POST /v1/competition/cohorts/assignments`. It re-proves the
current public serving origin, authenticates the route and receiving miner, and
retains the miner's signed storage receipt before acknowledging delivery. A lost
HTTP acknowledgement or local receipt write can retry the identical grant; a
retained receipt is readable offline. The same worker delivers original and
replacement grants. Delivery does not invoke inference.

The opt-in `CohortMinerAuthorizationAuthority` verifies the original quorum,
assigned evaluator, participant, policy, model and serving origin against its
configured cohort authority. It commits the grant, request lookup and receipt
intent together before signing. Restart resumes interrupted signing; closure
does not remove an existing storage acknowledgement. New inference additionally
requires current authenticated phase history and the miner's own finalized
transport-window validation. Cohort signatures cannot override issuance hashes,
window IDs, reveal rounds or request deadlines. Local replay has no overall
network timeout. Temporary source or storage-capacity failures remain retryable.

The evaluator's `CohortEndpointRetirement` authenticates the original request to
`POST /v1/competition/cohorts/assignments/retire` at its freshly proved origin.
It verifies the miner's exact request/grant receipt. A positive receipt must
match a retrieved original response; both records commit together before
acknowledgement. An absent response requires the evaluator's own expired block
and round observations. Invalid or unavailable evidence remains pending. Saved
records replay offline after restart without signing again or invoking inference.

The miner persists an execution fence before draining active protocol work and
commits its receipt intent before signing. It preserves signed failures and
prevents admitted-but-queued requests from executing. Its resource ledger moves
to schema 2 on first retirement so old readers cannot ignore the fence. Preserve
that database through upgrades and migration. A `no_response_retained` receipt
does not prove that inference never ran, stop detached sidecars or authorize a
void. Host fencing and independently authenticated proof replay remain required.


`CohortEndpointDecisionSigner` reviews each retired case under its own current
finality and certified request-phase history. It retains the exact review and
signing intent before voting. Independent policy groups certify either
`retain_response` or `retry_required`. A signed miner failure stays selected,
just like a successful response. An absence requires a valid miner retirement
receipt and the reviewer's independently observed expired block and round.
Neither a missing response nor a missing reviewer vote becomes a zero or void.

`CohortEndpointCaseCoordinator` combines retirement, durable review selection
and quorum collection. It stops requesting votes once quorum is available,
retains partial votes across outages and archives the certificate before
acknowledging completion. Reviews are keyed by their exact attempt and case;
later attempts must preserve those records. Completed votes and certificates
recover offline. An unfinished signing intent rechecks current authority, and
its decision has no expiration or coordinator-renewal requirement.

Native miner admission accepts `umi-cohort-miner-grant/2` for one certified
unresolved case. The independently signed replacement binds its original job,
case, next attempt number, parent grant hash and archive key, prior decision
and miner retirement receipt. It supplies a fresh bounded transport window
after its parent's deadline. A signed response, including a miner failure,
cannot become a retry. Each parent remains an immutable archive record;
iterative lineage verification avoids embedding all previous attempts in the
next request. Restart and lost acknowledgements recover the same grant.
Capacity can grow without changing retained grant identity.

The durable decision signer also reviews replacement cases. An absent response
requires another signed retirement and independent expiry observation before
another attempt; a recovered signed response remains selected. Closed phases
block new grants and inference, while retained acknowledgements and responses
remain recoverable. A decision certificate alone supplies no transport authority.

Evaluator grant delivery, response polling, retirement and decision collection
accept both original and replacement selections. Every attempt retains its own
response, retirement and review; a replacement cannot overwrite a completed
case or another transport window for the same attempt. Missing or conflicting
parents prevent delivery until the correct archive is restored.

Automatic replacement construction, durable order signing, inference scheduling
and complete terminal selection before request closure remain integration work. Host composition must supply authenticated
current history, owned finality, private state, the signer, writer fence and
service lifecycle; the standard miner CLI does not install this authority yet.
Recovery of an old policy's archive under a replacement evaluator key remains
unsupported. None of these storage acknowledgements proves publication timing,
scores or a native reward effect.

`umi-recoverable-roster-evidence/1` binds the entire round to its certified
intake seal and preparation result. The reviewer replays the original intake
inventory, including superseded submissions, every selected admission and all
retained phase decisions. This checks outage compensation as well as signatures.
Every selected participant must have one complete ordered outcome. Missing
outcomes raise `IncompleteRecoverableCohort` with the pending submission hashes;
missing archives remain source failures. Delay alone neither erases a member nor
creates a zero or void. This review does not certify dispatch/retry selection,
close scheduler work or calculate service credit.

Installed endpoint authorization and retry selection, complete roster
settlement, delayed first reward admission and standing reward continuation
still require integration. A reviewed void does not itself authorize closing
an unresolved scheduler obligation. These artifacts do not invoke models, prove host
isolation or independently verify the chain proofs referenced by their timing
boundaries. Production reviewers must retain and authenticate those sources.

Configure the intake's `recoverable_intake` with its private directory and exact
cohort/authority bindings. Initialize it with `initialize-cohort-intake` and
publish the certified history through `CohortIntakePublisher` before accepting
consent. Production intake retains the original registration proof and metadata
before acknowledging a participation request. After interrupted storage, retry
the identical signed request. A receipt remains `pending_attestation`; use the
admission status route for the subsequent certificate.

Run one reviewer process per policy-approved evaluator hotkey:

```sh
umi-competition --policy /absolute/path/policy.json \
  run-cohort-admission-worker --config /absolute/path/admission-worker.json
```

`CohortAdmissionWorkerConfig` uses schema `umi-cohort-admission-worker-config/1`.
Its `intake` configuration selects the shared local queue; `signing` selects
the reviewer hotkey, cohort authorities and private signing journal. `chain`
selects that reviewer's own finality state and RPC providers. These three state
directories must not overlap. Configure `wallet_name`, `hotkey_name`,
`wallet_path` and, if required, a private `hotkey_password_file`; the service
never prompts for credentials. The intake and reviewers must run under the
private queue's owning OS account. Separate signer identities do not by
themselves establish independently administered control groups.

The service holds a process lock, polls all configured cohorts, retries pending
records and drains in-flight signing before shutdown. `--once` performs one
bounded pass; omit it under a boot-persistent service manager. A pass is bounded
by `batch_size` (default 16, maximum 256); `poll_seconds` defaults to 5. Missing
proofs, capacity exhaustion and unavailable finality leave work pending. Increasing
`admission_capacity` or the signer's storage limits permits an unchanged retry.
These byte limits cover logical records; provision separate disk headroom for
SQLite, finality state, backups and migration.

When the original header was skipped or the reviewer was offline, admission
review reconstructs it from that reviewer's nearest retained finalized
descendant. Each RPC header must hash to the committed parent. The walk has no
total age or distance cutoff; `historical_header_batch_size` bounds a pass
(default 256, maximum 4,096). Completed downloads are retained and rechecked
after restart. `historical_header_maximum_bytes` bounds those durable header
hints separately from the registration cache (default 256 MiB); increase it
when needed. Recovery continues on later passes after a timeout or storage
failure. It still requires a fresh owned head, and a reconstructed historical
header never becomes a new observer record or current execution observation.

Reviewers verify original proof bytes against their own retained historical
headers or verified ancestry and a fresh owned head. Each records its exact signing intent before
signing. The queue verifies each vote and publishes a certificate only when the
policy's independent-group quorum is met. After intake closes, it requires the
original record selected by the certified intake seal. Public access exposes
the certificate, not the private registration archive.

Miners can inspect their retained request without signing again:

```sh
umi-competition --policy /absolute/path/policy.json \
  query-cohort-admission --origin https://intake.example \
  --request /absolute/path/signed-participation.json
```

This reads `GET /v1/competition/cohorts/{cohort_sha256}/admissions/{consent_sha256}`
and verifies the returned policy, consent, contribution and signature quorum.
`admission_certified` certifies participation only. It does not establish current
registration, assignment delivery, a score or reward activation; downstream
execution must still use the authoritative cohort history and fresh evidence.
