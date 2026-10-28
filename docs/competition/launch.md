[Documentation](../README.md) / Launch configuration

# Competition launch configuration

The active cohort runs under its signed policy, protected suite, installed
services and recoverable standing series. Published phase blocks are nominal
progression targets, not non-extendable deadlines, and do not advance the series
automatically. Public status, readiness and the current signed plan are the
authority for phase, admission and track availability.

The current scoring contract is `umi-open-competition-policy/3` with
`umi-competition-suite/2`. Public status and the signed plan bind the exact
policy and suite hashes used by the active cohort.

SN78 registration and a competition acceptance are separate. An intake receipt
does not promise selection, a score or a reward. The previous certified
allocation remains effective until the active cohort has a certified and
activated successor row. The public upgrade manifest and signed cohort plan
publish the canonical policy, transport and terms digests.

## Reward policy

When the signed plan enables both tracks, it records separate service and
public-model shares:

- **Service pool:** distributed across certified service work. Each job's credit
  is its certified work units multiplied by its normalized quality score.
- **Public-model pool:** eligible artifacts that match or beat the frozen
  baseline are placed in the quality bands selected by the policy. Each occupied
  band receives one credit, and the pool is distributed across those credits in
  proportion to their exact benchmark scores.

Duplicate model content counts once. The highest-scoring eligible artifact in a
band supplies its credit; an exact score tie is resolved by the earliest
certified complete acceptance. Small score variations within one band do not
create extra credits. A sole occupied band receives the complete model pool. If
all band-credit scores are zero, the pool is divided equally among occupied
bands. If no model qualifies, the pool goes to the policy's proved burn
destination. A participant may qualify independently for both pools.

Model-only plans disable endpoint/service participation and assign all 65,535 raw
competition units within the eligible public-model population using the same
baseline floor, deduplication and quality buckets. Read track selection and pool
shares from each signed cohort plan rather than inferring them from its number.
No unopened cohort profile is permanent; successor terms and a replacement
signed plan may change any of its settings before intake and miner consent. An
active cohort's plan is not changed retroactively.

Every submission must bind the exact immutable contribution terms and signed
policy advertised by its cohort plan. Earlier acceptance cannot be reused as
acceptance of successor terms. See [model
contributions](../contributors/models.md) for artifact, rights, provenance and
reconstruction requirements.

The signed plan identifies the frozen comparator bundle and execution runtime by
digest. Public discovery supplies those exact artifacts and their provenance.
Source archives do not replace the executable comparator identity.

## Scoring and video-dependence diagnostics

The active scoring profile, frozen suite and runtime determine the automatic
CER/WER benchmark scores. A plan may also compare a continuous-signing output
for its correct video with the same model's output for a matched unrelated
video. That comparison is diagnostic
unless its signed policy explicitly defines a qualified gate. A diagnostic-only
comparison cannot change a score, rank, eligibility decision, reward, settlement
or activation time, and a missing or unreliable diagnostic cannot hold
settlement.

Any future video-dependence payout gate requires published thresholds, a
qualified positive control, a newly signed successor policy and fresh participant
acceptance before its intake opens. The prospective procedure in
[private holdout operation](../operators/private-holdout.md) is not active merely
because its implementation exists.

## Certification progress

Request-phase observations share each exact order/evaluator terminal read within
that observation, without serializing the order's complete round for a lookup.
Later observations read terminals again so new arrivals remain visible. This
local bookkeeping grants no proof, closure or certification authority.

Model artifact acceptance runs continuously during intake, including while an
operator holds automatic progression. Latest replacement submissions take
priority over the ordinary export scan. When several cohorts have pending latest
models, the owner gives each cohort one model per pass and rotates which cohort
goes first. A large model in an earlier hash-sorted cohort therefore cannot hold
every later cohort behind its full batch. Keep the upload, acceptance and reviewer
owners running during intake; do not defer this work until roster closure.
Completed certificates and votes survive restart and are reused. Closure still
uses the native finalized-registration filter and exact certificates; a last-minute
upload or an unresolved review can leave unfinished work at closure.

Restoring completed model-file byte checkpoints yields between files so cached
progress and other service requests can run. Bulk receipt migration and byte-fact
imports use owned metadata workers; cancellation drains them before releasing
their original byte-store lease. These operations reuse successful byte verdicts
without fetching or rehashing completed model payloads.

Roster reviewers reuse their own committed admission verdicts for exact original
participations. Unfinished records receive native proof review and an atomic
checkpoint before their progress count advances. These private results bind the
original record, policy, cohort authority and verifier semantics; damaged completed
metadata requires repair. Existing signed admission journals remain supported.
Decision signing reuses the same signer's committed exact-progress review while
still checking the proposed transition and current owner history. Seal registration
and current finality remain independently verified. Preparation consumes the same
owned per-participation results rather than repeating historical proof work.
Final freshness checks use the verifier-owned finalized height; they do not
collect a new subnet membership snapshot when only the height is needed.

Preparation publishes the selected incumbent's small model declaration alongside
the round. A successor's newly certified baseline can therefore supply benchmark
orders without a manual setup-file copy. Missing declarations are restored from
the retained cohort-baseline certificate; model payloads stay in R2. Existing
immutable declarations are reused, and damaged declarations require repair.

Execution owners retain private exact-input history and order verification under
their existing execution journal's `authority-verification/` directory. The
records bind policy, configured evaluator/authorities, verifier semantics and
original signed inputs, and survive owner restart. Fresh finalized observations,
the selected owner history and the journal's monotonic/conflict fences are still
checked for each execution step. No miner reset or signed-history migration is
required for this additive private working state.

Request owners also retain the first successful read of each delivered order.
Private results bind the exact reference/object file identities, selected round
and submission, native semantics and requests-stage bounds. Later polls copy a
bounded private typed result and replay its original resource accounting; restart
restores the retained result without rereading or hashing the original order.
Changed originals or bounds and missing/damaged results expose a counted native
repair for the affected order. File clocks that cannot establish safe identity
reuse keep the original native reader. This does not establish completion,
current authority, a closure or a reward; those native checks remain separate.

Keep `.order-read-verification/` with the owner's retained state (or the selected
native-verification directory). Records are divided by round to bound directory
entries and can follow the ordinary durable R2 retention of inactive owner state.
The typed working set defaults to 256 MiB and 2048 entries. Explicit operating
overrides `UMI_REQUEST_ORDER_CACHE_BYTES` (up to 1 GiB) and
`UMI_REQUEST_ORDER_CACHE_ENTRIES` (up to 16384) change only that working set;
eviction preserves the durable results. Reuse counters report hits, misses and
capacity pressure under `purpose=request_order`. Deploy through the supported
cooperative source/config selection and preserve the original journals and signed
inputs. Older supported readers continue reading the unchanged original files;
miners need no new flag, signed request or state reset for this private change.

Held-cohort transport reservation proofs reopen their original lifecycle owner
after intake restart through the same serialized native initialization as
prepare/reserve. This restores the exact pending reservation and still checks
both original journals before signing a fresh challenge. It does not release the
hold or run an automatic phase. Repeating its exact pending reservation retains
the fresh local dual census
without repeating the completed remote model pass. Unreserved proposals still
require their initial independent verification. The change is private to intake;
existing miner requests, reviewer proof readers and published client formats
remain compatible. Select the updated owner through its supported cooperative
source/config updater, preserving the original state and signed plans.

A natively verified closed request history is retained as a monotonic denial
before collecting another registration snapshot. This does not advance finalized
highwater, create an execution observation, complete an obligation or remove any
endpoint response/retirement state. Existing endpoint retirement and evidence
recovery remain separate consumers. `execution_history_phase` reports this
substage with counted progress and a scoped ETA; native verification diagnostics
distinguish first verification, retained results, reuse and required repairs.

`GET /v1/competition/cohorts/{cohort_sha256}/progress` returns public diagnostics:
current `phase`, `stage`, `completed`, `total`, `percent`, elapsed time,
`eta_seconds`, its basis/scope, estimated UTC finish time in Unix milliseconds,
and stalled/retrying status. `components` separates intake certification,
selected-roster certification, the current acceptance operation and measured work.
After selected-roster certification completes, the current stage follows phase
review and decision certification. Their waiting heartbeats and ETAs remain
visible while unrelated uploads or exports run concurrently. R2 verification
reports bytes and promotion copies report parts within their cohort's work.
The owner copies up to four independent R2 parts at once, bounded by the signed
delivery profile. It completes parts in their original order and verifies the
new preserved object before recording promotion.
Each single-model acceptance substage also exposes `planning_eta_seconds` and
`eta_basis` under `components.acceptance` and the live nested work component.
The first planning range uses observed acceptance-stage bounds; after five
successful current-process examples of the same stage it uses their completed
durations with a twofold upper allowance. The range counts down from elapsed
time, and an overrun withdraws it with `planning_range_exceeded_retrying`.
These are current-substage planning ranges, not cohort completion forecasts;
provider retries and different model sizes can exceed them. Restart begins with
the initial range while retained certification and artifact checks still reuse
their own durable results.
Native R2 readers may select the [authenticated metadata batch transport](../../deploy/public-model-artifacts/README.md#private-metadata-transport)
without changing signed submissions, model identities, clocks or byte checkpoints.
Individual R2 HEAD/GET requests retry transient connection failures and temporary
provider status errors at most three times, preserving the exact selected object
and range. A failed partial response is discarded. Retry diagnostics expose the
attempt, transport error type, elapsed time and delay without provider details or
object credentials. Mutating requests retain their existing single-attempt
behavior; an ambiguous completion still requires native reconciliation. This
private read fix uses the ordinary consumer source/config update path and changes
no miner request, signed history, runtime requirement or retained verification ABI.
Keep historical credential exports for services that have not adopted the updated
reader; opt in through a new private export and the supported cooperative updater.
Intake counts cover latest accepted model submissions before registration
filtering; selected-roster counts cover the native seal's actual selection.
Percentages and ETAs apply to their stated stage, not the whole cohort.
Unmeasured, blocked, overdue or stale forecasts have a null ETA with a reason.
Overall ETA stays null until an end-to-end forecast is established. Responses
include observation age, disable caching, and never trigger verification or RPC.
After restart an unknown observation is null, not zero or complete. This separate
endpoint leaves signed history, readiness and existing client schemas unchanged.
For active successor intake, the owner restores its retained certification count
before reconciling older cohort exports. Pending successor submissions run first
in that poll, with one turn per pending cohort while multiple cohorts compete.
The owner discovers pending cohorts from its retained intake metadata without a
per-cohort priority setting. The HTTP read uses the cached
observation without opening the owner journal.

During model evaluation, `components.execution` reports completed selected models
with every evaluator terminal exported, the selected-model denominator, saved
execution and paired-comparison counts, and delivered orders. Its percentage
counts completed models, not equal-cost inference work or reward readiness.
Background history delivery, intake continuations and repair of earlier preparation publications
stay visible in their components without replacing the current evaluation counts.
Counts are confirmed export floors: unfinished or delayed exports can lag actual
execution. `projected_executions` assumes undelivered orders use the same case and
evaluator counts as delivered orders; `projection_basis` states that assumption.
Once all orders arrive, that total is exact even for differing order sizes.
Partial and terminal exports are never counted twice. A background worker samples
bounded metadata and persists small facts; restart reuses unchanged facts without
model downloads, proof replay or journal inspection. Damaged referenced metadata
is reported as requiring repair and never treated as completion. The scoped ETA
requires at least three new complete models over five minutes in the sampler's
current session, assumes comparable remaining cost and steady export delivery,
and excludes subsequent certification and rewards. Overall ETA remains separate.
Authenticated reviewer-epoch probes use a separate bounded HTTP pool so long
admission/review requests cannot consume their connections. Cached `rate_probe_*`
fields report availability, numeric HTTP status, attempts, failures and timeouts;
probe failures still withdraw the rate rather than borrowing an older epoch.

Prepared-round delivery reuses the native owner's immutable canonical snapshot.
Fresh history, authority, retained-row and requests-stage bindings remain required
on every handoff. Mutable public readers receive isolated objects. A private
`.prepared-publication` receipt preserves successful delivery across restart;
unchanged output identities require no payload reread, serialization or schema
replay. Older outputs acquire this additive receipt without changing their bytes.
Missing or damaged receipts and changed output identities report counted
`publication_repair` progress with a scoped planning ETA. Repairs compare the
original verified bytes, restore missing delivery and retain conflicts for repair;
they do not create a new round or repeat proof work. The receipt becomes visible
only after the output is durable. Older consumers can ignore this private namespace;
no signed history, cohort clock, miner startup schema or release selection changes.

Intake logs `cohort_model_certification_progress` from the same current roster
used to seal intake. `completed`, `total`, `remaining` and `percent` count model
artifact certificates for the selected latest submissions, excluding superseded
entries and other cohorts. These are diagnostics, not admission authority or a
quality score. The full native certificate/seal verification still follows.

The report includes elapsed time, the measured completion rate, ETA scope and
assumptions. Rates restart when the process or selected roster changes. A known
failed acceptance stage withdraws the estimate and appears in `blocked`; a
missing previously observed certificate requires repair. `model_acceptance_stage`
identifies payload, intent preparation, proposal publication and reviewer steps,
with redacted failure frames. Missing samples and unresolved holds have no
measured finish time. Certification ETA excludes preparation, challenges,
scoring and reward activation; report those stages separately.
When all selected submissions are certified and progression remains held, the
cached public `/progress` route shows that hold as the current stage and retains
the completed certificate count in `components.intake_certification`. Fresh
acceptance work can take precedence; a replacement submission makes
certification current again until its new roster completes.

## Timing and recovery

Published cohort dates are operating targets. Liveness failures do not expire a
cohort or authorize its evidence to be discarded.

- Every phase is journaled and replayable. A coordinator, evaluator or validator
  outage leaves unfinished work pending and resumes it from retained evidence.
- Request closure follows the original signed cohort plan and any authenticated
  pre-request rule adoption. Once at
  least 12 hours have elapsed from its certified request opening, plans `/1`
  through `/3` permit skipping unfinished work when at most 10% of the original
  selected miner identities remain unfinished. Plan `/4` explicitly selects
  `original_request_12h_with_completed_miner/1`: after the same 12 hours, closure
  may proceed once at least one original miner has completed all its selected
  work. If every original miner remains unfinished, requests stay open.
  For C6 and later, the owner also waits for every selected public model's
  execution and terminal certification before selecting this cutoff. Central
  evaluation backlog cannot make an uploaded model lose its evaluation. Once
  model work is complete, unfinished endpoint work follows the same signed
  rule and original clock. Historical certified tails remain replayable.
  Benchmark and accepted paid-work miners count in one union; multiple entries,
  cases or retries cannot enlarge the denominator or make a miner complete while
  its other original work remains unfinished. Legacy plans retain the 10% rule
  until adoption is certified. A legacy plan with `original_plan.sequence > 5`
  may adopt the completed-miner rule through a separate
  quorum-signed `adopt_request_tail_rule` transition while still in intake or
  preparation. This appends to the original history; it preserves the signed
  plan, accepted submissions, authority and storage bindings. An upgrade alone
  never changes the rule. Adoption during requests or later is refused.
  The 12-hour clock always uses the original certified request opening, with no
  new grace period after the first completion, restart or upgrade.
  The independently certified tail disposition can
  close an unavailable or uncompensated request window; original outage records
  and signed deadlines remain intact. The owner seals the exact accepted paid
  inventory only after this threshold qualifies. Before sealing individual
  queues, it publishes one durable cutoff under the first original catalog
  queue's journal directory (`cohort-tail-admission/tail.json`). Every catalog
  retains this directory binding: keep the file and directory with the existing
  journals during recovery or migration. A crash between publication and sealing
  still refuses fresh claims; accepted duplicate claims remain recoverable.
  Before signing a new plan `/4`, deploy compatible plan and tail decoders to
  the coordinator, independent reviewers, miners and settlement/reward consumers.
  Legacy-plan adoption also requires recovery transition `/3` support in every
  history consumer before publishing its certificate. Preserve historical
  decoders while original cohorts and reward packages still require them.
- Independent reviewers verify the original and closing chain timestamps, exact
  original inventory, genuine completed terminals and explicit skipped
  dispositions before certifying closure. Completed assignments and earned paid
  work retain their normal scoring and certification. Incomplete benchmark
  assignments have no aggregate score, and unperformed paid work earns no credit.
  Partial evidence is retained. The cutoff preserves work completed before its
  selection, including completions received after the first 12 hours. It does
  not rewrite signed attempt deadlines or create a miner retirement receipt.
  Each missing evaluator terminal requires that evaluator's signed inventory at
  a finalized block after the fixed cutoff and no later than closure. Reviewers
  replay that observation's native proof and the retained partial originals.
  An older partial export cannot establish that no newer work exists; a complete
  inventory still requires ordinary case or terminal certification. Retries keep
  the original cutoff while incorporating additional genuine completions.
  The owner requests these snapshots through its existing settlement history
  delivery only after selecting the cutoff. Each evaluator reuses the same
  signed snapshot for unchanged work, so a stalled cohort does not accumulate
  new inventory signatures or files on every poll. The cutoff request is
  advisory; it never authorizes closure or substitutes for independent quorum.
- An authenticated paid response whose miner retirement remains unavailable can
  use an evaluator-signed no-credit partial inventory after the same fixed
  cutoff. The inventory binds the exact accepted assignment, grant, response,
  selected evaluator, admission fence and later finalized snapshot. Native
  phase and settlement reviewers replay its proof and preserve every original
  in the portable reward package. A matching response-retirement pair, terminal
  signing intent or earned terminal retains its ordinary certification path.
  Missing referenced bytes remain pending; they never establish absence.
  Partial paid work has no measured score or credit, and no retirement is
  synthesized. Closure fixes the certified package; later originals cannot
  rewrite it or authorize retroactive compensation.
  This path requires service closure schema `/5` support in the owner, workers,
  independent reviewers and settlement/reward consumers before selection.
  Existing `/2` and `/4` closures retain their original canonical bytes and all
  upgrades preserve the original journals, cutoff file and directory bindings.
- The previous certified reward row remains effective until a newer cohort is
  certified and activated.
- The selected cutover-clock rule measures the five-hour minimum from cohort
  cutover, recording that observation during intake. Time spent on intake review
  and preparation counts toward it; restart does not start another interval.
  The predecessor must still have certified request closure. Legacy installations
  retain their certification-clock journals until their supported upgrade selects
  the cutover clock; explicit historical cutovers bind their retained source.
- Each designated validator must receive at least 24 hours of verified
  opportunity to submit the certified row. Offline time does not count toward
  that opportunity.
- Moving a service to another host preserves its journal, signed inputs and
  content-addressed evidence. Migration does not create a new cohort identity.
- Operation timeouts and retries detect stuck attempts. A timeout alone does not
  complete an obligation; recovery uses original evidence or the separately
  certified miner-tail disposition above.

Standing cohort authority carries these rules without periodic coordinator
renewal. A coordinator may be offline for longer than a nominal phase window;
recovery delays the cohort instead of losing it. Conflicting signed histories,
invalid signatures, changed immutable inputs and missing original evidence still
fail closed and require repair. Eventual completion does not weaken integrity
checks.

## Trust and evaluator profile

The signed plan lists evaluator identities, control groups and required quorum.
Public status distinguishes required evaluators from optional redundancy.
Signatures from validators in one administration count as one independent group.
Adding a control group, changing a required signer or increasing quorum requires
a successor policy and qualification of that exact profile.

## Protected inputs

The signed launch fixes the exact:

- policy, immutable terms digest and standing cohort authority;
- protected suite, references, strata and case provenance;
- frozen baseline and execution runtime;
- participant and model-artifact intake limits;
- evaluator set, control groups and chain/RPC configuration;
- service and model allocation rules; and
- publication, evidence-retention and recovery destinations.

Keep protected labels and private clips outside public storage and execution
requests. Candidate and baseline outputs use the same committed suite and
runtime. Do not repair labels, replace cases or alter scoring after candidate
outputs are known. See [private holdout operation](../operators/private-holdout.md).

## Activation checklist

Launch requires one retained evidence package for the exact production
configuration. Complete these checks in order:

1. **Policy and inputs:** Verify signatures, digests, baseline reconstruction,
   model-rights requirements, protected-suite integrity and available unused
   cases. Publish the miner-facing rules and tested commands.
2. **Installed predecessor handoff:** Install successor services beside the active
   services without selecting them. Rehearse the signed handoff and prove a failed
   successor boot leaves the predecessor active.
3. **Multi-cohort recovery:** Run the standing series with the tracks selected by
   each signed plan, alternating coordinator/evaluator outages, restart replay,
   five-hour rests, 24-hour validator opportunities and previous-row continuity.
4. **Capacity:** Run the intended host and container runtime with production-size
   evidence and generous test watchdogs. Verify the pinned CPU image and an actual
   bounded invocation as the evaluator service account under its exact systemd
   mount, namespace, privilege and cgroup settings. A successful shell invocation
   does not qualify a sandboxed service. Keep evaluator container storage separate
   from validator storage and wallets. Bound model concurrency across every
   evaluator on the host by their combined per-case memory limits, leaving
   headroom for chain observers and owner services. Include rootless case scopes
   when checking aggregate consumption; they may be outside the reviewer unit's
   cgroup. Test watchdogs may detect harness stalls;
   they must not define cohort expiry.

   Shared model admission is selected through the optional private benchmark
   `model_execution_admission` field. It binds a root-owned host policy and file
   leases to the protocol policy and signed CPU image, leaving existing configs
   and the legacy two-slot cache readable. All reviewers on a host must select
   the same capacity namespace. Reserve the full per-invocation memory ceiling,
   at least 4 GiB for owner services, and a separate preparation lane. Populated
   rootless container cgroups remain charged at their full ceilings even if a
   reviewer exits and releases its lease. Admission waits rather than exceeding
   capacity; its diagnostics identify the wait without changing signed clocks.
   Configure only the number of model slots qualified for the host's memory.

   Admitted pairs share one reference materialization, pin active model bytes,
   and project the complete resident working set before transfer. Resident reads
   can continue while another pair downloads. A pair larger than the bounded
   cache takes all model slots and uses the supported single-model path; it
   does not raise the cache cap or evict another active consumer. Interruption
   preserves completed challenge checkpoints and resumable transfers. Extra
   candidate slots are bounded and reclaimed after their job completes; retain
   unfinished model slots across cooperative updates so restart can reuse their
   byte receipts. Rollback selects the
   preserved source and config together, since older readers do not accept the
   added private config field. No miner/client signed schema changes are needed.
   Timing logs carry PID, work identity and job digest so concurrent samples
   remain distinct; journal timings surround the original operations and do not
   trigger extra verification. Public polling still reads diagnostic snapshots.

   For an installed predecessor that evicts unfinished extra slots on stop,
   hold its existing cache-allocation lease across the cooperative stop and source
   selection, then release it before model workers resume. This prevents the old
   cleanup path from discarding warm models without moving or copying files.
   This migration is needed only while such predecessor hosts remain installed.
   New releases preserve the bounded unfinished working set directly.

   Transfer ETAs separate measured byte time from fixed per-file/request
   completion overhead. Remaining large weight bytes and small metadata operations
   must not be extrapolated as equally costly files. Restored work supplies no
   native rate sample; a new transfer generation resets both rate histories.
   Partial range-response bytes are a child diagnostic scope, not completed or
   verified parent bytes. A stalled initial response withdraws its forecast.
5. **Storage and publication:** Restore evidence and model artifacts from the
   private R2 copies, verify every digest, and publish bounded public discovery
   records without exposing private clips or credentials.
6. **Validator path:** Verify every required validator consumes the certified row,
   survives restart and RPC failover, retains uncertain transaction state, and
   receives the full verified reward opportunity. Verify optional validators
   separately; their absence or retirement must not hold the cohort.
7. **Selection:** Publish the canonical standing boot selector only after all
   preceding infrastructure evidence passes. Verify the selected services,
   public status and retained predecessor rollback boundary.
8. **Operator test enrollment:** Submit an operator-controlled baseline artifact
   through every enabled live track under the exact active policy and confirm its
   complete acceptance and durable object-store copy.
9. **Chain proof:** After settlement, confirm every required validator's fresh
   finalized row and resulting incentive before announcing reward activation.
   Record any optional validator rows separately.

Source tests, a merged commit, staged files, a running service and a submitted
transaction are intermediate evidence. None alone proves a live reward row.

## Operational references

- [Current miner operation](../CURRENT_MINER_OPERATION.md)
- [Submission commands](../reference/commands.md)
- [Round coordination](../operators/rounds.md)
- [Settlement and publication](../operators/settlement.md)
- [Validator successor handoff](../validators/successor-upgrade.md)
- [Public results API](../reference/competition-results-api.md)

Retain predecessor signed artifacts and evidence for replay. Remove obsolete
migration instructions after no installed service or recovery consumer depends
on them; Git history is the record of superseded launch plans.

Owned-finality collection budgets accept 1 through 600 seconds, with a
120-second default. Intake shares one background collection per refresh, using
at least 240 seconds or the configured budget when larger; callers wait through
that same collection. These operation budgets do not relax verified head age,
cohort authority or signed issue deadlines. Retain existing journal bindings and
use a qualified migration before changing a bound installed configuration;
never reset evidence to change a timeout.
