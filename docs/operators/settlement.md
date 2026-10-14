[Documentation](../README.md) / Settle rounds and publish weights

# Settle rounds and publish weights

- [Recoverable cohort model awards](#recoverable-cohort-model-awards)
- [Automatic settlement preparation](#open-competition-settlement-preparation)
- [Independent settlement signing](#open-competition-settlement-signing)
- [Automatic settlement delivery](#open-competition-settlement-delivery)
- [Per-round successor signing](#open-competition-round-publisher)
- [Work progress and ETA logs](#work-progress-and-eta-logs)

## Work progress and ETA logs

The intake owner, phase reviewer, settlement service and reward runtime emit
`umi-competition-work-progress/1` JSON through `umi.competition.progress`. Each
record identifies a process, a fresh `work_id`, the cohort and a named `stage`.
Request review also identifies its review attempt and read cycle. Restarted work
gets a new identity; logs are diagnostics and do not replace retained votes or
create a replay checkpoint.

Settlement assembly, input preparation, input replay and native phase review
also identify `operation_name`, `operation_id` and `parent_operation_id`. These
labels distinguish repeated closure traversals without combining their counts
or forecasting overall completion. Each synchronous operation reuses only exact
canonical serialization bytes with a 64 MiB retained key/output budget and
65,536 entries. Nested preparation shares the assembly budget; the cache clears
on success or failure before later waits. This is not a process RSS limit: Python
bookkeeping, transient snapshots and input models consume additional memory.
The serialization cache is separate from durable native verification below;
aggregate streaming remains uncached. Oversize values use ordinary serialization
and are not rejected by this optimization.
Plain single-field `{"hex":"..."}` objects with ASCII alphanumeric contents use
direct encoding of the same RFC 8785 bytes. This avoids generic string escaping
for retained binary evidence without changing its format, signatures or replay
checks; no migration is needed.

Finite substages report `completed`, `total`, `unit`, `percent`,
`elapsed_seconds`, `eta_seconds` and `eta_samples`. Counts advance only after an
item returns successfully. Preparation and intake count original participation
proofs and registration observations; reference release counts committed inputs;
quality review counts participants and paid terminals; model certification counts
model artifacts; package construction and verification count evidence objects.
An exhausted substage reaches 100%. A failed or interrupted attempt keeps its
completed count and does not claim completion.

ETA uses the elapsed time and the completed work rate for that substage. It is
`null` until there is enough completed work to estimate a rate. Uneven object
sizes or expensive remaining inputs can change the estimate. Counted validation
steps with different costs deliberately retain a `null` ETA. Owner exports,
quorum votes, native review workers and history publication emit waiting
heartbeats with a `null` ETA: an external dependency has no measured finish time.
Those waits retain their native timeouts, cancellation and drain behavior.

When a native ETA is `null`, an operational status update must still give a
labeled planning range, its assumptions and the scope it covers. Use comparable
retained work measurements where available; identify an uncalibrated estimate
explicitly. If a dependency or retry invalidates the range, mark the remaining
ETA unknown and replace the plan. A zero lower bound is not completed work.
Preparation, migration and recovery tools must report their own started,
completed, stalled and retrying stages with elapsed time and counted scope.
No-new-count heartbeats identify missing observable progress; they do not prove
that a replay worker is deadlocked. Keep RPC exchange allowances separate from
estimates for complete local replay and cooperative child cleanup. Progress
output must use a diagnostic channel separate from an exact RPC response or a
success contract that requires empty stderr.

Settlement retry events retain the cohort, role, `tick` or `maintenance` boundary
and bounded causal error types, reason codes and native source locations. They
omit exception messages, inputs and URLs. The event is emitted before rejected
input frames are released, including through the series scheduler. A retry
withdraws the current ETA until progress supplies a new sample; diagnostic sink
failures cannot change the retry or cancellation result.

Report the stage name with every percentage and ETA. Separate nested substages
and repeated replays; do not add their percentages or describe a completed
object inventory as completed certification. Use the native certified phase
history, verified reward package and finalized chain observation to establish
those milestones. These log records explicitly carry
`certification_authority: false`.

## Durable native verification

Settlement and reward owners retain completed closure, participant, terminal,
endpoint ancestry/content, execution and paid-work verification under private
state. A restart or later phase reuses a result
only for the same original evidence, policy and lineage, owner, signed interval
and native verification rules. Each independent owner establishes its own result.
Current history, finality, authority, signature creation and chain selection keep
their native checks. A stored object alone does not establish valid miner work.

The first package read imports its exact native envelope and original object bytes
into a private immutable snapshot. Subsequent reads compare the actual package and
object file identities and metadata; unchanged payloads need no repeated hashing
or evidence replay. Dependency coverage and resource budgets are still counted
when a verdict is reused. Payloads are read when a new consumer actually needs them.
A completed participant's verdict survives interruption before full closure.

The default verdict location is
`promotion_directory/verification/<series-sha256>/native`. A reviewer and its
predecessor preparation share that location and verification context. Separate
role promotion directories do not share state automatically. To reuse native
facts across roles of the **same validator authority**, explicitly set
`UMI_NATIVE_VERIFICATION_DIRECTORY` to one private directory visible to all of
those services. Each series/policy/chain-reader context gets a separate child
directory. Preserve each service's promotion roots, journals and configured
bindings; for a service with `RootDirectory`, expose the same host directory
with an explicit service-manager bind. Independent validator authorities must
have separate private directories. Qualify ownership, access, restart and
role-to-role reuse before enabling the override.

For generated systemd successor services, configure this variable through the
unit's `Environment=` or `EnvironmentFile=` setting. The generated start and stop
commands explicitly preserve it through their clean environment. An unset or
empty setting retains the default location; nonempty paths must be absolute.
Existing generated drop-ins that lack the explicit assignment need a supported
host upgrade to the new signed environment contract before enabling shared
reuse. Recovery and drain of older signed hosts retain their original command
bytes; upgrading the operator tool alone does not change those controls. Preserve
their journals, promotion roots and existing bindings, and verify the effective
process environment and namespace access after the switch. Keep
this repair instruction while an installed successor uses the older rendering.

Enabling this override reads an existing completed local verdict and copies its
metadata into shared state before reuse; it does not repeat native verification
or delete the local record. Retain that fallback reader while a supported owner
still has completed verdicts only in its former default directory. A private
nonblocking owner lock prevents simultaneous workers from repeating the same
first verification; contention reports `waiting_for_owner` and remains pending.

Existing installations need no reset or signed format conversion. Their first
successful native review records the missing private verdicts; original packages,
journals, account paths, clocks and signatures remain unchanged. Interrupted import
resumes completed object checkpoints. Invalid private metadata is reported as
`repair_required` and rebuilt from originals; changed or missing immutable objects
require restoration from the unchanged selected package. Unsupported signed inputs
remain errors. Retain this compatibility path while installed owners have original
packages without snapshots; it may be removed only after those owners have imported
and qualified their retained inputs.

`umi-native-verification-reuse/1` events report misses, retained results, hits,
invalidation and required repair. Completion markers distinguish a lost completed
record from a first read. Snapshot preparation emits a labeled capacity planning
range before measured object import/identity and dependency accounting
also emit ordinary counted progress, elapsed time and substage ETA. Receipt writes
are atomic and publication failures remain visible; completed verdicts are not
silently evicted or dropped. These records do not certify a cohort or authorize
weights. There is no independent receipt or snapshot metadata size ceiling;
native selected evidence capacities and per-operation accounting still apply.
Native verification and JSON shape rule identifiers change only when accepted
validation semantics change, so unrelated releases preserve completed work.

`competition_verification_rules.json` binds the verifier's source dependency
closure to its explicit semantic ABI. The runtime refuses an unqualified source
change before reading verdicts. For a compatible implementation change, regenerate
the candidate manifest with `python tools/verification_manifest.py`, retain the ABI,
and qualify native historical/restart/reward parity before release. Change the ABI
when accepted semantics change. A manifest refresh alone is not qualification.
Storage identity is separate from the native ABI, so a verifier rule change does
not force unchanged immutable package objects to be extracted again.

The same manifest lists qualified external distribution versions, including their
installed dependency closure. Missing or unqualified versions stop the owner
before receipt access. A normal manifest refresh preserves those allowlists and
refuses new versions. Use `python tools/verification_manifest.py
--candidate-external-versions` to add candidate installed versions, then separately
qualify compatibility before release. Compatible external versions retain the
same native ABI and completed verdicts; accepted semantic changes require an ABI
change. Validate the installed wheel and dependency inventory before cutover.

## Reward-history checkpoints and repair

The reward-history owner keeps successful per-block native facts in its original
private journal. These facts bind the chain-configuration digest, control hotkey, initial block,
original directory and database identity, source-record mutation identities and
verifier semantics. Restart restores the compact verified prefix without rereading or
rehashing unchanged proof payloads. Ordered ancestry and the restored tip still
require a fresh owned finalized-chain check. A raw archive frame or a progress
log is not a successful-verification receipt.

Historical capture reuses the original owned finalized header when it is retained,
avoiding another target hash/header RPC. An archived target header can also supply
the final link of a historical ancestry walk; it remains an untrusted hint until
every link reaches the owned finalized descendant. Missing intermediate headers
still use normal recovery. Malformed owned records and corrupt durable hints stop
the operation instead of falling back to replacement data. These optimizations
preserve the original evidence format, state bindings and current-finality checks.

Retained block verification supports an explicit local
`service.history_verification` selection in both standing-writer and
coordinator/reviewer configurations:

```json
{
  "schema": "umi-history-verification-profile/1",
  "workers": 2,
  "maximum_in_flight": 2,
  "maximum_in_flight_bytes": 637534208
}
```

Omitting this field preserves existing serial behavior and canonical configuration
bytes. Selecting it does not alter a signed cohort, a clock, the history root or
its receipts. Current and configured predecessor histories, coverage collection
and both owner repair commands use the same selection. For each new cohort,
start the coverage/history owner at launch, retain the complete finalized interval
from its original authority block, and monitor catch-up during intake, paid work
and certification. Selecting workers alone does not start a missing capture owner.

The parent authenticates each child header against its owned finalized chain;
spawned workers receive only immutable evidence and the selected native verifier
context. They share the serial archive parser, runtime/slot proof checks and
complete body/event scanner, including parent-runtime changes. Each successful
result is committed independently, even when an earlier block fails. Only one
owner applies consecutive results in block order. Gaps and unresolved effects
cannot become a complete history. Worker shutdown drains started operations;
an abnormal worker exit cleans its owned native process group while healthy
peers finish and checkpoint their results. No signing key, RPC connection or
owner database handle enters a worker.

This parallel path accelerates retained or imported proof verification. Missing
frames still use the existing serial online native capture path. Do not derive an
online catch-up ETA or a production throughput promise from offline worker count.
Each window reserves room for maximum supported frames; the byte budget bounds
concurrency without reducing the evidence allowance. The default profile requires
10.5 GiB of conservative aggregate headroom for raw/IPC copies, decoded graphs,
worker interpreters and native tools. Qualify the selected host's full peak before
cutover. When host memory admission is configured, its enclosing transient slot
must cover the entire window; workers never acquire a nested lease. Unsupported
memory selections fail before loading a window. An absent host memory policy
leaves provisioning with the operator and does not claim that capacity is present.

Progress inventories read compact durable checkpoint metadata once, in bounded
batches, and then advance counts as work commits. `captured_blocks`,
`verified_blocks`, `exported_blocks` and `applied_blocks` are distinct.
`exported_blocks` describes the selected proof archive. With an R2 exporter,
`replicated_blocks` counts durable acknowledgements for complete block frames and
their dependencies. A filesystem exporter has no remote acknowledgement, so its
replication count remains null with an explicit unavailable-receipt basis. A past
replication receipt does not assert current R2 availability. Ordered pipeline and
ahead-of-prefix verification rates are separate; history ETAs use the ordered
rate. `local_release` separately reports original SQL records moved to R2 and
logical bytes released. It does not report a smaller SQLite file on disk.

### Optional R2 proof archives

The standing reward writer, reward coordinator/reviewer and settlement service
accept optional `proof_stores` alongside their existing import/export directory
paths. The admission owner's `lifecycle.proof_stores` selects the same transport
for original registration-proof publication. The phase reviewer accepts only
`proof_stores.imported`. Omission preserves legacy canonical configuration bytes
and local archive behavior. This transport
selection does not alter signed plans, clocks, acceptance rules or native proof
authority. Select it through each service's existing authenticated configuration
and upgrade boundary; source tests alone do not qualify a deployed successor.

An example selection is:

```json
{
  "schema": "umi-proof-archive-stores/1",
  "imported": {
    "schema": "umi-r2-proof-archive/1",
    "credentials_file": "/etc/umi/proof-reader.env",
    "bucket": "umi-proof-artifacts",
    "prefix": "cohort-proofs",
    "read_only": true,
    "maximum_cache_bytes": 1073741824,
    "maximum_index_bytes": 4294967296,
    "timeout_seconds": 60
  },
  "exported": {
    "schema": "umi-r2-proof-archive/1",
    "credentials_file": "/etc/umi/proof-writer.env",
    "bucket": "umi-proof-artifacts",
    "prefix": "cohort-proofs",
    "read_only": false,
    "maximum_cache_bytes": 1073741824,
    "maximum_index_bytes": 4294967296,
    "timeout_seconds": 60
  }
}
```

Each credential file uses the existing private R2 export format (`TOKEN_VALUE`,
`ACCESS_KEY_ID`, `SECRET_ACCESS_KEY`, `DEFAULT_ENDPOINT`). Keep it outside mutable
or replicated stores and separate from direct-model credentials. Provision
read-only bucket credentials for importers and publication permission only for
exporters. Cache and index limits are explicit host capacities; size them for the
cohort's retained range and full supported object size. An exhausted capacity
holds visibly without silently evicting durable verification state. The payload
cache is bounded, disposable and separate from private acknowledged receipts
under the original archive's `.remote-state` directory. Each store serializes
bounded transfers; active payload leases prevent eviction.

The private receipt index uses capability generation 4 and a separate immutable
completion ledger. Startup upgrades older indexes transactionally using only
their retained metadata, with counted progress and an ETA. Original receipt
bytes, owner binding and journal inode stay intact. Old runtimes and reservation
layout changes refuse this capability; keep its completed ledger with the index.
A missing receipt is damaged completed state, not permission to import it again.

Objects use content-addressed keys. Complete original `/1` frames publish after
their dependencies using conditional single PUT, SHA metadata and exact single-PUT
MD5 ETags. Reads pin the acknowledged generation and check bounded bytes. Transport
receipts establish replication, never native proof validity: a new independent
owner still performs its first native verification.

On writable selection, startup migrates retained local `/1` archives before
consumers run. It preserves exact frames, signed proof bytes and local originals,
and checkpoints each completed copy. Restart skips unchanged completed payloads
using private source-identity receipts. Progress includes counts, elapsed time,
planning or measured ETA, and retry/stall state. A changed completed local identity
requires explicit exact-byte repair. Retain this compatibility migration while
any installed or recovery consumer still has local `/1` archives.

Offline `migrate_proof_archive(original, selected, evict=True)` can remove local
archive payload files only after the complete graph is acknowledged. The caller
must hold the original service's exclusive upgrade boundary. This library repair
surface is not an installed cleanup command. Keep permanent `.remote-state`,
original journal directories and journals; never move their identity to reclaim
space. SQL externalization replaces raw records with charged immutable aliases
bound to their original revisions and remote receipts. Existing successful `/1`
history facts remain unchanged. Deleted raw records free logical capacity and
reusable SQLite pages, not physical database file size. The remote generation
fence refuses old runtimes and transitions to reservation-only layouts.

An observed missing, replaced or corrupt remote object creates a persistent
repair hold. Restore its exact original generation and invoke the original
owner's `RemoteProofStore.repair_reference` under an explicit repair operation;
normal retry never adopts another generation. An intact original completion
ledger can restore its exact missing or damaged receipt only through this
explicit repair, after checking the original remote generation. Lost or damaged
completion ledgers, private aliases or source-identity metadata require
restoration in place from the original owner backup. Remote transport alone
cannot reconstruct native verification facts.
Qualify backup/restore, startup migration, interruption, bounded capacity and all
selected consuming roles before adopting this transport in a cohort.

Supported journals containing only legacy `/1` raw history records receive a
counted source-identity migration and then a first native checkpoint pass. This
preserves all original record bytes. Retain that compatibility reader while an
installed owner or recovery consumer still has uncheckpointed legacy records;
remove it only after those consumers have completed and qualified migration.
An older running owner has no supported export of its process-local successful
prefix. Keep it running through its current handoff when preserving that work
requires avoiding replay; replacing it needs a disclosed first native checkpoint
pass over its retained legacy records. Source deployment alone cannot recover
volatile verification facts.
The completed original C5 admission route below is a narrow exception based on
an actual durable native decision result; it cannot preserve an incomplete
process-local prefix.

Migration and history review emit `reward_history_progress` with counts, elapsed
time, an ETA and its basis, and retrying or stalled states. Restored blocks count
toward completion but do not inflate measured native throughput. These estimates
cover history review only, not overall reward finality.

Unreserved history journals keep transactional record counts and byte totals, so
adding a block does not recount the entire retained history. Older unreserved
journals receive a metadata-only migration in place. Reserved journals retain
their original accounting and allowances. Migration emits
`round_journal_progress` with counts, elapsed time, ETA and retry state.

Capacity history is traversed in bounded batches without the former 32-transition
ceiling. Its schema and retained bytes are unchanged. An older runtime cannot
reopen a journal after more than 32 transitions; never discard retained capacity
history to downgrade. The separate 20 GiB registration domain and two-transition
RPC semantic restriction are unchanged.

Changed source dependencies or damaged successful records stop with
`repair_required`; they are not silent cache misses. Restore the exact original
source and run the bounded owner repair command using the installed interpreter,
original service account and original configuration. Cooperatively stop the
applicable owner through its supported service lifecycle first. The repair
command refuses overlapping ownership; it does not stop services for you.

For a coordinator or reviewer:

```sh
"$INSTALLED_PYTHON" -m umi.competition_reward_coordinator_cli repair-history --config "$ORIGINAL_CONFIG" --through-block "$LAST_BLOCK" --reason "original source restored"
```

For the sole reward writer, use its authentic supervisor configuration and
standing boot configuration, in the same namespace as the installed service:

```sh
"$INSTALLED_PYTHON" -m umi.competition_supervisor_cli --config "$ORIGINAL_SUPERVISOR_CONFIG" --standing-config "$ORIGINAL_BOOT_CONFIG" --repair-history --through-block "$LAST_BLOCK" --reason "original source restored"
```

Add `--history predecessor` only to select an explicitly configured predecessor.
The coordinator holds both current and predecessor service locks and, for its
publishing role, the original control-writer lock before opening journals. The
writer uses its native supervisor startup lease and root-approved original boot
configuration. A coordinator configuration cannot substitute for a writer's
namespace. Neither route constructs a signer, writer adapter or chain executor.

Repeat the same finite scope to resume after interruption. Completed native facts
remain in the original journal; unaffected blocks are restored without payload
reverification. Repair reports its counted scope, elapsed time, ETA basis and
retry/stall state. The startup planning range covers local open/provider startup
only; it is not an estimate for the selected history or final reward activation.

These same repair commands also repair damaged record-capacity counters before
opening the selected history. They rebuild only record lengths and counts under
the original owner's exclusive locks; signed records and verification results
are preserved. Healthy counters are reused on repeated commands. Missing native
verification identities still require their separate restoration in place;
repairing capacity metadata does not authorize evidence or reset history.

An existing original journal is required. Missing source-identity tables or the
owner marker require restoration of original metadata before reuse. Do not create
an empty success index, move the journal to a replacement identity, or treat stored
proofs as completed checks. This command cannot recover an older running reader's
volatile verified prefix. Keep that owner running through its handoff when
preserving those completed checks requires it.

### Completed original C5 admission migration

`migrate_completed_admission` in
`umi.competition_reward_admission_migration` supports the selected original
installed342 C5 owner after its native sequence-zero admission review completes.
Its prospective root-sealed selection identifies the existing installation,
service invocation, service account, configuration and state-file identities.
The selection asserts no completed verification. Completion requires the
original immutable native admission intent and that owner's matching retained
signature. A certificate, exported proof archive, progress log or raw block
range cannot substitute for this local result; the signature alone does not
authenticate the history digest.

Capture and retain the prospective selection while the original invocation is
still running. At migration, stop that owner through its supported service
lifecycle and prevent competing restart. Keep the original configuration and
installation in place until migration succeeds. The migrator requires the
original account and existing service, control-writer, history-journal and
decision-journal lock files. It refuses a running original invocation, changed
source/configuration or replaced paths; it opens no replacement empty journal.
Never infer exclusivity from a watcher seeing completion. Reconcile the actual
stopped journals while holding all original locks.

The importer validates the exact original series, policy, chain configuration,
manifest and initial decision, then independently verifies the finalized
boundary B. It preserves the original first block A and native rolling history
digest in one atomic completed interval A..B. Repeat execution reuses that
interval. It creates no per-block receipts for A..B and cannot serve a prefix
ending before B. Such a prefix requires separately scoped native recovery;
ordinary restart does not silently replay the whole interval.

An already reserved or certified sequence-one or later decision does not discard
the valid completed admission interval. The result separately reports its
later-record inventory and always requires stopped-owner economics reconciliation;
it never authorizes starting publication. Reconcile the immutable pending intent,
certified prefix and finalized control before allowing any publishing service to
restart. The coordinator resumes retained pending decisions before selecting new
ones; an effective old activation needs the supported suspend, drain and revision
path, subject to retained live-reward evidence. Do not delete an intent, reset a
journal or assume a short completion-to-stop interval removes this race. The
inventory itself does not verify or authorize later economic decisions.

The new reader rechecks the small original native records and current finalized
ancestry of B, then verifies and checkpoints every B+1 onward block normally.
Only A..B is preserved by this migration. Any later process-local tail may need
replay. Report its fixed target H separately: preserved blocks are B-A+1 and
the initial remaining tail is max(0,H-B); a moving finalized target adds work.
Use measured target-runtime throughput once available, or an explicitly labeled
planning range. Never count restored admission blocks as new native throughput
or replicated R2 proofs.

Retain the root seal, original installation provenance, original history and
decision database identities, original signed intent/vote and original raw
history sources. The migration deliberately disables source externalization for
this owner. Missing or damaged completion metadata, provenance, source records
or source fences requires explicit restoration in place; it is not a cache miss.
The four migration milestones report progress, elapsed time, planning ETA and
stalled/interrupted/repair states; this ETA covers the local result import and
one boundary check only, excluding later history replay or reward activation.

The no-launch runner requires the original service UID and loads the exact
configuration selected by the root seal. It inherits the original history,
header-cache, header-database and memory limits. It constructs and starts the
historical proof provider only after acquiring all original owner locks; provider
cleanup finishes before releasing them, including during interruption. It never
loads a signing key or constructs a publishing role. After the original owner
has completed admission and has been stopped and fenced against restart, run:

```sh
"$QUALIFIED_PYTHON" -m umi.competition_reward_admission_runner --selection "$ORIGINAL_OWNER_SELECTION"
```

Use the original service account; running the command as root is refused. The
result reports preserved history and required economic reconciliation. It does
not enable or restart any service, even when no later local decision is present.
Keep publishing services stopped across runner interruption and retry until exact
pending/certified decisions, finalized control and the post-B tail have been
reconciled under the selected runtime. A production cutover still needs that
qualified configuration handoff and restart; runner fixture qualification alone
does not establish deployment. Retain this compatibility route and its source
dependencies while an installed or recovery consumer relies on the completed
interval. Remove them
only after every such consumer has a separately qualified replacement receipt
or complete native per-block results and qualified restart/reward replay.

## Paid service review budgets and retained capacity

For a cohort whose signed tracks permit endpoint paid work, the selected phase
review profile also determines paid-history reads, owner export, native review,
authority refresh, peer exchange, signing and queue/transport allowances. An older
`service_signing.read_timeout_seconds` value cannot shorten that full selected
path. Signed assignment response clocks remain unchanged; a larger transport
allowance cannot extend the remaining signed response interval.

The reviewer configuration check exposes `service_execution_budget`. Treat
`managed_service_path_qualified: false` as an outstanding deployment check: compare
actual owner, reviewer, peer, proxy and unit overrides through
`validate_service_execution_path` before cutover. Printed source-derived budgets
are operating allowances, not completion estimates or proof of a managed route.

Provision reviewer transport for every admitted catalog sharing that journal,
including retained predecessors. Each provisioned claim attempt can require both
a request and a retry intent. `service_review_capacity_requirement` and
`validate_service_review_capacity` expose the selected claim/attempt assumptions;
an attempt assumption does not impose a protocol retry cutoff. Exact retries
reuse the existing intent. Inspect native remaining request/retry/byte capacity
and increase the existing configured envelope before it is exhausted.

`maximum_votes` can increase beyond the former 65,536 ceiling while retaining
original journal identity and bytes; the original explicit value remains in force
until it is provisioned. Byte accounting still applies. This is neither an
automatic capacity increase nor a model-only cohort eligibility change. Preserve
all original signed work and already-earned credit through closure and replay.

## Recoverable cohort model awards

The recoverable cohort implementation separates model payout from reference-model
promotion. Native geometric rewards use `umi-cohort-recovery-authority/4` with
`baseline_or_better_geometric_bands_first_complete/1` and signed
`model_reward_parameters`. The parameters are independently configurable:

```json
{
  "schema": "umi-geometric-reward-parameters/2",
  "band_width_bps": 500,
  "band_decay_bps": 7500,
  "within_band_decay_bps": 7500,
  "score_duplicate_tolerance_bps": 1
}
```

These defaults mean five-point quality bands and a 0.75 multiplier between
successive occupied bands and between successive models within a band. Width
can be any integer from 1 through 10000 basis points. Each decay multiplier can
independently range from 0 through 10000: zero gives all weight at that level to
its first rank, while 10000 gives equal weights at that level. A full-scale width
puts every eligible model in one band. Exact full-scale quality belongs to the
last band, including when the width does not divide 10000.

Before assigning bands, sort eligible distinct content by exact score, then
certified acceptance order. Retain the first model and exclude any subsequent
model whose score is within the signed tolerance of the last retained model,
including equality. The default one basis point is **0.01 points on the 0–100
displayed score scale**. Compare exact rational scores, not rounded displays.
Apply this across band boundaries. Excluded models cannot extend a group: scores
30.000, 29.995 and 29.988 retain the first and third. Exact-score ties retain the
first completed certified acceptance. Exclusion affects public-model rewards
only; independent service-work earnings remain unchanged. Normalize the full
public pool over the remaining models and occupied bands. Version1 parameters
retain their original behavior and bytes; the score rule requires version2.

Existing signed authorities and allocations retain their original bytes and
behavior. Applying geometric rewards or revising their parameters for an
already signed cohort requires a separately signed and explicitly selected
reward adoption. That adoption binds the original certified package and a new
effective allocation; it never rewrites original consent, certification,
service amounts or cohort clocks. Parameter revisions remain possible until
reward activation is verified live on-chain. Original reward verification,
revision lineage, pending transactions and the finalized activation lock must
be qualified across coordinator, reviewer, coverage and writer before cutover.
Public status must identify the selected authority, cohort and adoption.

Select the complete signed adoption lineage in `reward_adoptions` on the
coordinator, reviewers and standing writer. A successor consuming an adopted
predecessor also selects that predecessor's lineage in
`predecessor_reward_adoptions`; its current adoption cannot stand in for the
predecessor's. Omitted fields preserve the original canonical startup bytes.
Keep the original host approval, state directories and journal identities;
the separately signed adoption is selected by the root-owned startup configuration.

Changing the desired adoption stops stale preparations before reservation,
signing and sending. An activation already reserved keeps its exact signed
bytes. The coordinator suspends that activation, waits for finalized proof-lag
and transaction-mortality drainage, then checks every designated writer over
the interval in which those rewards could have become live. Completed native
coverage and revision results are retained across restart. If the old allocation
became live, the coordinator resumes that exact activation and keeps its
economics locked. Otherwise it can publish the selected revision. A current
matching row or an adoption signature alone cannot replace this historical
clearance. Missing retained completion state requires explicit repair; it must
not silently start the complete review again.

The complete sealed model roster must have independently certified quality,
complete preserved bundles and signed rights/reconstruction acceptances. Model
quality version 2 compares both sides with the same normalized baseline metric
on the frozen suite and runtime. Equality qualifies, including an unchanged
baseline or a baseline below the promotion threshold. Exact-content
deduplication uses the first complete certified acceptance's score and
eligibility; later aliases cannot create another benchmark trial. Each eligible
distinct model then enters its fixed quality band. Geometric rewards rank
occupied bands from highest to lowest, skipping empty bands. Within each band,
rank models by exact score, then certified acceptance ordinal, then submission
digest. Normalize the geometric band weights to sum to one, independently
normalize each band's model weights to sum to one, then multiply those exact
fractions. Perform one largest-remainder integer apportionment over **all model
credits**, with equal remainders following that deterministic rank order. Do not
round band budgets first. Aggregate the resulting credits by hotkey, then add
unchanged service earnings and service burn. When no model is eligible, the
model pool goes to burn. Missing evidence remains pending and cannot be removed
from the roster. The native geometric award and allocation are version 4 and version 5,
respectively; historical versions remain readable with unchanged digests.

Duplicate content retains the earliest certified complete-artifact acceptance's
recipient, score and eligibility. A later alias cannot make originally ineligible
content eligible. Distinct runnable content within one band receives successive
geometric ranks. The content digest ignores paths and license/provenance-only
changes; it does not detect semantic copies with changed runnable bytes, so
this is not complete Sybil resistance.

The retained version 3 quality-bucket rule selects one best model per occupied
band, weights those band winners by score, and apportions with band-index ties;
all-zero occupied credits split equally. Earlier single-winner and
content-proportional rules keep their own original native replay. Preserve these
compatibility readers while original signed packages or recovery consumers use
them. An adopted effective allocation is derived from the original complete
candidate evidence, not from the original rule's already rounded winner amounts.

Under the configured `CompetitionStore` directory, the reward owner reads
`model-reward-acceptances/<cohort-sha256>/<submission-sha256>.json` as private
`CertifiedModelArtifactAcceptance` records. Legacy delivery keeps candidate and
baseline bytes at
`model-reward-artifacts/<model-sha256>/{manifest.json,model/}`. Preservation
verifies the bytes while copying and retains a private verification record
alongside the content directory. Readers reuse that record across requests and
process restarts without hashing the model files again. Existing archives without
a record receive one after their first successful verification. Changed file
identity or metadata cannot reuse the old record and holds the operation rather
than silently accepting changed content. The record is host bookkeeping and is
not part of the published model bundle. Current policy, authorization and chain
state checks still run.

An older producer's owner-private, writable version-one receipt cannot authorize
reuse. The native verifier checks that artifact completely once under its normal
lock and, on success, replaces only the local receipt with the current read-only
format. Failed verification preserves the old receipt and model. Other unsafe
receipt ownership, links, permissions or identities remain errors; operators do
not need to reset a model or edit its manifest.

Each settlement service starts a bounded artifact-preparation worker alongside
its normal request-export and settlement tasks. It begins during intake and
requests, before request closure or reference release. Each pass prepares at
most two entries in rotating order; missing or invalid entries stay pending
without preventing their siblings from being prepared. Local legacy archives
need no configuration change. Successful native verification receipts survive
restart and are reused by final settlement. Preparation has no signing, scoring
or phase-transition authority, and its per-pass ready count is not a count of
certified results.

For direct R2 delivery, acceptance export also publishes the original
`ModelReviewRequest` under
`model-reward-preparation/<cohort>/<submission>.json`. The `model-evidence`
replication profile delivers it with the acceptance certificate. Each settlement
signer checks the certified submission bindings, then uses its own read-only
R2 verifier and private receipts to prepare the accepted object. No local model
copy is created. Unchanged bytes are not downloaded again on restart or final
settlement; ordinary object identity and authority checks still apply. Retained
older acceptances without this publication remain supported by the final
settlement path.

Completed request evidence continues to be exported independently while these
checks run. Final cohort quality decisions, allocation and signatures still
require the original certified request closure and reference release. Background
preparation cannot replace missing work or move those signed boundaries.

When assembling original settlement inputs, the settlement service supplies
missing Quicknet pulses in its own service account and mount namespace. Native
replay chooses each exact original reveal round; the producer fetches that round
from the pinned Quicknet chain, verifies the chain information, BLS signature and
randomness, then atomically retains the canonical pulse in `pulses_directory`.
Allow that service HTTPS access to `api.drand.sh`. It uses the native
`QuicknetClient` network profile: 15-second connect/read/write/pool timeouts,
64 KiB response bodies, 16 KiB headers, no redirects and no proxy environment.
These are bounds for one exchange, not a cohort completion deadline. An outage
returns to the service's configured polling loop; retries have no finite count
or overall elapsed-time cap. Completed pulses survive later failures and restart.
Cancellation interrupts the active async transfer, drains its HTTP cleanup and
prevents another round from starting. The HTTPX timeouts are inactivity bounds,
not a guarantee that a responsive, slowly streaming exchange finishes in 15 seconds.

Each retained pulse is reread and verified; conflicting, corrupt or unsafe files
hold settlement rather than being replaced. Exact retries preserve bytes and
repeat publication durability. The producer has no signing or phase-transition
authority and never substitutes a current round or resets a signed clock.
Already retained settlement packages use their original embedded pulses without
network access. A package recorded as reviewed remains restore-only if lost.
`settlement_pulse` logs expose the original round and `fetching`/`retained` status,
without private input contents or paths.

Reference reveal preserves the commitments in the original signed service
catalogs. Retained materializer references can use plain SHA256 of sorted,
compact, ASCII-escaped JSON. Native readers accept that historical encoding only
for a fully validated `umi-cohort-service-reference/1`, reconstruct its exact
committed bytes from private wrappers and replay packages, and verify its catalog
case, video and stratum bindings. Other objects keep their native canonical bytes
and domain-separated identities. Restore missing originals without changing
catalogs, reference text, salts or hashes; answers remain private until certified
reference release. Retain this decoder while any signed catalog or replay package
depends on that encoding.

Qualify a schema or encoding change with a retained-artifact matrix before
cutover. Record the producer runtime, original schema and byte/hash pins, each
consumer runtime and the result at publication, certification, reward replay and
restart. Run the actual retained signed artifacts through supported readers
without re-signing or normalizing their bytes; keep private payloads local.
Synthetic fixtures establish behavior but do not establish that every deployed
historical generation has been checked. Include both typed and historical
reference identities in one package, interruption before publication, delayed
restart after publication, repeat execution and cold downstream replay. Preserve
existing journals and directory bindings throughout. Retire a compatibility
reader only after confirming that no deployed or recovery consumer retains its
historical inputs.

Before advancing intake or preparation for a cohort with paid service work, the
lifecycle owner reads the selected terms, signed catalogs and every committed
reference from its configured private settlement sources. Missing, changed or
unreadable inputs hold progression before new requests open; a prior bootstrap
receipt cannot satisfy this check. The check repeats after restart and bypasses
signed model-only cohorts. Already running requests and settlement recovery keep
their existing evidence rules and do not acquire a new startup gate.

During legacy upload completion, each finished staging file likewise retains a
private verification record. Later completion passes and restarted uploaders
reuse it while other files are still arriving. These temporary records are
removed with the upload staging tree after the complete archive is preserved.

For a cohort whose signed model-delivery profile selects direct R2 multipart
delivery, acceptance version 2 also carries the owner's signed immutable R2
reservation. Before publishing acceptance, the owner uses server-side multipart
copy to place the verified payload at
`preservation/v1/<cohort>/<model>/<payload>/payload`, rereads and verifies every
byte, retains a promotion receipt, and deletes the exact incoming object. A
lost cleanup acknowledgement retries from that receipt without recopying.
Settlement config version 4 requires `direct_model_review` source schema 2 with a
read-only credential for the selected bucket and the same standing review
policy used at intake. Every settlement signer independently streams and
verifies the complete preserved object once before signing. Standing reward
coordinators, reviewers and validators repeat that check from their own
read-only credentials before activation review or package replay. Each retains
a small private receipt under its own state and checks the current object length
and ETag on replay. The completed byte result also binds the authenticated R2
endpoint and bucket, exact object key, signed bundle and payload, policy, cohort,
owner and qualified verifier semantics. Reuse reads only object metadata and the
bounded private result, including the original rights documents. It does not
download or hash the weights again, and one owner's receipt never substitutes
for another owner's independent verification. Missing or damaged owned results
trigger explicit native repair with progress and an ETA; unsafe links, ownership
or permissions are refused. Candidate archives are not copied into a
`promotion_directory`; the frozen baseline remains in the native local archive.
A missing or changed preserved R2 object keeps settlement or activation pending
or held. No consumer falls back to another object, URL or local candidate.

Both acceptance versions bind policy, authority, submission, recipient,
content, rights/reconstruction evidence, acceptance block and ordinal.
Reviewers must retain the original review documents in the content-addressed
evidence source. The signatures attest review; a file hash does not establish
permission to use or redistribute a model.

Allocation version 4 carries the bucketed model decision and its signed
acceptances. Portable package replay includes the original review documents,
replays quality, deduplication, band selection and allocation, and checks
independently retained artifact bytes. Recovery uses the original acceptances
without selecting a newer promotion or
assigning authorship to the reward recipient. Existing cohort certification and
standing chain checks still apply before any weight transaction.

Retained allocation versions 1 and 2 and the signed
`baseline_or_better_best_score_first_complete/1` rule keep their original
semantics for historical package replay. Selecting the proportional rule changes
the authority digest and requires fresh pre-intake consent. Never reinterpret
an existing certified allocation under new distribution rules.

The intake owner reserves artifact-acceptance proposals under its existing lock,
after admission certification and verification of all model bytes. It retains
the original review documents, block and completion ordinal before requesting
review. Independent reviewers approve that exact proposal; the intake owner
cannot sign on their behalf. A retry preserves the reserved position. The
ordinal records when the complete bundle and review documents were reserved,
not when the last review response reached the coordinator.

For authority version 3, intake remains open until every selected model has a
certified artifact acceptance. Missing evidence neither drops a participant nor
closes the phase. Private intake review export version 2 includes the full set
of model acceptance certificates so independent closure reviewers check the
same condition. Legacy intake and review export bytes remain unchanged.

The service-admission host polls private `model-reviews/<model-sha256>.json`
inputs and publishes retained `ModelAcceptanceIntent` records under the
competition store's `model-acceptance-proposals/<cohort>/<submission>.json`.
Service-admission host version 2 selects `model_review_peers`, each with an
evaluator hotkey, private review origin, private `token_file` and request timeout.
Use HTTPS across hosts or the explicit literal-loopback HTTP transport described
in the [private reviewer configuration](../validators/successor-upgrade.md).
Shared token files must retain matching signer and origin bindings across peer
lists. The recurring worker collects votes at `/internal/cohorts/model-artifacts/votes`,
retains each response in the original intake ledger and forms a certificate
only from independent policy groups. A disconnected peer leaves that entry
pending while other peers and entries continue. Restart reuses collected votes
and the original proposal, including its acceptance ordinal.

On each private reviewer, phase-review host version 4 adds `model_signing`
(`ModelReviewConfig`) alongside admission signing. Select distinct private
journal, approvals and artifact directories. The approvals directory contains
explicitly reviewed `ModelArtifactReviewInputs` at `<model-sha256>.json`; the
artifact directory contains native preserved bundles. Deliver and review these
inputs before asking for a vote. The HTTP proposal supplies their hashes, never
replacement approval documents, artifact URLs or executable code. The reviewer
verifies its local bundle, matching approved documents, certified participant
admission and current cohort authority. It reserves the original intent and
ordinal before signing; a committed vote can be returned without files or RPC.
An unfinished intent retains its documents but rechecks current authority.
Include the model journal in the reviewer's systemd `ReadWritePaths`; approvals
and model bytes need only read access.

The worker checks the original proposal, quorum, submission and model bytes
before retaining acceptance. It exports review documents under `objects/` before
publishing the certificate under `model-reward-acceptances/`. Replication must
deliver those documents and certificates to each settlement consumer. Legacy
delivery also replicates full bundles into each model archive. Direct R2
delivery uses the signed reservation carried by acceptance version 2 and each
consumer's read-only R2 credential instead. Pending entries do not prevent
siblings from being processed. Completed entries replay from retained state
before RPC, reviewers or original delivery inputs are consulted.

Host version 1 retains the private certificate-delivery path:
`model-acceptance-publications/<cohort>/<submission>.json` contains a complete
`ModelAcceptancePublication`. Both paths perform the same quorum checks.
Complete artifact ingestion, independent artifact-acceptance votes, replication
and installed coordinator qualification remain required before production
selection. Configure one standing review policy before intake. The delivery
worker applies it mechanically to complete bundles and retains the exact source
documents; the recurring vote service verifies those inputs independently.

For new cohort deployments, use admission-host schema version 8 and set
`model_uploads.admission_reviews_directory` to the owner's private
`ModelArtifactReviewInputs` directory. Also set
`model_uploads.standing_review_policy` to a policy that binds the exact
competition policy, contribution terms and retained operator approval. Upload
and preservation may finish before review. The worker publishes deterministic
review inputs once the complete bundle passes; missing, unreadable or oversized
documents produce a retained hold reason. An artifact that cannot pass review
never enters the cohort roster and therefore cannot hold sealing or settlement
open. Earlier host schemas retain their original behavior for recovery replay.

## Lost coordinator outcomes

A dispatched claim without a durable response remains uncertain. Never resend it,
mark it completed, or synthesize a miner failure. The ordinary paired-evidence
path still requires every original transcript.

A successor verifier can accept an explicit `umi-coordinator-outcome-repair/1`
amendment signed by **every evaluator assigned to the original order**. This is
a separate authorization to issue a neutral `coordinator_outcome_unavailable`
void. It does not establish whether the request reached the miner. The amendment
binds the unchanged policy, round (including its complete roster), order,
publication, submission, original claim digest and times, bounded retention-search
audit, and predecessor/successor release identity digests. It may be signed only
after each affected request's deadline and no later than the existing evidence
cutoff, using a fresh owned finalized capture. The normal void and settlement
signatures and actual local receipt by cutoff remain mandatory.

The affected evaluator retains the signed amendment privately at
`<evaluator state_directory>/dispatch-repairs/<order digest>.json`. The evaluator
checks the original uncertain claim, replays every available transcript and the
actual incumbent execution, and signs an unavailable-evidence observation. Other
evaluators retain their complete observations. The new void and void-evidence
schemas use version 2. Unknown responses have no fabricated `CaseOutput` or score.
The original dispatcher claim remains unchanged, including its reserved proof
allowance. This path does not reclaim scheduling capacity or enlarge any window.

Build and qualify a compatible worker and host before obtaining the scoped repair
signatures. Existing workers reject the new evidence. For delivery, retain the
original queue configuration and journal binding, then place the exact successor
`CompetitionReleaseIdentity` at
`<settlement delivery state_directory>/repair-releases/<round digest>.json`.
The queue requires the amendment's predecessor to match its original configured
release and its successor to match this file. Package preparation and loading
also enforce the signed successor identity. No journal reset or ordinary release
substitution is permitted. Publisher plans and follower consent must separately
bind the new verified release; none of these files activates weights.

For future dispatch, optional `transcript_spool` in the dispatcher configuration
contains a separate absolute private `directory`, `maximum_assignments` (default
4096), and `maximum_bytes` (default 8 GiB). Capacity is reserved before claiming.
The dispatcher durably retains request intent before sending and the actual
outcome before completing the scheduling journal. Restart recovery consumes only
stored outcomes with their original claims and never contacts a miner. An intent
without an outcome remains uncertain. The spool retains private authentication
and response bytes, so keep it private and include it in bounded recovery searches.
Omitting the option preserves historical configuration bytes and behavior.

<a id="open-competition-settlement-preparation"></a>

## Automatic settlement preparation

The round coordinator can prepare an unsigned settlement proposal after a
round's evidence cutoff. It reads completed independent evidence from the same
competition store that the evaluator exchange writes. No operator assembles
the roster or chooses which successful miners to include.

This output still needs independent review and settlement signatures. It does
not activate a policy, change weights, or prove independent receipt timing.
The current bridge services are unaffected.

<a id="open-competition-settlement-preparation--configuration"></a>

### Configuration

Add `settlement_directory` to the private
[`umi-round-coordinator-config/2` configuration](rounds.md#open-competition-round-coordinator).
Use an absolute path owned by the service user, separate from every other
coordinator directory. Configure this when establishing the coordinator's state;
an existing journal is bound to its original configuration. Do not delete a
journal to enable the option. The output directory uses mode `0700` and files
use `0600`. Omit this setting to keep the existing preparation behavior.

The coordinator and evaluator exchange must use the same policy-bound intake
store. That store needs the preserved baseline, admitted roster, fixed cutoff,
and completed independent evidence received by cutoff. A model reward share
also requires a qualifying promoted contributor in the preserved history.
Importing Michael's baseline alone does not establish that attribution.

The existing private round plan supplies the committed suite and original
windows. The coordinator's owned finality provider supplies the current
registration snapshot; an HTTP caller cannot choose it.

Settlement capacity follows the coordinator's `replay_limits` and the
evaluator's matching `settlement_replay_limits`. Profiles with at most 64 MiB
of evidence keep the existing 64 MiB proposal envelope and four-proposal page.
For larger profiles, the proposal envelope includes evidence, another roster,
two certificate allowances and 1 MiB of framing, rounded up to 64 MiB. The
maximum envelope is 512 MiB; configurations that exceed it are rejected.
For example, 256 MiB evidence with 4 MiB roster and certificate limits selects
a 320 MiB proposal envelope, one proposal per reply, and one active settlement
request through response transmission. The reply allows another 8192 bytes.
Private proposal files and settlement journals use the same envelope.

Package limits are configured separately: allow framing above the replay
evidence allowance and increase the aggregate package budget accordingly.
These changes do not increase native per-order reservations or total journal
budgets. Replay limits are part of retained configuration bindings; establish
the larger profile in newly staged state or use a separately reviewed migration.
Do not overwrite an existing journal's bound configuration or delete its state.

Aggregate package and request-export canonicalization traverses object inventories
one typed object at a time, including signed response envelopes. Domain checks,
size checks, digests and exact-byte comparisons use that same traversal. Plain
aggregate JSON parsing validates inventory objects individually, then applies the
original tuple constraints and aggregate validators through an operation-private
parser. The shared model schema remains unchanged. Unsupported schemas and input
forms retain the ordinary full-document parser. Private publication retries still
validate the complete retained schema, and reward preparation retains a detached
input snapshot while replay is active. No signed
bytes, evidence limits or validation requirements change.

Byte envelopes are not process memory limits. A caller model, its canonical bytes
and a validated snapshot can coexist; metadata and one serialized object also
need memory. Evidence is still replayed, and request timeouts still apply. Qualify
full-sized structured evidence on the intended host, including concurrent model workloads,
before relying on a larger profile for settlement timing or memory headroom.

<a id="open-competition-settlement-preparation--output-and-retry-behavior"></a>

### Output and retry behavior

For each usable complete round, the service writes:

```text
<round-digest>.settlement-proposal.json
```

Schema `umi-settlement-preparation/1` contains the signed cutoff, unsigned
settlement publication, exact signed roster and complete independent evidence.
The retained settlement includes the revealed suite, registration snapshot,
promotion-head binding and deterministic reward projection. Keep these files
private. They contain references and are excluded from cutoff/work discovery.

The store selects the earliest retained evidence per roster entry, with a
digest tie-break. Evidence received after cutoff cannot fill a missing entry.
Every frozen roster member must have either a scored result or a certified void
received by cutoff. A void retains all assigned evaluators' signed observations
and a separate agreement on the reason. It gives no score or reward attribution.
Missing work or quorum still blocks the round; neither can silently reduce the
roster or become a scored miner failure.

Mixed outcomes use `umi-competition-settlement/2` and
`umi-competition-replay-evidence/2`. Each void binding includes the decision
digest, full evidence digest and first observed block. Scored-only records keep
their version-1 encoding and digests. Conflicting scored/void outcomes or distinct
void decisions hold the round and dispute any existing settlement. Valid
signature variants alone do not change the decision identity.

After the first settlement, retries use its exact evidence identities and
original snapshot. A newer snapshot or another signature ordering does not
rewrite history. A crash after the database commit can be repaired by publishing
the same retained proposal. Original round expiry still applies. The existing
version 1/2 projection rejects an absent model contributor. Version 3 supports
the explicit [unallocated-model burn](../competition/launch.md),
with finalized proof of its destination. There is no endpoint-only fallback.

Each read uses one SQLite snapshot and checks stored sizes before loading
bodies. The existing replay limits also bound the combined roster and evidence;
the complete proposal has a 16 MiB ceiling. Configure filesystem quotas for
proposal files and the shared database. Four usable settlement rounds are
considered per poll, with a wrapping cursor so old rounds cannot monopolize it.

Poll summaries add `settlement_prepared`, `settlement_incomplete`, and
`settlement_held`. Alert on repeated incomplete/held rounds before expiry.
Do not delete a retained settlement to retry with more convenient inputs.

Later quorum conflicts hold subsequent preparation and mark the retained
settlement disputed. An existing file remains historical evidence. Its presence
must never override current conflict checks in the signer or successor worker.

<a id="open-competition-settlement-preparation--remaining-publication-work"></a>

### Remaining publication work

The [independent settlement signer](settlement.md#open-competition-settlement-signing)
checks local execution receipts and reviewed promotion history, re-proves the
registration snapshot, and retains signing intent before signing. Optional
[automatic delivery](settlement.md#open-competition-settlement-delivery) connects discovery,
eligible-group certificate collection and immutable replay packages.
A coordinator proposal alone is insufficient.
Signed activation and finalized incentive checks follow that connection and
the reviewed-input gates in the [execution plan](../competition/launch.md).


<a id="open-competition-settlement-signing"></a>

## Independent settlement signing

`IndependentSettlementSigner` reviews an unsigned settlement preparation using
one evaluator's own journals and finality provider. It returns one hotkey
endorsement. That endorsement alone is neither a quorum certificate nor
permission to submit weights.

The signer is used by the optional
[automatic delivery path](settlement.md#open-competition-settlement-delivery), which connects
proposal discovery, vote collection and replay-package publication. This code
does not change either deployed bridge validator.

<a id="open-competition-settlement-signing--inputs-and-local-checks"></a>

### Inputs and local checks

Construct the signer with the running `ContinuousEvaluator`, that evaluator's
cutoff-signing journal, its local `EvaluatorReviewStore`, and bounded
`PublicationReplayLimits`. Call `await signer.endorse(preparation)` with an
[`umi-settlement-preparation/1` proposal](settlement.md#open-competition-settlement-preparation).

The signer requires:

- Its own signed cutoff reservation, exact frozen roster and suite reservation.
- A completed local evaluator slot for every roster member, without a conflict
  hold. The retained independent evidence must match the proposal exactly.
- A local receipt showing that complete independent evidence was retained by
  cutoff. The matching signed execution announcement must reproduce the
  evaluator's run in the independent evidence.
- A promotion head matching the evaluator's local reviewed history. The
  proposal cannot initialize that history or import a contributor attribution.
- An exact registration snapshot re-proved through the evaluator's owned
  historical finality provider, and a fresh head inside the signing window.

The publication replay verifies the complete roster, result signatures and the
deterministic allocation bound by the active authority. A signer cannot be a roster submitter,
positive-weight recipient, promoted contributor, or a member of a policy
control group containing any of those identities. Quorum still requires the
configured number of distinct eligible groups. UID 0 and UID 54 operated by us
do not become two independent evaluators.

The [local review store](exchange.md#open-competition-review-history) receives cutoff and
roster history during independent work signing, at its actual receipt block.
Its baseline and promotions still require the preserved-bundle and signed
rights/quality review path. Copying the coordinator's SQLite database is rejected.
An empty promotion history blocks signing. This component provides no automatic
review approval. Known promotion and settlement conflicts remain blocking.

The reviewed histories must agree on the exact promotion record and parent link.
Legacy v1 records include an observation block, so creating similar records at
different blocks produces different digests. The versioned
[promotion agreement](promotion.md#open-competition-promotion-agreement) separates a shared
v2 decision from each operator's actual receipt block and full certificates.
The signer revalidates the bounded local receipt before using a v2 head.
The deployed review/distribution workflow still needs independent-operator
rehearsal; this signer never substitutes the coordinator's head to resolve a
mismatch.

<a id="open-competition-settlement-signing--evidence-timing-and-restart"></a>

### Evidence timing and restart

Before publishing completed independent evidence, the evaluator now saves an
`umi-independent-evidence-observation/1` receipt with its current owned finalized
boundary. A receipt is local provenance, not a proof of global network receipt
time. If a crash occurs after evidence retention but before receipt persistence,
recovery uses the actual restart observation. It never backdates a receipt from
an execution timestamp, relay claim or file modification time.

The coordinator's first-observation fields retain their existing meaning. A
signer checks its own evidence was also retained by cutoff; different operators
need not claim they first saw it at exactly the same block. The publication's
`finalized_receipt_timing_proven` field stays false.

The signer reserves the exact publication and suite before calling the hotkey.
A changed valid publication for the same round sequence creates a durable hold.
An exact retry returns the retained vote after checking current local state.
A missing vote after a crash can only be regenerated for the reserved bytes.
Never delete the journal to choose another settlement.

Owned finality is checked again after proof collection and evidence replay.
Missing evidence, a late local receipt, changed promotion history, an expired
snapshot, or a conflict discovered during collection blocks signing. No miner
is silently removed to make the remaining roster settle.

<a id="open-competition-settlement-signing--verification-scope-and-remaining-work"></a>

### Verification scope and remaining work

The tests exercise complete allocation publication signatures and signing-state
failure cases. Separate execution tests check model journals and the actual
authenticated endpoint-response path against the local-evidence verifier.
The combined service test additionally runs both tracks through scheduling,
execution, promotion and signed settlement using synthetic data and chain ports.
It does not establish real-model quality or independent administration.

The delivery tests additionally cover authenticated proposal discovery,
certificate collection and immutable package publication. The integrated
protected-data rehearsal, reviewed launch inputs, signed activation and finalized
incentive evidence remain required for a new allocation. Read required and
optional evaluators, control groups, enabled tracks and pool shares from the
signed cohort plan. Optional redundancy cannot hold settlement, and validators
under one administration do not supply independent votes. A successor plan may
change an unopened cohort before intake. Model-specific rights
approval and a qualifying acceptance are required before paying a contributor.
Importing the baseline grants no contributor reward by itself. See the
[allocation rule](../competition/launch.md).


<a id="open-competition-settlement-delivery"></a>

## Automatic settlement delivery

The round coordinator can collect independent settlement signatures and publish
an immutable replay package. Evaluators discover proposals through authenticated
HTTPS and sign only after the [local settlement checks](settlement.md#open-competition-settlement-signing).
No separate upload key or manual certificate assembly is required.

This path does not approve model rights, import a promotion head, activate a
reward allocation, or submit chain weights. It leaves the deployed bridge
unchanged.

<a id="open-competition-settlement-delivery--coordinator-configuration"></a>

### Coordinator configuration

Enable `settlement_directory` as described in the
[preparation guide](settlement.md#open-competition-settlement-preparation), then add a
`settlement_delivery` object to `umi-round-coordinator-config/2`:

- `state_directory`: private durable proposal, vote and certificate journal.
- `certificate_directory`: private certificate and package-reference output.
- `package_directory`: immutable content-addressed replay packages.
- `package_limits`: explicit `CompetitionPackageLimits` for every package file
  and the aggregate package. See [package rehearsal](../reference/commands.md#immutable-settlement-package-rehearsal).
- `release_identity`: reviewed `CompetitionReleaseIdentity`, including the
  exact revision, release manifest and bundle digests, and target triple.

All directories must be absolute, owned, private, and separate from each other
and the existing coordinator paths. These settings become part of the durable
journal binding. Configure them when provisioning; never delete a journal to
change bindings or bypass an expired round. The coordinator needs no wallet.

Expose `POST /v1/competition/settlements` on the same credential-free HTTPS origin
as the round service. Disable body logging and caching. Enforce a 16 KiB request
limit and reject compression at the proxy. Discovery is restricted to policy
evaluators, with short-lived hotkey signatures and replay-protected nonces.
Unlike the pre-reveal work feed, these responses contain the revealed reference
suite. Do not expose them as public miner discovery or static downloads.

<a id="open-competition-settlement-delivery--evaluator-configuration"></a>

### Evaluator configuration

In each `umi-evaluator-config/1`, supply:

- `round_coordinator_origin`: the coordinator HTTPS origin.
- `settlement_review_directory`: this evaluator's independently reviewed
  `CompetitionStore`, separate from all other evaluator paths.
- `settlement_replay_limits`: reviewed `PublicationReplayLimits` for roster,
  evidence and certificates.

For an evaluator on the coordinator host, an operator may explicitly configure
`settlement_loopback_port` (integer 1–65535) before initializing its journals.
Only settlement discovery and vote requests then connect to
`http://127.0.0.1:<port>/v1/competition/settlements`. The listener must be the
native coordinator service on that host. The public HTTPS origin remains the
logical coordinator identity and the connection used by cutoff and work signing.
The local port is retained in both evaluator configuration and settlement source
bindings; changing, adding or removing it on existing bound journals is rejected.
Do not rewrite those bindings or remove journals to enable this option.

This connection uses cleartext exclusively on literal IPv4 loopback. It is for
an explicitly authorized co-located deployment, with no DNS lookup, environment
proxy, redirect following, or fallback to the public origin. Native signed
queries, response bindings, independent evidence checks, finality, conflicts and
expiry still apply. Other hosts must use HTTPS and a route whose proxy deadlines
have been qualified for the complete query and certification operations.

Profiles with preparation capacity above 64 MiB allow 7,200 seconds for a server
operation, 7,260 seconds for a client read, and 7,320 seconds for a complete client
request. Legacy profiles retain 25/30/35 seconds. These budgets do not extend
protocol signing windows or upstream proxy deadlines. In particular, Cloudflare
documents a [125-second default proxy read timeout and a 30-second proxy write
timeout](https://developers.cloudflare.com/fundamentals/reference/connection-limits/);
increasing this client's budget alone cannot qualify that route.

Blocking settlement formation, journal replay, certificate/package work and
response serialization run in owned threads. Async finality providers and locks
stay on the service event loop. Background formation shares the settlement
queue lock with HTTP replay, so requests can authenticate promptly before
waiting without allocating a second full cohort. Cancellation or an operation
timeout drains the active worker before releasing its lock or request slot;
shutdown may therefore take longer than the requested timeout. Signed nonce
admission freshness, snapshot age, conflict checks and signing deadlines are
unchanged. The generous operational budgets do not extend those deadlines.

The worker polls, endorses and returns votes automatically. It uses its existing
hotkey and owned finality provider. Each endorsement still requires the worker's
own cutoff reservation, completed local execution for every roster member,
by-cutoff evidence receipts, and the exact locally reviewed promotion history.
An empty review store blocks signing. Copying the coordinator database is not
independent review. UID 54 and optional UID 0 under our administration count as
one group.

<a id="open-competition-settlement-delivery--delivery-and-recovery"></a>

### Delivery and recovery

The coordinator checks its current intake conflicts, retained settlement,
complete evidence and promotion head before accepting votes or publishing.
Independent eligible control groups must meet the policy quorum. The first
certificate is retained before package creation; later signatures cannot alter
its bytes. A failed write is retried by the coordinator's next preparation poll.

Discovery page and preparation bounds follow the configured settlement capacity;
large profiles send one proposal per page.
The snapshot-age limit and original round expiry apply throughout collection.
Expired proposals remain historical records; their deadlines are never shifted.
An expired retry can acknowledge an already retained vote but cannot create a
new current publication. An outstanding local conflict holds further delivery.

Successful delivery writes:

```text
<publication-digest>.certificate.json
<publication-digest>.package.json
```

The digest is the domain-specific settlement publication digest. The package
reference points to the existing eight-file sealed replay package. Its
`chain_submission_authorized` flag remains false. Successor activation and its
weight-worker verification are separate from this publication step.

Provision filesystem quotas for package storage as well as the bounded journal.
Logical journal capacity does not include SQLite overhead or sealed packages.
Alert on repeated `settlement_held`, missed windows, insufficient signatures,
and disk exhaustion. Preserve journals and certificates during recovery.

<a id="open-competition-settlement-delivery--verification-scope"></a>

### Verification scope

The delivery tests use synthetic keys and an in-process HTTP transport. They
exercise coordinator polling, a complete legacy 70/30 settlement, two endorsements,
package replay, restart recovery and rejection paths. Their local-execution
fixture is isolated; they do not prove model quality or independent operators.
The complete protected-data scheduling-to-execution rehearsal, agreed promotion
history, reviewed rights, signed activation and finalized incentive evidence
remain launch requirements.


<a id="open-competition-round-publisher"></a>

## Per-round successor signing

The publisher signs a settled round's weight authorization and v4 supervisor
directive under explicit release-authority controls. It runs separately from
the wallet-free coordinator. It does not submit a chain transaction or change
the running validators.

The local command supports one supplied package or polling completed coordinator
rounds with wallet-free feed delivery. Production HTTPS routing and the live
host handoff still need rehearsal. Do not use this command as a launch
announcement or a replacement for the signed initial supervisor upgrade.

When the retained store carries submissions from earlier policies, pass each
canonical private policy file with `--predecessor-policy`, from the immediate
predecessor to the oldest admitted policy. Both supplied-package and follow
modes accept the repeated option. The publisher checks the contiguous lineage
and preserves the existing contribution terms before opening the store or
loading authority wallets. A package's embedded lineage does not replace these
operator-selected inputs. Without the option, only the current policy is
admitted; another publisher invocation cannot supply its lineage implicitly.

During follow operation, validated private-mutex contention reports
`waiting_for_local_state` / `private_state_busy` and retries at the configured
poll interval. The same publisher, finality provider and replay cache stay open.
The report identifies the lock operation and a stable resource hash, without a
private path. Retained signing and delivery history are reconciled on retry,
including contention after signing or after delivery with a lost acknowledgement.
Signature, journal-integrity, permission and unrelated I/O errors still fail
validation. Do not delete journal files or remove locking to clear a busy report.

<a id="open-competition-round-publisher--inputs"></a>

### Inputs

Use a canonical, private `umi-successor-publisher-config/2` JSON file containing:

- `plan`: the fixed policy digest, supervisor trust configuration, operator
  consent, release identity, verifier pins, weight requirements and validity
  limits from `umi-successor-round-publication-plan/1`, the renewal-enabled `/2`,
  or the bounded settlement-reuse `/3` described below.
- `public_launch`: the exact `umi-competition-public-launch/1` identity bound to
  the retained intake store. For the first public round, these config fields are:

  ```json
  {
    "schema": "umi-successor-publisher-config/2",
    "submission_head_checkpoint_directory": "/ABSOLUTE/PRIVATE/SUBMISSION-HEAD-CHECKPOINT",
    "public_launch": {
      "schema": "umi-competition-public-launch/1",
      "round_schedule": {
        "schema": "umi-public-round-schedule/1",
        "intake_opened_block": 9085463,
        "roster_close_earliest_block": 9135843,
        "roster_close_latest_block": 9135903,
        "work_signing_close_block": 9135963,
        "evaluation_close_block": 9156243,
        "protected_reference_reveal_block": 9156263,
        "evidence_cutoff_block": 9156383,
        "round_valid_through_block": 9156983
      },
      "eligible_tracks": ["endpoint"]
    }
  }
  ```

- `chain`: the process-owned finality/proof configuration. Its policy, chain
  family and selected verifier hashes must match the plan.
- `intake_directory`: the existing retained competition store. Missing intake
  history is an error; the command cannot create a replacement empty source.
- `submission_head_checkpoint_directory`: the exact external checkpoint used by
  intake, the coordinator, and any intake-enabled exchange. It must remain
  separate from every component state tree.
- `publication_directory` and `replay_directory`: separate private state roots.
  They must not overlap each other, intake, checkpoint, or finality state.
- `replay_capacity`, `maximum_rounds` and `maximum_journal_bytes`: explicit local
  storage limits. Existing records are retained when these limits are reached.
- `authorization_wallet` and `directive_wallets`: explicit release-authority
  wallet references (`wallet_name`, `hotkey_name`, `wallet_path`). The configured
  directive signature threshold must be met by distinct trusted hotkeys.

Supply the reviewed policy and the coordinator's canonical
`umi-prepared-competition-replay-package/1` descriptor separately. All three
input files must be owned private regular files in private directories.
Complete the [writer-generation cutover](../reference/commands.md#owned-finality-intake-v2-cutover)
before this publisher or any other version 2 process opens a legacy intake
database.

```sh
python -m umi.competition_successor_publisher_cli \
  --config /absolute/private/publisher.json \
  --policy /absolute/private/policy.json \
  --prepared-package /absolute/private/settled-round.package.json
```

Stdout is the signed publication. Errors omit input payloads and wallet paths.
No coldkey is requested. These are release-authority signatures, not validator
weight transactions. Never mount these authority hotkeys into the coordinator
or a model-execution container.

<a id="open-competition-round-publisher--wallet-free-delivery"></a>

### Wallet-free delivery

Add `--feed-config /absolute/private/feed.json` to retain the signed result in
the delivery journal after the current signing checks. The canonical, private
`umi-successor-feed-config/1` file contains:

- `directory`: a private delivery journal separate from signing, replay, intake,
  finality and wallet directories.
- `plan`: the exact same approved publication plan.
- `execution` and `worker_limits`: fixed worker execution settings and ceilings.
- `maximum_rounds` and `maximum_journal_bytes`: bounded retained history.

The feed verifies the signed record, replays its complete package, validates
execution settings and requires a continuous predecessor chain before retaining
the export. Retries retain the same bytes. A different export at the same
sequence places the delivery journal on hold.

Run the wallet-free HTTP process separately:

```sh
python -m umi.competition_successor_feed \
  --config /absolute/private/feed.json --port 8094
```

It binds loopback only. The operator must route the installed directive origin's
`/successor` path to this service through HTTPS. For configurations whose installed
origin is R2, use the disabled-by-default
[successor feed relay](../../deploy/successor-feed-relay/README.md) to copy this
service's public protocol objects to that existing address. Do not change an
installed trust configuration merely to point it at a new origin.
Supply only its delivery journal,
configuration and the exact sealed package directories. Do not mount signing
wallets, authority state or the intake database into this process. Release
archives continue to use their separately signed immutable URLs.

GET serves cursor pages, hash-addressed authorizations, per-directive execution
settings and the nine declared replay-package files. The package descriptor and
its local filesystem paths are never served. There is no POST or HTTP signing
route. Cursor pages use `no-store`; immutable objects retain their exact bytes.
Concurrent reads are bounded; cancellation drains a read before releasing its
quota. Expired signed history remains available for validator catch-up and does
not renew an authorization.

If signing completed but delivery failed, recover the original signed export
without loading any wallet or collecting a new signing timestamp:

```sh
python -m umi.competition_successor_feed \
  --config /absolute/private/feed.json \
  --publication /absolute/private/original-signed-publication.json \
  --prepared-package /absolute/private/original-round.package.json
```

Recover missing predecessors in order. The source sealed packages must remain
available. No history or package is automatically evicted to free capacity.

Each directive's `page.json` supplies its exact immediate predecessor and signed
head. The host integration still needs to assemble the continuation from its
own root-sealed activation anchor, including catch-up across multiple feed
pages. A successful package download alone does not prove that host handoff.

<a id="open-competition-round-publisher--automatic-completed-round-publishing"></a>

### Automatic completed-round publishing

Use `--follow-config` instead of `--prepared-package` to poll the coordinator's
completed-package directory. The canonical private `umi-successor-follow-config/1`
file contains:

- `certificate_directory` and `package_directory`: the exact separate roots
  used by the coordinator's settlement-delivery configuration. They must already
  exist and must not overlap authority, wallet or execution state.
- `maximum_rounds`: the retained source limit, no greater than the signing and
  delivery journals' limits. The default is 1024.
- `poll_interval_seconds`: 2 to 60 seconds, default 15.

```sh
python -m umi.competition_successor_publisher_cli \
  --config /absolute/private/publisher.json \
  --policy /absolute/private/policy.json \
  --follow-config /absolute/private/follow.json \
  --feed-config /absolute/private/feed.json
```

Add `--once` to perform one tick and exit. Stdout contains bounded status records,
not package paths or wallet material. The process owns one finalized provider;
it closes that provider on exit and drains active signing work on cancellation.
Continuous following retries RPC throttling, transport failures, observation
timeouts and stale finalized heads at the configured poll interval. It retains
the same provider and completed package verification, reports `waiting_for_chain`
with a fixed reason code, and rechecks fresh authority before signing. Lost
publication acknowledgements recover the original signed record. Invalid proofs,
changed inputs, journal conflicts and a stopped finality observer stop the command;
the service manager can restart it without clearing durable holds. Reaching
capacity stops new work without deleting history.

Discovery accepts canonical private `<settlement-digest>.package.json`
descriptors whose sealed manifests match the descriptor, filename, policy and
fixed package root. It checks at most `2 * maximum_rounds + 1` directory entries
per tick. Discovered round identities are retained across restart. A descriptor
is not sufficient to sign: the selected package is fully replayed and the
publisher still checks its current source and owned finalized head.

Each tick first repairs a missing signed export, one predecessor at a time,
without a new signature or timestamp. When delivery is caught up, the publisher
resumes an unexpired partial signing attempt, or selects the highest completed
round number newer than its last publication. It waits if that round has no
usable original activation window. It does not extend expired windows or fall
back to another package after a validation failure.

The feed remains a separate wallet-free process. Automatic signing does not
install a TLS route, activate a host or establish miner incentive on chain.

<a id="open-competition-round-publisher--bounded-renewal-of-an-unchanged-settlement"></a>

### Bounded renewal of an unchanged settlement

The default version 1 plan signs each completed round once. A validator's
single-use authorization cannot refresh that row a second time. Deployments
where evaluation takes longer than the chain activity window must account for
this before activation.

To permit recurring row refreshes, use `umi-successor-round-publication-plan/2`
and set `renewal_interval_blocks` in both the signing and delivery plans. This
is an explicit change to the plan's identity. Do not overwrite a version 1 plan
inside an existing journal. Version 1 canonical bytes and retry behavior remain
unchanged.

With `--follow-config`, the publisher first recovers incomplete delivery or an
unexpired partial signing attempt, then prefers a newer completed round. If no
newer round exists and the configured interval has elapsed since the last
authorization's signing block, it can renew the latest unchanged package.
Renewal performs package replay, current retained-source conflict checks and
fresh owned-finality checks before signing. Each renewal has a new directive
sequence, predecessor and single-use authorization ID. It does not resubmit an
old transaction or change the package's allocation.

For version 2, the validity limit remains the earliest of the plan, policy,
original round, snapshot-age limit and new authorization's maximum lifetime. Renewal never
extends the underlying round or snapshot. If the remaining window is too short,
the follower waits for a current completed round. A conflict or changed recipient
registration still blocks submission. This feature does not authorize a fallback
allocation after failed validation.

Choose an interval no shorter than the configured chain weight rate limit and
short enough to allow replay, feed delivery and finalization before the activity
cutoff. The plan requires mortality and activation headroom within its maximum
authorization lifetime; that check alone does not prove sufficient operating
margin. Measure the complete deployed path. The weight worker independently
checks the actual chain rate limit and allows at most one transaction per
authorization.

Signing, delivery and worker attempt journals retain every renewal. Include
renewals in their capacity budgets, even where a limit is named `maximum_rounds`.
Reaching a limit stops new work without deleting old receipts. Retain the exact
sealed package for retries and catch-up. Fresh evaluation rounds and their
original expiry schedule are still required for ongoing operation.

<a id="open-competition-round-publisher--reusing-a-settled-round-with-current-recipient-checks"></a>

### Reusing a settled round with current recipient checks

Version 2 cannot support a reward interval longer than the original settlement
registration snapshot's configured freshness window, regardless of how long the
signed round remains valid. Renewing its authorization does not remove that limit.

To use a completed round for an explicitly longer reward interval, select
`umi-successor-round-publication-plan/3` and supply both
`renewal_interval_blocks` and `maximum_settlement_reuse_blocks`. The latter is
measured from the original settlement observation, never from a restart or the
most recent renewal. It must fit the reviewed scoring cadence. Each new
authorization still expires at the earliest of this reuse limit, the original
round, policy, plan and per-authorization lifetime. It cannot revive an expired
round or change a retained allocation, score, label or signature.

The managed publisher obtains a new owned finalized registration capture after
replay and before each signature and final publication. Every projected
recipient must still have the same UID and hotkey, and the configured burn
destination must still match. A removed or reassigned recipient, changed burn
destination, stale proof or retained evidence conflict prevents publication.
Unrelated registration changes do not invalidate the unchanged recipient set.
The weight worker independently repeats its fresh registration, burn, permit,
runtime, rate-limit and authorization checks before a chain write.

Weight proof collection reuses exclusive, method-specific WebSocket connections
and fetches up to 512 requested storage values in batches of at most 256 keys.
Every batch must name the exact owned finalized block and contain every requested
key once. These are untrusted values until the existing complete trie multiproof
and runtime decoder accept them. Wrong-block, missing, duplicate and oversized
responses fail the collection. Connection reuse does not extend snapshot freshness,
retry a failed proof, or authorize a transaction. Runtime-code reads use separate
connections and retain their separate byte limits. Shutdown closes the sockets.

Version 3 requires the managed current-recipient gate even for the first
publication. The signing builder rejects ungated use. Versions 1 and 2 retain
their original serialization and snapshot-limited semantics; they cannot opt in
by adding the version 3 field. Do not replace a plan inside an existing journal.
Feed delivery must use exactly the same version 3 plan as the publisher.

This separates the age of scored results from the freshness of chain state.
It does not generate new evaluations or admit new miners into an already closed
roster. Publish the next roster-close and evaluation windows so new submissions
can enter a later round. A recipient change still requires a current settlement;
this mode does not invent replacement recipients or an alternative weight row.

<a id="open-competition-round-publisher--continuity-between-rounds"></a>

### Continuity between rounds

An expired round stops new authorizations. The follower reports
`waiting_for_current_round` and keeps polling; a later completed, replayable
package can resume publication with fresh recipient evidence and a new signature.
Retained signed history remains unchanged. The host can follow that continuation
after holding through expiry, including after restart. It does not automatically
return to the registration bridge.

A retained on-chain row alone does not establish reward continuity. Check the
deployed chain runtime's activity rule: once the validator becomes inactive,
its stored row may no longer contribute to score-directed consensus and ranks.
Other active validators and epoch state also affect emissions. Renewal cadence
must leave time for replay, proof collection, delivery and inclusion.

For future cohorts, an evaluator-signed `umi-competition-launch-amendment/2`
can lengthen the final round-validity window while preserving work, reveal and
cutoff times and cadence. A round end covering the next evidence cutoff plus
bounded delivery grace, together with a version 3 settlement-reuse limit covering
that same interval, permits automatic refreshes until the next certified result
arrives. Every refresh still uses current chain evidence. Missing certificates
beyond the grace period or changed recipients cause a hold.

This amendment cannot modify a prepared or active cohort. Apply it after the
preceding round's validity and before the next unused roster, under the native
history and checkpoint checks. Rebind future launch-dependent profiles and plans;
the replacement launch numbers its first future cohort as cycle zero. A changed
publication plan must be selected before journal initialization. After intake
migration, update the publisher's launch configuration and restart its service
with the same signing history. Longer outer consent or a configuration edit
cannot extend an already certified round.

Size retained weight evidence for the full consent horizon before initializing
the worker journal or installing its host limits. A normal write collects evidence
before signing, before broadcast and after submission; retries and stopped recovery
can add more. Account for runtime metadata, proof growth and filesystem overhead.
The worker's `maximum_evidence_bytes` must agree with its immutable journal binding
and fit the installed `maximum_weight_evidence_bytes` ceiling. A longer renewal
interval must still satisfy the rate limit, authorization headroom and current
chain activity cutoff. Capacity exhaustion preserves history and stops work.

During one stopped recovery audit, consecutive renewals may reuse an already
verified package only while its complete target, release and sealed file identities
remain unchanged. Every directive and weight authorization is checked separately.
This reuse ends with the audit; the final chain observation is collected afterward
and retains the usual freshness and finalized-head checks.

<a id="open-competition-round-publisher--current-checks-and-recovery"></a>

### Current checks and recovery

The publisher fully replays the package and checks the current local intake
material, reviewed promotion head and retained publication conflicts. A fresh
owned finalized capture is collected after replay, before signing boundaries
and before retaining a complete publication. Head rollback, expiry, changed
source configuration or a newly observed conflict prevents current publication.
These are checks of retained local evidence, not a proof that no conflicting
certificate exists elsewhere.

Each authorization and directive signature is saved before the next signing
step. A retry reuses those exact bytes and the original validity window.
Incomplete attempts may be superseded by a later round only after strict expiry;
their records remain in the journal. Cancellation waits for the signing thread
to terminate before releasing the local service lock.

Historical publications remain readable from the signing journal. The current
publisher refuses to return an expired publication as an activation candidate.
It never extends a round or changes a retained authorization's signing time.
A version 2 renewal creates a separate authorization only while the original
round remains usable.

<a id="open-competition-round-publisher--verification-scope"></a>

### Verification scope

Run the release publisher and these signing/feed tests on Linux. The unchanged
version 1 publisher reproduces a database-locking failure on the Studio's native
macOS environment; Linux guest tests do not qualify native macOS publishing.

The signing-core and current-gate tests passed 19 cases on the Studio's Linux
VM. They use synthetic authority keys and real replayed fixture packages. Tests
cover consecutive rounds, retained partial signatures, conflicts arriving during
an owned-head read, expiry, rollback, source changes and cancellation cleanup.
They do not establish production authority, model quality or feed delivery.

The command-wiring suite passed five additional cases on the Studio. It checks
provider cleanup on success and failure, explicit wallet selection after
readiness, missing intake history, overlapping state roots and private input
permissions. The chain and wallet ports in those tests are test doubles.

The combined feed and publisher regression passed all 33 cases on the Studio's
Linux VM in 410.45 seconds. Nine new cases cover consecutive exports and restart,
missing predecessors, unsigned metadata changes, wallet-free recovery, export
cleanup, changed package files, the existing HTTPS consumer and canceled reads.
The HTTPS consumer uses an ASGI test transport and an inert hash-pinned release
archive. No production TLS route, OCI execution or host handoff is established
by those tests. Repository-wide Ruff and formatting checks also passed.

The first automatic-publication batch passed 11 cases on the Studio's Linux VM
in 257.44 seconds. It covers completed-round selection, signed-export recovery,
expiry, late conflicts, descriptor bindings, scan limits and provider cleanup.
Two further cases cover unfinished-signature priority and cancellation during
discovery. All 46 cases in the combined publisher/feed regression passed on the
Studio Linux VM in 567.77 seconds, with two dependency deprecation warnings.
No live publisher service has been installed by this work.

### Forward reward continuity

A version 4 successor publication plan can opt into an independently signed
`umi-reward-continuity-authority/1`. This is new authority for future weight
writes. Original policies, rounds, evidence cutoffs, certificates and allocation
bytes remain unchanged. Older plans retain their original expiry behavior.

The control binds one policy, chain, compatible release identity, first round
identity and an explicit range of eligible cohort sequences. Its lifetime is
`until_superseded_or_revoked`. The last eligible certified allocation may keep
renewing after the range's last round ends. Expanding the eligible cohort range
requires another reviewed authority; no operator can supply a replacement row.

Before the original round and policy end, the publisher must replay the complete
certified package and retain a signed allocation admission with its current
owned finality boundary. A certificate first presented after that deadline
cannot be admitted for continuation, even if it claims an earlier observation.
Admission is an explicit trusted-authority attestation, not independent proof
of the historical wall-clock time at which every evaluator signed.

Each new write still needs a fresh, short, single-use authorization, fresh
recipient identities, validator permit, nonce, runtime and finality proofs.
Version 2 weight authorizations carry the exact control and admission. The
supervisor's local consent pins the control hash and final host manifest, with
an explicit until-superseded lifetime. A longer ordinary consent cannot enable
this mode. The host and worker retain the highest adopted round and exact
package across restart. A newer certified allocation replaces it; older rounds
cannot return. Pending or cryptographically invalid candidate packages confer
no replacement authority. Corrupt discovery metadata or conflicts remain holds.

The signed call retains the allocation's raw weights. Subtensor scales the
largest submitted weight to 65,535 before storing the row. Submission checks
and stopped-worker recovery apply that same fixed-point scaling and rounding
when comparing finalized storage, together with the nonce, last-update and
recipient identity checks. This lets recovery recognize an already-applied
transaction without changing the signed allocation or submitting it again.

If a recipient UID changes hotkey, the original rule holds the row. A separately
threshold-signed `umi-reward-recipient-amendment/1` can route listed recipients'
exact raw shares to the policy's existing burn destination. It binds the original
continuity authority, package and projection. It cannot choose replacement
miners, change other shares or rewrite scores. Version 2 continuations carry the
amendment alongside the original timely admission. Current burn registration and
mode remain mandatory at publication and submission. The publisher retains one
immutable amendment per package; retry and restart reuse it. Older continuations
retain their original bytes and whole-row hold behavior.

Apply an approved signed amendment through the publisher's
`--prepared-package <private-preparation.json> --recipient-amendment
<private-signed-amendment.json>` mode, with the existing `--config` and `--policy`.
The command retains the amendment; ordinary publication/renewal produces the new
authorization. It does not submit weights. All consumers must support the new
continuation before it is published. A valid newer certified package can still
replace a held row without changing the original evidence.

An explicit `umi-reward-recipient-amendment/2` can also group an endpoint-only
allocation by the literal IP addresses in its certified, signed submissions.
Ports do not create separate groups; IPv4-mapped IPv6 addresses use their IPv4
identity. Each group's share uses its highest qualifying certified score, and
the resulting group budget is divided equally among its qualifying UIDs.
Integer rounding preserves the total endpoint budget and burn allocation.
Current endpoint changes cannot alter the retained grouping. This amendment
requires the model allocation to go to the policy's burn destination, preserves
the preceding burn amendment, and binds its signed digest. The publisher retains
both amendments and uses the grouping in subsequent renewals. Historical scores,
certificates and payments are unchanged. Upgrade all consumers before publishing
the new amendment; older consumers reject its schema.

A threshold-signed continuity revocation durably stops new publisher leases.
Already issued leases expire within the configured maximum write-authorization
lifetime, normally 360 blocks. A native signed supervisor hold or local operator
stop can stop execution sooner. The host latches a continuity hold; resuming
requires a separately reviewed local consent transition. There is no automatic
return to the old bridge or an older cohort allocation.

Expired partial signing attempts remain immutable. A fresh owned head may
reserve another attempt for the same round and next unconsumed directive
sequence only after the prior lease expires. An expiry audit links the old
intent; authorization and signature bytes are never overwritten or reused.

Authority lifetime does not remove storage limits. Current weight journals are
bounded at 16 GiB of retained evidence and 65,536 attempts. At three 12 MiB
captures per write this permits at most 455 writes before overhead and retries,
about 7.6 days at a 120-block interval with 12-second blocks. Capacity exhaustion
holds without deleting history. Indefinite unattended operation additionally
requires qualified archival or compaction; this release does not claim it.
Archival must retain authenticated certificates, control/admission bindings,
unresolved effects, nonce/finality high-water marks, adopted allocation and
policy holds, and hash-linked durable evidence. An ordinary log rotation cannot
replace native recovery qualification.

## Model delivery before recoverable enrollment

`umi-cohort-service-admission-host/9` selects `direct_model_uploads` for cohorts
whose signed plan uses `direct_r2_multipart_v1`. The host reads one private R2
credential export, issues short-lived capabilities for exact multipart part
numbers and sizes, and retains only signed declarations, provider identifiers,
ETags and verification receipts. Model bytes travel from the miner to private
R2 without passing through coordinator request bodies or accumulating in an
intake staging directory. The owner reads bounded R2 ranges to authenticate the
entire stream, every declared file, and the license/provenance documents. A
model cannot enter participation or artifact acceptance before those checks and
the standing review complete.

The direct host reuses the admission owner's hotkey and key file. Configure a
separate private metadata `directory`, the R2 credential file and bucket, plus
the standing review policy. The credential export must be an absolute,
non-linked owner-private file containing exactly `TOKEN_VALUE`, `ACCESS_KEY_ID`,
`SECRET_ACCESS_KEY` and `DEFAULT_ENDPOINT`; the account token is ignored by this
runtime. The endpoint must be the account's HTTPS R2 S3 origin. Keep the direct
metadata journal, R2 objects and review records across restart or migration.
Only the signed cohort plan selects direct delivery parameters, so later cohort
changes do not require a new miner command.

A standing series can contain both an older `coordinator_chunked_v1` cohort and
a successor direct-R2 cohort. In that case version nine carries both
`model_uploads` and `direct_model_uploads`. The immutable plan digest routes each
request to exactly one mechanism; the legacy journal and archive remain
available for unfinished older delivery while successor bytes bypass the host.
If every model-enabled plan in the installed series is direct, omit
`model_uploads`.

Each independent `umi-cohort-phase-review-service/7` receives a read-only R2
credential and the same standing review policy. It authenticates the owner's
signed object reservation, then reads the complete object itself once and checks
the stream digest, every manifest file and the declared rights documents. It does
not trust the owner's byte-verification result and does not retain another model
archive. The R2 reader credential must not allow writes, multipart creation,
completion, listing outside its selected bucket, or deletion.
The upload owner retains byte results under its private `byte-verification`
directory. Phase reviewers, settlement signers, standing reward coordinators
and reward writers keep theirs under `direct-model-byte-verification` in their
existing private service state. Keep these directories through upgrades and
restarts, independently of the disposable benchmark cache. Existing version-two
materialization and settlement receipts remain readable; installations without
the new private result build it during their next necessary native check, without
rewriting signed evidence or resetting retained journals.
When the signed host selects only the model track, version seven omits the
endpoint host entirely. A mixed-track selection still configures the endpoint
host and preserves its ordinary independent request and decision paths.

Benchmark execution necessarily needs the candidate bytes while its offline
runtime runs. A version-seven reviewer therefore keeps one bounded candidate
cache under the benchmark workspace. It streams and verifies the selected
object into that cache, reuses it across that candidate's cases, and removes the
old candidate before materializing another one. All active case leases finish
before a different selection can replace the cache, including a different request
for the same bundle. Materialization is serialized and capped by
`maximum_materialized_bytes`. It checks each file and the full payload while
writing, then publishes the local immutable receipt without rereading the newly
written weights. A retry retains completed files and their checks. A changed R2
namespace or object generation invalidates the pending transfer before reuse.
Completed aggregate verification survives failures during final publication;
only an unfinished concatenated SHA256 must reread retained local files, without
redownloading or repeating their completed per-file checks. Missing local results
receive visible scoped repair. Preparation, transfer, cache validation, lease
waiting and eviction report counts, elapsed time, ETA basis and retry/stall status.

Before writing, the remaining new allocation plus
`materialization_free_space_reserve_bytes` must be free. Verified retained files
and complete files requiring local receipt repair need no second allocation;
owned partial files are reclaimed before capacity is measured again. The
baseline remains in the pinned local archive. Put the benchmark workspace on a
dedicated quota-controlled scratch filesystem. Source schema 2 binds
`materialization_filesystem_maximum_bytes` and at least one
`materialization_protected_roots` entry. List every validator/coordinator state,
evidence and journal filesystem in that tuple. Before writing, the reviewer
requires the scratch device to differ from every listed device and requires the
filesystem's total capacity to fit the configured maximum. This makes a bounded
volume or filesystem quota a runtime prerequisite. Capacity exhaustion delays
work; it never sends candidate bytes to a protected filesystem.

Configure a bucket lifecycle rule that aborts incomplete multipart uploads after
the selected recovery interval. A part-level provider `404` causes the miner to
sign a restart request. The owner checks that the exact provider upload is
absent, fences the old generation and issues the next retained generation; the
miner then resumes from its unchanged local bundle without operator action.
Retain completed incoming objects until a
content-addressed preserved object and its acceptance or rejection evidence are
durable. Accepted objects are copied entirely inside R2, fully read back, and
their incoming source is deleted only after a private promotion receipt is
durable. Terminally rejected objects receive a durable cleanup intent and stay
available for the configured rejection-review interval. The owner then deletes
only the exact bound incoming key, verifies absence and retains the signed
request, hold and cleanup receipt. Cleanup is bounded per poll and retries after
lost acknowledgements. Lifecycle cleanup is storage management and never closes
intake, expires a retained participation request or makes an otherwise eligible
model late.

`umi-cohort-service-admission-host/8` is the retained legacy path. It carries
`model_uploads` alongside the
service admission host and independent model-review peers. Configure a private
`directory` disjoint from intake and the model archive, and an explicit
`maximum_reserved_bytes`. Reservations account for two copies of each declared
bundle, covering delivery staging and the verified archive. Increase capacity
without changing accepted manifests or clearing journals. Other bounds are
`maximum_models`, `maximum_metadata_bytes`, `maximum_concurrent_uploads` and
`idle_timeout_seconds`.

The public routes described in the [model guide](../miners/model.md#model-files-for-recoverable-cohorts)
retain signed chunks. The recurring host finalizes complete files and archives;
its `model_delivery` report gives preserved/pending counts and a bounded error
type. Verification retries after process exit, and the archive copy reuses one
per-manifest scratch directory. After the canonical archive fully verifies, the
worker removes the redundant completed staging tree under its upload lock. It
keeps incomplete prefixes and the durable archive. This disk reclamation does
not expand the conservative logical reservation. Accepted original bytes remain
unchanged. An unfinished model delivery is not admitted to the cohort roster.

Keep a legacy upload journal, retained file prefixes and model archive across service
restart or host migration. Configure durable replication of original model
artifacts and provenance before production launch. A local preservation receipt
does not establish an R2 copy, independent backup, rights approval or reward
certification.

Installed reward coverage collectors persist successful native endpoint facts
bound to their original journal, source generations, package, policy, authority,
requirement and verifier semantics. Restart can restore unchanged facts from
compact metadata without loading the package or endpoint payload. Restoration
still requires the selected owner's complete native history at the exact block;
a portable point or another owner's receipt cannot establish coverage. R2 cache
eviction and acknowledged SQL externalization preserve these facts. New endpoints
and changed dependencies still require their affected native checks.

For direct models, compact dependency receipts bind the selected native verifier,
standing review policy, original receipt owner and authenticated R2 object
generation. Restore checks those small receipts and object HEADs without loading
model weights or the reward package. Older receipts lacking these bindings receive
an explicitly reported first native qualification; existing durable byte checks
remain reusable. Older directory-based model acceptances retain their original
native path. Observed receipt or generation damage stays held even if the original
later reappears, until explicit scoped repair succeeds.

Keep `coverage-qualification-owner.json` and `coverage-qualification-ledger/`
under the original model receipt directory. The immutable completion ledger
detects lost per-item qualification files before new capture can repeat native
work. An explicit original-owner repair can restore an exact missing qualifier
from that ledger after receipt and object-generation checks. Lost owner or ledger
metadata requires restoration in place. Intact older qualifiers receive a counted
metadata-only migration without rewriting their bytes or loading model payloads.
Retain this migration while supported owners still have qualifiers without the
completion ledger; its private capability refuses reservation-layout changes.

Missing or damaged completed results require explicit scoped repair. After exact
original inputs are restored, `NativeRewardCoverageSource.repair(key, reason=...)`
requalifies the selected endpoint with progress and ETA and preserves earlier
successful result bytes. There is no installed coverage-repair CLI in this
surface. Recovery integration and original-owner metadata restoration must be
qualified before deployment. The current and predecessor collectors share one
process-local guard across package loading and replay; cancellation drains owned
work before releasing it. Other reward consumers and processes require separate
memory admission. This does not establish the whole-host memory envelope.


### Host memory admission

The admission owner, independent phase reviewer, settlement service, reward
coordinator and standing reward writer accept an optional `host_memory_admission`
selection with `policy_path` and the exact policy-file `policy_sha256`. The optional
`host_identity_path` defaults to `/etc/machine-id`. An omitted
selection preserves existing canonical configuration bytes. An explicit aggregate
evidence budget of up to **4 GiB (4,294,967,296 bytes)** is supported with this
optional policy omitted. Preserve existing signed clocks and state bindings
when changing the aggregate budget. Host memory admission is an
independent opt-in configuration: select the same qualified host policy in every
co-resident aggregate consumer; enabling one consumer alone does not establish
a host-wide capacity bound.

Provision the `umi-host-memory-admission/2` policy and its empty lock files on
persistent root-owned storage. The policy binds the host's `/etc/machine-id`,
namespace directory, group and every file's device/inode. The directory is mode
0750, files are mode 0400 or 0440, and ancestors cannot be writable by the service
accounts. Root-owned service configuration selects the policy's exact bytes.
Every participating service account must be able to read the same inode bindings
from its own mount namespace. Preserve these files across unattended reboot;
replacing a file requires a deliberate policy/configuration cutover after draining
all existing consumers. No runtime creates or rewrites this namespace.

The retained `umi-c5-requests-memory-admission/1` schema is restricted to its
original cohort, protocol policy, series, recovery authority and certified
preparation result. Its authority identity is `digest(series.recovery.authority)`;
its preparation identity is `digest(prepared.roster.round)`. Only the admission
owner and phase reviewer support this selection. Its measured owner-export,
transient and background allowances do not admit settlement or reward work.

For an existing restricted selection, preserve the exact `operations` list and
declaration, record, object, service, order, inventory and JSON shape bounds.
JSON value bounds include object keys as well as scalar and container values;
shape checks precede native proof validation.
`preparation_republish` remains required; without qualified `requests_publish`,
native request closure remains pending publication. Public routes and unqualified
private routes return 503 before consuming bodies or reading native state; disabled
dispatch remains unavailable. Preserve independent reward file/proof delivery,
chain RPC and gateway fallback dependencies when recovering such a selection.
Verify the complete configured request path before a supported migration.

Keep restricted-policy decoders, immutable policies, selectors, source and state
bindings while an installed service, active experiment or recovery consumer
references them. Retire their migration guidance only after the last such
dependency is removed. A retained helper or qualification receipt does not
require selecting that policy for an aggregate-budget upgrade.

A containerized writer may have its own `/etc/machine-id`. Preserve that local
identity and provide a separate read-only bind of the host identity, for example
`BindReadOnlyPaths=/etc/machine-id:/run/umi-host-machine-id`, then select
`host_identity_path: /run/umi-host-machine-id` in its bootstrap configuration.
Bind the shared immutable policy directory into the same namespace. The selected
identity path must be absolute, root owned and immutable; it must hash to the
policy's host identity. Verify the actual writer account sees the same slot inodes
and selected host identity as the ordinary services while retaining its own local
identity. A host-account test alone does not establish this namespace binding.

Full host policy reservations cover separate owner-export, transient-operation and retained
settlement capacity. An owner response keeps its reservation through bounded
ASGI sends. A reviewer can hold transient capacity while fetching an owner export,
so those lanes must remain independent. Reward opportunity and peer-vote waits
run outside package admission. Complete local operations drain owned threads
before releasing capacity, including on cancellation. Error boundaries replace
native exceptions with bounded diagnostic copies before releasing their rejected
input graphs. Never pass an admitted operation's full native graph to work that
outlives its reservation.

Each settlement role runs one native cohort at a time, in the approved series
order. A missing earlier authenticated handoff or mandatory original remains a
barrier; later cohorts cannot occupy that role's native slot while it waits.
Coordinator and reviewer have independent slots and may resume at different
cohorts. Completed cohorts continue repairing their exact input replicas,
certified histories and already signed votes using bounded delivery operations.
Their separate serial maintenance task can run while a later native worker is
busy. Per-cohort exclusion prevents maintenance and native replay from changing
the same cohort concurrently. Input and output aggregate digests run in owned
workers under the native reservation; they do not block the event loop.
An authenticated terminal-history extension keeps its original certification
prefix and does not reload the full input inventory.

If a completed coordinator's generated reward package disappears, its scheduler
releases the later cohort's graph and reservation after owned work drains, then
replays the earlier cohort from its original journals and files. A missing
mandatory input is restored in place; it is never regenerated as a shortcut.
Recovery detected during an active tick waits for that tick to drain. Shutdown
drains both the native and compact maintenance tasks before closing their stores.
Changed original bytes or a changed certification prefix refuse progress. A
process restart authenticates each earlier cohort again before proceeding, so
file counts, cohort numbers and elapsed time never establish completion.

Select reservations from measurements of the exact supported runtime and maximum
aggregate capacity. `maximum_aggregate_bytes` must cover each consumer's effective
configuration. `background_reservation_bytes` explicitly covers persistent native
selections, bounded history/vote/model/order buffers and future allocations that
do not own a slot. Logical object release does not imply that Python returned its
resident pages to the operating system.

With host memory admission enabled, startup requires current available memory
above the 24 GiB floor plus all slot reservations and background allowance.
Each serialized grant rechecks
current available memory against the floor, background allowance, candidate
reservation and the full reservations of all occupied slots. This deliberately
charges occupied work again even when it is already resident. Qualification must
therefore include this conservative envelope, retained allocator memory, all
configured concurrent consumers and downstream owner work. A policy fitting only
the sum of isolated peaks can block its own dependencies. Verify startup, steady
state, replica restart and recovery under the actual account/mount/cgroup limits
before cutover; do not infer these bounds from aggregate file sizes alone.
