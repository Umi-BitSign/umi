[Documentation](../README.md) / Review and promote contributed models

# Review and promote contributed models

- [Cohort winner baseline publication](#cohort-winner-baseline-publication)
- [Model promotion agreement](#open-competition-promotion-agreement)
- [Reviewed promotion delivery](#open-competition-promotion-delivery)

## Cohort winner baseline publication

Use `apply-cohort-baseline` to publish an already quorum-certified cohort winner
to an existing intake, phase-reviewer or evaluator promotion history. The
certificate must come from the native cohort preparation and bind the exact
source cohort, successor cohort, original parent and reviewed winning model.
This command does not perform the review, sign it, enable rewards or release a
cohort hold. Retained rounds and signed submissions keep their original bindings.

Check the intended replacement service configuration without starting finality
or creating or migrating a history:

```sh
umi-competition --policy /ABSOLUTE/competition-policy.json apply-cohort-baseline \
  --intake-config /ABSOLUTE/replacement-intake-config.json \
  --certificate /ABSOLUTE/certified-cohort-baseline.json \
  --chain-config /ABSOLUTE/baseline-observer-chain-config.json --check-only
```

Select exactly one of `--intake-config`, `--reviewer-config` or
`--evaluator-config`. Each role must use its original history and bindings. An
independent evaluator still needs its independently reviewed promotion parent;
do not copy an intake database or invent missing local evaluation. The intake's
replacement config pins the certified target baseline and preserves its exact
required-submission list. The preflight checks the currently retained anchor
before the command atomically advances it with the baseline record.

The observer chain configuration must bind the service's exact policy, chain
and finality authority, with separate finality state outside every service or
history directory. Run under the owning service account with its supported
state and native finality permissions. `--check-only` does not prove that the
current finalized head is inside the certificate's application window.

Actual retained rounds and disputed history block publication. An unused cycle
of the legacy continuous calendar does not block a certified cohort winner;
existing round records retain their original baseline and signed schedule.
Runtime-port publication keeps its separate published-calendar guard.

Before applying, quiesce all writers to that history and independently verify
the supported backup/restore coverage. Run the same command with
`--confirm-quiesced-backup` in place of `--check-only`. It obtains its own native
finalized observation, checks the original application window again at the
append, and retains the original certificate and observed block atomically.
There is no operator-supplied block override. Preparation, finality and append
emit counted progress, elapsed time and ETA basis on stderr; JSON results use
stdout. Observation delays do not create a new signed deadline.

Exact repeat execution authenticates the retained receipt and returns
`cohort_baseline_already_applied` without starting finality or revalidating model
payloads. Missing or damaged receipts, another parent, an occupied sequence or
changed retained bindings refuse explicitly. Preserve the original failure and
restore or repair that exact history through its supported recovery path; do
not clear the receipt or rerun the completed native review. Select only a
qualified compatible runtime for every writer before restarting the service:
the new history fences older writers while retaining historical readers.

For an R2-adopted cohort, the frozen legacy inventory continues to describe its
original baseline and execution incumbents. Do not rewrite that signed inventory
when publishing a new winner. The phase reviewer separately authenticates the
locally applied cohort-baseline receipt, including the exact target cohort,
sequence and model, before selecting reference bytes. If the winner is already
a preserved participant in an authenticated legacy inventory, the sandbox restores
that exact original through its R2 association into the bounded model cache.
A later direct-upload winner uses its retained source-cohort review request and
matching private acceptance intent to select the preserved R2 object. The source
submission, contributor, policy and complete bundle must match the certified
baseline. Unknown models still require their original authenticated source;
a missing or damaged promotion receipt requires repair. Candidate admission,
rights review and execution-order checks are unchanged.

Retain those source records and the applied baseline receipt while any cohort
uses the reference. Missing or damaged source records require explicit repair;
they are not ordinary cache misses. Successful byte verification stays outside
the disposable cache and survives eviction and restart. Each active invocation
holds the cache lease, including inherited references, so another model cannot
evict its bytes. Materialization progress counts chunk/file-finalization work as
well as bytes; the last payload byte does not mean publication is finished.
Direct-object restoration combines adjacent missing files into bounded R2 reads
while retaining the original file and payload checks. Retained local files split
those ranges, so interrupted restoration never downloads their bytes again.
Its ETA includes completed file operations and final publication; restored work
does not inflate the measured transfer rate.
Legacy chunk restoration overlaps up to four missing 8 MiB chunks (32 MiB of
payload buffers), then writes and checkpoints files in manifest order. Pending
reads are cancelled and drained before releasing the cache lease on failure;
already completed local files are excluded from prefetch after restart.
Native legacy chunk readers retain one HTTP connection pool through inventory,
range reads and generation confirmation. Requests remain separately signed and
bounded; cancellation drains outstanding reads before closing the pool. A
required unfinished child operation withdraws the parent ETA until it has a
positive forecast or completes, preventing the last payload byte from implying
that confirmation is finished.

### Rootless CPU namespace readiness

CPU phase reviewers keep `NoNewPrivileges=yes`. Prepare their existing rootless
Podman namespace in the separate `umi-cohort-cpu-namespace@.service`, which runs
as the same unprivileged account and can use `newuidmap`. An OOM event or stopped
user session can remove Podman's pause process; the timer recreates that namespace
without resetting storage, pulling images or changing model results.

Install `deploy/standing-reward-coordinator/ensure-cpu-namespace.py` root-owned
at `/usr/local/lib/umi/ensure-cpu-namespace.py`, and render the companion service
and timer for the reviewer. Use the reviewer's existing service user/group and
numeric `SERVICE_UID`. Its `%i.cpu-runtime.env` file under `CONFIG_DIRECTORY`
must preserve the installed `HOME`, `CONTAINERS_STORAGE_CONF`,
`CONTAINERS_CONF_OVERRIDE`, `XDG_RUNTIME_DIR` and `DBUS_SESSION_BUS_ADDRESS`.
Inspect the supported installed layout first; do not substitute a fresh store
or grant directory. Enable the companion timer for continuous recovery. The
phase-reviewer template orders its initial startup after namespace preparation;
phase-only reviewers without a CPU environment file skip that preparation.

Healthy repeats check the private pause-process and readiness metadata without
rerunning Podman inspection. Changed configuration, boot or process identity
causes a new local check. Counted progress and bounded failure details go to the
journal. A missing image, unsupported namespace or failed mapping remains an
infrastructure retry; preserve the original model assignment and journals.

Original baselines without an authenticated remote source continue to require
their canonical preserved archive. Bounded-cache selection alone never authorizes
canonical archive retirement, reservation release or a change to another live
consumer's retention contract. Preserve those bytes until durable remote custody,
required restoration and every consumer release are independently established.
Select a compatible phase-reviewer runtime with the committed R2 configuration
before the successor cohort executes; merely publishing the baseline or
configuring a transport-adoption reviewer is insufficient.

<a id="open-competition-promotion-agreement"></a>

## Model promotion agreement

`umi-model-promotion-review/2` lets independently run validators retain the same
model-history head even when their receipt blocks or valid certificate sets
differ. This is a versioned store/CLI contract. The reviewed-delivery procedure
below distributes approved decisions. Deployment must use the evaluator groups
named in the signed policy; two keys under one administrator are not independent.

<a id="open-competition-promotion-agreement--signed-decision"></a>

### Signed decision

The v2 review contains every v1 review field, plus:

- `round_sha256` and `submission_sha256` for the exact admitted evaluation;
- `previous_promotion_sha256` for the current reviewed history head;
- `sequence` for the next promotion, equal to the parent's sequence plus one.

`CompetitionStore.baseline_summary()` exposes the parent digest and sequence.
Reviewers sign the complete v2 body. The existing `promote` CLI accepts an
`AttestedPromotionReview` containing that body and the policy-required distinct
review groups. A body or digest supplied by a coordinator does not establish
local review, execution or rights approval.

Each operator independently checks the model's admission and evaluation,
preserved archive, paired quality gates and signed rights/reconstruction review.
Its current finalized registration snapshot and observation block must still
pass the existing validity and freshness rules. No shared observation timestamp
or retroactive observation is required. Those local checks can reject a decision
that another operator previously accepted, for example after expiry.

<a id="open-competition-promotion-agreement--history-and-local-receipts"></a>

### History and local receipts

The canonical `umi-model-baseline/2` record contains the shared evaluation result
and review bodies with the model, contributor and parent binding. Endorsement
ordering, additional valid endorsements and local receipt time do not change its
digest. That record alone is not a certificate or chain-write authorization.

The complete locally verified certificates and actual acceptance block are
retained atomically in `promotion_receipts`. Exact retries retain the first
receipt. A changed decision cannot rewrite an existing promotion. The store's
observed-block high-water mark advances normally; it is never set back to
another operator's receipt block.

Restart requires the matching local receipt, valid certificates and parent.
Settlement signers also check the bounded receipt when reading a reviewed head.
Missing, changed or oversized receipts hold the action. Existing evidence-cutoff
and conflict rules still apply; importing a decision after cutoff cannot invent
earlier local evaluation evidence.

The v1 review and `umi-model-baseline/1` history remain supported with their
original bytes and observation semantics. A v2 review does not rewrite a model
already promoted through v1 or transfer its contributor attribution.

<a id="open-competition-promotion-agreement--verification-boundary"></a>

### Verification boundary

Store tests exercise different receipt blocks, endorsement order and supersets,
changed decisions, parent/round/submission bindings, restart, missing receipts,
bounded signing reads and legacy compatibility. The combined service test uses
different local promotion blocks before its predeclared evidence cutoff.

These tests use synthetic model and rights inputs. Production decisions require
protected-data execution, reviewed launch inputs and signed activation. A
qualifying contributed model and its specific rights and provenance review are
required before awarding a model share. The signed
[evaluator profile](../competition/launch.md) defines required and optional
evaluators, control groups and quorum. Signatures under one administration do not
supply independent votes. Additional evaluator groups require a successor signed
policy. No live reward policy changes through this API.


<a id="open-competition-promotion-delivery"></a>

## Reviewed promotion delivery

The coordinator can deliver an approved model promotion to continuous evaluators
using their existing authenticated round connection. Each evaluator applies it
against its own completed execution, review history and preserved model archive.
No per-validator upload key or manual `promote` command is needed for this path.

This is an opt-in successor service. It does not activate the open competition,
change the live bridge, approve model rights or extend a round's deadlines.

<a id="open-competition-promotion-delivery--configuration-and-review-input"></a>

### Configuration and review input

Enable round work and settlement delivery first. Add this field to the
[round coordinator configuration](rounds.md#open-competition-round-coordinator):

```json
"promotion_delivery": {
  "reviewed_directory": "/ABSOLUTE/APPROVED-PROMOTIONS",
  "archive_directory": "/ABSOLUTE/VERIFIED-MODEL-ARCHIVE"
}
```

These directories must be private, absolute and separate from the coordinator's
other configured paths. The archive contains the already preserved model bytes.
The coordinator does not download arbitrary files from a review document.
Changing these paths changes the persistent service binding.

Publish an approved `ReviewedPromotion` JSON file into `reviewed_directory` by
atomic rename, with mode `0600`. Its filename is the domain-separated digest of
the v2 review body followed by `.json`. The document contains:

- `schema`: `umi-reviewed-promotion-delivery/1`.
- `review`: the full `AttestedPromotionReview`, including independent signatures
  over an `umi-model-promotion-review/2` decision.
- `round`: the exact previously closed evaluation round.
- `submission`: the miner's exact signed model submission.
- `chain_submission_authorized`: `false`.

Use the [promotion agreement](promotion.md#open-competition-promotion-agreement) for review
fields and certificate rules. Rights and reconstruction evidence must be reviewed
before signing. The service never creates either approval. Protected suite
references are not included in this delivery document.

<a id="open-competition-promotion-delivery--applying-a-decision"></a>

### Applying a decision

The coordinator verifies the review quorum and binds its sequence to one decision.
It looks up the round's original private plan and independent evaluation evidence
already retained by its exchange. It replays that evidence, checks its actual
observation time against the fixed cutoff, collects its own current finalized
snapshot and verifies quality, current registration, parent history and model
preservation. Only an accepted local promotion enters discovery.

Evaluators enable this path by configuring their existing round/work clients and
`settlement_review_directory`. They retain completed independent evidence in that
review store automatically. The review database records its own actual arrival
time, which can be later than the execution journal's observation after a crash.

On discovery, a worker requires its own completed order, authenticated execution
announcement, matching evaluator run and evidence receipt. It reads its locally
revealed suite and uses its own archive and current finalized snapshot. A remote
review cannot supply missing local inference or import the coordinator's database.
The same signed decision produces the same promotion head across operators;
their actual receipt blocks remain separate.

First application must complete no later than the predeclared evidence cutoff.
If evidence, preservation or finality is unavailable, the worker keeps that
history link pending. It does not skip to a later promotion. Missing a deadline
requires an operational recovery under a valid policy; retries never fabricate
an earlier acceptance time.

<a id="open-competition-promotion-delivery--retry-conflict-and-capacity-behavior"></a>

### Retry, conflict and capacity behavior

Discovery uses signed, nonce-protected round requests and returns at most four
reviews. Each review document is bounded at 256 KiB. Inbox and retained journal
capacity use the coordinator's configured round and byte limits. Summaries expose
`promotions_applied` and `promotions_held`, without protected data or exception text.

Workers retry pending decisions through the poll loop. A restart discovers history
from the beginning and verifies already accepted receipts without repromoting or
changing their timestamps. Different valid signature ordering leaves the decision
unchanged. A different authenticated decision for an occupied sequence creates a
durable hold. Unauthenticated inputs cannot reserve a sequence. Preserve journals
when a conflict or capacity hold needs investigation.

The automated lifecycle rehearsal uses synthetic models, data, keys and explicit
test-only rights approvals. Real ASL quality, approved contribution terms, an
independently administered evaluator run, signed activation and finalized reward
verification remain separate launch requirements.
