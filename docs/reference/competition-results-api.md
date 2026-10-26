[Documentation](../README.md) / Competition results API

# Public cohort results and model downloads

The cohort API exposes retained certified paid-work counts and exact credits,
and downloads for admitted public-model submissions. It includes public model
revisions and zero-reward entries. A model's reward rank does not control its
publication. Endpoint models and private evidence are not download sources.

These results do not establish that rewards are live on chain. Service output
uses `certification: quorum_certified_service_results` and
`reward_activation: not_verified_live`; raw service weights are allocation
integers, not alpha payments. The API never grants chain-submission authority.

## Read results

All paths use the full cohort digest. Lists accept `offset` and `limit` (1–100),
and return `total`, `next_offset` and `items`.

| GET path | Meaning |
| --- | --- |
| `/v1/competition/cohorts/{cohort}/progress` | Cached stage, counted work, scoped ETA and retry/repair status; advisory, never reward or phase authority |
| `/v1/competition/cohorts/{cohort}/service-results` | All sealed roster hotkeys, including zero-work rows, retained UIDs, successful/failed paid terminals, exact quality credit and certified service weight |
| `/v1/competition/cohorts/{cohort}/models` | Every exported admitted public submission, original terms and license, revision identity, artifact-release state and download availability |
| `/v1/competition/cohorts/{cohort}/models/{model}/download` | Native bundle manifest, renewable GET capabilities, optional complete tar archive, and the file-download endpoint |
| `/v1/competition/cohorts/{cohort}/models/{model}/download-files` | One manifest file's bounded pieces or preserved-payload byte range |

Execution counts are confirmed delivered export floors, so live execution can be
ahead. A completed model requires all of its selected evaluators' terminal exports.
Projected execution totals assume the undelivered orders match delivered profiles.
An execution ETA covers evaluations only; certification and reward activation are
separate. `overall_eta_seconds: null` means no end-to-end forecast is established.

Execution rates use completed models within the currently observed evaluator
processes, identified by `rate_epoch_sha256`. `rate_completed_models` and
`rate_sample_seconds` describe that sample only. An evaluator restart, rollout,
unavailable identity or change to the evaluator set withdraws the old rate while
preserving all completed work. A new sample needs three completed models and five
minutes before an estimate is issued. Older reviewers without the optional cached
identity endpoint keep counts available and report an unknown ETA. Public polling
reads only the retained in-process snapshot; it triggers no RPC or verification.
The exact progress GET has its own bounded read lane, using the configured
`maximum_concurrent_reads` limit. Slow native/status reads cannot consume its
slots. It remains available under the request-certification memory guard; that
exception grants no admission, native-read or submission authority. Unknown
cohorts still return 404.

File pages accept `file_index`, `offset` and `limit` (1–128 pieces). A preserved
chunk page has SHA-256 and byte size per piece. A concatenated R2 payload page
has `range_start`, byte size and the complete file hash. Files occur in original
signed manifest order. Zero-byte files have no pieces. A chunk package is not
a tar archive; `archive` is present only when a complete archive has been
separately prepared and bound to that package.

Capabilities authorize GET only and expire at `url_expires_at_utc`. Request the
metadata endpoint again to renew them. The API accepts model identities already
authorized by the private publication catalog; it has no arbitrary object-key
signing endpoint. Do not save capability URLs as durable model identities.

An unknown cohort or unpublished result returns 404. A missing, damaged or
unavailable published metadata record returns 503 and requires repair. It is
not silently reported as an empty result. Admission, artifact acceptance,
download availability, benchmark eligibility and reward activation remain
separate statuses.

## Download with restart support

Run `python -m umi.competition_cohort_public_download_cli --help` for the installed
client's arguments. Select the configured public API origin and identities from
the model catalog:

`python -m umi.competition_cohort_public_download_cli --api https://api.example.org --cohort COHORT_SHA256 --model MODEL_SHA256 --output /absolute/model-download`

The client writes `manifest.json` plus `model/` in a new, private output directory.
It supports original 8 MiB preserved chunks and C6+ concatenated payload ranges,
streams payloads through 128 KiB buffers, and retains at most one 128-entry URL
page. It verifies each native file at its final path before recording completion.
Wait for command success before consuming the output; interrupted output can
include a file awaiting its final check. It never executes submitted model code
or extracts an archive. Reserve local space for the complete model; the download
does not create a second full model copy.

Repeat the same command after an interruption. Keep `.umi-download/` with the
output: this private journal binds the API origin, cohort, model, transport and
verifier semantics. Completed pieces survive restart; only an interrupted piece
is retried. On a qualified Linux timestamp clock, unchanged completed files reuse
their native verification verdict without reading their payloads again. An
interrupted publication checks only its uncommitted file again, with repair
progress and an ETA. Platforms without a qualified clock visibly retain native
file verification on restart while reusing downloaded bytes. Expired URLs are
renewed from the same API; capabilities are never persisted in the journal or
printed in progress output.

A changed local file or missing verdict is reported as a repair. Add
`--repair-file relative/path/from/manifest` to redownload only that affected file;
other completed files remain reusable. Preserve a damaged journal for diagnosis;
do not delete it to force a reset. An unrelated, nonempty output directory is
refused, and symlinks, hard links and paths outside the manifest are not followed.

Progress includes completed bytes, elapsed time, ETA basis, retry/repair status
and available local space. `--timeout` controls the per-request idle timeout
(default 60 seconds), and `--refresh-attempts` controls capability renewal attempts
(default 3). Neither sets an overall download deadline. Exhausted retries leave
the journal available for the same command to resume.

## Publish from retained native results

The publisher consumes small native metadata. It does not open original reward
packages, rehash model payloads, replay evidence or contact chain RPC. Run it as
the owner of the selected private sources and publication directory:

`python -m umi.competition_cohort_public_cli publish --config /absolute/publisher.json`

`CohortPublicPublisherConfig` contains:

- `api`: the `CohortPublicApiConfig` used by the serving process.
- `policy`: an immutable metadata pin with `path`, `sha256`, `owner_uid` and exact
  `size_bytes`, selecting the original native policy JSON.
- Either `inventory`, another pin selecting `PublicModelInventory`, or
  `native_intake`, with the original `CohortIntakeConfig`, `cohort_sha256` and
  original `eligible_tracks`. The native source opens an owned SQLite read
  snapshot with `mode=ro` and `query_only`; it neither migrates the database nor
  acquires the native writer lock. It includes admitted superseded submissions.
- For certified service results, both `snapshot` and `service_quality_receipt`
  pins. Snapshot preparation and completed snapshot schemas are supported. The
  native receipt checksum, signed quality digest, evaluator quorum, retained UID
  bindings and cheap exact allocation arithmetic are checked.
- For legacy preserved models, `legacy_models`: one entry per model with
  `model_sha256`, pinned `association` and `package` metadata, plus optional
  `archive` hash, size and source-package digest. The compatibility reader
  supports `umi-cohort-model-preserved-package/1` and original 8 MiB chunks.
- For direct R2 models, `direct_promotion_journal`: its absolute SQLite `path`,
  `owner_uid` and exact `binding_sha256`. The reader selects only completed
  `direct-promotion` receipts for the original artifact acceptances, with no
  journal constructor or write transaction. It binds model, payload, source,
  preserved key and byte count. Acceptance without durable promotion remains
  listed while its download remains unavailable.

`inventory.scope` is `all_admitted_model_submissions` for native intake exports.
A retained settlement roster can instead be labeled `sealed_roster`; that
scope must not be represented as all admitted revisions. Public release
requires a signed model submission under supported original terms and quorum
artifact acceptance. Original contribution-terms versions 3 and 4 are supported;
an unknown terms digest is listed as `terms_review_required` with no download.

Publication installs content-addressed artifacts and a retained descriptor,
then atomically advances its checkpoint and serving descriptor under one
exporter lease. Repeating publication after an interruption restores a missing
serving descriptor while preserving admitted history and certified results. A
stale or incomplete inventory cannot remove previously published entries. A
missing checkpoint artifact or conflicting immutable artifact is an explicit
repair hold: restore the exact content-addressed metadata from the publication
backup before retrying. Never delete a checkpoint to force a fresh publication,
or replace signed inputs or native receipts to resolve a publication problem.
Retain the small publication metadata and checkpoints durably in R2. For automatic
certified C6+ catalogs, run
`python -m umi.competition_cohort_public_cli publish-certified --config /absolute/catalog-watch.json --watch`.
Its `NativePublicCatalogWatchConfig` selects `score_directory`, `state_directory`,
`cohorts` and a native `CohortPublicPublisherConfig` `template`. The selected score
artifact schedules publication; release still requires the original signed
admission, supported contribution terms, artifact acceptance and completed
preservation receipts. The output scope is `sealed_roster`, including unselected
reward candidates, rather than all historical intake revisions.

The template must preserve the native intake's original complete cohort/authority
bindings and `eligible_tracks`, even when current public submissions support only
models. This read-only binding does not reopen endpoint admission. A
`direct_promotion_source` selects the actual owner upload directory, owner UID and
hotkey, R2 endpoint/bucket and standing-review-policy digest. It derives each
original promotion journal binding from that cohort's retained transport history.
For retained chunk packages, `legacy_sources` maps cohort IDs to the same pinned
association/package metadata used by manual publication. Models outside the
certified catalog are ignored, and only missing download transports are added.
Successful original checks survive restart and incremental transport publication;
completed or damaged records never silently become fresh native verification.

Keep one publisher for each selected cohort/output directory. Refresh the watch
configuration automatically from the actual selected intake configuration as its
series changes; the watcher reloads an atomically replaced configuration. Preserve
completed state and independently deliver the resulting bounded `artifacts/` and
`cohorts/` metadata to the API account, artifacts first. No native owner restart,
chain RPC, model payload access or reward activation gate is needed. The current
public download client supports both retained chunk packages and concatenated
payload ranges. Its default HTTPX client sends `python-httpx/<version>` with
`trust_env=False`; raw Python-urllib requests can be rejected by the gateway, so
use the supported client or an explicit accepted User-Agent for custom clients.

## Serve separately or through intake

A dedicated read-only sidecar avoids restarting native owners:

`python -m umi.competition_cohort_public_cli serve --config /absolute/api.json --port 8108`

The sidecar listens on loopback. Route only the public GET paths through the
existing public gateway. Its private API configuration has `results.directory`,
optional `r2_credential_path`, `r2_bucket`, `url_expiry_seconds`,
`maximum_concurrent_reads` and `maximum_artifact_bytes`. The default metadata
artifact bound is 64 MiB and can be raised explicitly; it is not a model-size
or evidence limit. Credentials use the private credential-export format read
by `umi.r2_sigv4.load_r2_credentials`. Use a bucket-scoped read-only R2 key.
The API process needs only the published projections and signing credential;
it does not need native databases, wallets or private evidence.

The same router is available through optional
`CompetitionServiceConfig.cohort_public_results`. Existing configuration bytes
are preserved when it is absent. Adding this option changes the runtime
configuration, so qualify the normal supported intake upgrade before enabling
it; a sidecar does not require that owner cutover.

Qualify publication, missing/corrupt metadata, repeat execution, client
interruption, expired capabilities and both retained chunk and direct payload
formats before a new cohort deployment. Source tests alone do not establish
that the selected C6 production paths have been deployed.

## Existing round APIs

The public intake origin is `https://api.umi.vision`. Use the round index below
to discover retained rounds, then follow each item's detail and results URLs.
The index and C3 provisional score pages are deployed. A missing results URL
means no score artifact has been published for that round. Scores alone do not
confirm certification or on-chain rewards.

### Existing reads

| Method and path | Meaning |
| --- | --- |
| `GET /v1/competition/status` | Current intake policy, schedule and readiness; schema remains `umi-competition-status/2` |
| `GET /v1/competition/rounds/{round_sha256}?offset=0&limit=20` | Retained result/submission IDs, first-observed blocks and conflict/equivocation flags |
| `GET /v1/competition/settlements/{round_sha256}` | Retained computed settlement, its `settlement_sha256`, and current dispute flags; 404 if absent |

Both detail URLs take the **round** SHA-256. The settlement SHA is the identity
of the returned settlement, not its URL parameter. Round results use their
existing offset pagination and contain IDs, not a score leaderboard. A round
detail page does not count infrastructure voids as scored results.

The settlement's `results` binds submissions to result or void evidence.
Its `projection.allocations` contains UID/hotkey allocations, exact
`numerator`/`denominator` shares, and `raw_weight`; `projection.uids` and
`projection.weights` contain the computed row. These are proposed allocations,
not token payouts, finalized rewards, or a score ranking. Void outcomes are
not zero scores. These round routes do not provide paid-work results. Use the cohort routes
above for retained service credits. Do not manufacture quality rankings from
projected weights.

The settlement response contains replay material as well as the projection.
The index below returns only an explicit metadata allowlist. Website consumers
should select the fields they display rather than republishing entire responses.

### Round index

`GET /v1/competition/rounds/index?limit=20`

This unauthenticated, read-only route discovers retained round IDs, including
historical rounds still in the configured intake ledger. It is registered ahead
of `/rounds/{round_sha256}`. Its distinct path preserves the authenticated
coordinator's `POST /v1/competition/rounds` transport and existing proxy routes.
Deployment must route `/rounds/index` to intake, as it does round detail reads.

The response schema is `umi-competition-round-index/1`:

| Field | Meaning |
| --- | --- |
| `source` | Always `configured_intake_store`; no caller-selected database or certificate source |
| `policy_sha256` | Configured current intake policy; each item carries its own round policy |
| `items` | At most `limit` summaries, ordered by descending immutable round sequence |
| `limit` | Default 20, reduced to the configured `maximum_page_size` if smaller; maximum 100 |
| `before_sequence` | Requested exclusive cursor, or null on the first page |
| `next_before_sequence` | Last returned sequence when another page exists; otherwise null |
| `chain_submission_authorized` | Always false |

Fetch subsequent pages with the returned cursor:

```text
GET /v1/competition/rounds/index?limit=20&before_sequence=42
```

`before_sequence` must be an integer from 1 through 4294967295. Invalid paging
returns 422. Newer appended rounds cannot shift or duplicate a continuation
page. Refresh the first page to see new rounds. Each response reads one SQLite
snapshot; outcome counts and disputes can change between requests. This is not
a persistent snapshot of the whole ledger. An empty ledger returns 200 with
`items: []` and a null next cursor. Unavailable or corrupt round metadata returns
503 without database paths or error details. Responses use `Cache-Control: no-store`
and the existing configured public-read concurrency limit.

Each item contains:

| Fields | Meaning |
| --- | --- |
| `round_sha256`, `sequence`, `policy_sha256` | Retained round identity, sequence and policy |
| `public_schedule`, `submission_close_block`, `eligible_tracks` | Committed schedule, actual roster-close block and included tracks |
| `roster_count` | Number of submissions in the frozen round |
| `independent_result_count`, `void_count` | Distinct submissions with retained independent or void evidence, respectively |
| `outcome_count` | Distinct submissions in the union of those evidence tables; duplicate evidence never increases this count |
| `conflicted`, `disputed` | Retained conflict/dispute markers; a round conflict also makes `disputed` true |
| `settlement_sha256` | Computed settlement identity, or null |
| `round_url`, `settlement_url` | Origin-relative existing detail URLs; settlement URL is null until a row exists |
| `results_url` | New score-page URL when an operator has configured a public result artifact for this round; otherwise null |
| `state`, `certification` | Retained progress and certification availability, defined below |
| `chain_submission_authorized` | Always false |

Counts come from indexed SQL over stored identities. They do not replay,
rescore, certify, or even load evaluation/settlement bodies. A conflicting
submission can appear in both evidence counts; `outcome_count` counts it once.
The new response excludes rosters, private case references, video URLs, model
outputs, evaluator evidence and packages. Round metadata is bounded to 64 KiB
per item before parsing and its digest/sequence are checked.

### Progress and certification

| `state` | Evidence in this source |
| --- | --- |
| `prepared` | Round exists; no result or outcome is retained yet |
| `evaluating` | Some result or outcome exists; no computed settlement is retained |
| `closed_computed_uncertified` | Computed settlement row exists; this index has no checked certification evidence |

These are retained-progress labels, not live worker status or wall-clock phases.
An expired round without a settlement can still say `prepared` or `evaluating`.
All outcomes being present does not itself establish settlement or certification.
Always display conflict/dispute flags with any result.

`certification` is always `not_checked` in this version: the configured intake
ledger has no verified certificate source. This does not assert that certificates
cannot exist elsewhere. No `certified` state is emitted. A cutoff certificate,
an unsigned settlement, a filename, or a complete outcome count is insufficient
evidence for such a state. Signed settlement exchange is authenticated evaluator
transport; published successor packages use their separately configured,
verified feed. Neither is inferred or fetched during public discovery.

The newest retained round is not necessarily the current intake round. Read
`/status` for the current policy and schedule; a newly opened intake may not yet
have a frozen round or round SHA. This index does not synthesize one. It makes no
claim about finality, signing-window validity, active weights or payment.

### Public score pages

`GET /v1/competition/rounds/{round_sha256}/results?offset=0&limit=20`

This route serves a reviewed public score artifact from a local file pinned by
SHA-256 in intake configuration. It never fetches a URL or runs score calculation
on a request. There is no upload route. Before configuring an artifact, the
publisher must recalculate candidate and incumbent metrics with native
`replay_evaluation` and `aggregate_quality`, using the retained settlement's
`observed_block` for historical replay. That block does not grant current
eligibility, renew a signing window, or create a certificate. The artifact must
exclude protected case text, references, hypotheses, media and model outputs.

The artifact schema is `umi-competition-public-results/1`, defined by
`PublicRoundResults` in `src/umi/competition_public_results.py`. It binds
`round_sha256`, `policy_sha256`, `settlement_sha256`, `observed_block` and
`scoring_method: "native_replay_evaluation_at_settlement_observed_block"`.
Its flags are fixed: `provisional: true`, `certified: false`,
`rewards_active: false`, `chain_submission_authorized: false`. These describe
the provisional publication and grant no chain authority.

The published `umi-cohort3-provisional-results/1` static asset is also accepted
directly. The configured hash pins its original bytes. Its explicitly allowed
fields are mapped into the general response below, preserving exact fractions
and ranks; its rows are sorted into submission order. This adapter requires its
closed/uncertified, deadline-missed and inactive-rewards flags and verified
scoring-runtime declaration. It does not rerun scoring or accept private fields.

`items` must cover the whole frozen roster, sorted by `submission_sha256`, with
at most 512 entries. Each entry contains only:

| Fields | Meaning |
| --- | --- |
| `submission_sha256`, `hotkey`, `uid`, `track` | Submission identity and registration at the settlement snapshot; UID is null when absent |
| `status` | `scored` or `void` |
| `result_sha256`, `independent_evidence_sha256` | Retained independent result binding, or null for voids |
| `void_decision_sha256`, `void_evidence_sha256` | Retained void binding, or null for scored rows |
| `first_observed_block` | First observation recorded in the settlement |
| `candidate`, `incumbent` | Native quality metrics, or null for voids |
| `score_rank` | Provisional rank within this track among scored submissions, or null for voids |

Each metric object has `aggregate` and `by_stratum`. Each quality is an exact
`numerator`/`denominator` pair encoded as decimal integer strings, plus a numeric
`decimal` approximation in [0, 1]. Strata use the native profile names
`fingerspelling`, `continuous`, and, for older policies, `short_utterance`.
Scores retain native eligibility/dependence-gate semantics; a zero computed
score and an infrastructure void are different outcomes.

Ranks use exact candidate aggregate fractions, descending within each track.
Ties share a rank; the next rank skips the tied positions (1, 1, 3). Rounded
decimals and projected weight allocations never determine rank. Pagination
stays in submission-ID order; `score_rank` remains the whole-track rank.

The response retains the artifact metadata and adds
`source: "configured_public_results_artifact"`, `artifact_sha256`,
`state: "closed_computed_uncertified"`, current SQL `conflicted`/`disputed` flags,
`total`, `offset`, `limit`, and `next_offset` (null at the end). The default limit
is 20, capped by the configured page size; the existing offset bound applies.
No published source gives 404. A bad digest, unknown field, missing source,
wrong ledger binding or unavailable database gives 503 without echoing input.
Out-of-range paging gives 422. Responses use `Cache-Control: no-store`.

Configuration is additive and defaults to no published sources:

```json
{
  "public_results_sources": [
    {
      "round_sha256": "<64 lowercase hex characters>",
      "artifact_sha256": "<SHA-256 of the exact public JSON file>",
      "path": "/absolute/operator-reviewed/public-results.json"
    }
  ]
}
```

The source file is bounded to 8 MiB and parsed with unknown fields forbidden.
Its round and settlement must match the configured intake database. Each miner
identity, UID, and outcome binding is checked against the retained submission,
settlement and evidence indexes. Settlement metadata extraction is bounded to
64 MiB of stored settlement JSON. Current disputes are read in the same SQL
snapshot. GET does not load private evaluation bodies or certify that the
publisher computed scores correctly; score provenance rests on the reviewed
offline calculation and the pinned artifact. The file path and source selection
cannot be supplied by a public request. A release-asset copy can serve as the
immediate static publication; enabling its dynamic API source is a separate
deployment action.

### Recurring score export and discovery

The native publisher can export each newly retained settlement without changing
intake configuration for every round. Add one operator-owned directory to intake:

```json
{
  "public_results_directory": {"directory": "/srv/umi/public-results"}
}
```

Existing `public_results_sources` remain supported, including the historical C3
artifact. A conflicting dynamic artifact cannot override a configured digest.
Enabling this feature requires a separately qualified intake release and its
honest source pin; it does not bypass `public_deployment.umi_source_tree_sha256`.
After that deployment, new descriptors are discovered on requests without an
intake restart. Missing directories initially mean no published results.

The publisher configuration has this shape (replace placeholders with exact
policy digests and private absolute paths):

```json
{
  "schema": "umi-public-results-publisher-config/1",
  "database": "/srv/umi/intake/competition.sqlite3",
  "policy_path": "/srv/umi/competition-policy.json",
  "policy_sha256": "<competition policy digest>",
  "scoring_policy_path": "/srv/umi/transport-policy.json",
  "scoring_policy_sha256": "<exact scoring/transport policy digest>",
  "predecessor_policy_paths": [],
  "public_results_directory": {"directory": "/srv/umi/public-results"},
  "limits": {
    "maximum_record_bytes": 67108864,
    "maximum_evidence_bytes": 536870912,
    "maximum_roster_bytes": 16777216
  },
  "maximum_rounds_per_poll": 8,
  "poll_seconds": 60
}
```

Supply the deal-preserving predecessor chain newest first when retained
submissions require it. Policy files and scoring runtime pins are checked;
submissions are replayed under the configured round policy with that explicit
lineage. Other policies' settlements are skipped, so the old C3 artifact can
remain pinned separately. A future policy transition needs a reviewed publisher
configuration; ordinary new rounds under the same policy do not.

Run one bounded scan with the qualified interpreter/source:

```sh
python -m umi.competition_public_results_cli --config /srv/umi/public-results-publisher.json
```

For an operator-managed persistent service, append `--watch`. It has no wallet,
network, inference, signing or weight-submit path. The service should run under
the intake operator, with read access to intake and policy files, write access
to its publication directory, and an appropriate CPU/memory budget. A live WAL
database also needs access to SQLite's WAL/shared-memory sidecars, including
permission to create them when absent. Keep the main database read-only and
retain the exporter's `mode=ro` and `query_only` checks. For a systemd service
using `ProtectSystem=strict`, the relevant path overrides are:

```ini
[Service]
ReadWritePaths=/srv/umi/public-results /srv/umi/intake
ReadOnlyPaths=/srv/umi/intake/competition.sqlite3
```

Replace these paths with the actual deployment paths. The database read-only
bind mount pins its inode: stop and restart the publisher around an intentional
database-file replacement. Do not mark the live database immutable to avoid
sidecar access; that disables locking assumptions required for concurrent
writers. See [SQLite's read-only WAL requirements](https://sqlite.org/wal.html#read_only_databases).

SIGTERM/SIGINT in watch mode finishes the current bounded batch before
exit; choose service stop grace to allow that work. One-shot mode exits nonzero
when a round is held. Watch mode reports held rounds and retries them on later
scans. Logs contain round identifiers and error classes, not validation payloads.

Each export uses a query-only consistent SQLite snapshot and reads one private
outcome at a time. It validates the settlement digest, full roster, cutoff and
first-observation bindings, and independently signed scored or void evidence.
Scores use the retained settlement observation block, without creating a new
arrival time. This is historical replay, not permission to sign an expired
round. The intake WAL remains writable while replay holds its read snapshot;
long replays can retain WAL pages until that snapshot closes. Size limits apply
to each record and the total evidence/roster bytes per round. No full model or
media is read. HTTP requests only check public artifacts and ledger metadata.

New artifacts use `umi-competition-public-results/2`. They retain version 1's
exact fractions, within-track ranks, outcome digests and unranked null-score
voids. They explicitly report `certification: "not_checked"`,
`rewards: "not_checked"`, and `chain_submission_authorized: false`; they do not
emit the version 1 `certified`/`rewards_active` booleans. Their results-page state
is `closed_computed`. Export verifies score evidence, not settlement certificate
quorum, projected allocations, current reward activation or on-chain payment.
The existing round-index state vocabulary is unchanged; its separate
`certification: "not_checked"` field remains authoritative about inspection scope.

The directory and its `artifacts`/`rounds` children are private and operator-owned.
Artifacts are installed as `artifacts/<sha256>.json`, then immutable descriptors
as `rounds/<round_sha256>.json`, with file and directory synchronization. Paths
cannot be supplied in descriptors or public requests. Symlinks, hardlinked
artifacts, digest changes and unknown public fields are rejected. Per-request
ledger checks expose current dispute flags without rewriting historical scores.

A local lease prevents concurrent publishers. A durable cursor bounds each
scan and wraps to discover late settlements and retry repaired failures. A
malformed round does not prevent later rounds from exporting. Lost cursor or
descriptor files can be reconstructed without changing artifact bytes; a
missing artifact can be regenerated only if it matches the retained descriptor.
Existing conflicting bytes are held rather than overwritten. Retain the output
directory across restarts; it contains the cursor, completion descriptors and
immutable public artifacts. Private evidence remains in the intake ledger.
