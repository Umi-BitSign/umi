# Open competition: implementation and activation status

The [version 0.2 whitepaper](../whitepaper/README.md) defines open endpoint
participation and optional model contributions. This document describes the
code that exists and the remaining production integration. Nothing here
authorizes new weights or changes the current bootstrap.

Launch evaluation uses automatic CER/WER scoring against a
[private labeled holdout](OPEN_COMPETITION_PRIVATE_HOLDOUT.md). A human ASL
grading panel is not required. Dataset provenance and training exclusion remain
required. The approved initial evaluator is UID 0 alone, under the disclosed
[single-operator launch profile](OPEN_COMPETITION_UID0_LAUNCH.md). This does not
claim independent reproduction by UID 54 or activate competition rewards.

The approved initial scoring profile is policy/suite version 2: one authentic
reference per clip, fingerspelling CER weighted 3/13 and continuous-signing WER
weighted 10/13. Version 1 retains its three-task, three-to-five-reference rules.
Scheduling and replay must use the same versioned policy. The 70/30 reward split
and 120-second launch inference limit are unchanged. See the private-holdout
procedure for preparation and disclosure requirements.

## Implemented; successor rewards inactive

- An explicit single-evaluator competition transport, bound to the same signer
  in the competition policy. It does not relax the historical four-validator
  calibration profile or require fabricated legacy publisher identities.
- Canonical, hotkey-signed submissions with explicit policy and terms binding.
- Registration-snapshot checks, persistent idempotent intake, replacement
  rate limits, and a paginated admission log.
- Transactional admission-record and payload-byte quotas, bounded pagination,
  separate read/write/readiness capacity, and connection/backlog limits.
- A wallet-free intake service using an owned GRANDPA observer and authenticated
  storage proofs for the complete SN78 registration map at one finalized root.
  It rejects stale heads, rollback, missing mappings and runtime-pin changes.
- An HTTPS client that submits an already signed public object, checks the
  receipt's binding, and retries only when the operator asks it to.
- Complete round rosters with a usable publication window and fixed incumbent.
- Full model manifests and byte-verified archives. Links, extra files,
  traversal, missing files and corruption are rejected without model execution.
- Bounded HTTPS retrieval of signed model bundles through the pinned-IP client,
  with exact streamed size/hash checks, private staging and atomic preservation.
- CER/WER replay from a separately committed reference suite, minimum stratum
  coverage, resource deadlines and independent evaluator-group signatures.
- Promotion quality gates, signed reconstruction/rights reviews, and an
  append-only baseline history with transactional incumbent replacement.
- Exact rational endpoint/model allocation and deterministic u16 projection.
  Every projected row says `chain_submission_authorized: false`.
- Durable quorum-result intake, conflict holds and per-control-group signed
  evidence. Holds survive rejected actions and restarts, and apply to both
  promotion and projection, including descendants of a disputed promotion.
- Independently signed evaluator run records bound to the common result, with
  separate timings, exact output agreement and per-case eligibility checks.
- A pre-fixed evidence cutoff, durable first-observation records and immutable
  local settlement. Late conflicts are recorded separately; they do not rewrite
  the settlement or erase evidence.
- A local HTTP rehearsal API and CLI, with no chain-submit command.
- A separate Linux rootless-Podman CPU execution adapter. Its command isolation,
  output bounds and cleanup paths have unit tests. The supplied community
  baseline completed one actual Linux ARM64 invocation through the evaluator
  with bounded private shared memory. This synthetic-video smoke test does not
  establish ASL accuracy, production throughput or an approved release image.
- A wallet-free paired-model job runner with finalized boundary reads, retained
  raw-output receipts and an execution journal. Completed retries return the
  original evidence; failed or interrupted jobs cannot automatically rerun.
- Common-result proposals and unsigned evaluator-run records derived from those
  retained paired runs, checked against the committed suite after reveal.
- Offline replay of legacy authenticated endpoint transcripts, including real
  signature verification and timelock decryption. This bridge sends no requests
  and does not authorize successor work at a miner.
- A weight-disabled miner mode for a locally loaded, quorum-signed publication
  of exact successor assignments. Authenticated caller identity, model revision,
  local serving origin and successor-bound wire IDs are checked before work.
  Admission still uses the concrete legacy finalized-block/Quicknet authority.
- A durable assignment journal with verified announcement/issuance bindings,
  deadline-aware publication and claims, and restart-safe uncertain-dispatch
  holds. Expired coordinator windows never become miner faults or new retries.
- A hotkey-authenticated assignment feed and bounded HTTPS discovery client.
  The feed releases a complete signed publication only to its single miner
  audience after all included issuance boundaries have been verified. Lists
  contain no video URLs. Neither listing nor retrieval grants a dispatch token.
- A feed-backed no-weight miner mode that installs verified assignments into the
  running process. It retains overlapping usable publications in a bounded cache
  and preserves the existing authenticated transport and durable resource ledgers.
  This removes per-round manual authorization-file restarts in rehearsal; it
  does not establish a production publication or dispatch workflow.
- A continuous no-weight evaluator dispatcher with a private signed-publication
  inbox, verified origin checks, durable pre-sign claims and bounded transport.
  Cancellation and unrecorded outcomes cannot trigger duplicate requests.
  Its retained transcripts connect to offline endpoint replay after reveal.
  See [the dispatcher guide](OPEN_COMPETITION_DISPATCH.md). Protected round
  production and independent evidence publication still need deployment rehearsal.
- An owned-finality endpoint collector that verifies `Axons`, `Uids` and `Keys`
  under one pinned state root. HTTPS origins may use a public IP or a signed
  hostname whose public DNS answers include the announced IP. The transport
  connects to that IP with the signed hostname for TLS. Evidence is bounded
  and checked for integrity and rollback.
- Quorum-signed cutoff and settlement contracts, complete deterministic replay,
  and a durable publication journal. Alternate valid signature sets do not
  change the semantic statement; conflicting statements hold the round.
- Bounded immutable settlement packages and a wallet-free replay worker with
  durable receipts. Exact retries preserve the original receipt and separately
  report current conflict holds; the worker cannot submit weights.
- Read-only installed/staged supervisor inspection that verifies historical
  signed bindings and artifact bytes while preserving all upgrade/stop holds.
- Separate signed v4 supervisor and weight-authorization contracts, with
  exact-byte transaction intent, uncertain-effect recovery and per-round
  immutable input selection. The retained v3 history is preserved.
- A signed host/OCI upgrade command with wallet-free preflight, stopped-worker
  reconciliation, an immutable recovery archive, source publication and startup.
  Its resume command recovers a recorded interrupted switch without restoring
  the superseded writer. Both coordinator instances have separate paths,
  process locks, cleanup units and resource boundaries.
- Native amd64 and arm64 tests of signed preflight, rooted service startup,
  interruption and cleanup. The combined signed migration and interrupted-command
  scenario passed on both architectures at `aaf7689`; see the
  [native run](https://github.com/Umi-BitSign/umi/actions/runs/34741778051).
  It uses synthetic chain observations and a startup probe that verifies the
  installed anchor and original process lock. It does not run a live model or
  authorize a production transaction.
- Continuous round preparation, independent cutoff/work endorsement, evaluator
  exchange, reviewed promotion delivery and settlement publication. A synthetic
  two-round rehearsal restarts the coordinator and evaluators, executes the next
  round against the preserved promotion, and retains both exact 70/30 packages.
  The miner remains running and discovers the next assignments. Each round still
  requires its own prepared protected suite and explicit valid schedule.
- Explicit independently certified voids alongside scored results in complete
  mixed-outcome settlements. Missing observations or quorum remain holds; a void
  never assigns a miner-fault score. CLI and immutable-package replay accept both
  outcomes, and signers recheck conflicts after their final awaited chain read.

Model-bundle verification proves possession and byte integrity. The signed
review records are evaluator attestations about offline reconstruction and
rights. Neither a successful archive copy nor a signature proves those claims
by itself. The release must retain the underlying evidence and provide
independent access to it.

## Not deployed or complete

- A deployed HTTPS intake and observer-API integration. The owned-finality
  adapter has fixture tests, but needs real-sidecar and public-RPC latency
  rehearsal before serving miners.
- Reviewed archival retention and filesystem quotas. Admission limits count
  canonical submission and receipt bytes, not SQLite overhead or other stores.
  The HTTPS proxy still needs connection, header and per-source request limits
  on reads as well as writes. Rehearse the full deployment before exposing it.
- Deployment of immutable artifact retrieval, UMI Hugging Face publication and
  independent backup/restore monitoring. The local retrieval command does not
  provide those services or establish redistribution rights.
- The protected data pipeline, published capacity policy, round scheduling,
  the selected UID 0 evaluator and authenticated evidence exchange. The
  paired runner and local aggregation have fixture integration tests, not a
  completed live round or an independent execution rehearsal.
- Deployment of signed cutoff and settlement publication, finalized
  observation of their receipt times, and an explicit late-conflict recovery
  transition. A local settlement does not prove that no additional conflicting
  certificate exists or authorize a payment.
- A released, approved CPU inference image and protected-ASL quality/resource
  rehearsal. One real-model ARM64 synthetic-video smoke test passed; that does
  not measure ASL accuracy or production capacity. GPU model execution is not
  implemented by the CPU adapter.
- A deployed successor miner release, integrated evaluator dispatch and assignment
  feed. Static and feed-backed authorization
  check the signed mapping and existing transport schedule, but do not
  prove the chain-announced serving origin or independently observed publication
  timing. They are not a deployed self-service live onboarding path. Do not replace a
  legacy `ScoringPolicy` hash with a `CompetitionPolicy` hash in a live request.
  The new origin collector and release-gated feed have fixture integration tests;
  they do not yet establish a live protected-data publication workflow.
- Published license/reconstruction evidence and model-copy review operations.
  The [contributor checklist](MODEL_CONTRIBUTION_REVIEW.md), approved
  [version 1 terms and accepted-license list](MODEL_CONTRIBUTION_TERMS.md), and
  Sam's expert-referral review route are published. The signed launch policy
  must bind those exact terms; artifact-specific rights review and promotion
  remain separate launch requirements.
- Signed successor policy/activation artifacts and production chain submission.
- Publication of reviewed host/OCI upgrade artifacts and deployment-specific
  rehearsal. The dedicated upgrade command exists and has native migration tests;
  the existing fresh-install script cannot upgrade an installed supervisor.
  See [upgrade requirements](SUCCESSOR_SUPERVISOR_UPGRADE.md). Successor inputs
  must never be relabeled as the frozen bootstrap profile.

The protocol and lifecycle tests use inert model bytes and development signing
keys. The separate community-model smoke test uses the supplied real weights and
a synthetic video. Neither establishes real ASL model improvement, commercial
rights, independent operator participation or clinical fitness.

## Policy choices

`CompetitionPolicy` requires both `endpoint_reward_bps` and `model_reward_bps`;
they must sum to 10,000. There is no schema default. The operator approved
7,000 basis points (70%) for endpoint service and 3,000 (30%) for the current
promoted model's contributor for the initial open-competition launch. This
allocation must be included in the reviewed signed launch policy; this document
does not activate it or change the existing bootstrap.

The operator selected a simultaneous launch of endpoint and model-contribution
rewards. Activation therefore requires a qualifying preserved promotion with an
eligible contributor, plus qualifying endpoint evidence. Do not silently
substitute an endpoint-only launch or
assign the imported baseline a contributor to bypass this requirement.

The contribution share belongs to the current promoted model's registered
contributor while fresh evaluation qualifies it. The evaluator can run the
archived incumbent even when that contributor has no inference server online.
The endpoint share is proportional to qualifying exact quality scores. A new
promotion replaces model attribution prospectively, without perpetual royalties.

An allocated track with no qualifying recipient blocks row projection. The
initial profile never silently moves that share to another track or burns it.
The imported initial baseline has no contributor or model-reward recipient.
Until the first qualifying promotion, the model track must have zero basis
points or no successor row can be produced. A later change to that split needs
a new signed policy; promotion does not change the allocation automatically.
The activation policy must also choose explicit quality/resource bounds,
evaluation groups, licenses, submission cadence and expiry.

The remaining sequence and acceptance gates are tracked in
[OPEN_COMPETITION_EXECUTION_PLAN.md](OPEN_COMPETITION_EXECUTION_PLAN.md).

## Assignment and publication rehearsal

These commands operate on reviewed local artifacts. No live feed URL or
successor policy is supplied by these examples, and no command submits weights.

An endpoint proof check uses the owned finality sidecar and storage verifier:

```sh
umi-competition --policy policy.json check-endpoint-origin \
  --submission signed-endpoint.json --chain-config endpoint-chain.json
```

Use a dedicated private state directory in `endpoint-chain.json`. IP origins
must match the finalized Axon. For DNS origins, the port must match and the
resolved public addresses must include the finalized Axon IP. The hostname is
bound by the miner's signed submission; DNS is recorded as a local observation,
not a chain storage proof. The dispatcher connects to the captured IP without
resolving the hostname again, retaining the hostname for TLS verification and
HTTP routing. TLS identity, availability and authenticated miner responses still
need transport checks. See [hostname requirements](MINER_ENDPOINT_HOSTNAMES.md).
The storage layout is defined by the pinned runtime metadata; see the
[Subtensor storage definitions](https://github.com/opentensor/subtensor/blob/main/pallets/subtensor/src/lib.rs).

The local assignment feed serves a journal populated by the
[continuous dispatcher](OPEN_COMPETITION_DISPATCH.md) through typed publication,
observation and claim APIs. These APIs require concrete verifier-owned block
observations. There is no public publication or dispatch endpoint.

```sh
umi-competition --policy policy.json serve-assignment-feed \
  --legacy-policy legacy-policy.json --state /ABSOLUTE/PRIVATE/SCHEDULER \
  --nonce-path /ABSOLUTE/PRIVATE/FEED/nonces.sqlite3

umi-competition --policy policy.json discover-assignments \
  --legacy-policy legacy-policy.json --origin https://REVIEWED_ASSIGNMENT_HOST \
  --wallet-name YOUR_WALLET --hotkey-name YOUR_HOTKEY \
  --wallet-path /ABSOLUTE/PATH/TO/WALLETS
```

The server binds loopback port 8099 and requires an operator-managed HTTPS proxy
with ingress limits before external use. Discovery signs a fresh read query
using the named hotkey; it needs no per-miner credential. Add
`--publication PUBLICATION_SHA256` to retrieve and verify one exact signed
publication. Treat its output as private operational data because video URLs
can carry delivery credentials. This command does not install the authorization
into a running miner or start inference.

For ongoing discovery inside the no-weight miner process, use the separate
[`--competition-feed` mode](MINER_MODEL_INTEGRATION.md#successor-assignment-discovery-rehearsal).
It does not change this CLI command's behavior or activate competition rewards.

Use one miner and one usable issuance window per signed publication for this
feed. A multi-miner audience is refused; a future case within a larger publication
holds the complete document until every included issuance is verified. Retrieval
also refuses stale observations and publications without remaining unclaimed
work. The retained historical publication remains available to local audit APIs.

Cutoff and settlement certificates can be checked without signing anything:

```sh
umi-competition --policy policy.json verify-cutoff-publication \
  --certificate signed-cutoff.json --roster roster.json \
  --replay-limits publication-limits.json

umi-competition --policy policy.json verify-settlement-publication \
  --certificate signed-settlement.json --cutoff-certificate signed-cutoff.json \
  --roster roster.json --evidence independent-evidence.json \
  --retained-settlement retained-settlement.json \
  --replay-limits publication-limits.json
```

The roster is a `PublicationRoster`; the evidence wrapper is
`PublicationEvidenceInputs` in `competition_cli.py`. Each entry carries either
scored independent evidence or a complete independently certified void; both
remain bound to the exact frozen roster. The settlement and package commands
accept this same mixed evidence. Scored evaluation commands still reject voids.
Limits use
`PublicationReplayLimits` in `competition_publication.py`. A successful replay
does not prove publication timing or authorize a row. Real evaluation and
preservation evidence must support the retained settlement.

### Immutable settlement package rehearsal

These are coordinator rehearsal commands, not miner enrollment or validator
installation steps. They prepare a fixed-file package from retained evidence
and run a wallet-free settlement replay. They do not execute a model, access
the network, publish a release or submit weights.

```sh
umi-competition --policy policy.json prepare-settlement-package \
  --cutoff-certificate signed-cutoff.json \
  --certificate signed-settlement.json \
  --retained-settlement retained-settlement.json \
  --roster roster.json --evidence independent-evidence.json \
  --replay-limits publication-limits.json \
  --release-identity expected-release.json \
  --package-limits package-limits.json \
  --destination /ABSOLUTE/PRIVATE/PACKAGES

umi-competition --policy policy.json replay-settlement-package \
  --package /ABSOLUTE/PRIVATE/PACKAGES/PACKAGE_SHA256 \
  --expected-package-sha256 PACKAGE_SHA256 \
  --release-identity expected-release.json \
  --package-limits package-limits.json \
  --worker-capacity worker-capacity.json \
  --state /ABSOLUTE/PRIVATE/REPLAY_WORKER
```

Use the package path and digest returned by preparation. The expected policy
digest comes from `--policy`. Use the schemas `CompetitionPackageLimits` and
`CompetitionReleaseIdentity` in `competition_package.py`, and
`CompetitionWorkerCapacity` in `competition_worker.py`. All storage limits are
explicit. The preparation CLI additionally limits each source JSON file to
64 MiB; neither this command nor the package profile changes the old supervisor's
16 MiB bootstrap-input limit.

The package loader checks exact filenames, private ownership and permissions,
single-link regular files, canonical bytes, size/hash bounds and semantic
bindings. It refuses extra files, path traversal, links and mismatched expected
identities. The retained settlement must agree with its signed certificate and
pass full replay. Agreement does not establish independent custody or execution.

Preparation claims a digest-named directory exclusively. An interrupted write
leaves a mode-0700 partial directory that the loader refuses. The operator must
inspect and quarantine that exact partial directory before retrying preparation;
the command never overwrites or deletes it. Accepted directories are sealed at
mode 0500 with mode-0400 files. These permissions detect accidental changes;
they are not protection against a compromised owning account.

The worker retains an immutable local receipt. A retry returns the same
historical receipt and separately reports the journal's current conflict hold.
Always check `current_status`; an earlier successful receipt cannot clear a
later conflict. Restart can repeat interrupted arithmetic replay because this
worker has no external effect, but it cannot select different evidence for an
existing package identity.

Journal limits count reserved receipt/manifest bytes and retained certificate
bytes. SQLite overhead, backup space and filesystem quotas remain deployment
requirements. Capacity exhaustion stops new work without evicting history.

Release and platform fields are local equality bindings, not runtime
attestation. Results keep `runtime_identity_authenticated: false` and
`chain_submission_authorized: false`. The worker is not connected to the shared
supervisor feed, and real Linux sandbox rehearsal and the host upgrade remain
required before a release handoff.

## Local rehearsal commands

Use `python -m umi.competition_cli` from an installed checkout, or the installed
`umi-competition` entrypoint. Python 3.10 through 3.14 are supported.
Every command requires a reviewed policy JSON file. Input schemas are the
Pydantic models in [open_competition.py](../src/umi/open_competition.py).

```sh
umi-competition --policy policy.json inspect-policy

umi-competition --policy policy.json verify-bundle \
  --manifest model-bundle.json --source /ABSOLUTE/MODEL/DIRECTORY

umi-competition --policy policy.json preserve-bundle \
  --manifest model-bundle.json --source /ABSOLUTE/MODEL/DIRECTORY \
  --archive /ABSOLUTE/UMI/ARCHIVE

umi-competition --policy policy.json initialize-baseline \
  --state /ABSOLUTE/PRIVATE/STATE --archive /ABSOLUTE/UMI/ARCHIVE \
  --manifest baseline-bundle.json
```

The source model directory contains exactly the files named by the bundle
manifest. The manifest itself is supplied separately. An archived version has
`<model-digest>/manifest.json` and `<model-digest>/model/`. Initial baseline import
does not invent a miner contributor or assign a reward recipient.

The state directory must be private, mode 0700. Use a dedicated directory with
no wallet material. Each store is bound to one policy hash; changing the policy
requires an explicit state transition, not editing its metadata in place.

Miners can sign a prepared submission with their own hotkey:

```sh
umi-competition --policy policy.json sign-submission \
  --submission submission.json \
  --wallet-name YOUR_WALLET --hotkey-name YOUR_HOTKEY \
  --wallet-path /ABSOLUTE/PATH/TO/WALLETS
```

The command prints the signed public object. It does not upload anything or
access the coldkey. Never send wallet files or seed phrases to a registry.

Once a reviewed intake origin is published, submit that saved public object:

```sh
umi-competition --policy policy.json submit \
  --submission signed-submission.json --origin https://REVIEWED_INTAKE_HOST
```

This is a command example, not a live enrollment URL. The client refuses
redirects, oversized replies, mismatched receipts and any receipt claiming
chain submission is authorized. Version 2 receipts retain the registration
snapshot and its source marker. The client checks the snapshot digest and the
submitting hotkey's UID, and refuses fixture-source receipts. A source marker is
still a server claim over TLS, not a portable proof. No personal API key is
needed. A successful receipt says `accepted_no_weight`; it does not certify
evaluation or earnings.

For a local rehearsal using an explicitly supplied registration snapshot:

```sh
umi-competition --policy policy.json admit \
  --state /ABSOLUTE/PRIVATE/STATE --snapshot snapshot.json \
  --submission signed-submission.json --current-block 12345

umi-competition --policy policy.json serve-rehearsal \
  --state /ABSOLUTE/PRIVATE/STATE --snapshot snapshot.json --port 8098
```

The fixture server binds only `127.0.0.1`. A snapshot file is a rehearsal input,
not a finality proof. Its receipts are permanently marked `rehearsal_snapshot`;
putting this service behind a proxy does not make the miner client accept them.
Old version 1 receipts remain unchanged and cannot be upgraded by a retry.
The fixture CLI cannot select the verified-source marker or enable public binding.

### Owned-finality intake service

The separate service entrypoint accepts a strict local configuration:

```sh
umi-competition --policy policy.json serve-intake --config intake.json
```

Use the schemas in [competition_service.py](../src/umi/competition_service.py)
and [competition_chain.py](../src/umi/competition_chain.py). Configuration must
bind the exact policy digest, Finney genesis, runtime metadata, finality
checkpoint and both verifier binaries. Give intake and chain evidence separate,
private state directories. There are no wallet fields or fixture-provider
overrides in the configuration.

The service runs one loopback worker behind an operator-managed HTTPS proxy.
It does not trust forwarded headers. New admissions require a current verified
head; restarting cannot make old persisted finality fresh. Each capture checks
the subnet size and every forward and inverse UID/hotkey mapping against the
same state root. Runtime metadata and proof evidence are retained locally by
digest. The bounded cache fails closed when full; it never silently evicts
evidence. Backup/export and retention operations still need deployment design.

`GET /v1/competition/readiness` reports bounded provenance without private paths
or RPC addresses. Its evidence class is `verifier_attested_finality`, not a
portable offline finality proof. It reports `evaluation_ready: false` and
`rewards_active: false`. This route does not publish the full retained proof
archive. A working route is not a production launch gate by itself.

HTTP routes:

| Method and path | Purpose |
|---|---|
| `GET /v1/competition/status` | Explicit no-weight status, policy and preserved baseline |
| `POST /v1/competition/submissions` | Signed submission, no personal API key |
| `GET /v1/competition/submissions?offset=0&limit=20` | Paginated public admission log |
| `GET /v1/competition/submissions/{digest}` | One complete signed submission and its receipt |
| `GET /v1/competition/rounds/{digest}?offset=0&limit=20` | Bounded result identities, conflict status and recorded group equivocations |
| `GET /v1/competition/settlements/{round_digest}` | Immutable settlement and separate current dispute status, or 404 |

List and status responses contain bounded summaries; they do not embed every
model manifest or the complete evaluation history in each page.

Retry the exact signed body after network or snapshot failure. Successful
retries return the original receipt, including its original acceptance block;
they do not refresh expiry. Authenticated retries of a recorded admission do
not need a fresh proof capture; the saved snapshot and source stay unchanged.
New admissions still fail closed when current proofs are unavailable. A receipt
never certifies miner quality.

The remaining CLI subcommands are `close-round`, `replay-evaluation`, `promote`,
`project-weights` and `status`; each exposes its required files through `--help`.
Projection takes the current contributor from the local promotion store, not a
user-supplied reward-recipient flag. It requires the exact durably closed round
and reads its promotion head in the same transaction; a supplied roster alone
cannot establish that admission was complete.

## Conflict evidence and recovery

`AttestedResult` collects signatures on one common `EvaluationResult`.
The signed content includes each `CaseOutput.elapsed_ms`, the shared
`finished_block` and `runtime_sha256`. It has no separate per-evaluator run
records. Co-signers endorse those recorded observations; the schema does not
assert that separate runs had identical timings or prove those runs happened.
Do not remove timing fields from an existing signed result or describe them as
unsigned metadata.

`IndependentEvaluationEvidence` wraps that unchanged certificate plus one
separately signed `EvaluatorRunRecord` per common-result signer. Run signatures
use their own digest domain. Each record binds the policy, round, submission,
common result, suite, model, incumbent and runtime, plus its own interval,
outputs, timings and execution-evidence digest. Signer sets must match exactly,
with one key per authorized control group and no submitting hotkey evaluating
itself. All runs must agree on case identities, statuses and hypotheses. Their
timings may differ, but per-case resource eligibility and exact replayed scores
must agree. A signed evidence digest is still a claim: operators must retain
and independently inspect the underlying execution evidence.

The evidence slot is `(policy, round, submission)`. The store validates each
quorum certificate's signatures, control groups, historical interval and
immutable bindings before changing evidence state. It stores the canonical
result separately from its signatures. Signature order, extra signatures or
another key in the same group do not create a new result or extra group votes.

Two distinct valid quorum results for the same slot permanently mark that
round conflicted in this policy's store. Disjoint quorums also trigger the hold;
the detector does not depend on finding a shared double-signing key. Invalid
input and non-quorum dissent cannot poison the round. Recorded signatures
retain proof when a group signs conflicting results under different keys.

Evidence commits in its own transaction before any promotion or projection
transaction. Payability, snapshot, rights, archive and replay-expiry failures
cannot roll back independently authenticated evidence. Batch projection
records valid certificates even when another supplied entry is invalid.
Both action paths read the stored results and check the hold atomically.

For a local rehearsal, including evidence received after a reward window:

```sh
umi-competition --policy policy.json record-evaluation \
  --state /ABSOLUTE/PRIVATE/STATE --submission signed-submission.json \
  --round round.json --suite revealed-suite.json \
  --evaluation attested-result.json --observed-block 12345

umi-competition --policy policy.json round-status \
  --state /ABSOLUTE/PRIVATE/STATE --round-sha256 ROUND_SHA256
```

The observation block must be at or after reveal and cannot backdate the
store's observed block. The historical result must satisfy its original
assignment interval; accepting late evidence never renews its reward validity.
The CLI block remains a rehearsal input, not a finality proof.

A late conflict cannot retract a projection already returned to a caller or
an already-finalized chain payment. It blocks subsequent actions. If the
disputed round produced a preserved baseline, the store holds that baseline
and its descendants without rewriting the promotion history or deleting model
files. `baseline.held_for_conflict` exposes that state in status. There is no
clear-hold command; recovery requires an explicit policy transition and review.

On reopening an older rehearsal store, signed results retained in promotion
records populate the ledger. Their original record hashes and contents remain
unchanged, including records using the earlier nested `schema_` field spelling.
Historical projections were not retained and cannot be reconstructed from
that database. The pure arithmetic replay helper remains stateless; production
integration must use the durable guard and a separately specified settlement
procedure, not treat a helper's returned row as authorization.

## Local cutoff and settlement

`EvidenceCutoffSchedule` fixes one explicit cutoff for one complete round.
Record it before closing the round and no later than the submission-close
block. The cutoff must be at or after reveal and within the round's validity.
No default number of blocks or launch allocation is chosen by these commands.

```sh
umi-competition --policy policy.json fix-evidence-cutoff \
  --state /ABSOLUTE/PRIVATE/STATE --round round.json \
  --schedule cutoff.json --observed-block 12340

umi-competition --policy policy.json record-independent-evaluation \
  --state /ABSOLUTE/PRIVATE/STATE --submission signed-submission.json \
  --round round.json --suite revealed-suite.json \
  --evaluation independent-evidence.json --observed-block 12400

umi-competition --policy policy.json settle-round \
  --state /ABSOLUTE/PRIVATE/STATE --inputs settlement-inputs.json \
  --snapshot snapshot.json --current-block 12410

umi-competition --policy policy.json settlement-status \
  --state /ABSOLUTE/PRIVATE/STATE --round-sha256 ROUND_SHA256
```

These block numbers are illustrative local inputs, not finalized observations.
`SettlementInput` in [competition_cli.py](../src/umi/competition_cli.py) contains
the round, revealed suite and one signed-submission/independent-evidence pair
for every roster entry. Evidence must have been durably recorded by the fixed
cutoff. Retrying later cannot backdate its first observation.

Settlement replays retained evidence and binds the exact roster, result and
run-evidence identities, suite, registration snapshot, promotion head and row
in one transaction. It preserves the original artifact across retries and
restarts. Different inputs cannot overwrite it. Valid quorum certificates are
retained even when stronger run-evidence or settlement checks reject an action.
Late conflicts block subsequent actions and are exposed separately from the
immutable historical record. There is no clear-hold command.

These local cutoff and settlement objects remain weight-disabled. The separate
`SignedCutoffPublication` and `SignedSettlementPublication` contracts authenticate
and replay statements about them; see the publication rehearsal commands above.
Those contracts are implemented locally, but their production publication and
independently observed timing are not deployed. None of these objects authorizes
chain submission.

## Signed endpoint authorization rehearsal

The miner entrypoint accepts `--competition-policy`,
`--competition-authorization` and `--serving-origin` together, with the exact
submitted `--model-revision`. These supplement the existing transport policy,
finality observer, video-origin allowlist, backend and durable ledger arguments.
`python -m umi.miner --help` lists the complete required options. They are
rehearsal options; no live successor policy or assignment feed is published.

The authorization file uses `SignedEndpointAuthorization` from
[competition_authorization.py](../src/umi/competition_authorization.py). It
contains a reference-free case list, the frozen round, miner-signed endpoint
submissions and the exact requests, signed by the policy's evaluator-group
quorum. The file is bounded to 16 MiB and must be canonical, locally owned JSON.
Never include private keys or reference labels in it.

Each request's batch and challenge IDs bind the successor policy, round,
submission and evaluator, with the challenge also binding its case. The wire
`scoring_policy_hash` remains the actual legacy transport hash. A new successor
round cannot reuse an old cached assignment under another identity.

The HTTP handler passes the verified btauth caller into authorization before
reserving resources, fetching video or invoking the model. The exact signed
assignment and the concrete legacy finalized-block/Quicknet schedule must both
pass. The miner narrows inference and output limits to the successor policy.
Existing durable nonce, request-count and encrypted-response caches remain in
use; restarting does not reset those limits or rerun a cached answer.

This mode is `competition_no_weight`. The configured serving origin is matched
to the miner-signed submission; it is not an Axon storage proof. The first local
load time is not independently proven publication timing. Elapsed issue slots
are excluded on reload, so later usable assignments can still run. A publication
with no usable local assignments is rejected. This finite-file mode does not
supply the live scheduler, automatic assignment discovery or evidence binding
the protected suite's release to the successor block and Quicknet schedule.

## Signed model retrieval

`retrieve-bundle` downloads declared model files without executing them:

```sh
umi-competition --policy policy.json retrieve-bundle \
  --submission signed-model-submission.json \
  --source-base-url https://REVIEWED_ARTIFACT_HOST/IMMUTABLE_MODEL_DIRECTORY \
  --archive /ABSOLUTE/PRIVATE/ARCHIVE \
  --maximum-files REVIEWED_FILE_LIMIT \
  --maximum-file-bytes REVIEWED_FILE_BYTE_LIMIT \
  --maximum-total-bytes REVIEWED_TOTAL_BYTE_LIMIT \
  --request-timeout-seconds REVIEWED_REQUEST_TIMEOUT \
  --total-download-timeout-seconds REVIEWED_DOWNLOAD_TIMEOUT
```

The operator must supply numeric limits. The source URL is an untrusted location
hint; the signed manifest authenticates the exact bytes. Retrieval uses HTTPS on
port 443, rejects redirects and private DNS answers, pins the resolved address,
and disables environment proxies. Each streamed file must match its exact size
and SHA-256 digest. Files remain private data throughout retrieval.

The completed stage is verified before atomic content-addressed preservation.
An existing verified archive is returned without downloading again. Failure or
cancellation removes only this retrieval's staging directory; prior archives
remain intact. Peak disk space must allow roughly twice the bundle size for
staging and the verified copy, plus retained history and filesystem overhead.
The byte limits do not reserve disk space or replace filesystem quotas. A
preserved bundle still needs reconstruction, evaluation and rights review.

## CPU inference adapter contract

`OfflineCpuRuntime` pins an installed OCI image by digest and declares CPU,
memory, process, scratch-space and video-size limits. Its digest must equal the
policy's `evaluation_runtime_sha256`. The image is installed by the evaluator
operator; a miner cannot request an unreviewed image pull.

Runtime `umi-offline-cpu-runtime/2` supports CPU frameworks that create POSIX
semaphores or shared-memory buffers. It assigns up to one quarter of the declared
scratch budget (capped at 64 MiB) to private `/dev/shm`, with the remainder at
`/tmp`. Both mounts are bounded, non-executable tmpfs filesystems; their combined
allowance never exceeds `scratch_bytes`. Mount sizes are rounded down to 64 KiB
units. IPC remains private and the model/input trees remain read-only.
Runtime v1 retains its original single `/tmp` mount and read-only shared memory.
The version changes the runtime digest, so selecting v2 requires a policy that
binds it explicitly. It does not alter an existing signed policy.

The initial adapter supports exactly one manifest file with role `inference`,
ending in `.py`. The pinned image supplies `/usr/local/bin/python3` and all
runtime dependencies. The program receives `/input/video.mp4` as its only
argument and writes one English hypothesis to stdout. The complete model is
read-only at `/model`. No reference text is supplied to the container.

On the separate Linux evaluation host, the explicit single-case command is:

```sh
umi-competition --policy policy.json run-offline-case \
  --runtime offline-runtime.json --manifest model-bundle.json \
  --archive /ABSOLUTE/UMI/ARCHIVE --video assigned-video.mp4 \
  --case-id ASSIGNED_CASE_SHA256 --video-sha256 ASSIGNED_VIDEO_SHA256
```

This command executes the contributed inference code inside the declared
container. Run it only after the evaluator host and pinned image are reviewed.
Its output is a case observation; it does not sign an evaluation quorum or
promote a model automatically.

Cold start is included in the per-case deadline. Network access and proxy
inheritance are disabled. Output and runtime are bounded; failure cleanup
removes only the randomly named case container and waits through repeated
cancellation. A separate [Podman timeout](https://docs.podman.io/en/v4.3/markdown/podman-run.1.html#timeout-seconds)
limits container lifetime if the Python evaluator dies. Its seconds-based
limit does not extend the policy's millisecond scoring deadline.
Run this on a separate
wallet-free Linux evaluation host. Do not run arbitrary models inside either
existing validator VM or on a machine containing coldkeys.

## Paired-model execution rehearsal

`ModelEvaluationJob` in [competition_execution.py](../src/umi/competition_execution.py)
contains the frozen round, signed model submission, incumbent manifest, runtime
and evaluator identity. Its ordered case list contains case IDs, video hashes
and strata only. It contains no references, wallet paths or video URLs. Supply
each clip as `<video-sha256>.mp4` in an operator-controlled directory. Each clip
is read with a size limit, checked against its hash and copied into the
single-video sandbox input; the source directory is never mounted.

```sh
umi-competition --policy policy.json run-model-evaluation \
  --job model-job.json --chain-config chain-config.json \
  --archive /ABSOLUTE/UMI/ARCHIVE --videos /ABSOLUTE/PRIVATE/CLIPS \
  --state /ABSOLUTE/PRIVATE/EXECUTION_STATE

umi-competition --policy policy.json execution-status \
  --state /ABSOLUTE/PRIVATE/EXECUTION_STATE --execution-key EXECUTION_SHA256
```

Use a separate wallet-free Linux host, outside the UID 0 and UID 54 VMs. The
evaluator needs its own reviewed runtime, archived models, protected clips and
approved chain pins. No such live evaluator configuration or inference image is published by
this change. A local job file is not an authenticated round announcement.

The runner reserves one attempt per evaluator/round/submission before starting
the finalized observer. Startup waits, within its configured deadline, for a
new owned verified head. It then runs the candidate and incumbent sequentially
on each case, checking finalized boundaries around every invocation. Cold
start is timed; archive verification and finality collection are outside the
inference timer but must still fit within the round. Large models need a
throughput rehearsal because the adapter rechecks the archive before each case.

Each returned execution retains its bounded stdout prefix, outcome, elapsed
time and model/runtime/video digests. Stdout is persisted before the next
finality read. If that read fails, the pending observation remains in the
journal and the job fails without assigning miner blame. Missing evidence
after an abrupt crash never permits an automatic rerun. Completed retries
return the original evidence without reading models or starting the observer.
Keep the journal and the finalized provider's proof cache together in reviewed
backups. Boundary digests alone are not portable finality proofs.

The journal defaults to 1,024 jobs and 1 GiB of reserved logical receipt space;
`--maximum-jobs` and `--maximum-evidence-bytes` can set operator-reviewed limits.
Capacity includes worst-case JSON escaping. It excludes model/video archives
and database overhead. Full journals reject new jobs without deleting history.
The [continuous evaluator](OPEN_COMPETITION_EVALUATOR.md) now advances signed
orders through execution, reveal and peer agreement. Coordinator order delivery
and fleet-wide evaluator capacity management still need deployment wiring.

After the authorized reveal, local proposal commands check the retained cases
against the full committed suite:

```sh
umi-competition --policy policy.json propose-execution-result \
  --inputs executions.json --suite revealed-suite.json --current-block OBSERVED_BLOCK

umi-competition --policy policy.json prepare-execution-record \
  --execution execution.json --result common-result.json \
  --suite revealed-suite.json --current-block OBSERVED_BLOCK
```

`executions.json` contains an `executions` array of complete retained evidence
objects. The proposal requires distinct authorized evaluator groups, identical
outputs/statuses and matching per-case resource eligibility. It uses the
maximum observed elapsed time for each case and the latest completion block.
Each evaluator checks this proposal against its own run before co-signing.
The second command prepares the separate unsigned run record whose execution
digest identifies the retained artifact. Command output wraps the proposed
object in `object`; extract that member when preparing `common-result.json`.

Neither command opens a wallet, signs, publishes evidence, changes a promotion
head or submits weights. `--current-block` here is a local replay input, not
proof that reveal occurred. A production signing/release service still needs
its owned finalized reveal check and authenticated evidence exchange. CLI JSON
inputs, including an aggregate `executions` file, are capped at 64 MiB; choose
and rehearse the release's case/quorum/output bounds accordingly.

## Intake capacity configuration

`CompetitionServiceConfig` has operator-controlled `admission_capacity` and
`api_limits` fields. These are service bounds, not a miner reward rule:

| Bound | Default |
| --- | --- |
| Retained admissions | 65,536 |
| Canonical signed-submission plus receipt bytes | 2 GiB |
| Concurrent submissions / reads / readiness checks | 8 / 16 / 2 |
| Concurrent finalized registration collections | 1 |
| Maximum page offset / page size | 65,536 / 100 |
| HTTP concurrency / socket backlog | 64 / 128 |

Admission accounting and insertion share one SQLite transaction. Quota failures
do not advance the sequence or observed-block state. Historical authenticated
retries return their original receipts even if quotas are lowered below current
usage. Capacity exhaustion returns a bounded 503 response. Operators must
provision capacity and a retention plan; restarting does not erase the ledger.
Connection limits are process-local. The reviewed HTTPS proxy must also bound
headers, slow connections and per-source traffic, including read routes.

## Release checks

```sh
python -m pytest -q tests/test_open_competition.py tests/test_competition_*.py
python -m pytest -q tests/test_publication.py
make -C whitepaper
```

Before production activation, complete Section 10 of the successor whitepaper
and publish the exact evidence. Continue the existing bootstrap only through
its signed hard sunset. No local CLI result changes that schedule.
