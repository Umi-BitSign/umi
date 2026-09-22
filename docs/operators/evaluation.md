[Documentation](../README.md) / Run an evaluator

# Run an evaluator

- [Continuous evaluator](#open-competition-evaluator)
- [Native Mac Studio evaluator](#open-competition-native-evaluator)
- [Paired endpoint evaluation](#open-competition-endpoint-evaluation)

<a id="open-competition-evaluator"></a>

## Continuous evaluator

`run-evaluator` executes signed work orders for endpoint and model submissions,
retains each result, and exchanges signed observations with the nominated
independent evaluators. It produces the existing `IndependentEvaluationEvidence`
used by settlement replay. Optional settlement signing returns endorsements to
the coordinator. The worker does not submit weights.

The imported baseline still has no contributor attribution. The approved
[70/30 launch rule](../competition/launch.md) burns the unallocated
model share until a model qualifies. Running this worker does not activate
weights or satisfy the launch profile's evaluation and review requirements.

Scoring is automatic; no human ASL judge is part of the work-order path.
The [private holdout](private-holdout.md#open-competition-private-holdout) supplies committed
English references from documented annotations. An independent evaluator is a
separately administered execution service, not a person grading translations.

<a id="open-competition-evaluator--inputs-and-identity"></a>

### Inputs and identity

Use one hotkey per worker and a dedicated configuration with schema
`umi-evaluator-config/1`. Required fields:

- `policy_sha256`: digest of the reviewed competition policy.
- `chain`: the existing owned-finality `CompetitionChainConfig`, with the same
  policy hash and `collection_timeout_seconds` no greater than 15.
- `evaluator_hotkey`, `wallet_name`, `hotkey_name`, `wallet_path`: the named
  evaluator hotkey. The command never requests the coldkey.
- `state_directory`, `order_directory`, `reveal_directory`, `peer_directory`,
  `outbox_directory`: distinct private absolute directories owned by this user.
- `archive_directory`, `video_directory`: the verified model archive and
  reference-free `<video-sha256>.mp4` inputs used by the existing CPU runner.
- For endpoints, `dispatch_directory` and `legacy_policy_sha256`: the local
  [dispatcher](dispatch.md#open-competition-dispatch) journal and exact transport policy.
  Supply both, or omit both for a model-only evaluator worker.
- `scheduling_capacity`: optional [shared scheduling limits](dispatch.md#shared-scheduling-capacity),
  matching the dispatcher, assignment feed and evidence assembler for that journal.
- `maximum_journal_bytes` limits the evaluator journal and supplies the default
  for each auxiliary journal separately. Optional `journal_limits` overrides
  `execution`, `round_signing`, `work_signing`, and `work_admission` independently.
  Every value is a byte ceiling between 1 KiB and 16 GiB. Account for all stores,
  scheduling history, chain caches and filesystem overhead when sizing a host.
  Changing a ceiling preserves existing evidence and reservations; it does not
  reclaim space or make an undersized store able to accept new work.
- `exchange_origin` enables the [authenticated exchange](exchange.md#open-competition-exchange).
  For automatic endpoint publication delivery, set `assignment_directory` to
  the dispatcher's separate `publication_directory`. No extra upload key is used.
- `round_coordinator_origin` enables [independent cutoff signing](rounds.md#open-competition-round-coordinator).
  The worker proves the exact proposed registration snapshot through its own
  provider before signing.
- `work_signing_chain` and `work_minimum_issue_ms` additionally enable
  [automatic work signing](rounds.md#open-competition-work-signing). Both are required,
  along with the round origin and endpoint transport policy. The separate
  owned observer independently verifies endpoint issuance. The worker requires
  its own retained cutoff vote before signing an order or authorization.
- `settlement_review_directory` and `settlement_replay_limits` enable
  [automatic settlement signing](settlement.md#open-competition-settlement-delivery), using
  the round origin and the worker's independently reviewed promotion history.
  Both fields are required together. With work signing enabled, the worker
  [retains independently checked cutoff receipts](exchange.md#open-competition-review-history)
  in this store. Initialize its preserved baseline first. Empty or conflicting
  promotion history holds signing; proposals cannot approve model contributions.

Configure an archive-capable `rpc_url` for providers that recover historical
transport headers and timestamp proofs. The ordinary public entrypoint can
return a historical value while rejecting its trie proof because the state was
discarded. Test both `state_queryStorageAt` and `state_getReadProof` at the oldest
height the signed window can require. The public
`wss://archive.chain.opentensor.ai:443` served those proofs in the launch
rehearsal. Returned data remains untrusted until the local verifier checks it
against an owned finalized state root. Keep the collection timeout and proof
checks enabled; changing the RPC endpoint does not grant finality authority.

Registration, weight-state and runtime-code proof providers can add
`proof_rpc_fallback_urls` with exactly two ordered, credential-free `wss://`
endpoints. Qualify independently operated providers, their genesis, current
proofs, and the historical depth each role requires. Different hostnames alone
do not establish provider independence. A recent-state endpoint may serve live
intake while lacking proofs for an older roster; keep an archive-capable primary
and qualify historical reads on a backup too.

Adding the two fallbacks to an otherwise identical configuration preserves the
existing registration namespace, captures, metadata artifacts and observed head.
The cache records the old and new configuration bindings and the explicit
transport list. Changing the primary endpoint, verifier pins or other fields
is not covered by this migration. Existing configs omit the new field from
serialization, preserving their bytes. Back up the cache before deploying a
reviewed control release and its new config; reverting to a config without the
fallback list is rejected after its binding has advanced.

The provider tries the primary, then each backup only as needed. Connections
are lazy and persistent, with separate method receive limits. HTTP 429 is logged
as `competition_proof_rpc_throttled` with provider index and bounded Retry-After;
URLs, headers and payloads are omitted. Cooldown is shared across methods and
concurrent requests. Invalid protocol data or proof/chain checks remain terminal.
Unavailable-state RPC errors may try the next provider with the same capture
hash; they never move an old request to the latest block. The original overall
collection timeout and finality freshness checks still apply.

This setting affects `FinalizedRegistrationProvider` and the separate weight
and runtime-code collectors in `FinalizedCompetitionWeightProvider`. Each keeps
its original proof/value limits; untrusted prefetched weight values remain bound
to the exact requested block and must pass native proof verification. It does
not configure transaction submission, the Rust observer's P2P finality transport,
unrelated JSON-RPC clients, or existing roles running another frozen source
release. Keep those deployment scopes explicit.

The owned observer uses `startup_timeout_seconds` for its first verified record
(600 seconds by default, configurable up to 900). The source implementation now
reconnects a silent follow stream after 15 seconds or half the configured head-age
limit, whichever is shorter. Publication journals have a stricter 60-second
freshness check; the reconnect allowance also needs room for a header's existing
age and restart time. It recovers from the last retained head after reaping the
old process. Signing and execution still require
a fresh verified head. See [observer recovery and release qualification](rounds.md#open-competition-round-coordinator--capacity-operations-and-verification);
an installed service needs the corresponding qualified release to use this behavior.

The source finality store uses private SQLite schema 3 for transactionally
maintained evidence counters. Opening a schema-2 store audits its history and
installs the counters in one write transaction. Config bindings, attestation
bytes and acceptance receipts remain unchanged. Read-only capture supports both
versions. Startup still verifies all retained evidence and rejects inconsistent
counters. Existing open writers execute the database triggers, but older binaries
cannot reopen schema 3. Upgrade shared writers together; do not lower the schema
version or delete history to force a downgrade. Include this migration in release
qualification before deploying the new source.

None of these directories may overlap each other, the wallet, or the chain
verifier's state. Paths cannot traverse symlinks. The model container receives
only its existing fixed model/video mounts, never this configuration, the
hotkey, peer evidence, or reference suite.

Defaults are a five-second poll, `maximum_parallel_jobs: 1`, four retained orders
per poll, 1,024 retained orders, and 1 GiB logical capacity for each of the
evaluator and execution journals. At most four CPU jobs may be configured in
parallel. Raise that bound only after timing the pinned runtime on the actual
host: concurrent jobs share CPU, memory and accelerator capacity, and a slower
job does not receive a deadline extension. A full queue stays scheduled until a
slot is free; it is not recorded as a failed execution attempt. Files and
individual exported objects are limited to 64 MiB. These limits do not bound
SQLite overhead, the archive, verifier cache or outbox filesystem; provision
quotas and monitor disk usage separately. Capacity exhaustion holds work and
preserves history. Poll/page/concurrency/capacity limits can be changed without
changing the journal's identity or data-path bindings.

For endpoint submissions, an evaluator executes the frozen baseline once per
round and reuses its completed receipts for other submissions in that same round.
The reservation binds the round, evaluator, model, runtime and ordered case list.
Every submission still retains its own evidence and consumes journal capacity.
The original execution boundaries and outputs remain unchanged. A failed or
interrupted baseline attempt holds the other consumers; changing miner identity
cannot trigger another attempt. Reuse never crosses rounds or evaluators.
Model-contribution jobs retain their existing candidate/incumbent execution order.

Completed historical evidence remains readable after this update. An old round
with execution attempts but no shared reservation cannot acquire one retroactively;
use a new round without deleting its history. This avoids selecting among earlier
baseline attempts. The shared-run path reduces repeated inference; it does not
establish full-network dispatch throughput or change any signed deadline.

```sh
umi-competition --policy /ABSOLUTE/POLICY.json run-evaluator \
  --config /ABSOLUTE/EVALUATOR.json \
  --legacy-policy /ABSOLUTE/TRANSPORT-POLICY.json
```

Omit `--legacy-policy` for model-only operation. `--once` polls one batch and
waits only for jobs it has already started; it does not force early reveal,
manufacture missing peer evidence, or finish an entire future round. Use a
service manager for continuous operation. The process holds an exclusive
per-state-directory lock, and shutdown cancels and joins active execution before
closing the owned observer.

<a id="open-competition-evaluator--work-orders-and-reveal"></a>

### Work orders and reveal

The coordinator delivers canonical `SignedEvaluationOrder` JSON as
`<order-body-digest>.json` in `order_directory`. Its `order` has schema
`umi-evaluation-order/1` and contains:

- The frozen `round`, signed `submission`, incumbent bundle, pinned CPU runtime
  and complete reference-free `cases`.
- A fixed `evaluators` list sorted by decoded account identity. Each belongs to
  a distinct policy control group. All listed evaluators must agree; the worker
  never substitutes additional hotkeys under its own administration.
- For an endpoint, its quorum-signed `publication`, matching the complete local
  incumbent job and every nominated evaluator's transport assignments.
- `no_weight: true`.

The outer `signatures` must independently meet the policy quorum over the exact
order body using the existing competition `sign_object` domain. Work signing is
disabled unless configured explicitly; it signs only the independently checked
frozen roster and nominated work. The exchange can populate these private
directories and deliver peer results automatically. Without an exchange,
deliver complete private files by atomic rename, without symlinks, hardlinks,
or group/world access. The directories are not public upload endpoints.

The worker waits for an owned finalized head after submission close before
starting inference. It uses the existing per-invocation boundary capture and
execution journal. Incomplete or failed execution never automatically reruns.
A conflicting signed order for the same evaluator/round/submission is retained
as a hold across restart. Later valid rounds continue independently.

After reveal, deliver the committed `EvaluationSuite` as
`<suite-digest>.json` in `reveal_directory`. The worker does not read it before
the round's reveal block. Endpoint workers fetch the required published Quicknet
pulses from the pinned endpoint and independently verify their signatures before
retaining them. They assemble only completed local dispatches. Missing responses,
coordinator delay, and infrastructure errors cannot become invented miner scores.

<a id="open-competition-evaluator--peer-agreement-and-output"></a>

### Peer agreement and output

The private outbox uses `<order-digest>.<evaluator-account-hex>.<kind>.json`:

| Kind | Contents | Consumer |
| --- | --- | --- |
| `execution` | Signed, complete local paired execution | Other nominated evaluators |
| `vote` | Signature on the common result and independently signed local run | Other nominated evaluators |
| `independent` | Complete quorum result and run records | Settlement coordinator |
| `void_vote` | Signature on a deterministic void and every assigned evaluator's observations | Other nominated evaluators |
| `void` | Complete void certificate with all assigned signatures | Settlement coordinator |

The exchange delivers each peer's `execution` and `vote` files unchanged into
`peer_directory`; offline operators can provide the same files themselves.
The worker verifies signatures and replays all nominated executions before
signing a common result. Outputs/status and per-case resource eligibility must
agree. Measured time uses the maximum across these fixed runs. It retains the
exact result and local-run signing intent before touching the hotkey and checks
a fresh owned head again before signing. Unavailable peers hold agreement.
Authenticated changes to retained peer artifacts produce a persistent conflict
hold, including when the conflicting inbox file is later removed.

Complete observations that show infrastructure failure, failed incumbent
evaluation, or disagreement use the explicit void path. Every assigned evaluator
must sign its own observations and the common void decision. Agreeing valid
results and scored miner failures cannot use this path. Missing observations
or a missing peer signature still hold the round. Scored and void signing
intents are mutually exclusive for one local slot, including after restart.

The worker retains the full void evidence and its actual first-observation
block. Settlement signing requires that local receipt to precede the fixed
cutoff and checks the evaluator's exact retained observation. A certificate
downloaded from a peer cannot substitute for local execution. Void outcomes
assign no score or model-contribution credit.

Completed execution, signatures and certificates survive restart. Private peer
inputs already retained in the journal can be reused if the transport copy is
removed. Lost outbox copies can be republished byte-for-byte from that history.
An expired certificate remains historical evidence and gives no permission to
submit a new chain transaction. Never delete journals to retry a case or make
an expired round current again.

Keep the outbox private: paired endpoint transcripts can contain transport URL
credentials. Evidence signatures identify claims and bytes; they do not prove
independent administration, protected-data rights, or publication timing.

<a id="open-competition-evaluator--remaining-deployment-connection"></a>

### Remaining deployment connection

The worker automates local execution, reveal handling and peer agreement across
successive signed orders. The exchange handles authenticated delivery and can
record completed evidence in an already admitted and closed coordinator round.
The round coordinator and configured independent work signers can now supply
ongoing quorum-signed orders. Reviewed private plans and protected suites remain
required inputs. Settlement publication, promotion review and signed successor
activation remain separate stages.
The [execution plan](../competition/launch.md) tracks those gates;
this command alone is not an open-mining launch.


<a id="open-competition-native-evaluator"></a>

## Native Mac Studio evaluator

The opt-in `umi-offline-mps-runtime/1` backend runs preserved Python model
bundles on macOS arm64. It does not change validator installation requirements
or activate a competition policy. Launch qualification is still in progress.

Select this runtime explicitly in a new signed competition policy. Its digest
differs from both Linux CPU profiles. Candidate and incumbent executions must
use the same runtime digest. Old rounds, cached authorizations and execution
journals keep their original bindings.

<a id="open-competition-native-evaluator--execution-contract"></a>

### Execution contract

The declared inference file receives one video path in `argv[1]` and writes
one UTF-8 English hypothesis to stdout. `UMI_EVALUATION_DEVICE=mps` identifies
the available accelerator. Models must include all their weights and required
files in the preserved bundle and use the reviewed installation's dependencies.
The runner downloads nothing and installs no submitted dependencies.

Each case starts a new Python process. Model loading and inference share the
policy deadline, including the launch profile's 120-second limit. There is no
warm-worker exception for the baseline. Scratch and Metal compiler-cache paths
are unique to each case. Reference labels and wallet paths are never supplied
to the model process.

Seatbelt denies network access, process forking, signaling other processes and
reading user data outside the declared model/dependency/input roots. A trusted
prelude chooses the multiprocessing `fork` context so import-time semaphore
locks do not start a resource-tracker process. Actual forks remain denied.
This backend does not support models that require child processes.

An independent watchdog owns the model process group. Closing its controller
pipe cancels the case; the wall-clock deadline also applies if the evaluator
exits. Tests exercise normal completion, deadlines and controller disconnects.
Cleanup uncertainty stops the operation and retains its namespace for review.

<a id="open-competition-native-evaluator--resource-limits"></a>

### Resource limits

This profile uses sampled RSS and aggregate scratch/compiler-cache ceilings,
checked about every 200 milliseconds. These are not Linux cgroup allocation
limits, and transient allocations can exceed them between observations. The
prelude also disables core dumps and bounds open descriptors and individual
file sizes. The operator must reserve host headroom for the miner and other
workloads. Do not describe this backend as equivalent to a container's hard
memory limit or as remote hardware attestation.

<a id="open-competition-native-evaluator--installation-binding"></a>

### Installation binding

`UMI_NATIVE_EVALUATOR_CONFIG` points to an owner-private canonical JSON file:

```json
{
  "schema": "umi-native-evaluator-paths/1",
  "roots": {
    "environment": "/ABSOLUTE/REVIEWED/ENVIRONMENT",
    "python": "/ABSOLUTE/REVIEWED/PYTHON",
    "overlay": "/ABSOLUTE/REVIEWED/NATIVE-OVERLAY"
  },
  "manifest": "/ABSOLUTE/PRIVATE/installation.json"
}
```

The example is formatted for reading; stored files must use canonical JSON.
The installation manifest has schema `umi-native-evaluator-installation/1`
and an `entries` array produced by `competition_native_inventory.inventory`.
The signed runtime binds the SHA-256 of its canonical bytes, the macOS build,
Python ABI, thread count, video bound and resource ceilings. Root paths are
local bindings; inventory entries use logical root names.

Verification hashes every installed file. It rejects links outside inventoried
roots, hardlinks, special files, writable group permissions and oversized trees.
The interpreter is `environment/bin/python`; it must resolve inside the
reviewed installation. The model and dependencies are read-only in the sandbox.
The native prelude currently supports CPython 3.10.

This mechanism verifies local files against approved hashes. It does not prove
that another operator ran those bytes. Evaluation evidence continues to rely
on the policy's evaluator identities and independent-control-group rules.

<a id="open-competition-native-evaluator--launch-gate"></a>

### Launch gate

Run inert sandbox and cancellation checks first, then the preserved baseline
through `execute_offline_case` on the six already-exposed qualification clips.
Do not use unused holdout cases for operational debugging. A standalone miner
or worker timing pass is insufficient: finish the connected execution, reveal,
settlement and replay before installing competition weights on validators.


<a id="open-competition-endpoint-evaluation"></a>

## Paired endpoint evaluation

Each evaluator compares a miner's retained endpoint responses with actual runs
of the preserved incumbent model on the same assigned videos. The endpoint
track does not require the miner to disclose model weights. The incumbent runs
use the pinned offline CPU container, with no network, wallet, or references
mounted into it.

This path prepares unsigned evaluation evidence. It does not activate the
competition, award contributor attribution to the imported baseline, or submit
chain weights. The [execution-plan launch gates](../competition/launch.md)
still apply, including the approved simultaneous 70/30 policy.

<a id="open-competition-endpoint-evaluation--before-reference-reveal"></a>

### Before reference reveal

Use the signed publication accepted by the [endpoint dispatcher](dispatch.md#open-competition-dispatch).
Prepare one local incumbent job for this evaluator and endpoint submission:

```sh
umi-competition --policy /ABSOLUTE/POLICY.json prepare-endpoint-incumbent \
  --legacy-policy /ABSOLUTE/TRANSPORT-POLICY.json \
  --publication /ABSOLUTE/PUBLICATION.json \
  --submission-sha256 ENDPOINT_SUBMISSION_DIGEST \
  --incumbent /ABSOLUTE/INCUMBENT-MANIFEST.json \
  --runtime /ABSOLUTE/CPU-RUNTIME.json \
  --evaluator-hotkey YOUR_PUBLIC_EVALUATOR_HOTKEY
```

Save that JSON privately as the job input. Preparation checks the publication's
independent signatures and derives its complete, reference-free case list. An
evaluator without those assignments cannot prepare the job.

Run the incumbent during the frozen evaluation interval, before references are
revealed. Videos must be available in the private source directory as
`<video-sha256>.mp4`; their bytes are checked against the assignments. The model
archive must already contain the hash-verified incumbent bundle.

```sh
umi-competition --policy /ABSOLUTE/POLICY.json run-endpoint-incumbent \
  --job /ABSOLUTE/ENDPOINT-INCUMBENT-JOB.json \
  --chain-config /ABSOLUTE/EVALUATOR-CHAIN.json \
  --archive /ABSOLUTE/PRIVATE/MODEL-ARCHIVE \
  --videos /ABSOLUTE/PRIVATE/VIDEOS \
  --state /ABSOLUTE/PRIVATE/INCUMBENT-EXECUTION
```

The command owns its finalized registration provider. Each actual invocation is
bounded by retained provider observations. The execution journal reserves the
job before starting the observer or container, retains stdout before awaiting
the finished boundary, and refuses an automatic rerun after failure or
cancellation. A complete retry returns the exact saved receipts without touching
the model archive or network. Never clear this journal to retry a case.

The output schema is `umi-endpoint-incumbent-evidence/1`. Save the complete JSON
privately. It contains only incumbent runs; endpoint responses remain in the
dispatcher journal. Existing model-contribution jobs and evidence retain their
original schemas and candidate/incumbent semantics.

<a id="open-competition-endpoint-evaluation--after-reference-reveal"></a>

### After reference reveal

Obtain the committed reference suite and matching Quicknet reveal pulses. The
pulse file has the form `{"pulses":[{"round":123,"randomness":"...","signature":"..."}]}`,
using actual retained records. Verification checks their pinned BLS signatures;
placeholder values cannot pass. Duplicate pulse rounds are rejected.

```sh
umi-competition --policy /ABSOLUTE/POLICY.json assemble-endpoint-execution \
  --incumbent-execution /ABSOLUTE/INCUMBENT-EVIDENCE.json \
  --dispatch-state /ABSOLUTE/PRIVATE/SCHEDULER \
  --publication-sha256 PUBLICATION_BODY_DIGEST \
  --legacy-policy /ABSOLUTE/TRANSPORT-POLICY.json \
  --suite /ABSOLUTE/REVEALED-SUITE.json \
  --reveal-pulses /ABSOLUTE/RETAINED-PULSES.json \
  --current-block OBSERVED_FINALIZED_BLOCK
```

The result is `umi-endpoint-paired-evidence/1`. Assembly requires all local
dispatches to be complete and to match their journal hashes. It replays exact
request signatures, authenticated response ciphertext and model-revision
bindings, then validates both roles against the committed suite. It never
resends a request or reruns the incumbent. Missing or uncertain dispatches
cannot be turned into miner failures. An unauthenticated transport outage voids
the evaluation under the existing scoring policy.

Each transcript is bounded to 1 MiB; a paired evidence object is bounded to
64 MiB. Keep it private: transport URLs can contain credentials. Retain the
scheduler, origin-proof cache and execution journal for review. Exported
signatures authenticate bytes; they do not independently prove publication
time, origin proofs, execution boundaries, or evaluator independence. Endpoint
elapsed time is evaluator-observed round-trip time. The paired record uses the
assigned request interval as a conservative endpoint block bound, alongside
the separately retained incumbent execution boundaries.

<a id="open-competition-endpoint-evaluation--independent-result-agreement"></a>

### Independent result agreement

Collect complete paired evidence from the required independent evaluator groups
in `{"executions":[...]}`. The existing `propose-execution-result` command now
accepts these endpoint records as well as model-execution records. It requires
matching round/submission/runtime assignments, exact outputs and compatible
resource eligibility. Disagreement cannot be averaged into an accepted result.

Each evaluator then runs `prepare-execution-record` against its own retained
paired evidence and the proposed result before signing. Both commands return
`signed: false` and `chain_submission_authorized: false`. The resulting signed
run records and shared result enter the existing independent-evaluation and
settlement flow. Multiple hotkeys controlled by one operator still count as
one evaluator group.

These commands handle one assigned endpoint job at a time. The
[continuous evaluator](evaluation.md#open-competition-evaluator) runs them across successive
quorum-signed orders and prepares independent evidence through signed peer
agreement. It requires coordinator order/reveal delivery and private peer
transport. Settlement publication remains a separate stage; the dispatcher
alone does not perform those steps.

<a id="open-competition-endpoint-evaluation--miner-historical-header-admission"></a>

### Miner historical-header admission

A miner starting after a transport window opens may not have that window's
announcement header in its local observer journal. Observers can also skip an
exact issuance height. This produces `finalized_history_unavailable` even when
the HTTP health endpoint and assignment feed are current.

For the no-weight competition miner, `--competition-chain-config` accepts a
canonical `umi-competition-chain-config/1` document. It uses the same owned
observer, bounded hash-linked ancestry recovery and timestamp storage-proof
verification as the dispatcher. Configure an archive-capable proof RPC, the
reviewed storage-proof verifier and metadata decoder, and a dedicated private
state directory. The finality target, binary and chain spec must match the
miner's other verifier arguments. The configuration is rejected outside
competition mode.

This path starts one observer and owns its shutdown. An old block is accepted
only through a retained verified header or a verified path to the process-owned
finalized anchor, with its timestamp proved against the recovered state root.
Failed proofs, stale heads and out-of-bound recovery remain request rejections.
It does not reset nonce or assignment journals, trust evaluator-supplied headers,
or authorize chain submissions.

The existing Darwin finality-only artifact does not include a storage-proof
verifier. Historical admission therefore needs separately qualified artifacts
for the selected host target before this configuration can be deployed there.
A unit-test pass alone does not qualify those artifacts or the running miner.
