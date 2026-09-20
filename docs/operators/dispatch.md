[Documentation](../README.md) / Dispatch endpoint work

# Dispatch endpoint work

- [Endpoint dispatcher](#open-competition-dispatch)

<a id="open-competition-dispatch"></a>

## Endpoint dispatcher

This is the no-weight endpoint execution path for the open competition. It
consumes quorum-signed publications, sends their exact requests to miners and
retains responses for later replay. It neither generates protected challenges
nor signs evaluation results, promotions or chain weights. Production enrollment
and the simultaneous 70/30 activation still require the gates in the
[execution plan](../competition/launch.md).

<a id="open-competition-dispatch--required-inputs"></a>

### Required inputs

Use a dedicated evaluator account with its named hotkey. The dispatcher never
loads the coldkey. Do not point its directories at either live bridge validator.
Each evaluator has its own journal and owned finality observer.

The config schema is `EndpointDispatchConfig` in
[`competition_dispatch.py`](../../src/umi/competition_dispatch.py). It rejects
unknown fields and overlapping state/wallet directories. Supply these fields:

| Field | Value |
| --- | --- |
| `schema` | `umi-endpoint-dispatch-config/1` |
| `policy_sha256` | Digest of the reviewed competition policy |
| `legacy_policy_sha256` | Scoring-policy hash of the reviewed transport policy |
| `chain` | A complete `CompetitionChainConfig` object, including exact verifier pins and dedicated state directory |
| `journal_directory` | Absolute private scheduler directory, also used by the assignment feed |
| `publication_directory` | Separate absolute private directory for signed publications |
| `evaluator_hotkey` | This evaluator's public hotkey, registered in both policies |
| `wallet_name`, `hotkey_name`, `wallet_path` | Local hotkey wallet identifiers and absolute wallet root |
| `no_weight` | `true` |
| `scheduling_capacity` | Optional shared journal limits, described below |
| `timing_budget` | Qualified timing assumptions required before new endpoint work can be endorsed |

Defaults are a five-second poll, ten-second discovery grace, four concurrent
requests, pages of 32 assignments, and a 180-second total request timeout. At
most one request per miner runs at a time in this process. Select a timeout that
fits the reviewed inference and delivery budget. The signed response-close time
still limits every request; a timeout setting cannot extend it.

`maximum_concurrency` may be raised to 128 after qualifying the host and the
signed issue window for the intended cohort. The default remains four. Proof
requests queue before entering the provider's collection timeout and run one at
a time; miner HTTP requests can overlap. This queue does not extend any signed
deadline. A request that reaches its issue cutoff while queued remains unclaimed
and is recorded as infrastructure expiry, not a miner failure.

Budget for every assigned case. If six serialized tasks each consume the full
120-second inference limit, inference takes 720 seconds and the last task starts
after 600 seconds, before proof collection and delivery overhead. A 300-second
issue window cannot cover that case; actual inference may finish sooner.
The prospective dependence suite assigns three fingerspelling cases, 12 scored
continuous cases and 12 matched-swap controls. Its 27 serialized requests can
consume 3,240 seconds at the inference cap before proof, delivery and scheduling
overhead. Dependence-gated work requires a signed 5,400-second allowance.
Profiles that permit shorter allowances still need complete measured
qualification before selecting one.
For a larger cohort, qualify the shared proof queue, HTTP concurrency, publication
discovery, and total per-miner serial workload before signing the window. Preserve
the per-request inference limit; do not edit deadlines after publication.

For the single-evaluator competition transport, prepare a new policy with an
explicit `issue_allowance_seconds` between 300 and 28800. The builder retains
the historical 300-second default so existing policy construction and digests
do not change silently. A dependence-gated release must explicitly pass 5400;
work preparation rejects a shorter signed transport for that profile. The
extended allowance changes the transport-policy hash;
coordinator, evaluator, feed and miner must all use that new policy before any
assignments are signed. Existing assignments retain their original deadlines.
Legacy scoring-policy clocks remain fixed.

The clock derives the smallest whole multiple of the original 360-block stride
that contains issuance, responses and reveal. The 5400-second (90-minute) issue
allowance therefore uses a 720-block stride, about 144 minutes at the target
block interval. The response window stays 300 seconds, and the model's separately
configured 120-second inference limit is unchanged. Authentication still accepts
only the original 360-second nonce age: the dispatcher signs a fresh nonce after
claiming each request, rather than when the entire round was prepared. A
5400-second allowance is an available bound, not evidence that a full cohort can
finish. Measure publication, proof and request throughput before selecting it.

The chain config keeps the competition-policy digest. Its chain and finality pins
must equal those in the transport policy. The observer creates transport-bound
verified blocks directly. The dispatcher does not relabel competition-bound
blocks or treat an RPC finalized label as a verified attestation.

<a id="open-competition-dispatch--reading-storage-across-runtime-upgrades"></a>

#### Reading storage across runtime upgrades

For registration and endpoint reads, `chain.storage_codec_metadata_path` can
name an absolute regular file containing the approved SCALE metadata bytes.
Its SHA-256 must match `chain.chain_pin.metadata_sha256`. Supply the reviewed
artifact, not metadata fetched from an untrusted RPC during startup. Symlinks,
empty files, oversized files and digest mismatches are rejected before creating
provider state. Use a separate state directory when enabling this mode.

This optional mode derives storage keys and decodes values with the approved
codec while accepting changed runtime and transaction version numbers. Every
value still needs a proof under the owned finalized state root, strict decoding,
and the registration/origin checks. State versions other than 1 remain rejected.
Evidence identifies the mode as `reviewed_storage_codec/1`; reported runtime
numbers are RPC observations, not proof that the current runtime semantics match
the codec. Operators must review changes to the storage layout or its meaning.

This is a storage-read mode only. The weight transport rejects transaction
encoding with this context before signing. It does not authorize a newer runtime's
call encoding or transaction extensions. Without the optional field, the existing
exact-runtime checks and serialized configuration remain unchanged.

### Shared scheduling capacity

The dispatcher, endpoint evaluator, assignment feed and evidence assembler open
the same scheduling journal. Use the same limits in all four. The optional
`scheduling_capacity` object in dispatcher and evaluator configs has these defaults:

```json
{
  "maximum_publications": 1024,
  "maximum_assignments": 16384,
  "maximum_bytes": 1073741824,
  "maximum_outcome_bytes": 1048576
}
```

For `serve-assignment-feed` and `assemble-endpoint-execution`, supply that object
as a JSON file with `--scheduling-capacity /ABSOLUTE/CAPACITY.json`. Omission keeps
the historical defaults. This is source configuration; installed binaries must
support the option before using it. The outcome limit is bound into existing
journals and cannot be changed in place. The other limits can be increased
without rewriting retained evidence or changing signed assignments.

The default 1 GiB is insufficient for 256 endpoints with six cases: reserved
outcomes and events alone need 1,623,195,648 bytes per evaluator represented in
each publication, before publication bodies and finality proofs. Filesystem
overhead needs additional space. Configure and qualify the entire cohort.
The settings alone do not reserve work. Before a new endpoint endorsement, the
signer reconstructs the complete frozen cohort and reserves its publication,
assignment, outcome and event storage atomically. It also reserves up to 4 MiB
of verifier evidence plus 64 KiB of block metadata for each missing proof height
through the cohort's last deadline. Overlapping intervals share that allowance;
retained proofs count at their actual size. Separate unsigned-body and admission
records are charged too. Never delete evidence or retime work to regain capacity.
Evaluators sharing a journal share the immutable assignment and proof reservation.
Each evaluator must qualify its own dispatcher profile; those timing receipts are
separate and cannot substitute for one another.
Unused future-proof allowance is released only after every publication is
consumed and every assignment is recorded completed or expired. An unknown claim
or an unpublished body keeps its allowance. Retained evidence remains charged.

The first successful reservation upgrades the private journal to generation 2
and fences older writers, including already-open SQLite connections. Drain any
dispatched claim without a recorded completion before migration. Failed admission
rolls back the migration and the new reservation together. Historical signed
publications remain readable; new publications must match their reserved bodies.
Upgrade all services sharing this journal before enabling new endorsements.

### Timing qualification before endorsement

Configure `timing_budget` on the actual dispatcher before the work signer runs.
It records its operative concurrency, page size, poll cadence, discovery grace,
request timeout and publication inbox in the shared journal. Omitting this object
keeps an unqualified legacy dispatcher usable, but cannot authorize new endpoint
work or bypass an existing profile. Do not copy synthetic test timings.

Every budget field is explicit:

| Field | Required bound |
| --- | --- |
| `proof_collection_ms`, `origin_collection_ms` | Serialized owned-proof and serving-origin collection |
| `publication_ingestion_ms` | Parse, verify and durably ingest one publication |
| `local_cycle_ms` | Remaining polling and per-job local processing |
| `publication_delay_ms` | Endorsement through delivery of the complete signed inbox |
| `block_advance_numerator`, `block_advance_denominator_ms` | Assumed maximum block advance over elapsed milliseconds |
| `finality_headroom_blocks` | Observation age and finality catch-up allowance |
| `measurement_sha256` | Digest identifying the retained qualification measurements |

The calculation includes pending and reserved local assignments, per-miner
serialization, bounded page scans, repeated discovery waits, the current inbox
and full request timeouts. An unresolved claim holds further admission. The
dispatcher runs at most one request per miner. When its task slots cover every
distinct miner in the complete workload, the HTTP bound uses the longest miner
chain; spare slots do not shorten that chain. With fewer slots it also charges
for contention. Serialized proofs, ingestion and scan delays remain charged.
The block prediction is conditional on the supplied bound; a target block interval
does not establish that bound. Actual deadline and finality checks still apply.
The first qualification receipt is retained with the reservation.

Continuation of the exact admitted cohort reuses its receipt, so an active
request does not block the cohort's remaining endorsements. This never resets
the delivery allowance. After that allowance elapses, continuation requires all
cohort publications to have been journaled before its original deadline.
Budget for authorization/order signing, delivery and ingestion.

The dispatcher rechecks its profile each poll and inside the atomic claim path.
The production command holds an exclusive evaluator/journal lease through
shutdown, keeping its per-miner serialization and concurrency bound enforceable.
Changing a profile with unfinished work is rejected. These checks reserve
scheduler storage and qualify dispatch timing only. Whole-cohort work admission
also checks native signing, evaluator, execution and configured review-store
reservations before a new signature. A publication may use fewer bytes than its
reserved maximum; its verified receipt keeps the original bound and timing.
Full-round runtime and filesystem qualification still require a connected
rehearsal before release.

<a id="open-competition-dispatch--run-and-feed-miners"></a>

### Run and feed miners

Create the publication directory with mode 0700 under the evaluator account.
Put each complete canonical `SignedEndpointAuthorization` in it as
`<publication-body-digest>.json`, mode 0600 or 0400. Write to a temporary filename
and atomically rename it only after all bytes are present. The reviewed round
producer must supply the required independent signatures. There is no command
that fabricates them or edits signed deadlines.

Run the dispatcher and feed as separate processes under the same account:

```sh
umi-competition --policy /ABSOLUTE/POLICY.json run-endpoint-dispatch \
  --legacy-policy /ABSOLUTE/TRANSPORT-POLICY.json \
  --config /ABSOLUTE/DISPATCH-CONFIG.json

umi-competition --policy /ABSOLUTE/POLICY.json serve-assignment-feed \
  --legacy-policy /ABSOLUTE/TRANSPORT-POLICY.json \
  --state /ABSOLUTE/PRIVATE/SCHEDULER \
  --nonce-path /ABSOLUTE/PRIVATE/FEED/nonces.sqlite3
```

The feed binds loopback. An operator-managed HTTPS proxy with ingress limits
must protect it before miners connect. Use the same scheduler path and policies
in both commands. Miners use the existing feed-backed competition mode described
in [OPEN_COMPETITION.md](../OPEN_COMPETITION.md).

The dispatcher reads one inbox file per poll and continues accepting later
publications without restarting. The inbox admits at most 1,024 entries; each
publication is bounded to 16 MiB. Journal quotas reserve outcome capacity before
admission. A rejected inbox file does not block already accepted assignments.
Inspect `publication_intake: held` locally and correct the producer or capacity
problem. Never clear the journal to recover space or retry work.

`--once` runs one bounded poll and waits for its requests. It may only retain a
publication or begin discovery grace. Use continuous mode for ongoing dispatch.
SIGTERM and SIGINT cancel in-flight work and close the observer.

<a id="open-competition-dispatch--evidence-and-recovery"></a>

### Evidence and recovery

If an observer restart missed an exact historical issuance header, the transport
provider can recover its identity from the nearest later header retained by that
same owned observer. It fetches headers by the expected parent hash, reconstructs
their SCALE encoding, and verifies every hash and height back to the requested
block. It then verifies `Timestamp.Now` membership against the recovered state
root using the configured storage codec and proof verifier.

Recovery is limited to 2,048 parent links, 64 KiB per header and 1 MiB for the
encoded path. The existing collection timeout and evidence-cache quota also
apply. A fresh owned head is required before and after recovery. Headers before
the configured minimum remain unavailable. Invalid proofs or exhausted limits
hold work rather than accepting an RPC finality claim.

The provider retains this derivation separately as
`umi-owned-finalized-ancestor/1`, with evidence class
`verified_finalized_ancestry`. It never inserts a replacement observer record or
claims when the historical header was locally received. Original journal gaps
remain visible. Consumers that require an original local acceptance receipt
still cannot use a recovered header. This recovery does not extend a signed
deadline, reopen expired work, or authorize a resend.

The dispatcher waits until the entire publication is retrievable, then gives
miners the configured discovery grace. This delay does not prove that every
miner fetched it or provide independent publication-time evidence. A restart
begins grace again and cannot extend the signed issue window.

Before signing, it verifies the current bidirectional UID/hotkey mapping and
announced public-IP HTTPS origin. The Axon application tag may be `0` (legacy)
or `4` (the current SDK's `ServeAxon` default); other tags are rejected. Neither
tag substitutes for the HTTPS and signed-response checks. A signed hostname must
resolve exclusively to public addresses including the announced IP, on the same
port. The dispatcher
pins that IP while keeping the hostname for TLS/SNI and the HTTP Host header;
it does not perform a second DNS lookup. It then commits a journal claim.
Completed work is never resent. Cancellation, deadline or recording failure after the claim
leaves `uncertain_dispatched`. That uncertainty cannot be automatically retried,
even if the miner may never have received the request. Expired coordinator work
is retained with `miner_fault: false`.

The private transcript retains exact request/authentication and response bytes,
receipt times, and the digest of the separately retained origin proof. A
`completed` dispatch means bytes were recorded, not that the miner succeeded.
`replay_dispatch_transcript` reconstructs those inputs without a wallet or a
network request and uses the existing endpoint replay checks. Authenticated
sealed responses require the matching verified reveal pulse and committed
reference suite. Unauthenticated transport failures remain infrastructure
failures. This replay does not certify origin proofs or independent evaluation.

Use [paired endpoint evaluation](evaluation.md#open-competition-endpoint-evaluation) to run
the preserved incumbent on the assigned videos before reveal, then assemble
the retained endpoint responses into evidence for independent result agreement.

Keep the scheduler and origin evidence through the evaluation/audit retention
period. Do not publish raw transcripts or inbox files: video delivery URLs can
contain credentials. Public loop status contains bounded counters and no wallet
paths, endpoint URLs or authentication headers.

The synthetic integration tests cover the actual miner HTTP handler, signature
and sealed-response checks, hostname routing and connection pinning, inbox
admission, wrong origins, expired work, lost results and restart without duplicate
dispatch. They do not establish protected
ASL accuracy, independent operator participation or production activation.
