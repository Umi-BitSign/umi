# Endpoint dispatcher

This is the no-weight endpoint execution path for the open competition. It
consumes quorum-signed publications, sends their exact requests to miners and
retains responses for later replay. It neither generates protected challenges
nor signs evaluation results, promotions or chain weights. Production enrollment
and the simultaneous 70/30 activation still require the gates in the
[execution plan](OPEN_COMPETITION_EXECUTION_PLAN.md).

## Required inputs

Use a dedicated evaluator account with its named hotkey. The dispatcher never
loads the coldkey. Do not point its directories at either live bridge validator.
Each evaluator has its own journal and owned finality observer.

The config schema is `EndpointDispatchConfig` in
[`competition_dispatch.py`](../src/umi/competition_dispatch.py). It rejects
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

Budget for every assigned case, not just one request. Six tasks at a 120-second
inference limit already require at least 720 seconds for one single-worker miner,
before proof collection and delivery. A 300-second issue window is insufficient.
For a larger cohort, qualify the shared proof queue, HTTP concurrency, publication
discovery, and total per-miner serial workload before signing the window. Preserve
the per-request inference limit; do not edit deadlines after publication.

The chain config keeps the competition-policy digest. Its chain and finality pins
must equal those in the transport policy. The observer creates transport-bound
verified blocks directly. The dispatcher does not relabel competition-bound
blocks or treat an RPC finalized label as a verified attestation.

### Reading storage across runtime upgrades

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

## Run and feed miners

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
in [OPEN_COMPETITION.md](OPEN_COMPETITION.md).

The dispatcher reads one inbox file per poll and continues accepting later
publications without restarting. The inbox admits at most 1,024 entries; each
publication is bounded to 16 MiB. Journal quotas reserve outcome capacity before
admission. A rejected inbox file does not block already accepted assignments.
Inspect `publication_intake: held` locally and correct the producer or capacity
problem. Never clear the journal to recover space or retry work.

`--once` runs one bounded poll and waits for its requests. It may only retain a
publication or begin discovery grace. Use continuous mode for ongoing dispatch.
SIGTERM and SIGINT cancel in-flight work and close the observer.

## Evidence and recovery

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

Use [paired endpoint evaluation](OPEN_COMPETITION_ENDPOINT_EVALUATION.md) to run
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
