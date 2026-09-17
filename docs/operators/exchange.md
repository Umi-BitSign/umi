[Documentation](../README.md) / Evaluator exchange and retained history

# Evaluator exchange and retained history

- [Evaluator exchange](#open-competition-exchange)
- [Evaluator review history](#open-competition-review-history)

<a id="open-competition-exchange"></a>

## Evaluator exchange

The exchange delivers signed orders, scheduled reference reveals, and peer
results over hotkey-authenticated HTTPS. It can record complete independent
evaluation evidence in the coordinator's existing competition store. It has
no wallet and cannot sign orders, settlements, promotions, or chain weights.

<a id="open-competition-exchange--coordinator-setup"></a>

### Coordinator setup

Run one process behind an HTTPS reverse proxy. The command binds only loopback;
the proxy must reject compressed requests, enforce a 64 MiB + 8 KiB body limit,
and disable body logging and caching for this private route:
`POST /v1/competition/evaluators/exchange`.

Use a private configuration with schema `umi-evaluator-exchange-config/1`:

- `policy_sha256` and `chain`: the reviewed competition policy digest and its
  owned-finality configuration. Proof collection must finish within 15 seconds.
- `state_directory`: private durable exchange database and nonce store.
- `order_directory`: canonical quorum-signed `SignedEvaluationOrder` files,
  named `<order-body-digest>.json`.
- `reveal_directory`: committed `EvaluationSuite` files named
  `<suite-digest>.json`. Keep these private even before publication.
- `legacy_policy_sha256`: required when delivering endpoint orders; pass that
  same transport policy on the command line.
- Optional `intake_directory`: the existing competition store. Admissions,
  baseline initialization, cutoff scheduling, and round closure must already
  exist there. The relay will not create them to make a result eligible.
- Optional `host` and `port`: loopback address and port, default `127.0.0.1:8100`.

All configured directories must be separate, absolute, owned by the service
user, and inaccessible to other users. Symlinks and hardlinked input files are
rejected. Do not put wallets in this service's filesystem view. Transfer local
input files atomically with mode `0600` and their directories with mode `0700`.

```sh
umi-competition --policy /ABSOLUTE/POLICY.json serve-evaluator-exchange \
  --config /ABSOLUTE/EXCHANGE.json \
  --legacy-policy /ABSOLUTE/TRANSPORT-POLICY.json
```

Omit the transport-policy argument and setting for model-only operation. Supply
actual quorum-signed orders before their execution windows. The service rejects
reuse of one protected suite across different rounds. It does not retime late
orders or convert a missed coordinator deadline into miner fault.

<a id="open-competition-exchange--evaluator-setup"></a>

### Evaluator setup

Set `exchange_origin` in each [continuous evaluator](evaluation.md#open-competition-evaluator)
configuration to the proxy's credential-free HTTPS origin. The evaluator signs
short-lived transport requests with its existing named hotkey. The relay checks
policy membership and the exact order's audience before returning private data.
Operators do not need a per-validator API key or manual result uploads.

For endpoint operation, set `assignment_directory` to the running dispatcher's
`publication_directory`. The exchange client installs the exact signed endpoint
publication there. The dispatcher performs its own origin and deadline checks;
receiving an order alone does not authorize a translation request.

Delivery runs as one bounded background task. An unavailable relay does not
block local execution of already admitted orders. Missing reveals or independent
peer evidence still prevent new result signatures. Shutdown cancels and joins
the delivery task alongside active CPU work.

<a id="open-competition-exchange--retention-and-limits"></a>

### Retention and limits

The defaults retain 1,024 orders, 65,536 events, and 1 GiB of logical object
data. Individual objects are limited to 64 MiB; responses contain at most
16 descriptors, with each object fetched separately. Two requests can occupy
the server at once. Database overhead and rollback files need additional disk
space; set filesystem quotas and monitor capacity. Capacity exhaustion preserves
existing history and refuses additional objects.

The relay stores accepted objects before acknowledging them. Evaluators install
and retain objects before advancing their durable cursors. Retrying an identical
accepted upload returns its original receipt, even after round expiry. That
does not renew the round or authorize another chain transaction. Changed signed
peer results are retained as conflicts; workers hold that order across restart.

Each evaluator upload cycle sends at most one page of pending files and audits
a separate page of acknowledged files. Retained acknowledgments do not consume
the pending-upload budget. Both cursors rotate, and durable acknowledgments
prevent duplicate uploads after restart. The audits compare retained payloads
against their acknowledged digests; changed payloads or disappearing markers
stop that cycle. Outbox and delivery-marker counts remain bounded.

Reference suites are released only after the relay's owned finalized boundary
reaches the committed reveal block. Workers also check their own boundary before
installing the reveal and before signing results. Private endpoint transcripts
can contain URL credentials, so never publish the exchange database or peer
outboxes as public artifacts.

The optional coordinator collector replays complete scored or void evidence.
The coordinator records its actual collection block, independently of the
relay's earlier transport receipt. Delayed collection cannot backdate evidence
across the fixed settlement cutoff. Exact retries preserve the coordinator's
first retained receipt. Missing admission or cutoff state leaves collection
pending. Preserve these records; deleting them would lose first-arrival evidence.

Void votes and certificates carry all assigned evaluators' signed observations.
The relay verifies the deterministic decision and signatures before retaining
them. Endpoint observations must also match the exact assigned publication and
transport policy. A final certificate delivered to an evaluator never replaces
that evaluator's own completion and local receipt.

<a id="open-competition-exchange--what-this-establishes"></a>

### What this establishes

Local tests cover two workers reaching agreement through authenticated ASGI
HTTP transport, nonce replay across restart, reveal withholding, audience checks,
conflicting peer results, capacity holds, coordinator collection, and endpoint
publication delivery. The Linux runtime test uses the same exchange with actual
Podman execution. The ASGI tests do not exercise a public TLS proxy or establish
that two test hotkeys are independently administered operators.

The relay's cursor and arrival timestamp are transport observations. They do not
prove independently witnessed publication timing, model quality, rights approval,
or reward eligibility. The [round coordinator](rounds.md#open-competition-round-coordinator)
and [independent work signers](rounds.md#open-competition-work-signing) can supply its
cutoff and signed-order inputs. Settlement publication, production throughput,
and the reviewed 70/30 activation remain launch work. Keep the live registration
bridge unchanged until those gates pass.


<a id="open-competition-review-history"></a>

## Evaluator review history

The continuous evaluator maintains its own review history while signing work.
It does not copy the coordinator's SQLite database or treat the coordinator's
claimed admission time as its own observation.

This path uses `EvaluatorReviewStore` in `settlement_review_directory`. Enable
the round, work and settlement clients together as described in the
[evaluator guide](evaluation.md#open-competition-evaluator).

<a id="open-competition-review-history--initial-baseline"></a>

### Initial baseline

Each operator first selects and preserves the reviewed initial baseline in its
own archive. Initialize the review store with the same replay limits configured
for its evaluator:

```sh
umi-competition --policy /ABSOLUTE/POLICY.json initialize-baseline \
  --state /ABSOLUTE/EVALUATOR-REVIEWS \
  --manifest /ABSOLUTE/BASELINE-MANIFEST.json \
  --archive /ABSOLUTE/VERIFIED-ARCHIVE \
  --evaluator-review-limits /ABSOLUTE/REPLAY-LIMITS.json
```

This verifies the preserved bundle and records an initial reference without a
contributor reward. The worker does not choose a new initial baseline from an
incoming work proposal. The baseline, policy and later signed promotions must
agree across participating operators.

Repeat this initialization check when creating a replacement review directory.
Copying evaluator configuration and preserving the archive does not initialize
the new database. Confirm its baseline history before preparing the first round;
an empty review store cannot endorse work against the coordinator's incumbent.

The review store has a persistent role separate from the coordinator's intake.
Opening an intake database as evaluator history is rejected. Existing manually
seeded rehearsal databases cannot be reclassified. Keep them as historical test
evidence and use a separate review directory for the automatic path. Neither
live bridge validator uses this successor store.

<a id="open-competition-review-history--receiving-a-round"></a>

### Receiving a round

Before signing a work proposal, the evaluator checks its own prior cutoff vote
and suite reservation. It verifies the quorum certificate over the exact roster
and schedule, and checks the cutoff registration snapshot against its own retained
proof observation. The round signer records a locally signed proof receipt while
the snapshot is fresh, before signing the cutoff vote. That receipt binds the
exact proposal, owned execution boundary and observation boundary. Work signing
checks the original vote, suite reservation, proof-receipt signature and snapshot
binding, then reads a fresh current finalized head. This permits a verified
historical cutoff to remain usable after its original snapshot stops being a
fresh head. The execution and issue deadlines remain unchanged.

Old journals without a proof receipt still require a fresh independent collection
from the historical finality provider. A missing receipt cannot be created
retrospectively from coordinator data. Invalid or mismatched retained receipts
hold work rather than triggering a fallback. These evaluator-local receipts are
signed observations, not portable finality proofs or proof of independent
administration.

The store atomically retains the signed cutoff, complete signed roster and
actual receipt block. The first receipt must arrive before evaluation closes.
It must extend the round sequence without reusing a suite, and its incumbent
must match the locally preserved baseline. Capacity failures roll back the
whole receipt.

Submission receipts use `umi-evaluator-roster-observation/1` and contain
`first_observed_block`. They do not claim `accepted_block` or prove when the
coordinator originally received an enrollment. The signed cutoff authenticates
the selected roster; it does not independently prove absence of omitted
enrollments or global receipt timing. Those existing publication flags remain
false. The coordinator's own intake ledger retains its separate meaning.

An exact retry keeps the original receipt. Additional valid endorsements or a
different signature order do not replace it. Changed decisions, missing or
corrupt stored material, or a different local snapshot hold further work.
Restart and signer reads recheck the retained certificate and its bindings.
These receipts cannot be used to admit miners, prepare new coordinator rounds,
change the cutoff schedule, or create coordinator settlements.

<a id="open-competition-review-history--promotion-and-settlement"></a>

### Promotion and settlement

The received history supplies the round and submission bindings needed by the
existing independent evaluation and promotion checks. It does not create
evaluation results, sign a rights review, or award the contribution share.
Settlement signing still requires the worker's own completed execution and
evidence receipts, plus its reviewed promotion head.

For an explicitly supplied reviewed promotion, the existing no-weight `promote`
CLI also accepts `--evaluator-review-limits`. Its review must bind the exact
evaluation and preserved model; use the
[v2 agreed review](promotion.md#open-competition-promotion-agreement) to retain a common
history head with separate local receipt times.

The [reviewed promotion delivery](promotion.md#open-competition-promotion-delivery) path
retains completed independent evidence automatically and delivers approved v2
decisions through the existing authenticated round connection. Each operator
applies the decision using its own evidence, archive and actual finalized head.
Real protected-data evaluation, rights approval, independent operators,
signed activation and finalized incentive verification remain launch gates.
This implementation does not change the live bridge policy or deadlines.

Exchange timeouts and HTTP transport failures are retryable availability errors.
The continuous poll loop retries using retained journals and a fresh request
nonce. Authentication failures and malformed responses remain distinct errors;
retry never changes a signed case or extends its deadline. The lifecycle test
allows transport recovery but still requires every result, matching promotion
heads, the exact 70/30 package, and unchanged inference counts on retries.
