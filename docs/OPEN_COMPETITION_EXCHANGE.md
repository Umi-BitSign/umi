# Evaluator exchange

The exchange delivers signed orders, scheduled reference reveals, and peer
results over hotkey-authenticated HTTPS. It can record complete independent
evaluation evidence in the coordinator's existing competition store. It has
no wallet and cannot sign orders, settlements, promotions, or chain weights.

## Coordinator setup

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

## Evaluator setup

Set `exchange_origin` in each [continuous evaluator](OPEN_COMPETITION_EVALUATOR.md)
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

## Retention and limits

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

## What this establishes

Local tests cover two workers reaching agreement through authenticated ASGI
HTTP transport, nonce replay across restart, reveal withholding, audience checks,
conflicting peer results, capacity holds, coordinator collection, and endpoint
publication delivery. The Linux runtime test uses the same exchange with actual
Podman execution. The ASGI tests do not exercise a public TLS proxy or establish
that two test hotkeys are independently administered operators.

The relay's cursor and arrival timestamp are transport observations. They do not
prove independently witnessed publication timing, model quality, rights approval,
or reward eligibility. The [round coordinator](OPEN_COMPETITION_ROUND_COORDINATOR.md)
and [independent work signers](OPEN_COMPETITION_WORK_SIGNING.md) can supply its
cutoff and signed-order inputs. Settlement publication, production throughput,
and the reviewed 70/30 activation remain launch work. Keep the live registration
bridge unchanged until those gates pass.
