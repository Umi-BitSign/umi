# Continuous evaluator

`run-evaluator` executes signed work orders for endpoint and model submissions,
retains each result, and exchanges signed observations with the nominated
independent evaluators. It produces the existing `IndependentEvaluationEvidence`
used by settlement replay. It does not publish settlements or submit weights.

The imported baseline still has no contributor attribution. Running this worker
does not activate the approved simultaneous 70/30 reward policy or satisfy its
protected-data, rights-review and independent-operator launch gates.

## Inputs and identity

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
  [dispatcher](OPEN_COMPETITION_DISPATCH.md) journal and exact transport policy.
  Supply both, or omit both for a model-only evaluator worker.
- `exchange_origin` enables the [authenticated exchange](OPEN_COMPETITION_EXCHANGE.md).
  For automatic endpoint publication delivery, set `assignment_directory` to
  the dispatcher's separate `publication_directory`. No extra upload key is used.

None of these directories may overlap each other, the wallet, or the chain
verifier's state. Paths cannot traverse symlinks. The model container receives
only its existing fixed model/video mounts, never this configuration, the
hotkey, peer evidence, or reference suite.

Defaults are a five-second poll, one CPU job at a time, four retained orders per
poll, 1,024 retained orders, and 1 GiB logical capacity for each of the evaluator
and execution journals. Files and individual exported objects are limited to
64 MiB. These limits do not bound SQLite overhead, the archive, verifier cache
or outbox filesystem; provision quotas and monitor disk usage separately.
Capacity exhaustion holds work and preserves history. Poll/page/capacity limits
can be changed without changing the journal's identity or data-path bindings.

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

## Work orders and reveal

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
order body using the existing competition `sign_object` domain. The worker
does not sign orders or choose a roster. The exchange can populate these private
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

## Peer agreement and output

The private outbox uses `<order-digest>.<evaluator-account-hex>.<kind>.json`:

| Kind | Contents | Consumer |
| --- | --- | --- |
| `execution` | Signed, complete local paired execution | Other nominated evaluators |
| `vote` | Signature on the common result and independently signed local run | Other nominated evaluators |
| `independent` | Complete quorum result and run records | Settlement coordinator |

The exchange delivers each peer's `execution` and `vote` files unchanged into
`peer_directory`; offline operators can provide the same files themselves.
The worker verifies signatures and replays all nominated executions before
signing a common result. Outputs/status and per-case resource eligibility must
agree. Measured time uses the maximum across these fixed runs. It retains the
exact result and local-run signing intent before touching the hotkey and checks
a fresh owned head again before signing. Unavailable peers hold agreement.
Authenticated changes to retained peer artifacts produce a persistent conflict
hold, including when the conflicting inbox file is later removed.

Completed execution, signatures and certificates survive restart. Private peer
inputs already retained in the journal can be reused if the transport copy is
removed. Lost outbox copies can be republished byte-for-byte from that history.
An expired certificate remains historical evidence and gives no permission to
submit a new chain transaction. Never delete journals to retry a case or make
an expired round current again.

Keep the outbox private: paired endpoint transcripts can contain transport URL
credentials. Evidence signatures identify claims and bytes; they do not prove
independent administration, protected-data rights, or publication timing.

## Remaining deployment connection

The worker automates local execution, reveal handling and peer agreement across
successive signed orders. The exchange handles authenticated delivery and can
record completed evidence in an already admitted and closed coordinator round.
It still needs ongoing quorum-signed orders and committed protected suites.
Settlement cutoff publication, promotion review and signed successor activation
remain separate stages.
The [execution plan](OPEN_COMPETITION_EXECUTION_PLAN.md) tracks those gates;
this command alone is not an open-mining launch.
