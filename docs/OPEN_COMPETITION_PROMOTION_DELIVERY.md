# Reviewed promotion delivery

The coordinator can deliver an approved model promotion to continuous evaluators
using their existing authenticated round connection. Each evaluator applies it
against its own completed execution, review history and preserved model archive.
No per-validator upload key or manual `promote` command is needed for this path.

This is an opt-in successor service. It does not activate the open competition,
change the live bridge, approve model rights or extend a round's deadlines.

## Configuration and review input

Enable round work and settlement delivery first. Add this field to the
[round coordinator configuration](OPEN_COMPETITION_ROUND_COORDINATOR.md):

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

Use the [promotion agreement](OPEN_COMPETITION_PROMOTION_AGREEMENT.md) for review
fields and certificate rules. Rights and reconstruction evidence must be reviewed
before signing. The service never creates either approval. Protected suite
references are not included in this delivery document.

## Applying a decision

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

## Retry, conflict and capacity behavior

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
