# Evaluator review history

The continuous evaluator maintains its own review history while signing work.
It does not copy the coordinator's SQLite database or treat the coordinator's
claimed admission time as its own observation.

This path uses `EvaluatorReviewStore` in `settlement_review_directory`. Enable
the round, work and settlement clients together as described in the
[evaluator guide](OPEN_COMPETITION_EVALUATOR.md).

## Initial baseline

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

The review store has a persistent role separate from the coordinator's intake.
Opening an intake database as evaluator history is rejected. Existing manually
seeded rehearsal databases cannot be reclassified. Keep them as historical test
evidence and use a separate review directory for the automatic path. Neither
live bridge validator uses this successor store.

## Receiving a round

Before signing a work proposal, the evaluator checks its own prior cutoff vote
and suite reservation. It verifies the quorum certificate over the exact roster
and schedule, and obtains the cutoff registration snapshot from its own
historical finality provider. It then reads its current finalized head.

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

## Promotion and settlement

The received history supplies the round and submission bindings needed by the
existing independent evaluation and promotion checks. It does not create
evaluation results, sign a rights review, or award the contribution share.
Settlement signing still requires the worker's own completed execution and
evidence receipts, plus its reviewed promotion head.

For an explicitly supplied reviewed promotion, the existing no-weight `promote`
CLI also accepts `--evaluator-review-limits`. Its review must bind the exact
evaluation and preserved model; use the
[v2 agreed review](OPEN_COMPETITION_PROMOTION_AGREEMENT.md) to retain a common
history head with separate local receipt times.

The [reviewed promotion delivery](OPEN_COMPETITION_PROMOTION_DELIVERY.md) path
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
