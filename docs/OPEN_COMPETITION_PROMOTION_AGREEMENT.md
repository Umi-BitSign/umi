# Model promotion agreement

`umi-model-promotion-review/2` lets independently run validators retain the same
model-history head even when their receipt blocks or valid certificate sets
differ. This is a versioned store/CLI contract. Automated review distribution
and a deployed independent-operator rehearsal remain pending.

## Signed decision

The v2 review contains every v1 review field, plus:

- `round_sha256` and `submission_sha256` for the exact admitted evaluation;
- `previous_promotion_sha256` for the current reviewed history head;
- `sequence` for the next promotion, equal to the parent's sequence plus one.

`CompetitionStore.baseline_summary()` exposes the parent digest and sequence.
Reviewers sign the complete v2 body. The existing `promote` CLI accepts an
`AttestedPromotionReview` containing that body and the policy-required distinct
review groups. A body or digest supplied by a coordinator does not establish
local review, execution or rights approval.

Each operator independently checks the model's admission and evaluation,
preserved archive, paired quality gates and signed rights/reconstruction review.
Its current finalized registration snapshot and observation block must still
pass the existing validity and freshness rules. No shared observation timestamp
or retroactive observation is required. Those local checks can reject a decision
that another operator previously accepted, for example after expiry.

## History and local receipts

The canonical `umi-model-baseline/2` record contains the shared evaluation result
and review bodies with the model, contributor and parent binding. Endorsement
ordering, additional valid endorsements and local receipt time do not change its
digest. That record alone is not a certificate or chain-write authorization.

The complete locally verified certificates and actual acceptance block are
retained atomically in `promotion_receipts`. Exact retries retain the first
receipt. A changed decision cannot rewrite an existing promotion. The store's
observed-block high-water mark advances normally; it is never set back to
another operator's receipt block.

Restart requires the matching local receipt, valid certificates and parent.
Settlement signers also check the bounded receipt when reading a reviewed head.
Missing, changed or oversized receipts hold the action. Existing evidence-cutoff
and conflict rules still apply; importing a decision after cutoff cannot invent
earlier local evaluation evidence.

The v1 review and `umi-model-baseline/1` history remain supported with their
original bytes and observation semantics. A v2 review does not rewrite a model
already promoted through v1 or transfer its contributor attribution.

## Verification boundary

Store tests exercise different receipt blocks, endorsement order and supersets,
changed decisions, parent/round/submission bindings, restart, missing receipts,
bounded signing reads and legacy compatibility. The combined service test uses
different local promotion blocks before its predeclared evidence cutoff.

These tests use synthetic model and rights inputs. Launch still requires real
protected data, reviewed terms and provenance, independently administered
evaluators, a qualifying model and signed activation. UID 0 and UID 54 operated
by us remain one administration. No live reward policy changes through this API.
