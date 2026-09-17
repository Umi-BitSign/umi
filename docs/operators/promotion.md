[Documentation](../README.md) / Review and promote contributed models

# Review and promote contributed models

- [Model promotion agreement](#open-competition-promotion-agreement)
- [Reviewed promotion delivery](#open-competition-promotion-delivery)

<a id="open-competition-promotion-agreement"></a>

## Model promotion agreement

`umi-model-promotion-review/2` lets independently run validators retain the same
model-history head even when their receipt blocks or valid certificate sets
differ. This is a versioned store/CLI contract. The reviewed-delivery procedure
below distributes approved decisions. Deployment must use the evaluator groups
named in the signed policy; two keys under one administrator are not independent.

<a id="open-competition-promotion-agreement--signed-decision"></a>

### Signed decision

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

<a id="open-competition-promotion-agreement--history-and-local-receipts"></a>

### History and local receipts

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

<a id="open-competition-promotion-agreement--verification-boundary"></a>

### Verification boundary

Store tests exercise different receipt blocks, endorsement order and supersets,
changed decisions, parent/round/submission bindings, restart, missing receipts,
bounded signing reads and legacy compatibility. The combined service test uses
different local promotion blocks before its predeclared evidence cutoff.

These tests use synthetic model and rights inputs. Launch still requires real
protected-data execution, reviewed launch inputs and signed activation. A
qualifying contributed model and its specific rights and provenance review are
required before awarding the model share. Until then, version 3 burns the
unallocated 30% under the [allocation rule](../competition/launch.md).
The approved
[initial evaluator profile](../competition/launch.md) uses UID 0 alone,
with one disclosed operator group and a quorum of one. UID 54 operated by us
does not supply an independent vote. Additional evaluator groups require a
later signed policy. No live reward policy changes through this API.


<a id="open-competition-promotion-delivery"></a>

## Reviewed promotion delivery

The coordinator can deliver an approved model promotion to continuous evaluators
using their existing authenticated round connection. Each evaluator applies it
against its own completed execution, review history and preserved model archive.
No per-validator upload key or manual `promote` command is needed for this path.

This is an opt-in successor service. It does not activate the open competition,
change the live bridge, approve model rights or extend a round's deadlines.

<a id="open-competition-promotion-delivery--configuration-and-review-input"></a>

### Configuration and review input

Enable round work and settlement delivery first. Add this field to the
[round coordinator configuration](rounds.md#open-competition-round-coordinator):

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

Use the [promotion agreement](promotion.md#open-competition-promotion-agreement) for review
fields and certificate rules. Rights and reconstruction evidence must be reviewed
before signing. The service never creates either approval. Protected suite
references are not included in this delivery document.

<a id="open-competition-promotion-delivery--applying-a-decision"></a>

### Applying a decision

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

<a id="open-competition-promotion-delivery--retry-conflict-and-capacity-behavior"></a>

### Retry, conflict and capacity behavior

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
