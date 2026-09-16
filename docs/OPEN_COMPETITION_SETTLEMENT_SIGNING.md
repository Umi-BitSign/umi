# Independent settlement signing

`IndependentSettlementSigner` reviews an unsigned settlement preparation using
one evaluator's own journals and finality provider. It returns one hotkey
endorsement. That endorsement alone is neither a quorum certificate nor
permission to submit weights.

The signer is used by the optional
[automatic delivery path](OPEN_COMPETITION_SETTLEMENT_DELIVERY.md), which connects
proposal discovery, vote collection and replay-package publication. This code
does not change either deployed bridge validator.

## Inputs and local checks

Construct the signer with the running `ContinuousEvaluator`, that evaluator's
cutoff-signing journal, its local `EvaluatorReviewStore`, and bounded
`PublicationReplayLimits`. Call `await signer.endorse(preparation)` with an
[`umi-settlement-preparation/1` proposal](OPEN_COMPETITION_SETTLEMENT_PREPARATION.md).

The signer requires:

- Its own signed cutoff reservation, exact frozen roster and suite reservation.
- A completed local evaluator slot for every roster member, without a conflict
  hold. The retained independent evidence must match the proposal exactly.
- A local receipt showing that complete independent evidence was retained by
  cutoff. The matching signed execution announcement must reproduce the
  evaluator's run in the independent evidence.
- A promotion head matching the evaluator's local reviewed history. The
  proposal cannot initialize that history or import a contributor attribution.
- An exact registration snapshot re-proved through the evaluator's owned
  historical finality provider, and a fresh head inside the signing window.

The existing publication replay verifies the complete roster, result signatures
and deterministic 70/30 projection. A signer cannot be a roster submitter,
positive-weight recipient, promoted contributor, or a member of a policy
control group containing any of those identities. Quorum still requires the
configured number of distinct eligible groups. UID 0 and UID 54 operated by us
do not become two independent evaluators.

The [local review store](OPEN_COMPETITION_REVIEW_HISTORY.md) receives cutoff and
roster history during independent work signing, at its actual receipt block.
Its baseline and promotions still require the preserved-bundle and signed
rights/quality review path. Copying the coordinator's SQLite database is rejected.
An empty promotion history blocks signing. This component provides no automatic
review approval. Known promotion and settlement conflicts remain blocking.

The reviewed histories must agree on the exact promotion record and parent link.
Legacy v1 records include an observation block, so creating similar records at
different blocks produces different digests. The versioned
[promotion agreement](OPEN_COMPETITION_PROMOTION_AGREEMENT.md) separates a shared
v2 decision from each operator's actual receipt block and full certificates.
The signer revalidates the bounded local receipt before using a v2 head.
The deployed review/distribution workflow still needs independent-operator
rehearsal; this signer never substitutes the coordinator's head to resolve a
mismatch.

## Evidence timing and restart

Before publishing completed independent evidence, the evaluator now saves an
`umi-independent-evidence-observation/1` receipt with its current owned finalized
boundary. A receipt is local provenance, not a proof of global network receipt
time. If a crash occurs after evidence retention but before receipt persistence,
recovery uses the actual restart observation. It never backdates a receipt from
an execution timestamp, relay claim or file modification time.

The coordinator's first-observation fields retain their existing meaning. A
signer checks its own evidence was also retained by cutoff; different operators
need not claim they first saw it at exactly the same block. The publication's
`finalized_receipt_timing_proven` field stays false.

The signer reserves the exact publication and suite before calling the hotkey.
A changed valid publication for the same round sequence creates a durable hold.
An exact retry returns the retained vote after checking current local state.
A missing vote after a crash can only be regenerated for the reserved bytes.
Never delete the journal to choose another settlement.

Owned finality is checked again after proof collection and evidence replay.
Missing evidence, a late local receipt, changed promotion history, an expired
snapshot, or a conflict discovered during collection blocks signing. No miner
is silently removed to make the remaining roster settle.

## Verification scope and remaining work

The tests exercise complete 70/30 publication signatures and signing-state
failure cases. Separate execution tests check model journals and the actual
authenticated endpoint-response path against the local-evidence verifier.
The combined service test additionally runs both tracks through scheduling,
execution, promotion and signed settlement using synthetic data and chain ports.
It does not establish real-model quality or independent administration.

The delivery tests additionally cover authenticated proposal discovery,
certificate collection and immutable package publication. The integrated
protected-data rehearsal, reviewed launch inputs, signed activation and finalized
incentive evidence remain launch requirements. The approved initial evaluator
cohort is UID 0 alone, with one disclosed operator group. Version 3 permits
70% endpoint allocation and 30% verified burn before the first promotion;
model-specific rights approval and a qualifying promotion are required before
paying the contributor share. Importing Michael's baseline grants no contributor
reward by itself. See the [allocation rule](OPEN_COMPETITION_MODEL_ALLOCATION.md).
