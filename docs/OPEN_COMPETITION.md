[Documentation](README.md) / Open competition

# Open competition

The active signed cohort plan defines its eligible tracks and allocation. Service
work and public models can have separate pools; a model-only plan can assign the
complete competition allocation to the public-model track. Never infer a split
from a cohort number. Every opened cohort is governed by the exact plan its
participants accepted, and an unopened cohort has no permanent profile. A
complete accepted model entry must match or beat the plan's frozen baseline; a
sole eligible entrant receives the entire model pool. See the
[recoverable cohort configuration](operators/rounds.md#participation-admission).

Published phase blocks are nominal progression targets, not non-extendable
deadlines. Liveness delays retain and extend unfinished work and do not advance
the cohort automatically. The previous certified allocation remains effective
until the active cohort produces and activates a certified successor row. Read
the current
[status](https://api.umi.vision/v1/competition/status) and
[readiness](https://api.umi.vision/v1/competition/readiness) before submitting.
`admission_accepting_new` reports whether intake accepts a request;
`cohort_eligibility_confirmed` reports whether cohort eligibility is confirmed.
An intake receipt or healthy endpoint alone does not establish a score or payment.

Submissions bind the exact advertised policy and contribution terms. A changed
reward policy requires fresh miner consent; old signatures cannot be reinterpreted
as acceptance of a successor split. Preserve original submissions and receipts.

## Endpoint miners

Run the [protocol miner with a working model](miners/model.md). The endpoint
track supports a public HTTPS IP or a hotkey-signed hostname bound to its
chain-announced IP. A keepalive alone cannot answer translation requests.

Sign your submission with the registered hotkey. It binds your endpoint, model
revision, policy and accepted terms. No seed phrase, coldkey or personal API key
is submitted. The live origin and complete procedure are in the
[submission commands](reference/commands.md#live-first-round-intake). A valid
receipt has status `accepted_no_weight`; keep it and keep the submitted model and
endpoint unchanged and online through evaluation.

The accepted-submission log is public. It contains the complete signed
submission and receipt, including the hotkey, endpoint URL, model revision,
signature and finalized registration snapshot. Use a credential-free HTTPS
origin with no secret in its host, path, query or fragment. Do not put
credentials, private dataset details, confidential provenance or private review
material in a submission. Endpoint intake records metadata; it does not upload
model weights or training data.

Use the released policy and transport configuration for the cohort being
served. Health checks alone do not prove that the translation route accepts
requests. The [miner guide](miners/model.md) covers serving, grant admission and
retained-response recovery. The recoverable-cohort startup option does not by
itself open evaluation or activate rewards.

## Model contributors

Model contribution is separate from running an endpoint. Each cohort uses a
signed policy and frozen runtime. Public status reports whether model admission
accepts new submissions. The public endpoint receipt does not enroll a model or
preserve its weights.

Prepare a complete, reproducible artifact: weights or base-plus-adapter files,
configuration, tokenizer/processor, inference code, dependency inventory, hashes
and notices. The `submit-cohort-model` command resumes signed uploads and submits
participation only after native preservation succeeds. It requires the applicable
published policy and a complete signed model request.

Read the [preparation and rights checklist](contributors/models.md) and the exact
immutable terms named by the selected policy before spending compute. Retain every
immutable terms version referenced by accepted submissions so its original bytes
remain available for verification. Ownership and upstream obligations remain
with their respective holders.

Model reward eligibility requires preserved runnable artifacts,
permitted provenance/rights and quality at least equal to the frozen baseline.
An unchanged baseline may qualify through a complete model submission. A sole
eligible entrant receives the model pool; incomplete competitors cannot be
dropped to create a sole entrant. Exact duplicate content is counted once. The
remaining eligible models enter fixed five-percentage-point quality bands; each
occupied band creates one credit, awarded to its highest exact score. The model
pool is divided among those credits in proportion to their exact scores. The
first complete certified acceptance fixes score, eligibility and attribution
for exact copies, so later aliases do not create another trial. It also breaks
an exact score tie. Model reward eligibility and promotion of the reference
model are separate decisions.

## Evaluation and trust

The signed policy defines evaluator identities, control groups and quorum. Public
status identifies required and optional evaluators. Multiple validators under
one administration count as one independent group; optional redundancy cannot
hold cohort progress. Changing the required evaluator profile needs a successor
policy and qualification of that exact profile.

Automatic scoring compares one authentic reference per clip. Fingerspelling
uses CER over graphemes with whitespace removed; continuous signing uses WER
over word tokens. Each case similarity is
`max(0, 1 - edit_distance / max(1, reference_units))`. Case similarities are
averaged within each stratum, then combined as 3/13 fingerspelling and 10/13
continuous signing. The 120-second inference limit is the evaluator-observed
full request-response round trip, not a miner-reported duration. Candidates and
the preserved incumbent use the same committed suite and runtime profile.
Labels stay out of execution until reveal; exposed cases are retired. Text error
rates do not establish human interpreter equivalence, clinical safety or
unseen-training performance.

The applicable signed terms may permit a diagnostic comparison between outputs
for correct videos and matched unrelated videos. Unless the active policy
explicitly defines a qualified payout gate, it does not affect scores,
eligibility, settlement or payouts. Missing or failed diagnostics do not hold
settlement. A future payout gate would require published
thresholds and operating characteristics, a known-dependent positive control,
advance notice, a successor policy and fresh participant acceptance.

A candidate output that is late, oversized, invalid or returns an authenticated
miner error scores zero for that case. A verified evaluator or dispatch
infrastructure failure voids the affected evaluation instead of charging it to
the miner. Every frozen roster entry needs scored evidence or a complete signed
void; missing evidence holds the round.

The signed policy defines the minimum aggregate score, enabled pools and exact
allocation formula. Integer rounding uses largest remainders, with UID order
breaking an exact tie. Promotion also follows the policy's improvement, stratum,
preservation, reconstruction and rights requirements. Review conflicts or
missing quorum hold settlement; operators cannot edit frozen labels or issue an
ad hoc rescore after seeing answers.

## Incidents and score challenges

Report a possible protocol, evidence, evaluator or protected-data defect to Sam
(`sam0x17`) in a public UMI community channel. Send confidential supporting
material only through the restricted route he provides. Include the cohort identity and the relevant published policy. Pending
recoverable cohorts retain their original evidence through delayed review;
reporting an issue does not reopen sealed requests or rewrite finalized rewards.

Useful evidence includes the signed submission and receipt digest, signed
requests or responses, bounded endpoint logs with timestamps, public chain
references, and signed evaluator or dispatch evidence. Never publish seed
phrases, credentials, private labels, restricted videos or confidential
provenance material.

There is no discretionary appeal of a correctly computed automatic score.
Reports are limited to objective protocol, evidence, execution or data defects.
No operator may manually override one miner's score. A material evaluator,
dispatch or holdout defect found before settlement holds or voids the complete
affected round; a replacement round uses a fresh protected suite. Finalized
rows are not rewritten. A verified late conflict or defect stops renewal and
holds the next cutover while it is handled prospectively. UMI publishes a
bounded incident record and the relevant evidence digests, with private or
restricted material redacted.

## Operations and release checks

The [launch configuration](competition/launch.md) is the single acceptance
checklist and policy reference. It covers the burn proof, exact intake windows,
real workload qualification, signed artifacts, state-preserving handoff and
finalized competition-row verification.

The repository's `main` branch is not the release channel. It may include
reviewed changes that are not active in the coordinator, evaluator, intake or
validator fleet. The public status identifies the live policy; signed release
artifacts identify validator code; finalized chain state identifies the row that
can affect incentives. A merged commit changes none of those by itself.

Service operators should follow the [round](operators/rounds.md),
[dispatch](operators/dispatch.md), [evaluation](operators/evaluation.md),
[settlement](operators/settlement.md) and [promotion](operators/promotion.md)
guides. Ordinary weight validators consume certified results; installing one
does not grant access to private labels.

Renewal uses fresh chain checks and bounded reuse of an existing settlement.
New reviewed rounds and protected suites remain necessary. The
[whitepaper](../whitepaper/README.md) describes the mechanism; the
[CLI reference](reference/commands.md) retains component and rehearsal recipes.
