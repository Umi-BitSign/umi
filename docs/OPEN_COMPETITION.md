[Documentation](README.md) / Open competition

# Open competition

The signed C4 allocation has two tracks. Qualifying translation endpoints share
70% of the miner allocation, proportional to quality. A qualifying promoted
model's contributor receives 30%. Until the first promotion, that 30% is burned.
The imported baseline has no contributor award or founding-model exception.

C5+ is being prepared with a selected **50% service / 50% model** split. A
complete accepted model entry must match or beat the frozen baseline; a sole
eligible entrant receives the entire model pool. These future rules require
their own reviewed policy and activation. They do not change C4's signed
allocation. See the [recoverable cohort configuration](operators/rounds.md#participation-admission).

Public endpoint intake is held on **C5 preparation**, with no announced closing
block or evaluation start and no automatic advance to C6. Read the current
[status](https://api.umi.vision/v1/competition/status) and
[readiness](https://api.umi.vision/v1/competition/readiness) before submitting.
`admission_accepting_new` reports whether intake accepts a request;
`cohort_eligibility_confirmed` reports whether cohort eligibility is confirmed.
An intake receipt or healthy endpoint alone does not establish a score or payment.

Submissions bind the exact advertised policy and contribution terms. A changed
reward policy requires fresh miner consent; old signatures cannot be reinterpreted
as acceptance of C5+'s new split. Preserve original submissions and receipts.

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
retained-response recovery. The recoverable-cohort startup option is part of the
C5+ candidate and does not by itself open evaluation or activate rewards.

## Model contributors

Model contribution is separate from running an endpoint. C5+ model intake and its
50% allocation require the new reviewed policy, runtime and enrollment opening.
The public endpoint receipt does not enroll a model or preserve its weights.

Prepare a complete, reproducible artifact: weights or base-plus-adapter files,
configuration, tokenizer/processor, inference code, dependency inventory, hashes
and notices. The candidate `submit-cohort-model` command resumes signed uploads
and submits participation only after native preservation succeeds. It still
requires the applicable published policy and a complete signed model request.

Read the [preparation and rights checklist](contributors/models.md) and the exact
immutable terms named by the selected policy before spending compute. Original
C4 consumers still use the [version 2 terms](MODEL_CONTRIBUTION_TERMS_V2.md);
keep those bytes available for verification while C4 remains in use. Ownership
and upstream obligations remain with their respective holders.

For C5+, model reward eligibility requires preserved runnable artifacts,
permitted provenance/rights and quality at least equal to the frozen baseline.
An unchanged baseline may qualify through a complete model submission. A sole
eligible entrant receives the model pool; incomplete competitors cannot be
dropped to create a sole entrant. Multiple eligible distinct artifacts divide
the model pool in proportion to normalized benchmark score. Exact duplicate
content is counted once, using the first complete certified acceptance for
attribution. Model reward eligibility and promotion of the reference model are
separate decisions.

## Evaluation and trust

The C4 policy uses UID 0 as one evaluator group. UID 54 shares its
administration and is not an independent vote. This is a disclosed
single-operator launch, not independent evaluator consensus.

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

The [version 3 terms](MODEL_CONTRIBUTION_TERMS_V3.md) permit a diagnostic C5
comparison between outputs for correct videos and matched unrelated videos. It
does not affect C5 scores, eligibility, settlement or payouts. Missing or failed
diagnostics do not hold settlement. A future payout gate would require published
thresholds and operating characteristics, a known-dependent positive control,
advance notice, a successor policy and fresh participant acceptance.

A candidate output that is late, oversized, invalid or returns an authenticated
miner error scores zero for that case. A verified evaluator or dispatch
infrastructure failure voids the affected evaluation instead of charging it to
the miner. Every frozen roster entry needs scored evidence or a complete signed
void; missing evidence holds the round.

Under the signed C4 policy, the minimum aggregate quality score is 10%. Qualifying endpoint miners split
the 70% endpoint allocation in proportion to their exact scores. Integer
rounding uses largest remainders, with UID order breaking an exact tie. A model
can be promoted only if it meets the minimum score, beats the incumbent by at
least one percentage point, does not regress either scoring stratum, and passes
preservation, reconstruction and rights review. Review conflicts or missing
quorum hold settlement; operators cannot edit frozen labels or issue an ad hoc
rescore after seeing answers.

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
