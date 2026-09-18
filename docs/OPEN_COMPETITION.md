[Documentation](README.md) / Open competition

# Open competition

The successor mechanism has two tracks. Qualifying translation endpoints share
70% of the miner allocation, proportional to quality. A qualifying promoted
model's contributor receives 30%. Until the first promotion, that 30% is burned.
The imported baseline has no contributor award or founding-model exception.

Public endpoint intake is live at `https://api.umi.vision` and has been publicly
reachable since block `9,085,463`. Block `9,135,843` is the guaranteed
first-round deadline for submissions and replacements accepted on or after the
opening block. The coordinator polls
after that block and may close the roster at any time through its operator close
bound, block `9,135,903`, so an acceptance after `9,135,843` is not guaranteed
first-round inclusion. Evaluation closes at block `9,156,243`. A submission
intended for this round must remain valid through at least that block, and its
hotkey must still be registered on SN78 in the finalized roster-close snapshot.
The exact policy digest is
`81c118c5b45527650d7f304a6574d04223de30fbad76c69df09e7f2ae4897fa0`.

The prospective staged-activation successor policy has digest
`eae2a709bd54468d7ea42c370867be77144115ec709c22e976320828a0e90e56`
and binds [version 2 contribution terms](MODEL_CONTRIBUTION_TERMS_V2.md), SHA-256
`c8efb288f648e26f178e2e253c9c282a7500107371866f1ab7d62a9e80ef935b`.
It becomes the intake policy only when the public status advertises that exact
digest. Existing version 1 submissions and receipts retain their original bytes
and no-weight meaning. Each affected miner must sign and receive acceptance for
a fresh successor submission by block `9,135,843`; no operator can reinterpret
a version 1 signature as acceptance of version 2.

Competition rewards have not yet replaced the registration bridge. Until the
signed transition is verified on chain, miners should keep following the
[current bridge instructions](CURRENT_MINER_OPERATION.md) as well. A healthy
endpoint or `accepted_no_weight` receipt proves neither evaluation nor payment.

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

Assignment delivery is not public yet. Do not start a miner from placeholder
feed examples. UMI will publish the exact signed feed configuration and a tested
command before first-round evaluation, with operating lead time. A coordinator,
feed or evaluator infrastructure delay is not a miner failure and cannot be
scored against a miner.

## Model contributors

Contribution is optional. Model-artifact intake and evaluation are **not open
for the first round** because the exact canonical runtime and its immutable,
reconstructible environment have not been published. The public endpoint intake
does not accept or evaluate model bytes. The 30% model allocation remains burned
until a later announced model round supplies that runtime and a model passes all
promotion checks. No reward accrues while the share is unallocated, and a later
promotion has no retroactive award.

The current endpoint-only intake is a no-weight intake. Version 1 says both
tracks launch together. The published version 2 terms permit endpoint-only
activation with the 30% model share burned, and the sequence 5 successor policy
binds those terms. Rewards remain inactive until affected miners submit new
hotkey signatures under that exact successor, the round completes, and the
signed validator cutover is finalized on chain.

A future contribution must provide a complete, reproducible artifact with
weights or base-plus-adapter files, configuration, tokenizer, inference code,
dependency inventory, hashes and notices. UMI preserves qualifying promoted
models so future miners and products can use them independently of an endpoint.

Read the [preparation and rights checklist](contributors/models.md), the
[historical version 1 terms](MODEL_CONTRIBUTION_TERMS.md), and the
[staged-activation version 2 terms](MODEL_CONTRIBUTION_TERMS_V2.md) before
spending compute.
Ownership stays with contributors; licenses and upstream obligations still apply.
Uploading an archive or winning an endpoint benchmark does not grant the model
share. Promotion requires reconstruction, paired improvement, preservation and
rights review.

The [model-manifest preparation notes](reference/commands.md#live-first-round-model-contribution)
are for advance preparation only. A future opening will publish its own runtime,
cutoffs, submission route and review process. If two new candidates are exactly
tied for the highest qualifying promotion result, neither is promoted in that
round and the 30% remains burned.

## Evaluation and trust

The initial policy uses UID 0 as one evaluator group. UID 54 shares its
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

The prospective version 4 policy and
[version 3 terms draft](competition/TERMS_V3_DRAFT.md) also test whether
continuous output depends on the video. Twelve scored continuous clips are
paired with duration-matched controls that preserve each anchor reference while
substituting a different real clip. Eligibility uses the correct-score minus
swapped-score differences, not whether the returned strings merely differ. The
policy separates the observed effect threshold from its sampling-confidence
test. The latter
requires a strictly positive one-sided 95% lower bound; it does not require the
lower bound to clear the point-estimate threshold. Controls sit on top of the
minimum scored cases and do not satisfy scored-case coverage. Byte-identical
output frequency, reversed video, repeated frames and blank inputs are
diagnostics only.

Before settlement, a policy-pinned known-dependent control must pass the same
protected suite and runtime with a stronger margin. The required evaluator
groups attest that exact execution. If the control, evaluator, assignment feed
or protected inputs fail, the round holds or voids instead of assigning miner
failures. These controls apply only after the version 4 policy and final version
3 terms are approved, published and freshly accepted; they do not alter existing
intake receipts.

A candidate output that is late, oversized, invalid or returns an authenticated
miner error scores zero for that case. A verified evaluator or dispatch
infrastructure failure voids the affected evaluation instead of charging it to
the miner. Every frozen roster entry needs scored evidence or a complete signed
void; missing evidence holds the round.

The minimum aggregate quality score is 10%. Qualifying endpoint miners split
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
material only through the restricted route he provides. A report that could
affect first-round settlement must arrive by the evidence cutoff, block
`9,156,383`.

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
