# Private holdout for automatic launch evaluation

The first 70/30 competition uses automatic CER/WER scoring against fixed English
references. It does not require a new human ASL grading panel, a person reviewing
every miner output, or human approval of each score. Existing labeled ASL data
can supply the references. This choice does not activate the competition or
change the signed policy, scoring formula, evaluator quorum or bridge lifetime.

## Private storage and evaluator setup

Keep the original archive and an intake record outside Git and public artifact
storage. Use owner-only directories (0700) and files (0600), preserve provenance
and attribution, and verify the archive digest at each private backup destination.
File permissions do not provide encryption or isolation from other processes
running as the same account. Use an encrypted volume and a separate evaluator
account when stronger separation is required.

Before extraction, reject absolute paths, parent traversal, symlinks, duplicate
archive entries and oversized payloads. Verify every member against the supplied
checksums. Record counts by task, timestamp intervals, reference counts and known
training exposure without logging the references themselves. For interval-labeled
source videos, the case input must contain only the labeled interval; a full
source video must not be scored against one sentence's label.

Archive intake is separate from accepting an `EvaluationSuite`. Retain a candidate
with `activation_ready: false` if required strata or references are missing.
Do not duplicate labels, invent paraphrases, or reclassify fingerspelling clips
to fill a missing short-utterance stratum. Changing that contract requires a
reviewed policy/code change and scoring rehearsal before activation.

Only after qualification should the coordinator commit the suite. Configure the
[evaluator](OPEN_COMPETITION_EVALUATOR.md) with a separate `video_directory`
containing reference-free, hash-named case videos. Keep the archive, manifest,
labels and provenance outside that directory and every model/miner mount.
Deliver reference suites through the access-controlled evaluation exchange to
the policy-selected evaluators. Installing a weight-writing validator does not
grant access to the holdout.

## Data needed before activation

Provide the dataset privately to the evaluation operators, with:

- ASL clips and their English references, annotation source and procedure.
- Source permissions covering the proposed evaluation, evaluator access and any
  later evidence disclosure. Do not put consent records or personal details in
  the public repository.
- A recorded evaluation split excluded from baseline/candidate training,
  fine-tuning and model selection. Disclose known overlap and unknown upstream
  exposure. A new random split of data already used to train Michael's model
  would not establish unseen performance for that model.
- Recording and signer grouping where available, so overlapping clips from one
  recording are kept together and signer overlap can be reported. Keep exact
  duplicates and known near-duplicates out of competing splits. Do not claim
  unseen-signer performance without a signer-disjoint test.

The source may be a private training corpus, but the evaluation portion must
have been held back from training and tuning. Public development examples are
separate from the protected pool. Prefer an independently held pool; if a
contributor supplies it, disclose that access and any influence on selection.

## Approved launch input contract

`EvaluationSuite` binds the policy hash and distinct case/video identities.
The approved `umi-open-competition-policy/2` and `umi-competition-suite/2`
profile uses one authentic English reference per case, with fingerspelling and
continuous signing as its two required tasks. Their exact score weights are
3/13 and 10/13, respectively. Each task must meet the policy's minimum case count,
and the suite must contain at least three cases overall. Short utterances are
not scored under this profile. It preserves the 70/30 reward split and the
120-second launch inference deadline.

Historical version 1 retains three to five references, all three required tasks,
and the 15%/35%/50% weights. A version 1 suite cannot be replayed as version 2,
or the reverse. New weights apply only through the newly signed policy, not by
reinterpretation of retained results.

Check actual video readability, hashes, label presence, annotation provenance,
stratum assignment and duplicate records before committing a suite. Existing
annotation documentation and deterministic data checks can support this step;
there is no requirement to recruit a new panel to regrade every clip. Automatic
format checks cannot establish that a label translates the ASL correctly.
Document annotation limitations and exclude known mismatches before commitment.

Use the supplied reference unchanged under version 2. Do not repeat one label or
generate unverified paraphrases to satisfy version 1. A single reference can
penalize otherwise valid paraphrases, so disclose this limitation. The revised
profile still requires scoring rehearsal before activation; preparation alone
does not authorize rewards.

The runtime verifies case identities and reference structure. Training exposure,
annotation correctness, permissions and actual operator independence are
documented operational claims, not properties a hash or signature proves.

## Protect each evaluation window

1. Fix the suite, baseline and complete candidate roster before execution.
   Compare candidates and incumbent on the same suite and runtime profile.
2. Deliver reference-free video inputs to execution. Keep labels out of miner
   requests, model mounts, logs and public APIs until the committed reveal.
   Models must produce and retain their outputs before reference disclosure.
3. Have the policy-selected evaluators execute and sign the result evidence.
   The initial [UID 0 launch profile](OPEN_COMPETITION_UID0_LAUNCH.md) uses one
   operator and one signed run. It provides no independent second evaluation.
   UID 54 does not supply another vote. A later multi-group policy requires
   reproduction by its independently administered groups.
4. Reveal evidence only to the audience allowed by the data policy. Restricted
   clips require access-controlled verification; a public digest alone is not
   a publicly reproducible dataset.
5. Retire the suite before later adaptive submissions can be tested against it.
   Never recycle exposed cases as hidden tests. Exhaustion of the protected pool
   holds new rounds until another valid suite is available.

Do not correct labels after seeing a candidate's answers or rescore a frozen
round with changed references. Use the published incident rules and a new suite.

## What the score means

Publish automatic benchmark scores and their strata, resource limits and known
data limitations. CER/WER compare text with the committed references; they do
not establish human-verified ASL understanding or clinical safety. Semantically
valid paraphrases can lose points, and small text edits can change meaning.
Human semantic evaluation can be added later under a prospective published
policy without being a dependency for this automatic-scoring launch.

The 70/30 allocation, model preservation and contribution-rights checks remain
unchanged. The [execution plan](OPEN_COMPETITION_EXECUTION_PLAN.md) tracks the
remaining operational activation gates.
