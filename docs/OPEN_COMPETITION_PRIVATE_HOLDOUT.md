# Private holdout for automatic launch evaluation

The first 70/30 competition uses automatic CER/WER scoring against fixed English
references. It does not require a new human ASL grading panel, a person reviewing
every miner output, or human approval of each score. Existing labeled ASL data
can supply the references. This choice does not activate the competition or
change the signed policy, scoring formula, evaluator quorum or bridge sunset.

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

## Existing input contract

`EvaluationSuite` binds the policy hash and distinct case/video identities.
Each `EvaluationCase` currently needs three to five English references and one
of the required strata: fingerspelling, short utterance or continuous signing.
The policy sets the minimum count per stratum; all three must meet it.

Check actual video readability, hashes, label presence, annotation provenance,
stratum assignment and duplicate records before committing a suite. Existing
annotation documentation and deterministic data checks can support this step;
there is no requirement to recruit a new panel to regrade every clip. Automatic
format checks cannot establish that a label translates the ASL correctly.
Document annotation limitations and exclude known mismatches before commitment.

If the supplied corpus has only one reference per clip, report that mismatch
before activation. Do not repeat one label or generate unverified paraphrases
to make it look as though the required references exist. Changing the reference
contract needs an explicit specification/code revision and a new scoring
rehearsal. Do not silently pad or relax it in the dataset importer.

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
