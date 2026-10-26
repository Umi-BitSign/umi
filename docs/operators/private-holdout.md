[Documentation](../README.md) / Protect evaluation data

# Protect evaluation data

- [Private holdout for automatic launch evaluation](#open-competition-private-holdout)

<a id="open-competition-private-holdout"></a>

## Private holdout for automatic launch evaluation

The current automatic profile is `umi-open-competition-policy/3` with
`umi-competition-suite/2`. It uses CER/WER scoring against fixed English
references. It does not require a new human ASL grading panel, a person reviewing
every miner output, or human approval of each score. Existing labeled ASL data
can supply the references. A separate video-dependence comparison is diagnostic
only unless the signed policy explicitly activates a qualified gate. A
diagnostic cannot change a score, eligibility, reward or settlement. These
data-handling instructions do not activate the competition or change a signed
policy, scoring formula or evaluator quorum.

<a id="open-competition-private-holdout--private-storage-and-evaluator-setup"></a>

### Private storage and evaluator setup

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
[evaluator](evaluation.md#open-competition-evaluator) with a separate `video_directory`
containing reference-free, hash-named case videos. Keep the archive, manifest,
labels and provenance outside that directory and every model/miner mount.
Deliver reference suites through the access-controlled evaluation exchange to
the policy-selected evaluators. Installing a weight-writing validator does not
grant access to the holdout.

<a id="open-competition-private-holdout--data-needed-before-activation"></a>

### Data needed before activation

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

Private evaluation may use data under any recorded license, including research-only
and noncommercial datasets. Retain the publisher's license, attribution, provenance
and disclosure restrictions with the private inputs. This permission does not
change the licenses or contribution-rights checks for publicly distributed model
bundles.

Call a suite a training-excluded holdout only when its evaluation portion was
held back from training and tuning. An unfamiliar public dataset or an unpublished
choice of public clips does not establish that property. Report known and unknown
upstream exposure for a public-source benchmark. Public development examples are
separate from the protected pool. Prefer an independently held pool; if a
contributor supplies it, disclose that access and any influence on selection.

### Broader source coverage and overlap exclusion

Use independent corpora and recording groups rather than treating another media
transform of the same source as new evaluation data. Suitable source families
include [How2Sign](https://how2sign.github.io/) instructional continuous ASL,
[Microsoft ASL-STEM Wiki](https://www.microsoft.com/en-us/research/project/asl-stem-wiki/)
continuous scientific explanations, and
[ChicagoFSWild](https://ttic.uchicago.edu/~klivescu/ChicagoFSWild.htm)
fingerspelling in natural recordings. Keep FSboard's sentence phrases as well as
names, addresses and numbers represented in the fingerspelling pool. Retain the
source's exact labeled interval and English reference; isolated vocabulary must
not be relabeled as continuous translation or fingerspelling without evidence.
Published annotations and their limitations support preparation without requiring
a new grading panel.

How2Sign's realigned sentence metadata carries original recording IDs and exact
intervals, while its supplied sentence table does not identify signers. ASL-STEM
Wiki supplies participant, article, topic and sentence identities. ChicagoFSWild
supplies source URLs, signer IDs and fingerspelling labels; a cropped sequence
filename is not an independent source recording. Confirm actual frame rate and
clip boundaries during media preparation.

Prepare prospective suites with the metadata-only selector:

```sh
python -m umi.competition_suite_selection_cli \
  --policy /PRIVATE/policy.json \
  --inventory /PRIVATE/candidates.json \
  --exclusions /PRIVATE/exclusions.json \
  --counts /PRIVATE/selection-counts.json \
  --selection-key /PRIVATE/selection.key \
  --destination /PRIVATE/prepared-suite
```

All inputs and output directories are private. The 32-byte selection key remains
outside the report. `umi-private-suite-candidates/1` retains each exact single-
reference case, dataset/version, original recording-group digest, provenance,
license, attribution, exposure declaration and any known signer/topic metadata.
Issue a case only after the actual transformed video and its digest exist; an
acquisition URL or CSV row is not a verified video. The
`umi-private-suite-exclusions/1` input binds the metadata inventories supplying
known training/development references, previous suites and source/signer groups.
Use stable original recording identities across crops, encodings and aliases.

Selection excludes exact scorer-normalized and whitespace-equivalent references,
known source/signer overlap and lexical-near sentences with at least four unique
tokens. Its default near threshold is 80% token-set Jaccard similarity; record
the selected threshold with the suite. This catches a defined lexical similarity,
not arbitrary semantic paraphrases. It never edits references or changes CER/WER.
Required corpus, known-signer and topic coverage are explicit in the counts input;
unknown metadata cannot fill a known-coverage requirement. The default requires
two continuous corpora, two known signers in each task and two continuous topics.
It prefers balanced datasets and less represented known signers/topics, and
refuses unmet quotas instead of duplicating cases or relaxing exclusions.

Adoptable cases also require a known signer and a retained reference/interval QA
record identified by `reference_qa_sha256`. Strict selection defaults to
`require_qualified_cases: true` and `distinct_signer_per_case: true`, keeping
signers separate across selected tasks. Include known training/development signer
groups and previous selected suites in later exclusion inputs. Acquisition-only
planning may retain unknown rows explicitly, but the native adoption reviewer
refuses relaxed selection settings or missing QA/signer identities. How2Sign's
unknown signer rows therefore need additional verified signer information before
adoption. Do not invent identities from a cropped filename or silently classify
unknown training exposure as unseen.

The private preparation and selection report retain original provenance and
exposure counts. Exact retries reuse completed selection and restore interrupted
output publication. Media remains in the bounded active working set with durable
R2 storage under the normal case-delivery path; this command performs no media
download, inference, signing or cohort activation.

<a id="open-competition-private-holdout--approved-launch-input-contract"></a>

### Approved launch input contract

The signed policy and suite define the reference count, required strata, stratum
weights, enabled tracks and allocation. A successor plan may change an unopened
cohort before intake. An active plan retains its original allocation and meaning.

An existing intake cohort can select a better benchmark through an authenticated
`adopt_evaluation_suite` history transition before intake closes. The version 5
transition binds its original plan, previously selected suite, new suite and
private selection-manifest identity. It preserves the cohort digest, accepted
submissions, admissions, signed clocks and reward/scoring policy. Never replace
the signed plan or overwrite a committed suite file. The existing owner reserves
the exact predecessor and the selected independent reviewers verify the suite and
private delivery before normal quorum publication. Deployment must first update
all history readers, miners, evaluators, validators and their supported automatic
update paths to understand this explicit version.

Preparation, execution and settlement resolve the suite from that authenticated
history. Run the incumbent quality-floor model and all submitted models on the
same adopted suite; an old numeric score from another corpus is not a comparable
cutoff. Once intake closes, another suite amendment is refused. In-progress and
completed evaluations, including C6, retain their original suite and results.

Configure `evaluation_suite_adoption_candidates` on the owner and every selected
reviewer. Each candidate names its exact suite, selection report, inventory,
exclusions and selection-key files; private videos and reference-QA evidence;
the pinned ffmpeg/ffprobe binaries and hashes; and a durable per-owner
verification directory. `verification_owner_hotkey` must match the actual owner
or reviewer signer. Select the complete phase-review resource budget. Preserve
completed per-item checks across interruption, restart and suite replacement;
missing or changed completion metadata requires the supported explicit repair.

`reference_qa_directory` retains private canonical
`<reference_qa_sha256>.json` files with schema `umi-suite-reference-qa/1`. Each
binds the exact case and references, source/signer groups, provenance, annotation
source and limitations. Its interval is either a full publisher-labeled clip
without invented bounds, an exact integer-millisecond source range, or a
start/end-exclusive source-frame range with evidenced rational frame rate.
Preparation must complete the selection, per-case QA and pinned media checks
before returning a proposal. Their owner-bound receipts are independent, so a
suite replacement can reuse unchanged media. Byte and shape checks authenticate
these retained inputs; actual ASL reference correctness remains an annotation/QA
claim and must be supported by that evidence.

First qualification runs outside live intake/controller/sampling locks. On
reentry the owner compares the same selected history, predecessor and immutable
input identities before reserving the original journals. Changed state is refused
without repeating a media pass under those locks, so intake remains available
while a new candidate is first being checked.

The owner uses its separate `evaluation_suite_operator_token_file` for
`/internal/cohorts/evaluation-suite-adoption/prepare`, `/reserve` and `/commit`.
Preparation binds the original series, cohort and current predecessor. Reservation
fences the original intake and control journals without closing intake. Reviewers
use the normal vote token at `/vote` and independently verify exact selector,
QA evidence and media; fresh `/reservation` evidence uses the owner export token.
Repeat preparation after reservation recovers the original proposal and observed
block, then normal quorum commit publishes the append-only history. This operation
does not reseal a cohort, close intake or start scoring; Sam controls those steps.

### Prospective dependence-gated input contract

This section describes a possible successor policy. It is not active payout
policy. An active plan can collect the comparison diagnostically where feasible,
but a missing or failed diagnostic cannot hold settlement. Activating this gate in a
future cohort requires published thresholds, qualification, a newly signed
policy and fresh participant acceptance before intake.

`EvaluationSuite` binds the policy hash and case identities. The prospective
dependence-gated launch uses `umi-open-competition-policy/4` and
`umi-competition-suite/3`. Version 4 retains version 3's scoring, then adds
duration-matched continuous-video controls. Its reward allocation must be
defined by its own signed authority. It also requires fresh acceptance of the
final form of the
[version 3 terms](../MODEL_CONTRIBUTION_TERMS_V3.md).
The scoring profile uses one authentic English reference per case, with
fingerspelling and continuous signing as its two required tasks. Their exact
score weights are 3/13 and 10/13, respectively. Each task must meet the policy's
minimum case count, and the suite must contain at least three cases overall.
Short utterances are not scored under this profile. The inference deadline and
reward split are prospective policy choices and cannot be inherited silently
from an earlier cohort.

Suite version 3 pairs every scored continuous case with one control. The
control retains the anchor's reference and uses another scored clip's video.
The source mapping must be a complete derangement within deterministic duration
bins, and each source video therefore appears once as a scored input and once
as a control input. The policy fixes the pair count, bin count, maximum duration
difference, bootstrap repetitions, confidence level and effect thresholds.
Fingerspelling videos and all scored video identities remain unique.
Matched-swap controls are additional requests and do not count toward any
minimum scored-case coverage.

The matched-swap comparison uses score differences. Output-string changes are
not eligibility evidence because an input-blind model can vary fluent guesses.
For a fixed submitted artifact, resample paired clip differences rather than
requiring several training seeds. Policy version 4 requires the one-sided 95%
bootstrap lower bound to be strictly above zero. Its separate observed-margin
minimum is a point-estimate noise control whose release value and operating
characteristics must be published before signing. Keep output identity,
reversal, static-frame and blank-input measurements as diagnostics unless a
later signed policy gives them a different role.

Retain one exact-suite, exact-runtime run of the policy-pinned known-dependent
positive control. Its model identity, execution-evidence digest, outputs,
evaluation block and evaluator signatures enter the protected round plan and
settlement. A missing or failed calibration holds the round. It cannot be
replaced after candidate outputs are known.

#### Run and attest the positive control

The execution operator runs the policy-pinned positive-control bundle through
the exact private suite and runtime. The command records finalized boundaries,
each sandbox receipt and the derived calibration body in one canonical private
preparation:

```sh
umi-competition --policy /PRIVATE/policy.json \
  run-dependence-calibration \
  --suite /PRIVATE/suite.json \
  --chain-config /PRIVATE/chain-config.json \
  --bundle /PRIVATE/positive-control-bundle.json \
  --runtime /PRIVATE/runtime.json \
  --archive /PRIVATE/preserved-models \
  --videos /PRIVATE/content-addressed-videos \
  --evaluator-hotkey EVALUATOR_HOTKEY \
  > /PRIVATE/dependence-calibration-preparation.json
```

The video directory contains one regular file named `SHA256.mp4` for every
suite case. The preparation binds the exact policy, suite, runtime,
positive-control model, retained execution evidence and finalized evaluation
block. Keep the preparation, outputs and source videos private. The deliberately
memorizing positive control is an evaluator fixture only. It is never an
incumbent, baseline or reward candidate.

Each nominated evaluator validates and signs the same body with its explicitly
named hotkey:

```sh
umi-competition --policy /PRIVATE/policy.json \
  sign-dependence-calibration \
  --preparation /PRIVATE/dependence-calibration-preparation.json \
  --suite /PRIVATE/suite.json \
  --latest-block FINALIZED_BLOCK \
  --wallet-name VALIDATOR_WALLET \
  --hotkey-name VALIDATOR_HOTKEY \
  --wallet-path /ABSOLUTE/PATH/TO/WALLETS \
  > /PRIVATE/evaluator-attestation.json
```

`FINALIZED_BLOCK` is the current finalized block observed after the run. Do not
substitute a planned deadline or future block. The command reproduces the
calibration body from the retained execution before signing. It rejects a
tampered preparation, a failed positive control and a hotkey outside the
policy's evaluator set. It reads only the named hotkey.

After collecting the required independent evaluator groups, assemble and verify
the exact quorum. Repeat `--attestation` for each evaluator file:

```sh
umi-competition --policy /PRIVATE/policy.json \
  assemble-dependence-calibration \
  --attestation /PRIVATE/evaluator-one.json \
  --attestation /PRIVATE/evaluator-two.json \
  --suite /PRIVATE/suite.json \
  --latest-block FINALIZED_BLOCK \
  > /PRIVATE/dependence-calibration.json
```

The assembler rejects mismatched bodies, duplicate evaluators, duplicate control
groups, invalid signatures and insufficient quorum. Put the resulting object in
the private `RoundPlan.dependence_calibration` field before the coordinator sees
the plan. The coordinator checks the calibration block against its actual
finalized head. It does not accept a future-dated calibration.

Policy and suite versions 3 and 2 remain the prospective predecessor profile.
Their original bytes and semantics are unchanged; they do not acquire matched
controls retroactively.

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

Use the supplied reference unchanged under suite version 3. Do not repeat one label or
generate unverified paraphrases to satisfy version 1. A single reference can
penalize otherwise valid paraphrases, so disclose this limitation. The revised
profile still requires scoring rehearsal before activation; preparation alone
does not authorize rewards.

The runtime verifies case identities and reference structure. Training exposure,
annotation correctness, permissions and actual operator independence are
documented operational claims, not properties a hash or signature proves.

<a id="open-competition-private-holdout--protect-each-evaluation-window"></a>

### Protect each evaluation window

1. Fix the suite, baseline and complete candidate roster before execution.
   Compare candidates and incumbent on the same suite and runtime profile.
2. Deliver reference-free video inputs to execution. Keep labels out of miner
   requests, model mounts, logs and public APIs until the committed reveal.
   Models must produce and retain their outputs before reference disclosure.
3. Have the policy-selected evaluators execute and sign the result evidence.
   The initial [UID 54 launch profile](../competition/launch.md) uses one
   operator and one required signed run. Optional UID 0 review does not provide
   an independent second evaluation. A later multi-group policy requires
   reproduction by its independently administered groups.
4. Reveal evidence only to the audience allowed by the data policy. Restricted
   clips require access-controlled verification; a public digest alone is not
   a publicly reproducible dataset.
5. Retire the suite before later adaptive submissions can be tested against it.
   Never recycle exposed cases as hidden tests. Exhaustion of the protected pool
   holds new rounds until another valid suite is available.

Do not correct labels after seeing a candidate's answers or rescore a frozen
round with changed references. Use the
[published incident and score-challenge rules](../OPEN_COMPETITION.md#incidents-and-score-challenges)
and a new suite.

<a id="open-competition-private-holdout--what-the-score-means"></a>

### What the score means

Publish automatic benchmark scores and their strata, resource limits and known
data limitations. CER/WER compare text with the committed references; they do
not establish human-verified ASL understanding or clinical safety. Semantically
valid paraphrases can lose points, and small text edits can change meaning.
Human semantic evaluation can be added later under a prospective published
policy without being a dependency for this automatic-scoring launch.

Track allocation, model preservation and contribution-rights checks are defined
by the signed cohort policy and immutable terms it names. The [execution
plan](../competition/launch.md) tracks operational activation gates. A future
dependence-gated policy defines its own allocation prospectively; this document
does not reinterpret an active policy.
