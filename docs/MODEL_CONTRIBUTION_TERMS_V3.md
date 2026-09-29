# UMI open-competition contribution terms, version 3

Adopted by Sam (`sam0x17`), UMI project operator and approval contact, on
2026-09-29 UTC. A participant accepts this version only by signing a submission
that binds both this file's SHA-256 and the exact governing policy digest.
Publication, SN78 registration, or acceptance of an earlier version does not
accept version 3. Publication also does not activate rewards or approve a model.

This document is not a legal opinion or a third-party rights warranty.

## 1. Separate service and public-model tracks

The signed cohort plan fixes the enabled tracks and their pools before intake.
For C5 and C7-C10, the miner allocation is divided equally: 50% for certified
endpoint service work and 50% for complete eligible public-model contributions.
C6 enables only the public-model track and assigns it 100% of the miner
allocation. A series-level policy that supports both tracks cannot widen a
narrower signed cohort plan.

The service pool is allocated among certified jobs within each published
stratum. A job's credit is its certified work units multiplied by its normalized
quality score. A miner-side failure receives zero quality credit. Missing or
invalid evaluator evidence remains pending or becomes an infrastructure void
under the governing protocol; it cannot be converted into a miner failure.
Leaderboard rank alone does not determine the service allocation.

An artifact is eligible for the public-model pool only if its complete accepted
submission, preserved runnable files, reconstruction review and rights review
are present and its score matches or exceeds the frozen baseline on the same
suite and runtime.

Eligible artifacts are placed into fixed quality bands using the aggregate
normalized benchmark score and the exact band width bound by the signed cohort
authority. For C5-C10, the width is 500 basis points. Each occupied band receives
one model credit. Band boundaries are lower-inclusive and upper-exclusive in
basis points, except that the final band includes an exact score of 10,000 basis
points. The highest-scoring eligible artifact in a band supplies that credit; an
exact score tie is resolved by the earliest complete certified acceptance. The
public-model pool is divided among the occupied band credits in proportion to
their exact benchmark scores. If those scores sum to zero, the pool is divided
equally among the occupied bands. If there is one occupied band, it receives the
complete public-model pool. If there are no eligible artifacts, the pool goes to
the proved burn destination named by the policy.

Canonical model content is counted once. When multiple accepted submissions
contain the same canonical model content, the first complete certified
acceptance fixes that content's score, eligibility and attribution. Later
aliases remain visible in the evidence but receive no additional trial or model
credit, even if their observed outputs differ. Minor metadata or packaging
changes do not create a second model when the protocol computes the same
canonical content digest.

Small output or score variations that remain within one quality band do not
create additional model credits. A distinct artifact that crosses a signed band
boundary can create another credit. Quality bands limit reward multiplication;
they do not prove that differently packaged or behaviorally similar models have
independent operators or training lineages.

A participant may qualify independently in both tracks through separate valid
submissions when both tracks are enabled. Running a public reference model at
an endpoint does not create a public-model award without complete model-track
enrollment. Offering service
from the same model through several endpoints does not multiply one certified
job; every service credit must correspond to distinct certified work.

These per-cohort percentages describe the miner allocation. They do not
describe total subnet emission or guarantee payment. A signed submission is an application for
evaluation, not a promise of inclusion, score, consensus, incentive or reward.

## 2. Model-contribution delivery and rights

An artifact contributor supplies the weights, or a complete reconstructible
base-plus-adapter package, with configuration, tokenizer or processor,
inference code, dependency inventory, immutable hashes and required notices.
Publicly available dependencies must remain retrievable at the identified
revisions.

The contributor retains ownership of its work. It offers the contributed parts
under the approved declared license, with permissions sufficient for UMI and
other licensees to preserve, run, modify and redistribute those parts, including
commercial use, subject to that license's conditions. UMI's continued use does
not depend on the contributor's endpoint remaining online or on SN78 rewards
continuing. This does not give UMI exclusive ownership of an open model.

Licenses and other obligations for inherited components remain in force. A
bundle-level identifier cannot relicense third-party weights or erase
attribution, share-alike, patent or access conditions. Do not promise rights the
contributor cannot grant. Dataset ownership and personal-information
permissions are assessed separately from the license attached to resulting
weights.

## 3. Accepted identifiers for review

Subject to the full source-stack review, the initial list is:

- `MIT`: retain its copyright and permission notice.
- `Apache-2.0`: comply with its license, notice and modification requirements.
- `CC-BY-4.0`: preserve the applicable attribution and license information.
- `CC-BY-SA-4.0`: preserve attribution and applicable share-alike obligations;
  do not label an adaptation MIT merely to enter the list.

Prefer established software licenses for new inference code. Preserve the
actual applicable license for weights. The list permits review; an identifier
match alone does not approve the bundle or determine compatibility between
components.

Authoritative texts: [MIT](https://opensource.org/license/mit),
[Apache-2.0](https://www.apache.org/licenses/LICENSE-2.0),
[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/), and
[CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/legalcode.en).

## 4. Provenance and review

Supply a versioned inventory of base models and data sources, their licenses or
permissions, and their use in training, validation and testing. Identify
unknown history instead of asserting unrestricted rights. Confidential evidence
goes through an agreed restricted channel, not a public issue. Do not send
patient records, signer identity documents or entire private corpora when a
relevant permission record is sufficient.

Research-only, non-commercial or unspecified source permissions require a
case-specific basis for the proposed use. Separate permission or a documented
legal assessment may resolve the question; unresolved material restrictions
hold model acceptance. These terms do not claim that training on any
non-commercial source always makes resulting weights unlawful.

Sam (`sam0x17`) is the project approval contact. Contributors can contact him in
the UMI community channel with a preliminary or final review request, source
links, and no confidential material. Sam will refer review requests to an expert
and arrange restricted evidence access when required. An automated agent can
prepare evidence but cannot approve rights or sign for a reviewer. Naming the
contact does not approve a model.

Preliminary findings should carry forward if the disclosed sources, uses and
governing terms stay unchanged. New facts can reopen review, with recorded
reasons. The final artifact still needs reconstruction and rights review. Record
the exact artifact, evidence and policy digests, reviewer, decision and
conditions. Publish a bounded decision summary. Preliminary acceptance does not
guarantee an award, promotion or legal immunity.

## 5. Benchmarking, diagnostics and continued rewards

The public-model benchmark award is separate from promotion of the reference
model. An eligible artifact can receive model credit without becoming the next
reference, and promotion does not create a model award without the cohort's
complete acceptance and benchmark evidence. The imported starting baseline has
no founding-model exception.

C5 may compare outputs for the correct video with outputs for matched unrelated
videos. This video-dependence measurement is diagnostic only for C5. It does not
change scores, eligibility or payouts, and missing or failed diagnostics do not
delay request closure, settlement or rewards. Repeated wording or identical
outputs do not independently disqualify a C5 participant. Any later payout gate
requires published thresholds, operating characteristics, an identified
positive control, advance notice, a successor policy and fresh participant
acceptance.

Future rewards follow the active certified allocation and are not a perpetual
royalty or purchase price. Passing the benchmark does not establish interpreter
equivalence, clinical safety or fitness for a particular product.

## 6. Acceptance and historical records

This is the approved version 3 publication. The governing policy must bind this
file's exact SHA-256 and the accepted-license list. A participant must sign a
fresh submission whose `policy_sha256` and `accepted_terms_sha256` match that
policy and this file. Earlier signatures or receipts cannot be migrated,
rewritten or treated as version 3 acceptance.

Earlier terms, submissions, signatures, receipts, scores and reward allocations
retain their original bytes and meaning. Version 3 applies prospectively and
does not alter settled results or third-party license grants.
