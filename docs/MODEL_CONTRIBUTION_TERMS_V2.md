# UMI open-competition contribution terms, version 2

Adopted by Sam (`sam0x17`), UMI project operator and approval contact, on
2026-09-18 UTC. A participant accepts this version only by signing a submission
that binds both this file's SHA-256 and the exact successor-policy digest.
Publication, SN78 registration, or acceptance of version 1 does not accept
version 2. Publication also does not activate rewards or approve a model.

This document is not a legal opinion or a third-party rights warranty.

## 1. Staged participation tracks

The endpoint track may activate before the model-contribution track. While only
the endpoint track is active, qualifying endpoints receive 70% of the miner
allocation in proportion to their scores. The other 30% must go to the proved
burn destination named by the policy. It cannot be redistributed to endpoints,
validators, the subnet owner, or a future contributor.

The model-contribution track may activate only after UMI publishes its runtime,
intake route, evaluation window, preservation requirements, and rights-review
process. Once a model qualifies under the governing policy, its verified
contributor may receive the 30% model allocation for prospective reward periods.
No model reward accrues while the share is burned. A later promotion cannot
claim the burned share or any other retroactive reward.

These percentages describe the miner allocation. They do not describe total
subnet emission or guarantee payment. A signed submission is an application for
evaluation, not a promise of inclusion, score, consensus, incentive, or reward.

An endpoint operator may keep its model private. Offering an endpoint does not
transfer model ownership or give UMI a right to publish its weights. The
operator must have permission for the service it provides and disclose relevant
material restrictions through the review route.

## 2. Model-contribution delivery and rights

An artifact contributor supplies the weights, or a complete reconstructible
base-plus-adapter package, with configuration, tokenizer or processor,
inference code, dependency inventory, immutable hashes, and required notices.
Publicly available dependencies must remain retrievable at the identified
revisions.

The contributor retains ownership of its work. It offers the contributed parts
under the approved declared license, with permissions sufficient for UMI and
other licensees to preserve, run, modify, and redistribute those parts,
including commercial use, subject to that license's conditions. UMI's continued
use does not depend on the contributor's endpoint remaining online or on SN78
rewards continuing. This does not give UMI exclusive ownership of an open
model.

Licenses and other obligations for inherited components remain in force. A
bundle-level identifier cannot relicense third-party weights or erase
attribution, share-alike, patent, or access conditions. Do not promise rights
the contributor cannot grant. Dataset ownership and personal-information
permissions are assessed separately from the license attached to resulting
weights.

## 3. Accepted identifiers for review

Subject to the full source-stack review, the initial list is:

- `MIT`: retain its copyright and permission notice.
- `Apache-2.0`: comply with its license, notice, and modification requirements.
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
permissions, and their use in training, validation, and testing. Identify
unknown history instead of asserting unrestricted rights. Confidential evidence
goes through an agreed restricted channel, not a public issue. Do not send
patient records, signer identity documents, or entire private corpora when a
relevant permission record is sufficient.

Research-only, non-commercial, or unspecified source permissions require a
case-specific basis for the proposed use. Separate permission or a documented
legal assessment may resolve the question; unresolved material restrictions
hold promotion. These terms do not claim that training on any non-commercial
source always makes resulting weights unlawful.

Sam (`sam0x17`) is the project approval contact. Contributors can contact him in
the UMI community channel with a preliminary or final review request, source
links, and no confidential material. Sam will refer review requests to an expert
and arrange restricted evidence access when required. An automated agent can
prepare evidence but cannot approve rights or sign for a reviewer. Naming the
contact does not approve a model.

Preliminary findings should carry forward if the disclosed sources, uses, and
governing terms stay unchanged. New facts can reopen review, with recorded
reasons. The final artifact still needs reconstruction and rights review. Record
the exact artifact, evidence and policy digests, reviewer, decision, and
conditions. Publish a bounded decision summary. Preliminary acceptance does not
guarantee promotion.

## 5. Promotion and continued rewards

Uploading a model, supplying the first baseline, winning the endpoint track, or
passing a license-string check does not create contributor attribution. The
artifact must satisfy the governing promotion policy, including its comparison
with the incumbent, evaluation, preservation, and rights checks. Attribution
belongs to the verified contributor identity in the promotion record. No
special treatment is assigned to Michael or UMI-operated miners.

The imported starting baseline has no contributor reward recipient. An accepted
license remains governed by its own terms after a successor wins. Future rewards
follow the active policy and are not a perpetual royalty or purchase price.
Passing the benchmark does not establish interpreter equivalence, clinical
safety, or fitness for a particular product.

## 6. Acceptance and historical records

This is the approved version 2 publication. The governing successor policy must
bind this file's exact SHA-256 and the accepted-license list. A participant must
sign a fresh submission whose `policy_sha256` and `accepted_terms_sha256` match
that policy and this file. A version 1 signature or receipt cannot be migrated,
rewritten, or treated as version 2 acceptance.

Version 1 terms, submissions, signatures, and receipts retain their original
bytes and meaning. They remain evidence of the no-weight intake in which they
were created. They do not authorize rewards under the successor policy. Later
changes are prospective and must not alter accepted terms, settled results, or
third-party license grants.
