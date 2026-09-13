# Model contributions: prepare before spending compute

Open-competition intake and rewards are not active yet. This checklist explains
what to prepare for rights and reconstruction review. It is not a license grant,
contribution agreement, accepted-license list or approval of a particular model.

## What must be published before intake opens

The signed launch policy must name the accepted model-license identifiers and
bind the exact contribution terms by SHA-256. UMI must publish those terms, the
license list, the review route and the supported evaluation resource limits
before asking contributors to train or submit for this competition. No date is
committed until those inputs and the deployment checks are ready.

The current reference repository declares Apache-2.0 for code and CC BY-SA 4.0
for weights and its portable bundle. That does not make those licenses a general
allowlist or clear every upstream model and dataset. Do not remove attribution,
change inherited license labels, or assume a new bundle license overrides
upstream restrictions.

The code checks `license_id` against `CompetitionPolicy.accepted_model_licenses`
and binds `accepted_terms_sha256` to the policy. Those checks establish agreement
with a published policy, not the truth of a rights claim. Promotion also requires
a signed rights review with retained supporting evidence.

## Evidence checklist

For each source, identify the exact version and how it was used. A link to a
mutable repository or a statement that data is public is not enough.

- **Model lineage:** base model, parent baseline, adapters and other inherited
  weights; repository and immutable revision or digest; original license text,
  attribution and any access or commercial-use agreement.
- **Training data:** dataset name, version, source and acquisition date; relevant
  license or access terms; permission or consent records where applicable;
  restrictions on training, commercial use, redistribution and use of personal
  information. Include synthetic-data sources and relevant provider terms.
- **Changes:** which sources were used for training, validation or testing;
  material filtering, labeling, preprocessing and fine-tuning steps. Distinguish
  unavailable evidence from a claim that no restriction exists.
- **Permission evidence:** the actual terms or written authorization relied on,
  who granted it, what it covers, and any expiry or conditions. Identify unresolved
  third-party, privacy, consent or attribution questions.
- **Reconstruction:** weights or a complete reproducible base-plus-adapter
  package; architecture/config, tokenizer/processor, inference code, dependency
  versions, entrypoint, file hashes and resource requirements.
- **Proposed distribution:** the bundle license, required notices, what UMI may
  preserve and publish, and evidence supporting commercial inference,
  modification and redistribution. Describe incompatibilities rather than
  selecting a convenient license identifier.

Do not post private datasets, identifiable patient or signer records, credentials
or confidential agreements in public issues. Use public metadata and document
digests for coordination; agree a restricted evidence channel with the reviewer
when needed. Review should request relevant evidence, not unnecessary personal
information or the contributor's entire training corpus.

## How review should decide

Review the proposed bundle's rights and the underlying model/data restrictions
separately. Then check whether the intended preservation, publication and product
uses are supported together. Successful inference, a high score, a valid archive
hash or an evaluator signature does not answer these questions.

Research-only, non-commercial and unspecified permissions are not automatically
accepted. For example, CC BY-NC limits uses covered by that license to
non-commercial purposes; it also warns that other rights can matter.
See the [CC BY-NC 4.0 terms](https://creativecommons.org/licenses/by-nc/4.0/).

These source categories need case-specific review, not an assumption that all
resulting weights are either prohibited or unrestricted. Relevant written
permission from the rights holder, a separate commercial agreement, or a
documented legal assessment may resolve a concern. It must cover the actual
source and proposed use. Unresolved material restrictions hold promotion; a
reviewer must not mark them passed merely because the model can be downloaded.
Qualified legal review is needed where the applicable rights are uncertain.

The review record should identify the model and evidence digests, governing
policy and terms, reviewer, decision, reasons and unresolved conditions. The
underlying evidence must remain available to authorized independent reviewers.
A hash with no accessible supporting record is insufficient. Publish a decision
summary without exposing confidential or personal material.

## Preliminary review

Contributors should be able to ask about a proposed source stack before training.
Include the source inventory above, intended use and outstanding questions.
UMI must publish the reviewer/contact route before intake opens; an unanswered
request is not approval, and no turnaround time is promised by this document.

A preliminary response should distinguish accepted points, missing evidence and
restrictions needing resolution. Bind it to the disclosed source versions, uses,
policy and terms. If those facts are unchanged, carry the reviewed evidence into
the final review rather than asking for the same material again. Explain any
reopened question. New facts, omissions or changed restrictions can require
reassessment, and the final artifact still needs reconstruction and rights
review. Preliminary feedback cannot guarantee promotion, rewards or legal immunity.

## Endpoint service is a different track

An endpoint miner can keep its model private. Endpoint participation does not by
itself grant UMI a copy, redistribution rights or the model-contribution share.
It still requires acceptance of the applicable published terms and lawful use
of the model and data for the service offered. Keeping weights private does not
remove privacy, consent, access-agreement or commercial-use restrictions.

Contributors seeking the 30% model track additionally need a preserved,
reconstructible, rights-reviewed artifact that qualifies for promotion. Endpoint
scores compete for the 70% service track. Both tracks launch together only after
the [activation gates](OPEN_COMPETITION_EXECUTION_PLAN.md) pass.
