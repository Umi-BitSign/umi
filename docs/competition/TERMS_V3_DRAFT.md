# UMI open-competition contribution terms, version 3 draft

This draft is not adopted and cannot yet be accepted by a miner submission.
UMI must publish an approved, immutable version 3 file and its SHA-256 before a
version 4 successor policy can bind it. Until then, the approved version 2 terms
and all earlier signed records retain their exact bytes and meaning.

This draft incorporates the approved
[version 2 terms](../MODEL_CONTRIBUTION_TERMS_V2.md), SHA-256
`c8efb288f648e26f178e2e253c9c282a7500107371866f1ab7d62a9e80ef935b`,
except where the prospective additions below are more specific. It is not a
legal opinion or a third-party rights warranty.

## 1. Endpoint input-dependence eligibility

An endpoint's continuous-sign output must depend materially on the submitted
video. Fluent or length-appropriate English is not sufficient if the endpoint
would score the same on an unrelated video. A change in output text is also not
sufficient by itself.

Under the prospective version 4 successor policy, the protected suite contains
12 scored continuous cases and one matched-swap control for each case. The
controls form a derangement within six deterministic duration bins. Each
control uses a different real video, no more than 500 milliseconds from its
anchor's duration, while retaining the anchor's reference. The evaluator
compares the anchor score with the matched-swap score. It does not use output
diversity to decide eligibility.

For one fixed submitted model, the evaluator performs deterministic bootstrap
resampling over the paired score differences. The confidence rule is a
strictly positive one-sided 95% lower bound, not a lower bound above the
point-estimate threshold. The point-estimate minimum is a separate noise-control
parameter. Its release value and operating characteristics must be published
before the policy is signed. A measured noise ceiling is not presented as a
minimum material effect. Multiple training seeds are not required for a
submitted artifact.

Byte-identical output frequency, time reversal, static-frame inputs and blank
inputs may be reported as diagnostics, but do not independently decide
eligibility.

Matched-swap controls are additional requests. They do not count toward the
minimum number of scored continuous cases or any other scored-case minimum.
The signed request transport must reserve enough time for all scored and
control requests. An evaluator, dispatcher or scheduling expiry is
infrastructure failure and cannot be converted into a miner failure.

Before settlement, the policy-pinned known-dependent positive control must run
through the exact protected suite and evaluation runtime. Its 95% lower bound
must be at least 0.50, and the required evaluator groups must attest the exact
calibration. The deliberately memorizing positive control is an evaluator
fixture only. It cannot be an incumbent, baseline or reward candidate.

A positive-control, evaluator, assignment-feed or protected-input failure holds
or voids the evaluation rather than reducing a miner's score. A miner endpoint
that returns an authenticated miner-side failure for an assigned control has
incomplete dependence evidence and does not qualify in that round.

## 2. Prospective acceptance

These requirements apply only through an explicit version 4 successor policy
and a fresh signed acceptance of the final approved version 3 terms. They do not
rewrite version 1 or version 2 submissions, receipts, policies, evaluations or
no-weight intake records.

The final approved file must state its adoption, exact policy relationship and
acceptance procedure. A participant must sign a fresh submission whose
`policy_sha256` and `accepted_terms_sha256` match that policy and the approved
file. No reward cutover may infer acceptance from an earlier signature.
