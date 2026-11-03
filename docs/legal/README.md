# Training data and model licensing review

The current [review PDF](../../UMI%20Rights%20Review%20Sign-Language%20Datasets%20and%20Public%20Model%20Weights.pdf)
and its canonical [LaTeX source](rights-review.tex) describe the two conditional
model licensing tracks from C7 onward. Permitted NC training or an inherited NC
checkpoint selects CC BY-NC-SA 4.0; compatible permissive models keep their
original terms. The November 2, 2026 legal/operator determination permits
Microsoft ASL STEM Wiki training on the NC track, retaining its source-specific
research, consent, confidentiality, no-redistribution and destruction conditions.
It records no Microsoft permission letter or amendment. Existing accurately
declared submissions retain their signed terms.
Use the [contributor guide](../contributors/models.md#training-data-and-research-model-licensing)
for the supported submission procedure.

## Rebuild

Install [Tectonic](https://tectonic-typesetting.github.io/) (the checked-in PDF
was built with 0.17.0), then run from the repository:

```sh
./tools/build_rights_review.sh
```

The script compiles `docs/legal/rights-review.tex`, checks for overflow and
unresolved references, and atomically replaces the existing root PDF so its
published URL stays stable. Commit the LaTeX and rebuilt PDF together. There is
no Markdown generation step or Pandoc dependency. Set `TECTONIC` to an alternate
executable path if needed.

Tectonic downloads missing TeX packages on the first build and reuses its normal
cache thereafter. The script removes its temporary output on success, failure
and interruption; `TMPDIR` chooses the temporary workspace. On constrained
hosts, bound compiler memory and use a task-scoped cache via `XDG_CACHE_HOME`.
The fixed `SOURCE_DATE_EPOCH` removes build-date churn; update it when changing
the policy revision date. With the same Tectonic/TeX bundle, check that the
committed PDF matches with `./tools/build_rights_review.sh --check`.

## Current and historical signed bindings

The current policy revision is November 2, 2026. The original legal analysis and
rights-holder records retain their October 22 assessment date. This document
does not identify any cohort's evaluation sources.

The new [version-2 NC supplement](../MODEL_CONTRIBUTION_TERMS_NC_V2.md) and
[version-2 training-rights contract](../../src/umi/competition_model_training_rights_v2.json)
bind the revised PDF and the ASL STEM Wiki allowance. They take effect for an
exact model only through authenticated adoption and fresh model-bound consent.
The supported updated client must select that revision from published signed
metadata; installing a client or publishing these documents alone does not
activate it.

When updating a direct-upload owner's standing review policy, retain its exact
predecessor in `standing_review_policy_continuation` together with the signed
license adoption. The owner authenticates the authority, cohort and rights
selection before opening the existing journal. Its original binding, upload
records and completed verification remain unchanged; new reviews use the
selected rights revision. Cohorts before the adoption's first sequence keep
their original review policy. This continuation is required while an existing
upload journal binds the predecessor policy, including after restart.

The retained [version-1 NC supplement](../MODEL_CONTRIBUTION_TERMS_NC_V1.md) and training-rights
contract intentionally retain the original review's SHA-256:
`9f6694015a84f453ef8298afac4fd9c5dedfc741e74eb0ac3b6833f045b83502`.
Their original PDF is available at its
[fixed repository revision](https://github.com/Umi-BitSign/umi/blob/1819ad78abf6a37da4809dca64366c42316e5970/UMI%20Rights%20Review%20Sign-Language%20Datasets%20and%20Public%20Model%20Weights.pdf).
That historical reference remains necessary for existing signed adoptions and
replay. Do not change the signed terms or contract to follow a rebuilt PDF.
The current review incorporates the source-specific legal/operator decision; it
does not change submitted bytes, consent, baseline licenses, cohort clocks,
scoring or reward rules.
