# Training data and model licensing review

The current [review PDF](../../UMI%20Rights%20Review%20Sign-Language%20Datasets%20and%20Public%20Model%20Weights.pdf)
and its canonical [LaTeX source](rights-review.tex) describe the two conditional
model licensing tracks from C7 onward. Permitted NC training or an inherited NC
checkpoint selects CC BY-NC-SA 4.0; compatible permissive models keep their
original terms. Existing C7 submissions need no action because of this update.
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

## Historical signed bindings

The policy wording was updated on October 28, 2026. The legal analysis and
rights-holder records retain their October 22 assessment date. This document
does not identify any cohort's evaluation sources.

The signed [NC supplement](../MODEL_CONTRIBUTION_TERMS_NC_V1.md) and training-rights
contract intentionally retain the original review's SHA-256:
`9f6694015a84f453ef8298afac4fd9c5dedfc741e74eb0ac3b6833f045b83502`.
Their original PDF is available at its
[fixed repository revision](https://github.com/Umi-BitSign/umi/blob/1819ad78abf6a37da4809dca64366c42316e5970/UMI%20Rights%20Review%20Sign-Language%20Datasets%20and%20Public%20Model%20Weights.pdf).
That historical reference remains necessary for existing signed adoptions and
replay. Do not change the signed terms or contract to follow a rebuilt PDF.
The current review incorporates the already-adopted conditional decision; it
does not change submitted bytes, consent, baseline licenses, cohort clocks,
scoring or reward rules.
