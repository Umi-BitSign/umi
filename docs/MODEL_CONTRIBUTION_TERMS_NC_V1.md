# UMI non-commercial research-model contribution terms, version 1

These supplemental terms define the **non-commercial model route** for C7 and
later cohorts. They apply to an exact model only after the operator's
authenticated adoption selects this file's SHA-256 and the contributor signs
fresh consent binding that model, its declared license and these terms.
Publication of this file alone does not change a signed cohort or submission.

## 1. Conditional model licensing

A model trained using permitted NonCommercial data, including How2Sign, must
declare that source and be released under **CC BY-NC-SA 4.0**. The same applies
where an inherited checkpoint requires an NC-SA release. Weights, adapters,
tokenizer and label vocabularies, and the portable model bundle carry this
license. Do not label such a model MIT, Apache-2.0 or CC BY-SA to enter the
permissive route.

A model using only sources and inherited components that support its existing
permissive release remains under the cohort's original contribution terms and
declared license. These supplemental terms do not force all cohort models to
be NC. In a mixed-source model, using a permitted NC source selects the NC
route for the resulting model. The two routes use the same cohort evaluation,
resource limits, quality floor and reward formula; the license class does not
provide additional model credit.

The operator's conditional decision supersedes the universal-NC requirement in
the October 22, 2026 rights review. The review's source permissions and the
conditions attached to use and publication of an NC model still apply. The
review PDF is `UMI Rights Review Sign-Language Datasets and Public Model
Weights.pdf`, SHA-256
`9f6694015a84f453ef8298afac4fd9c5dedfc741e74eb0ac3b6833f045b83502`.

## 2. Model rights and research use

The contributor retains ownership and grants UMI permission to evaluate,
preserve, publish and use the exact submission as a research baseline under
CC BY-NC-SA 4.0. Public non-commercial release is a condition of an award on
this route. This grant replaces the original contribution terms' commercial-use
grant **for this model only**. It does not relicense any other contributor's
model, the existing baseline or an earlier signed artifact.

Retain the CC BY-NC-SA 4.0 legal code or URL in `LICENSE-WEIGHTS`. Contributor
inference code and configurations may be Apache-2.0 or MIT. UMI-authored runtime
code remains Apache-2.0 with its original notices. The model card uses CC BY 4.0.
Retain the licenses and notices of inherited components; a bundle-level label
does not grant rights its contributor does not have.

UMI may store, evaluate and publish an NC model, use it as a research baseline,
and cite its results. This route does not grant commercial inference rights,
permit bundling, linking or setting the model as a UMI app default, or permit
using it or its outputs to build or bootstrap a product model. A user's own
use is governed by the model's license. Awards recognize the certified public
model under the cohort's existing rules; they are not a fee for paid inference
from the NC model.

## 3. Training-source declarations and permissions

Declare every training and development source and inherited checkpoint, with
its name, version, canonical URL, license, acquisition route/date, archive names
and SHA-256 values, and any access terms accepted. Preserve the actual terms
attached to the acquired copy. State unknown history explicitly; a public URL
or a license label alone does not prove permission.

The reviewed CC BY-NC 4.0 and CC BY-NC-SA 4.0 sources are permitted for the
public NC research-model use when no additional dataset contract conflicts
with it. How2Sign is allowed with consortium attribution and citation of the
CVPR 2021 paper. Do not redistribute its videos, clips, landmarks or English
sentences, and do not train How2 source transcripts into a model intended for
another track. Its recorded approval does not wait for the pending consortium
notice response.

Retain the reviewed attribution and responsible-use requirements for
FLEURS-ASL, FLORES, 2M-Flores-ASL, FSboard and Taskmaster-1, and the UMI contributor
consent for UMI consented data. Apply the full license-class decisions in the
rights review. No-derivatives terms and unlicensed/scraped sources are not
authorized by this route. Bespoke research or access contracts require the
rights holder's written permission on file; ASL STEM Wiki remains pending that
permission. A generic NC declaration does not clear those contracts.

The operator separately approved ChicagoFSWild and ChicagoFSWild+ **train
splits only**, with provenance disclosure and no dev/test training. Retain this
specific ruling and actual publisher terms; do not invent a publisher license.

## 4. Bundle records and warranty

Include `PROVENANCE.json`, `NOTICE`, a model card, a hashed bundle inventory and
a rights warranty covering the declared sources and the exact intended release.
One NOTICE entry is required for every dataset and base checkpoint; inherit
checkpoint notices in full. Include relevant responsible-use requests and any
required destruction attestation. The model card states the component licenses
and that the NC model is a research model, not an interpreter or commercial
product. Do not include training videos, frames, landmark caches, captions or
sentence lists in the bundle.

The contributor warrants that the disclosures are complete and accurate, that
each source falls under an applicable recorded permission, that accepted access
terms are disclosed, and that it can grant the model rights above. The exact
bundle and supplemental consent must bind these records. Independent artifact
acceptance remains required; a declaration does not certify itself.

The rights review also requires a memorisation probe with per-source
verbatim-match rates and longest matched spans. Its numerical threshold is not
specified in the review. UMI must publish the actual probe rule before claiming
that requirement is enforced; a declaration or an ordinary benchmark score is
not evidence that the independent probe passed. These terms do not invent a
threshold or retroactively change a cohort's signed scoring rules.

## 5. Existing artifacts and continuity

Keep all original submissions, receipts, consent signatures and certification
history. A previously submitted NC-trained model must use the authenticated NC
declaration/consent path; a fresh manifest is required if its bundle bytes or
declared license change. Do not rewrite its original signature or receipt.
Unchanged permissive models retain their original agreement and participation.
Canonical content and duplicate-credit rules remain unchanged across both
license routes.

This supplement changes only the declared model's rights and applicable
training/publication conditions. The cohort's signed clocks, evaluation suite,
baseline identity, resource limits, reward formula and historical results remain
as selected by their existing authenticated records. An earlier baseline keeps
its original license when referenced by a later cohort.
