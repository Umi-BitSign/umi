# UMI non-commercial research-model contribution terms, version 2

These supplemental terms define the **non-commercial model route** for C7 and
later cohorts. They apply to an exact model only after the operator's
authenticated adoption selects this file's SHA-256 and the contributor signs
fresh consent binding that model, its declared license and these terms.
Publication of this file alone does not change a signed cohort or submission.

## 1. Conditional model licensing

A model trained using permitted NonCommercial data, including How2Sign and
ASL STEM Wiki under the source-specific ruling below, must declare that source
and be released under **CC BY-NC-SA 4.0**. The same applies
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

The November 2, 2026 review incorporates the conditional model-license policy
and the source-specific legal/operator determination for ASL STEM Wiki. Its
source conditions apply to use and publication of an NC model. The review PDF
is `UMI Rights Review Sign-Language Datasets and Public Model Weights.pdf`,
SHA-256 `de65b701ded5d414b4f3be5b8f9cbcda59c13b8c08006488d6d3f28f42074808`.

Version 1 and its original PDF binding remain unchanged for existing signed
adoptions and replay. This version takes effect only when the authenticated
adoption selects the version-2 training-rights contract and these exact terms,
and the contributor provides fresh model-bound consent.

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
rights holder's written permission on file except for an applicable named
source-specific determination in this version. A generic NC declaration does
not clear those contracts.

ASL STEM Wiki is allowed for the public NC research-model use under the
November 2, 2026 legal/operator determination. The operator reports legal's
assessment that this use is noncommercial because the models are publicly
released and miner emissions are grant-like research funding. This records no
Microsoft reply, permission letter, license amendment or waiver. It approves
only ASL STEM Wiki under its actual Microsoft Research License Terms and does
not extend to other Microsoft datasets or materially different access terms.

Declare the canonical source as
`https://www.microsoft.com/en-us/research/project/asl-stem-wiki/`, the license
as `LicenseRef-Microsoft-Research`, and the actual acquisition and access terms,
including
`https://www.microsoft.com/en-us/research/project/asl-stem-wiki/dataset-license/`.
Set `additional_dataset_contract` to `true`. The selected version-2 contract
supplies this source-specific approval; do not invent a permission-record hash.
Publish the resulting research model under CC BY-NC-SA 4.0 with fresh
model-bound NC consent and preserve these conditions:

- Use the source solely for noncommercial, non-revenue-generating research
  consistent with the signer consent and accepted access terms.
- Do not share, publish, host or redistribute the Materials or modifications
  to the data, including source videos, clips, frames, landmarks, captions and
  sentence lists. Research results must not include a material or substantial
  portion of the Materials.
- Preserve confidentiality and applicable personal-data restrictions. Complete
  required destruction immediately upon completion of research and provide
  the required dated destruction attestation. Declare whether research is
  ongoing or complete; submitting a model does not itself establish completion.
  An ongoing-research declaration acknowledges the destruction obligation
  without inventing a deletion date. These declarations are contributor
  attestations, not independent proof of deletion.
- Attribute Microsoft and ASL STEM Wiki, retain applicable Wikipedia text-layer
  notices, and reproduce the responsible-use request against technology
  purporting to replace sign language interpreters.

This determination does not grant commercial inference, app distribution or
product-model rights beyond section 2.

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
