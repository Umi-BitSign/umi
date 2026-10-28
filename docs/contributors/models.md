[Documentation](../README.md) / Contribute a model

# Contribute a model

- [Model contributions: prepare before spending compute](#model-contribution-review)

<a id="model-contribution-review"></a>

## Model contributions: prepare before spending compute

Public status reports the active cohort, its allowed tracks and whether model
admission accepts new submissions. This checklist describes artifact, rights and
reconstruction requirements; it does not approve a model or grant a license.
The active signed policy publishes the service and model reward shares. A
successor plan may change any unopened cohort; only the plan published when
intake opens governs that cohort. Use the runtime, immutable policy and upload
route published by live status and cohort history. Do not upload a new artifact
unless `admission_accepting_new` is true.

For C7 and later, the operator's conditional training-data decisions are described under
[Training data and research-model licensing](#training-data-and-research-model-licensing).
Models trained with permitted NonCommercial sources, including How2Sign, must
declare that use and accept the model-bound NC research terms. Permissive-only
models retain the original terms and license. Existing submissions and cohort
clocks are not rewritten. The authenticated model-license adoption and fresh
contributor consent select the NC route; publication of this guide alone does not.

The [version 2 terms](../MODEL_CONTRIBUTION_TERMS_V2.md) remain necessary for
records whose signed policy bound them. Their split and promotion rule do not
define a successor model award. Each submission must use the exact terms named
by its signed policy.

The [version 3 terms](../MODEL_CONTRIBUTION_TERMS_V3.md) define the separate
service and public-model pools. The active policy's continuous-video dependence
comparison is diagnostic only and does not affect scores, eligibility,
settlement or payouts. The policy binds the terms file's published
[SHA-256](../MODEL_CONTRIBUTION_TERMS_V3.sha256).

The [version 4 terms](../MODEL_CONTRIBUTION_TERMS_V4.md) govern successor
policies that use automatic standing artifact review. Their published
[SHA-256](../MODEL_CONTRIBUTION_TERMS_V4.sha256) must be bound by the signed
policy before a participant can accept them. The live status and policy remain
authoritative for the current cohort.

Keep original submissions and acceptance receipts. Enrollment under a different
reward policy requires fresh miner consent; an operator cannot carry old
signatures into the new rules.

<a id="model-contribution-review--what-must-be-published-before-intake-opens"></a>

### Published launch inputs

The signed launch policy names the accepted model-license identifiers and binds
the exact contribution terms by SHA-256. The current policy, endpoint cutoffs and
public status are linked from the
[launch configuration](../competition/launch.md). Submit only against the exact
runtime, immutable environment and route published for the live cohort. The
intake service applies the standing artifact-review policy after complete upload.

The signed cohort plan also selects the payload transport. A direct-R2 cohort
uses short-lived, part-specific capabilities so the model bytes go from the
contributor to private object storage without passing through the coordinator or
reviewer HTTP service. The standard `submit-cohort-model` command discovers that
selection; contributors do not need a cohort-specific uploader. Direct storage
completion alone is not acceptance. The owner and each independent reviewer
read the exact object, verify its full stream and declared files, and retain the
ordinary signed artifact decision before the entry can qualify.

Use the [current model client installation](../miners/connection.md#install-or-update-the-model-submission-client)
before signing, resuming delivery or querying admission. It installs the published
compatible client independently of endpoint services and existing protocol state.

The released S1 reference declares Apache-2.0 for code and CC BY-SA 4.0 for its
weights and portable bundle. The separate
[community candidate](https://github.com/Umi-BitSign/umi-reference-model/blob/main/community/README.md)
records the supplied SHuBERT model's MIT declaration and retains separate
wrapper, DINO and ByT5 notices. It does not inherit S1's CC BY-SA label. Neither
candidate defines the launch allowlist or clears every upstream model and
dataset. Do not remove attribution, change inherited license labels, or assume
a new bundle license overrides upstream restrictions.

The code checks `license_id` against `CompetitionPolicy.accepted_model_licenses`
and binds `accepted_terms_sha256` to the policy. Those checks establish agreement
with a published policy, not the truth of a rights claim. Promotion also requires
a certified artifact review with retained supporting evidence.

### Runtime interface

Declare one Python file with role `inference`. If your bundle declares several
inference files (for example a translator and fingerspelling helpers), declare
the root `umi_inference.py` as `inference`; that wrapper is always the entrypoint.
Other helper files can use role `dependency`. The submission client and intake
check this interface before reserving a new upload. Existing signed bundles do
not need to be relabelled or resubmitted for the root-wrapper convention.

The offline entrypoint receives `/input/video.mp4` as its only argument. The
evaluator does not pass the case ID, reference, task or stratum through an
argument, environment variable or sidecar file. A bundle may inspect the video
and route it among declared model components. The complete router, model paths,
weights, configuration and dependencies must remain inside the bundle and run
offline within the published resource limits. A router must not rely on hidden
filenames, protected case metadata, network access or benchmark lookup data.

Document every routed model and its training data in the same provenance and
rights records. Include data-split attribution and an evaluation-overlap check.
Routing does not create a separate submission or relax the baseline quality
floor.

### Comparator downloads

The [current comparator index](https://artifacts.umi.vision/v1/index.json) publishes
the exact archive lengths and SHA-256 values. The immutable artifacts are:

- [Comparator model bundle](https://artifacts.umi.vision/v1/models/6fe8df59ec11ba89f4dfe0474a673fe757e378cd9184449965861c5a7c59b641/umi-model-bundle.tar):
  model identity `6fe8df59ec11ba89f4dfe0474a673fe757e378cd9184449965861c5a7c59b641`,
  archive SHA-256 `ea9e3e3e46cb95bb8177b2362050d0396da058868a37f6a89f43f783291d699a`,
  2,935,470,080 bytes.
- [Pinned offline CPU runtime](https://artifacts.umi.vision/v1/runtimes/f025ceb38cacc5c71873d94b8f2010aae10a0193a0e410e410a202f4def3b7b0/offline-cpu-runtime.oci.tar):
  runtime identity `f025ceb38cacc5c71873d94b8f2010aae10a0193a0e410e410a202f4def3b7b0`,
  archive SHA-256 `37e09eae8f862d75ddc25fe6b3eadc2fa8d9d7c6b03bfe5d7af4da6b3f97974a`,
  2,215,539,200 bytes.

Verify the archive SHA-256 before extraction, then verify the extracted model or
runtime identity. A successful download does not enroll or approve a model.

<a id="model-contribution-review--evidence-checklist"></a>

### Evidence checklist

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

<a id="model-contribution-review--how-review-should-decide"></a>

### How review should decide

Review the proposed bundle's rights and the underlying model/data restrictions
separately. Then check whether the intended preservation, publication and product
uses are supported together. Successful inference, a high score, a valid archive
hash or an evaluator signature does not answer these questions.

Research-only, non-commercial and unspecified permissions are not automatically
interchangeable. Apply the published training-data decisions below to the actual
source and download terms. In particular, How2Sign is allowed under the reviewed
public non-commercial research model conditions; it does not need a new
case-by-case permission request merely because its license is CC BY-NC 4.0.

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

### Training data and research-model licensing

The authoritative [UMI Training Data and Model Licensing Policy](../../UMI%20Rights%20Review%20Sign-Language%20Datasets%20and%20Public%20Model%20Weights.pdf),
dated October 22, 2026, is the recorded legal assessment for these decisions.
Its PDF SHA-256 is
`9f6694015a84f453ef8298afac4fd9c5dedfc741e74eb0ac3b6833f045b83502`.
Sam selected conditional licensing from C7 onward: permitted NC training data
or inherited NC checkpoints require the NC route for that model; other models
retain the original terms. This supersedes the review's universal-NC clause and
the earlier blanket C8 proposal. This section does not identify sources,
references or clips used in any cohort evaluation.

For an NC-trained model, the [supplemental terms](../MODEL_CONTRIBUTION_TERMS_NC_V1.md)
require a **public, non-commercial research-model release under CC BY-NC-SA 4.0**.
Weights, adapters, tokenizer and label vocabularies, and the portable bundle
carry that license. Contributor inference code and configuration may use
Apache-2.0 or MIT; redistributed UMI runtime code retains Apache-2.0 and its
notices. The model card uses CC BY 4.0. A permissive-only model is not converted
to NC by sharing a cohort or baseline with an NC model.

| Training source | Recorded decision and conditions |
| --- | --- |
| How2Sign | Allowed under the research-model conditions. Attribute the consortium and cite the CVPR 2021 paper in `NOTICE`. Do not redistribute videos, clips, landmarks or English sentences, or train the How2 source transcripts into a model intended for another track. Record the actual acquisition route and any additional terms. The pending consortium notice and request for CORA.RDR terms do not make the documented public-license approval contingent on a reply. |
| FLEURS-ASL | Allowed. Attribute FLEURS-ASL and FLORES, retain their license notices and reproduce the responsible-use requests: blur faces in publicity, no reidentification and no deepfakes. The review records the position supporting a mixed NC-SA model; the requested Google confirmation does not suspend its ruling. |
| 2M-Flores-ASL, FSboard and Taskmaster-1 | Allowed. Retain the attribution and license entries from the reference model's `NOTICE`. |
| UMI consented data | Allowed under the UMI contributor consent. Attribute "UMI contributors" without identifying individual contributors. |
| ChicagoFSWild and ChicagoFSWild+ | Separately approved by the operator for **train splits only**, disclosed in provenance. Do not train on their dev/test splits. This is the operator's specific training ruling, not a claim that the PDF lists these datasets or supplies a new publisher license. |
| ASL STEM Wiki | Pending permission. The review explicitly requires Microsoft's written permission to be recorded before training is permitted; the NC research-model label alone does not satisfy its bespoke contract. |

For other sources, classify the terms attached to the copy actually acquired:

| Source license or access class | Training decision under the review |
| --- | --- |
| CC0 or public domain; CC BY 3.0/4.0; CC BY-SA 3.0/4.0 | Allowed with the applicable attribution and notices, under the review's stated treatment of mixed-model weights. |
| CC BY-NC 4.0 or CC BY-NC-SA 4.0, without additional contractual restrictions | Allowed for the documented public NC-SA research-model use. |
| Apache-2.0, MIT, BSD, ODC-By or CDLA-Permissive | Allowed with the applicable license and notice conditions. |
| CC BY-ND, CC BY-NC-ND or another no-derivatives term | Not permitted by the review. |
| Bespoke research/access contracts, including Microsoft Research, ELRA end-user or click-through academic agreements | Require the rights holder's written permission on file; do not treat them as ordinary CC NonCommercial licenses. |
| Scraped or unlicensed video, social-platform material or unlicensed mirrors | Not permitted by the review. A public URL alone is not a training permission. |

The NC route's reviewed bundle includes `PROVENANCE.json` with every training/development
source's name, version, canonical URL, license, download route and date, archive
names/hashes, and any accepted access terms. Include one `NOTICE` entry per
dataset and base checkpoint, retaining responsible-use requests. Inherit a
fine-tuned checkpoint's notices and NC-SA license. Also include the model card,
signed rights warranty, bundle inventory, memorisation-probe results, and any
required destruction attestation. Do not package training videos, frames,
landmark caches, captions or sentence lists with the model. Sections 4 and 5 of
the review contain the exact notice template and declarations. The
[structured provenance format](../reference/model-training-provenance.md) describes
the bounded declarations checked by artifact review and their limits.

The NC permission does not authorize UMI commercial deployment, app bundling,
linking, defaults or model-specific app instructions, or use of cohort models or
their outputs to bootstrap a product model. UMI may preserve, evaluate and
publish the research models and use them as research baselines. The review's
memorisation probe requires a published threshold; the PDF itself does not
specify a numeric threshold, and the ordinary benchmark score is not a substitute
for that probe.

#### Authenticated model-license adoption

Publishing the review records the operator's legal basis; it does not change
existing signed submissions. The conditional route uses a version-2 model
bundle carrying the authenticated `license_adoption`, binding the original
policy and terms, cohort authority, NC supplement and training-rights policy.
Its submission accepts the exact NC supplement hash, and fresh cohort consent
binds that exact submission. Version-1 bundles and permissive-only submissions
retain their original readers, license and terms. The original V3/V4 commercial
grant cannot be silently read as an NC grant.

Check the active cohort's published adoption and supported client before
preparing an NC upload. Do not change an existing bundle's label to a permissive
identifier to bypass the NC route. Changed license or document bytes require a
new manifest, signed submission and cohort consent; retain the original
artifacts. This additive adoption does not replace the cohort's base policy,
reward series, clocks, baseline or score formula. Supported miner clients,
intake, independent reviewers, validator replay and publication must consume the
same authenticated route before rollout is described as live.

<a id="model-contribution-review--preliminary-review"></a>

### Automatic artifact review and holds

Routine complete bundles enter artifact review automatically. For legacy
delivery, the intake worker verifies the completed retained files. Successful
verification receipts are reused while their exact local file identities remain
unchanged. For direct delivery,
the owner and independent evaluators stream the owner-bound object from private
R2. Both paths verify every declared file, read only bounded UTF-8 license and
provenance records, apply the standing policy bound to the governing competition
policy and retain the exact review inputs. Static review does not import or
execute submitted model code. Independent evaluators still sign the artifact
acceptance, and benchmark execution remains a separate offline step.

Upload finalization, direct-object verification, service-catalog installation and
model acceptance have separate recurring owners. A slow independent model review
cannot delay the next legacy upload-finalization pass or service installation.
Each owner reconciles its own work serially; model publication and its ordinal
remain serialized. Shutdown drains owned file operations before releasing the
client or storage lease. A preserved payload alone still does not certify
admission, artifact rights, benchmark quality or rewards.

Contributors do not need to contact Sam for this step. A missing, unreadable or
out-of-bounds declared record leaves that exact bundle pending with a
machine-readable reason. Correct the bundle and submit its new digest, or use
the community channel to appeal a hold. Preliminary policy questions are
optional and do not reserve a place or replace final certification. Do not post
confidential or personal evidence in a public channel.

<a id="model-contribution-review--endpoint-service-is-a-different-track"></a>

### Endpoint service is a different track

An endpoint miner can keep its model private. Endpoint participation does not by
itself grant UMI a copy, redistribution rights or the model-contribution share.
It still requires acceptance of the applicable published terms and lawful use
of the model and data for the service offered. Keeping weights private does not
remove privacy, consent, access-agreement or commercial-use restrictions.

Model-track participation additionally requires a preserved, reconstructible,
rights-reviewed artifact and explicit enrollment. The
[manifest preparation notes](../reference/commands.md#live-first-round-model-contribution)
describe the live submission path. A model submission registers a signed manifest
and provides the complete bytes through the published delivery route, where every
declared file is rehashed before execution.

Both tracks use the same signed policy. Rewards begin only after the
[activation gates](../competition/launch.md) pass and the competition row is
confirmed on chain.

Read the active policy for the service and model reward shares and the cohort
manifest for allowed tracks. Future track selection may change until that
cohort's intake opens. The public-model quality floor is equality with the
reference selected for that cohort's frozen evaluation. When a previous cohort's
winner becomes the next reference, entries must match or beat that model on
the new cohort's paired evaluation; its previous aggregate is not a fixed numeric
cutoff. A model may retain an older declared parent: derivation provenance and
the paired evaluation reference serve different purposes.

A sole eligible distinct model receives the full model pool. Exact duplicate
content is counted once. The signed authority and any authenticated reward
adoption select the allocation rule. Under geometric bands, eligible distinct
models share normalized decaying weights across occupied bands and within each
band. Read those signed parameters for band width and both decay factors rather
than assuming fixed values. Historical cohort rules remain readable. The first
complete certified acceptance fixes score, eligibility and attribution for exact
copies; later aliases do not create another trial. It also breaks an exact score
tie. Complete submission, artifact preservation and rights checks remain required.
The model award is separate from promotion of the reference model. The previous
certified allocation retains its existing rules until a certified successor row
takes over.
