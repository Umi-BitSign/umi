[Documentation](../README.md) / Conditional model training provenance

# Conditional model training provenance

From C7 onward, a model trained with permitted NonCommercial data or an
inherited NC checkpoint uses the authenticated NC model route. Its license is
`CC-BY-NC-SA-4.0`, and fresh model-bound consent accepts the
[NC supplement](../MODEL_CONTRIBUTION_TERMS_NC_V1.md). A permissive-only model
keeps its original terms and reader. See the
[training-permission decisions](../contributors/models.md#training-data-and-research-model-licensing)
before spending compute; an NC label does not clear a bespoke access contract.

The NC bundle includes these exact paths and manifest roles:

| Path | Role | Content |
| --- | --- | --- |
| `PROVENANCE.json` | `provenance` | Structured source inventory and rights warranty below. |
| `NOTICE` | `license` | Attribution for every dataset and inherited checkpoint, retained notices and responsible-use requests. |
| `LICENSE-WEIGHTS` | `license` | CC BY-NC-SA 4.0 legal code or its canonical URL and identifier. |
| `MODEL_CARD.md` | `provenance` | Component licenses, research-model scope, intended use and limitations. |

All four must be nonempty UTF-8 documents authenticated by the bundle inventory.
The common artifact reader enforces its published document size and aggregate
limits, hashes each document once and supplies the verified bytes to the rights
classifier. The classifier reuses the inventory digest; it does not reread the
model or rehash the documents. Keep source evidence in the bundle's existing
bounded document allowance rather than embedding training media.

## Structured declaration

Use schema `umi-model-training-provenance/1`. This illustrative entry must be
replaced with the actual acquired release, archive hash and access route; the
example hash is not evidence of acquisition or permission.

```json
{
  "schema": "umi-model-training-provenance/1",
  "model_license_id": "CC-BY-NC-SA-4.0",
  "sources": [
    {
      "name": "How2Sign",
      "version": "ACTUAL_RELEASE",
      "canonical_url": "https://how2sign.github.io/",
      "license_id": "CC-BY-NC-4.0",
      "download_route": "ACTUAL_PUBLISHER_DOWNLOAD_ROUTE",
      "acquired_on": "2026-10-01",
      "archives": [
        {
          "name": "ACTUAL_ARCHIVE_NAME",
          "sha256": "0000000000000000000000000000000000000000000000000000000000000000"
        }
      ],
      "uses": ["training"],
      "accepted_access_terms": [],
      "additional_dataset_contract": false,
      "permission_record_sha256": null,
      "split": "train",
      "responsible_use_requests": [],
      "destruction_required": false,
      "destroyed_on": null
    }
  ],
  "rights_warranty": {
    "complete_source_inventory": true,
    "sources_and_access_terms_accurately_disclosed": true,
    "public_nc_sa_model_release": true,
    "research_only_umi_model_use": true,
    "no_training_media_landmarks_captions_or_sentence_lists_in_bundle": true,
    "inherited_notices_retained": true,
    "responsible_use_requests_retained": true,
    "how2_source_transcripts_not_used_for_other_track": true
  }
}
```

Declare every training, validation and test source and inherited checkpoint.
`uses` contains unique entries from `training`, `validation`, `testing` and
`inherited_checkpoint`. Only training and inherited-checkpoint use select the
NC model class; a validation/test declaration does not itself authorize source
use for evaluation. Acquisition and destruction dates use `YYYY-MM-DD`.
Required destruction must have an attested date no earlier than acquisition.

The contract permits up to 512 sources, each with up to 512 archive references,
subject to the artifact reader's tighter byte budget. Text fields are bounded;
unknown fields, malformed dates and false warranty statements are rejected.
Use canonical HTTP(S) source URLs without credentials. Do not publish tokens,
private URLs or personal contributor information in the inventory.

For ChicagoFSWild and ChicagoFSWild+, preserve the actual publisher license
description even where no explicit license was stated; do not invent an SPDX
license. The recorded operator permission requires `split: "train"` and
excludes dev/test training. This is a source-specific permission, not a general
exception for unlicensed datasets. Additional bespoke access terms still need
a selected recorded approval.

## Review behavior and limits

The rights contract has SHA-256
`daeaa1596ffc46890c9b896682484a86f079d907af4538a6f7768e5ffe4b39ab`.
The NC supplement has SHA-256
`80c95e1e758c5668440f3799dff8f60b971f09d4b954d74df5aa5d6baadddd3b`.
The authenticated adoption binds both; a locally edited JSON contract grants
no rights. The current contract contains no selected bespoke permission.
Providing an arbitrary permission-record hash does not clear Microsoft or
other bespoke conditions. A new approved permission needs its authenticated
contract revision before submission.

Artifact review rejects unsupported training license classes, missing required
records, missing source attribution/responsible-use requests, and an NC route
with no declared NC training or inherited checkpoint. How2Sign cannot be
relabelled permissive; its NOTICE must include consortium attribution and the
CVPR 2021 citation. Legacy freeform provenance keeps the original reader.
Previously accepted artifacts are not retrospectively rewritten by detecting
a new schema in a later submission.

The retained review evidence states exactly what was checked: authenticated
source declarations, their selected contract and the signed warranty. It does
not claim independent access to actual training runs or completion of every
condition in the PDF. The review's memorisation probe has no published numeric
threshold in that PDF; this module does not invent one or execute that probe.
The contributor must still meet the full source and release obligations.
