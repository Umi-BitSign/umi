"""Bounded declared-source checks for the authenticated conditional NC route.

This is artifact-declaration review, not a claim to inspect actual training or
to execute the separate memorisation probe. Callers authenticate model bytes,
the signed license adoption and contributor consent before using the result.
Legacy permissive documents keep their original reader and signed bytes.
"""

from __future__ import annotations

import hashlib
import json
from datetime import date
from importlib.resources import files
from typing import Annotated, Literal
from urllib.parse import urlsplit

from pydantic import Field, ValidationError, field_validator, model_serializer, model_validator

from .protocol import Hex32, StrictProtocolModel

_LEGACY_RAW = files("umi").joinpath("competition_model_training_rights.json").read_bytes()
_RAW = files("umi").joinpath("competition_model_training_rights_v2.json").read_bytes()
_LEGACY_POLICY = json.loads(_LEGACY_RAW)
_POLICY = json.loads(_RAW)
LEGACY_CONDITIONAL_TRAINING_RIGHTS_SHA256 = hashlib.sha256(_LEGACY_RAW).hexdigest()
CONDITIONAL_TRAINING_RIGHTS_SHA256 = hashlib.sha256(_RAW).hexdigest()
LEGACY_NC_CONTRIBUTION_TERMS_SHA256 = (
    "80c95e1e758c5668440f3799dff8f60b971f09d4b954d74df5aa5d6baadddd3b"
)
NC_CONTRIBUTION_TERMS_SHA256 = _POLICY["supplemental_terms_sha256"]
_POLICIES = {
    LEGACY_CONDITIONAL_TRAINING_RIGHTS_SHA256: _LEGACY_POLICY,
    CONDITIONAL_TRAINING_RIGHTS_SHA256: _POLICY,
}
_TERMS = {
    LEGACY_CONDITIONAL_TRAINING_RIGHTS_SHA256: LEGACY_NC_CONTRIBUTION_TERMS_SHA256,
    CONDITIONAL_TRAINING_RIGHTS_SHA256: NC_CONTRIBUTION_TERMS_SHA256,
}
SUPPORTED_NC_CONTRIBUTION_TERMS_SHA256S = frozenset(_TERMS.values())
NC_MODEL_LICENSE = "CC-BY-NC-SA-4.0"
PROVENANCE_SCHEMA = "umi-model-training-provenance/1"
_REQUIRED = {
    "PROVENANCE.json": "provenance",
    "NOTICE": "license",
    "LICENSE-WEIGHTS": "license",
    "MODEL_CARD.md": "provenance",
}
_TRAINING_USES = frozenset(("training", "inherited_checkpoint"))
Text = Annotated[str, Field(min_length=1, max_length=2048)]


def training_rights_policy(rights_policy_sha256):
    """Select exact retained semantics, never reinterpret an older signed pair."""
    try:
        return _POLICIES[rights_policy_sha256]
    except KeyError:
        raise ValueError("conditional_training_rights_policy_not_supported") from None


def validate_model_training_terms(*, rights_policy_sha256, supplemental_terms_sha256):
    """Require the supplement reviewed with this exact rights revision."""
    training_rights_policy(rights_policy_sha256)
    if _TERMS[rights_policy_sha256] != supplemental_terms_sha256:
        raise ValueError("conditional_model_terms_not_supported")


class SourceArchive(StrictProtocolModel):
    name: Text
    sha256: Hex32


class TrainingSource(StrictProtocolModel):
    name: Text
    version: Text
    canonical_url: Text
    license_id: Annotated[str, Field(min_length=1, max_length=128)]
    download_route: Text
    acquired_on: date
    archives: Annotated[tuple[SourceArchive, ...], Field(min_length=1, max_length=512)]
    uses: Annotated[
        tuple[Literal["training", "validation", "testing", "inherited_checkpoint"], ...],
        Field(min_length=1, max_length=4),
    ]
    accepted_access_terms: Annotated[tuple[Text, ...], Field(max_length=64)]
    additional_dataset_contract: bool
    permission_record_sha256: Hex32 | None = None
    split: Text | None = None
    responsible_use_requests: Annotated[tuple[Text, ...], Field(max_length=64)]
    destruction_required: bool
    destroyed_on: date | None = None
    research_complete: bool | None = None

    @model_serializer(mode="wrap")
    def preserve_original_source(self, handler):
        value = handler(self)
        if "research_complete" not in self.model_fields_set:
            value.pop("research_complete", None)
        return value

    @field_validator("canonical_url")
    @classmethod
    def public_source_url(cls, value):
        parsed = urlsplit(value)
        if (
            parsed.scheme not in ("https", "http")
            or not parsed.hostname
            or parsed.username
            or parsed.password
        ):
            raise ValueError("source URL must identify a public source without credentials")
        return value

    @model_validator(mode="after")
    def unique_uses_and_destruction(self):
        if len(set(self.uses)) != len(self.uses):
            raise ValueError("source uses must be unique")
        if (
            self.destruction_required
            and self.destroyed_on is None
            and self.research_complete is not False
        ):
            raise ValueError("required destruction attestation missing")
        if self.destroyed_on is not None and self.destroyed_on < self.acquired_on:
            raise ValueError("destruction predates acquisition")
        return self


class ResearchRightsWarranty(StrictProtocolModel):
    complete_source_inventory: Literal[True]
    sources_and_access_terms_accurately_disclosed: Literal[True]
    public_nc_sa_model_release: Literal[True]
    research_only_umi_model_use: Literal[True]
    no_training_media_landmarks_captions_or_sentence_lists_in_bundle: Literal[True]
    inherited_notices_retained: Literal[True]
    responsible_use_requests_retained: Literal[True]
    how2_source_transcripts_not_used_for_other_track: Literal[True]


class ModelTrainingProvenance(StrictProtocolModel):
    schema_: Literal["umi-model-training-provenance/1"] = Field(alias="schema")
    model_license_id: Literal["CC-BY-NC-SA-4.0"]
    sources: Annotated[tuple[TrainingSource, ...], Field(min_length=1, max_length=512)]
    rights_warranty: ResearchRightsWarranty


def _named(source):
    return "".join(c for c in source.name.casefold() if c.isalnum() or c == "+")


def _stem_source(source, policy):
    approval = policy.get("asl_stem_wiki_approval")
    if approval is None:
        return False
    return _named(source) in approval["normalized_names"] or source.canonical_url.rstrip(
        "/"
    ) == approval["canonical_url"].rstrip("/")


def _nc_training(source, policy):
    return bool(_TRAINING_USES.intersection(source.uses)) and (
        source.license_id in policy["allowed_noncommercial_licenses"]
        or _named(source) == "how2sign"
        or _stem_source(source, policy)
    )


def _provenance_context(provenance, policy):
    for source in provenance.sources:
        if "research_complete" in source.model_fields_set and not _stem_source(source, policy):
            # This optional declaration is selected only by the V2 STEM ruling.
            # V1's strict source schema and all other source conditions stay intact.
            raise ValueError("nc_provenance_schema_invalid")


def _source_decision(source, policy):
    name = _named(source)
    if not _TRAINING_USES.intersection(source.uses):
        return "declared_evaluation_source_not_training_permission"
    if _stem_source(source, policy):
        approval = policy["asl_stem_wiki_approval"]
        if (
            source.canonical_url.rstrip("/") != approval["canonical_url"].rstrip("/")
            or source.license_id != approval["license_id"]
            or not source.additional_dataset_contract
            or approval["access_terms_url"] not in source.accepted_access_terms
        ):
            raise ValueError("asl_stem_requires_microsoft_research_source_declaration")
        if source.accepted_access_terms != (approval["access_terms_url"],):
            raise ValueError("asl_stem_access_terms_not_selected")
        if not source.destruction_required or source.research_complete is None:
            raise ValueError("asl_stem_requires_research_completion_and_destruction_declaration")
        if source.permission_record_sha256 is not None:
            raise ValueError("nc_source_permission_record_not_selected")
        return "operator_approved_noncommercial_research_source"
    if source.additional_dataset_contract or name == "aslstemwiki":
        # A contributor-supplied permission digest is not approval. This exact
        # contract records no Microsoft/bespoke permission; a later authenticated
        # rights-policy revision must enumerate any newly approved permission.
        raise ValueError("nc_source_written_permission_not_selected")
    if source.permission_record_sha256 is not None:
        raise ValueError("nc_source_permission_record_not_selected")
    if name in ("chicagofswild", "chicagofswild+", "chicagofswildplus"):
        if source.split != "train":
            raise ValueError("chicago_training_requires_train_split")
        return "operator_approved_train_split"
    if name == "how2sign" and source.license_id not in policy["allowed_noncommercial_licenses"]:
        raise ValueError("how2sign_requires_noncommercial_source_declaration")
    if source.license_id in policy["allowed_noncommercial_licenses"]:
        return "noncommercial_research_source"
    if source.license_id in policy["allowed_permissive_licenses"]:
        return "permissive_source"
    raise ValueError("nc_source_license_not_permitted")


def declared_nc_training(
    raw_documents, *, rights_policy_sha256=LEGACY_CONDITIONAL_TRAINING_RIGHTS_SHA256
):
    """Recognize explicit new-schema NC declarations without parsing old prose.

    Bare permissive bundles do not embed a rights adoption. Their review owner
    must select a prospective revision explicitly before using its additional
    NC-source rules. The default preserves the retained V1 reader.
    """
    raw = raw_documents.get("PROVENANCE.json")
    if not isinstance(raw, bytes):
        return False
    try:
        value = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        return False
    if not isinstance(value, dict) or value.get("schema") != PROVENANCE_SCHEMA:
        return False
    try:
        provenance = ModelTrainingProvenance.model_validate_json(raw)
    except ValidationError as error:
        raise ValueError("nc_provenance_schema_invalid") from error
    policy = training_rights_policy(rights_policy_sha256)
    _provenance_context(provenance, policy)
    return any(_nc_training(source, policy) for source in provenance.sources)


def validate_model_training_provenance(bundle, raw_documents, *, rights_policy_sha256):
    """Return declared-rights evidence for one already authenticated NC bundle."""
    policy = training_rights_policy(rights_policy_sha256)
    if bundle.license_id != NC_MODEL_LICENSE:
        raise ValueError("nc_training_requires_nc_model_license")
    records = {record.path: record for record in bundle.files}
    for path, role in _REQUIRED.items():
        record = records.get(path)
        raw = raw_documents.get(path)
        if record is None or record.role != role or type(raw) is not bytes or not raw.strip():
            raise ValueError("nc_required_document_missing:" + path)
        # The common caller already authenticates each digest, size and UTF-8
        # body once; do not repeat those payload checks here.
    try:
        provenance = ModelTrainingProvenance.model_validate_json(raw_documents["PROVENANCE.json"])
    except ValidationError as error:
        raise ValueError("nc_provenance_schema_invalid") from error
    _provenance_context(provenance, policy)
    if not any(_nc_training(source, policy) for source in provenance.sources):
        raise ValueError("nc_route_requires_declared_nc_training_or_checkpoint")
    weights = raw_documents["LICENSE-WEIGHTS"].decode("utf-8")
    if (
        NC_MODEL_LICENSE not in weights
        and "creativecommons.org/licenses/by-nc-sa/4.0" not in weights
    ):
        raise ValueError("nc_weights_license_notice_missing")
    notice = raw_documents["NOTICE"].decode("utf-8")
    decisions = []
    seen = set()
    for source in provenance.sources:
        key = (source.name.casefold(), source.version, source.canonical_url)
        if key in seen:
            raise ValueError("nc_provenance_source_duplicated")
        seen.add(key)
        decision = _source_decision(source, policy)
        if source.name.casefold() not in notice.casefold() or any(
            request not in notice for request in source.responsible_use_requests
        ):
            raise ValueError("nc_source_notice_or_responsible_use_missing")
        if _named(source) == "how2sign" and not all(
            token in notice.casefold() for token in ("consortium", "cvpr", "2021")
        ):
            raise ValueError("how2sign_attribution_or_citation_missing")
        decisions.append(
            {
                "name": source.name,
                "version": source.version,
                "license_id": source.license_id,
                "decision": decision,
            }
        )
    return {
        "schema": "umi-declared-model-training-rights-review/1",
        "training_rights_policy_sha256": rights_policy_sha256,
        "supplemental_terms_sha256": _TERMS[rights_policy_sha256],
        "declared_model_license": NC_MODEL_LICENSE,
        "provenance_sha256": records["PROVENANCE.json"].sha256,
        "source_decisions": decisions,
        "rights_warranty_bound_by": "exact_model_manifest_and_fresh_nc_consent",
        "actual_training_independently_audited": False,
        "memorisation_probe_executed": False,
        "memorisation_probe_threshold": None,
        "review_scope": "authenticated_declared_sources_not_complete_pdf_compliance",
    }
