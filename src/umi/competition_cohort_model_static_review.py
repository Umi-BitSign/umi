"""Deterministic artifact review under one retained standing operator policy.

The review reads only declared license and provenance records from a complete,
byte-verified bundle. It never imports or executes submitted code and never
uses the network. Independent validators still decide whether to sign the
resulting artifact-acceptance body.
"""

from __future__ import annotations

import hashlib
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, model_validator

from .competition_artifacts import _artifact, _directory, verify_preserved_bundle
from .competition_cohort_model_acceptance import ModelArtifactReviewInputs
from .competition_model_license import model_contribution_terms, verify_model_license_adoption
from .open_competition import CompetitionPolicy, ModelBundle, digest
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes


class StandingModelReviewPolicy(StrictProtocolModel):
    """One operator decision applied mechanically to routine complete bundles."""

    schema_: Literal["umi-standing-model-artifact-review-policy/1"] = Field(alias="schema")
    competition_policy_sha256: Hex32
    contribution_terms_sha256: Hex32
    standing_approval_record_sha256: Hex32
    approved_by: Annotated[str, Field(min_length=1, max_length=256)]
    approved_at_utc: Annotated[
        str,
        Field(pattern=r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"),
    ]
    maximum_document_bytes: Annotated[int, Field(ge=1, le=4 * 1024**2)] = 2 * 1024**2
    maximum_total_document_bytes: Annotated[int, Field(ge=1, le=12 * 1024**2)] = 8 * 1024**2
    complete_declared_bundle_rights_approved: Literal[True]
    licenses_and_notices_reviewed: Literal[True]
    public_redistribution_and_evaluation_approved: Literal[True]

    @model_validator(mode="after")
    def bounded_documents(self):
        if self.maximum_document_bytes > self.maximum_total_document_bytes:
            raise ValueError("per-document review limit exceeds the total limit")
        return self


class StaticModelReviewHeld(ValueError):
    """The exact immutable bundle cannot pass the configured standing policy."""

    def __init__(self, reason_code: str):
        super().__init__(reason_code)
        self.reason_code = reason_code


def review_hold_key(model_sha256: str, standing: StandingModelReviewPolicy) -> str:
    """Version negative decisions independently of successful native byte facts."""
    return digest(
        {
            "schema": "umi-standing-model-artifact-review-rules/2",
            "model_sha256": model_sha256,
            "review_policy_sha256": digest(standing),
        }
    )


def verify_standing_review_policy(
    standing: StandingModelReviewPolicy, policy: CompetitionPolicy
) -> None:
    if standing.competition_policy_sha256 != digest(policy):
        raise ValueError("standing model review belongs to another competition policy")
    if standing.contribution_terms_sha256 != policy.contribution_terms_sha256:
        raise ValueError("standing model review belongs to other contribution terms")


def _read_document(root_fd: int, record, standing: StandingModelReviewPolicy) -> str:
    if not 0 <= record.size_bytes <= standing.maximum_document_bytes:
        raise StaticModelReviewHeld("review_document_size_outside_policy")
    with _artifact(root_fd, record) as (stream, before):
        raw = stream.read(standing.maximum_document_bytes + 1)
        after = os.fstat(stream.fileno())
    if (
        len(raw) != record.size_bytes
        or hashlib.sha256(raw).hexdigest() != record.sha256
        or (before.st_dev, before.st_ino, before.st_mtime_ns, before.st_ctime_ns)
        != (after.st_dev, after.st_ino, after.st_mtime_ns, after.st_ctime_ns)
    ):
        raise ValueError("review document changed or differs from its manifest")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise StaticModelReviewHeld("review_document_not_utf8") from error
    if (raw and not text.strip()) or "\x00" in text:
        raise StaticModelReviewHeld("review_document_not_plain_text")
    return text


def obsolete_empty_document_hold(bundle, standing, reason_code: str) -> bool:
    """Reconsider only the old lower-bound rule, preserving genuine holds.

    Previously accepted reviews remain byte-identical. A legacy hold is retained
    as evidence; a new review must still authenticate every file and require
    substantive license and provenance documents.
    """
    documents = [r for r in bundle.files if r.role in {"license", "provenance"}]
    return (
        reason_code == "review_document_size_outside_policy"
        and any(r.size_bytes == 0 for r in documents)
        and all(r.size_bytes <= standing.maximum_document_bytes for r in documents)
    )


def _review_from_documents(
    bundle: ModelBundle,
    policy: CompetitionPolicy,
    standing: StandingModelReviewPolicy,
    raw_documents: Mapping[str, bytes],
) -> ModelArtifactReviewInputs:
    """Build the same decision from authenticated local or remote document bytes."""

    review_policy_sha256 = digest(standing)
    documents = []
    encoded_document_bytes = 0
    expected_paths = {
        record.path for record in bundle.files if record.role in {"license", "provenance"}
    }
    if set(raw_documents) != expected_paths:
        raise ValueError("review documents differ from the model manifest")
    for record in bundle.files:
        if record.role not in {"license", "provenance"}:
            continue
        raw = raw_documents[record.path]
        if not 0 <= record.size_bytes <= standing.maximum_document_bytes:
            raise StaticModelReviewHeld("review_document_size_outside_policy")
        if len(raw) != record.size_bytes or hashlib.sha256(raw).hexdigest() != record.sha256:
            raise ValueError("review document differs from its manifest")
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as error:
            raise StaticModelReviewHeld("review_document_not_utf8") from error
        if (raw and not text.strip()) or "\x00" in text:
            raise StaticModelReviewHeld("review_document_not_plain_text")
        encoded_document_bytes += len(canonical_json_bytes(text))
        if encoded_document_bytes > standing.maximum_total_document_bytes:
            raise StaticModelReviewHeld("review_documents_exceed_total_policy")
        documents.append(
            {
                "path": record.path,
                "role": record.role,
                "sha256": record.sha256,
                "size_bytes": record.size_bytes,
                "text": text,
            }
        )
    if not any(item["role"] == "license" and item["text"].strip() for item in documents):
        raise StaticModelReviewHeld("declared_license_document_missing")
    if not any(item["role"] == "provenance" and item["text"].strip() for item in documents):
        raise StaticModelReviewHeld("declared_provenance_document_missing")

    from .competition_model_training_rights import (
        NC_CONTRIBUTION_TERMS_SHA256,
        declared_nc_training,
        validate_model_training_provenance,
    )

    license_adoption, training_review = None, None
    try:
        if bundle.license_adoption is not None:
            license_adoption = verify_model_license_adoption(bundle, policy)
            if license_adoption.noncommercial_terms_sha256 != NC_CONTRIBUTION_TERMS_SHA256:
                raise StaticModelReviewHeld("conditional_model_terms_not_supported")
            training_review = validate_model_training_provenance(
                bundle,
                raw_documents,
                rights_policy_sha256=license_adoption.training_rights_policy_sha256,
            )
        elif declared_nc_training(raw_documents):
            raise StaticModelReviewHeld("declared_nc_training_requires_authenticated_nc_route")
    except ValueError as error:
        raise StaticModelReviewHeld(str(error)) from error

    model_sha256 = digest(bundle)
    decision = {
        "schema": "umi-standing-model-artifact-rights-decision/1",
        "review_policy_sha256": review_policy_sha256,
        "competition_policy_sha256": digest(policy),
        "contribution_terms_sha256": model_contribution_terms(bundle, policy),
        "standing_approval_record_sha256": standing.standing_approval_record_sha256,
        "approved_by": standing.approved_by,
        "approved_at_utc": standing.approved_at_utc,
        "approval_basis": "standing_operator_policy_for_complete_declared_bundles",
        "rights_approved": True,
        "licenses_and_notices_reviewed": True,
        "public_redistribution_and_evaluation_approved": True,
    }
    if license_adoption is not None:
        decision.update(
            schema="umi-standing-model-artifact-rights-decision/2",
            approval_basis="quorum_authorized_conditional_model_terms_and_declared_source_review",
            original_contribution_terms_sha256=policy.contribution_terms_sha256,
            license_adoption_sha256=digest(license_adoption),
            training_rights_policy_sha256=license_adoption.training_rights_policy_sha256,
            operator_decision_sha256=license_adoption.operator_decision_sha256,
            declared_training_rights_review=training_review,
        )
    return ModelArtifactReviewInputs(
        model_sha256=model_sha256,
        rights_evidence={
            "schema": (
                "umi-standing-model-rights-review/1"
                if license_adoption is None
                else "umi-standing-model-rights-review/2"
            ),
            "model_sha256": model_sha256,
            "declared_license_id": bundle.license_id,
            "accepted_model_licenses": list(policy.accepted_model_licenses)
            + ([] if license_adoption is None else [license_adoption.license_id]),
            "original_documents": documents,
            "decision": decision,
        },
        reconstruction_evidence={
            "schema": "umi-static-model-reconstruction-review/1",
            "model_sha256": model_sha256,
            "review_policy_sha256": review_policy_sha256,
            "original_manifest": bundle.model_dump(mode="json", by_alias=True),
            "complete_bundle_hash_verification": {
                "status": "complete_bundle_verified",
                "file_count": len(bundle.files),
                "total_bytes": sum(record.size_bytes for record in bundle.files),
                "model_code_executed": False,
                "network_used": False,
            },
        },
    )


def build_standing_model_review_from_documents(
    bundle: ModelBundle,
    policy: CompetitionPolicy,
    standing: StandingModelReviewPolicy,
    raw_documents: Mapping[str, bytes],
) -> ModelArtifactReviewInputs:
    """Review exact authenticated document bytes without a local model archive."""

    bundle = ModelBundle.model_validate_json(canonical_json_bytes(bundle))
    standing = StandingModelReviewPolicy.model_validate_json(canonical_json_bytes(standing))
    verify_standing_review_policy(standing, policy)
    return _review_from_documents(bundle, policy, standing, raw_documents)


def build_standing_model_review(
    bundle: ModelBundle,
    archive: Path,
    policy: CompetitionPolicy,
    standing: StandingModelReviewPolicy,
) -> ModelArtifactReviewInputs:
    """Build stable review inputs from one exact preserved model bundle."""

    bundle = ModelBundle.model_validate_json(canonical_json_bytes(bundle))
    standing = StandingModelReviewPolicy.model_validate_json(canonical_json_bytes(standing))
    verify_standing_review_policy(standing, policy)
    model_sha256 = verify_preserved_bundle(bundle, archive, policy)
    raw_documents = {}
    with _directory(archive / model_sha256 / "model") as root_fd:
        for record in bundle.files:
            if record.role not in {"license", "provenance"}:
                continue
            # The local reader applies the same bounds and encoding checks; retain
            # exact bytes so the common builder also authenticates their digest.
            text = _read_document(root_fd, record, standing)
            raw_documents[record.path] = text.encode("utf-8")
    return _review_from_documents(bundle, policy, standing, raw_documents)
