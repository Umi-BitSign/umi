"""Artifact acceptance contracts shared by intake and later reward replay."""

from typing import Annotated, Literal

from pydantic import Field, JsonValue, model_validator

from .competition_cohort_recovery import Block, ModelRewardCohortAuthority, verify_recovery_quorum
from .open_competition import Hotkey, Signature, digest, identity, model_content_digest
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes


class ModelArtifactAcceptance(StrictProtocolModel):
    """Independent rights and reconstruction review of a complete model entry.

    The acceptance ordinal is assigned durably when all files and reviews are
    ready, before intake closes. It is not a miner-supplied upload timestamp.
    """

    schema_: Literal["umi-cohort-model-artifact-acceptance/1"] = Field(alias="schema")
    policy_sha256: Hex32
    cohort_sha256: Hex32
    authority_sha256: Hex32
    submission_sha256: Hex32
    model_sha256: Hex32
    content_sha256: Hex32
    recipient_hotkey: Hotkey
    rights_evidence_sha256: Hex32
    reconstruction_evidence_sha256: Hex32
    accepted_at_block: Block
    accepted_ordinal: Annotated[int, Field(ge=1, le=2**53 - 1)]
    rights_and_reconstruction_passed: Literal[True]


class CertifiedModelArtifactAcceptance(StrictProtocolModel):
    acceptance: ModelArtifactAcceptance
    signatures: Annotated[tuple[Signature, ...], Field(min_length=1, max_length=64)]


class ModelArtifactReviewInputs(StrictProtocolModel):
    """Operator-reviewed documents; their presence never grants signing authority."""

    model_sha256: Hex32
    rights_evidence: dict[str, JsonValue]
    reconstruction_evidence: dict[str, JsonValue]

    @model_validator(mode="after")
    def bounded(self):
        for body in (self.rights_evidence, self.reconstruction_evidence):
            if not body or len(canonical_json_bytes(body)) > 16 * 1024**2:
                raise ValueError("model artifact review requires bounded original documents")
        return self


class ModelAcceptancePublication(StrictProtocolModel):
    certificate: CertifiedModelArtifactAcceptance
    inputs: ModelArtifactReviewInputs

    @model_validator(mode="after")
    def bindings(self):
        a, inputs = self.certificate.acceptance, self.inputs
        if (
            a.model_sha256 != inputs.model_sha256
            or a.rights_evidence_sha256 != digest(inputs.rights_evidence)
            or a.reconstruction_evidence_sha256 != digest(inputs.reconstruction_evidence)
        ):
            raise ValueError("model acceptance publication changes original review documents")
        return self


class ModelAcceptanceIntent(StrictProtocolModel):
    acceptance: ModelArtifactAcceptance
    inputs: ModelArtifactReviewInputs

    @model_validator(mode="after")
    def bindings(self):
        a, inputs = self.acceptance, self.inputs
        if (
            a.model_sha256 != inputs.model_sha256
            or a.rights_evidence_sha256 != digest(inputs.rights_evidence)
            or a.reconstruction_evidence_sha256 != digest(inputs.reconstruction_evidence)
        ):
            raise ValueError("model acceptance intent changes original review documents")
        return self


def verify_model_acceptance(certificate, record, history, policy, *, maximum_block):
    a = certificate.acceptance
    sub, admission = record.request.signed_submission.submission, record.proposed_admission
    authority = history.authority.authority
    if (
        not isinstance(authority, ModelRewardCohortAuthority)
        or sub.track != "model"
        or sub.model_bundle is None
        or a.policy_sha256 != digest(policy)
        or a.cohort_sha256 != digest(history.plan)
        or a.authority_sha256 != digest(authority)
        or a.submission_sha256 != digest(sub)
        or a.model_sha256 != digest(sub.model_bundle)
        or a.content_sha256 != model_content_digest(sub.model_bundle)
        or identity(a.recipient_hotkey) != identity(sub.hotkey)
        or not admission.admitted_at_block <= a.accepted_at_block <= maximum_block
        or "0" * 64 in (a.rights_evidence_sha256, a.reconstruction_evidence_sha256)
    ):
        raise ValueError("model artifact acceptance differs from the original complete entry")
    verify_recovery_quorum(a, certificate.signatures, policy)
    if identity(sub.hotkey) in {identity(s.hotkey) for s in certificate.signatures}:
        raise ValueError("model submitters cannot certify their own artifact acceptance")
