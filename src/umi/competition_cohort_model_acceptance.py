"""Artifact acceptance contracts shared by intake and later reward replay."""

from typing import Annotated, Literal

from pydantic import Field, JsonValue, model_serializer, model_validator

from .competition_cohort_direct_model_upload import SignedDirectModelUploadReservation
from .competition_cohort_intake_records import RetainedCohortParticipation
from .competition_cohort_model_batch import (
    CertifiedModelAcceptanceBatch,
    ModelAcceptanceBatchProof,
    model_acceptance_batch_proofs,
    verify_model_acceptance_batch,
    verify_model_acceptance_batch_proof,
)
from .competition_cohort_model_transport import verify_direct_model_transport
from .competition_cohort_participation import AttestedCohortParticipantAdmission
from .competition_cohort_recovery import Block, ModelRewardCohortAuthority, verify_recovery_quorum
from .open_competition import (
    Hotkey,
    Signature,
    digest,
    identity,
    model_content_digest,
    verify_signature,
)
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes


class ModelArtifactAcceptance(StrictProtocolModel):
    """Independent rights and reconstruction review of a complete model entry.

    The acceptance ordinal is assigned durably when all files and reviews are
    ready, before intake closes. It is not a miner-supplied upload timestamp.
    """

    schema_: Literal[
        "umi-cohort-model-artifact-acceptance/1",
        "umi-cohort-model-artifact-acceptance/2",
    ] = Field(alias="schema")
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
    direct_artifact: SignedDirectModelUploadReservation | None = None

    @model_serializer(mode="wrap")
    def omit_legacy_artifact(self, handler):
        value = handler(self)
        if self.direct_artifact is None:
            value.pop("direct_artifact", None)
        return value

    @model_validator(mode="after")
    def exact_artifact_source(self):
        if (self.schema_ == "umi-cohort-model-artifact-acceptance/2") != (
            self.direct_artifact is not None
        ):
            raise ValueError("model acceptance artifact source differs")
        if self.direct_artifact is not None:
            body = self.direct_artifact.reservation
            if (
                body.cohort_sha256 != self.cohort_sha256
                or body.payload.model_sha256 != self.model_sha256
                or identity(body.hotkey) != identity(self.recipient_hotkey)
            ):
                raise ValueError("direct model acceptance source differs")
        return self


class CertifiedModelArtifactAcceptance(StrictProtocolModel):
    acceptance: ModelArtifactAcceptance
    signatures: Annotated[tuple[Signature, ...], Field(max_length=64)] = ()
    batch_proof: ModelAcceptanceBatchProof | None = None

    @model_serializer(mode="wrap")
    def preserve_original_certificate(self, handler):
        value = handler(self)
        if self.batch_proof is None:
            value.pop("batch_proof", None)
        elif not self.signatures:
            value.pop("signatures", None)
        return value

    @model_validator(mode="after")
    def exactly_one_proof(self):
        if bool(self.signatures) == (self.batch_proof is not None):
            raise ValueError("model acceptance requires exactly one individual or batch proof")
        return self


class ModelAcceptanceBatchManifest(StrictProtocolModel):
    schema_: Literal["umi-cohort-model-acceptance-manifest/1"] = Field(alias="schema")
    certificate: CertifiedModelAcceptanceBatch
    acceptances: Annotated[tuple[ModelArtifactAcceptance, ...], Field(max_length=512)]

    @model_validator(mode="after")
    def exact_manifest(self):
        if tuple(a.submission_sha256 for a in self.acceptances) != tuple(
            sorted(a.submission_sha256 for a in self.acceptances)
        ):
            raise ValueError("model acceptance manifest must use canonical submission order")
        model_acceptance_batch_proofs(self.acceptances, self.certificate)
        return self


def model_acceptance_batch_certificates(manifest):
    """Project actual membership evidence; no per-model signature is implied."""
    manifest = ModelAcceptanceBatchManifest.model_validate_json(canonical_json_bytes(manifest))
    proofs = model_acceptance_batch_proofs(manifest.acceptances, manifest.certificate)
    return tuple(
        CertifiedModelArtifactAcceptance(acceptance=acceptance, batch_proof=proof)
        for acceptance, proof in zip(manifest.acceptances, proofs, strict=True)
    )


def verify_model_acceptance_batch_manifest(manifest, history, policy, *, maximum_block):
    """Verify complete artifact scope; roster completeness remains the owner's check."""
    manifest = ModelAcceptanceBatchManifest.model_validate_json(canonical_json_bytes(manifest))
    verify_model_acceptance_batch(
        manifest.certificate, history, policy, maximum_block=maximum_block
    )
    signers = {identity(s.hotkey) for s in manifest.certificate.signatures}
    if any(identity(a.recipient_hotkey) in signers for a in manifest.acceptances):
        raise ValueError("model submitters cannot certify their own batch membership")
    return manifest


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


def verify_model_acceptance_body(a, record, history, policy, *, maximum_block):
    from .competition_model_license import verify_cohort_model_terms

    sub, admission = record.request.signed_submission.submission, record.proposed_admission
    verify_cohort_model_terms(
        sub,
        record.request.consent.consent,
        history,
        policy,
        current_block=maximum_block,
    )
    authority = history.authority.authority
    direct = a.direct_artifact
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
        or (
            direct is not None
            and (
                direct.reservation.payload.upload_sha256 != digest(record.request)
                or direct.reservation.payload.model_sha256 != digest(sub.model_bundle)
                or identity(direct.signature.hotkey)
                not in {identity(e.hotkey) for e in policy.evaluators}
                or identity(direct.signature.hotkey) == identity(sub.hotkey)
            )
        )
    ):
        raise ValueError("model artifact acceptance differs from the original complete entry")
    if direct is not None:
        verify_direct_model_transport(
            direct,
            history,
            policy,
            accepted_at_block=a.accepted_at_block,
        )


def verify_model_acceptance(certificate, record, history, policy, *, maximum_block):
    certificate = CertifiedModelArtifactAcceptance.model_validate_json(
        canonical_json_bytes(certificate)
    )
    a = certificate.acceptance
    verify_model_acceptance_body(a, record, history, policy, maximum_block=maximum_block)
    if certificate.batch_proof is not None:
        verify_model_acceptance_batch_proof(
            a, certificate.batch_proof, history, policy, maximum_block=maximum_block
        )
        return
    verify_recovery_quorum(a, certificate.signatures, policy)
    if identity(a.recipient_hotkey) in {identity(s.hotkey) for s in certificate.signatures}:
        raise ValueError("model submitters cannot certify their own artifact acceptance")


class ModelReviewRequest(StrictProtocolModel):
    schema_: Literal["umi-cohort-model-review-request/1", "umi-cohort-model-review-request/2"] = (
        Field(alias="schema")
    )
    acceptance: ModelArtifactAcceptance
    record: RetainedCohortParticipation
    admission: AttestedCohortParticipantAdmission
    direct_artifact: SignedDirectModelUploadReservation | None = None

    @model_serializer(mode="wrap")
    def omit_legacy_artifact(self, handler):
        value = handler(self)
        if self.direct_artifact is None:
            value.pop("direct_artifact", None)
        return value

    @model_validator(mode="after")
    def exact_artifact_source(self):
        if (self.schema_ == "umi-cohort-model-review-request/2") != (
            self.direct_artifact is not None
        ) or self.acceptance.direct_artifact != self.direct_artifact:
            raise ValueError("model review request artifact source differs")
        return self


class ModelArtifactVote(StrictProtocolModel):
    acceptance: ModelArtifactAcceptance
    signature: Signature


def check_model_vote(vote: ModelArtifactVote, acceptance, policy, *, signer=None):
    account = identity(vote.signature.hotkey)
    if (
        vote.acceptance != acceptance
        or account == identity(acceptance.recipient_hotkey)
        or account not in {identity(e.hotkey) for e in policy.evaluators}
        or (signer is not None and account != identity(signer))
    ):
        raise ValueError("model acceptance vote changes body or independent reviewer")
    verify_signature(vote.acceptance, vote.signature)
