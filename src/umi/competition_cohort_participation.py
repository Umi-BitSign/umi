"""Explicit miner consent and quorum admission for a recoverable cohort.

The original signed submission stays unchanged. A separate hotkey signature
authorizes that exact contribution for one admitted recoverable cohort, including
overruns beyond the original submission interval. Native intake must supply an
owned finalized registration snapshot before attesting the admission returned
here; a JSON snapshot alone is not a finality proof.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field, model_validator
from typing_extensions import Self

from .competition_cohort_history import CohortRecoveryHistory, verify_cohort_history
from .competition_cohort_recovery import Block, verify_recovery_quorum
from .open_competition import (
    CompetitionPolicy,
    Hotkey,
    RegistrationSnapshot,
    Signature,
    SignedSubmission,
    digest,
    identity,
    validate_bundle_policy,
    verify_signature,
)
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes


class CohortParticipationConsent(StrictProtocolModel):
    schema_: Literal["umi-cohort-participation-consent/1"] = Field(alias="schema")
    cohort_sha256: Hex32
    authority_sha256: Hex32
    submission_sha256: Hex32
    hotkey: Hotkey
    signed_at_block: Block
    lifetime: Literal["until_cohort_completed_or_revoked"]
    timing_rule: Literal["quorum_recovery_history/1"]
    original_submission_expiry_does_not_end_participation: Literal[True]


class SignedCohortParticipationConsent(StrictProtocolModel):
    consent: CohortParticipationConsent
    signature: Signature

    @model_validator(mode="after")
    def signature_matches(self) -> Self:
        if identity(self.signature.hotkey) != identity(self.consent.hotkey):
            raise ValueError("cohort participation signer is not the consenting hotkey")
        verify_signature(self.consent, self.signature)
        return self


class CohortParticipantAdmission(StrictProtocolModel):
    schema_: Literal["umi-cohort-participant-admission/1"] = Field(alias="schema")
    cohort_sha256: Hex32
    recovery_tip_sha256: Hex32
    consent_sha256: Hex32
    submission_sha256: Hex32
    snapshot_sha256: Hex32
    admitted_at_block: Block
    uid: Annotated[int, Field(ge=0, le=255)]


class AttestedCohortParticipantAdmission(StrictProtocolModel):
    admission: CohortParticipantAdmission
    signatures: Annotated[tuple[Signature, ...], Field(min_length=1, max_length=64)]


def admit_recovery_participant(
    signed: SignedSubmission,
    consent: SignedCohortParticipationConsent,
    history: CohortRecoveryHistory,
    policy: CompetitionPolicy,
    snapshot: RegistrationSnapshot,
    *,
    expected_tip_sha256: str,
    current_block: int,
) -> CohortParticipantAdmission:
    """Derive an admission to attest after native finality/roster verification."""
    policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
    signed = SignedSubmission.model_validate_json(canonical_json_bytes(signed))
    consent = SignedCohortParticipationConsent.model_validate_json(canonical_json_bytes(consent))
    snapshot = RegistrationSnapshot.model_validate_json(canonical_json_bytes(snapshot))
    view = verify_cohort_history(
        history, policy, expected_tip_sha256=expected_tip_sha256, current_block=current_block
    )
    if view.state.phase != "intake" or current_block < view.state.not_before_block:
        raise ValueError("cohort intake is not open")
    sub, body = signed.submission, consent.consent
    if (
        sub.policy_sha256 != digest(policy)
        or sub.accepted_terms_sha256 != policy.contribution_terms_sha256
        or body.cohort_sha256 != view.state.cohort_sha256
        or body.authority_sha256 != view.state.authority_sha256
        or body.submission_sha256 != digest(sub)
        or identity(body.hotkey) != identity(sub.hotkey)
        or current_block < sub.valid_from_block
        or not history.authority.authority.issued_at_block <= body.signed_at_block <= current_block
    ):
        raise ValueError("cohort consent does not cover this policy, authority or submission")
    # Preserve the base contract's bounds and deal; the new consent explicitly
    # authorizes this cohort after the old interval, without rewriting it.
    if not (
        policy.valid_from_block
        <= sub.valid_from_block
        < sub.valid_through_block
        <= policy.valid_through_block
        and sub.valid_through_block - sub.valid_from_block
        <= policy.maximum_submission_lifetime_blocks
    ):
        raise ValueError("base submission lifetime is outside its policy")
    if not 0 <= current_block - snapshot.block <= policy.maximum_snapshot_age_blocks:
        raise ValueError("registration snapshot is stale or from the future")
    if sub.model_bundle is not None:
        validate_bundle_policy(sub.model_bundle, policy)
    matches = [r.uid for r in snapshot.registrations if identity(r.hotkey) == identity(sub.hotkey)]
    if len(matches) != 1 or matches[0] >= policy.maximum_uids:
        raise ValueError("hotkey is not registered in this policy's UID range")
    return CohortParticipantAdmission(
        schema="umi-cohort-participant-admission/1",
        cohort_sha256=view.state.cohort_sha256,
        recovery_tip_sha256=view.state.tip_sha256,
        consent_sha256=digest(body),
        submission_sha256=digest(sub),
        snapshot_sha256=digest(snapshot),
        admitted_at_block=current_block,
        uid=matches[0],
    )


def verify_participant_admission(
    attested: AttestedCohortParticipantAdmission,
    signed: SignedSubmission,
    consent: SignedCohortParticipationConsent,
    history: CohortRecoveryHistory,
    policy: CompetitionPolicy,
    snapshot: RegistrationSnapshot,
    *,
    expected_tip_sha256: str,
    current_block: int,
) -> CohortParticipantAdmission:
    """Replay historical intake after closure without admitting a new participant."""
    attested = AttestedCohortParticipantAdmission.model_validate_json(
        canonical_json_bytes(attested)
    )
    view = verify_cohort_history(
        history, policy, expected_tip_sha256=expected_tip_sha256, current_block=current_block
    )
    if view.state.phase == "revoked":
        raise ValueError("cohort recovery has been revoked")
    admission = attested.admission
    if admission.admitted_at_block > current_block:
        raise ValueError("participant admission is ahead of the owned finalized observation")
    tips = [digest(history.genesis)] + [digest(t.transition) for t in history.transitions]
    if admission.recovery_tip_sha256 not in tips:
        raise ValueError("participant admission does not belong to the selected cohort history")
    index = tips.index(admission.recovery_tip_sha256)
    if index < len(history.transitions) and (
        admission.admitted_at_block > history.transitions[index].transition.observed_at_block
    ):
        raise ValueError("participant admission uses a superseded schedule observation")
    prefix = history.model_copy(update={"transitions": history.transitions[:index]})
    expected = admit_recovery_participant(
        signed,
        consent,
        prefix,
        policy,
        snapshot,
        expected_tip_sha256=admission.recovery_tip_sha256,
        current_block=admission.admitted_at_block,
    )
    if admission != expected:
        raise ValueError("participant admission differs from consent or registration evidence")
    verify_recovery_quorum(admission, attested.signatures, policy)
    return admission
