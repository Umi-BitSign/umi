"""Authenticated direct continuation of an original unfinished legacy upload.

The existing quorum-signed adoption commits the entire immutable census. Its
original request may acquire a new, genuinely miner-signed direct declaration;
this proof grants no admission, preservation, deletion or capacity credit.
"""

from typing import Literal

from pydantic import Field

from .competition_cohort_history import verify_cohort_history
from .competition_cohort_legacy_model_storage import (
    MAX_INVENTORY_BYTES,
    LegacyModelStorageInventory,
)
from .competition_cohort_model_transport_selection import (
    CommittedModelDeliveryHistory,
    committed_model_delivery_selection,
)
from .competition_cohort_participation import CohortParticipationRequest
from .competition_cohort_recovery import ModelDeliveryProfile
from .open_competition import CompetitionPolicy, digest
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes, sha256_hex

# The original inventory and its signed history are metadata, never model bytes.
MAX_CONTINUATION_BYTES = 2 * MAX_INVENTORY_BYTES


class LegacyModelUploadContinuation(StrictProtocolModel):
    schema_: Literal["umi-legacy-model-upload-continuation/1"] = Field(alias="schema")
    request_sha256: Hex32
    selection: CommittedModelDeliveryHistory
    legacy_inventory: LegacyModelStorageInventory


def owned_upload_continuation(intake, sources, request):
    """Read current committed authority without changing any frozen original."""
    cohort, key = request.consent.consent.cohort_sha256, digest(request)
    selected = None if sources is None else sources.authenticated.get(cohort)
    if selected is None:
        return None
    entry = next((e for e in selected.legacy.entries if e.request_sha256 == key), None)
    if entry is None:
        raise OSError("retained legacy upload is missing from its selected census")
    if entry.admission_raw_sha256 is not None:
        return None
    with intake._connection(prefer_history=True) as (_, store):
        value = LegacyModelUploadContinuation(
            schema="umi-legacy-model-upload-continuation/1",
            request_sha256=key,
            selection=committed_model_delivery_selection(store, cohort, intake.policy),
            legacy_inventory=selected.legacy,
        )
        verify_upload_continuation(value, request, intake.policy)
    if len(canonical_json_bytes(value)) > MAX_CONTINUATION_BYTES:
        raise OSError("legacy continuation metadata exceeds its supported delivery bound")
    return value


def verify_upload_continuation(
    value: LegacyModelUploadContinuation,
    request: CohortParticipationRequest,
    policy: CompetitionPolicy,
) -> ModelDeliveryProfile:
    """Authenticate one unchanged request without extending the frozen census."""
    value = LegacyModelUploadContinuation.model_validate_json(canonical_json_bytes(value))
    # Revalidate both miner signatures and the consent's exact submission/hotkey
    # before using this proof as a reason to sign a new transport declaration.
    request = CohortParticipationRequest.model_validate_json(canonical_json_bytes(request))
    selection, legacy = value.selection, value.legacy_inventory
    history, sub, consent = (
        selection.history,
        request.signed_submission.submission,
        request.consent.consent,
    )
    state = verify_cohort_history(
        history,
        policy,
        expected_tip_sha256=selection.committed_tip_sha256,
        current_block=selection.observed_at_block,
    ).state
    adoption = state.model_delivery_adoption
    if (
        value.request_sha256 != digest(request)
        or digest(history.plan) != consent.cohort_sha256
        or state.authority_sha256 != consent.authority_sha256
        or sub.policy_sha256 != digest(policy)
        or sub.track != "model"
        or not history.authority.authority.issued_at_block
        <= consent.signed_at_block
        <= legacy.captured_at_block
        or adoption is None
        or adoption.delivery.mechanism != "direct_r2_multipart_v1"
        or digest(legacy) != adoption.legacy_inventory_sha256
    ):
        raise ValueError("legacy continuation differs from authenticated transport adoption")
    transition = next(
        signed.transition
        for signed in history.transitions
        if signed.transition.model_delivery_adoption == adoption
    )
    if (
        legacy.cohort_sha256 != digest(history.plan)
        or legacy.policy_sha256 != digest(policy)
        or legacy.authority_sha256 != digest(history.authority.authority)
        or legacy.predecessor_sha256 != transition.predecessor_sha256
        or not history.genesis.admitted_at_block
        <= legacy.captured_at_block
        <= transition.observed_at_block
    ):
        raise ValueError("legacy continuation changes its original census binding")
    entry = next(
        (entry for entry in legacy.entries if entry.request_sha256 == digest(request)), None
    )
    if (
        entry is None
        or entry.request_raw_sha256 != sha256_hex(canonical_json_bytes(request))
        or entry.model_sha256 != sub.model_revision
        or any(
            value is not None
            for value in (
                entry.admission_raw_sha256,
                entry.intent_raw_sha256,
                entry.certificate_raw_sha256,
            )
        )
    ):
        raise ValueError("legacy continuation requires its exact uncertified original")
    return adoption.delivery
