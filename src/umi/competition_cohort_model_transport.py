"""Authenticated effective model transport without changing the signed plan.

This pure boundary does not obtain current finality, reserve an owner journal or
authorize migration. Callers must select the authoritative history tip and the
owned finalized height. Retained older prefixes retain their original meaning.
"""

from .competition_cohort_direct_model_upload import SignedDirectModelUploadReservation
from .competition_cohort_history import CohortRecoveryHistory, verify_cohort_history
from .competition_cohort_recovery import (
    CohortModelDeliveryAdoption,
    CohortRecoveryTransition,
    ModelDeliveryProfile,
    cohort_model_delivery,
    propose_recovery_transition,
)
from .open_competition import CompetitionPolicy, digest
from .protocol import canonical_json_bytes


def authenticated_model_delivery(
    history: CohortRecoveryHistory,
    policy: CompetitionPolicy,
    *,
    expected_tip_sha256: str,
    current_block: int,
    at_block: int | None = None,
) -> ModelDeliveryProfile:
    """Resolve transport from a verified prefix, optionally at an earlier block.

    The entire selected history is authenticated before resolving an old
    acceptance. A later amendment cannot retrospectively authorize an earlier
    direct artifact; legacy acceptances keep their original provenance.
    """
    history = CohortRecoveryHistory.model_validate_json(canonical_json_bytes(history))
    state = verify_cohort_history(
        history,
        policy,
        expected_tip_sha256=expected_tip_sha256,
        current_block=current_block,
    ).state
    if at_block is not None:
        if (
            type(at_block) is not int
            or not history.genesis.admitted_at_block <= at_block <= current_block
        ):
            raise ValueError("model delivery historical block is outside the verified interval")
        adopted = next(
            (
                signed.transition.model_delivery_adoption
                for signed in history.transitions
                if signed.transition.model_delivery_adoption is not None
                and signed.transition.observed_at_block <= at_block
            ),
            None,
        )
    else:
        adopted = state.model_delivery_adoption
    if adopted is not None:
        return adopted.delivery
    return cohort_model_delivery(history.plan)


def verify_direct_model_transport(
    artifact, history, policy, *, accepted_at_block, current_block=None
):
    """Check retained direct provenance against the transport selected at acceptance.

    This neither selects current owner history nor authorizes new reservations.
    The caller owns that boundary and any pending-adoption fences. Historical
    replay authenticates the complete selected prefix without claiming fresh
    finality; a live caller can additionally supply its owned current block.
    Legacy /1 acceptances deliberately do not use this direct-only predicate.
    """
    artifact = SignedDirectModelUploadReservation.model_validate_json(
        canonical_json_bytes(artifact)
    )
    selected = history.transitions[-1].transition if history.transitions else history.genesis
    if current_block is None:
        tip_block = (
            selected.observed_at_block if history.transitions else selected.admitted_at_block
        )
        current_block = max(tip_block, accepted_at_block)
    delivery = authenticated_model_delivery(
        history,
        policy,
        expected_tip_sha256=digest(selected),
        current_block=current_block,
        at_block=accepted_at_block,
    )
    if (
        artifact.reservation.cohort_sha256 != digest(history.plan)
        or delivery.mechanism != "direct_r2_multipart_v1"
        or artifact.reservation.payload.part_size_bytes != delivery.part_size_bytes
    ):
        raise ValueError("direct model acceptance lacks its authenticated transport profile")


def prepare_model_delivery_adoption(
    history: CohortRecoveryHistory,
    policy: CompetitionPolicy,
    *,
    expected_tip_sha256: str,
    current_block: int,
    delivery: ModelDeliveryProfile,
    legacy_inventory_sha256: str,
    preservation_inventory_sha256: str,
) -> CohortRecoveryTransition:
    """Prepare exact unsigned bytes after native inventory/restore verification.

    The owner must fence both intake and legacy upload reservations before
    selecting these inventories, then reserve the exact proposal atomically.
    A digest supplied here does not establish those conditions. Independent
    reviewers must establish them against the original retained inputs before
    using their normal predecessor non-equivocation signing slot.
    """
    history = CohortRecoveryHistory.model_validate_json(canonical_json_bytes(history))
    state = verify_cohort_history(
        history,
        policy,
        expected_tip_sha256=expected_tip_sha256,
        current_block=current_block,
    ).state
    adoption = CohortModelDeliveryAdoption(
        schema="umi-cohort-model-delivery-adoption/1",
        original_plan=history.plan,
        delivery=delivery,
        legacy_inventory_sha256=legacy_inventory_sha256,
        preservation_inventory_sha256=preservation_inventory_sha256,
    )
    return propose_recovery_transition(
        state,
        history.authority.authority,
        operation="adopt_model_delivery",
        observed_at_block=current_block,
        evidence_sha256=digest(adoption),
        model_delivery_adoption=adoption,
    )
