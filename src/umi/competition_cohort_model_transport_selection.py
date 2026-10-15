"""Portable boot selections prepared from committed native transport history.

The root-selected configuration attests where a history was obtained, not new
cohort authority. Its complete signed history independently proves the one-way
transport amendment. Preparing a selection requires the owner's native snapshot;
an unsigned or signed-but-pending intent is not a committed publication.
"""

from typing import Annotated, Literal

from pydantic import Field

from .competition_cohort_history import CohortRecoveryHistory, verify_cohort_history
from .competition_cohort_model_transport import authenticated_model_delivery
from .competition_cohort_recovery import cohort_model_delivery
from .open_competition import digest
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes


class CommittedModelDeliveryHistory(StrictProtocolModel):
    schema_: Literal["umi-committed-model-delivery-history/1"] = Field(alias="schema")
    history: CohortRecoveryHistory
    committed_tip_sha256: Hex32
    observed_at_block: Annotated[int, Field(ge=0, le=2**53 - 1)]


ModelDeliveryAdoptionSelections = Annotated[
    tuple[CommittedModelDeliveryHistory, ...], Field(max_length=512)
]


def committed_model_delivery_selection(store, cohort, policy):
    """Read the actual owner snapshot without reserving, signing or publishing.

    Keep this result only in the root-controlled deployment selection. A remote
    caller cannot use this record to replace the authoritative intake history.
    """
    with store.read_snapshot():
        state, pending = store.status(cohort)
        history = store.published_history(cohort)
    if pending is not None:
        raise ValueError("model transport selection awaits the committed owner decision")
    view = verify_cohort_history(
        history,
        policy,
        expected_tip_sha256=state.tip_sha256,
        current_block=state.observed_at_block,
    )
    if view.state != state or state.model_delivery_adoption is None:
        raise ValueError("model transport selection requires published committed adoption")
    return CommittedModelDeliveryHistory(
        schema="umi-committed-model-delivery-history/1",
        history=history,
        committed_tip_sha256=state.tip_sha256,
        observed_at_block=state.observed_at_block,
    )


def effective_model_deliveries(series, policy, selections=()):
    """Bind every amendment to the unchanged plan and exact original authority."""
    plans = {digest(plan): plan for plan in series.cohorts}
    selected = {}
    for raw in selections:
        value = CommittedModelDeliveryHistory.model_validate_json(canonical_json_bytes(raw))
        history = value.history
        cohort = digest(history.plan)
        if (
            cohort not in plans
            or cohort in selected
            or canonical_json_bytes(history.plan) != canonical_json_bytes(plans[cohort])
            or canonical_json_bytes(history.authority) != canonical_json_bytes(series.recovery)
            or (
                history.plan.eligible_tracks is not None
                and "model" not in history.plan.eligible_tracks
            )
            or not history.transitions
            or not any(
                t.transition.model_delivery_adoption is not None for t in history.transitions
            )
        ):
            raise ValueError("model transport selection differs from the original series authority")
        delivery = authenticated_model_delivery(
            history,
            policy,
            expected_tip_sha256=value.committed_tip_sha256,
            current_block=value.observed_at_block,
        )
        if delivery.mechanism != "direct_r2_multipart_v1":
            raise ValueError("model transport selection has no committed direct adoption")
        selected[cohort] = delivery
    if list(selected) != sorted(selected):
        raise ValueError("model transport selections must be unique and cohort-sorted")
    return {
        cohort: selected.get(cohort, cohort_model_delivery(plan))
        for cohort, plan in plans.items()
        if plan.eligible_tracks is None or "model" in plan.eligible_tracks
    }


def requires_direct_model_review(series, policy, selections=()):
    return any(
        profile.mechanism == "direct_r2_multipart_v1"
        for profile in effective_model_deliveries(series, policy, selections).values()
    )


def selected_direct_model_review(config):
    """Recheck authenticated selection before constructing credentialed consumers."""
    required = requires_direct_model_review(
        config.series, config.policy, config.model_delivery_adoptions
    )
    if required != (config.direct_model_review is not None):
        raise ValueError("direct model reviewer differs from authenticated transport selection")
    return config.direct_model_review
