"""Select a bounded request tail from original native owner inventories."""

from .competition_cohort_request_tail import (
    MINIMUM_REQUEST_OPEN_MS,
    RequestTailObservation,
    original_request_miners,
)
from .competition_cohort_service_seal import sealed_service_assignments
from .competition_execution import execution_boundary
from .open_competition import digest, identity


def select_request_tail(
    *,
    roster,
    orders,
    terminals,
    catalogs,
    seals,
    service_terminals,
    objects,
    policy,
    opened,
    capture,
    accepted_assignments=None,
):
    """Only explicit owner absence qualifies; proof or storage failures propagate.

    The caller caches these exact terminal reads for the closure builders. New
    arrivals are considered on a later observation; existing completions are
    never discarded merely because they arrived after the first twelve hours.
    """
    if opened is None:
        return None
    timestamp = capture.provenance.get("timestamp_ms")
    if type(timestamp) is not int or type(opened.timestamp_ms) is not int:
        raise ValueError("request tail selection requires native timestamps")
    if timestamp - opened.timestamp_ms < MINIMUM_REQUEST_OPEN_MS:
        return None
    members = {
        digest(p.record.request.signed_submission.submission): identity(
            p.record.request.signed_submission.submission.hotkey
        )
        for p in roster.participants
    }
    selected = {digest(o.order.submission.submission): o for o in orders}
    if len(selected) != len(orders) or selected.keys() - members.keys():
        raise ValueError("request tail inventory repeats or substitutes an original order")
    unfinished = set()
    for key, miner in members.items():
        order = selected.get(key)
        if order is None:
            unfinished.add(miner)
        else:
            # Evaluate every original evaluator; no short-circuit hides a bad
            # retained terminal behind another evaluator's explicit absence.
            missing = [terminals(order, evaluator) is None for evaluator in order.order.evaluators]
            if any(missing):
                unfinished.add(miner)
    assignments = (
        tuple(accepted_assignments)
        if accepted_assignments is not None
        else tuple(
            assignment
            for catalog, seal in zip(catalogs, seals, strict=True)
            for assignment in sealed_service_assignments(
                seal, objects, policy, catalog=catalog, round_=roster.round
            )
        )
    )
    for assignment in assignments:
        if service_terminals(assignment) is None:
            unfinished.add(identity(assignment.admission.submission.submission.hotkey))
    original = original_request_miners(roster, assignments)
    if len(unfinished) * 10 > len(original):
        return None
    return RequestTailObservation(
        schema="umi-cohort-request-tail-observation/1",
        opened_observation=opened.original,
        opened_timestamp_ms=opened.timestamp_ms,
        observation=execution_boundary(capture),
        observed_timestamp_ms=timestamp,
        original_hotkeys=original,
        unfinished_hotkeys=tuple(sorted(unfinished)),
    )
