"""Select a bounded request tail from original native owner inventories."""

import json
import logging
import time

from .competition_cohort_recovery import cohort_request_tail_rule
from .competition_cohort_request_rule import authenticated_request_tail_rule
from .competition_cohort_request_tail import (
    MINIMUM_REQUEST_OPEN_MS,
    RequestTailObservation,
    original_request_miners,
)
from .competition_cohort_service_seal import sealed_service_assignments
from .competition_execution import execution_boundary
from .open_competition import digest, identity

_LOG = logging.getLogger("umi.competition.progress")


def select_request_tail(
    *,
    plan,
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
    history=None,
):
    """Only explicit owner absence qualifies; proof or storage failures propagate.

    The caller caches these exact terminal reads for the closure builders. New
    arrivals are considered on a later observation; existing completions are
    never discarded merely because they arrived after the first twelve hours.
    """
    if opened is None:
        return None
    if history is not None and history.plan != plan:
        raise ValueError("request tail history differs from its original plan")
    rule = (
        cohort_request_tail_rule(plan)
        if history is None
        else authenticated_request_tail_rule(history, policy)
    )
    timestamp = capture.provenance.get("timestamp_ms")
    if type(timestamp) is not int or type(opened.timestamp_ms) is not int:
        raise ValueError("request tail selection requires native timestamps")
    if timestamp - opened.timestamp_ms < MINIMUM_REQUEST_OPEN_MS:
        return None
    started = time.monotonic()
    members, models = {}, set()
    for participant in roster.participants:
        submission = participant.record.request.signed_submission.submission
        key = digest(submission)
        members[key] = identity(submission.hotkey)
        if submission.track == "model":
            models.add(key)
    selected = {digest(o.order.submission.submission): o for o in orders}
    if len(selected) != len(orders) or selected.keys() - members.keys():
        raise ValueError("request tail inventory repeats or substitutes an original order")
    unfinished, unfinished_models = set(), set()
    for key, miner in members.items():
        order = selected.get(key)
        if order is None:
            unfinished.add(miner)
            if key in models:
                unfinished_models.add(key)
        else:
            # Evaluate every original evaluator; no short-circuit hides a bad
            # retained terminal behind another evaluator's explicit absence.
            missing = [terminals(order, evaluator) is None for evaluator in order.order.evaluators]
            if any(missing):
                unfinished.add(miner)
                if key in models:
                    unfinished_models.add(key)
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
    if plan.sequence > 5 and unfinished_models:
        # Public bundles are already in our custody. Central execution or
        # certification backlog must never turn into an absent miner and lose
        # that model's evaluation at the endpoint-response cutoff. This only
        # defers a new owner selection; historical certified tails and their
        # replay rules remain unchanged, including all original C5 evidence.
        _LOG.info(
            json.dumps(
                dict(
                    schema="umi-request-tail-readiness/1",
                    stage="request_tail_model_readiness",
                    status="waiting",
                    completed=1,
                    total=1,
                    unit="readiness_checks",
                    elapsed_seconds=time.monotonic() - started,
                    eta_seconds=0,
                    eta_basis="readiness_check_complete_model_execution_forecast_separate",
                    eta_scope="readiness_check_only_not_model_scoring",
                    completed_model_submissions=len(models) - len(unfinished_models),
                    selected_model_submissions=len(models),
                    pending_model_submissions=len(unfinished_models),
                    reason="central_model_evaluation_or_certification_pending",
                    stalled_or_retrying=False,
                    certification_authority=False,
                ),
                separators=(",", ":"),
            )
        )
        return None
    if rule == "original_request_12h_at_most_tenth/1" and len(unfinished) * 10 > len(original):
        return None
    if rule == "original_request_12h_with_completed_miner/1" and len(unfinished) == len(original):
        return None
    return RequestTailObservation(
        schema="umi-cohort-request-tail-observation/1",
        rule=rule,
        opened_observation=opened.original,
        opened_timestamp_ms=opened.timestamp_ms,
        observation=execution_boundary(capture),
        observed_timestamp_ms=timestamp,
        original_hotkeys=original,
        unfinished_hotkeys=tuple(sorted(unfinished)),
    )
