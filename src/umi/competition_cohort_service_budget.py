"""Paid-work allowances derived from the selected policy/runtime review profile.

These are execution allowances, never ETAs or replacements for signed request
clocks. Legacy hosts retain their serialized selections and existing behavior.
"""

from dataclasses import dataclass

from .competition_cohort_review_budget import (
    PhaseReviewBudget,
    check_review_seconds,
    validate_phase_export_path,
)


@dataclass(frozen=True)
class ServiceExecutionBudget:
    export_seconds: int
    read_seconds: int
    call_seconds: int
    vote_seconds: int
    exchange_seconds: int
    dispatch_seconds: int  # Complete owned origin proof, not a miner HTTP timeout.

    def __post_init__(self):
        for value in vars(self).values():
            check_review_seconds(value)

    def effective(self):
        return dict(vars(self))


def service_execution_budget(
    profile: PhaseReviewBudget | None,
    *,
    read_seconds=2400,
    signing_seconds=None,
    vote_seconds=2400,
    operation_seconds=2400,
) -> ServiceExecutionBudget:
    if signing_seconds is None:
        signing_seconds = 300 if profile is None else profile.signing_seconds
    for value in (read_seconds, signing_seconds, vote_seconds, operation_seconds):
        check_review_seconds(value)
    if profile is None:
        return ServiceExecutionBudget(
            operation_seconds,
            read_seconds,
            read_seconds,
            vote_seconds,
            vote_seconds,
            operation_seconds,
        )
    if signing_seconds > profile.signing_seconds:
        raise ValueError("service review budget shortens the selected signing allowance")
    export = max(operation_seconds, profile.export_seconds)
    read = max(read_seconds, profile.export_exchange_seconds)
    # The native reviewer's generic owned call wraps fetch PLUS response
    # verification, archive replay or current finalized authority. It must not
    # truncate the underlying HTTP reader's complete selected exchange.
    call = max(read + profile.replay_seconds, profile.authority_seconds)
    # A fresh retry vote has eleven serial owned calls: two history, two
    # assignment, archive read, registration replay, window capture, two current
    # observations and two rounds. Seven local validation/history journal
    # sections can also replay native evidence. Both vote kinds share the
    # conservative retry allowance; completed retained votes return early.
    vote = max(
        vote_seconds,
        11 * call
        + 7 * profile.replay_seconds
        + profile.signing_seconds
        + profile.vote_queue_seconds,
    )
    return ServiceExecutionBudget(
        export,
        read,
        call,
        vote,
        vote + profile.vote_queue_seconds + profile.transport_seconds,
        max(operation_seconds, 11 * call + 7 * profile.replay_seconds),
    )


def validate_service_execution_path(
    *,
    owner,
    owner_budget,
    reviewer,
    peer,
    reviewer_budget,
    peer_budget,
    owner_proxy_seconds=None,
    vote_proxy_seconds=None,
    direct_owner=False,
    direct_vote=False,
):
    """Compare actual selected local overrides and every managed private hop."""
    validate_phase_export_path(
        owner=owner,
        reviewer=reviewer,
        owner_proxy_seconds=owner_proxy_seconds,
        direct_owner=direct_owner,
    )
    if reviewer_budget.read_seconds < (
        owner.export_queue_slots * owner_budget.export_seconds + owner.transport_seconds
    ):
        raise ValueError("service reviewer shortens the actual owner export allowance")
    if (
        peer.policy_sha256 != reviewer.policy_sha256
        or peer.evaluation_runtime_sha256 != reviewer.evaluation_runtime_sha256
        or peer.maximum_aggregate_evidence_bytes != reviewer.maximum_aggregate_evidence_bytes
    ):
        raise ValueError("service review path changes policy, runtime or capacity")
    if peer_budget.exchange_seconds < reviewer_budget.exchange_seconds:
        raise ValueError("service peer shortens the complete reviewer allowance")
    if not direct_owner and owner_proxy_seconds < reviewer_budget.read_seconds:
        raise ValueError("managed owner proxy shortens the service read allowance")
    if direct_vote:
        if vote_proxy_seconds is not None:
            raise ValueError("direct service path cannot also select a managed proxy")
    else:
        check_review_seconds(vote_proxy_seconds)
        if vote_proxy_seconds < peer_budget.exchange_seconds:
            raise ValueError("managed vote proxy shortens the complete service allowance")


def service_review_capacity_requirement(
    catalog_work_counts,
    *,
    maximum_claims_per_catalog,
    attempts_per_claim,
):
    """Provision both request and retry intents across one reviewer's full scope.

    Attempts are an explicit provisioning assumption, never a protocol cutoff.
    Call with all selected catalogs sharing a transport/reviewer journal, across
    every configured cohort. Retained exact retries reuse their existing intent.
    """
    if type(maximum_claims_per_catalog) is not int or not 1 <= maximum_claims_per_catalog <= 8192:
        raise ValueError("service intake claim capacity is outside bounds")
    check_review_seconds(attempts_per_claim)
    counts = tuple(catalog_work_counts)
    if not counts or any(type(count) is not int or not 1 <= count <= 8192 for count in counts):
        raise ValueError("service catalog work counts are outside bounds")
    claims = sum(min(count, maximum_claims_per_catalog) for count in counts)
    required = 2 * claims * attempts_per_claim
    check_review_seconds(required)
    return {
        "catalogs": len(counts),
        "admissible_claims": claims,
        "provisioned_attempts_per_claim": attempts_per_claim,
        "required_intents": required,
        "basis": "request_and_retry_intents_for_all_selected_catalogs_and_provisioned_attempts",
        "retry_cutoff_authorized": False,
    }


def validate_service_review_capacity(*, maximum_votes, requirement):
    check_review_seconds(maximum_votes)
    if maximum_votes < requirement["required_intents"]:
        raise ValueError(
            "service reviewer capacity omits admitted work or provisioned retry intents"
        )
