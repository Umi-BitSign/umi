"""Compare actual private phase-review selections before changing services."""

from .competition_cohort_admission_host import AdmissionOwnerConfig
from .competition_cohort_review_budget import (
    checked_budget,
    validate_phase_export_path,
    validate_phase_review_path,
)
from .competition_cohort_review_config import PhaseReviewServiceConfig
from .competition_cohort_review_origin import private_review_origin
from .open_competition import identity
from .protocol import canonical_json_bytes


def _hosts(owner, reviewer):
    owner = AdmissionOwnerConfig.model_validate_json(canonical_json_bytes(owner))
    reviewer = PhaseReviewServiceConfig.model_validate_json(canonical_json_bytes(reviewer))
    owner.check_policy(reviewer.policy)
    if identity(owner.owner_hotkey) != identity(reviewer.owner_hotkey):
        raise ValueError("phase review path changes owner identity")
    if owner.request_evidence_bytes != reviewer.request_evidence_bytes:
        raise ValueError("phase review path changes selected aggregate evidence capacity")
    selections = tuple(
        checked_budget(value, reviewer.policy, owner.request_evidence_bytes)
        for value in (owner.phase_review_budget, reviewer.phase_review_budget)
    )
    if any(value is None for value in selections):
        raise ValueError("complete phase review path requires explicit budgets at every host")
    return owner, reviewer, *selections


def _direct_listener(origin, host):
    url = private_review_origin(origin)
    direct = url.scheme == "http"
    # HTTPX normalizes an explicitly written default :80 to port=None.
    port = url.port if url.port is not None else 80 if direct else 443
    if direct and (url.host, port) != (host.listen_host, host.listen_port):
        raise ValueError("direct phase review origin differs from selected loopback listener")
    return direct


def validate_reviewer_export_path(
    owner: AdmissionOwnerConfig,
    reviewer: PhaseReviewServiceConfig,
    *,
    owner_proxy_seconds: int | None = None,
) -> dict:
    """Check an available reviewer's owner path without adding a vote peer."""
    owner, reviewer, selected_owner, selected_reviewer = _hosts(owner, reviewer)
    direct_owner = _direct_listener(reviewer.owner_origin, owner)
    validate_phase_export_path(
        owner=selected_owner,
        reviewer=selected_reviewer,
        owner_proxy_seconds=owner_proxy_seconds,
        direct_owner=direct_owner,
    )
    return {
        "status": "phase_review_export_path_configuration_valid",
        "runtime_qualified": False,
        "vote_path_checked": False,
        "owner_transport": "direct_loopback" if direct_owner else "managed_https",
        "owner": selected_owner.effective(),
        "reviewer": selected_reviewer.effective(),
    }


def validate_selected_phase_review_path(
    owner: AdmissionOwnerConfig,
    reviewer: PhaseReviewServiceConfig,
    *,
    owner_proxy_seconds: int | None = None,
    vote_proxy_seconds: int | None = None,
) -> dict:
    """Validate one selected owner/reviewer/peer path without opening state.

    Direct HTTP must match the actual configured loopback listeners. HTTPS
    requires explicit managed-proxy allowances verified by the deployment
    adapter; this pure comparison cannot observe a running proxy or certify
    throughput, process placement, or peak host resources.
    """
    owner, reviewer, selected_owner, selected_reviewer = _hosts(owner, reviewer)
    peers = [p for p in owner.reviewers if identity(p.signer) == identity(reviewer.signing.signer)]
    if len(peers) != 1:
        raise ValueError("phase review path changes selected reviewer identity")
    peer = peers[0]
    selected_peer = checked_budget(
        peer.phase_review_budget, reviewer.policy, owner.request_evidence_bytes
    )
    if selected_peer is None:
        raise ValueError("complete phase review path requires an explicit peer budget")
    direct_owner = _direct_listener(reviewer.owner_origin, owner)
    direct_vote = _direct_listener(peer.origin, reviewer)
    validate_phase_review_path(
        owner=selected_owner,
        reviewer=selected_reviewer,
        peer=selected_peer,
        owner_proxy_seconds=owner_proxy_seconds,
        vote_proxy_seconds=vote_proxy_seconds,
        direct_owner=direct_owner,
        direct_vote=direct_vote,
    )
    return {
        "status": "phase_review_path_configuration_valid",
        "runtime_qualified": False,
        "policy_sha256": selected_owner.policy_sha256,
        "evaluation_runtime_sha256": selected_owner.evaluation_runtime_sha256,
        "maximum_aggregate_evidence_bytes": owner.request_evidence_bytes,
        "owner_transport": "direct_loopback" if direct_owner else "managed_https",
        "vote_transport": "direct_loopback" if direct_vote else "managed_https",
        "owner": selected_owner.effective(),
        "reviewer": selected_reviewer.effective(),
        "peer": selected_peer.effective(),
    }
