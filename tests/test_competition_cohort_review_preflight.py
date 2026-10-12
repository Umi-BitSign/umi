"""Compare concrete selected hosts and actual direct/managed review routes."""

from types import SimpleNamespace

import pytest

from umi.competition_cohort_admission_host import AdmissionOwnerConfig
from umi.competition_cohort_review_budget import validate_phase_review_path
from umi.competition_cohort_review_config import PhaseReviewServiceConfig
from umi.competition_cohort_review_preflight import (
    _direct_listener,
    validate_reviewer_export_path,
    validate_selected_phase_review_path,
)
from umi.open_competition import identity
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_review_budget import chain as chain
from .test_competition_cohort_review_budget import chain_config as chain_config
from .test_competition_cohort_review_budget import control as control
from .test_competition_cohort_review_budget import inputs as inputs
from .test_competition_cohort_review_budget import owner_config, profile
from .test_competition_cohort_review_budget import policy as inherited_policy
from .test_competition_cohort_review_budget import selected as selected
from .test_competition_cohort_review_budget import series_case as series_case

base_policy = inherited_policy


@pytest.fixture
def policy(base_policy):
    # An available evaluator need not be selected in the owner's active quorum.
    return base_policy.model_copy(update={"required_evaluator_groups": 1})


@pytest.fixture
def hosts(selected, tmp_path):
    budget = profile(selected.config.policy)
    owner = owner_config(selected, tmp_path, budget)
    peer = owner.reviewers[0]
    other = next(
        e for e in selected.config.policy.evaluators if identity(e.hotkey) != identity(peer.signer)
    )
    peer = peer.model_copy(update={"origin": f"http://127.0.0.1:{selected.config.listen_port}"})
    other_peer = peer.model_copy(
        update={"signer": other.hotkey, "token_file": str(tmp_path / "other-token")}
    )
    owner = AdmissionOwnerConfig.model_validate_json(
        canonical_json_bytes(owner.model_copy(update={"reviewers": (peer, other_peer)}))
    )
    reviewer = PhaseReviewServiceConfig.model_validate_json(
        canonical_json_bytes(
            selected.config.model_copy(
                update={
                    "phase_review_budget": budget,
                    "maximum_aggregate_evidence_bytes": owner.request_evidence_bytes,
                    "owner_origin": f"http://127.0.0.1:{owner.listen_port}",
                }
            )
        )
    )
    return owner, reviewer


def test_exact_direct_selected_path_uses_complete_budget_without_proxy_claim(hosts):
    owner, reviewer = hosts
    report = validate_selected_phase_review_path(owner, reviewer)
    assert report["status"] == "phase_review_path_configuration_valid"
    assert report["owner_transport"] == report["vote_transport"] == "direct_loopback"
    assert report["runtime_qualified"] is False
    assert report["maximum_aggregate_evidence_bytes"] == 4 * 1024**3
    assert report["owner"] == report["reviewer"] == report["peer"]


@pytest.mark.parametrize("side", ["owner", "vote"])
def test_direct_path_must_match_selected_listener(hosts, side):
    owner, reviewer = hosts
    if side == "owner":
        reviewer = reviewer.model_copy(update={"owner_origin": "http://127.0.0.1:12345"})
    else:
        peer, other = owner.reviewers
        owner = owner.model_copy(
            update={
                "reviewers": (peer.model_copy(update={"origin": "http://127.0.0.1:12345"}), other)
            }
        )
    with pytest.raises(ValueError, match="listener"):
        validate_selected_phase_review_path(owner, reviewer)


def test_https_path_requires_explicit_non_shortening_proxy_allowances(hosts):
    owner, reviewer = hosts
    peer, other = owner.reviewers
    owner = owner.model_copy(
        update={
            "reviewers": (peer.model_copy(update={"origin": "https://reviewer.example"}), other)
        }
    )
    reviewer = reviewer.model_copy(update={"owner_origin": "https://owner.example"})
    budget = reviewer.phase_review_budget
    limits = dict(
        owner_proxy_seconds=budget.export_exchange_seconds,
        vote_proxy_seconds=budget.vote_exchange_seconds("decision"),
    )
    report = validate_selected_phase_review_path(owner, reviewer, **limits)
    assert report["owner_transport"] == report["vote_transport"] == "managed_https"
    for key, value in limits.items():
        for shorter in (None, value - 1):
            with pytest.raises(ValueError):
                validate_selected_phase_review_path(owner, reviewer, **(limits | {key: shorter}))


def test_preflight_rejects_missing_profile_capacity_and_identity_mismatch(hosts):
    owner, reviewer = hosts
    for changes in (
        {"phase_review_budget": None},
        {"maximum_aggregate_evidence_bytes": 1024**3},
        {"owner_hotkey": reviewer.signing.signer},
    ):
        with pytest.raises(ValueError):
            validate_selected_phase_review_path(owner, reviewer.model_copy(update=changes))


@pytest.mark.parametrize("hop", ["export", "peer", "pin"])
def test_pure_comparison_rejects_shorter_selected_hops(policy, hop):
    budget = profile(policy)
    values = dict(owner=budget, reviewer=budget, peer=budget, direct_owner=True, direct_vote=True)
    if hop == "export":
        values["reviewer"] = profile(policy, export_seconds=3999)
    elif hop == "peer":
        values["peer"] = profile(policy, replay_seconds=4999)
    else:
        values["peer"] = profile(policy, policy_sha256="12" * 32)
    with pytest.raises(ValueError):
        validate_phase_review_path(**values)


def test_direct_path_cannot_also_claim_a_managed_proxy(hosts):
    owner, reviewer = hosts
    with pytest.raises(ValueError, match="managed proxy"):
        validate_selected_phase_review_path(owner, reviewer, owner_proxy_seconds=100000)


@pytest.mark.parametrize("host", ["127.0.0.1", "::1"])
def test_explicit_default_http_port_compares_effective_listener_port(host):
    origin = f"http://[{host}]:80" if ":" in host else f"http://{host}:80"
    assert _direct_listener(origin, SimpleNamespace(listen_host=host, listen_port=80))
    with pytest.raises(ValueError, match="listener"):
        _direct_listener(origin, SimpleNamespace(listen_host=host, listen_port=8080))


def test_unselected_reviewer_export_path_does_not_add_or_claim_a_vote_peer(hosts):
    owner, reviewer = hosts
    _, other = owner.reviewers
    owner = owner.model_copy(update={"reviewers": (other,)})
    original = canonical_json_bytes(owner)
    report = validate_reviewer_export_path(owner, reviewer)
    assert report["status"] == "phase_review_export_path_configuration_valid"
    assert report["vote_path_checked"] is report["runtime_qualified"] is False
    assert canonical_json_bytes(owner) == original
    with pytest.raises(ValueError, match="selected reviewer identity"):
        validate_selected_phase_review_path(owner, reviewer)
