"""Host-only review allowances preserve supported layouts and durable bindings."""

import json
from types import SimpleNamespace

import pytest

from umi.competition_cohort_admission_host import AdmissionOwnerConfig
from umi.competition_cohort_intake import CohortIntakeConfig
from umi.competition_cohort_lifecycle_host import LifecycleHost, LifecycleHostConfig
from umi.competition_cohort_progress_signer import CohortProgressSigner
from umi.competition_cohort_request_start import RequestStartConfig
from umi.competition_cohort_review_budget import (
    MAX_REVIEW_SECONDS,
    PhaseReviewBudget,
    checked_budget,
)
from umi.competition_cohort_review_config import PhaseReviewServiceConfig
from umi.competition_cohort_review_http import CohortReviewPeerConfig
from umi.competition_cohort_settlement_config import SettlementOriginalSources
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_review_boot import chain as chain
from .test_competition_cohort_review_boot import chain_config as chain_config
from .test_competition_cohort_review_boot import control as control
from .test_competition_cohort_review_boot import inputs as inputs
from .test_competition_cohort_review_boot import policy as policy
from .test_competition_cohort_review_boot import selected as selected
from .test_competition_cohort_review_boot import series_case as series_case
from .test_competition_cohort_review_boot import (
    with_admission,
    with_benchmark,
    with_direct_model_review,
    with_endpoint,
    with_models,
    with_service,
)

GIB4 = 4 * 1024**3


def profile(policy, **changes):
    fields = dict(
        schema="umi-cohort-phase-review-budget/1",
        policy_sha256=digest(policy),
        evaluation_runtime_sha256=policy.evaluation_runtime_sha256,
        maximum_aggregate_evidence_bytes=GIB4,
        export_seconds=4000,
        replay_seconds=5000,
        authority_seconds=700,
        signing_seconds=300,
        transport_seconds=11,
        vote_queue_seconds=31,
        export_queue_slots=2,
    )
    return PhaseReviewBudget(**(fields | changes))


def select(config, budget):
    return PhaseReviewServiceConfig.model_validate_json(
        canonical_json_bytes(config.model_copy(update={"phase_review_budget": budget}))
    )


def test_complete_serial_budget_counts_exports_replays_and_both_queues(policy):
    budget = profile(policy)
    assert budget.effective() == {
        "profile": "umi-cohort-phase-review-budget/1",
        "owner_export_seconds": 4000,
        "export_exchange_seconds": 8011,
        "progress_vote_seconds": 27053,
        "decision_vote_seconds": 40064,
        "progress_exchange_seconds": 27095,
        "decision_exchange_seconds": 40106,
    }
    assert budget.vote_seconds("decision") - budget.vote_seconds("progress") == 13011
    with pytest.raises(ValueError, match="unsupported"):
        budget.vote_seconds("settlement")


@pytest.mark.parametrize(
    "field",
    [
        "export_seconds",
        "replay_seconds",
        "authority_seconds",
        "signing_seconds",
        "transport_seconds",
        "vote_queue_seconds",
    ],
)
@pytest.mark.parametrize("value", [True, 2.0, "4000", 0, -1, MAX_REVIEW_SECONDS + 1])
def test_budget_requires_positive_exact_integer_allowances(policy, field, value):
    with pytest.raises(ValueError):
        profile(policy, **{field: value})


@pytest.mark.parametrize("slots", [False, 2.0, "2", 0, 65])
def test_export_queue_slots_are_strict_and_bounded(policy, slots):
    with pytest.raises(ValueError):
        profile(policy, export_queue_slots=slots)


@pytest.mark.parametrize("field", ["export_seconds", "replay_seconds", "vote_queue_seconds"])
def test_composite_deadline_cannot_overflow_its_representation(policy, field):
    with pytest.raises(ValueError, match="outside bounds"):
        profile(policy, **{field: MAX_REVIEW_SECONDS})


@pytest.mark.parametrize(
    "change",
    [
        {"policy_sha256": "fe" * 32},
        {"evaluation_runtime_sha256": "fe" * 32},
        {"maximum_aggregate_evidence_bytes": GIB4 - 1},
    ],
)
def test_profile_is_bound_to_policy_runtime_and_selected_capacity(policy, change):
    with pytest.raises(ValueError, match="policy, runtime or capacity"):
        checked_budget(profile(policy, **change), policy, GIB4)


def test_exact_capacity_reviewers_and_signer_budget_are_accepted(policy):
    budget = profile(policy)
    assert checked_budget(budget, policy, GIB4, reviewers=2, signing_seconds=300) == budget
    with pytest.raises(ValueError, match="reviewers"):
        checked_budget(budget, policy, GIB4, reviewers=3)
    with pytest.raises(ValueError, match="signing"):
        checked_budget(budget, policy, GIB4, signing_seconds=301)
    assert checked_budget(None, policy, GIB4) is None


def test_checked_budget_revalidates_unchecked_model_copy(policy):
    budget = profile(policy).model_copy(update={"export_seconds": MAX_REVIEW_SECONDS})
    with pytest.raises(ValueError, match="outside bounds"):
        checked_budget(budget, policy, GIB4)


@pytest.mark.parametrize(
    "version, transform",
    [
        (1, lambda config: config),
        (2, with_service),
        (3, with_admission),
        (4, with_models),
        (5, with_benchmark),
        (6, with_endpoint),
        (7, with_direct_model_review),
    ],
)
def test_all_supported_reviewer_layouts_preserve_signed_bytes_and_stores(
    selected, version, transform
):
    old = transform(selected.config)
    assert old.schema_ == f"umi-cohort-phase-review-service/{version}"
    original = canonical_json_bytes(old)
    assert b'"phase_review_budget"' not in original
    assert canonical_json_bytes(PhaseReviewServiceConfig.model_validate_json(original)) == original
    new = select(old, profile(old.policy))
    assert new.signing == old.signing
    assert new.stores() == old.stores()
    assert new.review_timeout_seconds == old.review_timeout_seconds == 2400
    for field in ("series", "policy", "manifest"):
        assert canonical_json_bytes(getattr(new, field)) == canonical_json_bytes(
            getattr(old, field)
        )
    updated = json.loads(canonical_json_bytes(new))
    del updated["phase_review_budget"]
    assert updated == json.loads(original)
    assert select(new, profile(old.policy)) == new


def test_reviewer_rejects_profile_shortening_actual_signer(selected):
    with pytest.raises(ValueError, match="signing"):
        select(selected.config, profile(selected.config.policy, signing_seconds=299))


def test_host_budget_change_reopens_original_native_signer_journal(selected):
    old = selected.config
    reviewer = SimpleNamespace(policy=old.policy, cohorts=old.signing.cohorts)
    first = CohortProgressSigner(old.signing, reviewer, None)
    marker = {"original_clock": 12000, "evidence_sha256": "11" * 32}
    first.journal.put("retained_native_binding", "original", marker)
    new = select(old, profile(old.policy))
    reopened = CohortProgressSigner(new.signing, reviewer, None)
    assert reopened.journal.get("retained_native_binding", "original") == marker
    assert new.signing.directory == old.signing.directory


def owner_config(selected, root, budget=None):
    config = selected.config
    return AdmissionOwnerConfig(
        schema="umi-cohort-admission-owner/1",
        directory=str(root / "owner"),
        owner_hotkey=config.owner_hotkey,
        owner_key_file=str(root / "owner-key"),
        export_token_file=str(root / "owner-token"),
        reviewers=(
            CohortReviewPeerConfig(
                signer=config.signing.signer,
                origin="https://reviewer.example",
                token_file=str(root / "reviewer-token"),
                timeout_seconds=17,
                phase_review_budget=budget,
            ),
        ),
        listen_port=19400,
        maximum_aggregate_evidence_bytes=GIB4,
        phase_review_budget=budget,
    )


def test_owner_and_peer_preserve_legacy_canonical_bytes(selected, tmp_path):
    old = owner_config(selected, tmp_path)
    original = canonical_json_bytes(old)
    assert b'"phase_review_budget"' not in original
    assert canonical_json_bytes(AdmissionOwnerConfig.model_validate_json(original)) == original
    new = owner_config(selected, tmp_path, profile(selected.config.policy))
    assert AdmissionOwnerConfig.model_validate_json(canonical_json_bytes(new)) == new
    assert new.stores() == old.stores()
    assert new.host_memory_admission is None
    assert new.request_evidence_bytes == old.request_evidence_bytes == GIB4
    assert new.reviewers[0].timeout_seconds == old.reviewers[0].timeout_seconds == 17
    updated = json.loads(canonical_json_bytes(new))
    del updated["phase_review_budget"]
    for peer in updated["reviewers"]:
        del peer["phase_review_budget"]
    assert updated == json.loads(original)


@pytest.mark.parametrize("use_budget", [False, True])
def test_owner_export_is_independent_of_short_ordinary_peer_timeout(selected, tmp_path, use_budget):
    config = selected.config
    budget = profile(config.policy) if use_budget else None
    owner = owner_config(selected, tmp_path, budget)
    intake = CohortIntakeConfig(directory=str(tmp_path / "intake"), cohorts=config.signing.cohorts)
    sources = SettlementOriginalSources(
        intake=intake,
        eligible_tracks=config.eligible_tracks,
        round_directory=str(tmp_path / "rounds"),
        objects_directory=str(tmp_path / "objects"),
        catalogs_directory=config.inputs_directory + "/catalogs",
        transport_directory=str(tmp_path / "transport"),
        pulses_directory=str(tmp_path / "pulses"),
    )
    lifecycle = LifecycleHostConfig(
        schema="umi-cohort-lifecycle-host/1",
        directory=str(tmp_path / "lifecycle"),
        request_start=RequestStartConfig(
            schema="umi-cohort-request-start-config/1",
            directory=str(tmp_path / "request-start"),
            first_cohort_not_before_unix_ms=1,
        ),
        request_completion_directory=str(tmp_path / "completion"),
        settlement_history_directory=str(tmp_path / "history"),
        proof_export_directory=str(tmp_path / "proof-export"),
        sources=sources,
        public_origin="https://owner.example",
    )
    service = SimpleNamespace(
        config=SimpleNamespace(
            lifecycle=lifecycle,
            admission_owner=owner,
            inputs_directory=config.inputs_directory,
            series=config.series,
        ),
        intake=SimpleNamespace(config=intake, policy=config.policy, tracks=config.eligible_tracks),
        provider=SimpleNamespace(
            policy=config.policy,
            config=SimpleNamespace(maximum_head_age_ms=120000, maximum_future_skew_ms=30000),
        ),
        history=None,
    )
    host = LifecycleHost(service, None, None, (), None)
    assert host.readiness_timeout_seconds == 17
    assert host.timeout_seconds == (4000 if use_budget else 17)
    assert host.maximum_bytes == host.request_replay_bytes == GIB4
