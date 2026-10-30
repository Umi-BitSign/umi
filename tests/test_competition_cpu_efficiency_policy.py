"""Prospective CPU timing authority, native binding and immutable preparation."""

from dataclasses import replace

import pytest

from umi.competition_cohort_evaluation import RecoverableEvaluationRound
from umi.competition_cohort_intake import CohortIntake, CohortIntakeBinding, CohortIntakeConfig
from umi.competition_cohort_preparation import PreparedCohortRound
from umi.competition_cohort_preparation_export import (
    PreparationReviewExporter,
    replay_preparation_export,
)
from umi.competition_cohort_preparation_owner import CohortPreparation
from umi.competition_cohort_preparation_phase import NativePreparationProgressSource
from umi.competition_cohort_preparation_publisher import CohortPreparationPublicationConfig
from umi.competition_cohort_recovery import SignedCohortRecoveryAuthority, admit_recoverable_cohort
from umi.competition_cpu_efficiency_policy import (
    AuthorizedCpuEfficiency,
    CohortCpuEfficiencyAdoption,
    SignedCohortCpuEfficiencyAdoption,
    authorize_cpu_efficiency,
    default_cpu_efficiency_proposal,
    prepared_cpu_efficiency_authorization,
    require_cpu_efficiency_for_new_round,
    round_cpu_efficiency_authorization,
    validate_cpu_efficiency_authorization,
    verify_cpu_efficiency_adoption_selection,
)
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from . import test_competition_evaluation_runtime as runtime_fixtures
from .test_competition_cohort_consumers import scenario as scenario
from .test_competition_cohort_intake import capture_at
from .test_competition_cohort_preparation import preparation as preparation
from .test_competition_cohort_preparation import run
from .test_competition_cohort_recovery import recovery as original_recovery
from .test_competition_cohort_recovery import signatures
from .test_competition_evaluation_runtime import base_policy as base_policy
from .test_competition_evaluation_runtime import original_runtime as original_runtime
from .test_competition_evaluation_runtime import policy as policy
from .test_competition_evaluation_runtime import runtime as runtime
from .test_open_competition import wallet

runtime_adoption = runtime_fixtures.adoption


@pytest.fixture
def intake(tmp_path, scenario):
    """Exercise model-capable intake from its original initialized binding."""
    history = scenario["intake_history"]
    config = CohortIntakeConfig(
        directory=str(tmp_path / "cohort-intake"),
        cohorts=(
            CohortIntakeBinding(
                cohort_sha256=digest(history.plan),
                authority_sha256=digest(history.authority.authority),
            ),
        ),
    )
    service = CohortIntake(
        config, scenario["policy"], eligible_tracks=("endpoint", "model"), initialize=True
    )
    service.publish(history, capture_at(210))
    return service


@pytest.fixture
def recovery(policy, request):
    plan, signed, _ = original_recovery.__wrapped__(policy, request)
    sequence = getattr(request, "param", 8)
    plan = plan.model_copy(update={"sequence": sequence})
    authority = signed.authority.model_copy(update={"cohort_sha256s": (digest(plan),)})
    signed = SignedCohortRecoveryAuthority(authority=authority, signatures=signatures(authority))
    _, state = admit_recoverable_cohort(plan, signed, policy, admitted_at_block=160)
    return plan, signed, state


@pytest.fixture
def adoption(scenario, policy, runtime_adoption):
    authority = scenario["history"].authority.authority
    body = CohortCpuEfficiencyAdoption(
        schema="umi-cohort-cpu-efficiency-adoption/1",
        policy_sha256=digest(policy),
        authority_sha256=digest(authority),
        cohort_sha256s=authority.cohort_sha256s,
        first_cohort_sequence=8,
        runtime_sha256=digest(runtime_adoption.adoption.runtime),
        issued_at_block=200,
        reason="Prospective CPU efficiency from cold model execution",
    )
    return SignedCohortCpuEfficiencyAdoption(adoption=body, signatures=signatures(body))


def efficiency_round(round_, adoption, runtime_adoption):
    return RecoverableEvaluationRound.model_validate_json(
        canonical_json_bytes(
            round_.model_copy(
                update={
                    "schema_": "umi-recoverable-evaluation-round/3",
                    "runtime_sha256": adoption.adoption.runtime_sha256,
                    "runtime_adoption": runtime_adoption,
                    "cpu_efficiency_adoption": adoption,
                }
            )
        )
    )


def selected(scenario, policy, adoption):
    return authorize_cpu_efficiency(
        adoption,
        policy=policy,
        authority=scenario["history"].authority.authority,
        plan=scenario["history"].plan,
        runtime_sha256=adoption.adoption.runtime_sha256,
        current_block=330,
    )


def test_signed_fixed_parameters_match_exact_arithmetic(adoption):
    from umi.competition_cpu_efficiency_math import (
        MAX_EFFICIENCY_PPM,
        MIN_EFFICIENCY_PPM,
        PPM,
    )

    body = adoption.adoption
    assert body.minimum_multiplier_ppm == MIN_EFFICIENCY_PPM
    assert body.maximum_multiplier_ppm == MAX_EFFICIENCY_PPM
    assert body.multiplier_precision_ppm == PPM
    assert body.slowdown_precision == 1_000_000_000
    assert body.slowdown_rounding_rule == "ceil_per_evaluator/1"
    from umi.competition_cpu_timing import cpu_timing_limits_v1

    limits = cpu_timing_limits_v1()
    for field in (
        "maximum_external_busy_bps",
        "maximum_steal_bps",
        "maximum_snapshot_ms",
        "maximum_boundary_overhead_ms",
        "maximum_clock_disagreement_bps",
    ):
        assert getattr(body, field) == getattr(limits, field)


def test_native_authority_matches_prepared_and_history_paths(
    scenario, policy, adoption, runtime_adoption
):
    round_ = efficiency_round(scenario["round_"], adoption, runtime_adoption)
    native = round_cpu_efficiency_authorization(round_, policy, scenario["history"])
    assert native == prepared_cpu_efficiency_authorization(round_, policy)
    assert native.authority_sha256 == digest(scenario["history"].authority.authority)
    assert (
        validate_cpu_efficiency_authorization(
            native,
            policy=policy,
            runtime_sha256=round_.runtime_sha256,
            cohort_sha256=round_.cohort_sha256,
            sequence=8,
            prepared_at_block=round_.prepared_at_block,
            adoption_sha256=digest(adoption.adoption),
        )
        is native
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("first_cohort_sequence", 7),
        ("minimum_multiplier_ppm", 900000),
        ("maximum_multiplier_ppm", 1100000),
        ("speed_power_denominator", 2),
        ("slowdown_precision", 1_000_000),
        ("slowdown_rounding_rule", "floor_per_evaluator/1"),
        ("timing_rule", "warm_inference_only/1"),
        ("candidate_failure_rule", "ignore_failed_cases/1"),
        ("reference_failure_rule", "alter_baseline_quality/1"),
        ("invalid_timing_rule", "neutral_on_missing/1"),
        ("measurement_semantics", "warm-process-timing/1"),
        ("maximum_external_busy_bps", 101),
        ("maximum_steal_bps", 51),
        ("maximum_snapshot_ms", 51),
        ("maximum_boundary_overhead_ms", 101),
        ("maximum_clock_disagreement_bps", 101),
        ("cohort_sha256s", ("aa" * 32, "aa" * 32)),
        ("cohort_sha256s", ("ff" * 32, "aa" * 32)),
    ],
)
def test_contract_cannot_silently_change_protocol(adoption, field, value):
    damaged = adoption.adoption.model_copy(update={field: value})
    with pytest.raises(ValueError):
        CohortCpuEfficiencyAdoption.model_validate_json(canonical_json_bytes(damaged))


@pytest.mark.parametrize("change", ["runtime", "policy", "authority", "scope", "clock", "quorum"])
def test_startup_rejects_wrong_selection(scenario, policy, adoption, change):
    authority = scenario["history"].authority.authority
    runtime_sha256 = adoption.adoption.runtime_sha256
    if change == "runtime":
        runtime_sha256 = "ab" * 32
    elif change == "policy":
        policy = policy.model_copy(update={"evaluation_runtime_sha256": "ab" * 32})
    elif change == "authority":
        authority = authority.model_copy(update={"issued_at_block": 151})
    elif change == "scope":
        authority = authority.model_copy(update={"cohort_sha256s": ("cd" * 32,)})
    elif change == "clock":
        authority = authority.model_copy(update={"issued_at_block": 201})
    else:
        adoption = adoption.model_copy(
            update={"signatures": signatures(adoption.adoption, ("Alice",))}
        )
    with pytest.raises(ValueError):
        verify_cpu_efficiency_adoption_selection(
            adoption, policy=policy, authority=authority, runtime_sha256=runtime_sha256
        )


@pytest.mark.parametrize("change", ["c7", "cohort", "late", "runtime", "quorum"])
def test_prepared_measurement_rejects_damaged_scope(
    scenario, policy, adoption, runtime_adoption, change
):
    round_ = efficiency_round(scenario["round_"], adoption, runtime_adoption)
    if change == "c7":
        round_ = round_.model_copy(update={"sequence": 7})
    elif change == "cohort":
        round_ = round_.model_copy(update={"cohort_sha256": "ab" * 32})
    elif change == "late":
        round_ = round_.model_copy(update={"prepared_at_block": 199})
    elif change == "runtime":
        round_ = round_.model_copy(update={"runtime_sha256": policy.evaluation_runtime_sha256})
    else:
        bad = adoption.model_copy(update={"signatures": signatures(adoption.adoption, ("Alice",))})
        round_ = round_.model_copy(update={"cpu_efficiency_adoption": bad})
    with pytest.raises(ValueError):
        prepared_cpu_efficiency_authorization(round_, policy)


def test_authorization_refuses_future_issuance_and_changed_plan(scenario, policy, adoption):
    kwargs = dict(
        policy=policy,
        authority=scenario["history"].authority.authority,
        plan=scenario["history"].plan,
        runtime_sha256=adoption.adoption.runtime_sha256,
        current_block=199,
    )
    with pytest.raises(ValueError, match="clock"):
        authorize_cpu_efficiency(adoption, **kwargs)
    kwargs["current_block"] = 330
    kwargs["plan"] = kwargs["plan"].model_copy(update={"sequence": 7})
    with pytest.raises(ValueError, match="cohort"):
        authorize_cpu_efficiency(adoption, **kwargs)


@pytest.mark.parametrize(
    "change", ["forged", "binding", "policy", "runtime", "cohort", "sequence", "clock", "adoption"]
)
def test_native_measurement_rejects_forged_or_reused_context(scenario, policy, adoption, change):
    native = selected(scenario, policy, adoption)
    kwargs = dict(
        policy=policy,
        runtime_sha256=native.runtime_sha256,
        cohort_sha256=native.cohort_sha256,
        sequence=native.sequence,
        prepared_at_block=native.prepared_at_block,
        adoption_sha256=native.adoption_sha256,
    )
    if change == "forged":
        native = AuthorizedCpuEfficiency(
            native.policy_sha256,
            native.authority_sha256,
            native.cohort_sha256,
            native.sequence,
            native.runtime_sha256,
            native.prepared_at_block,
            native.adoption_sha256,
        )
    elif change == "binding":
        native = replace(native, authority_sha256="ab" * 32)
    elif change == "policy":
        kwargs["policy"] = policy.model_copy(update={"evaluation_runtime_sha256": "ab" * 32})
    elif change == "runtime":
        kwargs["runtime_sha256"] = "ab" * 32
    elif change == "cohort":
        kwargs["cohort_sha256"] = "ab" * 32
    elif change == "sequence":
        kwargs["sequence"] = 7
    elif change == "clock":
        kwargs["prepared_at_block"] += 1
    else:
        kwargs["adoption_sha256"] = "ab" * 32
    with pytest.raises(ValueError, match="native cohort authorization"):
        validate_cpu_efficiency_authorization(native, **kwargs)


def test_signature_verification_reuses_exact_authenticated_contract(
    scenario, policy, adoption, runtime_adoption, monkeypatch
):
    from umi import competition_cpu_efficiency_policy as module

    module._verified_contract.cache_clear()
    actual, calls = module.verify_recovery_quorum, []

    def verify(*args):
        calls.append(1)
        return actual(*args)

    monkeypatch.setattr(module, "verify_recovery_quorum", verify)
    round_ = efficiency_round(scenario["round_"], adoption, runtime_adoption)
    for _ in range(3):
        selected(scenario, policy, adoption)
        prepared_cpu_efficiency_authorization(round_, policy)
    assert len(calls) == 1


def test_preparation_retains_contract_across_restart_and_independent_export(
    preparation, adoption, runtime_adoption
):
    h = preparation
    h.certify()
    h.owner = CohortPreparation(
        h.queue, h.store, runtime_adoption=runtime_adoption, cpu_efficiency_adoption=adoption
    )
    first = run(h)
    assert first.roster.round.cpu_efficiency_adoption == adoption
    assert first.roster.round.schema_ == "umi-recoverable-evaluation-round/3"
    raw = canonical_json_bytes(first)
    assert PreparedCohortRound.model_validate_json(raw) == first
    restarted = CohortPreparation(h.queue, h.store)
    assert canonical_json_bytes(run(h, block=100_330, owner=restarted)) == raw
    source = NativePreparationProgressSource(restarted)
    with h.queue._connection() as (_, store):
        state, _ = store.status(h.cohort)
    progress = source.observe(state, capture_at(100_330))
    exporter = PreparationReviewExporter(
        source, wallet("Charlie").hotkey.ss58_address, lambda _: None
    )
    exported = exporter.export(progress)
    reviewed = replay_preparation_export(
        exported,
        h.intake.policy,
        first.promotion_head,
        eligible_tracks=first.roster.round.eligible_tracks,
    )
    assert canonical_json_bytes(reviewed.prepared) == raw


@pytest.mark.parametrize("recovery", [7, 8], indirect=True)
def test_existing_preparation_is_never_backfilled(
    preparation, adoption, runtime_adoption, monkeypatch
):
    from umi import competition_cohort_preparation_owner as owner_module

    h = preparation
    h.certify()
    # Produce an authentic legacy round under the previous producer rule. Only
    # the new creation-presence guard is disabled; all original native checks
    # and canonical retention run normally. The upgraded reader is never patched.
    with monkeypatch.context() as legacy:
        legacy.setattr(owner_module, "require_cpu_efficiency_for_new_round", lambda **kw: None)
        first = run(h)
    raw = canonical_json_bytes(first)
    assert b"cpu_efficiency_adoption" not in raw
    restarted = CohortPreparation(
        h.queue, h.store, runtime_adoption=runtime_adoption, cpu_efficiency_adoption=adoption
    )
    assert canonical_json_bytes(run(h, block=100_330, owner=restarted)) == raw
    if first.roster.round.sequence >= 8:
        with h.queue._connection() as (_, store):
            state, _ = store.status(h.cohort)
        with pytest.raises(ValueError, match="cpu_efficiency_measurement_policy_missing"):
            NativePreparationProgressSource(restarted).observe(state, capture_at(100_330))


@pytest.mark.parametrize("recovery", [7], indirect=True)
def test_new_c7_preparation_ignores_future_efficiency_selection(
    preparation, adoption, runtime_adoption
):
    h = preparation
    h.certify()
    h.owner = CohortPreparation(
        h.queue, h.store, runtime_adoption=runtime_adoption, cpu_efficiency_adoption=adoption
    )
    first = run(h)
    assert first.roster.round.runtime_adoption == runtime_adoption
    assert first.roster.round.cpu_efficiency_adoption is None
    assert first.roster.round.schema_ == "umi-recoverable-evaluation-round/2"


def test_efficiency_can_bind_original_unamended_runtime(preparation, adoption):
    h = preparation
    h.certify()
    body = adoption.adoption.model_copy(
        update={"runtime_sha256": h.intake.policy.evaluation_runtime_sha256}
    )
    signed = SignedCohortCpuEfficiencyAdoption(adoption=body, signatures=signatures(body))
    h.owner = CohortPreparation(h.queue, h.store, cpu_efficiency_adoption=signed)
    first = run(h)
    assert first.roster.round.runtime_adoption is None
    assert first.roster.round.schema_ == "umi-recoverable-evaluation-round/3"
    assert prepared_cpu_efficiency_authorization(first.roster.round, h.intake.policy)


def test_publication_config_preserves_old_bytes_and_round_trips_contract(tmp_path, adoption):
    old = CohortPreparationPublicationConfig(
        promotion_directory=str(tmp_path / "promotion"),
        output_directory=str(tmp_path / "output"),
    )
    raw = canonical_json_bytes(old)
    assert b"cpu_efficiency" not in raw
    assert canonical_json_bytes(CohortPreparationPublicationConfig.model_validate_json(raw)) == raw
    new = old.model_copy(update={"cpu_efficiency_adoption": adoption})
    assert CohortPreparationPublicationConfig.model_validate_json(canonical_json_bytes(new)) == new


@pytest.mark.parametrize("recovery", [8, 9, 10, 11], indirect=True)
def test_new_model_preparation_holds_without_policy_before_any_participant_work(
    preparation, adoption, runtime_adoption, monkeypatch
):
    h = preparation

    def forbidden(*args, **kwargs):
        raise AssertionError(
            "missing measurement policy must hold before participant or promotion work"
        )

    with monkeypatch.context() as patch:
        patch.setattr(h.queue, "_record", forbidden)
        patch.setattr(h.store, "reviewed_promotion_head", forbidden)
        with pytest.raises(ValueError, match="cpu_efficiency_measurement_policy_missing"):
            run(h)
    with h.queue._connection() as (db, _):
        assert db.execute("SELECT COUNT(*) FROM cohort_prepared_rounds").fetchone()[0] == 0
    h.certify()
    h.owner = CohortPreparation(
        h.queue, h.store, runtime_adoption=runtime_adoption, cpu_efficiency_adoption=adoption
    )
    assert run(h).roster.round.cpu_efficiency_adoption == adoption


def test_default_proposal_uses_current_authority_scope_and_actual_runtime(
    scenario, policy, adoption
):
    authority = scenario["history"].authority.authority
    original = canonical_json_bytes(authority)
    body = default_cpu_efficiency_proposal(
        policy=policy,
        authority=authority,
        runtime_sha256=adoption.adoption.runtime_sha256,
        issued_at_block=adoption.adoption.issued_at_block,
        reason=adoption.adoption.reason,
    )
    assert body == adoption.adoption
    assert canonical_json_bytes(authority) == original
    current = default_cpu_efficiency_proposal(
        policy=policy,
        authority=authority,
        runtime_sha256=policy.evaluation_runtime_sha256,
        reason="Default contract for the next authority's original CPU runtime",
    )
    assert current.issued_at_block == authority.issued_at_block
    assert current.runtime_sha256 == policy.evaluation_runtime_sha256
    signed = SignedCohortCpuEfficiencyAdoption(adoption=current, signatures=signatures(current))
    verify_cpu_efficiency_adoption_selection(
        signed, policy=policy, authority=authority, runtime_sha256=current.runtime_sha256
    )
    with pytest.raises(ValueError, match="issuance window"):
        default_cpu_efficiency_proposal(
            policy=policy,
            authority=authority,
            runtime_sha256=current.runtime_sha256,
            issued_at_block=authority.issued_at_block - 1,
            reason=current.reason,
        )


def test_new_round_requirement_does_not_change_c7_or_endpoint_only(adoption):
    require_cpu_efficiency_for_new_round(sequence=7, eligible_tracks=("model",), adoption=None)
    require_cpu_efficiency_for_new_round(sequence=8, eligible_tracks=("endpoint",), adoption=None)
    require_cpu_efficiency_for_new_round(sequence=8, eligible_tracks=("model",), adoption=adoption)
    later = adoption.model_copy(
        update={"adoption": adoption.adoption.model_copy(update={"first_cohort_sequence": 9})}
    )
    with pytest.raises(ValueError, match="cpu_efficiency_measurement_policy_missing"):
        require_cpu_efficiency_for_new_round(sequence=8, eligible_tracks=("model",), adoption=later)


async def test_operator_start_missing_policy_holds_before_baseline_or_runtime_reads(scenario):
    from types import SimpleNamespace

    from umi.competition_cohort_lifecycle_host import LifecycleHost

    plan = scenario["history"].plan
    # The real callback must reject the missing policy before touching the
    # deliberately absent promotion/runtime dependencies in this small shell.
    shell = SimpleNamespace(
        service=SimpleNamespace(
            preparation=SimpleNamespace(selected_cpu_efficiency=lambda *args: None),
            intake=SimpleNamespace(tracks=("model",)),
            config=SimpleNamespace(
                series=SimpleNamespace(cohorts=(plan,), recovery=SimpleNamespace(authority=None)),
                cpu_efficiency_adoption=None,
            ),
        )
    )
    with pytest.raises(ValueError, match="cpu_efficiency_measurement_policy_missing"):
        await LifecycleHost._operator_request_start_selection(shell, digest(plan), 330)
