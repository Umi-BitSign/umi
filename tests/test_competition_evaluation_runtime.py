"""Prospective resource adoption keeps signed historical evidence immutable."""

from fractions import Fraction

import pytest

from umi.competition_cohort_evaluation import RecoverableEvaluationRound
from umi.competition_cohort_preparation import PreparedCohortRound
from umi.competition_cohort_preparation_export import (
    PreparationReviewExporter,
    replay_preparation_export,
)
from umi.competition_cohort_preparation_owner import CohortPreparation
from umi.competition_cohort_preparation_phase import NativePreparationProgressSource
from umi.competition_cohort_recovery import (
    SignedCohortRecoveryAuthority,
    admit_recoverable_cohort,
)
from umi.competition_evaluation_runtime import (
    CohortEvaluationRuntimeAdoption,
    SignedCohortEvaluationRuntimeAdoption,
    authorize_evaluation_runtime,
    prepared_runtime_authorization,
    verify_runtime_adoption_selection,
)
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from . import test_competition_runner as runner_fixtures
from . import test_open_competition as policy_fixtures
from .test_competition_cohort_consumers import scenario as scenario
from .test_competition_cohort_execution import observe, replay, setup_scenario
from .test_competition_cohort_intake import capture_at
from .test_competition_cohort_intake import intake as intake
from .test_competition_cohort_preparation import preparation as preparation
from .test_competition_cohort_preparation import run
from .test_competition_cohort_recovery import recovery as original_recovery
from .test_competition_cohort_recovery import signatures
from .test_open_competition import wallet

original_runtime = runner_fixtures.runtime
base_policy = policy_fixtures.policy


@pytest.fixture
def runtime(original_runtime):
    return original_runtime.model_copy(update={"pids_limit": 128})


@pytest.fixture
def policy(base_policy, runtime):
    return base_policy.model_copy(update={"evaluation_runtime_sha256": digest(runtime)})


@pytest.fixture
def recovery(policy, request):
    plan, authority, _ = original_recovery.__wrapped__(policy, request)
    plan = plan.model_copy(update={"sequence": 7})
    body = authority.authority.model_copy(update={"cohort_sha256s": (digest(plan),)})
    authority = SignedCohortRecoveryAuthority(authority=body, signatures=signatures(body))
    _, state = admit_recoverable_cohort(plan, authority, policy, admitted_at_block=160)
    return plan, authority, state


@pytest.fixture
def adoption(scenario, runtime, policy):
    authority = scenario["history"].authority.authority
    body = CohortEvaluationRuntimeAdoption(
        schema="umi-cohort-evaluation-runtime-adoption/1",
        policy_sha256=digest(policy),
        authority_sha256=digest(authority),
        cohort_sha256s=authority.cohort_sha256s,
        first_cohort_sequence=7,
        original_runtime=runtime,
        runtime=runtime.model_copy(update={"pids_limit": 256}),
        issued_at_block=200,
        reason="Allow bounded inference worker threads on evaluator hosts",
    )
    return SignedCohortEvaluationRuntimeAdoption(adoption=body, signatures=signatures(body))


def amended_round(round_, adoption):
    return RecoverableEvaluationRound.model_validate_json(
        canonical_json_bytes(
            round_.model_copy(
                update={
                    "schema_": "umi-recoverable-evaluation-round/2",
                    "runtime_sha256": digest(adoption.adoption.runtime),
                    "runtime_adoption": adoption,
                }
            )
        )
    )


def test_amended_preparation_restart_and_independent_export(preparation, adoption):
    h = preparation
    h.certify()
    h.owner = CohortPreparation(h.queue, h.store, runtime_adoption=adoption)
    first = run(h)
    assert first.roster.round.schema_ == "umi-recoverable-evaluation-round/2"
    assert first.roster.round.runtime_sha256 == digest(adoption.adoption.runtime)
    raw = canonical_json_bytes(first)
    assert PreparedCohortRound.model_validate_json(raw) == first
    # A restart with no profile selected must still reuse its embedded original.
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


def test_retained_original_round_ignores_new_config(preparation, adoption):
    h = preparation
    h.certify()
    first = run(h)
    raw = canonical_json_bytes(first)
    assert b"runtime_adoption" not in raw
    restarted = CohortPreparation(h.queue, h.store, runtime_adoption=adoption)
    assert canonical_json_bytes(run(h, block=100_330, owner=restarted)) == raw


def test_amended_execution_replays_same_scores_without_rewriting_old_evidence(
    scenario, adoption, runtime, tmp_path
):
    old = setup_scenario(scenario, tmp_path / "old", runtime)
    old_raw = tuple(canonical_json_bytes(value) for value in old["artifacts"])
    s = dict(scenario, round_=amended_round(scenario["round_"], adoption))
    s = setup_scenario(s, tmp_path / "new", adoption.adoption.runtime)
    assert observe(s).candidate
    candidate, incumbent = replay(s)
    assert set(candidate.values()) == {Fraction(1)}
    assert set(incumbent.values()) == {Fraction(0)}
    replay(old)
    assert tuple(canonical_json_bytes(value) for value in old["artifacts"]) == old_raw


@pytest.mark.parametrize(
    "field,value",
    [
        ("cpus", 3),
        ("memory_bytes", 2 * 1024**3),
        ("scratch_bytes", 32 * 1024**2),
        ("image", "ghcr.io/other/image@sha256:" + "ef" * 32),
        ("pids_limit", 255),
    ],
)
def test_profile_cannot_change_other_resources(adoption, field, value):
    body = adoption.adoption.model_copy(
        update={"runtime": adoption.adoption.runtime.model_copy(update={field: value})}
    )
    with pytest.raises(ValueError, match="128 to 256"):
        CohortEvaluationRuntimeAdoption.model_validate_json(canonical_json_bytes(body))


@pytest.mark.parametrize("change", ["cohort", "c6", "late", "runtime", "signature"])
def test_bare_round_resource_authorization_rejects_scope_or_proof_damage(
    scenario, adoption, policy, change
):
    round_ = amended_round(scenario["round_"], adoption)
    if change == "cohort":
        round_ = round_.model_copy(update={"cohort_sha256": "ab" * 32})
    elif change == "c6":
        round_ = round_.model_copy(update={"sequence": 6})
    elif change == "late":
        round_ = round_.model_copy(update={"prepared_at_block": 199})
    elif change == "runtime":
        round_ = round_.model_copy(update={"runtime_sha256": policy.evaluation_runtime_sha256})
    else:
        bad = adoption.model_copy(update={"signatures": signatures(adoption.adoption, ("Alice",))})
        round_ = round_.model_copy(update={"runtime_adoption": bad})
    with pytest.raises(ValueError):
        prepared_runtime_authorization(round_, policy)


def test_config_validation_checks_actual_authority_and_quorum(scenario, adoption, policy):
    authority = scenario["history"].authority.authority
    verify_runtime_adoption_selection(adoption, policy=policy, authority=authority)
    for changed in (
        authority.model_copy(update={"issued_at_block": 201}),
        authority.model_copy(update={"cohort_sha256s": ("cd" * 32,)}),
    ):
        with pytest.raises(ValueError, match="configured authority"):
            verify_runtime_adoption_selection(adoption, policy=policy, authority=changed)
    with pytest.raises(ValueError):
        verify_runtime_adoption_selection(
            adoption.model_copy(update={"signatures": signatures(adoption.adoption, ("Alice",))}),
            policy=policy,
            authority=authority,
        )
    with pytest.raises(ValueError, match="phase"):
        authorize_evaluation_runtime(
            adoption,
            policy=policy,
            authority=authority,
            plan=scenario["history"].plan,
            current_block=199,
        )


def test_repeated_profile_consumers_reuse_exact_quorum_verification(
    scenario, adoption, policy, monkeypatch
):
    from umi import competition_evaluation_runtime as module

    module._verified_profile.cache_clear()
    native, calls = module.verify_recovery_quorum, []

    def verify(*args):
        calls.append(1)
        return native(*args)

    monkeypatch.setattr(module, "verify_recovery_quorum", verify)
    round_ = amended_round(scenario["round_"], adoption)
    for _ in range(3):
        verify_runtime_adoption_selection(
            adoption, policy=policy, authority=scenario["history"].authority.authority
        )
        prepared_runtime_authorization(round_, policy)
    assert len(calls) == 1


async def test_actual_sandbox_and_journal_receive_amended_runtime_authorization(
    scenario, adoption, tmp_path, monkeypatch
):
    from types import SimpleNamespace

    from umi import competition_cohort_sandbox as sandbox
    from umi.competition_cohort_execution_journal import (
        CohortExecutionAttempt,
        CohortExecutionJournal,
    )
    from umi.competition_evaluation_runtime import validate_evaluation_runtime_authorization

    from .test_competition_execution import boundary

    selected = dict(scenario, round_=amended_round(scenario["round_"], adoption))
    selected = setup_scenario(selected, tmp_path / "inputs", adoption.adoption.runtime)
    artifact = selected["artifacts"][0]
    job, result = artifact.job, artifact.steps[0].execution
    attempt = CohortExecutionAttempt(
        schema="umi-cohort-execution-attempt/1",
        job_sha256=digest(job),
        step_index=0,
        number=1,
        predecessor_sha256=None,
        started=boundary(1500),
        history_sha256="ac" * 32,
    )
    port = sandbox.CohortCpuSandbox(
        selected["policy"],
        archive=tmp_path / "archive",
        videos=tmp_path / "videos",
        workspace=tmp_path / "work",
    )
    seen = []

    async def execute(**kwargs):
        effective = validate_evaluation_runtime_authorization(
            kwargs["runtime_authorization"],
            policy=selected["policy"],
            runtime_sha256=digest(kwargs["runtime"]),
        )
        seen.append(effective.pids_limit)
        return result

    monkeypatch.setattr(sandbox, "execute_offline_case", execute)
    monkeypatch.setattr(sandbox, "read_case_video", lambda *args: b"inert")
    assert await port.invoke(job, attempt) == result
    assert seen == [256]
    assert (
        CohortExecutionJournal.check_result(
            SimpleNamespace(policy=selected["policy"]), job, attempt, result
        )
        == result
    )
