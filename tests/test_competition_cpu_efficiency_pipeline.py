"""Native CPU timing through retained terminals, quality and reward adoption.

Only finality, sandbox counters, paid-service work and the outer package envelope
are fixture boundaries. No inference or production state is opened. Preparation,
shared baseline, execution journals, signing, quality and reward replay are real.
"""

import shutil
from fractions import Fraction
from types import SimpleNamespace

import pytest
from pydantic import BaseModel

from umi.competition_cohort_execution_journal import CohortExecutionJournal
from umi.competition_cohort_history import CohortRecoveryHistory
from umi.competition_cohort_order_signer import order_slot
from umi.competition_cohort_quality_signing import (
    CohortQualityManifest,
    retained_quality_vote,
    review_quality_manifest,
)
from umi.competition_cohort_request_terminal import (
    SharedRequestExecutionArchive,
    parse_request_execution_archive,
    seal_request_terminal,
)
from umi.competition_cohort_reward_allocation import (
    CohortRewardAllocation,
    derive_effective_reward_allocation,
    retain_reward_allocation,
)
from umi.competition_cohort_reward_certification import replay_reward_allocation
from umi.competition_cohort_roster import RecoverableRosterEvidence
from umi.competition_cohort_service_certification import CertifiedServiceAllocation
from umi.competition_cpu_efficiency_policy import (
    CohortCpuEfficiencyAdoption,
    SignedCohortCpuEfficiencyAdoption,
)
from umi.competition_cpu_timing import CpuTimingEvidence
from umi.competition_geometric_rewards import cohort_reward_parameters
from umi.competition_reward_adoption import (
    RewardAdoptionSelection,
    RewardModelAdoption,
    SignedRewardModelAdoption,
    verify_reward_adoption,
)
from umi.competition_reward_decisions import StandingRewardSeries
from umi.competition_round_journal import RoundJournal
from umi.competition_store import CompetitionStore
from umi.grandpa_finality import FINNEY_GENESIS_HASH
from umi.open_competition import digest, identity
from umi.private_files import publish_private_model
from umi.protocol import canonical_json_bytes

from . import test_competition_cohort_model_award as model_fixtures
from .test_competition_cohort_model_award import base_policy as base_policy
from .test_competition_cohort_model_award import legacy_scenario as legacy_scenario
from .test_competition_cohort_model_award import policy as policy
from .test_competition_cohort_model_award import receipt_scenario as receipt_scenario
from .test_competition_cohort_model_award import runtime as runtime
from .test_competition_cohort_quality import reviewer
from .test_competition_cohort_recovery import signatures
from .test_competition_cpu_efficiency_policy import recovery as recovery
from .test_competition_cpu_timing import bundle_cache, conditions, context, sample
from .test_open_competition import wallet


class PipelineInputs(BaseModel):
    """Only inputs consumed by effective reward adoption; not a portable package."""

    history: CohortRecoveryHistory
    roster: RecoverableRosterEvidence


class PipelinePackage(BaseModel):
    policy_sha256: str
    inputs: PipelineInputs
    allocation: CohortRewardAllocation
    service: CertifiedServiceAllocation
    benchmark: CohortQualityManifest


def timed_execution(step, runtime, contract, elapsed_ms):
    ctx = context(memory_max_bytes=runtime.memory_bytes)
    before = sample(ctx)
    timing = CpuTimingEvidence(
        schema="umi-cpu-timing-evidence/1",
        contract_sha256=contract,
        context=ctx,
        bundle_cache=bundle_cache(model=step.execution.model_sha256, started=before.finished_us),
        conditions=conditions(
            ctx, started=before.finished_us, finished=before.finished_us + elapsed_ms * 1000
        ),
        before=before,
        after=sample(
            ctx,
            now=before.finished_us + elapsed_ms * 1000,
            ticks=100 + elapsed_ms // 10,
            busy=50 + elapsed_ms // 20,
            usage=elapsed_ms * 1000,
        ),
        started_monotonic_us=before.finished_us,
        model_started_monotonic_us=before.finished_us + 1,
        finished_monotonic_us=before.finished_us + elapsed_ms * 1000,
        launch_gate_elapsed_us=1,
    )
    return step.execution.model_copy(
        update={
            "schema_": "umi-offline-case-execution/2",
            "output": step.execution.output.model_copy(
                update={"elapsed_ms": elapsed_ms, "cpu_timing": timing}
            ),
        }
    )


@pytest.fixture
async def pipeline_case(receipt_scenario, tmp_path, runtime, monkeypatch):
    native_setup = model_fixtures.setup_scenario
    native_closure = model_fixtures.closure_fixture
    timed = receipt_scenario["history"].plan.sequence >= 8
    if timed:
        native_observe = CohortExecutionJournal.observe

        def bind_timed_invocation(owner, job, attempt, result):
            # The synthetic sandbox observations precede journal allocation.
            # Bind them at that fixture boundary using the actual retained
            # attempt, while keeping native ingestion/checkpoint checks intact.
            timing = result.output.cpu_timing
            if timing is not None:
                invocation = digest(attempt)
                conditions = timing.conditions.model_copy(
                    update={
                        "invocation_sha256": invocation,
                        "before_probe": timing.conditions.before_probe.model_copy(
                            update={"invocation_sha256": invocation}
                        ),
                        "after_probe": timing.conditions.after_probe.model_copy(
                            update={"invocation_sha256": invocation}
                        ),
                    }
                )
                timing = timing.model_copy(
                    update={
                        "conditions": conditions,
                        "bundle_cache": timing.bundle_cache.model_copy(
                            update={"invocation_sha256": invocation}
                        ),
                    }
                )
                result = result.model_copy(
                    update={"output": result.output.model_copy(update={"cpu_timing": timing})}
                )
            return native_observe(owner, job, attempt, result)

        monkeypatch.setattr(CohortExecutionJournal, "observe", bind_timed_invocation)

    def setup(*args, **kwargs):
        s = native_setup(*args, **kwargs)
        if timed:
            authority = s["history"].authority.authority
            contract = CohortCpuEfficiencyAdoption(
                schema="umi-cohort-cpu-efficiency-adoption/1",
                policy_sha256=digest(s["policy"]),
                authority_sha256=digest(authority),
                cohort_sha256s=authority.cohort_sha256s,
                first_cohort_sequence=8,
                runtime_sha256=digest(runtime),
                issued_at_block=200,
                reason="Prospective synthetic CPU timing integration fixture",
            )
            s["round_"] = s["round_"].model_copy(
                update={
                    "schema_": "umi-recoverable-evaluation-round/3",
                    "cpu_efficiency_adoption": SignedCohortCpuEfficiencyAdoption(
                        adoption=contract, signatures=signatures(contract)
                    ),
                }
            )
        return s

    async def close(original, path, *, prepared, shared_incumbents):
        # The model fixture already chose distinct candidate hypotheses. Keep a
        # nonempty imperfect reference so the shared timing has useful meaning.
        for scenario in prepared["scenarios"]:
            artifacts = []
            for artifact in scenario["artifacts"]:
                steps = []
                for step in artifact.steps:
                    if step.role == "incumbent":
                        step = step.model_copy(
                            update={
                                "execution": step.execution.model_copy(
                                    update={
                                        "stdout_hex": b"h\n".hex(),
                                        "output": step.execution.output.model_copy(
                                            update={"hypothesis": "h"}
                                        ),
                                    }
                                )
                            }
                        )
                    if timed:
                        duration = (
                            200
                            if step.role == "incumbent"
                            else 100
                            if scenario["miner_name"] == "Bob"
                            else 400
                        )
                        step = step.model_copy(
                            update={
                                "execution": timed_execution(
                                    step,
                                    runtime,
                                    digest(artifact.job.round.cpu_efficiency_adoption.adoption),
                                    duration,
                                )
                            }
                        )
                    steps.append(step)
                artifacts.append(artifact.model_copy(update={"steps": tuple(steps)}))
            scenario["artifacts"] = tuple(artifacts)
        return await native_closure(
            original, path, prepared=prepared, shared_incumbents=shared_incumbents
        )

    monkeypatch.setattr(model_fixtures, "setup_scenario", setup)
    monkeypatch.setattr(model_fixtures, "closure_fixture", close)
    return await model_fixtures.model_case.__wrapped__(
        receipt_scenario,
        tmp_path,
        runtime,
        SimpleNamespace(param=("shared-proportional", 2)),
    )


@pytest.mark.parametrize("receipt_scenario", ["geometric-model-awards-c7"], indirect=True)
@pytest.mark.parametrize("recovery", [8], indirect=True)
async def test_cpu_timing_cannot_be_substituted_between_retained_attempts(pipeline_case):
    b = pipeline_case[0]
    order = b["orders"][0]
    evaluator = order.order.evaluators[0]
    owner = b["owners"][(digest(order), identity(evaluator))]
    _, job = owner.assignment_and_job(order_slot(order.order))
    attempt = owner.head(job, 0)
    execution = owner.result(job, attempt).execution
    assert execution.output.cpu_timing.conditions.invocation_sha256 == digest(attempt)
    assert owner.check_result(job, attempt, execution) == execution
    another_attempt = attempt.model_copy(
        update={"number": attempt.number + 1, "predecessor_sha256": digest(attempt)}
    )
    with pytest.raises(ValueError, match="CPU timing invocation differs from its retained attempt"):
        owner.check_result(job, another_attempt, execution)


@pytest.mark.parametrize("receipt_scenario", ["geometric-model-awards-c7"], indirect=True)
@pytest.mark.parametrize("recovery", [7, 8], indirect=True)
async def test_signed_cpu_timing_survives_shared_baseline_restart_and_reward_adoption(
    pipeline_case, tmp_path
):
    b, review, benchmark, acceptances, archive = pipeline_case
    sequence = b["history"].plan.sequence
    timed = sequence >= 8
    outcomes = review_quality_manifest(benchmark, reviewer(b))
    assert len(outcomes) == 2
    assert all(len(outcome.runs) == 2 for outcome in outcomes)
    summaries = [outcome.cpu_efficiency for outcome in outcomes]
    if timed:
        assert sorted(s.multiplier_ppm for s in summaries) == [933_032, 1_071_773]
        assert all(len(s.runs) == 2 for s in summaries)
        assert all(
            s.contract_sha256 == digest(b["roster"].round.cpu_efficiency_adoption.adoption)
            for s in summaries
        )
        assert all(r.candidate_failed_cases == 0 for s in summaries for r in s.runs)
    else:
        assert summaries == [None, None]
        assert b"cpu_efficiency" not in canonical_json_bytes(benchmark)

    archives = [
        parse_request_execution_archive(b["objects"][terminal.terminal.execution_archive_sha256])
        for terminal in b["terminals"].values()
    ]
    assert len(archives) == 4
    assert sum(isinstance(item, SharedRequestExecutionArchive) for item in archives) == 2

    async def no_new_signature(_):
        pytest.fail("restart must reuse the retained signed terminal")

    for order in b["orders"]:
        slot = order_slot(order.order)
        for evaluator in order.order.evaluators:
            key = digest(order), identity(evaluator)
            owner = b["owners"][key]
            restarted = CohortExecutionJournal(owner.config, b["policy"])
            terminal = await seal_request_terminal(restarted, slot, no_new_signature)
            assert canonical_json_bytes(terminal) == canonical_json_bytes(b["terminals"][key])
            vote = retained_quality_vote(owner, slot)
            assert vote is not None
            assert retained_quality_vote(restarted, slot) == vote
            assert vote.result in outcomes
            # One original baseline plus two candidates, with no repeated
            # baseline execution when another model or owner uses the receipt.
            with restarted.journal.read_transaction() as db:
                attempts = db.execute(
                    "SELECT COUNT(*) FROM records WHERE kind='attempt'"
                ).fetchone()[0]
            assert attempts == 3 * len(b["suite"].cases)

    service_review, service = model_fixtures.service_boundary(pipeline_case, 0)
    store = CompetitionStore(tmp_path / "pipeline-reward-store", b["policy"])
    shutil.copytree(archive, store.directory / "model-reward-artifacts")
    for acceptance in acceptances:
        publish_private_model(
            store.directory
            / "model-reward-acceptances"
            / digest(b["history"].plan)
            / (acceptance.acceptance.submission_sha256 + ".json"),
            acceptance,
        )
    scope = {"scope": "cpu-efficiency-pipeline"}
    journal = RoundJournal(tmp_path / "pipeline-reward-owner", scope)
    allocation = retain_reward_allocation(
        journal,
        store,
        service,
        service_review,
        benchmark,
        review,
        maximum_promotion_bytes=1_000_000,
    )
    original_bytes = canonical_json_bytes(allocation)
    assert (
        replay_reward_allocation(
            allocation,
            store,
            service,
            service_review,
            benchmark,
            reviewer(b),
            maximum_promotion_bytes=1_000_000,
        )
        == allocation
    )
    assert (
        retain_reward_allocation(
            RoundJournal(journal.root, scope),
            store,
            service,
            service_review,
            benchmark,
            reviewer(b),
            maximum_promotion_bytes=1_000_000,
        )
        == allocation
    )
    assert allocation.model_award == model_fixtures.award(pipeline_case)

    package = PipelinePackage(
        policy_sha256=digest(b["policy"]),
        inputs=PipelineInputs(history=review.history, roster=b["roster"]),
        allocation=allocation,
        service=service,
        benchmark=benchmark,
    )
    parameters = cohort_reward_parameters(sequence)
    effective = derive_effective_reward_allocation(package, parameters)
    original_credits, effective_credits = (
        allocation.model_award.credits,
        effective.model_award.credits,
    )
    assert len(original_credits) == len(effective_credits) == 2
    assert [c.submission_sha256 for c in original_credits] == [
        c.submission_sha256 for c in effective_credits
    ]
    if timed:
        assert [c.efficiency_multiplier_ppm for c in effective_credits] == [1_071_773, 933_032]
        assert effective.schema_ == "umi-cohort-reward-allocation/6"
        assert effective.recipients != allocation.recipients
    else:
        assert effective == allocation
        assert b"cpu_efficiency" not in original_bytes
        assert b"efficiency_multiplier_ppm" not in original_bytes
    assert (
        sum(Fraction(int(c.weight.numerator), int(c.weight.denominator)) for c in effective_credits)
        == 1
    )
    assert sum(r.raw_weight for r in effective.recipients) + effective.burn_weight == 65535

    series = StandingRewardSeries(
        schema="umi-standing-reward-series/1",
        genesis_hash=FINNEY_GENESIS_HASH,
        netuid=78,
        policy_sha256=digest(b["policy"]),
        policy_epoch=1,
        manifest_sha256="ab" * 32,
        control_hotkey=wallet("Charlie").hotkey.ss58_address,
        recovery=review.history.authority,
        cohorts=(review.history.plan,),
        validators=tuple(sorted(b["orders"][0].order.evaluators, key=identity)),
        maximum_proof_lag_blocks=32,
        maximum_transaction_lifetime_blocks=128,
        lifetime="until_superseded_or_revoked",
    )
    body = RewardModelAdoption(
        schema="umi-standing-model-reward-adoption/1",
        series_sha256=digest(series),
        policy_sha256=digest(b["policy"]),
        cohort_sha256=digest(review.history.plan),
        authority_sha256=digest(review.history.authority.authority),
        package_sha256=digest(package),
        allocation_sha256=digest(allocation),
        service_certificate_sha256=digest(service),
        quality_manifest_sha256=digest(benchmark),
        effective_allocation_sha256=digest(effective),
        parameters=parameters,
        revision=1,
        predecessor_adoption_sha256=None,
        issued_at_block=2000,
        lifetime="until_first_verified_live_reward_then_locked",
    )
    selected = RewardAdoptionSelection(
        schema="umi-standing-reward-adoption-selection/1",
        adoptions=(SignedRewardModelAdoption(adoption=body, signatures=signatures(body)),),
    )
    adopted, replayed = verify_reward_adoption(
        selected,
        digest(body),
        series=series,
        policy=b["policy"],
        package=package,
        current_block=2000,
        include_effective_allocation=True,
    )
    assert adopted == body and replayed == effective
    assert canonical_json_bytes(package.allocation) == original_bytes
    damaged = body.model_copy(update={"effective_allocation_sha256": "cd" * 32})
    changed = selected.model_copy(
        update={
            "adoptions": (
                SignedRewardModelAdoption(adoption=damaged, signatures=signatures(damaged)),
            )
        }
    )
    with pytest.raises(ValueError, match="deterministic effective allocation"):
        verify_reward_adoption(
            changed,
            digest(damaged),
            series=series,
            policy=b["policy"],
            package=package,
            current_block=2000,
        )
