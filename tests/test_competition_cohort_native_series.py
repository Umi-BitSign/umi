"""One configured C5-C10 series through native intake, rest and settlement.

The selected series uses a mixed C5 profile and model-only C6-C10 profiles. It
reuses original owner/evaluator journals across cohorts. C8-C10 select a signed
CPU contract before preparation; C5-C7 retain untimed historical behavior.
Finality, inference, host counters, rights review and HTTP remain the explicit
fixture ports. This does not establish actual host qualification, reward
activation, coverage or installed chain effects.
"""

import pytest

from umi.competition_cohort_history import CohortRecoveryHistory
from umi.competition_cohort_recovery import (
    SignedCohortRecoveryAuthority,
    admit_recoverable_cohort,
)
from umi.competition_cohort_reward_allocation import derive_effective_reward_allocation
from umi.competition_cpu_efficiency_policy import (
    SignedCohortCpuEfficiencyAdoption,
    default_cpu_efficiency_proposal,
)
from umi.competition_cpu_timing import CpuTimingEvidence
from umi.competition_execution import execution_boundary
from umi.competition_geometric_rewards import cohort_reward_parameters
from umi.open_competition import digest, sign_object
from umi.private_files import publish_private_model
from umi.protocol import canonical_json_bytes

from . import test_competition_cohort_native_pipeline as native_pipeline
from .test_competition_cohort_executor import output as native_output
from .test_competition_cohort_native_pipeline import (
    chain_config as chain_config,
)
from .test_competition_cohort_native_pipeline import (
    host as host,
)
from .test_competition_cohort_native_pipeline import (
    intake as intake,
)
from .test_competition_cohort_native_pipeline import (
    legacy_scenario as legacy_scenario,
)
from .test_competition_cohort_native_pipeline import (
    lifecycle as lifecycle,
)
from .test_competition_cohort_native_pipeline import (
    lifecycle_before_intake as lifecycle_before_intake,
)
from .test_competition_cohort_native_pipeline import (
    model_request,
    precommit_model_inventory,
    run_pipeline,
)
from .test_competition_cohort_native_pipeline import (
    policy as policy,
)
from .test_competition_cohort_native_pipeline import (
    recovery as recovery,
)
from .test_competition_cohort_native_pipeline import (
    runtime as runtime,
)
from .test_competition_cohort_native_pipeline import scenario as single_scenario  # noqa: F401
from .test_competition_cohort_recovery import signatures
from .test_competition_cpu_timing import bundle_cache, conditions, context, sample
from .test_open_competition import policy as base_policy  # noqa: F401
from .test_open_competition import wallet

pytestmark = pytest.mark.parametrize(
    "lifecycle_before_intake", [precommit_model_inventory], indirect=True
)


@pytest.fixture
def scenario(single_scenario, policy):  # noqa: F811
    original = single_scenario["intake_history"]
    plans = tuple(
        original.plan.model_copy(
            update={
                "schema_": "umi-recoverable-cohort-plan/2",
                "sequence": n,
                "eligible_tracks": ("endpoint", "model") if n == 5 else ("model",),
                "service_pool_bps": 5000 if n == 5 else 0,
            }
        )
        for n in range(5, 11)
    )
    body = original.authority.authority.model_copy(
        update={"cohort_sha256s": tuple(sorted(digest(p) for p in plans))}
    )
    authority = SignedCohortRecoveryAuthority(authority=body, signatures=signatures(body))
    histories = []
    for plan in plans:
        genesis, _ = admit_recoverable_cohort(plan, authority, policy, admitted_at_block=160)
        histories.append(
            CohortRecoveryHistory(
                schema="umi-cohort-recovery-history/1",
                plan=plan,
                authority=authority,
                genesis=genesis,
                genesis_signatures=signatures(genesis),
                transitions=(),
            )
        )
    result = dict(single_scenario, histories=tuple(histories))
    return select_scenario(result, histories[0])


def select_scenario(scenario, history):
    body = scenario["consent"].consent.model_copy(
        update={
            "cohort_sha256": digest(history.plan),
            "authority_sha256": digest(history.authority.authority),
        }
    )
    return dict(
        scenario,
        intake_history=history,
        consent=scenario["consent"].model_copy(
            update={"consent": body, "signature": sign_object(body, wallet("Alice"))}
        ),
    )


def timed_output(job, attempt):
    """Supply synthetic trusted-host counters only at the existing sandbox port.

    The original case result still comes from the shared inference fixture.
    Native ingestion validates contract, resources and exact retained attempt;
    no preparation, journal, scoring or certification boundary is replaced.
    """
    execution = native_output(job, attempt)
    adopted = job.round.cpu_efficiency_adoption
    if adopted is None:
        return execution
    # The fixture submits the same inert model as its reference. Equal matched
    # durations therefore earn no placement-derived or artificial speed bonus.
    elapsed_ms = 200
    invocation = digest(attempt)
    ctx = context(memory_max_bytes=job.runtime.memory_bytes)
    assert len(ctx.cpu_ids) == job.runtime.cpus
    before = sample(ctx)
    finished = before.finished_us + elapsed_ms * 1000
    timing = CpuTimingEvidence(
        schema="umi-cpu-timing-evidence/1",
        contract_sha256=digest(adopted.adoption),
        context=ctx,
        bundle_cache=bundle_cache(
            model=execution.model_sha256,
            started=before.finished_us,
            invocation=invocation,
        ),
        conditions=conditions(
            ctx, started=before.finished_us, finished=finished, invocation=invocation
        ),
        before=before,
        after=sample(
            ctx,
            now=finished,
            ticks=100 + elapsed_ms // 10,
            busy=50 + elapsed_ms // 20,
            usage=elapsed_ms * 1000,
        ),
        started_monotonic_us=before.finished_us,
        model_started_monotonic_us=before.finished_us + 1,
        finished_monotonic_us=finished,
        launch_gate_elapsed_us=1,
    )
    return execution.model_copy(
        update={
            "schema_": "umi-offline-case-execution/2",
            "output": execution.output.model_copy(
                update={"elapsed_ms": elapsed_ms, "cpu_timing": timing}
            ),
        }
    )


async def test_six_cohorts_reuse_owners_and_recover_without_extensions(
    host, scenario, runtime, tmp_path, monkeypatch, chain_config
):
    o, h = host, host.h
    selected_series = canonical_json_bytes(o.config.series)
    authority = o.config.series.recovery.authority
    proposal = default_cpu_efficiency_proposal(
        policy=h.intake.policy,
        authority=authority,
        runtime_sha256=digest(runtime),
        issued_at_block=h.block,
        reason="Prospective C8-C10 synthetic host timing through the native series",
    )
    adoption = SignedCohortCpuEfficiencyAdoption(adoption=proposal, signatures=signatures(proposal))
    directory = tmp_path / "cpu-adoptions"
    publish_private_model(directory / (digest(authority) + ".json"), adoption)
    # The next configure_owner goes through validated ServiceAdmissionHost
    # startup and its ordinary immutable directory selection. C5-C7 deliberately
    # ignore the future contract while the same owners retain their old work.
    o.config = o.config.model_copy(update={"cpu_efficiency_adoptions_directory": str(directory)})
    monkeypatch.setattr(native_pipeline, "output", timed_output)
    base_routes = {name: tuple(app.router.routes) for name, app in o.apps.items()}
    packages = []
    for index, history in enumerate(scenario["histories"]):
        h.offline = False
        o.outages.clear()
        for name, routes in base_routes.items():
            o.apps[name].router.routes[:] = routes
        h.history, h.cohort = history, digest(history.plan)
        h.terms = h.terms_by_cohort[h.cohort]
        h.precommitted = h.catalogs[index], h.precommitted[1], h.precommitted[2]
        selected = select_scenario(scenario, history)
        mixed = history.plan.eligible_tracks == ("endpoint", "model")
        expected_recovered_jobs = sum(
            1 + int("endpoint" in prior.plan.eligible_tracks)
            for prior in scenario["histories"][: index + 1]
        )
        if index:
            for sequence in (1, 2):
                h.block += h.intake.policy.minimum_submission_interval_blocks
                request = model_request(selected, h.model, sequence=sequence, block=h.block)
                capture = h.capture(h.block)
                receipt = h.intake.retain(request, capture)
                h.queue.attach_evidence(
                    h.cohort,
                    receipt["proposed_admission"]["consent_sha256"],
                    *await h.provider.retained_archive(execution_boundary(capture)),
                )
        settled = await run_pipeline(
            o,
            selected,
            runtime,
            tmp_path,
            monkeypatch,
            chain_config,
            interrupt=index % 2 == 1,
            mixed=mixed,
            cohort_index=index,
            expected_recovered_jobs=expected_recovered_jobs,
            activate=False,
        )
        assert canonical_json_bytes(o.config.series) == selected_series
        assert settled.package.inputs.history.plan == history.plan
        assert all(
            t.transition.operation != "extend" for t in settled.package.inputs.history.transitions
        )
        round_ = settled.package.inputs.roster.round
        award = settled.package.allocation.model_award
        assert award is not None
        if history.plan.sequence < 8:
            assert round_.cpu_efficiency_adoption is None
            assert award.cpu_efficiency_adoption_sha256 is None
            assert all(candidate.cpu_efficiency is None for candidate in award.candidates)
        else:
            assert round_.cpu_efficiency_adoption == adoption
            assert award.cpu_efficiency_adoption_sha256 == digest(proposal)
            summaries = [candidate.cpu_efficiency for candidate in award.candidates]
            assert all(
                summary is not None
                and summary.multiplier_ppm == 1_000_000
                and len(summary.runs) == 2
                for summary in summaries
            )
            # Prospective economics consume the timing already certified in the
            # original package; do not rewrite its historical authority/allocation.
            original_package = canonical_json_bytes(settled.package)
            effective = derive_effective_reward_allocation(
                settled.package, cohort_reward_parameters(history.plan.sequence)
            )
            assert effective.schema_ == "umi-cohort-reward-allocation/6"
            assert effective.model_award.parameters.cpu_efficiency_rule is not None
            assert all(
                credit.efficiency_multiplier_ppm == 1_000_000
                for credit in effective.model_award.credits
            )
            assert canonical_json_bytes(settled.package) == original_package
        packages.append(settled.output.read_bytes())
        print({"cohort": history.plan.sequence, "status": "package_published"}, flush=True)
    assert len(set(packages)) == 6
