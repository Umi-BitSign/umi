"""One configured C5-C10 series through native intake, rest and settlement.

The selected series uses a mixed C5 profile and model-only C6-C10 profiles. It reuses original
owner/evaluator journals across cohorts. Finality, inference, rights review and
HTTP remain the explicit ports of the connected pipeline. This does not establish
reward activation, coverage or installed chain effects.
"""

import pytest

from umi.competition_cohort_history import CohortRecoveryHistory
from umi.competition_cohort_recovery import (
    SignedCohortRecoveryAuthority,
    admit_recoverable_cohort,
)
from umi.competition_execution import execution_boundary
from umi.open_competition import digest, sign_object
from umi.protocol import canonical_json_bytes

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


async def test_six_cohorts_reuse_owners_and_recover_without_extensions(
    host, scenario, runtime, tmp_path, monkeypatch, chain_config
):
    o, h = host, host.h
    selected_series = canonical_json_bytes(o.config.series)
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
        packages.append(settled.output.read_bytes())
        print({"cohort": history.plan.sequence, "status": "package_published"}, flush=True)
    assert len(set(packages)) == 6
