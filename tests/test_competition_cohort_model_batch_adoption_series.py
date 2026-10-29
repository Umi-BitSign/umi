"""Automatic successor adoption resumes the same signed jobs and repairs delivery."""

from dataclasses import replace
from pathlib import Path

import pytest

from umi import competition_cohort_model_batch_adoption_operator as operator
from umi import competition_cohort_model_batch_adoption_series as series

from .test_competition_cohort_model_batch_adoption import adoption as adoption
from .test_competition_cohort_model_batch_adoption import adoption_operator as adoption_operator
from .test_competition_cohort_model_batch_adoption import base_policy as base_policy
from .test_competition_cohort_model_batch_adoption import legacy_scenario as legacy_scenario
from .test_competition_cohort_model_batch_adoption import policy as policy
from .test_competition_cohort_model_batch_adoption import prepared as prepared
from .test_competition_cohort_model_batch_adoption import receipt_scenario as receipt_scenario
from .test_competition_cohort_model_batch_adoption import recovery as recovery
from .test_competition_cohort_model_batch_adoption import reviews as reviews
from .test_competition_cohort_model_batch_adoption import runtime as runtime

pytestmark = [
    pytest.mark.parametrize("receipt_scenario", ["model-awards"], indirect=True),
    pytest.mark.parametrize("recovery", ["legacy7"], indirect=True),
]


@pytest.fixture
def series_job(adoption_operator, tmp_path, monkeypatch):
    o = adoption_operator
    config = series.ModelBatchAdoptionSeriesConfig(
        schema="umi-model-batch-adoption-series/1",
        state_directory=str(tmp_path / "series"),
        policy_file=o.config.policy_file,
        histories_directory=str(tmp_path / "histories"),
        standing_operator_request_reference=o.config.operator_request_reference,
        owner=o.config.owner,
        reviewers=o.config.reviewers,
    )
    selected = {t.target.service_unit: t for t in o.selected}
    monkeypatch.setattr(series, "load_adoption_target", lambda t: selected[t.service_unit])

    async def run_job(job, policy, history, *, client):
        return await operator.run_model_batch_adoption(
            job,
            policy,
            history,
            client=client,
            publish=o.publish,
            peer_factory=o.peer_factory,
        )

    async def run(*, read_history=True):
        def load_history(path):
            assert read_history, "completed jobs must not reload the mutable source history"
            assert path.name == o.a.r.cohort + ".json"
            return o.a.history

        return await series.run_model_batch_adoption_series(
            config,
            o.a.policy,
            client=None,
            run_job=run_job,
            load_history=load_history,
            select=lambda t: selected[t.service_unit],
            publish=o.publish,
        )

    return o, config, run


async def test_series_automatically_materializes_future_job_and_reuses_signed_completion(
    series_job,
):
    o, config, run = series_job
    first = await run()
    assert first["status"] == "complete"
    assert first["completed"] == first["total"] == 1
    assert first["intake_closure_authorized"] is False
    assert (Path(config.state_directory) / o.a.r.cohort / "history.json").exists()
    before = list(o.state.calls)
    second = await run(read_history=False)
    assert second["cohorts"][0]["status"] == "reused"
    assert o.state.calls == before


async def test_series_mixed_C5_C6_C7_selection_never_loads_excluded_histories(
    series_job, monkeypatch
):
    o, config, _ = series_job
    original = o.selected[0]
    binding = original.cohorts[0]
    owner = replace(
        original,
        cohorts=(
            binding.model_copy(update={"cohort_sha256": "05" * 32}),
            binding.model_copy(update={"cohort_sha256": "06" * 32}),
            *original.cohorts,
        ),
        cohort_sequences=(
            ("04" * 32, 4),
            ("05" * 32, 5),
            ("06" * 32, 6),
            *original.cohort_sequences,
        ),
    )
    targets = {t.target.service_unit: t for t in (owner, *o.selected[1:])}
    monkeypatch.setattr(series, "load_adoption_target", lambda t: targets[t.service_unit])
    histories = []

    def load_history(path):
        histories.append(path.name)
        assert path.name == o.a.r.cohort + ".json"
        return o.a.history

    async def run_job(job, policy, history, *, client):
        return await operator.run_model_batch_adoption(
            job, policy, history, client=client, publish=o.publish, peer_factory=o.peer_factory
        )

    async def run():
        return await series.run_model_batch_adoption_series(
            config,
            o.a.policy,
            client=None,
            run_job=run_job,
            load_history=load_history,
            select=lambda t: targets[t.service_unit],
            publish=o.publish,
        )

    first = await run()
    before = list(o.state.calls)
    second = await run()
    assert first["completed"] == second["completed"] == first["total"] == 1
    assert second["cohorts"][0]["status"] == "reused"
    assert histories == [o.a.r.cohort + ".json"]
    assert o.state.calls == before


async def test_series_missing_service_selection_repairs_exact_file_without_resigning(series_job):
    o, _, run = series_job
    await run()
    target = o.selected[1].directory / (o.a.r.cohort + ".json")
    original = target.read_bytes()
    target.unlink()
    before = list(o.state.calls)
    result = await run(read_history=False)
    assert result["status"] == "complete"
    assert result["cohorts"][0]["status"] == "repaired"
    assert result["cohorts"][0]["restored_selected_consumers"] == 1
    assert target.read_bytes() == original
    assert o.state.calls == before


@pytest.mark.parametrize("lost", ["signed.json", "history.json"])
async def test_series_missing_operator_evidence_is_not_a_new_job(series_job, lost):
    o, config, run = series_job
    await run()
    (Path(config.state_directory) / o.a.r.cohort / lost).unlink()
    before = list(o.state.calls)
    result = await run(read_history=False)
    assert result["status"] == "pending"
    assert result["pending"] == 1
    assert "repair_required" in result["cohorts"][0]["reason_code"]
    assert o.state.calls == before


def test_series_materializer_preserves_earlier_cohorts(adoption_operator):
    o = adoption_operator
    config = series.ModelBatchAdoptionSeriesConfig(
        schema="umi-model-batch-adoption-series/1",
        state_directory=o.config.state_directory,
        policy_file=o.config.policy_file,
        histories_directory=str(o.a.r.root / "histories"),
        standing_operator_request_reference=o.config.operator_request_reference,
        minimum_cohort_sequence=8,
        owner=o.config.owner,
        reviewers=o.config.reviewers,
    )
    assert series.materialize_model_batch_adoption_job(config, o.a.history, o.a.policy) is None
