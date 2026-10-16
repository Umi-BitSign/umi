"""The actual native owner emits accounting without changing retained verdicts."""

from contextlib import ExitStack
from types import SimpleNamespace

import pytest

from umi import competition_history_forecast as forecast_module
from umi import competition_reward_history_progress as progress_module
from umi.competition_forecast import ForecastLedger
from umi.competition_history_forecast import HistoryForecast
from umi.open_competition import digest

from .test_competition_reward_history import chain as chain
from .test_competition_reward_history import chain_config as chain_config
from .test_competition_reward_history import control as control
from .test_competition_reward_history import historical as historical
from .test_competition_reward_history import history_case as history_case
from .test_competition_reward_history import policy as policy
from .test_competition_reward_history import series_case as series_case

pytestmark = pytest.mark.parametrize("historical", ["exact_runtime"], indirect=True)


def attach(reader, ledger):
    reader.progress.forecast = HistoryForecast(
        ledger,
        {
            "chain_config_sha256": reader.config_sha256,
            "first_block": reader.first_block,
            "checkpoint_owner": reader.checkpoints.owner,
            "verifier_semantics": reader.checkpoints.semantics,
        },
    )


async def test_native_restart_preserves_issued_forecasts_and_reuses_completed_proofs(
    history_case, tmp_path, monkeypatch
):
    h = history_case
    directory = tmp_path / "native-forecast"
    ledger = ForecastLedger(directory)
    attach(h.reader, ledger)
    result = await h.reader.advance(h.item.provider, through_block=h.end, maximum_blocks=2)
    assert result.history is None
    scope = h.reader.progress.forecast.scope
    before = ledger.records(scope)
    original_owner = h.reader.checkpoints.owner
    ledger.close()
    h.offline_through = result.next_block - 1
    h.reader = await h.restart()
    ledger = ForecastLedger(directory)
    attach(h.reader, ledger)
    try:
        load = h.reader._load

        def new_sources_only(height):
            if height <= h.offline_through:
                pytest.fail("unchanged native proof was read again")
            return load(height)

        monkeypatch.setattr(h.reader, "_load", new_sources_only)
        completed = await h.reader.advance(h.item.provider, through_block=h.end)
        assert completed.history is not None
        assert h.reader.checkpoints.owner == original_owner
        assert h.reader.progress.forecast.scope == scope
        records = ledger.records(scope)
        assert records[: len(before)] == before
        assert ledger.status(scope)["completion_examples"] == 1
        assert h.reader.progress.latest["restored_completed"] == 2
        await h.reader.advance(h.item.provider, through_block=h.end)
        assert ledger.status(scope)["completion_examples"] == 1
    finally:
        ledger.close()


async def test_native_error_is_retained_without_replacing_owner_error(
    history_case, tmp_path, monkeypatch
):
    h = history_case
    ledger = ForecastLedger(tmp_path / "native-forecast")
    attach(h.reader, ledger)
    original = h.reader._advance
    failure = OSError("retained test failure")

    async def fail(*args, **kwargs):
        raise failure

    try:
        monkeypatch.setattr(h.reader, "_advance", fail)
        with pytest.raises(OSError) as caught:
            await h.reader.advance(h.item.provider, through_block=h.end)
        assert caught.value is failure
        scope = h.reader.progress.forecast.scope
        record = ledger.records(scope)[-1]
        assert record["native_progress"]["state"] == "retrying"
        assert record["native_progress"]["error_type"] == "OSError"
        assert ledger.status(scope)["outcome"] == "unfinished"
        monkeypatch.setattr(h.reader, "_advance", original)
        assert (await h.reader.advance(h.item.provider, through_block=h.end)).history is not None
        assert ledger.status(scope)["completion_examples"] == 1
    finally:
        ledger.close()


async def test_selected_native_owner_emits_qualified_originals_across_restart(
    history_case, tmp_path, monkeypatch
):
    h = history_case
    now = [100.0]
    monkeypatch.setattr(progress_module, "time", SimpleNamespace(monotonic=lambda: now[0]))
    monkeypatch.setattr(
        forecast_module, "time", SimpleNamespace(time_ns=lambda: int(now[0] * 10**9))
    )
    config = SimpleNamespace(
        series=h.c.series,
        policy=h.item.policy,
        service={"fixture": "native-control-history"},
        eligibility=None,
        runtime_adoptions=(),
        runtime_proof_reads=True,
        forecast_accounting_bytes=1024**2,
    )

    def select(resources):
        forecast_module.select_history_forecasts(
            h.reader,
            root=tmp_path / "selected-owner",
            config=config,
            resources=resources,
            role="reward_writer",
        )
        native_finished = h.reader.progress.native_finished

        def counted(height):
            now[0] += 1
            native_finished(height)

        monkeypatch.setattr(h.reader.progress, "native_finished", counted)
        return h.reader.progress.forecast.ledger

    with ExitStack() as resources:
        ledger = select(resources)
        partial = await h.reader.advance(h.item.provider, through_block=h.end, maximum_blocks=3)
        scope = h.reader.progress.forecast.scope
        before = ledger.records(scope)
        original = ledger.status(scope)["original_point_comparison"]
        assert original is not None
        assert original["forecast_origin"] == "prospective"
        assert original["population_qualified"] is True
        assert original["outcome_unit_identity"] == scope
        assert original["correlation_group_identity"] == digest(h.c.series)
        population = original["comparison_population_sha256"]
        assert original["comparison_population"]["policy_sha256"] == digest(h.item.policy)
        assert (
            original["comparison_population"]["verifier_semantics"]
            == h.reader.checkpoints.semantics
        )
    h.offline_through = partial.next_block - 1
    h.reader = await h.restart()
    now[0] += 100  # Downtime is part of the realized error, never erased by restart.
    with ExitStack() as resources:
        ledger = select(resources)
        load = h.reader._load

        def new_sources_only(height):
            if height <= h.offline_through:
                pytest.fail("native forecast upgrade reread unchanged proof")
            return load(height)

        monkeypatch.setattr(h.reader, "_load", new_sources_only)
        outcome = await h.reader.advance(h.item.provider, through_block=h.end)
        assert outcome.history is not None
        assert h.reader.progress.forecast.scope == scope
        assert ledger.records(scope)[: len(before)] == before
        result = ledger.status(scope)["original_point_comparison"]
        assert result["comparison_population_sha256"] == population
        assert result["forecast_identity"] == original["forecast_identity"]
        assert result["empirical_eligible"] is True
        assert result["point_error_range_seconds"][0] > 90
        assert h.reader.progress.latest["restored_completed"] == 3
        report = ledger.calibration_report(population, metric="point")
        assert report["eligible_completed_correlation_groups"] == 1
        assert report["independent_runs_established"] is False
        assert report["prospective_eta_correction_selected"] is False
