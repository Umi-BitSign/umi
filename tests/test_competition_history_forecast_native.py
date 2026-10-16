"""The actual native owner emits accounting without changing retained verdicts."""

import pytest

from umi.competition_forecast import ForecastLedger
from umi.competition_history_forecast import HistoryForecast

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
