import pytest

from umi.competition_dispatch import EndpointDispatchConfig, EndpointDispatcher
from umi.competition_dispatch_spool import DispatchSpoolConfig
from umi.protocol import canonical_json_bytes

from .test_competition_dispatch import authorization as authorization
from .test_competition_dispatch import dispatch as dispatch
from .test_competition_dispatch import ready
from .test_competition_feed import feed as feed
from .test_open_competition import policy as policy


def enable(dispatch, tmp_path, **limits):
    config = dispatch.config.model_copy(
        update={
            "transcript_spool": DispatchSpoolConfig(directory=str(tmp_path / "spool"), **limits)
        }
    )
    driver = EndpointDispatcher(
        config,
        dispatch.feed.journal,
        dispatch.provider,
        dispatch.feed.item.validator_wallet,
        transport=dispatch.driver.transport,
    )
    dispatch.driver = driver
    return driver


async def test_spool_recovers_actual_outcome_after_completion_write_failure(
    dispatch, tmp_path, monkeypatch
):
    driver = enable(dispatch, tmp_path)
    await ready(dispatch)
    original = dispatch.feed.journal.complete

    def fail(*a, **kw):
        raise OSError("synthetic disk failure")

    monkeypatch.setattr(dispatch.feed.journal, "complete", fail)
    assert await driver.dispatch_one(dispatch.key) == "uncertain"
    assert dispatch.feed.journal.status(dispatch.key)["state"] == "uncertain_dispatched"
    assert dispatch.miner.translator.calls == 1
    monkeypatch.setattr(dispatch.feed.journal, "complete", original)
    restarted = EndpointDispatcher(
        driver.config,
        dispatch.feed.journal,
        dispatch.provider,
        dispatch.feed.item.validator_wallet,
        transport=driver.transport,
    )
    assert restarted.spool.recover(dispatch.feed.journal) == 1
    assert dispatch.feed.journal.status(dispatch.key)["state"] == "completed"
    assert restarted.spool.recover(dispatch.feed.journal) == 0
    assert await restarted.dispatch_one(dispatch.key) == "held"
    assert dispatch.miner.translator.calls == 1
    assert (tmp_path / "spool" / "rounds.sqlite3").stat().st_mode & 0o077 == 0


async def test_intent_alone_never_authorizes_completion_or_resend(dispatch, tmp_path, monkeypatch):
    driver = enable(dispatch, tmp_path)
    await ready(dispatch)

    def fail(*a, **kw):
        raise OSError("synthetic spool outage after response")

    monkeypatch.setattr(driver.spool, "retain_outcome", fail)
    assert await driver.dispatch_one(dispatch.key) == "uncertain"
    assert driver.spool.recover(dispatch.feed.journal) == 0
    assert await driver.dispatch_one(dispatch.key) == "held"
    assert dispatch.miner.translator.calls == 1
    assert dispatch.feed.journal.status(dispatch.key)["state"] == "uncertain_dispatched"


async def test_capacity_exhaustion_stops_before_claim_or_request(dispatch, tmp_path):
    driver = enable(dispatch, tmp_path, maximum_bytes=1024)
    await ready(dispatch)
    assert await driver.dispatch_one(dispatch.key) == "held"
    assert dispatch.feed.journal.status(dispatch.key)["state"] == "published"
    assert dispatch.miner.translator.calls == 0


async def test_spool_rejects_changed_request_and_preserves_original(dispatch, tmp_path):
    driver = enable(dispatch, tmp_path)
    await ready(dispatch)
    assert await driver.dispatch_one(dispatch.key) == "completed"
    import json

    raw = dispatch.feed.journal.outcome(dispatch.key)
    doc = json.loads(raw)
    doc["request_hex"] = "00"
    with pytest.raises(ValueError, match="durable outbound intent"):
        driver.spool.retain_outcome(dispatch.key, canonical_json_bytes(doc))
    assert dispatch.feed.journal.outcome(dispatch.key) == raw


def test_legacy_config_does_not_gain_spool_bytes(dispatch):
    raw = canonical_json_bytes(dispatch.config)
    assert b"transcript_spool" not in raw
    assert canonical_json_bytes(EndpointDispatchConfig.model_validate_json(raw)) == raw


def test_spool_must_not_overlap_wallet_or_scheduling_state(dispatch):
    for directory in (dispatch.config.wallet_path, dispatch.config.journal_directory):
        config = dispatch.config.model_copy(
            update={"transcript_spool": DispatchSpoolConfig(directory=directory)}
        )
        with pytest.raises(ValueError, match="separate"):
            EndpointDispatchConfig.model_validate_json(canonical_json_bytes(config))
