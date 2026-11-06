"""Archived accounting can be restored without replay and after interrupted replacement."""

import hashlib
import json

import pytest

from umi import competition_forecast_snapshot as snapshots
from umi.competition_forecast import ForecastRepairRequired, restore_forecast_snapshot
from umi.competition_forecast_health import record_gap, write_health
from umi.competition_forecast_summary import ForecastSummary

from .test_competition_forecast_archive import historical as historical
from .test_competition_forecast_retention import opened
from .test_competition_forecast_segments import Remote


@pytest.fixture
def bundle(historical, tmp_path):
    remote = Remote()
    ledger = opened(tmp_path, remote)
    ledger.maintain_retention()
    ledger.append("new:start", "next", "scope_started", {"observed_unix_ms": 5000})
    snapshot = tmp_path / "snapshot"
    receipt = ledger.snapshot(snapshot)
    ledger.close()
    return remote, snapshot, receipt, original_pins(tmp_path)


def original_pins(tmp_path):
    return {
        argument: hashlib.sha256(
            (tmp_path / "legacy" / snapshots.FILES[key]).read_bytes()
        ).hexdigest()
        for key, argument in (
            ("forecasts.sqlite3", "damaged_sha256"),
            ("index.sqlite3", "damaged_index_sha256"),
            ("binding.json", "damaged_binding_sha256"),
        )
    }


def repair(tmp_path, bundle, **kwargs):
    remote, snapshot, receipt, pins = bundle
    kwargs = {**pins, **kwargs}
    return restore_forecast_snapshot(
        tmp_path / "legacy",
        snapshot,
        receipt,
        remote_store=remote,
        ledger_sha256="b" * 64,
        damaged_sha256=kwargs.pop("damaged_sha256", None),
        **kwargs,
    )


def damage(tmp_path, key, raw=b"damaged"):
    path = tmp_path / "legacy" / snapshots.FILES[key]
    path.write_bytes(raw)
    return hashlib.sha256(raw).hexdigest()


def test_restore_archived_scores_hot_tail_and_reuse_completed_work(
    bundle, historical, tmp_path, monkeypatch
):
    remote = bundle[0]
    pinned = damage(tmp_path, "forecasts.sqlite3")

    def no_replay(*args, **kwargs):
        raise AssertionError("restore must not replay archived events")

    monkeypatch.setattr(ForecastSummary, "accept", no_replay)
    assert repair(tmp_path, bundle, damaged_sha256=pinned)["status"] == "restored"
    assert remote.reads == 0
    monkeypatch.setattr(snapshots, "stream_file", no_replay)
    assert repair(tmp_path, bundle, damaged_sha256=pinned)["status"] == "already_restored"
    ledger = opened(tmp_path, remote)
    try:
        expected = historical[1]
        actual = ledger.status("a" * 64, observed_unix_ms=4000)
        for field in ("first_forecast_error_seconds", "completion_examples", "outcome"):
            assert actual[field] == expected[field]
        assert ledger.status("next", observed_unix_ms=6000)["outcome"] == "unfinished"
        assert not ledger.health["coverage_complete"]
        assert ledger.db.execute("SELECT COUNT(*) FROM events").fetchone() == (1,)
    finally:
        ledger.close()
    assert not (tmp_path / "legacy" / snapshots.INTENT).exists()
    assert not [p for p in (tmp_path / "legacy").glob("restore-*") if p.is_dir()]


@pytest.mark.parametrize("key", snapshots.FILES)
def test_missing_files_can_be_restored(bundle, tmp_path, key):
    (tmp_path / "legacy" / snapshots.FILES[key]).unlink()
    argument = {
        "forecasts.sqlite3": "damaged_sha256",
        "index.sqlite3": "damaged_index_sha256",
        "binding.json": "damaged_binding_sha256",
    }[key]
    assert repair(tmp_path, bundle, **{argument: None})["status"] == "restored"
    ledger = opened(tmp_path, bundle[0])
    ledger.close()


@pytest.mark.parametrize(
    "key,argument",
    [
        ("forecasts.sqlite3", "damaged_sha256"),
        ("index.sqlite3", "damaged_index_sha256"),
        ("binding.json", "damaged_binding_sha256"),
    ],
)
def test_damage_requires_exact_pin_and_preserves_original(bundle, tmp_path, key, argument):
    pinned = damage(tmp_path, key)
    with pytest.raises(ValueError, match="original identity changed"):
        repair(tmp_path, bundle)
    assert not (tmp_path / "legacy" / snapshots.INTENT).exists()
    assert repair(tmp_path, bundle, **{argument: pinned})["status"] == "restored"
    assert (tmp_path / "legacy" / (key + ".damaged-" + pinned)).read_bytes() == b"damaged"


@pytest.mark.parametrize("key", snapshots.FILES)
def test_changed_snapshot_refuses_before_replacing_any_original(bundle, tmp_path, key):
    (bundle[1] / key).write_bytes(b"corrupt snapshot")
    argument = {
        "forecasts.sqlite3": "damaged_sha256",
        "index.sqlite3": "damaged_index_sha256",
        "binding.json": "damaged_binding_sha256",
    }[key]
    bundle[3][argument] = damage(tmp_path, key)
    before = {k: (tmp_path / "legacy" / v).read_bytes() for k, v in snapshots.FILES.items()}
    with pytest.raises(ValueError, match="differs from its retained receipt"):
        repair(tmp_path, bundle)
    for k, v in snapshots.FILES.items():
        assert (tmp_path / "legacy" / v).read_bytes() == before[k]
    with pytest.raises(ForecastRepairRequired, match="restoration is unfinished"):
        opened(tmp_path, bundle[0])


def test_active_owner_and_pending_sqlite_recovery_refuse_repair(bundle, tmp_path):
    ledger = opened(tmp_path, bundle[0])
    try:
        with pytest.raises(BlockingIOError):
            repair(tmp_path, bundle)
    finally:
        ledger.close()
    journal = tmp_path / "legacy" / "forecasts.sqlite3-journal"
    journal.write_bytes(b"pending recovery")
    with pytest.raises(ValueError, match="pending SQLite"):
        repair(tmp_path, bundle)


@pytest.mark.parametrize("key", snapshots.FILES)
def test_crash_after_replace_before_checkpoint_resumes_without_recopies(
    bundle, tmp_path, monkeypatch, key
):
    target = tmp_path / "legacy" / snapshots.FILES[key]
    argument = {
        "forecasts.sqlite3": "damaged_sha256",
        "index.sqlite3": "damaged_index_sha256",
        "binding.json": "damaged_binding_sha256",
    }[key]
    bundle[3][argument] = damage(tmp_path, key)
    replace = snapshots.os.replace
    fired = False

    def interrupted(source, destination):
        nonlocal fired
        replace(source, destination)
        if destination == target and not fired:
            fired = True
            raise OSError("injected replacement interruption")

    monkeypatch.setattr(snapshots.os, "replace", interrupted)
    with pytest.raises(OSError, match="injected replacement"):
        repair(tmp_path, bundle)
    with pytest.raises(ForecastRepairRequired, match="restoration is unfinished"):
        opened(tmp_path, bundle[0])
    monkeypatch.setattr(snapshots.os, "replace", replace)
    stream = snapshots.stream_file

    def no_recopy(path, **kwargs):
        assert kwargs.get("destination") is None, "completed copies must be reused"
        return stream(path, **kwargs)

    monkeypatch.setattr(snapshots, "stream_file", no_recopy)
    assert repair(tmp_path, bundle)["status"] == "restored"
    assert bundle[0].reads == 0


def test_same_snapshot_supports_another_explicitly_pinned_repair(bundle, tmp_path):
    first = damage(tmp_path, "forecasts.sqlite3", b"first damage")
    repair(tmp_path, bundle, damaged_sha256=first)
    second = damage(tmp_path, "forecasts.sqlite3", b"second damage")
    assert repair(tmp_path, bundle, damaged_sha256=second)["status"] == "restored"
    assert len(list((tmp_path / "legacy").glob("*.completed.json"))) == 2


def test_restore_preserves_snapshot_gap_when_current_health_is_missing(historical, tmp_path):
    remote = Remote()
    ledger = opened(tmp_path, remote)
    ledger.maintain_retention()
    for _ in range(3):
        ledger.health = record_gap(ledger.health, reason="known_prior_gap", head=ledger.head)
    write_health(ledger.health_path, ledger.health)
    snapshot = tmp_path / "snapshot"
    receipt = ledger.snapshot(snapshot)
    ledger.close()
    (tmp_path / "legacy.health").unlink()
    repair(tmp_path, (remote, snapshot, receipt, original_pins(tmp_path)))
    ledger = opened(tmp_path, remote)
    try:
        assert ledger.health["gap_count"] >= receipt["accounting_health"]["gap_count"] + 1
        assert ledger.health["first_gap"] == receipt["accounting_health"]["first_gap"]
    finally:
        ledger.close()


def test_changed_repair_selection_is_refused(bundle, tmp_path, monkeypatch):
    original = snapshots._validate

    def interrupted(*args, **kwargs):
        raise OSError("before validation")

    monkeypatch.setattr(snapshots, "_validate", interrupted)
    with pytest.raises(OSError):
        repair(tmp_path, bundle)
    monkeypatch.setattr(snapshots, "_validate", original)
    path = tmp_path / "legacy" / snapshots.INTENT
    state = json.loads(path.read_bytes())
    state["selection"]["ledger_sha256"] = "c" * 64
    path.write_text(json.dumps(state))
    with pytest.raises(ValueError, match="selection or checkpoint"):
        repair(tmp_path, bundle)


def test_snapshot_of_unfinished_remote_publication_resumes(historical, tmp_path, monkeypatch):
    remote = Remote()
    ledger = opened(tmp_path, remote)
    publish = remote.put_bytes

    def unavailable(*args, **kwargs):
        raise OSError("offline")

    monkeypatch.setattr(remote, "put_bytes", unavailable)
    with pytest.raises(OSError):
        ledger.maintain_retention()
    snapshot = tmp_path / "snapshot"
    receipt = ledger.snapshot(snapshot)
    ledger.close()
    pins = original_pins(tmp_path)
    pins["damaged_index_sha256"] = damage(tmp_path, "index.sqlite3")
    repair(tmp_path, (remote, snapshot, receipt, pins))
    monkeypatch.setattr(remote, "put_bytes", publish)
    ledger = opened(tmp_path, remote)
    try:
        assert ledger.maintain_retention()
        assert ledger.db.execute("SELECT COUNT(*) FROM events").fetchone() == (0,)
        assert remote.uploads == 1
        assert ledger.status("a" * 64, observed_unix_ms=4000)["completion_examples"] == 1
    finally:
        ledger.close()


@pytest.mark.parametrize(
    "damage_sql",
    [
        "UPDATE archives SET receipt=NULL",
        "DELETE FROM summaries",
        "UPDATE archives SET last_sequence=3",
        "UPDATE summaries SET body=x'7b7d'",
    ],
)
def test_snapshot_refuses_damaged_retained_metadata(bundle, tmp_path, damage_sql):
    ledger = opened(tmp_path, bundle[0])
    try:
        with ledger.retention.index.db:
            ledger.retention.index.db.execute(damage_sql)
        with pytest.raises(ValueError):
            ledger.snapshot(tmp_path / "damaged-snapshot")
        assert not (tmp_path / "damaged-snapshot").exists()
        assert not list(tmp_path.glob("forecast-snapshot-*"))
    finally:
        ledger.close()


def test_snapshot_refuses_unfinished_index_migration(historical, tmp_path):
    ledger = opened(tmp_path, Remote())
    try:
        with pytest.raises(ValueError, match="migration pending"):
            ledger.snapshot(tmp_path / "snapshot")
    finally:
        ledger.close()
