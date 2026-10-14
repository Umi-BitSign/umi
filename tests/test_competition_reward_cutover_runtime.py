"""Real selected config/locks/journals; provider and review ports are synthetic."""

import asyncio
import fcntl
import json
import logging
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from umi import competition_reward_admission_provenance as provenance
from umi import competition_reward_cutover_cli as cli
from umi import competition_reward_cutover_ownership as ownership
from umi import competition_reward_cutover_runtime as runtime
from umi.competition_reward_control_journal import RewardControlTransactionJournal
from umi.competition_reward_decisions import StandingRewardControlReader
from umi.competition_reward_history import RewardControlHistoryReader
from umi.competition_reward_signing import RewardDecisionJournal
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from .test_competition_reward_coordinator_boot import chain as chain
from .test_competition_reward_coordinator_boot import chain_config as chain_config
from .test_competition_reward_coordinator_boot import config_case as config_case
from .test_competition_reward_coordinator_boot import control as control
from .test_competition_reward_coordinator_boot import inputs as inputs
from .test_competition_reward_coordinator_boot import policy as policy
from .test_competition_reward_coordinator_boot import series_case as series_case


def components(config):
    """Establish an installed fixture before testing a no-create owner."""
    root = Path(config.state_directory) / digest(config.series)
    root.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    root.mkdir(mode=0o700, exist_ok=True)
    chain = digest(config.chain)
    reader = StandingRewardControlReader(
        root / "control",
        config.series,
        config.policy,
        expected_series_sha256=digest(config.series),
        expected_chain_config_sha256=chain,
        maximum_bytes=config.maximum_reader_bytes,
        reward_adoptions=config.reward_adoptions,
    )
    history = RewardControlHistoryReader(
        root / "history",
        control_hotkey=config.series.control_hotkey,
        chain_config_sha256=chain,
        first_block=config.series.recovery.authority.issued_at_block,
        maximum_bytes=config.maximum_history_bytes,
    )
    decisions = RewardDecisionJournal(
        root / "decisions",
        config.series,
        config.policy,
        config.signer_hotkey,
        expected_chain_config_sha256=chain,
        maximum_bytes=config.service.maximum_journal_bytes,
        reward_adoptions=config.reward_adoptions,
    )
    transactions = RewardControlTransactionJournal(
        root / "transactions",
        config.series,
        config_sha256=chain,
        maximum_bytes=config.service.maximum_journal_bytes,
    )
    for path in (
        root / "service.lock",
        root.parent / "control-writer.lock",
        root / "transactions/control-writer.lock",
    ):
        path.touch(mode=0o600, exist_ok=True)
    return root, reader, history, decisions, transactions


@pytest.fixture
def original_selection(config_case, monkeypatch, tmp_path):
    config = config_case.config
    # Capture configuration identity through the real provenance file reader.
    # Substitute only root/kernel selection ports, never the digest convention.
    monkeypatch.setattr(provenance, "_ROOT_UID", os.getuid())
    monkeypatch.setattr(provenance, "_TRUST_ROOT", tmp_path)
    raw, bound = provenance._read_root(config_case.path, 8 * 1024**2, modes={0o444})
    assert raw == canonical_json_bytes(config)
    assert bound["sha256"] != digest(config)
    selection = {
        "owner_uid": os.getuid(),
        "paths": {"service_root": str(Path(config.state_directory) / digest(config.series))},
        "series_sha256": digest(config.series),
        "policy_sha256": digest(config.policy),
        "chain_config_sha256": digest(config.chain),
        "configuration": bound,
    }
    monkeypatch.setattr(ownership, "load_provenance", lambda _: selection)
    monkeypatch.setattr(ownership, "validate_provenance", lambda *a, **k: None)
    return selection


def test_captured_config_file_hash_preserves_native_lease_identity(config_case, original_selection):
    config = config_case.config
    components(config)
    for _ in range(2):
        with ownership.hold_reward_cutover_owner(
            config, original_owner_selection=Path("fixture")
        ) as lease:
            assert lease.config_sha256 == digest(config)
            assert lease.config_sha256 != original_selection["configuration"]["sha256"]
            lease.recheck(config)
            changed = config.model_copy(
                update={"maximum_header_bytes": config.maximum_header_bytes + 1}
            )
            with pytest.raises(ValueError, match="live coordinator"):
                lease.recheck(changed)


@pytest.mark.parametrize("change", ["domain_digest", "history_capacity", "other_field"])
def test_changed_original_config_refused_before_state(
    config_case, original_selection, monkeypatch, change
):
    config = config_case.config
    if change == "domain_digest":
        original_selection["configuration"]["sha256"] = digest(config)
    elif change == "history_capacity":
        config = config.model_copy(update={"maximum_history_bytes": 64 * 1024**3})
    else:
        config = config.model_copy(update={"maximum_header_bytes": config.maximum_header_bytes + 1})
    monkeypatch.setattr(ownership, "_existing", lambda *a, **k: pytest.fail("state inspected"))
    with (
        pytest.raises(ValueError, match="selected original owner"),
        ownership.hold_reward_cutover_owner(config, original_owner_selection=Path("fixture")),
    ):
        pytest.fail("changed original selected")


@pytest.mark.parametrize("which", [0, 1, 2])
def test_existing_process_lock_contention_does_not_open_old_state(config_case, which):
    config = config_case.config
    root, *_ = components(config)
    paths = (
        root / "service.lock",
        root.parent / "control-writer.lock",
        root / "transactions/control-writer.lock",
    )
    before = {p: p.stat().st_ino for p in root.rglob("rounds.sqlite3")}
    fd = os.open(paths[which], os.O_RDWR)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(BlockingIOError), ownership.hold_reward_cutover_owner(config):
            pytest.fail("busy owner entered")
    finally:
        os.close(fd)
    assert before == {p: p.stat().st_ino for p in root.rglob("rounds.sqlite3")}
    with ownership.hold_reward_cutover_owner(config) as lease:
        lease.recheck(config)
        # Native compound locks remain usable while all process owners are fenced.
        for _, journal in (
            ("history", components(config)[2]),
            ("decisions", components(config)[3]),
        ):
            with journal.journal.locked():
                pass


def test_missing_state_refused_without_recreation_and_closed_lease_invalid(config_case):
    config = config_case.config
    root, *_ = components(config)
    with ownership.hold_reward_cutover_owner(config) as lease:
        lease.recheck(config)
    with pytest.raises(ValueError, match="live coordinator"):
        lease.recheck(config)
    missing = root / "decisions/rounds.sqlite3"
    missing.unlink()
    with pytest.raises(FileNotFoundError), ownership.hold_reward_cutover_owner(config):
        pytest.fail("missing original accepted")
    assert not missing.exists()


def test_replaced_path_and_forged_lease_rejected(config_case):
    config = config_case.config
    root, *_ = components(config)
    with ownership.hold_reward_cutover_owner(config) as lease:
        with pytest.raises(ValueError, match="live coordinator"):
            ownership.RewardCutoverLease(root, digest(config), {}, (), None).recheck(config)
        old = root / "service.lock"
        old.rename(root / "old-lock")
        old.touch(mode=0o600)
        with pytest.raises(ValueError, match=r"identity changed|lock was replaced"):
            lease.recheck(config)


@pytest.mark.parametrize("mode", ["success", "error", "cancel", "progress"])
@pytest.mark.parametrize("capacity", [False, True])
@pytest.mark.parametrize("migrated_origin", [False, True])
async def test_runtime_cleanup_is_inside_genuine_lease_no_publishing(
    config_case, original_selection, monkeypatch, mode, capacity, migrated_origin, tmp_path
):
    config = config_case.config
    selected_path = None
    if capacity:
        selected_path = tmp_path / "capacity.json"
        config_case.save(
            selected_path,
            canonical_json_bytes(config.model_copy(update={"maximum_history_bytes": 64 * 1024**3})),
        )
    root, *_ = components(config)
    events, started = [], asyncio.Event()
    origin_path = tmp_path / "origin.json" if migrated_origin else None

    def migrated(history, lease, path):
        lease.recheck(config)
        assert path == origin_path and lease.provenance == original_selection
        assert history.journal.root == root / "history"
        events.append("selected_migration")
        return {"origin_sha256": "a1" * 32}

    monkeypatch.setattr(runtime, "_original_export_migration_selection", migrated)

    def locked():
        with pytest.raises(BlockingIOError), ownership.hold_reward_cutover_owner(config):
            pytest.fail("owner lost")

    class Provider:
        def __init__(self, *args, **kwargs):
            locked()
            events.append("construct")
            self.config = config.chain

        async def start(self):
            locked()
            events.append("start")

        def ensure_observer_running(self):
            locked()

        async def current_finalized_block(self):
            return config.chain.minimum_finalized_block

    class Review:
        def __init__(self, **kwargs):
            kwargs["lease"].recheck(config)
            assert type(kwargs["history"]) is RewardControlHistoryReader
            assert kwargs["history"].journal.maximum_bytes == (
                64 * 1024**3 if capacity else config.maximum_history_bytes
            )
            assert kwargs["provider"].__class__ is Provider
            assert kwargs["history_origin_sha256"] == ("a1" * 32 if migrated_origin else None)

        async def step(self, cohort):
            locked()
            started.set()
            events.append("review")
            if mode == "progress" and events.count("review") == 1:
                return {"status": "historical_recovery_progress", "publication_authorized": False}
            if mode == "cancel":
                await asyncio.Event().wait()
            if mode == "error":
                raise ValueError("synthetic review failure")
            return {"status": "reconciled", "publication_authorized": False}

    async def close(provider):
        locked()
        events.append("closed")

    monkeypatch.setattr(runtime, "HistoricalRewardControlProvider", Provider)
    monkeypatch.setattr(runtime, "NativeRewardCutoverReview", Review)
    monkeypatch.setattr(runtime, "_close_provider", close)
    work = asyncio.create_task(
        runtime.reconcile_reward_cutover(
            config_case.path,
            cohort=digest(config.series.cohorts[0]),
            operation="fixture-v1",
            history_capacity_config=selected_path,
            original_owner_selection=Path("fixture-only.json") if migrated_origin else None,
            original_export_origin=origin_path,
        )
    )
    if mode == "cancel":
        await started.wait()
        work.cancel()
        with pytest.raises(asyncio.CancelledError):
            await work
    elif mode == "error":
        with pytest.raises(ValueError, match="synthetic"):
            await work
    else:
        result = await work
        assert not result["publication_authorized"]
        assert not result["publishing_roles_started"]
        assert not result["service_restart_performed"]
        if capacity:
            assert result["history_capacity_selection"]["original_config_sha256"] == digest(config)
            assert (
                result["history_capacity_selection"]["selected_maximum_history_bytes"]
                == 64 * 1024**3
            )
        else:
            assert result["history_capacity_selection"] is None
    assert events == [
        *(["selected_migration"] if migrated_origin else []),
        "construct",
        "start",
        "review",
        *(["review"] if mode == "progress" else []),
        "closed",
    ]
    with ownership.hold_reward_cutover_owner(config):
        pass
    assert not (root / "transactions").joinpath("signed").exists()


async def test_original_missing_migration_fails_before_provider(
    config_case, original_selection, monkeypatch
):
    config = config_case.config
    components(config)
    selection = original_selection
    monkeypatch.setattr(
        runtime,
        "HistoricalRewardControlProvider",
        lambda *a, **k: pytest.fail("provider opened before migration"),
    )
    with pytest.raises(ValueError, match="completed-admission migration"):
        await runtime.reconcile_reward_cutover(
            config_case.path,
            cohort=digest(config.series.cohorts[0]),
            operation="fixture-v1",
            original_owner_selection=Path("fixture-only.json"),
        )
    selection["configuration"]["sha256"] = "00" * 32
    with (
        pytest.raises(ValueError, match="selected original owner"),
        ownership.hold_reward_cutover_owner(config, original_owner_selection=Path("fixture")),
    ):
        pytest.fail("changed configuration accepted")


@pytest.mark.parametrize("change", ["equal", "decrease", "other_limit", "state", "noncanonical"])
async def test_capacity_selection_refuses_changes_before_owner_or_provider(
    config_case, monkeypatch, tmp_path, change
):
    config = config_case.config
    updated = {"maximum_history_bytes": 64 * 1024**3}
    if change == "equal":
        updated["maximum_history_bytes"] = config.maximum_history_bytes
    elif change == "decrease":
        updated["maximum_history_bytes"] = config.maximum_history_bytes - 1
    elif change == "other_limit":
        updated["maximum_header_bytes"] = config.maximum_header_bytes + 1
    elif change == "state":
        updated["state_directory"] = str(tmp_path / "different-owner")
    raw = canonical_json_bytes(config.model_copy(update=updated))
    selected = tmp_path / "capacity.json"
    config_case.save(selected, b" " + raw if change == "noncanonical" else raw)
    monkeypatch.setattr(
        runtime, "hold_reward_cutover_owner", lambda *a, **k: pytest.fail("owner opened")
    )
    with pytest.raises(ValueError, match=r"only increase history|not canonical"):
        await runtime.reconcile_reward_cutover(
            config_case.path,
            cohort=digest(config.series.cohorts[0]),
            operation="fixture-v1",
            history_capacity_config=selected,
        )


async def test_capacity_selection_keeps_original_provenance_and_requires_migration(
    config_case, original_selection, monkeypatch, tmp_path
):
    config = config_case.config
    components(config)
    selected = tmp_path / "capacity.json"
    config_case.save(
        selected,
        canonical_json_bytes(config.model_copy(update={"maximum_history_bytes": 64 * 1024**3})),
    )
    monkeypatch.setattr(
        runtime, "HistoricalRewardControlProvider", lambda *a, **k: pytest.fail("provider opened")
    )
    with pytest.raises(ValueError, match="completed-admission migration"):
        await runtime.reconcile_reward_cutover(
            config_case.path,
            cohort=digest(config.series.cohorts[0]),
            operation="fixture-v1",
            original_owner_selection=Path("fixture-only.json"),
            history_capacity_config=selected,
        )
    assert runtime.load_reward_coordinator_config(config_case.path) == config


def test_cli_only_reports_error_type(config_case, monkeypatch, capsys):
    async def fail(_):
        raise ValueError("wss://private.example/?credential=do-not-print")

    monkeypatch.setattr(cli, "_run", fail)
    with pytest.raises(SystemExit):
        cli.main(
            ["--config", str(config_case.path), "--cohort", "aa" * 32, "--operation", "fixture-v1"]
        )
    value = json.loads(capsys.readouterr().out)
    assert value == {
        "status": "repair_required",
        "error_type": "ValueError",
        "publication_authorized": False,
    }


def test_cli_interruption_is_not_reported_as_success(monkeypatch, capsys):
    async def interrupted(_):
        return None

    monkeypatch.setattr(cli, "_run", interrupted)
    with pytest.raises(SystemExit) as result:
        cli.main(["--config", "/fixture/config", "--cohort", "aa" * 32, "--operation", "fixture"])
    assert result.value.code == 130
    assert json.loads(capsys.readouterr().out)["status"] == "interrupted"


def test_cli_selects_capacity_control_without_replacing_original_config(monkeypatch, capsys):
    observed = []

    async def reconcile(path, **kwargs):
        observed.append((path, kwargs))
        return {"status": "reconciled", "publication_authorized": False}

    monkeypatch.setattr(cli, "reconcile_reward_cutover", reconcile)
    cli.main(
        [
            "--config",
            "/fixture/original.json",
            "--cohort",
            "aa" * 32,
            "--operation",
            "fixture",
            "--original-owner-selection",
            "/fixture/owner.json",
            "--history-capacity-config",
            "/fixture/capacity64.json",
        ]
    )
    assert observed == [
        (
            Path("/fixture/original.json"),
            {
                "cohort": "aa" * 32,
                "operation": "fixture",
                "original_owner_selection": Path("/fixture/owner.json"),
                "original_export_origin": None,
                "history_capacity_config": Path("/fixture/capacity64.json"),
                "bootstrap_manifest": None,
            },
        )
    ]
    assert not json.loads(capsys.readouterr().out)["publication_authorized"]


async def test_initial_finality_retries_only_missing_head_and_keeps_selected_budget(
    monkeypatch, caplog
):
    caplog.set_level(logging.INFO, logger=runtime.__name__)
    config = SimpleNamespace(minimum_finalized_block=5, startup_timeout_seconds=1800)
    calls = []

    async def observed():
        calls.append("observed")
        if len(calls) == 1:
            raise runtime.GrandpaFinalitySupervisorError("no_verified_finalized_head")
        return 5

    async def pause(_):
        pass

    monkeypatch.setattr(runtime.asyncio, "sleep", pause)
    provider = SimpleNamespace(
        config=config,
        ensure_observer_running=lambda: None,
        current_finalized_block=observed,
    )
    assert await runtime._await_initial_finality(provider) == 5
    assert len(calls) == 2
    events = [r.args for r in caplog.records if r.msg == "reward_cutover_initial_finality %s"]
    assert [v["state"] for v in events] == ["pending", "completed"]
    assert events[-1]["eta_seconds"] == 0 and events[-1]["percent"] == 100

    async def corrupt():
        raise runtime.GrandpaFinalitySupervisorError("fixture_corrupt_history")

    provider.current_finalized_block = corrupt
    with pytest.raises(runtime.GrandpaFinalitySupervisorError):
        await runtime._await_initial_finality(provider)


async def test_original_export_requires_explicit_owner_before_config(monkeypatch):
    monkeypatch.setattr(
        runtime, "load_reward_coordinator_config", lambda *a: pytest.fail("opened config")
    )
    with pytest.raises(ValueError, match="requires its original owner"):
        await runtime.reconcile_reward_cutover(
            Path("unused"),
            cohort="a1" * 32,
            operation="fixture",
            original_export_origin=Path("origin.json"),
        )
