"""Durable installed selection joined to the native legacy writer handoff.

The host seal/container, root approval ownership and completed C5 proof/replay
ports are fixture substitutions inherited from the handoff tests. SQL storage,
old writer locks, journal identity, crash ordering and restart are real.
"""

import asyncio
import logging
import os
import shutil
import threading
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from umi import competition_host_activation as activation
from umi import competition_reward_host as host
from umi import competition_reward_service as service
from umi.competition_reward_control_archive import HistoricalRewardControlProvider
from umi.competition_reward_handoff import hold_legacy_reward_handoff
from umi.competition_reward_history import RewardControlHistoryReader
from umi.competition_reward_host import StandingRewardHostApproval, bind_standing_reward_host
from umi.competition_reward_service import StandingRewardServiceLimits, run_standing_reward_service
from umi.competition_reward_transactions import StandingWeightJournal
from umi.competition_round_journal import RoundJournal
from umi.open_competition import digest
from umi.private_files import lock_private_file
from umi.protocol import canonical_json_bytes

from .reward_service_execution_fixture import connect_executor
from .test_competition_reward_handoff import (
    adapter_case as adapter_case,
)
from .test_competition_reward_handoff import assert_locked, signed_attempt
from .test_competition_reward_handoff import (
    chain as chain,
)
from .test_competition_reward_handoff import (
    chain_config as chain_config,
)
from .test_competition_reward_handoff import (
    control as control,
)
from .test_competition_reward_handoff import (
    migration as migration,
)
from .test_competition_reward_handoff import (
    package_case as package_case,
)
from .test_competition_reward_handoff import (
    package_limits as package_limits,
)
from .test_competition_reward_handoff import (
    policy as policy,
)
from .test_competition_reward_handoff import (
    release_identity as release_identity,
)
from .test_competition_reward_handoff import (
    replay_limits as replay_limits,
)
from .test_competition_reward_handoff import (
    series_case as series_case,
)
from .test_competition_reward_handoff import (
    successor_case as successor_case,
)
from .test_competition_reward_handoff import (
    successor_chain as successor_chain,
)
from .test_competition_reward_handoff import (
    successor_release as successor_release,
)
from .test_competition_reward_handoff import (
    v3_predecessor as v3_predecessor,
)
from .test_competition_reward_handoff import (
    weight_case as weight_case,
)
from .test_competition_reward_handoff import (
    worker_capacity as worker_capacity,
)
from .test_signed_extrinsic_native import native_encoding as native_encoding


@pytest.fixture
async def installed(migration, monkeypatch, tmp_path):
    c = migration
    c.installation.host_manifest_sha256 = "55" * 32
    c.preparation.policy_sha256 = c.series.policy_sha256
    c.preparation.manifest = {"fixture": "completed replay selection"}
    c.preparation.reader.chain_config_sha256 = digest(c.item.config)
    c.preparation._authority = lambda: None
    c.approval = StandingRewardHostApproval(
        schema="umi-standing-reward-host-approval/1",
        source_config_sha256=digest(c.config),
        installation_receipt_sha256=c.installation.receipt_sha256,
        host_manifest_sha256=c.installation.host_manifest_sha256,
        validator_hotkey=c.config.validator_hotkey,
        series_sha256=c.preparation.series_sha256,
        policy_sha256=c.preparation.policy_sha256,
        manifest_sha256=digest(c.preparation.manifest),
        chain_config_sha256=c.preparation.reader.chain_config_sha256,
        legacy_handoff_plan_sha256=digest(c.plan),
    )
    c.approval_path = tmp_path / "standing-approval.json"

    def publish(raw):
        if c.approval_path.exists():
            c.approval_path.chmod(0o600)
        c.approval_path.write_bytes(raw)
        c.approval_path.chmod(0o444)

    c.publish = publish
    c.publish(canonical_json_bytes(c.approval))
    monkeypatch.setattr(activation, "_root_owner_uid", os.getuid)
    c.bind = lambda runtime, handoff: bind_standing_reward_host(
        runtime,
        approval_path=c.approval_path,
        preparation=c.preparation,
        first=c.prepared,
        handoff=handoff,
        maximum_journal_bytes=128 * 1024**2,
    )
    c.check = lambda bound: bound.recheck(
        journal=bound.journal,
        preparation=c.preparation,
        first=c.prepared,
        handoff=bound._handoff,
    )
    return c


async def test_binding_reopens_original_journal_after_restart(installed):
    c = installed
    identities = []
    for _ in range(2):
        async with c.reopen() as runtime, hold_legacy_reward_handoff(runtime, **c.args) as handoff:
            bound = c.bind(runtime, handoff)
            c.check(bound)
            identities.append(bound._retained)
            assert (
                bound.journal.journal.root
                == Path(c.config.state_root) / "standing-rewards" / digest(c.series) / "weights"
            )
            bound.journal.journal.put("test-preserved", "one", {"retained": True})
            assert bound.journal.journal.get("test-preserved", "one") == {"retained": True}
        with pytest.raises(ValueError):
            c.check(bound)
    assert identities[0] == identities[1]


@pytest.mark.parametrize("name", ["rounds.sqlite3", "rounds.lock", "standing-writer.lock"])
async def test_missing_retained_file_is_not_reinitialized(installed, name):
    c = installed
    async with c.reopen() as runtime, hold_legacy_reward_handoff(runtime, **c.args) as handoff:
        bound = c.bind(runtime, handoff)
        path = bound.journal.journal.root / name
    path.rename(path.with_suffix(path.suffix + ".preserved"))
    async with c.reopen() as runtime, hold_legacy_reward_handoff(runtime, **c.args) as handoff:
        with pytest.raises(ValueError, match="retained journal is missing"):
            c.bind(runtime, handoff)
        assert not path.exists()


async def test_copied_original_state_survives_inode_change_only_after_restart(installed):
    c = installed
    async with c.reopen() as runtime, hold_legacy_reward_handoff(runtime, **c.args) as handoff:
        bound = c.bind(runtime, handoff)
        root = bound.journal.journal.root
        original = bound._retained
        root.rename(root.with_name("preserved-weights"))
        shutil.copytree(root.with_name("preserved-weights"), root)
        with pytest.raises(ValueError, match="journal changed"):
            c.check(bound)
    async with c.reopen() as runtime, hold_legacy_reward_handoff(runtime, **c.args) as handoff:
        reopened = c.bind(runtime, handoff)
        c.check(reopened)
        assert reopened._retained == original


async def test_empty_replacement_database_cannot_claim_original_identity(installed):
    c = installed
    async with c.reopen() as runtime, hold_legacy_reward_handoff(runtime, **c.args) as handoff:
        bound = c.bind(runtime, handoff)
        path = bound.journal.journal.path
        options = dict(bound.journal.binding)
    path.rename(path.with_suffix(".preserved"))
    StandingWeightJournal(
        path.parent,
        series_sha256=options["series_sha256"],
        validator_hotkey=c.item.hotkey,
        chain_config_sha256=options["chain_config_sha256"],
        maximum_bytes=128 * 1024**2,
    )
    async with c.reopen() as runtime, hold_legacy_reward_handoff(runtime, **c.args) as handoff:
        with pytest.raises(ValueError, match="identity differs"):
            c.bind(runtime, handoff)


@pytest.mark.parametrize(
    "field",
    [
        "source_config_sha256",
        "installation_receipt_sha256",
        "host_manifest_sha256",
        "series_sha256",
        "policy_sha256",
        "manifest_sha256",
        "chain_config_sha256",
        "legacy_handoff_plan_sha256",
    ],
)
async def test_approval_cannot_select_another_context(installed, field):
    c = installed
    c.publish(canonical_json_bytes(c.approval.model_copy(update={field: "ab" * 32})))
    async with c.reopen() as runtime, hold_legacy_reward_handoff(runtime, **c.args) as handoff:
        with pytest.raises(ValueError, match="approved installation"):
            c.bind(runtime, handoff)
        assert host._retained_binding(runtime) is None


async def test_changed_approval_after_binding_stops_execution(installed):
    c = installed
    async with c.reopen() as runtime, hold_legacy_reward_handoff(runtime, **c.args) as handoff:
        bound = c.bind(runtime, handoff)
        c.publish(b"{}")
        with pytest.raises(ValueError, match="journal changed"):
            c.check(bound)
        with pytest.raises(ValueError, match="host binding"):
            c.check(replace(bound, _approval_path=c.approval_path.with_name("other.json")))


async def test_new_valid_selection_cannot_reset_existing_binding(installed):
    c = installed
    async with c.reopen() as runtime, hold_legacy_reward_handoff(runtime, **c.args) as handoff:
        c.bind(runtime, handoff)
    c.preparation.manifest = {"fixture": "another replay selection"}
    c.publish(
        canonical_json_bytes(
            c.approval.model_copy(update={"manifest_sha256": digest(c.preparation.manifest)})
        )
    )
    async with c.reopen() as runtime, hold_legacy_reward_handoff(runtime, **c.args) as handoff:
        with pytest.raises(ValueError, match="cannot replace"):
            c.bind(runtime, handoff)


@pytest.mark.parametrize("point", ["journal_identity", "runtime_binding"])
async def test_lost_commit_reply_reuses_original_identity(installed, monkeypatch, point):
    c = installed
    lost = False
    original_put = RoundJournal.put

    def lose_put(self, kind, key, value):
        nonlocal lost
        original_put(self, kind, key, value)
        if point == "journal_identity" and kind == "standing_host_identity" and not lost:
            lost = True
            raise OSError("lost journal acknowledgement")

    monkeypatch.setattr(RoundJournal, "put", lose_put)
    async with c.reopen() as runtime, hold_legacy_reward_handoff(runtime, **c.args) as handoff:
        original_db = runtime._db

        @contextmanager
        def lose_db():
            nonlocal lost
            with original_db() as db:
                before = db.execute(
                    "SELECT 1 FROM sqlite_master WHERE name='standing_execution'"
                ).fetchone()
                yield db
                after = db.execute(
                    "SELECT 1 FROM sqlite_master WHERE name='standing_execution'"
                ).fetchone()
            if point == "runtime_binding" and not before and after and not lost:
                lost = True
                raise OSError("lost runtime acknowledgement")

        monkeypatch.setattr(runtime, "_db", lose_db)
        with pytest.raises(OSError, match="acknowledgement"):
            c.bind(runtime, handoff)
        root = Path(c.config.state_root) / "standing-rewards" / digest(c.series) / "weights"
        journal = StandingWeightJournal(
            root,
            series_sha256=digest(c.series),
            validator_hotkey=c.item.hotkey,
            chain_config_sha256=digest(c.item.config),
            maximum_bytes=128 * 1024**2,
        )
        original = journal.journal.get("standing_host_identity", "original")
    async with c.reopen() as runtime, hold_legacy_reward_handoff(runtime, **c.args) as handoff:
        bound = c.bind(runtime, handoff)
        assert bound._retained.journal_id == original
        c.check(bound)
    assert lost


async def test_runtime_binding_cannot_disappear_as_empty_table(installed):
    c = installed
    async with c.reopen() as runtime, hold_legacy_reward_handoff(runtime, **c.args) as handoff:
        c.bind(runtime, handoff)
        with runtime._db() as db:
            db.execute("DELETE FROM standing_execution")
        with pytest.raises(ValueError, match="incomplete"):
            c.bind(runtime, handoff)


@pytest.mark.parametrize("kind", ["mode", "owner", "symlink", "hardlink", "missing", "oversized"])
async def test_host_approval_uses_native_bounded_sealed_file_reader(installed, monkeypatch, kind):
    c = installed
    if kind == "mode":
        c.approval_path.chmod(0o600)
    elif kind == "owner":
        monkeypatch.setattr(activation, "_root_owner_uid", lambda: os.getuid() + 1)
    elif kind == "symlink":
        original = c.approval_path.with_name("preserved-approval.json")
        c.approval_path.rename(original)
        c.approval_path.symlink_to(original)
    elif kind == "hardlink":
        os.link(c.approval_path, c.approval_path.with_name("hardlink"))
    elif kind == "missing":
        c.approval_path.unlink()
    else:
        c.publish(b"x" * 8193)
    async with c.reopen() as runtime, hold_legacy_reward_handoff(runtime, **c.args) as handoff:
        with pytest.raises((ValueError, OSError)):
            c.bind(runtime, handoff)
        assert host._retained_binding(runtime) is None


async def test_capacity_increase_preserves_bound_journal(installed):
    c = installed
    async with c.reopen() as runtime, hold_legacy_reward_handoff(runtime, **c.args) as handoff:
        original = c.bind(runtime, handoff)._retained
    async with c.reopen() as runtime, hold_legacy_reward_handoff(runtime, **c.args) as handoff:
        larger = bind_standing_reward_host(
            runtime,
            approval_path=c.approval_path,
            preparation=c.preparation,
            first=c.prepared,
            handoff=handoff,
            maximum_journal_bytes=256 * 1024**2,
        )
        assert larger._retained == original
        assert larger.journal.journal.maximum_bytes == 256 * 1024**2
        c.check(larger)


@pytest.fixture
def service_case(installed, monkeypatch, tmp_path):
    """Native runtime/handoff/binding; provider lifecycle and executor are ports."""
    c = installed
    c.provider = object.__new__(HistoricalRewardControlProvider)
    c.provider.config = c.item.config.model_copy(
        update={"proof_rpc_fallback_urls": ("wss://backup-one.example", "wss://backup-two.example")}
    )
    c.preparation.reader.chain_config_sha256 = digest(c.provider.config)
    c.preparation.reader.admission_chain_config_sha256 = digest(c.provider.config)
    c.provider.policy = c.item.policy
    c.approval = c.approval.model_copy(update={"chain_config_sha256": digest(c.provider.config)})
    c.publish(canonical_json_bytes(c.approval))
    c.events, c.executors = [], []
    c.stop = asyncio.Event()
    for label, value in (("current", c.provider), ("legacy", next(iter(c.providers.values())))):

        async def start(label=label):
            c.events.append("start-" + label)

        async def close(label=label):
            c.events.append("close-" + label)

        value.start, value.aclose = start, close
        value.ensure_observer_running = lambda: None

    def signer():
        assert_locked(Path(c.config.state_root) / "supervisor-process.lock")
        assert_locked(c.item.worker.lock_path)
        assert host._retained_binding(c.current_runtime) is not None
        c.events.append("signer")
        return object()

    async def execute(inputs):
        c.stop.set()

    c.execute = execute

    class Executor:
        def __init__(self, **inputs):
            self.inputs = inputs
            c.executors.append(inputs)
            c.events.append("executor")

        async def run(self, stop, *, poll_seconds):
            assert stop is c.stop and poll_seconds == 0.001
            inputs = self.inputs
            bound = inputs["host"]
            bound.recheck(
                journal=inputs["journal"],
                preparation=inputs["preparation"],
                first=inputs["first"],
                handoff=inputs["handoff"],
            )
            assert_locked(c.item.worker.lock_path)
            fd = lock_private_file(inputs["journal"].journal.root / "standing-writer.lock")
            try:
                await c.execute(inputs)
            finally:
                os.close(fd)
                c.events.append("executor-stopped")

    monkeypatch.setattr(service, "StandingRewardExecutor", Executor)
    c.service_options = dict(
        approval_path=c.approval_path,
        preparation=c.preparation,
        first=c.prepared,
        plan=c.plan,
        provider=c.provider,
        legacy_providers=c.providers,
        history=RewardControlHistoryReader(
            tmp_path / "service-history",
            control_hotkey=c.series.control_hotkey,
            chain_config_sha256=digest(c.provider.config),
            first_block=c.series.recovery.authority.issued_at_block,
        ),
        packages=object(),
        decisions=object(),
        opportunity=object(),
        load_signer=signer,
        stop=c.stop,
        limits=StandingRewardServiceLimits(
            maximum_journal_bytes=128 * 1024**2, mortality_period=4, poll_seconds=0.001
        ),
    )
    return c


async def test_service_restarts_with_original_binding_and_orders_shutdown(service_case):
    c = service_case
    original = None
    for _ in range(2):
        c.stop.clear()
        async with c.reopen() as runtime:
            c.current_runtime = runtime
            await run_standing_reward_service(runtime, **c.service_options)
            binding = host._retained_binding(runtime)
            assert original is None or original == binding
            original = binding
        assert c.events[-7:] == [
            "start-current",
            "start-legacy",
            "signer",
            "executor",
            "executor-stopped",
            "close-legacy",
            "close-current",
        ]
    assert len(c.executors) == 2


async def test_service_rejects_approval_before_stop_and_closes_unstarted_providers(service_case):
    c = service_case
    c.publish(canonical_json_bytes(c.approval.model_copy(update={"series_sha256": "ff" * 32})))
    async with c.reopen() as runtime:
        c.current_runtime = runtime
        with pytest.raises(ValueError, match="approved installation"):
            await run_standing_reward_service(runtime, **c.service_options)
        assert runtime._standing_handoff_intent() is None
    assert c.events == ["close-legacy", "close-current"]


async def test_service_closes_all_owners_when_provider_start_fails(service_case):
    c = service_case

    async def fail():
        raise ConnectionError("private provider credential")

    c.provider.start = fail
    async with c.reopen() as runtime:
        with pytest.raises(ConnectionError):
            await run_standing_reward_service(runtime, **c.service_options)
        assert runtime._standing_handoff_intent() is None
    assert c.events == ["close-legacy", "close-current"]


async def test_service_terminal_observer_exits_for_restart(service_case):
    c = service_case

    def stopped():
        raise RuntimeError("owned_finality_observer_stopped")

    c.provider.ensure_observer_running = stopped
    async with c.reopen() as runtime:
        with pytest.raises(RuntimeError, match="observer_stopped"):
            await run_standing_reward_service(runtime, **c.service_options)
        assert runtime._standing_handoff_intent() is None
    assert c.events == ["start-current", "start-legacy", "close-legacy", "close-current"]


async def test_service_retries_retained_handoff_without_loading_signer_early(
    service_case, monkeypatch
):
    c = service_case
    await signed_attempt(c)
    original = service.hold_legacy_reward_handoff
    calls = 0

    def recovering(*args, **kwargs):
        nonlocal calls
        calls += 1
        c.expired = calls > 1
        return original(*args, **kwargs)

    monkeypatch.setattr(service, "hold_legacy_reward_handoff", recovering)
    async with c.reopen() as runtime:
        c.current_runtime = runtime
        await run_standing_reward_service(runtime, **c.service_options)
    assert calls == 2 and c.events.count("signer") == 1
    assert len(c.reviews) == 2


async def test_service_executor_failure_reuses_journal_and_redacts_errors(service_case, caplog):
    c = service_case
    attempts = []

    async def execute(inputs):
        attempts.append(inputs["host"]._retained)
        if len(attempts) == 1:
            raise OSError("private bearer or RPC credential")
        c.stop.set()

    c.execute = execute
    with caplog.at_level(logging.INFO):
        async with c.reopen() as runtime:
            c.current_runtime = runtime
            await run_standing_reward_service(runtime, **c.service_options)
    assert len(attempts) == 2 and attempts[0] == attempts[1]
    assert "standing_service_retry reason=OSError" in caplog.text
    assert "stage=execution" in caplog.text
    assert "private bearer" not in caplog.text


@pytest.mark.parametrize(
    "stage",
    [
        "initial_control",
        "initial_replay",
        "legacy_handoff",
        "journal_binding",
        "signer_load",
        "executor_start",
    ],
)
async def test_service_reports_failed_stage_and_recovers_without_reset(
    service_case, monkeypatch, caplog, stage
):
    c = service_case
    if stage in {"initial_control", "initial_replay"}:
        c.service_options.pop("first")

        async def collect(hotkey):
            assert hotkey == c.series.control_hotkey
            return SimpleNamespace(snapshot=SimpleNamespace(block_number=1000))

        async def prepare(*args):
            return c.prepared

        c.provider.collect_control = collect
        monkeypatch.setattr(service, "_prepare_first", prepare)
    target, name = {
        "initial_control": (c.provider, "collect_control"),
        "initial_replay": (service, "_prepare_first"),
        "legacy_handoff": (service, "hold_legacy_reward_handoff"),
        "journal_binding": (service, "bind_standing_reward_host"),
        "executor_start": (service, "StandingRewardExecutor"),
        "signer_load": (None, "load_signer"),
    }[stage]
    operation = c.service_options[name] if target is None else getattr(target, name)
    attempts = []

    def interrupted(*args, **kwargs):
        attempts.append(1)
        if len(attempts) == 1:
            raise OSError("private bearer, wallet path and RPC credential")
        return operation(*args, **kwargs)

    if target is None:
        c.service_options[name] = interrupted
    else:
        monkeypatch.setattr(target, name, interrupted)

    async def predecessor():
        return SimpleNamespace(status="healthy", reason="fixture_legacy_continuation")

    with caplog.at_level(logging.INFO):
        async with c.reopen() as runtime:
            c.current_runtime = runtime
            monkeypatch.setattr(runtime, "reconcile", predecessor)
            await asyncio.wait_for(run_standing_reward_service(runtime, **c.service_options), 15)
    assert len(attempts) == 2 and len(c.executors) == 1
    assert f"standing_service_retry reason=OSError stage={stage}" in caplog.text
    assert "private bearer" not in caplog.text and "RPC credential" not in caplog.text
    assert c.events.count("signer") == (2 if stage == "executor_start" else 1)
    assert c.events[-2:] == ["close-legacy", "close-current"]


async def test_service_cancellation_drains_signer_before_unlocking(service_case):
    c = service_case
    entered, release = threading.Event(), threading.Event()
    original = c.service_options["load_signer"]

    def slow_signer():
        value = original()
        entered.set()
        assert release.wait(10)
        assert_locked(c.item.worker.lock_path)
        return value

    c.service_options["load_signer"] = slow_signer
    async with c.reopen() as runtime:
        c.current_runtime = runtime
        task = asyncio.create_task(run_standing_reward_service(runtime, **c.service_options))
        try:
            while not entered.is_set():
                await asyncio.sleep(0.001)
            task.cancel()
            await asyncio.sleep(0.01)
            task.cancel()
            await asyncio.sleep(0.01)
            assert not task.done() and runtime._mutex.locked()
            assert_locked(c.item.worker.lock_path)
            assert not any(e.startswith("close-") for e in c.events)
        finally:
            release.set()
            with pytest.raises(asyncio.CancelledError):
                await task
        assert not runtime._mutex.locked()
    assert not c.executors
    assert c.events[-2:] == ["close-legacy", "close-current"]


@pytest.mark.parametrize("failure", ["history_pending", "package_unavailable", "not_activated"])
async def test_service_boot_retries_before_handoff_and_keeps_replay_target(
    service_case, monkeypatch, failure
):
    c = service_case
    c.service_options.pop("first")
    targets, captures = [], []

    async def collect(hotkey):
        assert hotkey == c.series.control_hotkey
        captures.append(1000 + len(captures))
        return SimpleNamespace(snapshot=SimpleNamespace(block_number=captures[-1]))

    async def prepare(*args):
        assert c.current_runtime._standing_handoff_intent() is None
        assert not c.executors and "signer" not in c.events
        targets.append(args[-2])
        if len(targets) == 1:
            if failure == "history_pending":
                raise service.StandingHistoryPending
            if failure == "package_unavailable":
                raise OSError("private delivery error")
            return None
        return c.prepared

    c.provider.collect_control = collect
    monkeypatch.setattr(service, "_prepare_first", prepare)

    async def predecessor():
        return SimpleNamespace(status="healthy", reason="fixture_legacy_continuation")

    async with c.reopen() as runtime:
        c.current_runtime = runtime
        monkeypatch.setattr(runtime, "reconcile", predecessor)
        await run_standing_reward_service(runtime, **c.service_options)
    assert targets == ([1000, 1001] if failure == "not_activated" else [1000, 1000])
    assert captures == ([1000, 1001] if failure == "not_activated" else [1000])
    assert len(c.executors) == 1 and c.executors[0]["first"] is c.prepared


async def test_service_stop_during_boot_preserves_old_handoff_state(service_case, monkeypatch):
    c = service_case
    c.service_options.pop("first")

    async def collect(hotkey):
        return SimpleNamespace(snapshot=SimpleNamespace(block_number=1000))

    async def prepare(*args):
        c.stop.set()
        return c.prepared

    c.provider.collect_control = collect
    monkeypatch.setattr(service, "_prepare_first", prepare)

    async def predecessor():
        return SimpleNamespace(status="healthy", reason="fixture_legacy_continuation")

    async with c.reopen() as runtime:
        c.current_runtime = runtime
        monkeypatch.setattr(runtime, "reconcile", predecessor)
        await run_standing_reward_service(runtime, **c.service_options)
        assert runtime._standing_handoff_intent() is None
    assert not c.executors and "signer" not in c.events
    assert c.events[-2:] == ["close-legacy", "close-current"]


@pytest.mark.parametrize("feed_fails", [False, True])
async def test_slow_boot_continues_c4_and_feed_failure_does_not_block_c5(
    service_case, monkeypatch, feed_fails
):
    c = service_case
    c.service_options.pop("first")
    reconciled = asyncio.Event()
    reconciles = []

    async def collect(hotkey):
        return SimpleNamespace(snapshot=SimpleNamespace(block_number=1000))

    async def prepare(*args):
        await asyncio.wait_for(reconciled.wait(), timeout=2)
        assert c.current_runtime._standing_handoff_intent() is None
        assert "signer" not in c.events
        return c.prepared

    c.provider.collect_control = collect
    monkeypatch.setattr(service, "_prepare_first", prepare)
    async with c.reopen() as runtime:
        c.current_runtime = runtime

        async def reconcile():
            async with runtime._mutex:
                assert runtime._standing_handoff_intent() is None
                reconciles.append("old-worker")
                reconciled.set()
                if feed_fails:
                    raise OSError("fixture unavailable old feed")
                return SimpleNamespace(status="healthy", reason="current_worker_healthy")

        monkeypatch.setattr(runtime, "reconcile", reconcile)
        await run_standing_reward_service(runtime, **c.service_options)
        assert runtime._standing_handoff_intent() is not None
    assert reconciles == ["old-worker"]
    assert len(c.executors) == 1
    assert not any(t.get_name() == "standing-predecessor-continuation" for t in asyncio.all_tasks())


async def test_boot_continuation_never_restarts_c4_after_retained_handoff(
    service_case, monkeypatch
):
    c = service_case
    async with c.reopen() as runtime:
        c.current_runtime = runtime
        await run_standing_reward_service(runtime, **c.service_options)
    c.stop.clear()
    async with c.reopen() as runtime:
        assert runtime._standing_handoff_intent() is not None

        async def forbidden():
            pytest.fail("retained C5 handoff must not fetch or restart C4")

        monkeypatch.setattr(runtime, "reconcile", forbidden)
        await service._continue_predecessor(runtime, c.stop, 0.001)


@pytest.mark.parametrize("failure", [None, "observer", "early_return", "cancel"])
async def test_installed_coverage_lifecycle_drains_before_providers(
    service_case, monkeypatch, failure
):
    from umi.competition_reward_coverage_service import StandingRewardCoverageService

    c = service_case
    collection = object.__new__(StandingRewardCoverageService)
    collection.provider = c.provider
    collection.history = c.service_options["history"]
    collection.preparation = c.preparation
    c.service_options.update(coverage=collection, opportunity=collection.opportunity)
    started, executing = asyncio.Event(), asyncio.Event()

    async def collect(self, stop, *, poll_seconds):
        assert self is collection
        assert "start-current" in c.events and "start-legacy" in c.events
        c.events.append("coverage-started")
        started.set()
        try:
            await executing.wait()
            if failure == "observer":
                raise RuntimeError("fixture finality child stopped")
            if failure == "early_return":
                return
            await asyncio.Event().wait()
        finally:
            await asyncio.sleep(0.001)  # owned cleanup must be drained
            c.events.append("coverage-stopped")

    async def execute(_inputs):
        await started.wait()
        executing.set()
        if failure is None:
            c.stop.set()
        else:
            await asyncio.Event().wait()

    monkeypatch.setattr(StandingRewardCoverageService, "run", collect)
    c.execute = execute
    async with c.reopen() as runtime:
        c.current_runtime = runtime
        task = asyncio.create_task(run_standing_reward_service(runtime, **c.service_options))
        if failure == "cancel":
            await asyncio.wait_for(executing.wait(), 10)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        elif failure:
            with pytest.raises(RuntimeError):
                await asyncio.wait_for(task, 10)
        else:
            await asyncio.wait_for(task, 10)
    for stopped in ("coverage-stopped", "executor-stopped"):
        assert c.events.index(stopped) < c.events.index("close-current")
        assert c.events.index(stopped) < c.events.index("close-legacy")


async def test_service_executes_original_journal_through_restart_and_outage(
    native_encoding, service_case, monkeypatch
):
    c = connect_executor(service_case, native_encoding, monkeypatch)
    await signed_attempt(c)
    c4_before = c.item.worker.path.read_bytes()
    bindings, attempts = [], []
    for attempt in range(3):
        c.stop.clear()
        if attempt == 2:
            c.resolve_expired = True
            c.execution_chain.block += 3000  # Ten hours at the fixture's 12-second cadence.
            c.execution_chain.runtime = replace(
                c.execution_chain.runtime,
                snapshot=replace(
                    c.execution_chain.runtime.snapshot, block_number=c.execution_chain.block
                ),
            )
        async with c.reopen() as runtime:
            c.current_runtime = runtime
            await asyncio.wait_for(run_standing_reward_service(runtime, **c.service_options), 15)
            bindings.append(host._retained_binding(runtime))
            executor = c.native_executors[-1]
            attempts.append(executor.journal.pending())
            assert executor._descriptor is None
        assert not runtime._mutex.locked()
        assert c.item.worker.path.read_bytes() == c4_before
    assert bindings[0] == bindings[1] == bindings[2]
    assert attempts[0] == attempts[1]
    assert attempts[2].intent.block == attempts[0].intent.block + 3000
    assert len(c.native_executors) == 3
    assert len(c.signed) == len(c.sent) == 2
    assert c.sent[0] != c.sent[1]
    assert c.recoveries == [attempts[0], attempts[0]]
    journal = c.native_executors[-1].journal.journal
    assert len(journal.keys("standing_weight_intent")) == 2
    assert len(journal.keys("standing_weight_signed")) == 2
    for name in ("current", "legacy"):
        assert c.events.count("start-" + name) == c.events.count("close-" + name) == 3
