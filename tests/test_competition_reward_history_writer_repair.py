"""Writer repair keeps approved boot inputs, supervisor ownership and namespace."""

import asyncio
import os
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

from umi import competition_reward_history_repair as repair
from umi.competition_chain_resources import CompetitionChainResources
from umi.competition_supervisor_runtime import SuccessorRuntimeError
from umi.open_competition import digest
from umi.private_files import PrivateStateBusyError, ensure_private_directory, lock_private_file
from umi.protocol import canonical_json_bytes

from .test_competition_reward_boot import chain as chain
from .test_competition_reward_boot import chain_config as chain_config
from .test_competition_reward_boot import control as control
from .test_competition_reward_boot import direct_reward_config, successor_boot
from .test_competition_reward_boot import inputs as inputs
from .test_competition_reward_boot import policy as policy
from .test_competition_reward_boot import series_case as series_case


@pytest.fixture
def writer_owner(inputs, monkeypatch):
    events = []
    state = Path(inputs.anchor.config.state_root)
    ensure_private_directory(state)
    lock = state / "supervisor-process.lock"

    @contextmanager
    def lease(anchor):
        assert anchor is inputs.anchor
        descriptor = lock_private_file(lock)
        events.append("lock")
        try:
            yield SimpleNamespace(config=anchor.config, recheck=lambda: events.append("recheck"))
        finally:
            events.append("unlock")
            os.close(descriptor)

    monkeypatch.setattr(repair, "hold_successor_startup_lease", lease)
    return SimpleNamespace(events=events, lock=lock)


@pytest.mark.parametrize("selection", ["current", "predecessor"])
async def test_writer_refuses_owner_before_boot_or_history_read(
    inputs, writer_owner, monkeypatch, selection
):
    descriptor = lock_private_file(writer_owner.lock)

    def forbidden(*args, **kwargs):
        pytest.fail("writer repair inspected configuration or journals while live owner held lock")

    monkeypatch.setattr(repair, "load_standing_boot", forbidden)
    monkeypatch.setattr(repair, "RewardControlHistoryReader", forbidden)
    monkeypatch.setattr(repair, "HistoricalRewardControlProvider", forbidden)
    try:
        with pytest.raises(PrivateStateBusyError):
            await repair.run_installed_history_repair(
                inputs.anchor,
                inputs.path,
                asyncio.Event(),
                through_block=200,
                reason="retained source restored",
                history=selection,
            )
    finally:
        os.close(descriptor)
    assert not writer_owner.events


@pytest.mark.parametrize("layout", ["original", "direct", "successor", "predecessor"])
@pytest.mark.parametrize("failure", [None, "invalid_source", "provider_start"])
async def test_writer_uses_original_history_headers_approval_and_provider_lifetime(
    inputs, writer_owner, monkeypatch, tmp_path, layout, failure
):
    config = inputs.value
    if layout == "direct":
        config = direct_reward_config(config, tmp_path, "umi-standing-reward-boot/2")
        approval = inputs.approval.model_copy(
            update={
                "series_sha256": digest(config.series),
                "manifest_sha256": digest(config.manifest),
                "legacy_handoff_plan_sha256": digest(config.handoff),
            }
        )
        inputs.save(inputs.path, canonical_json_bytes(config))
        inputs.save(Path(config.approval_path), canonical_json_bytes(approval))
    elif layout in {"successor", "predecessor"}:
        config, approval = successor_boot(inputs)
        inputs.save(inputs.path, canonical_json_bytes(config))
        inputs.save(Path(config.approval_path), canonical_json_bytes(approval))
    history = "predecessor" if layout == "predecessor" else "current"
    selected = config.predecessor_series if history == "predecessor" else config.series
    state = Path(inputs.anchor.config.state_root) / "standing-rewards"
    root, owner_root = state / digest(selected), state / digest(config.series)
    ensure_private_directory(root / "history")
    (root / "history" / "rounds.sqlite3").touch(mode=0o600)
    providers = []

    class Request:
        sha256 = "11" * 32

        def __init__(self, reader, target, reason):
            assert target == 200 and reason == "original restored"
            writer_owner.events.append("durable-intent")

        def finish(self, history):
            writer_owner.events.append("durable-result")

    class Reader:
        def __init__(self, path, **kwargs):
            writer_owner.events.append("history")
            assert path == root / "history"
            assert kwargs["chain_config_sha256"] == digest(config.chain)
            assert kwargs["first_block"] == selected.recovery.authority.issued_at_block
            assert kwargs["control_hotkey"] == selected.control_hotkey
            with pytest.raises(PrivateStateBusyError):
                lock_private_file(writer_owner.lock)
            self.progress = SimpleNamespace(latest={})

        async def repair_checkpoints(self, provider, **kwargs):
            assert provider.started and kwargs["reason"] == "original restored"
            if failure == "invalid_source":
                raise ValueError("unsupported source")
            self.progress.latest = dict(state="completed", percent=100, eta_seconds=0)
            return SimpleNamespace(history=object())

    class Provider:
        def __init__(self, chain, policy, **kwargs):
            assert chain == config.chain and policy == config.policy
            assert kwargs["resources"] == CompetitionChainResources.from_config(config.chain)
            assert kwargs["historical_header_directory"] == owner_root / "headers" / digest(chain)
            assert kwargs["runtime_proof_reads"] == config.runtime_proof_reads
            self.started = self.closed = False
            providers.append(self)

        async def start(self):
            if failure == "provider_start":
                raise OSError("transport unavailable")
            self.started = True

        async def aclose(self):
            assert writer_owner.events[-1] != "unlock"
            self.closed = True

    def forbidden(*args, **kwargs):
        pytest.fail("history repair loaded a signing key or writer")

    monkeypatch.setattr(repair, "RewardControlHistoryReader", Reader)
    monkeypatch.setattr(repair, "HistoricalRewardControlProvider", Provider)
    monkeypatch.setattr(repair, "HistoryRepairRequest", Request)
    monkeypatch.setattr("umi.named_hotkey.load_named_hotkey", forbidden)
    monkeypatch.setattr("umi.competition_reward_boot.run_standing_reward_service", forbidden)
    if failure:
        with pytest.raises(OSError if failure == "provider_start" else ValueError):
            await repair.run_installed_history_repair(
                inputs.anchor,
                inputs.path,
                asyncio.Event(),
                through_block=200,
                reason="original restored",
                history=history,
            )
    else:
        result = await repair.run_installed_history_repair(
            inputs.anchor,
            inputs.path,
            asyncio.Event(),
            through_block=200,
            reason="original restored",
            history=history,
        )
        assert result["role"] == "reward_writer" and result["status"] == "history_repaired"
        assert result["history"] == history and result["series_sha256"] == digest(selected)
    assert len(providers) == 1 and providers[0].closed
    assert writer_owner.events[:3] == ["lock", "recheck", "history"]
    assert writer_owner.events[-1] == "unlock"


async def test_writer_repair_rejects_unapproved_boot_before_history(
    inputs, writer_owner, monkeypatch
):
    inputs.save(Path(inputs.value.approval_path), b"{}")

    def forbidden(*args, **kwargs):
        pytest.fail("unapproved boot reached mutable history")

    monkeypatch.setattr(repair, "RewardControlHistoryReader", forbidden)
    with pytest.raises(ValueError):
        await repair.run_installed_history_repair(
            inputs.anchor,
            inputs.path,
            asyncio.Event(),
            through_block=200,
            reason="original restored",
        )
    assert writer_owner.events == ["lock", "unlock"]


async def test_writer_repair_requires_genuine_native_anchor(inputs):
    with pytest.raises(SuccessorRuntimeError, match="genuine root-owned anchor"):
        await repair.run_installed_history_repair(
            inputs.anchor,
            inputs.path,
            asyncio.Event(),
            through_block=200,
            reason="original restored",
        )
