from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from umi import competition_recovery as recovery
from umi import competition_recovery_capture as capture

from .test_competition_bridge_recovery import completed as completed
from .test_competition_bridge_recovery import signed_policy as signed_policy
from .test_competition_bridge_recovery import snapshot
from .test_competition_recovery import explicit as explicit
from .test_competition_recovery import limits as limits
from .test_competition_recovery import trusted_ports as trusted_ports


@pytest.fixture
def capture_case(trusted_ports, monkeypatch):
    monkeypatch.setattr(capture, "_check_stopped", recovery._check_stopped)
    return trusted_ports


async def test_locked_parsing_precedes_each_fresh_read_and_archive_bytes_are_unchanged(
    capture_case, monkeypatch
):
    item = capture_case
    original = recovery._classify
    events = []

    def slow_classification(*args, **kwargs):
        # Simulate arbitrary history latency. The old observation is unusable
        # until the observer is called after this native classification returns.
        item.observation.live = False
        events.append("classify")
        return original(*args, **kwargs)

    async def observe(snapshot):
        assert not item.observation.live
        assert snapshot._files
        recovery._unchanged(snapshot)
        item.observation.live = True
        events.append("observe")
        return item.observation, None

    monkeypatch.setattr(recovery, "_classify", slow_classification)
    prepared = await capture.prepare_recovery_checkpoint(
        item.stopped, observe=observe, destination_root=item.archives, limits=item.limits
    )
    assert prepared.prior_effects_reconciled and not prepared.holds
    verified = await capture.verify_recovery_checkpoint(
        Path(prepared.checkpoint_path),
        expected_checkpoint_sha256=prepared.checkpoint_sha256,
        stopped=item.stopped,
        observe=observe,
        limits=item.limits,
    )
    recovery.validate_checkpoint_for_successor(
        verified,
        validator_hotkey=item.stopped.validator_hotkey,
        predecessor_directive_sha256=item.stopped.accepted_directive_sha256,
        minimum_finalized_block=item.observation.block,
    )
    assert events == ["classify", "observe", "classify", "observe"]
    monkeypatch.setattr(recovery, "_classify", original)
    synchronous = recovery.prepare_recovery_checkpoint(
        item.stopped, item.observation, destination_root=item.archives, limits=item.limits
    )
    assert synchronous == prepared
    assert not recovery._SNAPSHOT_BRIDGES


@pytest.mark.parametrize("fault", ["expired", "state_changed", "stopped_lease_closed"])
async def test_capture_cannot_replace_freshness_or_stopped_unchanged_state(capture_case, fault):
    item = capture_case

    async def observe(snapshot):
        if fault == "expired":
            item.observation.live = False
        elif fault == "stopped_lease_closed":
            item.stopped.live = False
        else:
            path = item.root / "service.lock"
            path.write_bytes(b"changed during proof capture")
            path.chmod(0o600)
        return item.observation, None

    with pytest.raises(ValueError):
        await capture.prepare_recovery_checkpoint(
            item.stopped, observe=observe, destination_root=item.archives, limits=item.limits
        )
    assert not list(item.archives.iterdir())
    assert not recovery._SNAPSHOT_BRIDGES


@pytest.mark.parametrize("mutation", ["raw_bytes", "parsed_row"])
def test_scoped_history_reuse_rejects_changed_bytes_or_nested_models(
    tmp_path, completed, limits, mutation
):
    with snapshot(tmp_path / "worker", completed, limits) as retained:
        audit = recovery.bridge_history_for_snapshot(retained)
        if mutation == "raw_bytes":
            retained._files["registration-bridge-journal.json"] += b" "
        else:
            audit.current.attempt.expected_row[0][1] ^= 1
        with pytest.raises(ValueError, match="history binding changed"):
            recovery._reconcile_snapshot(retained, completed.owned, ())
    assert not recovery._SNAPSHOT_BRIDGES


def test_history_parsing_is_scoped_and_reconciliation_still_rechecks_owned_row(
    tmp_path, completed, limits, monkeypatch
):
    original = recovery.audit_bridge_history
    calls = []

    def audit(*args, **kwargs):
        calls.append(1)
        return original(*args, **kwargs)

    monkeypatch.setattr(recovery, "audit_bridge_history", audit)
    with snapshot(tmp_path / "worker", completed, limits) as retained:
        assert calls == [1]
        stopped = SimpleNamespace(
            expected_registration_bridge_policy_sha256=completed.current.attempt.policy_sha256,
            expected_manifest_sha256=None,
            validator_hotkey=completed.current.validator_hotkey,
        )
        recovery._check_current_manifest(retained, stopped)
        stopped.expected_registration_bridge_policy_sha256 = "00" * 32
        with pytest.raises(ValueError, match="installed signed policy"):
            recovery._check_current_manifest(retained, stopped)
        assert not recovery._reconcile_snapshot(retained, completed.owned, ())[1]
        completed.owned.validator_row = ()
        assert (
            "registration_bridge_latest_effect_not_proven"
            in recovery._reconcile_snapshot(retained, completed.owned, ())[1]
        )
        assert calls == [1]
    assert not recovery._SNAPSHOT_BRIDGES
    recovery.bridge_history_for_snapshot(retained)
    assert calls == [1, 1]
