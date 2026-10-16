"""Bridge the runtime reuse boundary to genuine retained adapter audits.

Only runtime persistence/lease ports and the existing fixture's host/OS ports
are substituted. Package signatures, continuations, proof capabilities, journal
families, audit matching and launch checks use their production implementations.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from dataclasses import replace
from types import SimpleNamespace

import pytest

from umi import competition_supervisor_runtime as runtime
from umi.competition_chain_state import validate_owned_weight_observation
from umi.competition_supervisor import successor_continuation_bytes
from umi.competition_supervisor_runtime import SuccessorWorkerSelection

from .test_competition_supervisor import _signed_continuation
from .test_competition_supervisor_adapters import (
    _stopped,
)
from .test_competition_supervisor_adapters import (
    adapter_case as adapter_case,
)
from .test_competition_supervisor_adapters import (
    chain as chain,
)
from .test_competition_supervisor_adapters import (
    chain_config as chain_config,
)
from .test_competition_supervisor_adapters import (
    package_case as package_case,
)
from .test_competition_supervisor_adapters import (
    package_limits as package_limits,
)
from .test_competition_supervisor_adapters import (
    policy as policy,
)
from .test_competition_supervisor_adapters import (
    release_identity as release_identity,
)
from .test_competition_supervisor_adapters import (
    replay_limits as replay_limits,
)
from .test_competition_supervisor_adapters import (
    successor_case as successor_case,
)
from .test_competition_supervisor_adapters import (
    successor_chain as successor_chain,
)
from .test_competition_supervisor_adapters import (
    successor_release as successor_release,
)
from .test_competition_supervisor_adapters import (
    v3_predecessor as v3_predecessor,
)
from .test_competition_supervisor_adapters import (
    weight_case as weight_case,
)
from .test_competition_supervisor_adapters import (
    worker_capacity as worker_capacity,
)
from .test_competition_weights import _advance


@pytest.mark.parametrize("change", [None, "registry", "attempts", "package", "corrupt_evidence"])
async def test_new_prefix_runtime_reuse_with_real_adapter(
    adapter_case, monkeypatch, caplog, change
):
    case = adapter_case
    caplog.set_level(logging.INFO, logger="umi.competition.progress")
    anchor = case.selection.signed
    case.adapter._retain(case.adapter._verify(case.selection, case.files))
    audits = []
    original_audit = case.adapter._audit_retained_recovery

    def audit():
        audits.append(True)
        return original_audit()

    monkeypatch.setattr(case.adapter, "_audit_retained_recovery", audit)
    initial = await _stopped(case)
    saved_audit = case.adapter._stopped_audit
    assert saved_audit is not None and len(audits) == 1

    # Stage a different, genuinely signed directive without retaining a launch.
    successor = _signed_continuation(anchor, 1)[0]
    continuation = successor_continuation_bytes(anchor, [successor])
    selection = SuccessorWorkerSelection(successor, continuation)
    case.files = replace(case.files, current_directive_page_bytes=continuation)
    await case.adapter.stage(selection)
    assert selection.directive_sha256 != anchor.directive_sha256
    assert len(case.adapter._records()) == 1
    assert case.adapter._stopped_audit_matches()

    checks = []
    original_retry = case.adapter.retry_stopped_start

    async def retry():
        matched = await original_retry()
        checks.append(matched)
        return matched

    monkeypatch.setattr(case.adapter, "retry_stopped_start", retry)
    observations, stored_workers = [], []

    async def observe():
        _advance(case.item, initial.block + len(observations) + 1)
        observation = await case.observer.observe()
        validate_owned_weight_observation(observation)
        observations.append(observation)
        await asyncio.sleep(0)
        if len(observations) == 1 and change is not None:
            assert checks == [True]
            if change == "corrupt_evidence":
                with case.item.worker._db() as db:
                    db.execute("INSERT INTO evidence VALUES (?,?)", ("ff" * 32, b"damaged"))
            else:
                path = {
                    "registry": case.adapter.path,
                    "attempts": case.item.worker.path,
                    "package": case.files.package_path / "manifest.json",
                }[change]
                stamp = path.stat()
                os.utime(path, ns=(stamp.st_atime_ns, stamp.st_mtime_ns + 1))
        return observation

    # The full runtime tests own journal and lease coverage. Here those ports
    # expose the idle boundary established by the genuine completed audit above.
    engine = SimpleNamespace(
        adapter=case.adapter,
        _restart_checked=True,
        _load_history=lambda: (None, None, runtime._idle()),
        _refresh_observation=observe,
        _require_lease=lambda: None,
        _store_worker=stored_workers.append,
    )
    before_stops = case.container.events.count("stop")
    if change == "corrupt_evidence":
        with pytest.raises(ValueError):
            await runtime.SuccessorSupervisorRuntime._stop_and_recover(engine, initial)
        assert case.adapter._stopped_audit is None
        assert case.adapter._recovered is None
        assert "launch" not in case.container.events
    else:
        observation = await runtime.SuccessorSupervisorRuntime._stop_and_recover(engine, initial)
        validate_owned_weight_observation(observation)
        assert observation.block > initial.block
        assert observation is observations[-1]
        assert case.adapter._stopped_audit_matches()
        if change is None:
            assert case.adapter._stopped_audit is saved_audit
            assert stored_workers == []
        else:
            assert case.adapter._stopped_audit != saved_audit
            assert len(stored_workers) == 1 and stored_workers[0].phase == "idle"
        await case.adapter.start_replay(selection)
        assert case.container.events[-1] == "launch"
        assert not await original_retry()
        assert len(case.adapter._records()) == 2

    assert checks == [True, change is None]
    assert len(audits) == (1 if change is None else 2)
    assert case.container.events.count("stop") - before_stops == (0 if change is None else 1)
    assert not case.item.encoded
    telemetry = [
        json.loads(record.message)
        for record in caplog.records
        if '"stage":"supervisor_recovery_audit_reused"' in record.message
    ]
    assert any(item["state"] == "completed" for item in telemetry) is (change is None)
