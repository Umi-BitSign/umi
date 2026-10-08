"""Stopped-audit reuse refuses journal/package changes and runtime restart."""

from pathlib import Path

import pytest

from umi.competition_container import SuccessorContainerStatus
from umi.competition_supervisor_adapters import ProductionSuccessorRuntimeAdapter

from .test_competition_chain import chain as chain
from .test_competition_chain import chain_config as chain_config
from .test_competition_package import package_case as package_case
from .test_competition_package import package_limits as package_limits
from .test_competition_package import release_identity as release_identity
from .test_competition_publication import replay_limits as replay_limits
from .test_competition_supervisor import successor_case as successor_case
from .test_competition_supervisor import successor_chain as successor_chain
from .test_competition_supervisor import successor_release as successor_release
from .test_competition_supervisor import v3_predecessor as v3_predecessor
from .test_competition_supervisor_adapters import _stopped
from .test_competition_supervisor_adapters import adapter_case as adapter_case
from .test_competition_weights import weight_case as weight_case
from .test_competition_worker import worker_capacity as worker_capacity
from .test_open_competition import policy as policy


@pytest.mark.parametrize("changed", ["registry", "journal", "package"])
async def test_stopped_audit_change_requires_full_recovery(adapter_case, changed):
    case = adapter_case
    case.select("competition_weights")
    await case.adapter.stage(case.selection)
    case.adapter._retain(case.adapter._staged[case.selection.directive_sha256])
    await _stopped(case)
    assert await case.adapter.retry_stopped_start()
    if changed == "registry":
        case.adapter.path.touch()
    elif changed == "journal":
        case.item.worker.path.touch()
    else:
        roots = tuple(case.adapter._stopped_audit[2])
        assert roots
        path = next(p for p in Path(roots[0]).iterdir() if p.is_file())
        path.touch()
    assert not await case.adapter.retry_stopped_start()
    with pytest.raises(ValueError):
        await case.adapter.start_weights(case.selection)
    assert "launch" not in case.container.events


async def test_stopped_audit_is_not_reused_after_restart_or_running_container(adapter_case):
    case = adapter_case
    case.select("competition_weights")
    await case.adapter.stage(case.selection)
    case.adapter._retain(case.adapter._staged[case.selection.directive_sha256])
    await _stopped(case)
    assert await case.adapter.retry_stopped_start()
    fresh = ProductionSuccessorRuntimeAdapter(
        installation=case.adapter.installation,
        materializer=case.materializer,
        observer=case.observer,
        container=case.container,
        limits=case.adapter.limits,
    )
    assert not await fresh.retry_stopped_start()
    case.container.current = SuccessorContainerStatus(
        "running", "ab" * 32, case.selection.directive_sha256
    )
    assert not await case.adapter.retry_stopped_start()
    assert "launch" not in case.container.events
