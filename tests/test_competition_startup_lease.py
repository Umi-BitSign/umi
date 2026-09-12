from __future__ import annotations

import fcntl
import os
from dataclasses import replace
from types import SimpleNamespace

import pytest

from umi import competition_supervisor_runtime as runtime
from umi.protocol import canonical_json_bytes

from .test_competition_materializer import (
    activation_case as activation_case,
)
from .test_competition_materializer import (
    anchor_case as anchor_case,
)
from .test_competition_materializer import (
    case as signed_case,  # noqa: F401
)
from .test_competition_materializer import (
    chain_config as chain_config,
)
from .test_competition_materializer import (
    explicit as explicit,
)
from .test_competition_materializer import (
    limits as limits,
)
from .test_competition_materializer import (
    package_case as package_case,
)
from .test_competition_materializer import (
    package_limits as package_limits,
)
from .test_competition_materializer import (
    policy as policy,
)
from .test_competition_materializer import (
    release_identity as release_identity,
)
from .test_competition_materializer import (
    replay_limits as replay_limits,
)
from .test_competition_materializer import (
    successor_release as successor_release,
)
from .test_competition_materializer import (
    trusted_ports as trusted_ports,
)
from .test_competition_materializer import (
    worker_capacity as worker_capacity,
)
from .test_competition_supervisor_runtime import Adapter, Fetcher


@pytest.fixture
def case(signed_case):  # noqa: F811
    signed = signed_case
    root = signed.item.state_root
    lock = root / "supervisor-process.lock"
    payload = b'{"pid":123,"retained":"original-v3-lock"}'
    lock.write_bytes(payload)
    lock.chmod(0o600)
    old = root / "directive-state.json"
    old.write_bytes(canonical_json_bytes(signed.installation.v3_state))
    old.chmod(0o600)
    adapter = Adapter()

    async def observe():
        return signed.mint()

    def make(lease, **changes):
        args = dict(
            installation=signed.installation,
            worker_adapter=adapter,
            directive_fetcher=Fetcher(signed.selection.signed),
            observation_reader=SimpleNamespace(observe=observe),
            limits=runtime.SuccessorRuntimeLimits(
                maximum_history_records=8, maximum_history_bytes=1_000_000
            ),
            startup_lease=lease,
        )
        return runtime.SuccessorSupervisorRuntime(**(args | changes))

    return SimpleNamespace(
        signed=signed, root=root, lock=lock, payload=payload, adapter=adapter, make=make
    )


def _competitor(path):
    descriptor = os.open(path, os.O_RDWR)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    finally:
        os.close(descriptor)


def test_scope_preserves_original_lock_and_excludes_competitor(case):
    before = case.lock.stat().st_ino
    with runtime.hold_successor_startup_lease(case.signed.anchor) as lease:
        lease.recheck()
        with pytest.raises(BlockingIOError):
            _competitor(case.lock)
    with pytest.raises(runtime.SuccessorRuntimeError, match="transferred"):
        lease.recheck()
    _competitor(case.lock)
    assert case.lock.stat().st_ino == before
    assert case.lock.read_bytes() == case.payload


def test_failed_competing_claim_does_not_stop_owner(case):
    with runtime.hold_successor_startup_lease(case.signed.anchor) as first:
        with (
            pytest.raises(BlockingIOError),
            runtime.hold_successor_startup_lease(case.signed.anchor),
        ):
            pytest.fail("second process acquired the original lock")
        first.recheck()
        assert case.adapter.events == []


@pytest.mark.asyncio
async def test_runtime_adopts_exact_same_fd_and_cannot_adopt_twice(case):
    with runtime.hold_successor_startup_lease(case.signed.anchor) as lease:
        original_fd = lease._descriptor
        async with case.make(lease) as engine:
            assert engine._lock_fd == original_fd
            with pytest.raises(BlockingIOError):
                _competitor(case.lock)
            with pytest.raises(runtime.SuccessorRuntimeError, match="transferred"):
                async with case.make(lease):
                    pytest.fail("lease was adopted a second time")
            assert case.adapter.events == []
            engine._require_lease()
        with pytest.raises(OSError):
            os.fstat(original_fd)
    _competitor(case.lock)
    assert case.lock.read_bytes() == case.payload


def test_raw_anchor_or_fd_document_is_not_a_startup_lease(case):
    with (
        pytest.raises(runtime.SuccessorRuntimeError, match="genuine"),
        runtime.hold_successor_startup_lease(SimpleNamespace(config=case.signed.base.config)),
    ):
        pytest.fail("plain document was accepted")
    with pytest.raises(runtime.SuccessorRuntimeError, match="absent"):
        runtime._validate_startup_lease(SimpleNamespace(_descriptor=0))


@pytest.mark.parametrize("fault", ["issuer", "descriptor", "binding"])
def test_forged_capability_cannot_be_rebound(case, fault):
    with runtime.hold_successor_startup_lease(case.signed.anchor) as lease:
        value = replace(
            lease,
            **{
                "issuer": {"_issuer": object()},
                "descriptor": {"_descriptor": lease._descriptor + 10000},
                "binding": {"_binding": "00" * 32},
            }[fault],
        )
        with pytest.raises(runtime.SuccessorRuntimeError, match="absent"):
            value.recheck()
        lease.recheck()


@pytest.mark.parametrize("fault", ["closed", "unlocked", "bytes", "legacy"])
def test_lost_or_mutated_lease_is_not_accepted(case, fault):
    with runtime.hold_successor_startup_lease(case.signed.anchor) as lease:
        if fault == "closed":
            os.close(lease._descriptor)
        elif fault == "unlocked":
            fcntl.flock(lease._descriptor, fcntl.LOCK_UN)
        elif fault == "bytes":
            case.lock.write_bytes(b"changed owner")
        else:
            (case.root / "directive-state.json").write_bytes(b"{}")
        with pytest.raises((OSError, runtime.SuccessorRuntimeError)):
            lease.recheck()


def test_unconfirmed_stop_preserves_lock_but_expired_scope_cannot_be_adopted(case):
    descriptor = -1
    try:
        with (
            pytest.raises(RuntimeError, match="unconfirmed"),
            runtime.hold_successor_startup_lease(case.signed.anchor) as lease,
        ):
            descriptor = lease._descriptor
            lease.preserve_on_failure()
            raise RuntimeError("unconfirmed worker absence")
        with pytest.raises(BlockingIOError):
            _competitor(case.lock)
        with pytest.raises(runtime.SuccessorRuntimeError, match="transferred"):
            lease.recheck()
    finally:
        # Only this synthetic fixture's deliberately retained process descriptor.
        if descriptor >= 0:
            os.close(descriptor)
    _competitor(case.lock)


@pytest.mark.asyncio
async def test_adopted_initialization_failure_stops_before_releasing_lock(case, monkeypatch):
    with runtime.hold_successor_startup_lease(case.signed.anchor) as lease:
        engine = case.make(lease)

        def fail():
            raise OSError("injected journal failure")

        monkeypatch.setattr(engine, "_open_journal", fail)
        with pytest.raises(OSError, match="journal"):
            await engine.__aenter__()
        assert case.adapter.events == [("stop", None)]
        _competitor(case.lock)


@pytest.mark.asyncio
async def test_adopted_initialization_failure_with_failed_stop_keeps_lock(case, monkeypatch):
    engine = None
    try:
        with runtime.hold_successor_startup_lease(case.signed.anchor) as lease:
            engine = case.make(lease)

            def fail():
                raise OSError("injected journal failure")

            monkeypatch.setattr(engine, "_open_journal", fail)
            case.adapter.fail_stop = True
            with pytest.raises(ValueError, match="alive"):
                await engine.__aenter__()
        with pytest.raises(BlockingIOError):
            _competitor(case.lock)
    finally:
        if engine is not None and engine._lock_fd >= 0:
            os.close(engine._lock_fd)
            engine._lock_fd = -1
