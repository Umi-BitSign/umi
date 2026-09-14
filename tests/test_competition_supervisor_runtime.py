from __future__ import annotations

import asyncio
import shutil
import sqlite3
from types import SimpleNamespace

import pytest

from umi import competition_supervisor_runtime as runtime
from umi.competition_supervisor import (
    SuccessorSupervisorDirectivePage,
    parse_canonical_successor_supervisor_directive_history,
    successor_source_config_sha256,
)
from umi.protocol import canonical_json_bytes
from umi.validator_supervisor import MAX_SUPERVISOR_DIRECTIVES_PER_PAGE

from .test_competition_supervisor import (
    _directive,
    _signed,
    _signed_continuation,
)
from .test_competition_supervisor import (
    package_case as package_case,
)
from .test_competition_supervisor import (
    package_limits as package_limits,
)
from .test_competition_supervisor import (
    policy as policy,
)
from .test_competition_supervisor import (
    release_identity as release_identity,
)
from .test_competition_supervisor import (
    replay_limits as replay_limits,
)
from .test_competition_supervisor import (
    successor_case as successor_case,
)
from .test_competition_supervisor import (
    successor_chain as successor_chain,
)
from .test_competition_supervisor import (
    successor_release as successor_release,
)
from .test_competition_supervisor import (
    v3_predecessor as v3_predecessor,
)


@pytest.mark.parametrize("distinct_async_timeout", [False, True])
async def test_poll_continues_after_timeout(monkeypatch, distinct_async_timeout):
    class LegacyAsyncTimeout(Exception):
        pass

    timeout_type = LegacyAsyncTimeout if distinct_async_timeout else asyncio.TimeoutError
    monkeypatch.setattr(asyncio, "TimeoutError", timeout_type)
    stop = asyncio.Event()
    rounds = 0

    async def reconcile():
        nonlocal rounds
        rounds += 1
        if rounds == 2:
            stop.set()

    async def wait(awaitable, *, timeout):
        awaitable.close()
        assert timeout == 30.0
        if not stop.is_set():
            raise timeout_type()
        return True

    monkeypatch.setattr(asyncio, "wait_for", wait)
    supervisor = SimpleNamespace(config=SimpleNamespace(poll_seconds=30), reconcile=reconcile)
    await runtime.SuccessorSupervisorRuntime.poll(supervisor, stop)
    assert rounds == 2


class Adapter:
    def __init__(self):
        self.events = []
        self.alive = None
        self.fail_stage = set()
        self.fail_preflight = False
        self.fail_recovery = False
        self.fail_stop = False
        self.fail_start = False
        self.health = True

    async def stage(self, selection):
        self.events.append(("stage", selection.directive_sha256))
        if selection.directive_sha256 in self.fail_stage:
            raise ValueError("staging failed")

    async def preflight(self, selection, observation):
        self.events.append(("preflight", selection.directive_sha256))
        if self.fail_preflight:
            raise ValueError("conflicting publication")

    async def stop_worker(self):
        self.events.append(("stop", self.alive))
        if self.fail_stop:
            raise ValueError("worker remains alive")
        self.alive = None

    async def recover_stopped_transactions(self, observation):
        assert self.alive is None
        self.events.append(("recover", observation.block))
        if self.fail_recovery:
            raise ValueError("ambiguous transaction")

    async def worker_is_healthy(self, selection):
        return self.health and self.alive == selection.directive_sha256

    async def start_replay(self, selection):
        assert selection.signed.directive.capabilities.wallet_access == "none"
        await self._start("replay", selection)

    async def start_weights(self, selection):
        assert (
            selection.signed.directive.capabilities.wallet_access
            == "configured_validator_hotkey_read_only"
        )
        await self._start("weights", selection)

    async def _start(self, mode, selection):
        assert self.alive is None
        self.alive = selection.directive_sha256
        self.events.append((mode, self.alive))
        if self.fail_start:
            raise ValueError("partial startup")


class Fetcher:
    def __init__(self, first):
        self.heads = {first.directive_sha256: first}
        self.pending = []
        self.unavailable = False
        self.more = False
        self.calls = []

    async def fetch_directive_page(self, **cursor):
        self.calls.append(cursor)
        if self.unavailable:
            return None
        directives = list(self.pending)
        for signed in directives:
            self.heads[signed.directive_sha256] = signed
        return canonical_json_bytes(
            SuccessorSupervisorDirectivePage(
                schema="umi-validator-supervisor-directive-page/4",
                **cursor,
                directives=directives,
                more=self.more,
                head=directives[-1] if directives else self.heads[cursor["after_directive_sha256"]],
            )
        )


@pytest.fixture
def case(tmp_path, successor_case, monkeypatch):
    source = successor_case
    root = tmp_path / "supervisor"
    root.mkdir(mode=0o700)
    config = source.predecessor.config.model_copy(update={"state_root": str(root)})
    consent = source.consent.model_copy(
        update={
            "source_config_sha256": successor_source_config_sha256(config),
        }
    )
    old = canonical_json_bytes(source.predecessor.state)
    (root / "directive-state.json").write_bytes(old)
    (root / "directive-state.json").chmod(0o600)
    lock_bytes = b'{"pid":100,"schema":"test-original-process-lock"}'
    (root / "supervisor-process.lock").write_bytes(lock_bytes)
    (root / "supervisor-process.lock").chmod(0o600)
    installation = SimpleNamespace(
        config=config,
        operator_consent=consent,
        v3_state=source.predecessor.state,
        v3_signed_bytes=source.predecessor.body,
        initial_page=SuccessorSupervisorDirectivePage(
            schema="umi-validator-supervisor-directive-page/4",
            after_version=3,
            after_sequence=source.predecessor.state.accepted_sequence,
            after_directive_sha256=source.predecessor.state.accepted_directive_sha256,
            directives=[source.signed],
            more=False,
            head=source.signed,
        ),
        initial_accepted_at_finalized_block=140,
        receipt_sha256="76" * 32,
        valid=True,
    )
    observation = SimpleNamespace(
        validator_hotkey=config.validator_hotkey,
        validator_permit=True,
        block=140,
        block_hash="0x" + "44" * 32,
        genesis_hash="0x" + source.chain.chain_pin.genesis_block_hash,
        live=True,
    )

    def checked_installation(value):
        # Explicit in-process fixture: production uses the fixed root receipt
        # loader, never a caller boolean or this Namespace.
        if value is not installation or not value.valid:
            raise ValueError("installation capability invalid")

    def checked_observation(value):
        if value is not observation or not value.live:
            raise ValueError("owned observation stale or forged")

    monkeypatch.setattr(runtime, "_validate_installation", checked_installation)
    monkeypatch.setattr(runtime, "validate_owned_weight_observation", checked_observation)
    adapter, fetcher = Adapter(), Fetcher(source.signed)

    async def observe():
        return observation

    limits = runtime.SuccessorRuntimeLimits(
        maximum_history_records=8,
        maximum_history_bytes=1024**2,
    )

    def make(**changes):
        values = dict(
            installation=installation,
            worker_adapter=adapter,
            directive_fetcher=fetcher,
            observation_reader=SimpleNamespace(observe=observe),
            limits=limits,
        )
        values.update(changes)
        return runtime.SuccessorSupervisorRuntime(**values)

    return SimpleNamespace(
        source=source,
        installation=installation,
        config=config,
        root=root,
        old=old,
        lock_bytes=lock_bytes,
        observation=observation,
        adapter=adapter,
        fetcher=fetcher,
        limits=limits,
        make=make,
    )


def next_directive(
    case, *, previous=None, sequence=3, mode="competition_replay", start=150, end=190
):
    return _signed(
        _directive(
            case.source.predecessor,
            case.source.target,
            case.source.release,
            case.source.chain,
            case.installation.operator_consent,
            mode=mode,
            sequence=sequence,
            predecessor_version=4,
            previous=previous or case.source.signed.directive_sha256,
            issued_at_block=140,
            valid_from_block=start,
            valid_through_block=end,
        )
    )


def worker_state(engine):
    return engine._load_history()[2]


@pytest.mark.asyncio
async def test_wallet_free_start_preserves_v3_bytes_and_original_lock(case):
    async with case.make() as engine:
        result = await engine.reconcile()
        assert result.status == "started" and result.accepted_sequence == 2
        assert case.adapter.events[0][0] == "stop"
        assert [event[0] for event in case.adapter.events].count("replay") == 1
        assert worker_state(engine).phase == "running"
        again = await engine.reconcile()
        assert again.status == "healthy"
    assert (case.root / "directive-state.json").read_bytes() == case.old
    assert (case.root / "supervisor-process.lock").read_bytes() == case.lock_bytes
    assert case.adapter.alive is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "operation",
    ["stage", "preflight", "start_replay", "worker_is_healthy", "recover_stopped_transactions"],
)
async def test_slow_adapter_work_requires_new_owned_observations(case, monkeypatch, operation):
    issued = []

    async def observe():
        value = SimpleNamespace(**vars(case.observation))
        issued.append(value)
        return value

    def validate(value):
        # Explicit issuer/freshness OS port: a spent proof cannot be refreshed
        # by mutating it; only a new call to this observer yields a live proof.
        if not any(value is item for item in issued) or not value.live:
            raise ValueError("expired or unowned observation")

    monkeypatch.setattr(runtime, "validate_owned_weight_observation", validate)
    original = getattr(case.adapter, operation)

    async def slow(*args):
        if operation in {"preflight", "recover_stopped_transactions"}:
            validate(args[-1])
        result = await original(*args)
        for item in issued:
            item.live = False
        return result

    monkeypatch.setattr(case.adapter, operation, slow)
    async with case.make(observation_reader=SimpleNamespace(observe=observe)) as engine:
        assert (await engine.reconcile()).status == "started"
        assert engine._observation.live
        assert (await engine.reconcile()).status == "healthy"
        assert engine._observation.live
        assert len(issued) > 2


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["permit", "genesis", "rollback", "expiry"])
async def test_new_proof_after_preflight_can_veto_start(case, monkeypatch, change):
    original = case.adapter.preflight

    async def changed_preflight(*args):
        await original(*args)
        if change == "permit":
            case.observation.validator_permit = False
        elif change == "genesis":
            case.observation.genesis_hash = "0x" + "99" * 32
        elif change == "rollback":
            case.observation.block = 139
        else:
            case.observation.block = 191

    monkeypatch.setattr(case.adapter, "preflight", changed_preflight)
    async with case.make() as engine:
        result = await engine.reconcile()
        assert result.status == "holding"
        assert case.adapter.alive is None
        assert not any(event[0] in {"replay", "weights"} for event in case.adapter.events)


@pytest.mark.asyncio
async def test_future_directive_stages_without_cursor_or_worker_change(case):
    async with case.make() as engine:
        await engine.reconcile()
        before = len(case.adapter.events)
        future = next_directive(case, start=160)
        case.fetcher.pending = [future]
        result = await engine.reconcile()
        assert result.status == "healthy" and result.accepted_sequence == 2
        assert ("stage", future.directive_sha256) in case.adapter.events[before:]
        assert not any(event[0] == "stop" for event in case.adapter.events[before:])
        assert worker_state(engine).directive_sha256 == case.source.signed.directive_sha256


@pytest.mark.asyncio
async def test_failed_future_stage_keeps_current_worker(case):
    async with case.make() as engine:
        await engine.reconcile()
        future = next_directive(case, start=160)
        case.fetcher.pending = [future]
        case.adapter.fail_stage.add(future.directive_sha256)
        before = len(case.adapter.events)
        result = await engine.reconcile()
        assert result.status == "healthy" and result.reason == "future_stage_failed"
        assert not any(event[0] == "stop" for event in case.adapter.events[before:])


@pytest.mark.asyncio
async def test_active_transition_stages_then_stops_recovers_accepts_starts(case):
    async with case.make() as engine:
        await engine.reconcile()
        selected = next_directive(case)
        case.fetcher.pending = [selected]
        case.observation.block = 150
        before = len(case.adapter.events)
        result = await engine.reconcile()
        assert result.status == "started" and result.accepted_sequence == 3
        events = case.adapter.events[before:]
        assert events[0:2] == [
            ("stage", selected.directive_sha256),
            ("preflight", selected.directive_sha256),
        ]
        assert [event[0] for event in events][2:4] == ["stop", "recover"]
        assert events[-1] == ("replay", selected.directive_sha256)
        case.fetcher.pending = []
    async with case.make() as restarted:
        result = await restarted.reconcile()
        assert result.accepted_sequence == 3 and result.status == "started"


@pytest.mark.asyncio
async def test_fixed_weights_dispatch_is_separate_from_wallet_free_mode(case):
    async with case.make() as engine:
        await engine.reconcile()
        weight = next_directive(case, mode="competition_weights")
        case.fetcher.pending = [weight]
        case.observation.block = 150
        result = await engine.reconcile()
        assert result.status == "started"
        assert case.adapter.events[-1] == ("weights", weight.directive_sha256)


@pytest.mark.parametrize("failure", ["permit", "stale", "conflict", "feed", "genesis", "expiry"])
@pytest.mark.asyncio
async def test_current_failures_stop_without_reset_or_new_start(case, failure):
    async with case.make() as engine:
        await engine.reconcile()
        before = len(case.adapter.events)
        if failure == "permit":
            case.observation.validator_permit = False
        elif failure == "stale":
            case.observation.live = False
        elif failure == "conflict":
            case.adapter.fail_preflight = True
        elif failure == "feed":
            case.fetcher.unavailable = True
        elif failure == "genesis":
            case.observation.genesis_hash = "0x" + "99" * 32
        else:
            case.observation.block = 191
        result = await engine.reconcile()
        assert result.status == "holding" and result.accepted_sequence == 2
        assert case.adapter.alive is None
        assert not any(event[0] in {"weights", "replay"} for event in case.adapter.events[before:])


@pytest.mark.asyncio
async def test_ambiguous_effect_prevents_replacement_and_restart(case):
    async with case.make() as engine:
        await engine.reconcile()
        case.fetcher.pending = [next_directive(case)]
        case.observation.block = 150
        case.adapter.fail_recovery = True
        result = await engine.reconcile()
        assert result.status == "holding" and result.accepted_sequence == 2
        assert case.adapter.alive is None
    async with case.make() as restarted:
        result = await restarted.reconcile()
        assert result.status == "holding" and result.accepted_sequence == 2
        case.adapter.fail_recovery = False
        assert (await restarted.reconcile()).accepted_sequence == 3


@pytest.mark.asyncio
async def test_partial_start_is_stopped_and_retained_for_restart_recovery(case):
    case.adapter.fail_start = True
    async with case.make() as engine:
        assert (await engine.reconcile()).status == "holding"
        assert case.adapter.alive is None
        assert worker_state(engine).phase == "stop_intent"
    case.adapter.fail_start = False
    async with case.make() as restarted:
        before = len(case.adapter.events)
        assert (await restarted.reconcile()).status == "started"
        assert [item[0] for item in case.adapter.events[before:]][:2] == ["stop", "recover"]


@pytest.mark.asyncio
async def test_crash_after_start_intent_recovers_before_any_new_start(case, monkeypatch):
    async with case.make() as engine:
        original = case.adapter.start_replay

        async def crashed(selection):
            raise KeyboardInterrupt("simulated abrupt process death")

        monkeypatch.setattr(case.adapter, "start_replay", crashed)
        with pytest.raises(KeyboardInterrupt):
            await engine.reconcile()
        assert worker_state(engine).phase == "start_intent"
        monkeypatch.setattr(case.adapter, "start_replay", original)
    async with case.make() as restarted:
        assert (await restarted.reconcile()).status == "started"


@pytest.mark.asyncio
async def test_expired_catchup_advances_history_without_executing_expired_work(case):
    async with case.make() as engine:
        await engine.reconcile()
        expired = next_directive(case, start=150, end=155)
        selected = next_directive(case, previous=expired.directive_sha256, sequence=4, start=160)
        case.fetcher.pending = [expired, selected]
        case.observation.block = 170
        before = len(case.adapter.events)
        result = await engine.reconcile()
        assert result.status == "started" and result.accepted_sequence == 4
        assert ("replay", expired.directive_sha256) not in case.adapter.events[before:]
        assert len(engine._load_history()[1]) == 3


@pytest.mark.asyncio
async def test_inactive_successor_after_expired_current_never_resumes_legacy(case):
    async with case.make() as engine:
        await engine.reconcile()
        case.observation.block = 191
        future = next_directive(case, start=200, end=220)
        case.fetcher.pending = [future]
        result = await engine.reconcile()
        assert result.status == "holding" and result.accepted_sequence == 2
        assert case.adapter.alive is None


@pytest.mark.asyncio
async def test_retained_signed_history_tampering_is_rejected_before_restart(case):
    async with case.make() as engine:
        await engine.reconcile()
    with sqlite3.connect(engine.path) as db:
        db.execute("UPDATE history SET signed=?", (b"{}",))
    with pytest.raises(runtime.SuccessorRuntimeError, match="anchor"):
        async with case.make():
            pytest.fail("corrupt history was accepted")
    assert case.adapter.alive is None


@pytest.mark.asyncio
async def test_existing_incomplete_v4_state_is_not_reinitialized(case):
    (case.root / "successor-v4").mkdir(mode=0o700)
    (case.root / "successor-v4" / "runtime").mkdir(mode=0o700)
    with pytest.raises(ValueError, match="incomplete"):
        async with case.make():
            pytest.fail("incomplete state was reset")
    assert not (case.root / "successor-v4" / "runtime" / "supervisor.sqlite3").exists()


@pytest.mark.asyncio
async def test_provisioned_shared_directories_do_not_masquerade_as_runtime_history(case):
    shared = case.root / "successor-v4"
    shared.mkdir(mode=0o700)
    for name in ("activation-source", "input-cache", "download-cache"):
        (shared / name).mkdir(mode=0o700)
    async with case.make() as engine:
        assert engine.path == shared / "runtime" / "supervisor.sqlite3"
        assert (await engine.reconcile()).status == "started"
    assert all(
        (shared / name).is_dir() for name in ("activation-source", "input-cache", "download-cache")
    )


@pytest.mark.asyncio
async def test_earlier_successor_sqlite_layout_is_retained_not_migrated_implicitly(case):
    shared = case.root / "successor-v4"
    shared.mkdir(mode=0o700)
    old = shared / "supervisor.sqlite3"
    old.write_bytes(b"retained earlier layout")
    old.chmod(0o600)
    with pytest.raises(runtime.SuccessorRuntimeError, match="explicit migration"):
        async with case.make():
            pytest.fail("earlier journal was reset")
    assert old.read_bytes() == b"retained earlier layout"
    assert not (shared / "runtime").exists()


@pytest.mark.asyncio
async def test_original_process_lock_prevents_second_runtime(case):
    async with case.make():
        with pytest.raises(BlockingIOError):
            async with case.make():
                pytest.fail("two runtimes held the original lock")


@pytest.mark.parametrize("change", ["block", "hash"])
@pytest.mark.asyncio
async def test_finalized_highwater_survives_restart_and_rejects_rollback(case, change):
    async with case.make() as engine:
        case.observation.block = 150
        await engine.reconcile()
    if change == "block":
        case.observation.block = 149
    else:
        case.observation.block_hash = "0x" + "65" * 32
    async with case.make() as restarted:
        assert (await restarted.reconcile()).status == "holding"
        assert case.adapter.alive is None


@pytest.mark.asyncio
async def test_concurrent_reconciles_never_start_duplicate_workers(case):
    async with case.make() as engine:
        results = await asyncio.gather(engine.reconcile(), engine.reconcile())
        assert {item.status for item in results} == {"started", "healthy"}
        assert sum(event[0] == "replay" for event in case.adapter.events) == 1


@pytest.mark.asyncio
async def test_history_capacity_never_evicts_or_advances_cursor(case):
    limits = case.limits.model_copy(update={"maximum_history_records": 1})
    async with case.make(limits=limits) as engine:
        await engine.reconcile()
        case.fetcher.pending = [next_directive(case)]
        case.observation.block = 150
        result = await engine.reconcile()
        assert result.status == "holding" and result.accepted_sequence == 2
        assert len(engine._load_history()[1]) == 1


@pytest.mark.asyncio
async def test_v3_highwater_change_stops_current_worker_and_never_overwrites_it(case):
    engine = case.make()
    await engine.__aenter__()
    try:
        await engine.reconcile()
        changed = b"{}"
        (case.root / "directive-state.json").write_bytes(changed)
        result = await engine.reconcile()
        assert result.status == "holding" and case.adapter.alive is None
        assert (case.root / "directive-state.json").read_bytes() == changed
    finally:
        # Restore only this synthetic fixture so normal context shutdown can
        # verify the unchanged installation contract.
        (case.root / "directive-state.json").write_bytes(case.old)
        await engine.__aexit__(None, None, None)


@pytest.mark.parametrize("corruption", ["installation", "journal", "write_failure"])
@pytest.mark.asyncio
async def test_shutdown_stops_even_when_state_validation_or_persistence_fails(
    case, monkeypatch, corruption
):
    engine = case.make()
    await engine.__aenter__()
    await engine.reconcile()
    original = engine._store_worker
    if corruption == "installation":
        case.installation.valid = False
    elif corruption == "journal":
        with sqlite3.connect(engine.path) as db:
            db.execute("UPDATE worker SET body=?", (b"{}",))
    else:

        def fail_write(*_args):
            raise OSError("injected disk error")

        monkeypatch.setattr(engine, "_store_worker", fail_write)
    try:
        with pytest.raises((ValueError, OSError)):
            await engine.__aexit__(None, None, None)
        assert case.adapter.alive is None
        assert engine._lock_fd >= 0
    finally:
        case.installation.valid = True
        monkeypatch.setattr(engine, "_store_worker", original)
        engine._store_worker(runtime._idle())
        await engine.__aexit__(None, None, None)


@pytest.mark.asyncio
async def test_singleton_and_history_byte_bounds_precede_blob_materialization(case):
    async with case.make() as engine:
        await engine.reconcile()
    with sqlite3.connect(engine.path) as db:
        db.execute("UPDATE worker SET body=?", (b"0" * 8193,))
    with pytest.raises(ValueError, match="bounds"):
        async with case.make():
            pytest.fail("oversized worker body was read")


@pytest.mark.asyncio
async def test_partial_feed_page_never_executes_its_intermediate_head(case):
    async with case.make() as engine:
        await engine.reconcile()
        intermediate = next_directive(case)
        case.fetcher.pending = [intermediate]
        case.fetcher.more = True
        case.observation.block = 150
        before = len(case.adapter.events)
        result = await engine.reconcile()
        assert result.status == "holding" and result.accepted_sequence == 3
        assert case.adapter.alive is None
        assert not any(item[0] in {"weights", "replay"} for item in case.adapter.events[before:])
        case.fetcher.pending = []
        case.fetcher.more = False
        assert (await engine.reconcile()).status == "started"


@pytest.mark.asyncio
async def test_post_stop_observation_controls_recovery_and_acceptance_block(case):
    observed_stops = 0

    async def observe():
        nonlocal observed_stops
        stops = sum(event[0] == "stop" for event in case.adapter.events)
        if stops != observed_stops:
            assert case.adapter.events[-1][0] == "stop"
            observed_stops = stops
            case.observation.block = 142 if stops == 1 else 151
        return case.observation

    async with case.make(observation_reader=SimpleNamespace(observe=observe)) as engine:
        assert (await engine.reconcile()).finalized_block == 142
        assert ("recover", 142) in case.adapter.events
        case.fetcher.pending = [next_directive(case)]
        case.observation.block = 150
        result = await engine.reconcile()
        assert result.status == "started" and result.finalized_block == 151
        assert engine._load_history()[0].accepted_at_finalized_block == 151
        assert ("recover", 151) in case.adapter.events


def test_plain_installation_document_cannot_replace_authenticated_host_capability():
    with pytest.raises(ValueError):
        runtime._validate_installation(SimpleNamespace(receipt_sha256="76" * 32))


@pytest.mark.asyncio
async def test_missing_entire_successor_state_cannot_reset_to_initial_cursor(case):
    async with case.make() as engine:
        await engine.reconcile()
        case.fetcher.pending = [next_directive(case)]
        case.observation.block = 150
        assert (await engine.reconcile()).accepted_sequence == 3
    # Remove only this synthetic test's v4 directory. The marker retained next
    # to the untouched v3 high-water must prevent silent initialization.
    shutil.rmtree(engine.root)
    with pytest.raises(ValueError, match="incomplete"):
        async with case.make():
            pytest.fail("deleted v4 history was reset")
    assert not engine.root.exists()
    assert (case.root / "directive-state.json").read_bytes() == case.old


async def test_multi_page_catchup_and_restart_deliver_complete_installation_history(
    case, monkeypatch
):
    page_size = MAX_SUPERVISOR_DIRECTIVES_PER_PAGE
    first = next_directive(case)
    records = [first, *_signed_continuation(first, page_size + 3)]
    selections = []
    stage = case.adapter.stage

    async def capture(selection):
        selections.append(selection)
        await stage(selection)

    monkeypatch.setattr(case.adapter, "stage", capture)
    limits = runtime.SuccessorRuntimeLimits(
        maximum_history_records=128, maximum_history_bytes=1024**2
    )
    case.observation.block = 160
    case.fetcher.pending = records[:page_size]
    case.fetcher.more = True
    async with case.make(limits=limits) as engine:
        first = await engine.reconcile()
        assert first.status == "holding" and first.accepted_sequence == 2 + page_size
        assert case.adapter.alive is None
        case.fetcher.pending = records[page_size:]
        case.fetcher.more = False
        assert (await engine.reconcile()).status == "started"
        expected = selections[-1].continuation_bytes
        parsed = parse_canonical_successor_supervisor_directive_history(expected)
        assert parsed.directives == records
        assert parsed.after_directive_sha256 == case.source.signed.directive_sha256
        assert parsed.head == records[-1]
    case.fetcher.pending = []
    async with case.make(limits=limits) as restarted:
        assert (await restarted.reconcile()).status == "started"
        assert selections[-1].continuation_bytes == expected
        assert len(restarted._load_history()[1]) == len(records) + 1
    assert (case.root / "directive-state.json").read_bytes() == case.old
