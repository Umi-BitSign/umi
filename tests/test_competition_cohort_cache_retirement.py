"""Terminal cleanup uses real slots, leases and durable intent recovery."""

import asyncio
from collections import Counter
from types import SimpleNamespace

import pytest

from umi.competition_artifacts import _file_identity
from umi.competition_cohort_cache_retirement import TerminalModelCacheRetirement
from umi.competition_cohort_order_signer import (
    remember_closed_order_history,
    verified_order_history,
)
from umi.competition_cohort_sandbox import DirectCohortCpuSandbox
from umi.competition_model_cache_space import BootDiskModelCacheConfig
from umi.competition_round_journal import RoundJournal
from umi.open_competition import digest
from umi.private_files import ensure_private_directory


@pytest.fixture
def cache(tmp_path):
    model, incumbent, cohort = "ab" * 32, "cd" * 32, "ef" * 32
    root = tmp_path / "boot"
    ensure_private_directory(root)
    selected = root / "direct-model-cache"
    ensure_private_directory(selected)
    archive = selected / "archive"
    ensure_private_directory(archive)
    ensure_private_directory(archive / model)
    payload = archive / model / "payload"
    payload.write_bytes(b"inert model")
    payload.chmod(0o600)
    remote = tmp_path / "remote-result.json"
    remote.write_bytes(b"retained durable byte result")
    remote.chmod(0o600)
    boot = BootDiskModelCacheConfig(
        schema="umi-boot-disk-model-cache/1",
        directory=str(root),
        maximum_allocated_bytes=1024**2,
    )
    port = object.__new__(DirectCohortCpuSandbox)
    port.cache, port.boot = selected, boot
    port.materializations, port.paired_execution = asyncio.Condition(), asyncio.Lock()
    port.active_candidate_invocations = 0
    port.parallel = None
    port.slot_identities, port.slot_recency = {}, {}
    port.artifacts = SimpleNamespace(
        config=SimpleNamespace(materialization_free_space_reserve_bytes=0)
    )
    state = SimpleNamespace(checks=0, terminal=True, completed=True, frozen=False)

    def check(request, path):
        assert request == "original request" and path == archive
        state.checks += 1
        return dict(
            model_sha256=model,
            request_sha256="01" * 32,
            payload_bytes=11,
            remote_records={str(remote): _file_identity(remote.stat())},
        )

    async def source(job, role):
        assert role == "candidate"
        return SimpleNamespace(
            request="original request",
            materializer=SimpleNamespace(completed_cache_retirement=check),
        )

    port._source_plan = source
    order = SimpleNamespace(
        round=SimpleNamespace(cohort_sha256=cohort, incumbent_model_sha256=incumbent)
    )
    assignment = SimpleNamespace(certificate=SimpleNamespace(order=order))

    async def completed(value, slot):
        assert value is assignment and slot == "assignment"
        return object() if state.completed else None

    worker = SimpleNamespace(
        inbox=SimpleNamespace(
            assignments_for_models=lambda revisions, limit: ("assignment",),
            assignment=lambda slot: assignment,
            protects_incumbent=lambda revision: state.frozen,
        ),
        executor=SimpleNamespace(
            sandbox=port,
            _completed=completed,
            journal=SimpleNamespace(validate_assignment=lambda value: object()),
        ),
    )
    journal = RoundJournal(
        tmp_path / "journal", {"owner": "test"}, maximum_rounds=32, maximum_bytes=1024**2
    )
    baseline = dict(model_sha256=incumbent, held_for_conflict=False)
    promotion = SimpleNamespace(baseline_summary=lambda: baseline)

    def create():
        value = TerminalModelCacheRetirement(worker, journal, promotion)

        async def terminal(selected_cohort):
            assert selected_cohort == cohort
            return {"terminal_history": cohort} if state.terminal else None

        value._terminal = terminal
        return value

    return SimpleNamespace(
        create=create,
        port=port,
        state=state,
        baseline=baseline,
        archive=archive,
        model=model,
        remote=remote,
        journal=journal,
        payload=payload,
        worker=worker,
    )


async def test_terminal_candidate_retires_once_and_preserves_owner_state(cache):
    s = cache
    assert await s.create()() == {"status": "completed", "retired_models": 1, "payload_bytes": 11}
    assert not s.archive.exists() and s.remote.read_bytes() == b"retained durable byte result"
    assert len(s.journal.keys("model_cache_retirement")) == 1
    assert len(s.journal.keys("model_cache_retired")) == 1
    assert (await s.create()())["retired_models"] == 0
    assert s.state.checks == 1


@pytest.mark.parametrize(
    "hold", ["nonterminal", "unfinished", "incumbent", "frozen", "reader", "pair", "transfer"]
)
async def test_ineligible_or_busy_slots_survive(cache, hold):
    s = cache
    if hold == "nonterminal":
        s.state.terminal = False
    elif hold == "unfinished":
        s.state.completed = False
    elif hold == "incumbent":
        s.baseline["model_sha256"] = s.model
    elif hold == "frozen":
        s.state.frozen = True
    elif hold == "reader":
        s.port.active_candidate_invocations = 1
    elif hold == "pair":
        await s.port.paired_execution.acquire()
    else:
        (s.archive / "materialization-pending.json").write_text("pending")
    assert (await s.create()())["retired_models"] == 0
    assert s.payload.exists() and s.state.checks == 0


@pytest.mark.parametrize("busy", ["reader", "pin", "loader"])
async def test_parallel_consumer_or_transfer_is_never_evicted(cache, busy):
    s = cache
    selected = "candidate"
    parallel = SimpleNamespace(
        condition=asyncio.Condition(),
        slots=(s.archive,),
        readers=Counter(),
        pins=Counter(),
        assigned={s.archive: selected},
        locks={s.archive: asyncio.Lock()},
        recency={},
    )
    if busy == "reader":
        parallel.readers[s.archive] = 1
    elif busy == "pin":
        parallel.pins[selected] = 1
    else:
        await parallel.locks[s.archive].acquire()
    s.port.parallel = parallel
    assert (await s.create()())["retired_models"] == 0
    assert s.payload.exists() and s.state.checks == 0


@pytest.mark.parametrize("interrupt", ["partial_unlink", "after_unlink"])
async def test_restart_resumes_intent_without_reverification(cache, interrupt):
    s = cache
    native = s.port._evict_archive

    async def fail(path, *, leased):
        if interrupt == "partial_unlink":
            s.payload.unlink()
        else:
            await native(path, leased=leased)
        raise OSError("injected interruption")

    s.port._evict_archive = fail
    with pytest.raises(OSError, match="injected"):
        await s.create()()
    assert len(s.journal.keys("model_cache_retirement")) == 1
    assert not s.journal.keys("model_cache_retired")
    s.port._evict_archive = native
    assert (await s.create()())["status"] == "completed"
    assert not s.archive.exists() and s.state.checks == 1


async def test_changed_remote_completion_blocks_resumed_retirement(cache):
    s = cache

    async def fail(*args, **kwargs):
        raise OSError("leave intended release")

    s.port._evict_archive = fail
    with pytest.raises(OSError):
        await s.create()()
    s.remote.write_bytes(b"changed remote completion")
    assert (await s.create()())["reason"] == "terminal_cache_intent_requires_repair"
    assert s.payload.exists() and s.state.checks == 1


async def test_replaced_slot_is_not_removed_by_old_intent(cache):
    s = cache

    async def fail(*args, **kwargs):
        raise OSError("leave intended release")

    s.port._evict_archive = fail
    with pytest.raises(OSError):
        await s.create()()
    s.archive.rename(s.archive.with_name("original-retained"))
    ensure_private_directory(s.archive)
    assert (await s.create()())["reason"] == "terminal_cache_intent_requires_repair"
    assert s.archive.exists() and s.state.checks == 1


async def test_held_intent_does_not_block_another_terminal_candidate(cache):
    s = cache
    cleanup = s.create()
    standby = s.port.cache / "standby"
    ensure_private_directory(standby)
    incumbent = s.baseline["model_sha256"]
    ensure_private_directory(standby / incumbent)
    intent = dict(
        slot=str(standby),
        slot_identity=cleanup._slot_identity(standby),
        model_sha256=incumbent,
        payload_bytes=9,
        remote_records={str(s.remote): _file_identity(s.remote.stat())},
    )
    s.journal.put("model_cache_retirement", digest(intent), intent)
    assert (await cleanup())["retired_models"] == 1
    assert not s.archive.exists() and standby.exists()
    assert s.journal.get("model_cache_retired", digest(intent)) is None


async def test_resumed_intent_must_match_its_original_identity(cache):
    s = cache
    with pytest.raises(ValueError, match="intent identity requires repair"):
        await s.create()._retire("00" * 32, {"slot": str(s.archive)})
    assert s.payload.exists()


@pytest.mark.parametrize("phase", ["requests", "certification", "complete"])
async def test_terminal_discovery_uses_native_owner_history_and_retains_only_complete(cache, phase):
    s = cache
    plan, authority = {"cohort": 7}, {"authority": "original"}
    cohort = digest(plan)
    source = SimpleNamespace(
        history=SimpleNamespace(plan=plan, authority=SimpleNamespace(authority=authority))
    )
    executor = s.worker.executor
    executor.journal.cohorts = {cohort: digest(authority)}
    executor.journal.policy, executor.journal.journal = object(), s.journal
    calls, retained = [], []

    async def history(selected):
        assert selected == cohort
        calls.append("fetch")
        return source

    def verified(function, *args):
        assert source in args
        if function is verified_order_history:
            calls.append("native_verification_reuse")
            return SimpleNamespace(state=SimpleNamespace(phase=phase))
        assert function is remember_closed_order_history
        calls.append("retain_monotonic_history")
        retained.append(source)
        return True

    executor.history, executor._verified = history, verified
    cleanup = TerminalModelCacheRetirement(s.worker, s.journal, SimpleNamespace())
    cleanup._retained_history = lambda _: retained[0] if retained else None
    result = await cleanup._terminal(cohort)
    assert (result is source) == (phase == "complete")
    assert ("retain_monotonic_history" in calls) == (phase == "complete")
    assert await cleanup._terminal(cohort) is result
    assert calls.count("fetch") == 1
    if phase == "complete":
        restarted = TerminalModelCacheRetirement(s.worker, s.journal, SimpleNamespace())
        restarted._retained_history = cleanup._retained_history
        assert await restarted._terminal(cohort) is source
        assert calls.count("fetch") == 1


async def test_retained_terminal_with_another_authority_is_rejected(cache):
    s = cache
    plan = {"cohort": 7}
    cohort = digest(plan)
    source = SimpleNamespace(
        history=SimpleNamespace(plan=plan, authority=SimpleNamespace(authority={"wrong": True}))
    )
    s.worker.executor.journal.cohorts = {cohort: digest({"original": True})}
    cleanup = TerminalModelCacheRetirement(s.worker, s.journal, SimpleNamespace())
    cleanup._retained_history = lambda _: source
    with pytest.raises(ValueError, match="changed its cohort authority"):
        await cleanup._terminal(cohort)
