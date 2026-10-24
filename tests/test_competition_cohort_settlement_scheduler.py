"""Real role leases and service APIs with tiny retained/native graph ports."""

import asyncio
import json
import logging
import threading
import weakref
from types import SimpleNamespace

import pytest

from tests.test_competition_cohort_settlement_lifetime import Marker, blank, graph, ready
from tests.test_host_memory_admission import provisioned as provisioned
from tests.test_host_memory_admission import selected
from umi.competition_cohort_settlement_service import (
    CohortSettlementService,
    SettlementSeriesScheduler,
)
from umi.concurrency import run_owned_thread


def retained_input_snapshot(node, path, package, monkeypatch):
    """Represent the native first review required before compact maintenance."""
    from umi import competition_cohort_settlement_service as service
    from umi.competition_verification_snapshot import VerificationPackageStore

    monkeypatch.setattr(service, "SettlementInputPackage", type(package))
    node.verified_packages = VerificationPackageStore(path.parent / "verified-inputs")
    node.verified_packages.load(
        path, type(package), maximum_bytes=node.config.maximum_package_bytes
    )


async def replicas(provisioned, coordinator_done=0, reviewer_done=0):
    ports = SimpleNamespace(
        input_delivered=[False] * 6,
        history_delivered=[False] * 6,
        originals=[True] * 6,
        outputs=[i < coordinator_done for i in range(6)],
        handoffs=[True] * 6,
        pending=set(),
        loaded=[],
        graph_refs=[],
        repaired_votes=[],
    )
    roles = {}
    for role, done in (("coordinator", coordinator_done), ("reviewer", reviewer_done)):
        nodes = []
        for index in range(6):
            node = blank()
            node.last_report = None
            state, history = await ready(node, role=role)
            node.cohort = f"{index:064x}"
            node.config.poll_seconds = 0.001
            node._memory_admission, node._memory_lease = selected(provisioned), None

            async def selected_history(i=index, value=history, selected_role=role):
                if not ports.handoffs[i] or (
                    selected_role == "reviewer" and not ports.history_delivered[i]
                ):
                    raise FileNotFoundError("original authenticated handoff unavailable")
                return value

            async def replicate(i=index):
                if not ports.originals[i]:
                    raise FileNotFoundError("mandatory original input unavailable")
                ports.input_delivered[i] = True

            async def publish(value, i=index):
                ports.history_delivered[i] = True

            async def check(i=index):
                if not ports.outputs[i]:
                    raise FileNotFoundError("generated output absent")

            async def review(*, terminal, i=index):
                assert terminal
                ports.repaired_votes.append(i)

            async def remember(package, i=index):
                ports.outputs[i] = True

            async def load(value, owner=node, i=index, selected_role=role):
                if not ports.originals[i] or (
                    selected_role == "reviewer" and not ports.input_delivered[i]
                ):
                    raise FileNotFoundError("mandatory original input unavailable")
                ports.loaded.append((selected_role, i))
                ports.graph_refs.append((selected_role, i, graph(owner)))
                owner.votes = None
                owner.phases.owner.advance = lambda *a, **kw: SimpleNamespace(
                    status="pending" if i in ports.pending else "package_published",
                    package=object(),
                )
                owner.source = lambda: SimpleNamespace(
                    inputs=SimpleNamespace(history=value),
                    intake=(),
                    quality_votes=(),
                    service_votes=(),
                )

            node._selected_history = selected_history
            node._replicate_inputs, node._publish_history = replicate, publish
            node._check_reward_package, node._remember_reward_package = check, remember
            node._review_requests, node._load_active_inputs = review, load
            if index < done:
                node.terminal_certification_sha256 = "original-certified-prefix"
                if role == "coordinator":
                    node.published_tip = state.tip_sha256
                else:
                    graph(node)
                    node._release_active_inputs(retain_exchange=True)
                    node.reviewed_terminal_tip = state.tip_sha256
            nodes.append(node)
        roles[role] = nodes
    schedulers = {
        role: SettlementSeriesScheduler(nodes, ordered_cohorts=tuple(n.cohort for n in nodes))
        for role, nodes in roles.items()
    }
    return ports, roles, schedulers


@pytest.mark.parametrize("coordinator_done", range(6))
@pytest.mark.parametrize("reviewer_done", range(6))
async def test_both_roles_recover_every_six_cohort_restart_skew(
    provisioned, coordinator_done, reviewer_done
):
    ports, roles, schedulers = await replicas(provisioned, coordinator_done, reviewer_done)
    for _ in range(8):
        for scheduler in schedulers.values():
            await scheduler.tick()
        for role in roles:
            assert sum(ref() is not None for r, _, ref in ports.graph_refs if r == role) <= 1
    assert all(node.published_tip for node in roles["coordinator"])
    assert all(node.reviewed_terminal_tip for node in roles["reviewer"])
    assert all(ports.input_delivered) and all(ports.history_delivered)
    assert [i for role, i in ports.loaded if role == "coordinator"] == list(
        range(coordinator_done, 6)
    )
    assert [i for role, i in ports.loaded if role == "reviewer"] == list(range(reviewer_done, 6))
    assert all(ref() is None for _, _, ref in ports.graph_refs)
    assert all(node._memory_lease is None for nodes in roles.values() for node in nodes)


async def test_missing_earlier_handoff_blocks_later_native_start(provisioned):
    ports, _, schedulers = await replicas(provisioned)
    ports.handoffs[0] = False
    for _ in range(3):
        await schedulers["coordinator"].tick()
    assert ports.loaded == []
    ports.handoffs[0] = True
    await schedulers["coordinator"].tick()
    assert ports.loaded == [("coordinator", 0)]


async def test_explicit_holds_preserve_series_without_blocking_next_cohort(provisioned, caplog):
    ports, roles, _ = await replicas(provisioned)
    nodes = roles["coordinator"]
    cohorts = tuple(node.cohort for node in nodes)
    ports.handoffs[0] = False
    holds = (cohorts[0], *cohorts[2:])
    scheduler = SettlementSeriesScheduler(nodes, ordered_cohorts=cohorts, held_cohorts=holds)
    with caplog.at_level(logging.INFO, logger="umi.competition_cohort_settlement_service"):
        await scheduler.tick()
    assert ports.loaded == [("coordinator", 1)]
    assert tuple(node.cohort for node in scheduler.nodes) == cohorts
    assert all(nodes[index] not in scheduler._completed for index in (0, 2, 3, 4, 5))
    assert ports.outputs[0] is False
    assert all(nodes[index].data is None for index in (0, 2, 3, 4, 5))
    held_events = [
        json.loads(r.message.partition(" ")[2])
        for r in caplog.records
        if r.message.startswith("settlement_progression_hold ")
    ]
    assert {event["cohort_sha256"] for event in held_events} == set(holds)
    assert all(
        event["eta_seconds"] is None
        and event["completed"] == 0
        and event["eta_basis"] == "awaiting_explicit_configuration_release"
        for event in held_events
    )


async def test_holding_all_cohorts_does_not_load_or_certify_any_graph(provisioned):
    ports, roles, _ = await replicas(provisioned)
    nodes = roles["coordinator"]
    cohorts = tuple(node.cohort for node in nodes)
    scheduler = SettlementSeriesScheduler(nodes, ordered_cohorts=cohorts, held_cohorts=cohorts)
    await scheduler.tick()
    assert scheduler.active is None and not scheduler._completed
    assert ports.loaded == [] and not any(ports.outputs)
    with pytest.raises(ValueError, match="holds"):
        SettlementSeriesScheduler(
            nodes, ordered_cohorts=cohorts, held_cohorts=(cohorts[0], cohorts[0])
        )
    with pytest.raises(ValueError, match="holds"):
        SettlementSeriesScheduler(nodes, ordered_cohorts=cohorts, held_cohorts=("f" * 64,))


async def test_missing_generated_output_steps_back_and_releases_later_graph(provisioned):
    ports, roles, schedulers = await replicas(provisioned, coordinator_done=1)
    scheduler = schedulers["coordinator"]
    ports.pending.add(1)
    await scheduler.tick()
    later = roles["coordinator"][1]
    held, old_graph = later._memory_lease, ports.graph_refs[-1][2]
    assert held is not None and not held.closed and old_graph() is later.data
    ports.outputs[0] = False
    await scheduler.tick()
    assert held.closed and old_graph() is None
    assert ports.outputs[0]
    assert ports.loaded == [("coordinator", 1), ("coordinator", 0)]
    ports.pending.clear()
    await scheduler.tick()
    assert ports.loaded[-1] == ("coordinator", 1)
    assert later.published_tip and later._memory_lease is None


async def test_missing_original_is_restore_only_and_preserves_earlier_priority(provisioned):
    ports, roles, schedulers = await replicas(provisioned, coordinator_done=1)
    scheduler = schedulers["coordinator"]
    ports.pending.add(1)
    await scheduler.tick()
    held = roles["coordinator"][1]._memory_lease
    ports.originals[0], ports.outputs[0] = False, False
    for _ in range(3):
        await scheduler.tick()
    assert held.closed and ports.loaded == [("coordinator", 1)]
    assert not ports.outputs[0]
    ports.originals[0] = True
    await scheduler.tick()
    assert ports.outputs[0] and ports.loaded[-1] == ("coordinator", 0)


async def test_completed_deliveries_repair_without_stealing_later_native_slot(provisioned):
    ports, roles, schedulers = await replicas(provisioned, coordinator_done=1)
    scheduler = schedulers["coordinator"]
    ports.pending.add(1)
    await scheduler.tick()
    held = roles["coordinator"][1]._memory_lease
    ports.input_delivered[0] = ports.history_delivered[0] = False
    await scheduler.tick()
    assert ports.input_delivered[0] and ports.history_delivered[0]
    assert roles["coordinator"][1]._memory_lease is held and not held.closed
    assert ("coordinator", 0) not in ports.loaded
    scheduler._suspend()


async def test_terminal_extension_keeps_prefix_and_refuses_changed_certification(provisioned):
    ports, roles, _ = await replicas(provisioned, coordinator_done=1, reviewer_done=1)
    for role in roles:
        node = roles[role][0]
        ports.history_delivered[0] = True
        state = node.store.status(node.cohort)[0]
        state.phase, state.tip_sha256 = "complete", "appended-final-transition"
        assert await node.maintain() in {"package_published", "reviewing"}
        assert node.data is None and node._memory_lease is None
        node._certification_prefix = lambda history: "different-prefix"
        with pytest.raises(ValueError, match="certified allocation prefix"):
            await node.maintain()
    assert ports.loaded == []


async def test_scheduler_repeated_cancellation_drains_owned_loader_before_release(provisioned):
    ports, roles, schedulers = await replicas(provisioned)
    scheduler, node = schedulers["coordinator"], roles["coordinator"][0]
    entered, release = threading.Event(), threading.Event()
    original = node._load_active_inputs

    def work():
        entered.set()
        assert release.wait(10)

    async def load(history):
        await original(history)
        await run_owned_thread(work)

    node._load_active_inputs = load
    task = asyncio.create_task(scheduler.run(asyncio.Event()))
    assert await asyncio.to_thread(entered.wait, 5)
    held = node._memory_lease
    task.cancel()
    await asyncio.sleep(0)
    task.cancel()
    await asyncio.sleep(0)
    assert not task.done() and not held.closed and node.data is not None
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert held.closed and node.data is None and scheduler.active is None
    assert all(ref() is None for _, _, ref in ports.graph_refs)


async def eventually(predicate):
    async def wait():
        while not predicate():
            await asyncio.sleep(0.001)

    await asyncio.wait_for(wait(), timeout=5)


async def test_original_input_snapshot_load_runs_off_loop():
    from umi import competition_cohort_settlement_service as service

    node = blank()
    _, history = await ready(node)
    node.config.inputs_directory = "/unused-original"
    node.journal = SimpleNamespace(get=lambda *args: None)
    loop_thread = threading.get_ident()

    def load(path, model, *, maximum_bytes):
        assert path.name == node.cohort + ".json"
        assert str(path.parent) == node.config.inputs_directory
        assert model is service.SettlementInputPackage
        assert maximum_bytes == node.config.maximum_package_bytes
        assert threading.get_ident() != loop_thread
        raise OSError("stop after original snapshot load boundary")

    node.verified_packages = SimpleNamespace(load=load)
    with pytest.raises(OSError, match="original snapshot load boundary"):
        await node._load_active_inputs(history)


@pytest.mark.parametrize("cancel", [False, True])
async def test_output_digest_runs_off_loop_with_package_and_lease_owned(
    provisioned, monkeypatch, cancel
):
    from umi import competition_cohort_settlement_service as service

    ports, roles, schedulers = await replicas(provisioned)
    node, scheduler = roles["coordinator"][0], schedulers["coordinator"]
    entered, release = threading.Event(), threading.Event()
    references, loop_thread = [], threading.get_ident()
    node.config.settlement_directory = "/unused-output"
    node._remember_reward_package = CohortSettlementService._remember_reward_package.__get__(node)
    original_load, original_release = node._load_active_inputs, node._release_memory

    def advance(*args, **kwargs):
        package = Marker()
        references.append(weakref.ref(package))
        return SimpleNamespace(status="package_published", package=package)

    def digest(package):
        assert threading.get_ident() != loop_thread
        assert package is references[-1]()
        assert node._memory_lease is not None and not node._memory_lease.closed
        entered.set()
        assert release.wait(10)
        assert node._memory_lease is not None and not node._memory_lease.closed
        return "original-output-digest"

    async def load(history):
        await original_load(history)
        node.phases.owner.advance = advance

    def release_memory():
        assert all(reference() is None for reference in references)
        assert node.data is None
        original_release()

    node._load_active_inputs, node._release_memory = load, release_memory
    monkeypatch.setattr(service, "digest", digest)
    # Refuse the next handoff so a successful first tick remains observable.
    ports.handoffs[1] = False
    task = asyncio.create_task(scheduler.run(asyncio.Event()))
    try:
        assert await asyncio.to_thread(entered.wait, 5)
        held = node._memory_lease
        assert references[-1]() is not None and not held.closed
        if cancel:
            task.cancel()
            await asyncio.sleep(0)
            task.cancel()
            await asyncio.sleep(0)
            assert not task.done() and not held.closed
        release.set()
        if cancel:
            with pytest.raises(asyncio.CancelledError):
                await task
        else:
            await eventually(lambda: node.published_tip is not None)
            assert node.reward_package_reference[1] == "original-output-digest"
        assert held.closed and all(reference() is None for reference in references)
    finally:
        release.set()
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)


@pytest.mark.parametrize("missing_output", [False, True])
async def test_compact_replica_repair_runs_during_later_native_work(
    provisioned, tmp_path, missing_output, monkeypatch
):
    from umi.competition_cohort_aggregate_model import AggregateProtocolModel
    from umi.competition_cohort_reward_package import RewardPackageObject
    from umi.open_competition import digest
    from umi.protocol import canonical_json_bytes

    class Package(AggregateProtocolModel):
        payload: str
        objects: tuple[RewardPackageObject, ...] = ()

    ports, roles, schedulers = await replicas(provisioned, coordinator_done=1)
    earlier, later = roles["coordinator"][:2]
    scheduler = schedulers["coordinator"]
    ports.pending.add(1)
    entered, release = threading.Event(), threading.Event()
    original_load = later._load_active_inputs
    original = tmp_path / "original.json"
    package = Package(payload="native-reviewed-original")
    original.write_bytes(canonical_json_bytes(package))
    original.chmod(0o600)
    earlier.package_reference = original, digest(package)
    retained_input_snapshot(earlier, original, package, monkeypatch)
    earlier.config.exchange_outbox = str(tmp_path / "outbox")
    earlier._replicate_inputs = CohortSettlementService._replicate_inputs.__get__(earlier)
    replica = tmp_path / "outbox" / "inputs" / (earlier.cohort + ".json")

    def worker():
        entered.set()
        assert release.wait(10)

    async def load(history):
        await original_load(history)
        await run_owned_thread(worker)

    later._load_active_inputs = load
    task = asyncio.create_task(scheduler.run(asyncio.Event()))
    try:
        assert await asyncio.to_thread(entered.wait, 5)
        held, reference = later._memory_lease, ports.graph_refs[-1][2]
        replica.unlink()
        if missing_output:
            ports.outputs[0] = False
        await eventually(replica.exists)
        assert replica.read_bytes() == original.read_bytes()
        assert not release.is_set() and not held.closed and reference() is later.data
        assert ports.loaded == [("coordinator", 1)]
        if missing_output:
            await eventually(lambda: earlier.cohort in scheduler.recovery_requested)
            assert not ports.outputs[0] and not held.closed
            earlier_load = earlier._load_active_inputs

            async def recover(history):
                assert held.closed and reference() is None
                await earlier_load(history)

            earlier._load_active_inputs = recover
            release.set()
            await eventually(lambda: ports.outputs[0])
            assert ports.loaded[:2] == [("coordinator", 1), ("coordinator", 0)]
    finally:
        release.set()
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
    assert all(reference() is None for _, _, reference in ports.graph_refs)


async def test_shutdown_drains_independent_compact_and_native_workers(provisioned):
    ports, roles, schedulers = await replicas(provisioned, coordinator_done=1)
    earlier, later = roles["coordinator"][:2]
    scheduler = schedulers["coordinator"]
    native_entered, native_release = threading.Event(), threading.Event()
    compact_entered, compact_release = threading.Event(), threading.Event()
    original_load, original_replicate = later._load_active_inputs, earlier._replicate_inputs
    ports.pending.add(1)

    def native():
        native_entered.set()
        assert native_release.wait(10)

    def compact():
        compact_entered.set()
        assert compact_release.wait(10)

    async def load(history):
        await original_load(history)
        await run_owned_thread(native)

    async def replicate():
        if native_entered.is_set():
            await run_owned_thread(compact)
        await original_replicate()

    later._load_active_inputs, earlier._replicate_inputs = load, replicate
    task = asyncio.create_task(scheduler.run(asyncio.Event()))
    try:
        assert await asyncio.to_thread(native_entered.wait, 5)
        assert await asyncio.to_thread(compact_entered.wait, 5)
        held = later._memory_lease
        task.cancel()
        await asyncio.sleep(0)
        task.cancel()
        await asyncio.sleep(0)
        assert not task.done() and not held.closed
        native_release.set()
        await eventually(lambda: held.closed)
        assert not task.done() and scheduler.active is later
        compact_release.set()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert scheduler.active is None
        assert all(reference() is None for _, _, reference in ports.graph_refs)
    finally:
        native_release.set()
        compact_release.set()
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)


async def test_queued_earlier_recovery_prevents_starting_next_later_tick(provisioned):
    ports, roles, schedulers = await replicas(provisioned, coordinator_done=1)
    scheduler = schedulers["coordinator"]
    earlier, later = roles["coordinator"][:2]
    ports.pending.add(1)
    await scheduler.tick()
    held, reference = later._memory_lease, ports.graph_refs[-1][2]
    entered, release = asyncio.Event(), asyncio.Event()
    original = later.maintain
    native_started = []

    async def maintain():
        entered.set()
        await release.wait()
        return await original()

    async def native_tick():
        native_started.append(True)
        return "pending"

    later.maintain, later.tick = maintain, native_tick
    task = asyncio.create_task(scheduler.tick())
    try:
        await asyncio.wait_for(entered.wait(), 5)
        ports.outputs[0] = False
        await scheduler.maintain_completed()
        assert earlier.cohort in scheduler.recovery_requested
        release.set()
        await asyncio.wait_for(task, 5)
        assert native_started == [] and held.closed and reference() is None
        await scheduler.tick()
        assert ports.outputs[0] and ports.loaded[-1] == ("coordinator", 0)
    finally:
        release.set()
        await asyncio.gather(task, return_exceptions=True)
        scheduler._suspend()


async def test_terminal_maintenance_authenticates_original_bytes_and_never_rebuilds(
    tmp_path, monkeypatch
):
    from pathlib import Path

    from umi.competition_cohort_aggregate_model import AggregateProtocolModel
    from umi.competition_cohort_reward_package import RewardPackageObject
    from umi.competition_verification_snapshot import VerificationSnapshotRepairRequired
    from umi.open_competition import digest
    from umi.protocol import canonical_json_bytes

    class Package(AggregateProtocolModel):
        payload: str
        objects: tuple[RewardPackageObject, ...] = ()

    node = blank()
    state, history = await ready(node)
    node.config.exchange_outbox = str(tmp_path / "outbox")
    node.config.settlement_directory = str(tmp_path / "settlement")
    node.config.maximum_package_bytes = 4096
    node.published_tip = state.tip_sha256
    node.terminal_certification_sha256 = node._certification_prefix(history)
    original = tmp_path / "original.json"
    value = Package(payload="exact immutable input")
    original.write_bytes(canonical_json_bytes(value))
    original.chmod(0o600)
    node.package_reference = original, digest(value)
    retained_input_snapshot(node, original, value, monkeypatch)
    await node._remember_reward_package(value)
    output = Path(node.reward_package_reference[0])
    output.parent.mkdir(mode=0o700)
    output.write_bytes(canonical_json_bytes(value))
    output.chmod(0o600)
    published = []

    async def publish(selected):
        published.append(selected)

    node._publish_history = publish
    assert await node.maintain() == "package_published"
    replica = tmp_path / "outbox/inputs/cohort.json"
    assert replica.read_bytes() == original.read_bytes()
    identity = output.stat().st_ino
    replica.unlink()
    assert await node.maintain() == "package_published"
    assert replica.read_bytes() == original.read_bytes() and output.stat().st_ino == identity
    changed = canonical_json_bytes(Package(payload="changed generated package"))
    output.write_bytes(changed)
    with pytest.raises(ValueError, match="verified original"):
        await node.maintain()
    assert output.read_bytes() == changed
    assert original.read_bytes() == canonical_json_bytes(value)
    output.unlink()
    assert await node.maintain() is None
    assert not output.exists()  # only a scheduled native replay can rebuild
    original.unlink()
    with pytest.raises(VerificationSnapshotRepairRequired):
        await node.maintain()
    assert not original.exists() and not output.exists()
    assert node.data is None


async def test_boot_memory_refusal_releases_service_descriptor(tmp_path, monkeypatch):
    import os
    from contextlib import contextmanager

    from umi import competition_cohort_settlement_boot as boot

    config = SimpleNamespace(
        state_directory=str(tmp_path),
        series=object(),
        host_memory_admission=object(),
        maximum_package_bytes=4096,
        legacy_model_storage=(),
        model_delivery_adoptions=(),
        policy=object(),
    )
    monkeypatch.setattr(
        boot, "SettlementServiceConfig", SimpleNamespace(model_validate_json=lambda raw: config)
    )
    monkeypatch.setattr(boot, "canonical_json_bytes", lambda value: b"{}")
    monkeypatch.setattr(boot, "digest", lambda value: "original-series")
    monkeypatch.setattr(boot, "authenticate_legacy_model_sources", lambda *args, **kwargs: None)
    opened = []
    original = boot.lock_private_file

    def lock(path):
        descriptor = original(path)
        opened.append(descriptor)
        return descriptor

    @contextmanager
    def refuse(*args, **kwargs):
        raise OSError("qualified memory unavailable")
        yield

    monkeypatch.setattr(boot, "lock_private_file", lock)
    monkeypatch.setattr(boot, "memory_runtime", refuse)
    with pytest.raises(OSError, match="qualified memory"):
        await boot.run_settlement_service(config, asyncio.Event())
    assert len(opened) == 1
    with pytest.raises(OSError):
        os.fstat(opened[0])
    following = original(tmp_path / "original-series/service.lock")
    os.close(following)
