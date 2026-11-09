"""Admission with real lease witnesses and controlled cgroup observations."""

import os

import pytest

from umi import host_memory_admission as native
from umi import host_memory_peer as peer
from umi import host_memory_startup as startup
from umi.host_memory_residency import observation_slack

from .test_host_execution_memory import joint as joint
from .test_host_memory_graph_peer import shared as shared
from .test_host_memory_peer import parallel_joint as parallel_joint
from .test_host_memory_peer import pool as pool
from .test_host_memory_peer import provisioned as provisioned

GIB = 1024**3


def resident(root, anon=3 * GIB, current=8 * GIB, faults=100):
    (root / "memory.stat").write_text(
        f"anon {anon}\nfile {current - anon}\npgfault {faults}\n"
        "pgmajfault 0\nthp_fault_alloc 0\npglazyfree 0\n"
    )
    (root / "memory.current").write_text(str(current))
    (root / "memory.swap.max").write_text("0")
    (root / "memory.swap.current").write_text("0")
    (root / "cgroup.events").write_text("populated 1\n")


def test_existing_anon_counts_once_but_cache_and_remaining_growth_stay_charged(pool, monkeypatch):
    owner, reader = pool.controller(), pool.controller()
    held = owner.try_acquire_group("transient", 1)
    target = pool.container()
    resident(target)
    assert owner.bind_model_container(held, "a" * 64, target)
    lease = None
    try:
        margin = observation_slack(3 * GIB)
        monkeypatch.setattr(native, "_available_memory", lambda: 18 * GIB + margin - 1)
        assert reader.try_acquire_group("transient", 1) is None
        row = reader.last_model_admission
        assert row["pending_reservation_bytes"] == 16 * GIB
        assert row["resident_anonymous_credit_bytes"] == 3 * GIB - margin
        assert row["resident_observation_slack_bytes"] == margin
        assert row["resident_cache_credit_bytes"] == 0
        assert row["shortfall_bytes"] == 1
        monkeypatch.setattr(native, "_available_memory", lambda: 18 * GIB + margin)
        lease = reader.try_acquire_group("transient", 1)
        assert lease is not None and not lease.service_bounded
        assert reader.last_model_admission["required_available_bytes"] == 18 * GIB + margin
    finally:
        if lease is not None:
            lease.close()
        held.close()


@pytest.mark.parametrize(
    "change", ["free", "grow", "fault", "thp", "swap", "cap", "exit", "witness", "missing"]
)
def test_changes_around_host_sample_keep_full_ceiling(pool, monkeypatch, change):
    owner, reader = pool.controller(), pool.controller()
    held = owner.try_acquire_group("transient", 1)
    target = pool.container()
    resident(target)
    assert owner.bind_model_container(held, "a" * 64, target)

    def available():
        if change == "free":
            resident(target, anon=GIB)
        elif change == "grow":
            resident(target, anon=4 * GIB)
        elif change == "fault":
            # Free/reallocate can return to the same anon count. Fault churn
            # prevents a transient global availability sample earning credit.
            resident(target, faults=101)
        elif change == "thp":
            (target / "memory.stat").write_text(
                (target / "memory.stat")
                .read_text()
                .replace("thp_fault_alloc 0", "thp_fault_alloc 1")
            )
        elif change == "swap":
            (target / "memory.swap.current").write_text("4096")
        elif change == "cap":
            (target / "memory.max").write_text(str(7 * GIB))
        elif change == "exit":
            (target / "cgroup.events").write_text("populated 0\n")
        elif change == "witness":
            peer.clear(held._descriptor)
        else:
            (target / "memory.stat").unlink(missing_ok=True)
        return 18 * GIB

    try:
        monkeypatch.setattr(native, "_available_memory", available)
        # One exact slot avoids a second independent measurement after mutation.
        slot = next(
            s.name
            for s in reader.policy.slots
            if s.lane == "transient" and s.name != held.slot.name
        )
        before = len(os.listdir("/proc/self/fd"))
        assert reader.try_acquire_group("transient", 1, slot_names=[slot]) is None
        assert reader.last_model_admission["resident_anonymous_credit_bytes"] == 0
        assert reader.last_model_admission["required_available_bytes"] == 21 * GIB
        assert len(os.listdir("/proc/self/fd")) == before
    finally:
        held.close()


def test_graph_cap_is_credited_once_and_startup_uses_same_observation(pool, shared, monkeypatch):
    owner, target = shared
    reader = pool.controller()
    resident(target)
    graphs = [owner.try_acquire("transient") for _ in range(3)]
    try:
        margin = observation_slack(3 * GIB)
        monkeypatch.setattr(startup, "_available_memory", lambda: 18 * GIB + margin)
        row = startup.probe_startup_reservation(reader)
        assert row["status"] == "admitted"
        assert row["resident_anonymous_credit_bytes"] == 3 * GIB - margin
        assert row["resident_groups_credited"] == 1
        assert row["pending_reservation_bytes"] == 16 * GIB
        assert row["required_available_bytes"] == 18 * GIB + margin
    finally:
        for graph in graphs:
            graph.close()


def test_unwitnessed_container_cannot_credit_its_resident_pages(pool, monkeypatch):
    reader = pool.controller()
    resident(pool.container())
    monkeypatch.setattr(native, "_available_memory", lambda: 64 * GIB)
    assert reader.try_acquire_group("transient", 1) is None
    assert reader.last_model_admission["resident_anonymous_credit_bytes"] == 0
    assert reader.last_model_admission["exclusive_orphan_hold"] is True


def test_lazyfree_anonymous_memory_remains_fully_charged(pool, monkeypatch):
    owner, reader = pool.controller(), pool.controller()
    held = owner.try_acquire_group("transient", 1)
    target = pool.container()
    resident(target)
    (target / "memory.stat").write_text(
        (target / "memory.stat")
        .read_text()
        .replace("pglazyfree 0", f"pglazyfree {3 * GIB // os.sysconf('SC_PAGE_SIZE')}")
    )
    assert owner.bind_model_container(held, "a" * 64, target)
    try:
        monkeypatch.setattr(native, "_available_memory", lambda: 18 * GIB)
        assert reader.try_acquire_group("transient", 1) is None
        assert reader.last_model_admission["resident_anonymous_credit_bytes"] == 0
        assert reader.last_model_admission["required_available_bytes"] == 21 * GIB
    finally:
        held.close()


def test_three_full_model_grants_use_observed_residency_and_keep_growth_margin(pool, monkeypatch):
    owners = [pool.controller() for _ in range(3)]
    leases = []
    monkeypatch.setattr(native, "_available_memory", lambda: 24 * GIB)
    try:
        for index, owner in enumerate(owners):
            lease = owner.try_acquire_group("transient", 1)
            assert lease is not None and not lease.service_bounded
            assert lease.slot.reservation_bytes == 8 * GIB
            leases.append(lease)
            cid = "abc"[index] * 64
            target = pool.container(cid)
            resident(target)
            assert owner.bind_model_container(lease, cid, target)
        row = owners[-1].last_model_admission
        assert row["pending_reservation_bytes"] == 24 * GIB
        assert row["resident_anonymous_credit_bytes"] == 2 * (3 * GIB - observation_slack(3 * GIB))
        assert row["required_available_bytes"] == 23 * GIB + 2 * observation_slack(3 * GIB)
        assert len({lease.slot.name for lease in leases}) == 3
    finally:
        for lease in leases:
            lease.close()
