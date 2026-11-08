"""Idle maintenance shares native locks and refuses active or changed resources."""

import errno
import fcntl
import os
from types import SimpleNamespace

import pytest

from umi import host_cpu_cache_reclaim as module


@pytest.fixture
def pool(tmp_path, monkeypatch):
    locks = tmp_path / "locks"
    locks.mkdir()
    partition = tmp_path / "models"
    slots, selected, parents = [], [], []
    for name in ("a", "b"):
        (locks / name).touch()
        slot = SimpleNamespace(name=name, lane="transient", reservation_bytes=8 * 1024**3)
        slots.append(slot)
        parent = partition / name / ("uid" + str(os.getuid()))
        parent.mkdir(parents=True)
        parents.append(parent)
        for key, value in {
            "memory.max": str(slot.reservation_bytes),
            "memory.swap.max": "0",
            "memory.swap.current": "0",
            "cgroup.events": "populated 0\nfrozen 0\n",
            "memory.stat": "anon 0\nfile 1073741824\nshmem 0\nfile_dirty 0\nfile_writeback 0\n",
            "memory.current": "1073741824",
            "memory.reclaim": "",
        }.items():
            (parent / key).write_text(value)
        selected.append(
            SimpleNamespace(
                lock_name=name, parents=[SimpleNamespace(path=str(parent), uid=os.getuid())]
            )
        )
    controller = SimpleNamespace(
        policy_sha256="a" * 64,
        policy=SimpleNamespace(slots=slots),
        _open_root=lambda: os.open(locks, os.O_RDONLY | os.O_DIRECTORY),
        _open_slot=lambda root, slot: os.open(slot.name, os.O_RDONLY, dir_fd=root),
        _model_container_reservations=lambda: 0,
    )
    profile = SimpleNamespace(partition=SimpleNamespace(path=str(partition)), slots=selected)
    monkeypatch.setattr(module, "_require_cgroup2", lambda fd: None)
    return controller, profile, locks, parents


def released(locks):
    for path in locks.iterdir():
        with path.open() as stream:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)


def test_reclaims_one_empty_group_with_all_native_locks_held(pool, monkeypatch):
    controller, profile, locks, parents = pool
    original = module.os.write
    writes = []

    def write(fd, raw):
        for path in locks.iterdir():
            with path.open() as stream, pytest.raises(BlockingIOError):
                fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        writes.append(raw)
        return original(fd, raw)

    monkeypatch.setattr(module.os, "write", write)
    result = module.reclaim_once(controller, profile)
    assert result["reason"] == "bounded_reclaim"
    assert writes == [str(module.MAXIMUM_RECLAIM_BYTES).encode() + b"\n"]
    assert sum(bool((p / "memory.reclaim").read_bytes()) for p in parents) == 1
    released(locks)


def test_busy_later_slot_releases_earlier_lock_without_reclaim(pool):
    controller, profile, locks, parents = pool
    with (locks / "b").open() as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        assert module.reclaim_once(controller, profile)["reason"] == "pool_busy"
        with (locks / "a").open() as earlier:
            fcntl.flock(earlier, fcntl.LOCK_EX | fcntl.LOCK_NB)
    assert all(not (p / "memory.reclaim").read_bytes() for p in parents)
    released(locks)


@pytest.mark.parametrize("cause", ["orphan", "populated"])
def test_surviving_process_blocks_all_mutation(pool, cause):
    controller, profile, locks, parents = pool
    if cause == "orphan":
        controller._model_container_reservations = lambda: 8 * 1024**3
    else:
        (parents[-1] / "cgroup.events").write_text("populated 1\nfrozen 0\n")
    assert module.reclaim_once(controller, profile)["status"] == "skipped"
    assert all(not (p / "memory.reclaim").read_bytes() for p in parents)
    released(locks)


@pytest.mark.parametrize("counter", ["anon", "shmem", "file_dirty", "file_writeback"])
def test_dirty_or_anonymous_groups_are_not_reclaimed(pool, counter):
    controller, profile, locks, parents = pool
    for parent in parents:
        path = parent / "memory.stat"
        path.write_text(path.read_text().replace(counter + " 0", counter + " 4096"))
    assert module.reclaim_once(controller, profile)["reason"] == "no_eligible_cache"
    assert all(not (p / "memory.reclaim").read_bytes() for p in parents)
    released(locks)


@pytest.mark.parametrize("name,value", [("memory.max", "max"), ("memory.swap.max", "4096")])
def test_changed_resource_contract_refuses_before_reclaim(pool, name, value):
    controller, profile, locks, parents = pool
    (parents[-1] / name).write_text(value)
    with pytest.raises(module.AdmissionBindingError):
        module.reclaim_once(controller, profile)
    assert all(not (p / "memory.reclaim").read_bytes() for p in parents)
    released(locks)


def test_incomplete_profile_cannot_ignore_an_active_lane(pool):
    controller, profile, locks, parents = pool
    profile.slots.pop()
    with pytest.raises(module.AdmissionBindingError, match="complete timed pool"):
        module.reclaim_once(controller, profile)
    assert all(not (p / "memory.reclaim").read_bytes() for p in parents)
    released(locks)


def test_alias_refused(pool):
    controller, profile, locks, parents = pool
    path = parents[-1]
    moved = path.parent.parent.parent / "old"
    path.rename(moved)
    path.symlink_to(moved, target_is_directory=True)
    with pytest.raises(module.AdmissionBindingError, match="aliased"):
        module.reclaim_once(controller, profile)
    released(locks)


def test_pool_expansion_refuses_stale_selection(pool):
    controller, profile, locks, parents = pool
    (parents[0].parent.parent / "new-slot").mkdir()
    with pytest.raises(module.AdmissionBindingError, match="pool layout changed"):
        module.reclaim_once(controller, profile)
    assert all(not (p / "memory.reclaim").read_bytes() for p in parents)
    released(locks)


@pytest.mark.parametrize("number", [errno.EAGAIN, errno.EIO])
def test_kernel_partial_or_failed_reclaim_releases_all_locks(pool, monkeypatch, number):
    controller, profile, locks, _ = pool

    def fail(fd, raw):
        raise OSError(number, "injected kernel result")

    monkeypatch.setattr(module.os, "write", fail)
    if number == errno.EAGAIN:
        result = module.reclaim_once(controller, profile)
        assert result["partial_reclaim"] and result["reclaimed_bytes"] == 0
    else:
        with pytest.raises(OSError):
            module.reclaim_once(controller, profile)
    released(locks)
