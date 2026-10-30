"""Synthetic host metadata only: no probes, production cgroups or payload reads."""

import asyncio
from pathlib import Path
from types import SimpleNamespace

import pytest

from umi import host_cpu_conditions as host
from umi.competition_cpu_timing import CpuTimingInfrastructureError


def psi(path, total=0):
    path.write_text(
        f"some avg10=0.00 avg60=0.00 avg300=0.00 total={total}\n"
        f"full avg10=0.00 avg60=0.00 avg300=0.00 total={total}\n"
    )


@pytest.fixture
def pressure_tree(tmp_path):
    root = tmp_path / "cgroup"
    own = root / "execution/partition/model"
    own.mkdir(parents=True)
    siblings = (
        root / "system",
        root / "execution/reviewer",
        root / "execution/partition/other-slot",
    )
    for path in (*siblings, own):
        path.mkdir(parents=True, exist_ok=True)
        psi(path / "memory.pressure")
        psi(path / "io.pressure")
    (own / "memory.events").write_text("high 0\nmax 0\noom 0\noom_kill 0\n")
    (own / "memory.stat").write_text("pgmajfault 0\n")
    (own / "io.stat").write_text("8:1 rbytes=0 wbytes=0 rios=0 wios=0\n")
    proc = tmp_path / "proc"
    (proc / "pressure").mkdir(parents=True)
    psi(proc / "pressure/memory")
    psi(proc / "pressure/io")
    (proc / "vmstat").write_text("pswpin 0\npswpout 0\n")
    return SimpleNamespace(**locals())


def test_external_scope_partition_excludes_model_descendants(pressure_tree):
    fixture = pressure_tree
    reader = host.PressureReader(fixture.root, fixture.own, proc_root=fixture.proc)
    assert {Path(path) for path, _, _ in reader.scopes} == set(fixture.siblings)
    before = reader.sample()
    (fixture.own / "libpod-private").mkdir()
    psi(fixture.own / "memory.pressure", 9000)
    psi(fixture.proc / "pressure/memory", 12000)
    psi(fixture.siblings[0] / "memory.pressure", 7000)
    after = reader.sample()
    assert before.external_memory_full_us == 0
    assert after.external_memory_full_us == 7000  # Not host minus own = 3000.
    assert after.scope_identity_sha256 == before.scope_identity_sha256


def test_external_scope_creation_requires_fresh_measurement(pressure_tree):
    fixture = pressure_tree
    reader = host.PressureReader(fixture.root, fixture.own, proc_root=fixture.proc)
    (fixture.root / "new-service").mkdir()
    with pytest.raises(CpuTimingInfrastructureError, match="pressure_scope_changed"):
        reader.sample()


async def test_observer_detects_stall_even_before_first_tick(monkeypatch):
    clock = SimpleNamespace(now=1_000_000)
    monkeypatch.setattr(host, "time", SimpleNamespace(monotonic_ns=lambda: clock.now * 1000))
    monitor = host.ObserverLagMonitor()
    clock.now += 200_001
    observed = await monitor.finish()
    assert observed.ticks == 0
    assert observed.maximum_lateness_us == 150_001
    assert monitor.task.cancelled()


async def test_probe_timeout_kills_and_reaps_only_owned_helper(monkeypatch):
    trace = []
    process = SimpleNamespace(returncode=None)

    async def read(limit):
        await asyncio.Future()

    async def wait():
        trace.append("reap")
        return process.returncode

    def kill():
        trace.append("kill")
        process.returncode = -9

    process.stdout = SimpleNamespace(read=read)
    process.wait, process.kill = wait, kill

    async def spawn(*args, **kwargs):
        assert args[1:5] == ("-I", "-B", "-m", "umi.host_cpu_probe")
        assert "--cgroup" in args
        trace.append("spawn")
        return process

    async def expire(coroutine, timeout):
        assert timeout == 5
        coroutine.close()
        raise asyncio.TimeoutError

    monkeypatch.setattr(host, "check_probe_leaf", lambda *args: None)
    monkeypatch.setattr(host.asyncio, "create_subprocess_exec", spawn)
    monkeypatch.setattr(host.asyncio, "wait_for", expire)
    session = SimpleNamespace(
        parent=SimpleNamespace(path="/sys/fs/cgroup/umiexecution.slice/p"),
        slot=SimpleNamespace(cpu_ids=(0, 1)),
        cpu_set_argument="0,1",
        context=SimpleNamespace(profile_sha256="a" * 64),
    )
    with pytest.raises(CpuTimingInfrastructureError, match="probe_unavailable"):
        await host.run_probe(session, "b" * 64, "before")
    assert trace == ["spawn", "kill", "reap"]
