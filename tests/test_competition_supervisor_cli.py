from __future__ import annotations

import asyncio
import hashlib
import json
import os
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

from umi import competition_host_artifacts as host_artifacts
from umi import competition_supervisor_cli as cli
from umi.competition_supervisor_runtime import SuccessorRuntimeResult
from umi.protocol import canonical_json_bytes

from .test_competition_host_artifacts import sign as sign_host_artifact
from .test_competition_host_artifacts import staged as _staged_host_fixture


@pytest.fixture
def host(monkeypatch):
    events = []
    stop = asyncio.Event()
    config = SimpleNamespace(poll_seconds=30)
    # The CLI does not substitute these fixture controls in production. Real
    # activation/tree validation has separate owner/mount/signature coverage.
    inputs = SimpleNamespace(config=config)

    class Anchor:
        def __init__(self):
            self.config = config

        def recheck(self):
            events.append("recheck-anchor")

    anchor = Anchor()
    lease = SimpleNamespace()
    monkeypatch.setattr(cli.sys, "platform", "linux")
    monkeypatch.setattr(cli.os, "geteuid", lambda: 1001)
    monkeypatch.setattr(cli, "canonical_json_bytes", lambda value: b"exact-config")

    def read(*args):
        events.append("read-config")
        return b"exact-config"

    def load():
        events.append("load-seal")
        return inputs

    def load_anchor(path):
        assert path == Path("/etc/umi/supervisor.json")
        events.append("load-anchor")
        return anchor

    @contextmanager
    def hold(value):
        assert value is anchor
        events.append("lock")
        yield lease
        events.append("leave-lock-scope")

    async def stop_startup(value, held):
        assert value is config and held is lease
        events.append("stop-startup-worker")

    def repair(*, anchor: object, limits):
        assert anchor is host_anchor
        assert limits.maximum_stages == 1024
        events.append("repair")

    def verify(value):
        assert value is inputs
        events.append("verify-host")

    def verify_anchor(value):
        assert value is anchor
        events.append("verify-anchor-host")

    class Observer:
        async def aclose(self):
            events.append("close-observer")

    class Runtime:
        async def __aenter__(self):
            events.append("lock-and-recover")
            return self

        async def __aexit__(self, *args):
            events.append("stop-and-unlock")

        async def reconcile(self):
            events.append("reconcile")
            stop.set()
            return SuccessorRuntimeResult("holding", "signed_successor_hold", 8, "ab" * 32, 170)

    runtime = Runtime()

    def build(value, path, *, startup_lease):
        assert value is inputs and path == Path("/etc/umi/supervisor.json")
        assert startup_lease is lease
        events.append("build")
        return runtime, Observer()

    host_anchor = anchor
    monkeypatch.setattr(cli, "_root_control", read)
    monkeypatch.setattr(cli, "parse_canonical_validator_supervisor_config", lambda _raw: config)
    monkeypatch.setattr(cli, "load_materialized_successor_anchor_for_repair", load_anchor)
    monkeypatch.setattr(cli, "hold_successor_startup_lease", hold)
    monkeypatch.setattr(cli, "_stop_startup_worker", stop_startup)
    monkeypatch.setattr(cli, "repair_successor_source_permissions", repair)
    monkeypatch.setattr(cli, "load_successor_worker_inputs", load)
    monkeypatch.setattr(cli, "_verify_running_host", verify)
    monkeypatch.setattr(cli, "_verify_running_host_anchor", verify_anchor)
    monkeypatch.setattr(cli, "_build_runtime", build)
    monkeypatch.setattr(cli, "_emit", lambda result: events.append("bounded-status"))
    return SimpleNamespace(events=events, stop=stop, runtime=runtime, inputs=inputs)


async def test_cli_orders_seal_host_lock_recovery_and_shutdown(host):
    await cli.run_supervisor(Path("/etc/umi/supervisor.json"), stop_event=host.stop)
    assert host.events == [
        "read-config",
        "load-anchor",
        "verify-anchor-host",
        "lock",
        "stop-startup-worker",
        "repair",
        "recheck-anchor",
        "load-seal",
        "verify-host",
        "build",
        "lock-and-recover",
        "reconcile",
        "bounded-status",
        "stop-and-unlock",
        "close-observer",
        "leave-lock-scope",
    ]


@pytest.mark.parametrize("distinct_async_timeout", [False, True])
async def test_cli_continues_after_poll_timeout(host, monkeypatch, distinct_async_timeout):
    class LegacyAsyncTimeout(Exception):
        pass

    # Before Python 3.11, asyncio.TimeoutError was separate from the built-in.
    timeout_type = LegacyAsyncTimeout if distinct_async_timeout else asyncio.TimeoutError
    monkeypatch.setattr(asyncio, "TimeoutError", timeout_type)
    reconcile = host.runtime.reconcile
    rounds = 0

    async def twice():
        nonlocal rounds
        result = await reconcile()
        rounds += 1
        if rounds == 1:
            host.stop.clear()
        return result

    async def wait(awaitable, *, timeout):
        awaitable.close()
        assert timeout == 30.0
        if not host.stop.is_set():
            raise timeout_type()
        return True

    monkeypatch.setattr(host.runtime, "reconcile", twice)
    monkeypatch.setattr(asyncio, "wait_for", wait)
    await cli.run_supervisor(Path("/etc/umi/supervisor.json"), stop_event=host.stop)
    assert rounds == 2
    assert host.events.count("bounded-status") == 2
    assert host.events[-3:] == ["stop-and-unlock", "close-observer", "leave-lock-scope"]


@pytest.mark.parametrize("boundary", ["config", "seal", "host"])
async def test_cli_invalid_installation_never_builds_or_starts(host, monkeypatch, boundary):
    def denied(*args):
        raise ValueError("fixture invalid")

    if boundary == "config":
        monkeypatch.setattr(cli, "_root_control", lambda *args: b"other")
    elif boundary == "seal":
        monkeypatch.setattr(cli, "load_successor_worker_inputs", denied)
    else:
        monkeypatch.setattr(cli, "_verify_running_host", denied)
    with pytest.raises(ValueError):
        await cli.run_supervisor(Path("/etc/umi/supervisor.json"), stop_event=host.stop)
    assert "build" not in host.events


async def test_cli_failure_stops_runtime_before_closing_observer(host):
    async def fail():
        raise ValueError("fixture runtime error")

    host.runtime.reconcile = fail
    with pytest.raises(ValueError, match="runtime error"):
        await cli.run_supervisor(Path("/etc/umi/supervisor.json"), stop_event=host.stop)
    assert host.events[-2:] == ["stop-and-unlock", "close-observer"]


async def test_cli_cancellation_does_not_skip_runtime_shutdown(host):
    async def cancel():
        raise asyncio.CancelledError()

    host.runtime.reconcile = cancel
    with pytest.raises(asyncio.CancelledError):
        await cli.run_supervisor(Path("/etc/umi/supervisor.json"), stop_event=host.stop)
    assert host.events[-2:] == ["stop-and-unlock", "close-observer"]


@pytest.mark.parametrize("machine,euid", [("darwin", 501), ("linux", 0)])
async def test_cli_refuses_uninstalled_platform_or_root(host, monkeypatch, machine, euid):
    monkeypatch.setattr(cli.sys, "platform", machine)
    monkeypatch.setattr(cli.os, "geteuid", lambda: euid)
    with pytest.raises(ValueError, match="non-root Linux"):
        await cli.run_supervisor(Path("/etc/umi/supervisor.json"), stop_event=host.stop)
    assert not host.events


async def test_adapter_factory_is_deferred_until_first_locked_operation():
    events = []

    class Adapter:
        async def stop_worker(self):
            events.append("stop")

        async def stage(self, selection):
            events.append(selection)

    def build():
        events.append("construct-journals")
        return Adapter()

    deferred = cli._DeferredAdapter(build)
    assert events == []
    await deferred.stop_worker()
    await deferred.stage("stage")
    assert events == ["construct-journals", "stop", "stage"]


@pytest.mark.parametrize("failure", ["host-check", "stop", "uncertain"])
async def test_startup_cleanup_failure_preserves_original_lock(monkeypatch, failure):
    events = []

    class Lease:
        def preserve_on_failure(self):
            events.append("preserve")

    class Container:
        async def check_host(self):
            events.append("check-host")
            if failure == "host-check":
                raise ValueError("host check failed")

        async def stop(self):
            events.append("stop")
            if failure == "stop":
                raise ValueError("stop failed")
            return SimpleNamespace(phase="running" if failure == "uncertain" else "absent")

    monkeypatch.setattr(cli, "_new_container", lambda _config: Container())
    with pytest.raises(ValueError):
        await cli._stop_startup_worker(SimpleNamespace(), Lease())
    assert events[-1] == "preserve"


async def test_startup_cleanup_accepts_only_confirmed_stopped_phase(monkeypatch):
    events = []

    class Container:
        async def check_host(self):
            events.append("check-host")

        async def stop(self):
            events.append("stop")
            return SimpleNamespace(phase="completed")

    monkeypatch.setattr(cli, "_new_container", lambda _config: Container())
    await cli._stop_startup_worker(
        SimpleNamespace(),
        SimpleNamespace(preserve_on_failure=lambda: pytest.fail("preserved successful lease")),
    )
    assert events == ["check-host", "stop"]


@pytest.fixture(params=["linux/amd64", "linux/arm64"])
def running_host(tmp_path, monkeypatch, request):
    staged = _staged_host_fixture.__wrapped__(tmp_path, monkeypatch, request)
    value = next(staged)
    try:
        source = value.path / "src/umi/competition_supervisor_cli.py"
        for parent in (value.path, source.parent):
            parent.chmod(0o755)
        body = b"inert signed supervisor CLI source"
        source.write_bytes(body)
        source.chmod(0o444)
        source.parent.chmod(0o555)
        value.path.chmod(0o555)
        source_record = host_artifacts.HostArtifactFile(
            path="src/umi/competition_supervisor_cli.py",
            sha256=hashlib.sha256(body).hexdigest(),
            size_bytes=len(body),
            mode=0o444,
        )
        files = sorted([*value.manifest.files, source_record], key=lambda item: item.path)
        manifest = value.manifest.model_copy(
            update={
                "files": files,
                "total_size_bytes": sum(item.size_bytes for item in files),
            }
        )
        signed = sign_host_artifact(manifest)
        payload = canonical_json_bytes(signed)
        receipt = SimpleNamespace(
            host_umi_git_revision=manifest.umi_git_revision,
            signed_host_artifact_sha256=hashlib.sha256(payload).hexdigest(),
        )
        installation = SimpleNamespace(
            config=value.config,
            host_manifest_sha256=signed.manifest_sha256,
            _receipt=receipt,
        )
        expected_machine = "x86_64" if manifest.target_platform == "linux/amd64" else "aarch64"
        monkeypatch.setattr(cli, "_HOST_PARENT", value.path.parent)
        monkeypatch.setattr(cli, "ACTIVATION_MOUNT_ROOT", value.path.parent / "activation")
        monkeypatch.setattr(cli, "_ancestor_paths", host_artifacts._ancestor_paths)
        monkeypatch.setattr(cli, "__file__", str(source))
        monkeypatch.setattr(cli.sys, "platform", "linux")
        monkeypatch.setattr(cli.sys, "executable", str(value.path / ".venv/bin/python"))
        monkeypatch.setattr(cli.sys, "prefix", str(value.path / ".venv"))
        monkeypatch.setattr(cli.os, "geteuid", lambda: 1001)
        monkeypatch.setattr(cli.platform, "machine", lambda: expected_machine)
        monkeypatch.setattr(
            cli,
            "_root_control",
            lambda path, maximum: (
                payload
                if path.name == cli.SIGNED_HOST_ARTIFACT_FILENAME and len(payload) <= maximum
                else pytest.fail("running-host verification read an unexpected control")
            ),
        )
        monkeypatch.setattr(
            cli,
            "validate_authenticated_successor_installation",
            lambda candidate: (
                None
                if candidate is installation
                else pytest.fail("running-host verification accepted another capability")
            ),
        )
        monkeypatch.setattr(
            cli,
            "_running_executable_identity",
            lambda path: cli._stable_file_identity(path),
        )
        yield SimpleNamespace(
            installation=installation,
            root=value.path,
            source=source,
            signed=signed,
            payload=payload,
        )
    finally:
        with pytest.raises(StopIteration):
            next(staged)


def test_running_host_rechecks_exact_signed_tree_and_loaded_files(running_host):
    cli._verify_running_host(running_host.installation)


@pytest.mark.parametrize("tamper", ["source", "interpreter-mode", "unsigned-entry"])
def test_running_host_rejects_tree_tamper(running_host, tamper):
    case = running_host
    if tamper == "source":
        case.source.chmod(0o644)
        case.source.write_bytes(b"changed signed supervisor CLI")
        case.source.chmod(0o444)
    elif tamper == "interpreter-mode":
        (case.root / ".venv/bin/python").chmod(0o755)
    else:
        case.root.chmod(0o755)
        extra = case.root / "unsigned-host-hook.py"
        extra.write_bytes(b"not signed")
        extra.chmod(0o444)
        case.root.chmod(0o555)
    with pytest.raises(ValueError):
        cli._verify_running_host(case.installation)


def test_running_host_rejects_different_kernel_interpreter(running_host, monkeypatch):
    monkeypatch.setattr(
        cli,
        "_running_executable_identity",
        lambda _path: (_ for _ in ()).throw(ValueError("different kernel executable")),
    )
    with pytest.raises(ValueError, match="different kernel executable"):
        cli._verify_running_host(running_host.installation)


def test_running_executable_requires_same_inode(tmp_path, monkeypatch):
    expected = tmp_path / "python"
    other = tmp_path / "other-python"
    expected.write_bytes(b"python")
    other.write_bytes(b"other")
    monkeypatch.setattr(cli, "_PROC_SELF_EXE", expected)
    assert cli._running_executable_identity(expected) == cli._stable_file_identity(expected)
    monkeypatch.setattr(cli, "_PROC_SELF_EXE", other)
    with pytest.raises(ValueError, match="running interpreter"):
        cli._running_executable_identity(expected)


async def test_runtime_factory_wires_only_fixed_ports_and_defers_mutable_state(monkeypatch):
    from umi import (
        competition_container,
        competition_delivery,
        competition_materializer,
        competition_supervisor_adapters,
        competition_supervisor_observer,
    )

    events = []
    captured = {}
    config = SimpleNamespace(name="sealed-config")
    installation = SimpleNamespace(
        config=config,
        operator_consent=SimpleNamespace(name="sealed-consent"),
        worker_execution_limits=SimpleNamespace(name="sealed-ceilings"),
    )
    config_path = Path("/etc/umi/supervisor.json")
    delivery_client = object()
    monkeypatch.setattr(cli, "_delivery_client", lambda value: delivery_client)

    class Observer:
        def __init__(self, **kwargs):
            events.append("observer")
            captured["observer"] = kwargs

    class Fetcher:
        def __init__(self, value, *, client):
            assert value is config
            assert client is delivery_client
            captured["client"] = client
            events.append("fetcher")

    class Delivery:
        def __init__(self, **kwargs):
            events.append("delivery")
            captured["delivery"] = kwargs
            captured["delivery_instance"] = self

    class Materializer:
        def __init__(self, **kwargs):
            events.append("materializer")
            captured["materializer"] = kwargs
            captured["materializer_instance"] = self

    class Container:
        def __init__(self, value, **kwargs):
            assert value is config
            events.append("container")
            captured["container"] = kwargs
            captured["container_instance"] = self

    class Adapter:
        def __init__(self, **kwargs):
            events.append("adapter")
            captured["adapter"] = kwargs

        async def stop_worker(self):
            events.append("stop")

    class Runtime:
        def __init__(self, **kwargs):
            events.append("runtime")
            captured["runtime"] = kwargs

    monkeypatch.setattr(competition_supervisor_observer, "OwnedSuccessorHostObserver", Observer)
    monkeypatch.setattr(competition_delivery, "HTTPSSuccessorDirectiveFetcher", Fetcher)
    monkeypatch.setattr(competition_delivery, "HTTPSSuccessorArtifactDelivery", Delivery)
    monkeypatch.setattr(
        competition_materializer, "AuthenticatedSuccessorArtifactMaterializer", Materializer
    )
    monkeypatch.setattr(competition_container, "PodmanSuccessorContainer", Container)
    monkeypatch.setattr(
        competition_supervisor_adapters, "ProductionSuccessorRuntimeAdapter", Adapter
    )
    monkeypatch.setattr(cli, "SuccessorSupervisorRuntime", Runtime)

    startup_lease = object()
    _runtime, observer = cli._build_runtime(installation, config_path, startup_lease=startup_lease)
    assert events == ["observer", "fetcher", "runtime"]
    assert observer is captured["runtime"]["observation_reader"]
    await captured["runtime"]["worker_adapter"].stop_worker()
    assert captured["delivery"]["client"] is captured["client"]
    assert events == [
        "observer",
        "fetcher",
        "runtime",
        "delivery",
        "materializer",
        "container",
        "adapter",
        "stop",
    ]
    assert captured["observer"] == {"installation": installation}
    assert captured["delivery"]["config"] is config
    assert captured["delivery"]["operator_consent"] is installation.operator_consent
    assert captured["delivery"]["worker_limits"] is installation.worker_execution_limits
    assert captured["materializer"]["installation"] is installation
    assert captured["materializer"]["delivery"] is captured["delivery_instance"]
    assert captured["adapter"]["materializer"] is captured["materializer_instance"]
    assert captured["materializer"]["observer"] is observer
    assert captured["materializer"]["config_path"] == config_path
    assert captured["adapter"]["installation"] is installation
    assert captured["adapter"]["observer"] is observer
    assert captured["adapter"]["container"] is captured["container_instance"]
    assert captured["runtime"]["directive_fetcher"].__class__ is Fetcher
    assert captured["runtime"]["startup_lease"] is startup_lease
    assert captured["runtime"]["limits"].model_dump() == {
        "maximum_history_records": 65536,
        "maximum_history_bytes": 64 * 1024**2,
    }
    assert captured["delivery"]["limits"].maximum_cached_objects == 2048
    assert captured["materializer"]["limits"].maximum_stages == 1024
    assert captured["container"]["limits"].maximum_state_bytes == 32 * 1024**3
    assert captured["adapter"]["limits"].maximum_retained_runs == 65536


def test_help_does_not_load_mounts_network_or_wallet(monkeypatch, capsys):
    def denied(*args):
        pytest.fail("help touched installation")

    monkeypatch.setattr(cli, "load_successor_worker_inputs", denied)
    monkeypatch.setattr(cli, "_build_runtime", denied)
    with pytest.raises(SystemExit) as stopped:
        cli.run_cli(["--help"])
    assert stopped.value.code == 0
    assert "--config" in capsys.readouterr().out


@pytest.mark.parametrize(
    "extra",
    [
        ["--wallet", "secret"],
        ["--adapter", "evil.module"],
        ["--coldkey", "secret"],
        ["--activation", "/tmp/fake"],
        ["--conf", "/tmp/fake"],
    ],
)
def test_cli_has_no_wallet_plugin_or_activation_override(extra):
    with pytest.raises(SystemExit) as stopped:
        cli.run_cli(["--config", "/etc/umi/supervisor.json", *extra])
    assert stopped.value.code == 2


def test_cli_exception_output_has_no_sensitive_details(monkeypatch, capsys):
    async def fail(*args):
        raise ValueError("secret wallet path /private/sensitive")

    monkeypatch.setattr(cli, "run_supervisor", fail)
    assert cli.run_cli(["--config", "/etc/umi/supervisor.json"]) == 1
    result = capsys.readouterr()
    assert result.out == ""
    assert json.loads(result.err) == {
        "schema": "umi-successor-host-status/1",
        "status": "holding",
        "reason": "successor_host_failed",
    }
    assert "secret" not in result.err


def test_bounded_status_output(capsys):
    cli._emit(SuccessorRuntimeResult("holding", "signed_successor_hold", 8, "ab" * 32, 170))
    assert json.loads(capsys.readouterr().out) == {
        "schema": "umi-successor-host-status/1",
        "status": "holding",
        "reason": "signed_successor_hold",
        "accepted_sequence": 8,
        "accepted_directive_sha256": "ab" * 32,
        "finalized_block": 170,
    }


@pytest.mark.parametrize(
    "unsafe", ["relative", "symlink", "hardlink", "fifo", "owner", "mode", "oversized"]
)
def test_root_control_rejects_unsafe_files(tmp_path, monkeypatch, unsafe):
    path = tmp_path / "config"
    path.write_bytes(b"configuration")
    path.chmod(0o400)
    real = cli.os.fstat

    def observed(fd):
        info = real(fd)
        values = {name: getattr(info, name) for name in dir(info) if name.startswith("st_")}
        values["st_uid"] = 1 if unsafe == "owner" else 0
        return SimpleNamespace(**values)

    monkeypatch.setattr(cli.os, "fstat", observed)
    if unsafe == "relative":
        path = Path("relative")
    elif unsafe == "symlink":
        link = tmp_path / "link"
        link.symlink_to(path)
        path = link
    elif unsafe == "hardlink":
        os.link(path, tmp_path / "hardlink")
    elif unsafe == "fifo":
        path = tmp_path / "pipe"
        os.mkfifo(path, 0o600)
    elif unsafe == "mode":
        path.chmod(0o666)
    with pytest.raises((OSError, ValueError)):
        cli._root_control(path, 3 if unsafe == "oversized" else 100)


def test_root_control_reads_bounded_exact_bytes(tmp_path, monkeypatch):
    path = tmp_path / "config"
    path.write_bytes(canonical_json_bytes({"public": "value"}))
    path.chmod(0o400)
    real = cli.os.fstat

    def observed(fd):
        info = real(fd)
        values = {name: getattr(info, name) for name in dir(info) if name.startswith("st_")}
        values["st_uid"] = 0
        return SimpleNamespace(**values)

    monkeypatch.setattr(cli.os, "fstat", observed)
    assert cli._root_control(path, 100) == path.read_bytes()
