"""Process-exit recovery with synthetic systemd ports and real retained files."""

from __future__ import annotations

import json
import multiprocessing
import os
import shutil
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest

from .test_miner_upgrade_historical import (
    LOCAL_LIMITS,
    CohortMinerStartupConfig,
    RoundJournal,
    _main_harness,
    upgrade,
)


def _root_recovery_permissions(monkeypatch, state):
    """Only emulate root ownership of the updater's private recovery namespace."""
    root_paths = {state.parent, state, state / "activation-recovery.json"}
    lstat, fstat = Path.lstat, os.fstat

    def metadata(value):
        fields = list(value)
        fields[4:6] = [0, 0]
        return os.stat_result(fields)

    def root_lstat(path, *args, **kwargs):
        observed = lstat(path, *args, **kwargs)
        return metadata(observed) if path in root_paths else observed

    def root_fstat(fd):
        observed = fstat(fd)
        path = Path(os.readlink(f"/proc/self/fd/{fd}"))
        return metadata(observed) if path in root_paths else observed

    monkeypatch.setattr(Path, "lstat", root_lstat)
    monkeypatch.setattr(os, "fstat", root_fstat)


def _crash_harness(tmp_path, monkeypatch, boundary):
    native_activate = upgrade.activate_services
    native_controls = upgrade.unit_controls
    p = _main_harness(tmp_path, monkeypatch)
    monkeypatch.setattr(upgrade, "activate_services", native_activate)
    monkeypatch.setattr(upgrade, "unit_controls", native_controls)
    monkeypatch.setattr(upgrade, "SYSTEMD_ROOT", tmp_path / "etc")
    monkeypatch.setattr(upgrade, "SYSTEMD_RUNTIME_ROOT", tmp_path / "run")
    monkeypatch.setattr(upgrade, "LAUNCHER", tmp_path / "launcher")
    _root_recovery_permissions(monkeypatch, p.state)
    system = tmp_path / "systemd.json"
    trace = tmp_path / "commands.jsonl"
    killed = tmp_path / "interrupted"
    units = tmp_path / "units"
    units.mkdir()
    for name in ("umi-miner.service", "umi-model.service"):
        (units / name).write_bytes(
            b"[Service]\nWorkingDirectory=/\n# retained wrapper changes cwd\n"
        )
    sidecar = None
    if boundary.startswith("sidecar_"):
        sidecar_cwd = tmp_path / "sidecar-cwd"
        sidecar_cwd.mkdir()
        old_config = sidecar_cwd / "original.json"
        old_config.write_bytes(b'{"retained_model_configuration":true}')
        selected_config = sidecar_cwd / "selected.json"
        selected_config.write_bytes(b'{"selected_model_configuration":true}')
        old_arguments = [
            "/old/model/python",
            "-m",
            "umi.model_service",
            "--config",
            "original.json",
        ]
        sidecar = upgrade.Service(
            "umi-model.service", 124, p.current[0].user, old_arguments, sidecar_cwd
        )

        def prepare(command, *_args):
            updated = list(command)
            socket = p.state / "model/selected.sock"
            upgrade.replace_option(updated, "--translator-unix-socket", str(socket))
            selected = list(sidecar.arguments)
            upgrade.replace_option(selected, "--config", "selected.json")
            return replace(sidecar, arguments=selected), updated, socket

        monkeypatch.setattr(upgrade, "prepare_sidecar", prepare)
        monkeypatch.setattr(upgrade, "wait_capacity", lambda *_a, **_k: {"ok": True})
    upgrade._root_file(
        system,
        upgrade.canonical(
            {
                "running": True,
                "arguments": p.current[0].arguments,
                "user": p.current[0].user,
                "cwd": str(p.cwd),
                "configured_cwd": "/",
                "sidecar": {
                    "running": True,
                    "arguments": sidecar.arguments,
                    "user": sidecar.user,
                    "cwd": str(sidecar.working_directory),
                    "configured_cwd": "/",
                }
                if sidecar
                else None,
            }
        ),
        0o600,
    )

    def record(event):
        with trace.open("ab") as stream:
            stream.write(upgrade.canonical(event) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())

    def crash(point):
        if point == boundary and not killed.exists():
            upgrade._root_file(killed, point.encode(), 0o600)
            os._exit(91)

    def current(name="umi-miner.service"):
        value = json.loads(system.read_bytes())
        if name == "umi-model.service":
            value = value["sidecar"]
        if not value["running"]:
            raise upgrade.ServiceNotRunning("the miner is stopped and cannot be discovered")
        return replace(
            sidecar if name == "umi-model.service" else p.current[0],
            arguments=value["arguments"],
            user=value["user"],
            working_directory=Path(value["cwd"]),
        )

    def discover():
        record({"event": "discover"})
        return current()

    def run(*arguments, **kwargs):
        record({"event": "systemctl", "arguments": arguments})
        system_value = json.loads(system.read_bytes())
        is_sidecar = len(arguments) > 2 and arguments[2] == "umi-model.service"
        value = system_value["sidecar"] if is_sidecar else system_value
        if arguments[-1] == "--property=FragmentPath,DropInPaths,WorkingDirectory":
            output = (
                f"FragmentPath={units / arguments[2]}\nDropInPaths=\n"
                f"WorkingDirectory={value['configured_cwd']}\n"
            )
        elif arguments[-1] == "--property=User,WorkingDirectory":
            output = f"User={value['user']}\nWorkingDirectory={value['configured_cwd']}\n"
        elif arguments[-1] == "--property=ActiveState,ControlGroup":
            output = (
                "ActiveState=active\nControlGroup=/miner\n"
                if value["running"]
                else "ActiveState=inactive\nControlGroup=\n"
            )
        elif "show" in arguments:
            output = (
                "TimeoutStopUSec=infinity\nTimeoutStartUSec=infinity\nSendSIGKILL=no\n"
                "KillMode=mixed\nKillSignal=15\nSendSIGHUP=no\n"
            )
        else:
            output = ""
        if "stop" in arguments:
            assert kwargs["timeout"] is None
            value["running"] = False
            upgrade._root_file(system, upgrade.canonical(system_value), 0o600)
            crash("sidecar_stopped" if is_sidecar else "stopped")
        if arguments == ("systemctl", "daemon-reload"):
            dropin = upgrade.SYSTEMD_ROOT / "umi-miner.service.d/90-umi-cohort-upgrade.conf"
            if dropin.exists():
                system_value["configured_cwd"] = system_value["cwd"]
                if system_value["sidecar"]:
                    system_value["sidecar"]["configured_cwd"] = system_value["sidecar"]["cwd"]
                upgrade._root_file(system, upgrade.canonical(system_value), 0o600)
                crash("override_installed")
        if "start" in arguments:
            assert kwargs["timeout"] is None
            intent = json.loads((p.state / "activation-recovery.json").read_bytes())
            command = Path(
                intent["activation"]["sidecar_command_path" if is_sidecar else "miner_command_path"]
            )
            value["running"] = True
            value["arguments"] = json.loads(command.read_bytes())["arguments"]
            upgrade._root_file(system, upgrade.canonical(system_value), 0o600)
            crash("sidecar_started" if is_sidecar else "started")
        return subprocess.CompletedProcess(arguments, 0, output, "")

    native_write = upgrade.write_private

    def write(path, raw, account):
        native_write(path, raw, account)
        if path.name == "upgrade-receipt.json":
            crash("receipt_persisted")

    def enroll(**kwargs):
        crash("enrollment")
        return {"status": "retained_request_reused"}

    monkeypatch.setattr(upgrade, "run", run)
    monkeypatch.setattr(upgrade, "write_private", write)
    monkeypatch.setattr(upgrade, "discover_miner", discover)
    monkeypatch.setattr(upgrade, "service", current)
    monkeypatch.setattr(upgrade, "wait_health", lambda *_a, **_k: {"ok": True})
    monkeypatch.setattr(upgrade, "install_endpoint_enrollment", enroll)
    p.system = system
    p.trace = trace
    return p


def _process_attempt(expected):
    child = multiprocessing.get_context("fork").Process(target=upgrade.main)
    child.start()
    child.join(20)
    if child.is_alive():
        child.kill()
        child.join()
        pytest.fail("isolated upgrade child did not finish")
    assert child.exitcode == expected


def _effects(path):
    events = [json.loads(line) for line in path.read_bytes().splitlines()]
    return [
        event["arguments"]
        for event in events
        if event["event"] == "systemctl"
        and any(word in event["arguments"] for word in ("stop", "start"))
    ]


@pytest.mark.skipif(
    "fork" not in multiprocessing.get_all_start_methods(), reason="POSIX process exit"
)
@pytest.mark.parametrize(
    "boundary",
    [
        "stopped",
        "override_installed",
        "started",
        "receipt_persisted",
        "enrollment",
        "sidecar_stopped",
        "sidecar_started",
    ],
)
def test_process_exit_resumes_stopped_or_already_selected_miner_without_reset(
    tmp_path, monkeypatch, boundary
):
    p = _crash_harness(tmp_path, monkeypatch, boundary)
    retained = p.cwd / "protocol/nonce.sqlite3"
    retained.write_bytes(b"retained protocol state")
    config = CohortMinerStartupConfig.model_validate_json(p.startup_raw)
    binding = config.authority.model_dump(mode="json", by_alias=True, exclude=set(LOCAL_LIMITS))
    journal = RoundJournal(Path(config.authority.directory), binding)
    journal.put("upgrade-process-test", "retained", {"original": True})
    journal_before = (
        journal.path.stat().st_ino,
        journal.path.read_bytes(),
        Path(config.authority.directory).stat().st_ino,
    )
    before = (retained.stat().st_ino, retained.read_bytes(), (p.cwd / "startup.json").read_bytes())
    _process_attempt(91)
    recovery = p.state / "activation-recovery.json"
    assert recovery.exists() is (boundary != "enrollment")
    first = _effects(p.trace)
    _process_attempt(0)
    receipt = json.loads((p.state / "upgrade-receipt.json").read_bytes())
    assert receipt["status"] == "miner_upgrade_verified"
    assert not recovery.exists()
    assert not list(upgrade.SYSTEMD_RUNTIME_ROOT.rglob("zz-umi-cohort-upgrade-drain.conf"))
    assert json.loads(p.system.read_bytes())["running"]
    assert before == (
        retained.stat().st_ino,
        retained.read_bytes(),
        (p.cwd / "startup.json").read_bytes(),
    )
    after = _effects(p.trace)
    if boundary in {"started", "receipt_persisted", "enrollment"}:
        assert after == first, "a selected healthy runtime must be adopted without another stop"
    else:
        assert len(after) == len(first) + (4 if boundary.startswith("sidecar_") else 2)
    if boundary.startswith("sidecar_"):
        assert (
            tmp_path / "sidecar-cwd/original.json"
        ).read_bytes() == b'{"retained_model_configuration":true}'
        assert json.loads(p.system.read_bytes())["sidecar"]["running"]
    _process_attempt(0)
    assert _effects(p.trace) == after
    assert journal_before == (
        journal.path.stat().st_ino,
        journal.path.read_bytes(),
        Path(config.authority.directory).stat().st_ino,
    )
    reopened = RoundJournal(Path(config.authority.directory), binding)
    assert reopened.get_raw("upgrade-process-test", "retained") == b'{"original":true}'


@pytest.mark.parametrize(
    "fault",
    ["manifest", "account", "cwd", "command", "startup", "override", "base_unit", "live_command"],
)
def test_changed_recovery_binding_refuses_before_any_service_mutation(tmp_path, monkeypatch, fault):
    p = _crash_harness(tmp_path, monkeypatch, "stopped")
    _process_attempt(91)
    marker = p.state / "activation-recovery.json"
    record = json.loads(marker.read_bytes())
    if fault in {"manifest", "account"}:
        record["manifest_sha256" if fault == "manifest" else "uid"] = (
            "ff" * 32 if fault == "manifest" else record["uid"] + 1
        )
        marker.write_bytes(upgrade.canonical(record))
    elif fault == "cwd":
        value = json.loads(p.system.read_bytes())
        value["configured_cwd"] = str(tmp_path)
        p.system.write_bytes(upgrade.canonical(value))
    elif fault == "base_unit":
        (tmp_path / "units/umi-miner.service").write_bytes(
            b"[Service]\nExecStart=/unrelated/command\n"
        )
    elif fault == "live_command":
        value = json.loads(p.system.read_bytes())
        value["running"] = True
        value["arguments"] = ["/unrelated/command"]
        p.system.write_bytes(upgrade.canonical(value))
    elif fault == "command":
        Path(record["activation"]["miner_command_path"]).write_bytes(
            b'{"arguments":[],"schema":"changed"}'
        )
    elif fault == "startup":
        (p.state / "inputs/miner-startup.json").write_bytes(b'{"changed":true}')
    else:
        path = upgrade.SYSTEMD_ROOT / "umi-miner.service.d/90-umi-cohort-upgrade.conf"
        path.parent.mkdir(parents=True)
        path.write_bytes(b"operator changed the override")
    before = _effects(p.trace)
    marker_before = marker.read_bytes()
    _process_attempt(1)
    assert _effects(p.trace) == before
    assert marker.read_bytes() == marker_before
    assert json.loads(p.system.read_bytes())["running"] is (fault == "live_command")


@pytest.mark.parametrize("failure_at", ["validation", "observation"])
def test_running_service_with_unavailable_cwd_refuses_recovery_without_restart(
    tmp_path, monkeypatch, failure_at
):
    native_service = upgrade.service
    p = _crash_harness(tmp_path, monkeypatch, "stopped")
    _process_attempt(91)
    marker = p.state / "activation-recovery.json"
    record = json.loads(marker.read_bytes())
    command = Path(record["activation"]["miner_command_path"])
    arguments = json.loads(command.read_bytes())["arguments"]
    system = json.loads(p.system.read_bytes())
    system["running"] = True
    system["arguments"] = arguments
    p.system.write_bytes(upgrade.canonical(system))
    native_run, native_readlink = upgrade.run, os.readlink
    reads = [0]

    def run(*args, **kwargs):
        if args[-2:] == ("--property=MainPID", "--property=User"):
            return subprocess.CompletedProcess(
                args, 0, f"MainPID=987654\nUser={p.current[0].user}\n", ""
            )
        return native_run(*args, **kwargs)

    def readlink(path, *args, **kwargs):
        if str(path) == "/proc/987654/cwd":
            reads[0] += 1
            missing = failure_at == "validation" or reads[0] >= 2
            return str(tmp_path / "unavailable-live-cwd") if missing else str(p.cwd)
        return native_readlink(path, *args, **kwargs)

    monkeypatch.setattr(upgrade, "service", native_service)
    monkeypatch.setattr(upgrade, "run", run)
    monkeypatch.setattr(upgrade.os, "readlink", readlink)
    monkeypatch.setattr(upgrade, "cmdline", lambda _pid: arguments)
    before = _effects(p.trace)
    _process_attempt(1)
    assert _effects(p.trace) == before
    retained = json.loads(marker.read_bytes())
    assert retained["activation"] == record["activation"]
    assert retained["inputs_sha256"] == record["inputs_sha256"]
    assert json.loads(p.system.read_bytes()) == system


def test_migration_progress_has_counted_stages_elapsed_and_honest_eta(monkeypatch, capsys):
    now = [100.0]
    monkeypatch.setattr(upgrade.time, "monotonic", lambda: now[0])
    progress = upgrade.MigrationProgress()
    progress.select(["first", "second"])
    progress.advance("first")
    now[0] += 7
    initial = progress.snapshot()
    assert initial["percent"] == 0 and initial["eta_seconds"] is None
    assert initial["stage_elapsed_seconds"] == 7
    progress.history = {"first": 10, "second": 20}
    assert progress.snapshot()["eta_seconds"] == 23
    progress.advance("second")
    assert progress.snapshot()["percent"] == 50
    now[0] += 25
    overdue = progress.snapshot()
    assert overdue["eta_seconds"] is None
    assert overdue["eta_basis"] == "previous_duration_exceeded"
    assert overdue["elapsed_seconds"] == 32
    waits = iter((False, True))

    def wait(seconds):
        assert seconds == 30
        return next(waits)

    monkeypatch.setattr(progress.stop, "wait", wait)
    progress._heartbeat()
    progress.finish("complete")
    events = [json.loads(line) for line in capsys.readouterr().err.splitlines()]
    assert events[-2]["status"] == "waiting_beyond_estimate"
    assert events[-1]["percent"] == 100 and events[-1]["eta_seconds"] == 0
    assert events[-1]["stage_seconds"] == {"first": 7, "second": 25}


def test_first_run_planning_range_is_labeled_and_respects_selected_activation_budget(monkeypatch):
    progress = upgrade.MigrationProgress()
    progress.advance("manifest")
    snapshot = progress.snapshot()
    assert snapshot["eta_basis"] == "planning_estimate_not_deadline"
    low, high = snapshot["planning_eta_range_seconds"]
    assert 0 <= low <= snapshot["eta_seconds"] <= high
    assert snapshot["eta_confidence"] == "low"
    assert "no_prolonged_active_work_drain" in snapshot["planning_assumptions"]
    monkeypatch.setattr(upgrade, "PROGRESS", progress)
    upgrade.progress_limits({"startup_seconds": 7200, "inference_seconds": 600})
    progress.select(["activation"])
    progress.advance("activation")
    assert progress.snapshot()["planning_eta_range_seconds"][1] > 7799


def test_disconnected_progress_sink_does_not_interrupt_cutover_or_receipt(
    tmp_path, monkeypatch, capsys
):
    p = _main_harness(tmp_path, monkeypatch)

    class Disconnected:
        def write(self, _value):
            raise BrokenPipeError("logging connection closed")

        def flush(self):
            raise BrokenPipeError("logging connection closed")

    with monkeypatch.context() as disconnected:
        disconnected.setattr(upgrade.sys, "stderr", Disconnected())
        upgrade.main()
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "miner_upgrade_verified"
    assert report["migration_progress"]["progress_write_failures"] > 0
    assert not (p.state / "activation-recovery.json").exists()
    assert len(p.activated) == 1


def test_override_preserves_effective_working_directory_in_native_systemd(tmp_path, monkeypatch):
    verifier = shutil.which("systemd-analyze")
    if verifier is None:
        pytest.skip("native systemd verifier is unavailable")
    monkeypatch.setattr(upgrade, "SYSTEMD_ROOT", tmp_path / "systemd")
    monkeypatch.setattr(upgrade.os, "chown", lambda *_args: None)
    cwd = tmp_path / 'model 100% "quoted"'
    cwd.mkdir()
    path = upgrade.override(
        "umi-miner.service",
        tmp_path / "command.json",
        "ab" * 32,
        Path("/usr/bin/true"),
        3600,
        cwd,
    )
    unit = tmp_path / "native-qualified.service"
    unit.write_bytes(path.read_bytes())
    checked = subprocess.run(
        [verifier, "verify", "--man=no", str(unit)],
        text=True,
        capture_output=True,
        timeout=30,
        env=dict(os.environ, SYSTEMD_LOG_LEVEL="debug"),
    )
    assert checked.returncode == 0, checked.stderr
    assert f"WorkingDirectory: {cwd}" in checked.stdout + checked.stderr
