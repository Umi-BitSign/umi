"""Opt-in, wallet-free systemd/Podman rehearsal in the dedicated Lima VM.

Run as root with UMI_RUN_SERVICE_REHEARSAL=1 and UMI_REHEARSAL_OCI_ARCHIVE.
This uses synthetic capability issuers only to render the production service
override. The system account, unit hardening, rootless container, kernel cgroup,
and cleanup entrypoint are real. No competition activation or chain call runs.
Test accounts and fixtures are retained; only the named rehearsal workloads
and their dedicated user manager are stopped afterward.
"""

from __future__ import annotations

import hashlib
import json
import os
import pwd
import secrets
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from umi import competition_host_service as service
from umi.protocol import canonical_json_bytes

from .test_competition_host_service import case as case
from .test_validator_supervisor import _config

pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or os.environ.get("UMI_RUN_SERVICE_REHEARSAL") != "1",
    reason="requires explicit root opt-in inside the wallet-free service rehearsal VM",
)

_USER = "umi-succ-rehearsal"
_ROOT = Path("/var/lib/umi-successor-service-rehearsal")
_STATE = Path("/var/lib/umi-successor-service-rehearsal-state")
_WORKER = Path("/var/lib/umi-successor-service-rehearsal-worker")
_UNIT = "umi-successor-service-rehearsal.service"
_CLEANUP_UNIT = "umi-successor-service-rehearsal-successor-cleanup.service"
_UNIT_PATH = Path("/etc/systemd/system") / _UNIT
_CLEANUP_UNIT_PATH = Path("/etc/systemd/system") / _CLEANUP_UNIT
_DROPIN = Path("/etc/systemd/system") / (_UNIT + ".d") / "50-rehearsal.conf"
_SUBID_START, _SUBID_COUNT = 2**31, 65536


def _command(*args, check=True, timeout=60):
    result = subprocess.run(
        [str(arg) for arg in args],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=timeout,
        cwd="/",
    )
    assert len(result.stdout) + len(result.stderr) <= 4 * 1024 * 1024
    if check and result.returncode:
        raise AssertionError(
            f"rehearsal command failed ({result.returncode}): {args!r}\n"
            + result.stdout.decode(errors="replace")
            + result.stderr.decode(errors="replace")
        )
    return result


def _write(path, body, mode=0o644):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    path.write_bytes(body.encode() if isinstance(body, str) else body)
    path.chmod(mode)


def _owned_directory(path, user):
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.chmod(0o700)
    os.chown(path, user.pw_uid, user.pw_gid)


def _account():
    marker = _ROOT / "account.json"
    try:
        user = pwd.getpwnam(_USER)
    except KeyError:
        assert not marker.exists()
        _command(
            "/usr/sbin/useradd",
            "--system",
            "--user-group",
            "--home-dir",
            _ROOT / "home",
            "--shell",
            "/usr/sbin/nologin",
            _USER,
        )
        user = pwd.getpwnam(_USER)
        _write(marker, json.dumps({"user": _USER, "uid": user.pw_uid, "home": user.pw_dir}))
    assert json.loads(marker.read_bytes()) == {
        "user": _USER,
        "uid": user.pw_uid,
        "home": user.pw_dir,
    }
    assert user.pw_dir == str(_ROOT / "home") and user.pw_shell == "/usr/sbin/nologin"
    for path, option in (
        (Path("/etc/subuid"), "--add-subuids"),
        (Path("/etc/subgid"), "--add-subgids"),
    ):
        entries = [line.split(":") for line in path.read_text().splitlines() if line]
        own = [entry for entry in entries if entry[0] == _USER]
        if not own:
            for _, start, count in entries:
                assert int(start) + int(count) <= _SUBID_START or int(start) >= (
                    _SUBID_START + _SUBID_COUNT
                )
            _command(
                "/usr/sbin/usermod",
                option,
                f"{_SUBID_START}-{_SUBID_START + _SUBID_COUNT - 1}",
                _USER,
            )
        else:
            assert own == [[_USER, str(_SUBID_START), str(_SUBID_COUNT)]]
    _owned_directory(Path(user.pw_dir), user)
    return user


def _as_user(user, *args, **kwargs):
    return _command(
        "/usr/sbin/runuser",
        "-u",
        _USER,
        "--",
        "/usr/bin/env",
        "-i",
        "PATH=/usr/bin:/bin",
        "LANG=C.UTF-8",
        f"HOME={user.pw_dir}",
        f"USER={_USER}",
        f"LOGNAME={_USER}",
        f"XDG_RUNTIME_DIR=/run/user/{user.pw_uid}",
        f"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{user.pw_uid}/bus",
        *args,
        **kwargs,
    )


def _wait(probe, *, seconds=90):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if value := probe():
            return value
        time.sleep(0.1)
    raise AssertionError("rehearsal condition timed out")


def _show_unit(unit=_UNIT):
    data = _command(
        "/usr/bin/systemctl",
        "show",
        unit,
        "--property=ActiveState,SubState,MainPID,Result,ExecMainExitTimestampMonotonic",
        check=False,
    ).stdout.decode()
    return dict(line.split("=", 1) for line in data.splitlines())


def _install_test_code(destination):
    project = Path(__file__).resolve().parents[1]
    shutil.copytree(project / "src", destination / "src")
    environment = destination / ".venv"
    _command("/usr/bin/python3", "-m", "venv", "--without-pip", environment)
    version = f"python{sys.version_info.major}.{sys.version_info.minor}"
    site = Path(sys.prefix) / "lib" / version / "site-packages"
    assert site.is_dir()
    shutil.copytree(site, environment / "lib" / version / "site-packages", dirs_exist_ok=True)
    # The test venv uses /usr/bin/python3; no service access to the interactive
    # operator's private HOME or Python installation is granted.
    python = environment / "bin/python"
    preamble = f"#!{python} -I\nimport sys\nsys.path.insert(0, {str(destination / 'src')!r})\n"
    _write(
        environment / "bin/umi-competition-supervisor-cleanup",
        preamble + "from umi.competition_supervisor_cleanup import main\nmain()\n",
        0o555,
    )
    _write(
        environment / "bin/umi-competition-supervisor",
        preamble + _HOST_PROGRAM,
        0o555,
    )
    for root, directories, files in os.walk(destination):
        Path(root).chmod(0o755)
        for name in directories:
            item = Path(root) / name
            if not item.is_symlink():
                item.chmod(0o755)
        for name in files:
            item = Path(root) / name
            if not item.is_symlink():
                item.chmod(0o555 if os.access(item, os.X_OK) else 0o444)


_HOST_PROGRAM = r"""
import argparse, asyncio, json, os, secrets, subprocess
from pathlib import Path
from umi.competition_container import PodmanSuccessorContainer, SuccessorContainerLimits, PYTHON
from umi.competition_container import _REHEARSAL, _container_cgroup, _command_environment
from umi.competition_container import PODMAN_CGROUP_MANAGER_ARGUMENT
from umi.competition_supervisor_cleanup import _CleanupLease
from umi.validator_supervisor import parse_canonical_validator_supervisor_config
p = argparse.ArgumentParser()
p.add_argument('--config', type=Path, required=True)
p.add_argument('--orphan', action='store_true')
a = p.parse_args()
config = parse_canonical_validator_supervisor_config(a.config.read_bytes())
root = Path(config.state_root)
image = json.loads((a.config.parent / 'image.json').read_bytes())['reference']
async def run():
    with _CleanupLease(a.config):
        port = PodmanSuccessorContainer(config, limits=SuccessorContainerLimits(
            1, 1024, 1, 1024, 1, 1024, command_timeout_seconds=60))
        diagnostic = subprocess.run([config.container_runtime, PODMAN_CGROUP_MANAGER_ARGUMENT,
            'info', '--format=json'],
            capture_output=True, env=_command_environment(), timeout=60, cwd='/')
        os.write(2, diagnostic.stderr[:65536])
        if diagnostic.returncode:
            raise RuntimeError('test-only Podman info diagnostic failed')
        host = json.loads(diagnostic.stdout)['host']
        os.write(2, (json.dumps({'cgroupManager': host['cgroupManager'],
            'cgroupVersion': host['cgroupVersion'], 'ociRuntime': host['ociRuntime']['name'],
            'rootless': host['security']['rootless']}) + '\n').encode())
        await port.check_host()
        old = await port.status()
        if old.phase not in {'absent', 'running'}:
            await port.remove_stopped()
        if (await port.status()).phase != 'absent':
            raise RuntimeError('rehearsal refuses an existing live worker')
        args = ['create', '--name', port.name, *port._sandbox('none')]
        labels = {'config': port._config_sha256, 'hotkey': port._hotkey_sha256,
                  'directive': 'cd' * 32, 'receipt': 'ef' * 32,
                  'profile': 'competition_replay'}
        for key, value in sorted(labels.items()):
            args += ['--label', 'vision.umi.successor.' + key + '=' + value]
        # Test-only bounded proof output mount; the probe is the initial process,
        # just as in production rehearse(). An extra Podman exec originates in
        # the system unit and cannot migrate itself across cgroup delegations.
        proof = root / ('sandbox-proof-' + secrets.token_hex(8))
        proof.mkdir(mode=0o700)
        args += ['--mount', 'type=bind,src=' + str(proof) + ',dst=/run/umi-probe,rw',
            '--entrypoint', PYTHON, image, '-I', '-c', _REHEARSAL +
            "\npathlib.Path('/run/umi-probe/result.json').write_text(json.dumps(result))" +
            '\nimport time; time.sleep(600)', str(config.worker_uid),
            str(config.worker_memory_bytes), str(config.worker_pids_limit),
            str(config.worker_cpu_millis)]
        cid = (await port._command(*args)).decode().strip()
        await port._inspect_owned(cid)
        await port._command('start', cid)
        for attempt in range(100):
            if (proof / 'result.json').is_file():
                break
            await asyncio.sleep(0.1)
        if json.loads((proof / 'result.json').read_bytes()) != {
                'schema': 'umi-successor-sandbox-rehearsal/1', 'ok': True}:
            raise RuntimeError('sandbox probe did not pass')
        status = await port.status()
        if status.phase != 'running':
            raise RuntimeError('rehearsal worker not running')
        record = await port._inspect_owned(cid)
        kernel_cgroup = Path('/proc/' + str(record['State']['Pid']) + '/cgroup').read_text()
        if not kernel_cgroup.startswith('0::' + _container_cgroup(cid) + '/'):
            raise RuntimeError('worker is outside the expected user-manager cgroup')
        if not a.orphan and not os.statvfs('/run/umi-successor-activation').f_flag & os.ST_RDONLY:
            raise RuntimeError('activation parent is not mounted read-only')
        if not a.orphan and (list(Path('/home').iterdir()) or {
                item.name for item in Path('/run/user').iterdir()} != {str(os.geteuid())}):
            raise RuntimeError('service exposes another user home/runtime directory')
        (root / 'started.json').write_text(json.dumps({'pid': os.getpid(), 'id': cid,
            'cgroup': _container_cgroup(cid), 'kernel_cgroup': kernel_cgroup,
            'sandbox': True, 'orphan': a.orphan}))
        if not a.orphan:
            await asyncio.Event().wait()
asyncio.run(run())
"""


def test_generated_system_unit_and_crash_cleanup(case):
    assert os.geteuid() == 0
    assert socket.gethostname() == "lima-umi-successor-rehearsal"
    archive = Path(os.environ["UMI_REHEARSAL_OCI_ARCHIVE"])
    assert archive.is_absolute() and archive.is_file() and not archive.is_symlink()
    _ROOT.mkdir(mode=0o755, exist_ok=True)
    assert _ROOT.stat().st_uid == 0 and not _ROOT.is_symlink()
    user = _account()
    assert _show_unit().get("ActiveState") != "active"
    assert _show_unit(_CLEANUP_UNIT).get("ActiveState") not in {"active", "activating"}
    started_at = "@" + str(int(time.time()))
    run = _ROOT / ("run-" + secrets.token_hex(8))
    run.mkdir(mode=0o755)
    code = run / "code"
    _install_test_code(code)
    for path in (_STATE, _WORKER, _ROOT / "releases", _STATE / "successor-observer"):
        _owned_directory(path, user)
    activation = _STATE / "successor-v4/activation-source"
    activation.mkdir(parents=True, mode=0o755, exist_ok=True)
    activation.chmod(0o555)
    lock = _STATE / "supervisor-process.lock"
    if not lock.exists():
        _write(lock, b"test-only original supervisor lock", 0o600)
        os.chown(lock, user.pw_uid, user.pw_gid)
    source = run / "synthetic.oci.tar"
    shutil.copyfile(archive, source)
    source.chmod(0o444)
    manager = f"user@{user.pw_uid}.service"
    _command("/usr/bin/loginctl", "enable-linger", _USER)
    _command("/usr/bin/systemctl", "start", manager)
    try:
        _as_user(user, "/usr/bin/podman", "load", "--input", source, timeout=180)
        reference = "ghcr.io/umi-bitsign/umi-validator:synthetic-successor-rehearsal"
        (image,) = json.loads(
            _as_user(
                user,
                "/usr/bin/podman",
                "image",
                "inspect",
                "--format=json",
                reference,
            ).stdout
        )
        assert json.loads(_as_user(user, "/usr/bin/podman", "ps", "--format=json").stdout) == []
        # Offline import created a pause process outside the unit. End only this
        # test account's unused namespaces so service startup must recreate them.
        _as_user(user, "/usr/bin/podman", "system", "migrate")
        assert not Path(f"/run/user/{user.pw_uid}/libpod/tmp/pause.pid").exists()
        reference = "ghcr.io/umi-bitsign/umi-validator@" + image["Digest"]
        _write(run / "image.json", json.dumps({"reference": reference}), 0o444)
        config = _config(
            target_platform="linux/" + image["Architecture"],
            state_root=str(_STATE),
            worker_state_root=str(_WORKER),
            release_root=str(_ROOT / "releases"),
            worker_cpu_millis=1000,
            worker_memory_bytes=256 * 1024**2,
            worker_pids_limit=32,
            wallet={"path": str(_ROOT / "never-created-wallet"), "name": "none", "hotkey": "none"},
        )
        config_path = run / "supervisor.json"
        _write(config_path, canonical_json_bytes(config), 0o444)
        # Only issuer verification is synthetic. Feed the actual generated
        # unit text into systemd, preserving its fixed paths and '+' cleanup.
        case.user.pw_name, case.user.pw_uid, case.user.pw_dir = _USER, user.pw_uid, user.pw_dir
        object.__setattr__(case.anchor, "config", config)
        object.__setattr__(case.anchor, "service_uid", user.pw_uid)
        object.__setattr__(case.anchor, "source_root", activation)
        object.__setattr__(case.stopped, "service_uid", user.pw_uid)
        object.__setattr__(case.stopped, "validator_hotkey", config.validator_hotkey)
        object.__setattr__(case.stopped, "unit_name", _UNIT)
        object.__setattr__(case.stopped, "_lease", SimpleNamespace(config_path=config_path))
        object.__setattr__(case.tree, "path", code)
        for entry in case.signed.manifest.files:
            if entry.path.startswith("artifacts/"):
                body = ("wallet-free fixture " + entry.path).encode()
                entry.sha256 = hashlib.sha256(body).hexdigest()
                _write(code / entry.path, body, entry.mode)
        chain = case.anchor.observer_config.chain
        entries = {item.path: item for item in case.signed.manifest.files}
        chain.proof_binary_sha256 = entries["artifacts/umi-substrate-proof-verifier"].sha256
        chain.finality_pin.release_sha256_by_target[chain.target_triple] = entries[
            "artifacts/umi-grandpa-finality-observer"
        ].sha256
        chain.finality_pin.chain_spec_sha256 = entries["artifacts/raw_spec_finney.json"].sha256
        plan = service.plan_successor_service_switch(
            stopped=case.stopped,
            anchor=case.anchor,
            host_tree=case.tree,
            signed_host=case.signed,
        )
        base = (
            Path(__file__).parents[1]
            / "deploy/linux-validator-supervisor/umi-validator-supervisor.service"
        ).read_text()
        base = base.replace("User=umi-validator", "User=" + _USER)
        base = base.replace("Group=umi-validator", "Group=" + _USER)
        base = base.replace(
            "StateDirectory=umi-validator-supervisor",
            "StateDirectory=" + _STATE.name,
        )
        base = base.replace(
            "RuntimeDirectory=umi-validator-supervisor",
            "RuntimeDirectory=" + _ROOT.name,
        )
        _write(_UNIT_PATH, base)
        overrides = (
            "[Service]\nRestart=no\nWorkingDirectory="
            + str(_STATE)
            + "\nReadOnlyPaths=\nReadWritePaths=\nReadWritePaths="
            + str(_STATE)
            + " "
            + str(_WORKER)
            + "\n"
        ).encode() + plan.drop_in_bytes
        assert plan.cleanup_unit_name == _CLEANUP_UNIT
        assert plan.cleanup_unit_path == _CLEANUP_UNIT_PATH
        _write(_CLEANUP_UNIT_PATH, plan.cleanup_unit_bytes)
        _write(run / "generated-fallback.service", plan.cleanup_unit_bytes)
        _write(_DROPIN, overrides)
        _write(run / "generated-positive.conf", overrides)
        _command("/usr/bin/systemctl", "daemon-reload")
        _command("/usr/bin/systemctl", "start", _UNIT)

        def ready():
            current = _show_unit()
            assert current["ActiveState"] != "failed", "service exited before sandbox was ready"
            status_path = _STATE / "started.json"
            if current["ActiveState"] != "active" or not status_path.exists():
                return None
            record = json.loads(status_path.read_bytes())
            return record if record["pid"] == int(current["MainPID"]) else None

        first = _wait(ready)
        assert first["sandbox"] and not first["orphan"]
        assert first["cgroup"].startswith(f"/user.slice/user-{user.pw_uid}.slice/")
        busy = _as_user(
            user,
            code / ".venv/bin/umi-competition-supervisor-cleanup",
            "--config",
            config_path,
            check=False,
        )
        assert busy.returncode == 3 and busy.stderr == b"successor_cleanup=busy\n"
        (unchanged,) = json.loads(
            _as_user(
                user,
                "/usr/bin/podman",
                "container",
                "inspect",
                "--format=json",
                first["id"],
            ).stdout
        )
        assert unchanged["State"]["Running"] is True
        _command("/usr/bin/systemctl", "kill", "--kill-whom=main", "--signal=KILL", _UNIT)
        _wait(lambda: _show_unit()["ActiveState"] == "failed")

        def fallback_finished(after):
            current = _show_unit(_CLEANUP_UNIT)
            assert current["ActiveState"] != "failed", "mount-free cleanup failed"
            return (
                current
                if current["ActiveState"] == "inactive"
                and int(current["ExecMainExitTimestampMonotonic"]) > after
                else None
            )

        prior_cleanup = _wait(lambda: fallback_finished(0))
        (stopped,) = json.loads(
            _as_user(
                user,
                "/usr/bin/podman",
                "container",
                "inspect",
                "--format=json",
                first["id"],
            ).stdout
        )
        assert stopped["State"]["Running"] is False and stopped["State"]["Pid"] == 0
        _command("/usr/bin/systemctl", "reset-failed", _UNIT)
        _as_user(
            user,
            code / ".venv/bin/umi-competition-supervisor",
            "--config",
            config_path,
            "--orphan",
            timeout=120,
        )
        orphan = json.loads((_STATE / "started.json").read_bytes())
        assert orphan["orphan"] and orphan["id"] != first["id"]
        missing = run / "deliberately-missing-bind-source"
        assert not missing.exists()
        broken = (
            overrides
            + (
                "[Service]\nRestart=always\nRestartSec=15s\nBindReadOnlyPaths="
                + str(missing)
                + ":/run/umi-test-missing\n"
            ).encode()
        )
        _write(_DROPIN, broken)
        _write(run / "generated-broken-mount.conf", broken)
        _command("/usr/bin/systemctl", "daemon-reload")
        _command("/usr/bin/systemctl", "start", _UNIT, check=False)
        _wait(lambda: fallback_finished(int(prior_cleanup["ExecMainExitTimestampMonotonic"])))
        _command("/usr/bin/systemctl", "stop", _UNIT, check=False, timeout=180)
        (stopped,) = json.loads(
            _as_user(
                user,
                "/usr/bin/podman",
                "container",
                "inspect",
                "--format=json",
                orphan["id"],
            ).stdout
        )
        assert stopped["State"]["Running"] is False and stopped["State"]["Pid"] == 0
        logs = _command(
            "/usr/bin/journalctl",
            "--unit",
            _UNIT,
            "--unit",
            _CLEANUP_UNIT,
            "--no-pager",
            "--since",
            started_at,
            "-n",
            "200",
        ).stdout
        assert b"NAMESPACE" in logs or b"mount namespacing" in logs or b"mount namespace" in logs
        assert logs.count(b"successor_cleanup=stopped") >= 2
        assert not Path(config.wallet.path).exists()
        _write(
            run / "result.json",
            json.dumps(
                {
                    "schema": "umi-successor-service-rehearsal/1",
                    "service_uid": user.pw_uid,
                    "image": reference,
                    "noninteractive_sandbox": first,
                    "sigkill_cleanup": True,
                    "broken_mount_onfailure_cleanup": True,
                    "broken_mount_restart_always": True,
                    "concurrent_supervisor_lock_preserved": True,
                    "cold_rootless_namespace_startup": True,
                    "wallet_accessed": False,
                    "chain_submission": False,
                }
            ),
        )
        _write(run / "unit-journal.txt", logs)
        print("service rehearsal result:", run / "result.json")
    finally:
        # Explicit test-only identities; preserve account, image and evidence.
        try:
            _command("/usr/bin/systemctl", "stop", _UNIT, check=False, timeout=180)
            if (run / "supervisor.json").exists():
                _as_user(
                    user,
                    code / ".venv/bin/umi-competition-supervisor-cleanup",
                    "--config",
                    run / "supervisor.json",
                    check=False,
                    timeout=180,
                )
        finally:
            logs = _command(
                "/usr/bin/journalctl",
                "--unit",
                _UNIT,
                "--unit",
                _CLEANUP_UNIT,
                "--no-pager",
                "--since",
                started_at,
                "-n",
                "200",
                check=False,
            ).stdout
            _write(run / "unit-journal-final.txt", logs)
            _command("/usr/bin/systemctl", "stop", _CLEANUP_UNIT, check=False, timeout=180)
            _command("/usr/bin/systemctl", "stop", manager, check=False)
            _command("/usr/bin/loginctl", "disable-linger", _USER)
