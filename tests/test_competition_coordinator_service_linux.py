"""Rooted systemd startup, restart and crash cleanup for two fake validators.

Capability issuers and the long-running host are synthetic; systemd rendering,
rootless OCI execution, process locks and the cleanup executable are real. This
does not establish the signed initial migration or authorize a chain call.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import sys
import traceback
from pathlib import Path
from types import SimpleNamespace

import pytest

from umi import competition_coordinator_namespace as coordinator
from umi import competition_host_service as service
from umi.protocol import canonical_json_bytes

from .coordinator_rehearsal import (
    LEGACY_FRAGMENT,
    coordinator_roots,
    fixture_validator_hotkey,
    rooted_podman,
)
from .test_competition_host_service import case as case
from .test_competition_service_linux import (
    _command,
    _install_test_code,
    _owned_directory,
    _show_unit,
    _wait,
    _write,
)
from .test_validator_supervisor import _config

pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or os.environ.get("UMI_RUN_COORDINATOR_SERVICE_REHEARSAL") != "1",
    reason="requires explicit root opt-in in the wallet-free coordinator rehearsal VM",
)


def _render(case, layout, user, config, code, run):
    # Only the upgrade child acquires its private logical filesystem aliases.
    pid = os.fork()
    if pid == 0:
        try:
            coordinator.prepare_coordinator_host_view(
                unit_name=layout.unit_name, service_uid=user.pw_uid
            )
            case.user.pw_name = user.pw_name
            case.user.pw_uid = user.pw_uid
            case.user.pw_dir = user.pw_dir
            object.__setattr__(case.anchor, "config", config)
            object.__setattr__(case.anchor, "service_uid", user.pw_uid)
            object.__setattr__(
                case.anchor,
                "source_root",
                Path(config.state_root) / "successor-v4/activation-source",
            )
            object.__setattr__(case.stopped, "service_uid", user.pw_uid)
            object.__setattr__(case.stopped, "validator_hotkey", config.validator_hotkey)
            object.__setattr__(case.stopped, "unit_name", layout.unit_name)
            object.__setattr__(
                case.stopped,
                "_lease",
                SimpleNamespace(config_path=Path("/etc/umi/validator-supervisor.json")),
            )
            object.__setattr__(case.tree, "path", code)
            object.__setattr__(case.tree, "target_platform", config.target_platform)
            case.signed.manifest.target_platform = config.target_platform
            for entry in case.signed.manifest.files:
                if entry.path.startswith("artifacts/"):
                    entry.sha256 = hashlib.sha256((code / entry.path).read_bytes()).hexdigest()
            entries = {item.path: item for item in case.signed.manifest.files}
            chain = case.anchor.observer_config.chain
            chain.target_triple = {
                "linux/arm64": "aarch64-unknown-linux-gnu",
                "linux/amd64": "x86_64-unknown-linux-gnu",
            }[config.target_platform]
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
            _write(run / "override.conf", plan.drop_in_bytes)
            _write(run / "cleanup.service", plan.cleanup_unit_bytes)
        except BaseException:
            _write(run / "render-failure.txt", traceback.format_exc())
            os._exit(1)
        os._exit(0)
    _, status = os.waitpid(pid, 0)
    assert os.waitstatus_to_exitcode(status) == 0, (run / "render-failure.txt").read_text()


def _ready(record):
    unit = _show_unit(record.layout.unit_name)
    assert unit["ActiveState"] != "failed", "rooted supervisor failed before worker startup"
    path = record.state / "started.json"
    if unit["ActiveState"] == "active" and path.exists():
        value = json.loads(path.read_bytes())
        if value["pid"] == int(unit["MainPID"]):
            return value
    return None


def test_two_rooted_services_restart_and_clean_up_without_stopping_each_other(tmp_path, case):
    assert os.geteuid() == 0 and Path("/var/lib") in tmp_path.parents
    # Only these new, wallet-free fixture directories are made traversable by
    # the service users. pytest creates both with root-only access by default.
    for path in (tmp_path.parent, tmp_path):
        assert not path.is_symlink() and path.stat().st_uid == 0
        path.chmod(0o755)
    run = tmp_path / ("coordinator-lifecycle-" + secrets.token_hex(8))
    run.mkdir(mode=0o755)
    run.chmod(0o755)
    code = run / "code"
    # Match the production adapter's bounded cold image creation allowance.
    # The smaller generic fixture's 60 seconds is insufficient on the busy VM.
    _install_test_code(code, command_timeout_seconds=300)
    for entry in case.signed.manifest.files:
        if entry.path.startswith("artifacts/"):
            _write(code / entry.path, "unused public fixture " + entry.path, entry.mode)
    archive = Path(os.environ["UMI_REHEARSAL_OCI_ARCHIVE"])
    assert archive.is_absolute() and archive.is_file() and not archive.is_symlink()
    template = Path("/etc/systemd/system/umi-validator@.service")
    assert not template.exists()
    installed, records = [], []
    with coordinator_roots() as accounts:
        try:
            for layout, user in accounts:
                instance_run = run / ("uid" + layout.instance)
                instance_run.mkdir(mode=0o755)
                manager = f"user@{user.pw_uid}.service"
                _command("/usr/bin/loginctl", "enable-linger", user.pw_name)
                _command("/usr/bin/systemctl", "start", manager)

                def cli(*a, layout=layout, user=user, **kw):
                    return rooted_podman(layout, user, *a, binds=(code, archive), **kw)

                assert json.loads(cli("ps", "--format=json").stdout) == []
                cli("load", "--input", archive, timeout=300)
                image = json.loads(
                    cli(
                        "image",
                        "inspect",
                        "--format=json",
                        "ghcr.io/umi-bitsign/umi-validator:synthetic-successor-rehearsal",
                    ).stdout
                )[0]
                cli("system", "migrate")
                config = _config(
                    validator_hotkey=fixture_validator_hotkey(layout.instance),
                    target_platform="linux/" + image["Architecture"],
                    state_root="/var/lib/umi-validator-supervisor/state",
                    release_root="/var/lib/umi-validator-supervisor/releases",
                    worker_state_root="/var/lib/umi-validator-worker-state",
                    operator_input_root="/var/lib/umi-validator-operator-inputs",
                    worker_cpu_millis=1000,
                    worker_memory_bytes=256 * 1024**2,
                    worker_pids_limit=32,
                    wallet={
                        "path": "/var/lib/umi-validator-runtime-wallets",
                        "name": "none",
                        "hotkey": "none",
                    },
                )
                state = layout.physical(Path(config.state_root))
                source = state / "successor-v4/activation-source"
                source.mkdir(parents=True, mode=0o555, exist_ok=True)
                source.chmod(0o555)
                _owned_directory(state / "successor-observer", user)
                lock = state / "supervisor-process.lock"
                if not lock.exists():
                    _write(lock, "inert original process lock", 0o600)
                    os.chown(lock, user.pw_uid, user.pw_gid)
                _write(
                    layout.physical(Path("/etc/umi/validator-supervisor.json")),
                    canonical_json_bytes(config),
                    0o444,
                )
                _write(
                    layout.physical(Path("/etc/umi/image.json")),
                    json.dumps(
                        {"reference": "ghcr.io/umi-bitsign/umi-validator@" + image["Digest"]}
                    ),
                    0o444,
                )
                _write(
                    layout.physical(Path("/etc/umi/migration-approved")),
                    "synthetic rehearsal only",
                    0o444,
                )
                _render(case, layout, user, config, code, instance_run)
                dropin = (
                    Path("/etc/systemd/system")
                    / (layout.unit_name + ".d")
                    / "50-umi-successor.conf"
                )
                cleanup = Path("/etc/systemd/system") / (
                    layout.unit_name.removesuffix(".service") + "-successor-cleanup.service"
                )
                assert not dropin.exists() and not cleanup.exists()
                override = (
                    instance_run / "override.conf"
                ).read_bytes() + b"[Service]\nRestart=no\n"
                for path, body in (
                    (dropin, override),
                    (cleanup, (instance_run / "cleanup.service").read_bytes()),
                ):
                    _write(path, body)
                    installed.append(path)
                records.append(
                    SimpleNamespace(
                        layout=layout,
                        user=user,
                        state=state,
                        cli=cli,
                        dropin=dropin,
                        cleanup=cleanup,
                        lock_inode=lock.stat().st_ino,
                    )
                )
            _write(template, LEGACY_FRAGMENT)
            installed.append(template)
            _command("/usr/bin/systemctl", "daemon-reload")
            for record in records:
                _command("/usr/bin/systemctl", "start", record.layout.unit_name)
                record.first = _wait(lambda record=record: _ready(record), seconds=360)
                assert record.first["sandbox"] is True
            for record in records:
                other = next(r for r in records if r is not record)
                before_other = _ready(other)
                before = _ready(record)
                _command(
                    "/usr/bin/systemctl",
                    "kill",
                    "--kill-whom=main",
                    "--signal=KILL",
                    record.layout.unit_name,
                )
                _wait(
                    lambda record=record: (
                        _show_unit(record.layout.unit_name)["ActiveState"] == "failed"
                    )
                )
                _wait(
                    lambda record=record: (
                        _show_unit(record.cleanup.name)["ActiveState"] == "inactive"
                        and int(_show_unit(record.cleanup.name)["ExecMainExitTimestampMonotonic"])
                        > 0
                    )
                )
                stopped = json.loads(record.cli("inspect", "--format=json", before["id"]).stdout)[0]
                assert stopped["State"]["Running"] is False and stopped["State"]["Pid"] == 0
                assert _ready(other) == before_other
                assert (record.state / "supervisor-process.lock").stat().st_ino == record.lock_inode
                _command("/usr/bin/systemctl", "reset-failed", record.layout.unit_name)
                _command("/usr/bin/systemctl", "start", record.layout.unit_name)
                after = _wait(lambda record=record: _ready(record), seconds=360)
                assert after["pid"] != before["pid"] and after["id"] != before["id"]
                assert _ready(other) == before_other
            _write(
                run / "result.json",
                json.dumps(
                    {
                        "both_rooted_services": True,
                        "sigkill_and_restart_each": True,
                        "other_instance_unchanged": True,
                        "chain_submission": False,
                    }
                ),
            )
        finally:
            for record in records:
                _command(
                    "/usr/bin/systemctl", "stop", record.layout.unit_name, check=False, timeout=180
                )
                stopped = _show_unit(record.layout.unit_name)
                assert stopped["ActiveState"] in {"inactive", "failed"}
                assert stopped["MainPID"] == "0"
            for record in records:
                # Match failed-start containment: let the sealed fallback
                # finish. Stopping it here can strand a user-manager container
                # after the main unit has already stopped.
                _command("/usr/bin/systemctl", "start", record.cleanup.name, timeout=180)
                cleaned = _show_unit(record.cleanup.name)
                assert cleaned["ActiveState"] == "inactive" and cleaned["Result"] == "success"
                assert cleaned["MainPID"] == "0"
                assert json.loads(record.cli("ps", "--format=json").stdout) == []
            # Retain the exact test unit bytes off the systemd search path.
            for index, path in enumerate(installed):
                path.rename(run / f"retained-unit-{index}")
            _command("/usr/bin/systemctl", "daemon-reload")
            for record in records:
                _command("/usr/bin/systemctl", "reset-failed", record.layout.unit_name, check=False)
