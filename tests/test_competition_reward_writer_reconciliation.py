"""Real anchor/startup locks; synthetic systemd and Podman transport observations."""

import fcntl
import json
import os
import pwd
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from umi import competition_container as containers
from umi import competition_reward_writer_reconciliation as reconciliation
from umi import competition_reward_writer_service as service_selection
from umi import competition_supervisor_runtime as runtime
from umi.competition_supervisor_cli import _new_container
from umi.protocol import canonical_json_bytes

from .test_competition_materializer import (
    activation_case as activation_case,
)
from .test_competition_materializer import (
    anchor_case as anchor_case,
)
from .test_competition_materializer import (
    case as signed_case,  # noqa: F401
)
from .test_competition_materializer import (
    chain_config as chain_config,
)
from .test_competition_materializer import (
    explicit as explicit,
)
from .test_competition_materializer import (
    limits as limits,
)
from .test_competition_materializer import (
    package_case as package_case,
)
from .test_competition_materializer import (
    package_limits as package_limits,
)
from .test_competition_materializer import (
    policy as policy,
)
from .test_competition_materializer import (
    release_identity as release_identity,
)
from .test_competition_materializer import (
    replay_limits as replay_limits,
)
from .test_competition_materializer import (
    successor_release as successor_release,
)
from .test_competition_materializer import (
    trusted_ports as trusted_ports,
)
from .test_competition_materializer import (
    worker_capacity as worker_capacity,
)


@pytest.fixture
def owner_case(signed_case, monkeypatch):  # noqa: F811
    root = signed_case.item.state_root
    lock = root / "supervisor-process.lock"
    lock.write_bytes(b"original startup bytes")
    lock.chmod(0o600)
    legacy = root / "directive-state.json"
    legacy.write_bytes(canonical_json_bytes(signed_case.installation.v3_state))
    legacy.chmod(0o600)
    unit = "umi-validator-supervisor.service"
    systemd = root.parent / "fixture-systemd"
    systemd.mkdir(mode=0o700)
    run_systemd = root.parent / "fixture-run-systemd"
    run_systemd.mkdir(mode=0o700)
    fragment = systemd / unit
    fragment.write_text("[Service]\nExecStart=native successor CLI\n")
    fragment.chmod(0o644)
    dropin = systemd / (unit + ".d") / "standing.conf"
    dropin.parent.mkdir(mode=0o700)
    dropin.write_text("[Service]\nEnvironment=NATIVE=1\n")
    dropin.chmod(0o644)
    config_path = signed_case.item.paths.config
    monkeypatch.setattr(service_selection, "SYSTEMD_ROOTS", (systemd, run_systemd))
    monkeypatch.setattr(service_selection, "_needs_daemon_reload", lambda unit: False)
    values = {
        "Id": unit,
        "LoadState": "loaded",
        "ActiveState": "inactive",
        "SubState": "dead",
        "MainPID": "0",
        "ControlPID": "0",
        "ControlGroup": "",
        "RootDirectory": "",
        "RootImage": "",
        "Slice": "system.slice",
        "User": pwd.getpwuid(os.getuid()).pw_name,
        "DropInPaths": str(dropin),
        "ExecStart": "native successor CLI --config " + str(config_path) + " ;",
        "FragmentPath": str(fragment),
        "OnFailure": "",
    }
    item = SimpleNamespace(
        anchor=signed_case.anchor,
        root=root,
        lock=lock,
        unit=unit,
        config_path=config_path,
        values=values,
        commands=[],
        running=False,
        descendant=False,
        container_present=False,
    )
    selected = _new_container(item.anchor.config)
    container_id = "ac" * 32

    async def command(arguments, **kwargs):
        item.commands.append(arguments)
        args = arguments[2:]
        if args[0] == "ps":
            assert args[1:] == ("--all", f"--filter=name=^{selected.name}$", "--format=json")
            return json.dumps([{"Id": container_id}] if item.container_present else []).encode()
        assert args == ("container", "inspect", "--format=json", container_id)
        record = {
            "Id": container_id,
            "Name": selected.name,
            "Config": {
                "Labels": {
                    "vision.umi.successor.config": selected._config_sha256,
                    "vision.umi.successor.hotkey": selected._hotkey_sha256,
                    "vision.umi.successor.profile": "competition_weights",
                    "vision.umi.successor.directive": "ab" * 32,
                    "vision.umi.successor.receipt": "cd" * 32,
                }
            },
            "State": {
                "Status": "running" if item.running else "exited",
                "ExitCode": 0,
                "Running": item.running,
                "Pid": 17 if item.running else 0,
            },
        }
        return json.dumps([record]).encode()

    def cgroup(*args):
        if item.descendant:
            raise ValueError("descendant process remains")

    monkeypatch.setattr(reconciliation, "_unit_snapshot", lambda name: dict(values))
    monkeypatch.setattr(reconciliation, "_require_empty_cgroup", cgroup)
    monkeypatch.setattr(reconciliation, "_require_empty_container_cgroup", cgroup)
    monkeypatch.setattr(containers, "_run_command", command)
    return item


async def test_real_startup_lease_remains_owned_without_service_mutations(owner_case):
    c = owner_case
    before = c.lock.read_bytes(), c.lock.stat().st_ino
    with runtime.hold_successor_startup_lease(c.anchor) as startup:
        async with reconciliation.hold_stopped_standing_writer(
            startup, unit=c.unit, config_path=c.config_path
        ) as owner:
            await owner.recheck()
            contender = os.open(c.lock, os.O_RDWR)
            try:
                with pytest.raises(BlockingIOError):
                    fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                os.close(contender)
            with pytest.raises(ValueError, match="altered"):
                await replace(owner, unit="umi-validator-supervisor-other.service").recheck()
        with pytest.raises(ValueError, match="closed"):
            await owner.recheck()
    assert before == (c.lock.read_bytes(), c.lock.stat().st_ino)
    assert c.commands and all(call[2] == "ps" for call in c.commands)


@pytest.mark.parametrize("fault", ["unit", "uid", "descendant", "container"])
async def test_stopped_writer_refuses_live_or_wrong_owner(owner_case, fault):
    c = owner_case
    if fault == "unit":
        c.values["MainPID"] = "17"
    elif fault == "uid":
        c.values["User"] = "root" if os.getuid() else "nobody"
    elif fault == "descendant":
        c.descendant = True
    else:
        c.container_present = c.running = True
    try:
        with runtime.hold_successor_startup_lease(c.anchor) as startup, pytest.raises(ValueError):
            async with reconciliation.hold_stopped_standing_writer(
                startup, unit=c.unit, config_path=c.config_path
            ):
                pytest.fail("unconfirmed owner yielded")
    finally:
        # An uncertain owner remains fenced until process exit in production.
        os.close(startup._descriptor)


async def test_container_descendants_and_changed_unit_remain_fenced(owner_case):
    c = owner_case
    c.container_present = True
    with runtime.hold_successor_startup_lease(c.anchor) as startup:
        async with reconciliation.hold_stopped_standing_writer(
            startup, unit=c.unit, config_path=c.config_path
        ) as owner:
            c.descendant = True
            with pytest.raises(ValueError, match="descendant"):
                await owner.recheck()
            c.descendant = False
            c.values["DropInPaths"] += " /etc/systemd/system/changed.conf"
            with pytest.raises(ValueError):
                await owner.recheck()
            c.values["DropInPaths"] = c.values["DropInPaths"].removesuffix(
                " /etc/systemd/system/changed.conf"
            )


async def test_uncertain_exit_keeps_original_startup_descriptor_owned(owner_case):
    c = owner_case
    with (
        pytest.raises(ValueError, match="descendant"),
        runtime.hold_successor_startup_lease(c.anchor) as startup,
    ):
        async with reconciliation.hold_stopped_standing_writer(
            startup, unit=c.unit, config_path=c.config_path
        ):
            c.descendant = True
    assert startup._state.phase == "retained"
    contender = os.open(c.lock, os.O_RDWR)
    try:
        with pytest.raises(BlockingIOError):
            fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
    finally:
        os.close(contender)
        # Production keeps this until the command exits; the test owns teardown.
        os.close(startup._descriptor)


async def test_serialized_or_fixture_startup_assertions_are_not_authority():
    with pytest.raises(ValueError):
        async with reconciliation.hold_stopped_standing_writer(
            SimpleNamespace(config={}, _descriptor=0),
            unit="umi-validator-supervisor.service",
            config_path=Path("/absent/config.json"),
        ):
            pytest.fail("untrusted lease yielded")


@pytest.mark.parametrize(
    "fault", ["config", "fragment", "writable_override", "unloaded_override", "pending_reload"]
)
async def test_initial_writer_service_selection_requires_exact_root_controls(
    owner_case, fault, monkeypatch
):
    c = owner_case
    if fault == "config":
        c.values["ExecStart"] = "native successor CLI --config /different/config.json ;"
    elif fault == "fragment":
        c.values["FragmentPath"] = str(Path(c.values["FragmentPath"]).with_name("other.service"))
    elif fault == "writable_override":
        Path(c.values["DropInPaths"]).chmod(0o666)
    elif fault == "pending_reload":
        monkeypatch.setattr(service_selection, "_needs_daemon_reload", lambda unit: True)
    else:
        pending = Path(c.values["DropInPaths"]).with_name("unloaded.conf")
        pending.write_text("[Service]\nEnvironment=UNLOADED=1\n")
        pending.chmod(0o644)
    try:
        with runtime.hold_successor_startup_lease(c.anchor) as startup, pytest.raises(ValueError):
            async with reconciliation.hold_stopped_standing_writer(
                startup, unit=c.unit, config_path=c.config_path
            ):
                pytest.fail("unrelated or mutable writer service yielded")
    finally:
        os.close(startup._descriptor)
