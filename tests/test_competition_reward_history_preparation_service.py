"""Exact stopped root service selection; systemd and cgroup ports are explicit."""

from pathlib import Path

import pytest

from umi import competition_reward_history_preparation_service as service


@pytest.fixture
def stopped(monkeypatch):
    unit = "umi-isolated-preparation.service"
    python = "/opt/native/.venv/bin/python"
    argv = (
        python + " -B -m umi.competition_reward_history_preparation_cli replay"
        " --unit umi-validator@54.service --config /etc/umi/validator-supervisor.json"
        " --standing-boot /etc/umi/boot.json --approval /var/lib/preparation/approval.json"
        " --launch /var/lib/preparation/launch.json"
    )
    values = {
        "Id": unit,
        "LoadState": "loaded",
        "ActiveState": "failed",
        "SubState": "failed",
        "MainPID": "0",
        "ControlPID": "0",
        "ControlGroup": "",
        "User": "root",
        "FragmentPath": "/etc/systemd/system/" + unit,
        "DropInPaths": "",
        "RootDirectory": "",
        "RootImage": "",
        "Slice": "system.slice",
        "ExecStart": "{ path=" + python + " ; argv[]=" + argv + " ; ignore_errors=no"
        " ; start_time=[] ; stop_time=[] ; pid=0 ; code=(null) ; status=0/SUCCESS }",
    }
    monkeypatch.setattr(service, "_snapshot", lambda unit: values)
    monkeypatch.setattr(service, "_needs_daemon_reload", lambda unit: False)
    monkeypatch.setattr(service, "_control", lambda *a: (b"sealed", ("sealed",)))
    groups = []
    monkeypatch.setattr(service, "_require_empty_cgroup_path", lambda *a: groups.append(a))
    args = dict(
        installed_unit="umi-validator@54.service",
        config_path=Path("/etc/umi/validator-supervisor.json"),
        python_path=Path(python),
        choices=[
            (
                Path("/etc/umi/boot.json"),
                Path("/var/lib/preparation/approval.json"),
                Path("/var/lib/preparation/launch.json"),
            )
        ],
    )
    return unit, values, args, groups


def test_exact_preparation_service_stopped_outside_original_writer_cgroup(stopped):
    unit, values, args, groups = stopped
    first = service.stopped_preparation_service(unit, **args)
    assert groups == [("/system.slice/" + unit, "")]
    values.update(ActiveState="inactive", SubState="dead")
    assert service.stopped_preparation_service(unit, **args) == first


@pytest.mark.parametrize(
    "field,value",
    [
        ("ActiveState", "active"),
        ("SubState", "running"),
        ("MainPID", "999"),
        ("ControlPID", "999"),
        ("User", "miner"),
        ("RootDirectory", "/alternate"),
        ("Slice", "other.slice"),
        ("FragmentPath", "/tmp/other.service"),
        ("ExecStart", "{ malformed }"),
    ],
)
def test_running_or_unsupported_service_never_authorizes_migration(stopped, field, value):
    unit, values, args, _ = stopped
    values[field] = value
    with pytest.raises(ValueError):
        service.stopped_preparation_service(unit, **args)


@pytest.mark.parametrize(
    "argument", ["--standing-boot", "--approval", "--launch", "--config", "--unit"]
)
def test_unrelated_stopped_unit_is_not_preparation_absence_proof(stopped, argument):
    unit, values, args, _ = stopped
    values["ExecStart"] = values["ExecStart"].replace(argument + " ", argument + " /wrong ")
    with pytest.raises(ValueError, match="scope"):
        service.stopped_preparation_service(unit, **args)


def test_pending_reload_or_surviving_child_blocks(stopped, monkeypatch):
    unit, _, args, _ = stopped
    monkeypatch.setattr(service, "_needs_daemon_reload", lambda unit: True)
    with pytest.raises(ValueError):
        service.stopped_preparation_service(unit, **args)
    monkeypatch.setattr(service, "_needs_daemon_reload", lambda unit: False)

    def occupied(*args):
        raise ValueError("surviving child")

    monkeypatch.setattr(service, "_require_empty_cgroup_path", occupied)
    with pytest.raises(ValueError, match="surviving child"):
        service.stopped_preparation_service(unit, **args)
