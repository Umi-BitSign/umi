"""Real immutable hold configurations; system-manager and process ports substituted."""

import json
import os
import pwd
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from umi import competition_reward_hold_mirror as module
from umi import competition_reward_hold_mirror_cli as cli
from umi.competition_reward_transition_controls import RewardTransitionControlReader
from umi.protocol import canonical_json_bytes

from .test_competition_reward_transition_controls import chain as chain
from .test_competition_reward_transition_controls import chain_config as chain_config
from .test_competition_reward_transition_controls import control as control
from .test_competition_reward_transition_controls import controls_case as controls_case
from .test_competition_reward_transition_controls import inputs as inputs
from .test_competition_reward_transition_controls import policy as policy
from .test_competition_reward_transition_controls import public_deployment as public_deployment
from .test_competition_reward_transition_controls import selected as selected
from .test_competition_reward_transition_controls import series_case as series_case


@pytest.fixture
def mirror_case(controls_case, tmp_path, monkeypatch):
    c = controls_case
    role = "settlement"
    source = Path(c.config.settlement_config)
    target = tmp_path / "mirrors" / "settlement.json"
    target.parent.mkdir(mode=0o755)
    config = module.RewardHoldMirrorConfig(
        schema="umi-reward-hold-mirror/1",
        unit="umi-settlement.service",
        role=role,
        service_user=pwd.getpwuid(os.getuid()).pw_name,
        target=str(target),
    )
    state = {
        "Id": config.unit,
        "LoadState": "loaded",
        "ActiveState": "active",
        "SubState": "running",
        "MainPID": 12345,
        "User": config.service_user,
        "ControlGroup": "/system.slice/umi-settlement.service",
        "ExecMainStartTimestamp": time.time_ns() // 1000 + 1_000_000,
        "argv": [
            "/usr/bin/python3",
            "-I",
            "-m",
            module.MODULES[role][0],
            "run",
            "--config",
            str(source),
        ],
    }
    state_calls, process_calls = [], []

    def selected_owner(_):
        state_calls.append(1)
        return dict(state, argv=list(state["argv"]))

    def selected_process(selected):
        process_calls.append(1)
        assert selected["MainPID"] == 12345
        return ["12345", "1000", "1", "2"]

    real_selection = module.selected_service
    monkeypatch.setattr(module, "selected_service", selected_owner)
    monkeypatch.setattr(module, "process_identity", selected_process)
    return SimpleNamespace(
        c=c,
        config=config,
        source=source,
        target=target,
        state=state,
        receipt=target.with_name(target.name + ".receipt.json"),
        state_calls=state_calls,
        process_calls=process_calls,
        real_selection=real_selection,
    )


def test_published_mirror_reuses_verified_source_without_payload_read(mirror_case, monkeypatch):
    h = mirror_case
    assert module.update_hold_mirror(h.config, publish=True)["status"] == "published"
    original = h.target.read_bytes()
    assert original == h.source.read_bytes()
    identity = h.target.stat()
    read = module.root_files._read_root_control_path

    def no_source_read(path, *args, **kwargs):
        assert path != h.source, "unchanged source payload was read twice"
        return read(path, *args, **kwargs)

    monkeypatch.setattr(module.root_files, "_read_root_control_path", no_source_read)
    assert module.update_hold_mirror(h.config, publish=True)["status"] == "unchanged"
    assert h.target.stat() == identity
    assert h.target.read_bytes() == original


def test_lifecycle_invalidates_old_unheld_mirror_then_tracks_new_hold(mirror_case):
    h = mirror_case
    module.update_hold_mirror(h.config, publish=True)
    controls = h.c.config.model_copy(update={"settlement_config": str(h.target)})
    reader = RewardTransitionControlReader(controls, series=h.c.series, policy=h.c.policy)
    assert not reader.held(h.c.cohorts[1])
    for _ in range(2):
        assert module.update_hold_mirror(h.config, publish=False)["status"] == "invalidated"
    with pytest.raises(FileNotFoundError):
        reader.held(h.c.cohorts[1])
    assert not h.target.exists() and h.receipt.exists()

    successor = h.source.with_name("held-successor.json")
    held = h.c.settlement.model_copy(
        update={"automatic_progression_hold_cohorts": (h.c.cohorts[1],)}
    )
    h.c.save(successor, canonical_json_bytes(held))
    h.state["argv"][-1] = str(successor)
    h.state["ExecMainStartTimestamp"] += 1_000_000
    assert module.update_hold_mirror(h.config, publish=True)["status"] == "published"
    assert reader.held(h.c.cohorts[1])


def test_restart_reuses_source_validation_and_restores_only_mirror(mirror_case, monkeypatch):
    h = mirror_case
    module.update_hold_mirror(h.config, publish=True)
    module.update_hold_mirror(h.config, publish=False)
    h.state["ExecMainStartTimestamp"] += 1_000_000

    def repeated_validation(*args):
        raise AssertionError("restart repeated unchanged source validation")

    monkeypatch.setattr(module, "_validate_source", repeated_validation)
    assert module.update_hold_mirror(h.config, publish=True)["status"] == "published"
    assert h.target.read_bytes() == h.source.read_bytes()


def test_stop_hook_removes_bounded_interrupted_write_scratch(mirror_case):
    h = mirror_case
    pending = [
        h.target.with_name(h.target.name + ".pending"),
        h.receipt.with_name(h.receipt.name + ".pending"),
    ]
    for path in pending:
        path.write_bytes(b"interrupted")
        path.chmod(0o600)
    module.update_hold_mirror(h.config, publish=False)
    assert all(not path.exists() for path in pending)


def test_admission_mirror_supports_installed_global_policy_argument(mirror_case):
    h = mirror_case
    config = h.config.model_copy(update={"role": "admission"})
    h.state["argv"] = [
        "/usr/bin/python3",
        "-m",
        module.MODULES["admission"][0],
        "--policy",
        "/etc/umi/selected-policy.json",
        "serve-intake",
        "--config",
        h.c.config.admission_config,
    ]
    assert module.update_hold_mirror(config, publish=True)["status"] == "published"
    controls = h.c.config.model_copy(update={"admission_config": str(h.target)})
    reader = RewardTransitionControlReader(controls, series=h.c.series, policy=h.c.policy)
    assert not reader.held(h.c.cohorts[1])


@pytest.mark.parametrize("when", ["before_read", "after_process_check"])
def test_changed_root_config_cannot_publish_and_removes_old_view(mirror_case, monkeypatch, when):
    h = mirror_case
    module.update_hold_mirror(h.config, publish=True)
    changed = h.c.settlement.model_copy(
        update={"automatic_progression_hold_cohorts": (h.c.cohorts[1],)}
    )
    if when == "before_read":
        h.state["ExecMainStartTimestamp"] = time.time_ns() // 1000 - 1_000_000
        h.c.save(h.source, canonical_json_bytes(changed))
    else:
        original = module.process_identity
        calls = 0

        def replace_after_check(state):
            nonlocal calls
            result = original(state)
            calls += 1
            if calls == 2:
                h.c.save(h.source, canonical_json_bytes(changed))
            return result

        monkeypatch.setattr(module, "process_identity", replace_after_check)
    with pytest.raises(ValueError, match="changed"):
        module.update_hold_mirror(h.config, publish=True)
    assert not h.target.exists() and not h.receipt.exists()


@pytest.mark.parametrize("change", ["pid", "command", "process", "inactive"])
def test_selection_races_fail_closed(mirror_case, monkeypatch, change):
    h = mirror_case
    module.update_hold_mirror(h.config, publish=True)
    selected_owner, selected_process = module.selected_service, module.process_identity
    calls = 0

    def changed_owner(config):
        nonlocal calls
        calls += 1
        result = selected_owner(config)
        if calls == 2:
            if change == "pid":
                result["MainPID"] += 1
            elif change == "command":
                result["argv"][-1] = "/unselected.json"
            elif change == "inactive":
                raise ValueError("owner stopped")
        return result

    def changed_process(state):
        result = selected_process(state)
        return result if calls != 2 or change != "process" else ["reused-pid"]

    monkeypatch.setattr(module, "selected_service", changed_owner)
    monkeypatch.setattr(module, "process_identity", changed_process)
    with pytest.raises(ValueError):
        module.update_hold_mirror(h.config, publish=True)
    assert not h.target.exists() and not h.receipt.exists()


@pytest.mark.parametrize("role", ["admission", "settlement"])
@pytest.mark.parametrize("layout", ["module", "assigned", "runpy", "console"])
def test_supported_native_commands_select_exact_config(role, layout):
    module_name, command, verb = module.MODULES[role]
    path = "/etc/umi/selected.json"
    args = [verb, "--config", path]
    if layout == "module":
        argv = ["/usr/bin/python3", "-I", "-m", module_name, *args]
    elif layout == "console":
        argv = ["/opt/umi/bin/" + command, *args]
    else:
        assignment = "sys.argv=" + repr([module_name, *args]) + ";" if layout == "assigned" else ""
        code = (
            "import runpy,sys;"
            + assignment
            + f"runpy.run_module('{module_name}',run_name='__main__')"
        )
        argv = ["/usr/bin/python3", "-I", "-B", "-c", code]
        if layout == "runpy":
            argv += args
    assert module.selected_config(argv, role) == Path(path)


@pytest.mark.parametrize("change", ["module", "duplicate_config", "relative", "computed"])
def test_unsupported_or_ambiguous_commands_refused(change):
    argv = [
        "/usr/bin/python3",
        "-m",
        module.MODULES["settlement"][0],
        "run",
        "--config",
        "/etc/umi/selected.json",
    ]
    if change == "module":
        argv[2] = "unselected.module"
    elif change == "duplicate_config":
        argv += ["--config", "/elsewhere.json"]
    elif change == "relative":
        argv[-1] = "relative.json"
    else:
        argv = ["/usr/bin/python3", "-c", "import runpy;runpy.run_module(get_module())"]
    with pytest.raises(ValueError):
        module.selected_config(argv, "settlement")


def test_structured_manager_command_is_authoritative(mirror_case, monkeypatch):
    h = mirror_case
    # Restore this function; only D-Bus itself remains substituted.
    replies = [
        [["/org/freedesktop/systemd1/unit/selected"]],
        [h.config.unit, "loaded", "activating", "start-post"],
        [
            12345,
            h.config.service_user,
            [[h.state["argv"][0], h.state["argv"], False, 0, 0, 0, 0, 0, 0, 0]],
            h.state["ControlGroup"],
            h.state["ExecMainStartTimestamp"],
        ],
    ]
    monkeypatch.setattr(module, "_bus", lambda *args: replies.pop(0))
    actual = h.real_selection(h.config)
    assert actual["argv"] == h.state["argv"]
    assert actual["SubState"] == "start-post"


def test_real_process_requires_matching_command_and_cgroup():
    argv = [sys.executable, "-c", "import time;time.sleep(60)"]
    process = subprocess.Popen(argv)
    try:
        group = next(
            line[3:]
            for line in Path("/proc/self/cgroup").read_text().splitlines()
            if line.startswith("0::")
        )
        state = {
            "MainPID": process.pid,
            "User": pwd.getpwuid(os.getuid()).pw_name,
            "ControlGroup": group,
            "argv": argv,
        }
        assert module.process_identity(state)[0] == str(process.pid)
        with pytest.raises(ValueError, match="system manager command"):
            module.process_identity(dict(state, argv=["/not-selected"]))
        with pytest.raises(ValueError, match="cgroup"):
            module.process_identity(dict(state, ControlGroup="/not-selected"))
    finally:
        process.terminate()
        process.wait(timeout=5)


def test_drop_in_and_cli_render_only_explicit_owner_hooks(mirror_case, tmp_path, capsys):
    h = mirror_case
    path = tmp_path / "mirror-owner.json"
    h.c.save(path, canonical_json_bytes(h.config))
    source = tmp_path / "installed-src"
    source.mkdir(mode=0o755)
    cli.main(
        [
            "drop-in",
            "--config",
            str(path),
            "--python",
            "/usr/bin/python3",
            "--source-directory",
            str(source),
        ]
    )
    text = capsys.readouterr().out
    assert text.count("ExecStartPre=+") == text.count("ExecStartPost=+") == 1
    assert text.count("ExecStopPost=+") == 1
    assert text.count(" invalidate --config ") == 2
    assert "runpy.run_module('umi.competition_reward_hold_mirror_cli'" in text
    assert str(source) in text and "daemon-reload" not in text and "restart" not in text
    assert not h.target.exists()
    cli.main(["invalidate", "--config", str(path)])
    assert json.loads(capsys.readouterr().out)["status"] == "invalidated"


@pytest.mark.parametrize("damage", ["writable", "hardlink", "symlink"])
def test_unsafe_source_removes_old_view(mirror_case, damage):
    h = mirror_case
    module.update_hold_mirror(h.config, publish=True)
    if damage == "writable":
        h.source.chmod(0o644)
    elif damage == "hardlink":
        os.link(h.source, h.source.with_name("hardlink.json"))
    else:
        replacement = h.source.with_name("relocated.json")
        h.source.rename(replacement)
        h.source.symlink_to(replacement)
    with pytest.raises(ValueError):
        module.update_hold_mirror(h.config, publish=True)
    assert not h.target.exists()
