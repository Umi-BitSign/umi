"""Real immutable hold configurations; system-manager and process ports substituted."""

import hashlib
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


@pytest.fixture
def admission_projection(mirror_case):
    h = mirror_case
    h.source = Path(h.c.config.admission_config)
    h.config = h.config.model_copy(
        update={
            "role": "admission",
            "admission_compatibility": module.ADMISSION_PROJECTION,
        }
    )
    h.state["argv"] = [
        "/usr/bin/python3",
        "-I",
        "-m",
        module.MODULES["admission"][0],
        "serve-intake",
        "--config",
        str(h.source),
    ]
    value = json.loads(h.source.read_bytes())
    lifecycle = value["recoverable_service"]["lifecycle"]
    lifecycle["automatic_progression_hold_cohorts"] = [h.c.cohorts[1]]
    lifecycle["held_intake_sampling_cohorts"] = [h.c.cohorts[1]]
    lifecycle["request_start"]["operator_start_overrides"] = [
        {
            "schema": "umi-cohort-operator-request-start/1",
            "cohort_sha256": h.c.cohorts[1],
            "authorized_history_tip_sha256": "11" * 32,
            "suite_sha256": "22" * 32,
            "baseline_model_sha256": "33" * 32,
            "evaluation_runtime_sha256": "44" * 32,
            "runtime_adoption_sha256": None,
            "not_before_unix_ms": 1,
            "source_sha256": "55" * 32,
        }
    ]
    h.c.save(h.source, canonical_json_bytes(value))
    h.exact = h.source.read_bytes()
    h.source_copy = h.target.with_name(h.target.name + ".source.json")
    return h


def test_explicit_projection_preserves_every_reward_field_and_exact_source(admission_projection):
    h = admission_projection
    assert module.update_hold_mirror(h.config, publish=True)["status"] == "published"
    expected = json.loads(h.exact)
    lifecycle = expected["recoverable_service"]["lifecycle"]
    del lifecycle["held_intake_sampling_cohorts"]
    del lifecycle["request_start"]["operator_start_overrides"]
    assert json.loads(h.target.read_bytes()) == expected
    assert h.source.read_bytes() == h.source_copy.read_bytes() == h.exact
    receipt = json.loads(h.receipt.read_bytes())
    assert receipt["binding"]["schema"] == "umi-reward-hold-mirror-receipt/2"
    assert receipt["projection"]["source_sha256"] == hashlib.sha256(h.exact).hexdigest()
    assert (
        receipt["projection"]["output_sha256"] == hashlib.sha256(h.target.read_bytes()).hexdigest()
    )
    native = h.c.reader
    projected = RewardTransitionControlReader(
        h.c.config.model_copy(update={"admission_config": str(h.target)}),
        series=h.c.series,
        policy=h.c.policy,
    )
    assert [native.held(c) for c in h.c.cohorts] == [projected.held(c) for c in h.c.cohorts]


def test_projection_repeat_and_restart_reuse_validation(admission_projection, monkeypatch):
    h = admission_projection
    module.update_hold_mirror(h.config, publish=True)
    source_identity = h.source_copy.stat()
    read = module.root_files._read_root_control_path

    def no_original_read(path, *args, **kwargs):
        assert path != h.source
        return read(path, *args, **kwargs)

    monkeypatch.setattr(module.root_files, "_read_root_control_path", no_original_read)
    monkeypatch.setattr(module, "_validate_source", lambda *a: pytest.fail("repeat validation"))
    assert module.update_hold_mirror(h.config, publish=True)["status"] == "unchanged"
    module.update_hold_mirror(h.config, publish=False)
    h.state["ExecMainStartTimestamp"] += 1_000_000
    assert module.update_hold_mirror(h.config, publish=True)["status"] == "published"
    assert h.source_copy.stat() == source_identity
    assert (
        json.loads(h.receipt.read_bytes())["projection"]["output_sha256"]
        == hashlib.sha256(h.target.read_bytes()).hexdigest()
    )


@pytest.mark.parametrize("damaged", ["target", "source_copy", "receipt"])
def test_projection_damage_refuses_and_removes_visible_mirror(admission_projection, damaged):
    h = admission_projection
    module.update_hold_mirror(h.config, publish=True)
    path = getattr(h, damaged)
    h.c.save(path, b"{}")
    with pytest.raises(ValueError):
        module.update_hold_mirror(h.config, publish=True)
    assert not h.target.exists()


@pytest.mark.parametrize("fault", ["unknown_field", "invalid_sampling"])
def test_projection_cannot_hide_invalid_actual_source(admission_projection, fault):
    h = admission_projection
    value = json.loads(h.exact)
    lifecycle = value["recoverable_service"]["lifecycle"]
    if fault == "unknown_field":
        lifecycle["unknown_reward_authority"] = True
    else:
        lifecycle["held_intake_sampling_cohorts"] = ["ff" * 32]
    h.c.save(h.source, canonical_json_bytes(value))
    with pytest.raises(ValueError):
        module.update_hold_mirror(h.config, publish=True)
    assert not h.target.exists()


def test_projection_tracks_new_selected_hold_and_preserves_default_exact_mode(admission_projection):
    h = admission_projection
    module.update_hold_mirror(h.config, publish=True)
    value = json.loads(h.exact)
    lifecycle = value["recoverable_service"]["lifecycle"]
    lifecycle["automatic_progression_hold_cohorts"] = [h.c.cohorts[2]]
    lifecycle["held_intake_sampling_cohorts"] = [h.c.cohorts[2]]
    successor = h.source.with_name("new-scheduled-owner.json")
    h.c.save(successor, canonical_json_bytes(value))
    h.state["argv"][-1] = str(successor)
    h.state["ExecMainStartTimestamp"] += 1_000_000
    module.update_hold_mirror(h.config, publish=True)
    reader = RewardTransitionControlReader(
        h.c.config.model_copy(update={"admission_config": str(h.target)}),
        series=h.c.series,
        policy=h.c.policy,
    )
    assert not reader.held(h.c.cohorts[1]) and reader.held(h.c.cohorts[2])
    exact_config = h.config.model_copy(update={"admission_compatibility": None})
    module.update_hold_mirror(exact_config, publish=True)
    assert h.target.read_bytes() == successor.read_bytes()
    assert b"admission_compatibility" not in canonical_json_bytes(exact_config)


def test_settlement_cannot_select_admission_projection(mirror_case):
    value = mirror_case.config.model_dump(mode="json", by_alias=True)
    value["admission_compatibility"] = module.ADMISSION_PROJECTION
    with pytest.raises(ValueError, match="cannot select settlement"):
        module.RewardHoldMirrorConfig.model_validate_json(canonical_json_bytes(value))


def test_projection_selection_revalidates_existing_exact_receipt(admission_projection, monkeypatch):
    h = admission_projection
    exact = h.config.model_copy(update={"admission_compatibility": None})
    module.update_hold_mirror(exact, publish=True)
    assert json.loads(h.receipt.read_bytes())["binding"]["schema"].endswith("/1")
    validate = module._validate_source
    validations = []

    def checked(raw, role):
        validations.append((raw, role))
        validate(raw, role)

    monkeypatch.setattr(module, "_validate_source", checked)
    module.update_hold_mirror(h.config, publish=True)
    assert validations == [(h.exact, "admission")]
    assert h.target.read_bytes() != h.exact
    module.update_hold_mirror(exact, publish=True)
    assert validations == [(h.exact, "admission")] * 2
    assert h.target.read_bytes() == h.exact


@pytest.mark.parametrize("after", ["source_copy", "target", "receipt"])
@pytest.mark.parametrize("previous", [False, True])
def test_projection_interrupted_publication_recovers(
    admission_projection, monkeypatch, after, previous
):
    h = admission_projection
    if previous:
        module.update_hold_mirror(h.config, publish=True)
        value = json.loads(h.exact)
        value["recoverable_service"]["lifecycle"]["automatic_progression_hold_cohorts"] = [
            h.c.cohorts[1],
            h.c.cohorts[2],
        ]
        successor = h.source.with_name("next-owner.json")
        h.c.save(successor, canonical_json_bytes(value))
        h.state["argv"][-1] = str(successor)
        h.state["ExecMainStartTimestamp"] += 1_000_000
        h.source = successor
    write = module._write

    def interrupted(parent, name, raw):
        write(parent, name, raw)
        if name == getattr(h, after).name:
            raise InterruptedError("publication interrupted after atomic write")

    with monkeypatch.context() as interrupted_context:
        interrupted_context.setattr(module, "_write", interrupted)
        with pytest.raises(InterruptedError):
            module.update_hold_mirror(h.config, publish=True)
    assert not h.target.exists()
    assert module.update_hold_mirror(h.config, publish=True)["status"] == "published"
    assert h.source_copy.read_bytes() == h.source.read_bytes()
    reader = RewardTransitionControlReader(
        h.c.config.model_copy(update={"admission_config": str(h.target)}),
        series=h.c.series,
        policy=h.c.policy,
    )
    assert reader.held(h.c.cohorts[1])
    assert reader.held(h.c.cohorts[2]) == previous
    assert module.update_hold_mirror(h.config, publish=True)["status"] == "unchanged"


def test_projection_receipt_policy_damage_requires_repair(admission_projection):
    h = admission_projection
    module.update_hold_mirror(h.config, publish=True)
    value = json.loads(h.receipt.read_bytes())
    value["binding"]["projection_policy"] = "other-policy/1"
    h.c.save(h.receipt, canonical_json_bytes(value))
    with pytest.raises(ValueError, match="receipt requires repair"):
        module.update_hold_mirror(h.config, publish=True)
    assert not h.target.exists()


@pytest.mark.parametrize("legacy_source", os.environ.get("UMI_LEGACY_HOLD_SOURCES", "").split(":"))
def test_actual_selected_legacy_parser_and_control_parity(admission_projection, legacy_source):
    if not legacy_source:
        pytest.skip("actual installed source compatibility is an operator qualification")
    h = admission_projection
    module.update_hold_mirror(h.config, publish=True)
    script = """
import json,os,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from umi import competition_host_activation as files
from umi.competition_service import CompetitionServiceConfig
from umi.competition_cohort_settlement_config import SettlementServiceConfig
from umi.competition_reward_transition_controls import (
    RewardTransitionControlReader, RewardTransitionControls,
)
files._root_owner_uid=os.getuid
original,projected,settlement,approvals=map(Path,sys.argv[2:])
try: CompetitionServiceConfig.model_validate_json(original.read_bytes())
except ValueError: rejected=True
else: rejected=False
view=CompetitionServiceConfig.model_validate_json(projected.read_bytes())
final=SettlementServiceConfig.model_validate_json(settlement.read_bytes())
reader=RewardTransitionControlReader(
    RewardTransitionControls(
        admission_config=str(projected), settlement_config=str(settlement),
        operator_approval_directory=str(approvals),
    ), series=view.recoverable_service.series, policy=final.policy,
)
print(json.dumps({
    'full_new_source_rejected':rejected,
    'holds':[reader.held(v.cohort_sha256) for v in view.recoverable_intake.cohorts],
}))
"""
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-B",
            "-c",
            script,
            legacy_source,
            str(h.source),
            str(h.target),
            h.c.config.settlement_config,
            h.c.config.operator_approval_directory,
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=45,
    )
    value = json.loads(result.stdout)
    assert value["full_new_source_rejected"]
    assert value["holds"] == [
        h.c.reader.held(v.cohort_sha256) for v in h.c.admission.recoverable_intake.cohorts
    ]
