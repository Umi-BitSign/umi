from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from .test_miner_upgrade import SCRIPT, _manifest, _status, upgrade


@pytest.mark.parametrize("tracks", [["endpoint", "model"], ["model"]])
@pytest.mark.parametrize("platform", ["linux", "darwin"])
def test_standalone_client_never_discovers_or_upgrades_endpoint(
    tmp_path, monkeypatch, capsys, tracks, platform
):
    manifest = _manifest()
    manifest["eligible_tracks"] = tracks
    manifest["public_model_track_required"] = tracks == ["model"]
    responses = iter((upgrade.canonical(manifest), upgrade.canonical(_status(manifest))))
    monkeypatch.setattr(upgrade, "fetch", lambda *_: next(responses))
    monkeypatch.setattr(upgrade.sys, "platform", platform)
    monkeypatch.setattr(
        upgrade, "discover_miner", lambda: pytest.fail("standalone client inspected an endpoint")
    )
    calls = []
    monkeypatch.setattr(
        upgrade,
        "install_model_client",
        lambda selected, directory: calls.append((selected, directory)) or {"status": "installed"},
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [str(SCRIPT), "--install-model-client", "--model-client-directory", str(tmp_path)],
    )
    upgrade.main()
    assert json.loads(capsys.readouterr().out)["status"] == "installed"
    assert calls == [(manifest, tmp_path)]


def test_model_client_reexecs_supported_homebrew_python_before_manifest(monkeypatch):
    examined = []
    monkeypatch.setattr(upgrade.shutil, "which", lambda name: name)

    def probe(arguments, **kwargs):
        examined.append((arguments[0], kwargs["timeout"]))
        return subprocess.CompletedProcess(arguments, 0 if "3.12" in arguments[0] else 1)

    monkeypatch.setattr(upgrade.subprocess, "run", probe)

    class Reexecuted(Exception):
        pass

    def reexec(path, arguments):
        assert path == "/opt/homebrew/bin/python3.12"
        assert arguments[:3] == [path, "-I", "-B"]
        raise Reexecuted

    monkeypatch.setattr(upgrade.os, "execv", reexec)
    with pytest.raises(Reexecuted):
        upgrade.ensure_model_client_python(
            running_version=(3, 9),
            candidate_paths=("/usr/bin/python3", "/opt/homebrew/bin/python3.12"),
        )
    assert examined == [("/usr/bin/python3", 5), ("/opt/homebrew/bin/python3.12", 5)]


def test_model_client_supported_python_skips_discovery(monkeypatch):
    monkeypatch.setattr(
        upgrade.shutil, "which", lambda *_: pytest.fail("supported Python was probed")
    )
    upgrade.ensure_model_client_python(running_version=(3, 12))


def test_model_client_without_supported_interpreter_gives_actionable_error(monkeypatch):
    monkeypatch.setattr(upgrade.shutil, "which", lambda *_: None)
    with pytest.raises(ValueError, match="UMI_MODEL_CLIENT_PYTHON"):
        upgrade.ensure_model_client_python(running_version=(3, 9), candidate_paths=("python3.12",))


def test_model_client_python_handoff_precedes_manifest_read(monkeypatch):
    class Reexecuted(Exception):
        pass

    def handoff():
        raise Reexecuted

    monkeypatch.setattr(upgrade, "ensure_model_client_python", handoff)
    monkeypatch.setattr(upgrade, "fetch", lambda *_: pytest.fail("manifest fetched twice"))
    monkeypatch.setattr(sys, "argv", [str(SCRIPT), "--install-model-client"])
    with pytest.raises(Reexecuted):
        upgrade._main()


def test_client_dry_run_leaves_files_and_services_untouched(tmp_path, monkeypatch, capsys):
    manifest = _manifest()
    responses = iter((upgrade.canonical(manifest), upgrade.canonical(_status(manifest))))
    monkeypatch.setattr(upgrade, "fetch", lambda *_: next(responses))
    monkeypatch.setattr(
        upgrade, "install_model_client", lambda *_: pytest.fail("dry run installed")
    )
    monkeypatch.setattr(upgrade, "discover_miner", lambda: pytest.fail("dry run inspected service"))
    monkeypatch.setattr(
        sys,
        "argv",
        [
            str(SCRIPT),
            "--install-model-client",
            "--dry-run",
            "--model-client-directory",
            str(tmp_path / "client"),
        ],
    )
    upgrade.main()
    report = json.loads(capsys.readouterr().out)
    assert report["endpoint_service_unchanged"]
    assert report["installer_python"] == sys.executable
    assert report["installer_python_version"]
    assert not (tmp_path / "client").exists()


def test_client_refuses_a_mismatching_published_profile_before_install(monkeypatch):
    manifest = _manifest()
    status = _status(manifest)
    status["deployment"]["eligible_tracks"] = ["endpoint"]
    responses = iter((upgrade.canonical(manifest), upgrade.canonical(status)))
    monkeypatch.setattr(upgrade, "fetch", lambda *_: next(responses))
    monkeypatch.setattr(
        upgrade, "install_model_client", lambda *_: pytest.fail("bad profile installed")
    )
    monkeypatch.setattr(sys, "argv", [str(SCRIPT), "--install-model-client"])
    with pytest.raises(ValueError, match="public status differs"):
        upgrade.main()


def test_client_subprocess_ignores_endpoint_python_and_installer_environment(monkeypatch):
    for key in (
        "PYTHONPATH",
        "PYTHONHOME",
        "VIRTUAL_ENV",
        "UV_PROJECT_ENVIRONMENT",
        "PIP_EXTRA_INDEX_URL",
        "GIT_CONFIG_COUNT",
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
    ):
        monkeypatch.setenv(key, "/existing-endpoint")
    observed = []
    monkeypatch.setattr(
        upgrade.subprocess,
        "run",
        lambda *a, **kw: observed.append(kw["env"]) or subprocess.CompletedProcess(a, 0, "", ""),
    )
    upgrade.model_client_run("true")
    assert not set(observed[0]) & {
        "PYTHONPATH",
        "PYTHONHOME",
        "VIRTUAL_ENV",
        "UV_PROJECT_ENVIRONMENT",
        "PIP_EXTRA_INDEX_URL",
        "GIT_CONFIG_COUNT",
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
    }


@pytest.mark.parametrize("layout", ["legacy_checkout", "manual_state", "endpoint_runtime"])
def test_client_refuses_reusing_an_existing_endpoint_directory(tmp_path, monkeypatch, layout):
    monkeypatch.setattr(upgrade.os, "geteuid", lambda: 1000)
    sentinel = tmp_path / layout
    sentinel.write_bytes(b"original bound state")
    with pytest.raises(ValueError, match="unrelated"):
        upgrade.install_model_client(_manifest(), tmp_path)
    assert sentinel.read_bytes() == b"original bound state"
    assert list(tmp_path.iterdir()) == [sentinel]


def test_inherited_git_locations_cannot_redirect_writes_to_another_checkout(tmp_path, monkeypatch):
    intended, unrelated = tmp_path / "client-source", tmp_path / "endpoint-checkout"
    for repository in (intended, unrelated):
        subprocess.run(["git", "init", "--quiet", str(repository)], check=True)
    (intended / "payload").write_bytes(b"selected source")
    (unrelated / "retained").write_bytes(b"unrelated endpoint source")
    monkeypatch.setenv("GIT_DIR", str(unrelated / ".git"))
    monkeypatch.setenv("GIT_WORK_TREE", str(unrelated))
    monkeypatch.setenv("GIT_INDEX_FILE", str(unrelated / ".git/index"))
    monkeypatch.setenv("GIT_OBJECT_DIRECTORY", str(unrelated / ".git/objects"))
    upgrade.model_client_run("git", "-C", str(intended), "add", "--", "payload")
    assert upgrade.model_client_run("git", "-C", str(intended), "ls-files").stdout == "payload\n"
    assert not (unrelated / ".git/index").exists()
    assert (unrelated / "retained").read_bytes() == b"unrelated endpoint source"


def _installer_stub(monkeypatch, revision):
    calls = []

    def run(*arguments):
        calls.append(arguments)
        stdout = ""
        if arguments[:2] == ("git", "clone"):
            Path(arguments[-1]).mkdir(mode=0o700, exist_ok=True)
        elif arguments[0] == "git" and arguments[3:] == ("rev-parse", "HEAD"):
            stdout = revision[0]
        elif "venv" in arguments:
            Path(arguments[-1]).mkdir(mode=0o700, exist_ok=True)
        elif "-c" in arguments:
            stdout = json.dumps(
                {
                    "module": "installed/umi",
                    "python": "3.12.14",
                    "source_files": 1,
                    "lock_sha256": "00" * 32,
                }
            )
        return subprocess.CompletedProcess(arguments, 0, stdout, "")

    monkeypatch.setattr(upgrade, "model_client_run", run)
    monkeypatch.setattr(upgrade.os, "geteuid", lambda: 1000)
    return calls


def test_repeat_install_checks_existing_runtime_and_new_revision_selects_beside_it(
    tmp_path, monkeypatch
):
    manifest = _manifest()
    revision = [manifest["runtime"]["revision"]]
    calls = _installer_stub(monkeypatch, revision)
    root = tmp_path / "client"
    first = upgrade.install_model_client(manifest, root)
    selected = (root / "umi-model-client").resolve()
    old_command = selected.read_bytes()
    old_receipt = selected.with_name("installation.json").read_bytes()
    calls.clear()
    assert upgrade.install_model_client(manifest, root) == first
    assert (root / "umi-model-client").resolve() == selected
    assert any("sync" in call and "--check" in call for call in calls)
    assert not any(call[:2] == ("git", "clone") for call in calls)
    revision[0] = manifest["runtime"]["revision"] = "ab" * 20
    upgrade.install_model_client(manifest, root)
    assert (root / "umi-model-client").resolve() != selected
    assert selected.read_bytes() == old_command
    assert selected.with_name("installation.json").read_bytes() == old_receipt


@pytest.mark.parametrize("failure", ["sync", "verification", "help"])
def test_failed_client_install_keeps_selected_previous_command(tmp_path, monkeypatch, failure):
    manifest = _manifest()
    revision = [manifest["runtime"]["revision"]]
    _installer_stub(monkeypatch, revision)
    root = tmp_path / "client"
    upgrade.install_model_client(manifest, root)
    selected = os.readlink(root / "umi-model-client")
    original_run = upgrade.model_client_run
    revision[0] = manifest["runtime"]["revision"] = "ab" * 20

    def run(*arguments):
        if (
            (failure == "sync" and "sync" in arguments)
            or (failure == "verification" and "-c" in arguments)
            or (failure == "help" and "submit-cohort-model" in arguments)
        ):
            raise RuntimeError("qualified failure")
        return original_run(*arguments)

    monkeypatch.setattr(upgrade, "model_client_run", run)
    with pytest.raises(RuntimeError, match="qualified failure"):
        upgrade.install_model_client(manifest, root)
    assert os.readlink(root / "umi-model-client") == selected


def test_client_wrapper_uses_absolute_isolated_interpreter_with_spaces(tmp_path, monkeypatch):
    manifest = _manifest()
    _installer_stub(monkeypatch, [manifest["runtime"]["revision"]])
    report = upgrade.install_model_client(manifest, tmp_path / "client with spaces")
    python = Path(report["runtime_python"])
    python.parent.mkdir(parents=True)
    python.write_text('#!/bin/sh\nprintf "%s\\n" "$@"\n')
    python.chmod(0o700)
    observed = subprocess.check_output(
        [report["command"], "--policy", "policy with spaces"], text=True
    )
    assert observed.splitlines() == [
        "-I",
        "-B",
        "-m",
        "umi.competition_cli",
        "--policy",
        "policy with spaces",
    ]


def test_interrupted_source_download_retries_without_touching_prior_client(tmp_path, monkeypatch):
    manifest = _manifest()
    revision = [manifest["runtime"]["revision"]]
    calls = _installer_stub(monkeypatch, revision)
    root = tmp_path / "client"
    upgrade.install_model_client(manifest, root)
    selected = (root / "umi-model-client").resolve()
    original_run = upgrade.model_client_run
    revision[0] = manifest["runtime"]["revision"] = "ab" * 20

    def interrupted(*arguments):
        if arguments[:2] == ("git", "clone"):
            (Path(arguments[-1]) / "partial").write_bytes(b"incomplete source")
            raise RuntimeError("download interrupted")
        return original_run(*arguments)

    monkeypatch.setattr(upgrade, "model_client_run", interrupted)
    with pytest.raises(RuntimeError, match="interrupted"):
        upgrade.install_model_client(manifest, root)
    assert (root / "umi-model-client").resolve() == selected
    assert len(list(root.glob("releases/*/source.pending/partial"))) == 1
    monkeypatch.setattr(upgrade, "model_client_run", original_run)
    upgrade.install_model_client(manifest, root)
    assert (root / "umi-model-client").resolve() != selected
    assert selected.exists()
    assert not list(root.glob("releases/*/source.pending"))
    assert sum(call[:2] == ("git", "clone") for call in calls) == 2


def test_repeat_command_write_failure_preserves_selected_wrapper(tmp_path, monkeypatch):
    manifest = _manifest()
    _installer_stub(monkeypatch, [manifest["runtime"]["revision"]])
    root = tmp_path / "client"
    upgrade.install_model_client(manifest, root)
    command = (root / "umi-model-client").resolve()
    original = command.read_bytes()
    replace = os.replace

    def fail_command(source, target):
        if target == command:
            raise OSError("promotion failed")
        replace(source, target)

    monkeypatch.setattr(upgrade.os, "replace", fail_command)
    with pytest.raises(OSError, match="promotion failed"):
        upgrade.install_model_client(manifest, root)
    assert (root / "umi-model-client").resolve() == command
    assert command.read_bytes() == original
    assert not command.with_name(command.name + ".pending").exists()


def test_root_operator_keeps_its_owned_client_directory_and_never_discovers_endpoint(
    tmp_path, monkeypatch
):
    manifest = _manifest()
    _installer_stub(monkeypatch, [manifest["runtime"]["revision"]])
    monkeypatch.setattr(upgrade.os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        upgrade, "discover_miner", lambda: pytest.fail("root client inspected endpoint")
    )
    root = tmp_path / "root-account-client"
    report = upgrade.install_model_client(manifest, root)
    assert report["endpoint_service_unchanged"] is True
    assert (root / "umi-model-client").is_symlink()
    assert root.stat().st_uid == os.getuid()
