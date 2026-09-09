from __future__ import annotations

import ast
import hashlib
import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
HOLD_SCRIPT = REPOSITORY_ROOT / "tools" / "legacy_validator_hold.py"
HOLD_GUIDE = REPOSITORY_ROOT / "docs" / "LEGACY_VALIDATOR_TRANSITION.md"
HOTKEY = "5CaRQtMKLXd35MA7E6igoUbKTe5wyrmTp6RkDzZKaTewofRM"
REVISION = subprocess.check_output(
    ["git", "rev-parse", "HEAD"], cwd=REPOSITORY_ROOT, text=True
).strip()


def _source_hash() -> str:
    return hashlib.sha256(HOLD_SCRIPT.read_bytes()).hexdigest()


def _identity_arguments(state_dir: Path) -> list[str]:
    return [
        "--uid",
        "247",
        "--hotkey",
        HOTKEY,
        "--umi-revision",
        REVISION,
        "--expected-source-sha256",
        _source_hash(),
        "--repository-root",
        str(REPOSITORY_ROOT),
        "--state-dir",
        str(state_dir),
    ]


def _command(command: str, state_dir: Path) -> list[str]:
    return [sys.executable, str(HOLD_SCRIPT), command, *_identity_arguments(state_dir)]


def test_hold_source_has_no_network_wallet_chain_or_process_control_imports() -> None:
    source = HOLD_SCRIPT.read_text()
    tree = ast.parse(source)
    imported_roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_roots.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported_roots.add(node.module.split(".", 1)[0])

    assert not imported_roots.intersection(
        {"bittensor", "http", "httpx", "requests", "socket", "subprocess", "urllib"}
    )
    assert "shell=True" not in source
    assert "os.system" not in source
    assert "Popen" not in source


def test_operator_guide_pins_current_hold_source() -> None:
    guide = HOLD_GUIDE.read_text()
    assert guide.count(_source_hash()) == 4
    assert "python3 -I -S -c 'import hashlib,pathlib,sys" in guide


def test_run_receipt_singleton_and_clean_stop(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    secret = "seed-phrase-canary-do-not-print"
    environment = {**os.environ, "BT_WALLET_PASSWORD": secret}
    process = subprocess.Popen(
        _command("run", state_dir),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=environment,
    )
    try:
        assert process.stdout is not None
        marker = json.loads(process.stdout.readline())
        assert marker["status"] == "hold_process_running"
        assert marker["hotkey"] == HOTKEY

        receipt_result = subprocess.run(
            _command("receipt", state_dir),
            check=True,
            capture_output=True,
            text=True,
            env=environment,
        )
        receipt = json.loads(receipt_result.stdout)
        assert receipt["schema"] == "umi-legacy-validator-hold-receipt/1"
        assert receipt["status"] == "hold_lock_observed"
        assert receipt["scope"] == "local_process_observation_only"

        duplicate = subprocess.run(
            _command("run", state_dir), capture_output=True, text=True, env=environment
        )
        assert duplicate.returncode == 1
        assert duplicate.stderr == "error: hold_already_running\n"

        public_and_private_output = (
            json.dumps(marker)
            + receipt_result.stdout
            + receipt_result.stderr
            + (state_dir / "hold-state.json").read_text()
        )
        assert secret not in public_and_private_output
    finally:
        process.terminate()
        stdout, stderr = process.communicate(timeout=5)
        assert secret not in stdout + stderr

    stopped_marker = json.loads((state_dir / "hold-state.json").read_text())
    assert stopped_marker["status"] == "hold_process_stopped"
    stopped_receipt = subprocess.run(_command("receipt", state_dir), capture_output=True, text=True)
    assert stopped_receipt.returncode == 1
    assert stopped_receipt.stderr == "error: hold_not_running\n"


def test_wrong_source_hash_and_unknown_arguments_fail_without_echoing_values(
    tmp_path: Path,
) -> None:
    arguments = _command("receipt", tmp_path / "state")
    hash_index = arguments.index("--expected-source-sha256") + 1
    arguments[hash_index] = "0" * 64
    mismatch = subprocess.run(arguments, capture_output=True, text=True)
    assert mismatch.returncode == 1
    assert mismatch.stderr == "error: source_sha256_mismatch\n"

    secret = "wallet-secret-canary"
    rejected = subprocess.run(
        [*_command("receipt", tmp_path / "state"), "--wallet-password", secret],
        capture_output=True,
        text=True,
    )
    assert rejected.returncode == 1
    assert rejected.stderr == "error: invalid_arguments\n"
    assert secret not in rejected.stdout + rejected.stderr


def test_receipt_rejects_tampered_public_field(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    process = subprocess.Popen(
        _command("run", state_dir),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert process.stdout is not None
        marker = json.loads(process.stdout.readline())
        secret = "public-output-secret-canary"
        marker["started_at"] = secret
        (state_dir / "hold-state.json").write_text(
            json.dumps(marker, sort_keys=True, separators=(",", ":")) + "\n"
        )
        result = subprocess.run(_command("receipt", state_dir), capture_output=True, text=True)
        assert result.returncode == 1
        assert result.stderr == "error: invalid_hold_timestamp\n"
        assert secret not in result.stdout + result.stderr
    finally:
        process.terminate()
        process.communicate(timeout=5)


def test_unexpected_filesystem_failure_has_no_traceback_or_path() -> None:
    invalid_state = "/dev/null/private-state-canary"
    result = subprocess.run(
        _command("receipt", Path(invalid_state)), capture_output=True, text=True
    )
    assert result.returncode == 1
    assert result.stderr == "error: unsafe_state_dir\n"
    assert invalid_state not in result.stdout + result.stderr
    assert "Traceback" not in result.stdout + result.stderr


def test_receipt_is_read_only_and_rejects_symlinked_state_ancestor(tmp_path: Path) -> None:
    missing_state = tmp_path / "missing" / "state"
    missing = subprocess.run(_command("receipt", missing_state), capture_output=True, text=True)
    assert missing.returncode == 1
    assert missing.stderr == "error: state_dir_missing\n"
    assert not missing_state.parent.exists()

    real_parent = tmp_path / "real"
    real_parent.mkdir(mode=0o700)
    linked_parent = tmp_path / "linked"
    linked_parent.symlink_to(real_parent, target_is_directory=True)
    linked_state = linked_parent / "state"
    linked = subprocess.run(_command("receipt", linked_state), capture_output=True, text=True)
    assert linked.returncode == 1
    assert linked.stderr == "error: unsafe_state_dir\n"
    assert not (real_parent / "state").exists()


def test_receipt_rejects_non_regular_marker_without_blocking(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    process = subprocess.Popen(
        _command("run", state_dir),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert process.stdout is not None
        process.stdout.readline()
        marker = state_dir / "hold-state.json"
        marker.unlink()
        os.mkfifo(marker, mode=stat.S_IRUSR | stat.S_IWUSR)
        result = subprocess.run(
            _command("receipt", state_dir), capture_output=True, text=True, timeout=2
        )
        assert result.returncode == 1
        assert result.stderr == "error: unsafe_hold_marker\n"
    finally:
        process.kill()
        process.communicate(timeout=5)


def test_render_systemd_user_unit_is_pinned_and_network_restricted(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    output = tmp_path / "units" / "umi-sn78-validator-hold.service"
    result = subprocess.run(
        [
            sys.executable,
            str(HOLD_SCRIPT),
            "render-systemd-user",
            *_identity_arguments(state_dir),
            "--python",
            sys.executable,
            "--script",
            str(HOLD_SCRIPT),
            "--output",
            str(output),
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    unit = output.read_text()
    assert f"ExecStart=/usr/bin/env -i {sys.executable} -I -S {HOLD_SCRIPT}" in unit
    assert f"--umi-revision {REVISION}" in unit
    assert f"--expected-source-sha256 {_source_hash()}" in unit
    assert f"--repository-root {REPOSITORY_ROOT}" in unit
    assert "RestrictAddressFamilies=AF_UNIX" in unit
    assert "NoNewPrivileges=true" in unit
    assert "wallet" not in unit.lower()
    assert output.stat().st_mode & 0o777 == 0o600

    repeated = subprocess.run(
        [
            sys.executable,
            str(HOLD_SCRIPT),
            "render-systemd-user",
            *_identity_arguments(state_dir),
            "--python",
            sys.executable,
            "--script",
            str(HOLD_SCRIPT),
            "--output",
            str(output),
        ],
        capture_output=True,
        text=True,
    )
    assert repeated.returncode == 1
    assert repeated.stderr == "error: unit_output_exists\n"


@pytest.mark.parametrize(
    ("flag", "value", "reason"),
    [
        ("--hotkey", "not-an-address", "invalid_hotkey"),
        ("--umi-revision", "ABC", "invalid_umi_revision"),
        ("--state-dir", "/tmp/state with spaces", "invalid_state_dir"),
    ],
)
def test_identity_and_path_validation(tmp_path: Path, flag: str, value: str, reason: str) -> None:
    arguments = _command("receipt", tmp_path / "state")
    arguments[arguments.index(flag) + 1] = value
    result = subprocess.run(arguments, capture_output=True, text=True)
    assert result.returncode == 1
    assert result.stderr == f"error: {reason}\n"
