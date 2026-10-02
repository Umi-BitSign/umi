from __future__ import annotations

import ast
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_consumers import scenario as scenario
from .test_competition_cohort_recovery import recovery as recovery
from .test_open_competition import policy as policy
from .test_open_competition import wallet

ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "deploy/miner-upgrade/upgrade.py"
MANIFEST = ROOT / "deploy/miner-upgrade/current.json"

spec = importlib.util.spec_from_file_location("miner_upgrade", SCRIPT)
assert spec is not None and spec.loader is not None
upgrade = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = upgrade
spec.loader.exec_module(upgrade)


def _manifest() -> dict:
    raw = MANIFEST.read_bytes()
    value = json.loads(raw)
    assert raw in {upgrade.canonical(value), upgrade.canonical(value) + b"\n"}
    return value


def _status(manifest: dict) -> dict:
    return {
        "schema": "umi-competition-status/2",
        "policy_sha256": manifest["policy"]["value_sha256"],
        "deployment": {
            "umi_git_revision": manifest["runtime"]["revision"],
            "eligible_tracks": manifest["eligible_tracks"],
        },
    }


def test_current_manifest_accepts_either_c5_track() -> None:
    manifest = _manifest()
    upgrade.validate_manifest(manifest, _status(manifest), "no")
    upgrade.validate_manifest(manifest, _status(manifest), "yes")


def test_matching_live_deployment_supersedes_a_stale_static_runtime_pointer() -> None:
    manifest = _manifest()
    status = _status(manifest)
    status["deployment"]["repository"] = "https://github.com/Umi-BitSign/umi"
    manifest["runtime"]["revision"] = "00" * 20
    selected = upgrade.deployed_manifest(manifest, status)
    assert selected["runtime"]["revision"] == status["deployment"]["umi_git_revision"]
    upgrade.validate_manifest(selected, status, "no")


def test_live_runtime_cannot_cross_a_policy_or_track_profile() -> None:
    manifest = _manifest()
    status = _status(manifest)
    status["deployment"]["repository"] = "https://github.com/Umi-BitSign/umi"
    status["policy_sha256"] = "ff" * 32
    assert upgrade.deployed_manifest(manifest, status) is manifest
    with pytest.raises(ValueError, match="public status differs"):
        upgrade.validate_manifest(manifest, status, "no")


def test_upgrader_is_a_single_file_distribution() -> None:
    source = SCRIPT.read_text()
    ast.parse(source, feature_version=(3, 8))
    assert "install_launcher(Path(__file__))" in source
    assert 'with_name("launch.py")' not in source


@pytest.mark.parametrize("cohort", ["C6", "C7", "C10"])
def test_model_only_cohort_requires_public_track(cohort: str) -> None:
    manifest = _manifest()
    manifest["cohort"] = cohort
    manifest["eligible_tracks"] = ["model"]
    manifest["public_model_track_required"] = True
    status = _status(manifest)
    with pytest.raises(ValueError, match="requires the public-model track"):
        upgrade.validate_manifest(manifest, status, "no")
    upgrade.validate_manifest(manifest, status, "yes")


def test_miner_command_replaces_every_policy_bound_state_path(tmp_path: Path) -> None:
    manifest = _manifest()
    current = [
        "/old/bin/python",
        "-m",
        "umi.miner",
        "--policy",
        "/old/transport.json",
        "--competition-policy",
        "/old/competition.json",
        "--competition-cohort-config",
        "/old/startup.json",
        "--competition-feed",
        "https://old.example",
        "--competition-predecessor-policy",
        "/old/predecessor.json",
        "--competition-chain-config",
        "/old/chain.json",
        "--nonce-db",
        "/old/nonces.sqlite3",
        "--assignment-db",
        "/old/assignments.sqlite3",
        "--finality-state",
        "/old/finality.sqlite3",
        "--port",
        "8091",
    ]
    result = upgrade.miner_command(current, "/new/bin/python", tmp_path, manifest)
    assert result[:3] == ["/new/bin/python", "-m", "umi.miner"]
    assert upgrade.option(result, "--nonce-db") == str(tmp_path / "protocol/nonces.sqlite3")
    assert upgrade.option(result, "--assignment-db") == str(
        tmp_path / "protocol/assignments.sqlite3"
    )
    assert upgrade.option(result, "--finality-state") == str(tmp_path / "protocol/finality.sqlite3")
    assert "--competition-feed" not in result
    assert "--competition-predecessor-policy" not in result
    assert "--competition-chain-config" not in result
    assert current[0] == "/old/bin/python"


def test_python_module_entrypoint_accepts_interpreter_flags(tmp_path: Path) -> None:
    manifest = _manifest()
    current = [
        "/old/bin/python",
        "-I",
        "-B",
        "-m",
        "umi.miner",
        "--policy",
        "/old/transport.json",
        "--competition-policy",
        "/old/competition.json",
        "--competition-cohort-config",
        "/old/startup.json",
        "--nonce-db",
        "/old/nonces.sqlite3",
        "--assignment-db",
        "/old/assignments.sqlite3",
        "--finality-state",
        "/old/finality.sqlite3",
        "--port",
        "8091",
    ]
    result = upgrade.miner_command(current, "/new/bin/python", tmp_path, manifest)
    assert result[:5] == ["/new/bin/python", "-I", "-B", "-m", "umi.miner"]
    assert upgrade.miner_python(current) == "/old/bin/python"
    assert not upgrade.python_module_miner(["/bin/sh", "-m", "umi.miner"])


def test_startup_binds_current_cohort_and_track_independent_identity(tmp_path: Path) -> None:
    manifest = _manifest()
    raw = upgrade.startup(manifest, tmp_path, "miner-hotkey", "10" * 32, "https://miner")
    assert raw == upgrade.canonical(json.loads(raw))
    value = json.loads(raw)
    assert value["authority"]["cohorts"] == [
        {
            "authority_sha256": manifest["service_authority_sha256"],
            "cohort_sha256": manifest["cohort_sha256"],
        }
    ]
    assert value["authority"]["directory"] == str(tmp_path / "grants")
    assert value["authority"]["policy_sha256"] == manifest["policy"]["value_sha256"]


def test_hash_bound_launcher_executes_exact_command(tmp_path: Path) -> None:
    output = tmp_path / "output"
    program = f"from pathlib import Path; Path({str(output)!r}).write_text('ok')"
    command = {
        "arguments": [sys.executable, "-c", program],
        "schema": "umi-miner-upgrade-command/1",
    }
    path = tmp_path / "command.json"
    raw = upgrade.canonical(command)
    path.write_bytes(raw)
    path.chmod(0o600)
    subprocess.run(
        [sys.executable, str(SCRIPT), "--run-command", str(path), upgrade.sha256(raw)],
        check=True,
    )
    assert output.read_text() == "ok"


def test_hash_bound_launcher_rejects_changed_command(tmp_path: Path) -> None:
    path = tmp_path / "command.json"
    raw = upgrade.canonical(
        {"arguments": [sys.executable, "-c", "pass"], "schema": "umi-miner-upgrade-command/1"}
    )
    path.write_bytes(raw)
    path.chmod(0o600)
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--run-command", str(path), "00" * 32],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert not os.access(tmp_path / "unreachable", os.F_OK)


def test_secure_root_rejects_non_root_owned_directory(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="unsafe root directory"):
        upgrade.secure_root(tmp_path / "state")


def test_service_directory_is_private_to_service_account(tmp_path: Path) -> None:
    account = SimpleNamespace(
        pw_uid=os.getuid(), pw_gid=os.getgid(), pw_name="miner", pw_dir="/home/miner"
    )
    path = tmp_path / "protocol"
    upgrade.service_directory(path, account)
    assert path.stat().st_mode & 0o777 == 0o700


def test_endpoint_enrollment_config_reuses_running_wallet_and_identity() -> None:
    manifest = _manifest()
    raw = upgrade.endpoint_enrollment_config(
        [
            "/runtime/bin/python",
            "-m",
            "umi.miner",
            "--wallet-name",
            "miner",
            "--hotkey",
            "default",
            "--wallet-path",
            "/var/lib/umi-wallets",
        ],
        manifest,
        wallet("Alice").hotkey.ss58_address,
        "10" * 32,
        "https://miner.example",
        True,
    )
    value = json.loads(raw)
    assert value["cohort_sha256"] == manifest["cohort_sha256"]
    assert value["wallet_name"] == "miner"
    assert value["hotkey_name"] == "default"
    assert value["wallet_path"] == "/var/lib/umi-wallets"
    assert value["public_model_track"] is True
    assert raw == upgrade.canonical(value)


def test_endpoint_request_is_signed_once_for_the_open_recoverable_cohort(
    scenario, monkeypatch: pytest.MonkeyPatch
) -> None:
    import bittensor as bt

    miner_wallet = wallet("Alice")
    history = scenario["intake_history"]
    policy = scenario["policy"]
    config = {
        "cohort_sha256": digest(history.plan),
        "endpoint_url": "https://miner.example",
        "hotkey_name": "default",
        "intake_origin": "https://intake.example",
        "miner_hotkey": miner_wallet.hotkey.ss58_address,
        "model_revision": "10" * 32,
        "policy_sha256": digest(policy),
        "public_model_track": False,
        "schema": "umi-miner-cohort-enrollment/1",
        "service_authority_sha256": digest(history.authority.authority),
        "wallet_name": "miner",
        "wallet_path": "/unused",
    }
    status = {
        "admission_accepting_new": True,
        "admission_checked_block": 210,
        "admission_phase": "open",
        "policy_sha256": digest(policy),
        "schema": "umi-competition-status/2",
    }
    used = []

    def resolve_wallet(**kwargs):
        used.append(kwargs)
        return miner_wallet

    monkeypatch.setattr(bt, "Wallet", resolve_wallet)
    observed_policy, request, raw = upgrade._new_participation_request(
        config,
        canonical_json_bytes(policy),
        status,
        canonical_json_bytes(history),
    )
    assert observed_policy == policy
    assert raw == canonical_json_bytes(request)
    assert request.signed_submission.submission.sequence == 210
    assert request.signed_submission.submission.endpoint_url == "https://miner.example"
    assert request.consent.consent.original_submission_expiry_does_not_end_participation is True
    assert used == [{"name": "miner", "hotkey": "default", "path": "/unused"}]


def test_endpoint_request_waits_for_a_current_finalized_intake(scenario) -> None:
    policy = scenario["policy"]
    history = scenario["intake_history"]
    config = {
        "cohort_sha256": digest(history.plan),
        "endpoint_url": "https://miner.example",
        "hotkey_name": "default",
        "intake_origin": "https://intake.example",
        "miner_hotkey": wallet("Alice").hotkey.ss58_address,
        "model_revision": "10" * 32,
        "policy_sha256": digest(policy),
        "public_model_track": False,
        "schema": "umi-miner-cohort-enrollment/1",
        "service_authority_sha256": digest(history.authority.authority),
        "wallet_name": "miner",
        "wallet_path": "/unused",
    }
    with pytest.raises(upgrade.EnrollmentRetry, match="current open finalized"):
        upgrade._new_participation_request(
            config,
            canonical_json_bytes(policy),
            {
                "admission_accepting_new": False,
                "admission_checked_block": None,
                "admission_phase": "unverified",
                "policy_sha256": digest(policy),
                "schema": "umi-competition-status/2",
            },
            canonical_json_bytes(history),
        )


def test_endpoint_enrollment_timer_retries_every_fifteen_minutes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    systemd = tmp_path / "systemd"
    state = tmp_path / "state"
    state.mkdir()
    account = SimpleNamespace(
        pw_uid=os.getuid(), pw_gid=os.getgid(), pw_name="miner", pw_dir="/home/miner"
    )
    calls = []

    def fake_run(*arguments: str, **_kwargs: object) -> subprocess.CompletedProcess:
        calls.append(arguments)
        return subprocess.CompletedProcess(arguments, 0, "", "")

    monkeypatch.setattr(upgrade, "SYSTEMD_ROOT", systemd)
    monkeypatch.setattr(upgrade, "LAUNCHER", tmp_path / "umi-miner-upgrade")
    monkeypatch.setattr(upgrade, "run", fake_run)
    monkeypatch.setattr(upgrade.os, "chown", lambda *_args, **_kwargs: None)
    report = upgrade.install_endpoint_enrollment(
        state=state,
        account=account,
        runtime_python=Path(sys.executable),
        config_raw=b"{}",
        policy_raw=b"{}",
    )
    timer = (systemd / upgrade.ENROLLMENT_TIMER).read_text()
    service = (systemd / upgrade.ENROLLMENT_SERVICE).read_text()
    assert "OnUnitInactiveSec=15min" in timer
    assert "Persistent=true" in timer
    assert "ConditionPathExists=!" in service
    assert "Environment=HOME=/home/miner" in service
    assert "ProtectSystem=strict" in service
    assert ("systemctl", "enable", "--now", upgrade.ENROLLMENT_TIMER) in calls
    assert report == {"retry_seconds": 900, "status": "endpoint_enrollment_retry_scheduled"}


def test_activation_restores_previous_override_when_health_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    systemd = tmp_path / "systemd"
    prior = systemd / "umi-miner.service.d/90-umi-cohort-upgrade.conf"
    prior.parent.mkdir(parents=True)
    prior.write_bytes(b"old override\n")
    command = tmp_path / "command.json"
    command.write_bytes(b"{}")
    calls = []

    def fake_run(*arguments: str, **_kwargs: object) -> subprocess.CompletedProcess:
        calls.append(arguments)
        return subprocess.CompletedProcess(arguments, 0, "", "")

    def failed_health(*_args: object, **_kwargs: object) -> dict:
        raise ValueError("simulated startup failure")

    monkeypatch.setattr(upgrade, "SYSTEMD_ROOT", systemd)
    monkeypatch.setattr(upgrade, "LAUNCHER", tmp_path / "launcher")
    monkeypatch.setattr(upgrade, "run", fake_run)
    monkeypatch.setattr(upgrade, "wait_health", failed_health)
    monkeypatch.setattr(upgrade.os, "chown", lambda *_args: None)
    miner = upgrade.Service("umi-miner.service", 10, "miner", ["/bin/true"])
    with pytest.raises(ValueError, match="simulated startup failure"):
        upgrade.activate_services(
            miner=miner,
            sidecar=None,
            miner_command_path=command,
            miner_command_sha="10" * 32,
            sidecar_command_path=None,
            sidecar_command_sha=None,
            launcher_python=Path(sys.executable),
            new_socket=None,
            port=8091,
            policy="20" * 32,
            transport="30" * 32,
            model="40" * 32,
        )
    assert prior.read_bytes() == b"old override\n"
    assert ("systemctl", "start", "umi-miner.service") in calls


@pytest.mark.parametrize("cohort", ["C6", "C7", "C10"])
def test_model_only_dry_run_does_not_write_or_install(
    cohort: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    manifest = _manifest()
    manifest["cohort"] = cohort
    manifest["eligible_tracks"] = ["model"]
    manifest["public_model_track_required"] = True
    manifest_raw = upgrade.canonical(manifest)
    status_raw = upgrade.canonical(_status(manifest))
    miner = upgrade.Service(
        "umi-miner.service",
        10,
        "miner",
        [
            "/runtime/bin/python",
            "-m",
            "umi.miner",
            "--port",
            "8091",
            "--model-revision",
            "10" * 32,
            "--serving-origin",
            "https://miner.example",
        ],
    )
    responses = iter((manifest_raw, status_raw))
    monkeypatch.setattr(upgrade, "fetch", lambda *_args, **_kwargs: next(responses))
    monkeypatch.setattr(upgrade, "discover_miner", lambda: miner)
    monkeypatch.setattr(
        upgrade,
        "miner_identity",
        lambda *_args: ("miner-hotkey", "10" * 32, "https://miner.example"),
    )
    account = SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid(), pw_name="miner")
    monkeypatch.setattr(upgrade.pwd, "getpwnam", lambda *_args: account)
    monkeypatch.setattr(upgrade, "ROOT", tmp_path / "state")
    monkeypatch.setattr(upgrade.sys, "platform", "linux")
    monkeypatch.setattr(upgrade.shutil, "which", lambda *_args: "/bin/systemctl")
    monkeypatch.setattr(
        upgrade,
        "install_launcher",
        lambda *_args: pytest.fail("dry run installed the launcher"),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [str(SCRIPT), "--public-model-track", "yes", "--dry-run"],
    )
    upgrade.main()
    report = json.loads(capsys.readouterr().out)
    assert report["cohort"] == cohort
    assert report["endpoint_service_unchanged"] is True
    assert report["status"] == "upgrade_preflight_passed"
    assert not (tmp_path / "state").exists()


@pytest.mark.parametrize("cohort", ["C6", "C7", "C10"])
def test_model_only_upgrade_records_intent_without_touching_endpoint(
    cohort: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    manifest = _manifest()
    manifest["cohort"] = cohort
    manifest["eligible_tracks"] = ["model"]
    manifest["public_model_track_required"] = True
    manifest_raw = upgrade.canonical(manifest)
    responses = iter((manifest_raw, upgrade.canonical(_status(manifest))))
    miner = upgrade.Service(
        "umi-miner.service",
        10,
        "miner",
        ["/runtime/bin/python", "-m", "umi.miner", "--port", "8091"],
    )
    account = SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid(), pw_name="miner")
    launcher_installs = []
    monkeypatch.setattr(upgrade, "fetch", lambda *_args, **_kwargs: next(responses))
    monkeypatch.setattr(upgrade, "discover_miner", lambda: miner)
    monkeypatch.setattr(
        upgrade,
        "miner_identity",
        lambda *_args: ("miner-hotkey", "10" * 32, "https://miner.example"),
    )
    monkeypatch.setattr(upgrade.pwd, "getpwnam", lambda *_args: account)
    monkeypatch.setattr(upgrade, "ROOT", tmp_path / "state")
    monkeypatch.setattr(upgrade.sys, "platform", "linux")
    monkeypatch.setattr(upgrade.shutil, "which", lambda *_args: "/bin/systemctl")
    monkeypatch.setattr(upgrade.os, "geteuid", lambda: 0)
    monkeypatch.setattr(upgrade.os, "chown", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(upgrade, "secure_root", lambda *_args: None)
    monkeypatch.setattr(upgrade, "install_launcher", launcher_installs.append)
    monkeypatch.setattr(
        upgrade,
        "run",
        lambda *_args, **_kwargs: pytest.fail("model-only upgrade touched a service"),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [str(SCRIPT), "--public-model-track", "yes"],
    )
    upgrade.main()
    report = json.loads(capsys.readouterr().out)
    state = tmp_path / "state" / manifest["policy"]["value_sha256"][:16]
    intent = json.loads((state / "inputs/track-intent.json").read_bytes())
    assert report["status"] == "model_track_intent_recorded"
    assert report["endpoint_service_unchanged"] is True
    assert intent["public_model_track"] is True
    assert launcher_installs == [SCRIPT]
