from __future__ import annotations

import ast
import importlib.util
import json
import os
import subprocess
import sys
import venv
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


def test_miner_command_preserves_existing_cohort_state_paths(tmp_path: Path) -> None:
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
    assert result[:5] == ["/new/bin/python", "-I", "-B", "-m", "umi.miner"]
    assert upgrade.option(result, "--nonce-db") == "/old/nonces.sqlite3"
    assert upgrade.option(result, "--assignment-db") == "/old/assignments.sqlite3"
    assert upgrade.option(result, "--finality-state") == "/old/finality.sqlite3"
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


@pytest.mark.parametrize("console", [False, True])
def test_upgraded_miner_imports_selected_runtime_despite_old_source_environment(
    tmp_path: Path, console: bool
) -> None:
    runtime = tmp_path / "runtime"
    venv.EnvBuilder(with_pip=False).create(runtime)
    python = runtime / "bin/python"
    version = f"python{sys.version_info.major}.{sys.version_info.minor}"
    site = runtime / "lib" / version / "site-packages"
    old = tmp_path / "old-source"
    for root, label in ((site, "selected"), (old, "old")):
        package = root / "umi"
        package.mkdir(parents=True)
        (package / "__init__.py").write_text("")
        (package / "miner.py").write_text(
            "import json, os; print(json.dumps({'source': "
            + repr(label)
            + ", 'working_directory': os.getcwd()}))"
        )
    environment = dict(os.environ, PYTHONPATH=str(old), PYTHONDONTWRITEBYTECODE="1")
    environment.pop("PYTHONHOME", None)
    baseline = subprocess.run(
        [str(python), "-m", "umi.miner"],
        cwd=old,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert json.loads(baseline.stdout)["source"] == "old"
    environment["PYTHONHOME"] = str(old / "obsolete-python")
    current = ["/old/bin/umi-miner"] if console else ["/old/bin/python", "-m", "umi.miner"]
    command = upgrade.miner_command(current, str(python), tmp_path / "state", _manifest())
    result = subprocess.run(
        command,
        cwd=old,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert json.loads(result.stdout) == {"source": "selected", "working_directory": str(old)}


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


def test_service_claim_is_signed_once_and_recovers_its_receipt(
    scenario, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import bittensor as bt

    from umi.competition_cohort_service_work import (
        SignedServiceWorkClaim,
        service_claim_key,
        verify_service_claim,
    )

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
    monkeypatch.setattr(bt, "Wallet", lambda **_kwargs: miner_wallet)
    _, request, _ = upgrade._new_participation_request(
        config,
        canonical_json_bytes(policy),
        status,
        canonical_json_bytes(history),
    )
    catalog = "32" * 32
    index = canonical_json_bytes(
        {
            "schema": "umi-public-service-work-catalogs/1",
            "catalogs": [
                {
                    "authority_sha256": config["service_authority_sha256"],
                    "catalog_sha256": catalog,
                    "cohort_sha256": config["cohort_sha256"],
                    "policy_sha256": config["policy_sha256"],
                    "status": "installed",
                }
            ],
        }
    )
    monkeypatch.setattr(upgrade, "fetch", lambda *_args, **_kwargs: index)
    sent = []

    async def post(*, origin, path, body, transport=None, timeout_seconds):
        assert origin == config["intake_origin"]
        assert path == f"/v1/competition/service-work/{catalog}/claims"
        assert transport is None
        assert timeout_seconds == upgrade.SERVICE_CLAIM_TIMEOUT_SECONDS == 3600
        signed = verify_service_claim(SignedServiceWorkClaim.model_validate_json(body))
        sent.append(body)
        return canonical_json_bytes(
            {
                "admission_sha256": "41" * 32,
                "catalog_sha256": catalog,
                "chain_submission_authorized": False,
                "claim_sha256": service_claim_key(signed.claim),
                "ordinal": 7,
                "schema": "umi-public-service-work-admission/1",
                "service_credit_authorized": False,
                "status": "accepted",
                "work_sha256": "42" * 32,
            }
        )

    import umi.competition_client as client

    monkeypatch.setattr(client, "post_intake_document", post)
    enrollment = tmp_path / "enrollment"
    enrollment.mkdir(mode=0o700)
    first = upgrade.service_claim_step(enrollment, config, request)
    second = upgrade.service_claim_step(enrollment, config, request)
    assert (
        first
        == second
        == {
            "catalog_sha256": catalog,
            "ordinal": 7,
            "status": "service_work_admission_accepted",
            "work_sha256": "42" * 32,
        }
    )
    assert len(sent) == 1
    assert (enrollment / "service-work-claim.json").read_bytes() == sent[0]


def test_service_claim_waits_for_its_installed_cohort_catalog(
    scenario, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = {
        "cohort_sha256": digest(scenario["intake_history"].plan),
        "intake_origin": "https://intake.example",
        "policy_sha256": digest(scenario["policy"]),
        "service_authority_sha256": digest(scenario["intake_history"].authority.authority),
    }
    monkeypatch.setattr(
        upgrade,
        "fetch",
        lambda *_args, **_kwargs: canonical_json_bytes(
            {
                "schema": "umi-public-service-work-catalogs/1",
                "catalogs": [{"catalog_sha256": "32" * 32, "status": "pending_installation"}],
            }
        ),
    )
    with pytest.raises(upgrade.ServiceClaimRetry, match="not installed"):
        upgrade._service_catalog(config)


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
    assert "service-work-admission.json" in service
    assert "admission-certificate.json" not in service
    assert "Environment=HOME=/home/miner" in service
    assert "TimeoutStartSec=70min" in service
    assert "ProtectSystem=strict" in service
    assert ("systemctl", "enable", "--now", upgrade.ENROLLMENT_TIMER) in calls
    assert ("systemctl", "start", "--no-block", upgrade.ENROLLMENT_SERVICE) in calls
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


@pytest.mark.parametrize("public_track", ["no", "yes"])
@pytest.mark.parametrize("layout", ["standard", "manual_cohort"])
@pytest.mark.parametrize(
    "prior_runtime",
    [
        "old",
        "missing",
        "current",
        "current_unisolated",
        "rolled_back",
        "legacy",
        "missing_transport",
    ],
)
def test_same_policy_rerun_updates_changed_runtime_without_losing_state(
    prior_runtime: str,
    public_track: str,
    layout: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    manifest = _manifest()
    transport_path = ROOT / "docs/competition/C5_TRANSPORT_POLICY.json"
    pins = upgrade.scoring_runtime_pins(transport_path)
    target_python = (
        tmp_path
        / "runtimes"
        / (manifest["runtime"]["revision"] + "-" + upgrade.sha256(upgrade.canonical(pins))[:16])
        / "venv/bin/python"
    )
    actual_python = (
        target_python
        if prior_runtime in {"current", "current_unisolated", "missing_transport"}
        else tmp_path / "old/bin/python"
    )
    if prior_runtime == "legacy":
        actual_python = tmp_path / "runtimes" / manifest["runtime"]["revision"] / "venv/bin/python"
    arguments = [
        str(actual_python),
        "-m",
        "umi.miner",
        "--port",
        "8091",
        "--model-revision",
        "10" * 32,
        "--serving-origin",
        "https://miner.example",
        "--wallet-name",
        "miner",
        "--hotkey",
        "miner",
    ]
    if prior_runtime != "current_unisolated":
        arguments[1:1] = ["-I", "-B"]
    miner = upgrade.Service("umi-miner.service", 10, "miner", arguments)
    account = SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid(), pw_name="miner")
    root = tmp_path / "state"
    state = root / manifest["policy"]["value_sha256"][:16]
    inputs = state / "inputs"
    inputs.mkdir(parents=True)
    policy_raw = (ROOT / "docs/competition/C5_POLICY.json").read_bytes()
    transport_raw = (ROOT / "docs/competition/C5_TRANSPORT_POLICY.json").read_bytes()
    (inputs / "competition-policy.json").write_bytes(policy_raw)
    if prior_runtime != "missing_transport":
        (inputs / "transport-policy.json").write_bytes(transport_raw)
    prior = {
        "policy_sha256": manifest["policy"]["value_sha256"],
        "runtime_revision": "00" * 20
        if prior_runtime == "old"
        else manifest["runtime"]["revision"],
        "status": "miner_upgrade_verified",
    }
    if prior_runtime == "missing":
        prior.pop("runtime_revision")
    (state / "upgrade-receipt.json").write_bytes(upgrade.canonical(prior))
    protected = {
        state / "protocol/nonces.sqlite3": b"retained nonce state",
        state / "enrollment/signed-request.json": b"exact retained request",
    }
    for path, value in protected.items():
        path.parent.mkdir(exist_ok=True)
        path.write_bytes(value)
    if layout == "manual_cohort":
        custom = tmp_path / "custom-state"
        custom.mkdir()
        startup_bytes = upgrade.startup(
            manifest, custom, "miner-hotkey", "10" * 32, "https://miner.example"
        )
        startup_path = custom / "startup.json"
        startup_path.write_bytes(startup_bytes)
        arguments.extend(("--competition-cohort-config", str(startup_path)))
        for flag, filename in (
            ("--nonce-db", "nonces.sqlite3"),
            ("--assignment-db", "assignments.sqlite3"),
            ("--finality-state", "finality.sqlite3"),
        ):
            path = custom / filename
            protected[path] = b"retained custom journal"
            path.write_bytes(protected[path])
            arguments.extend((flag, str(path)))
        protected[startup_path] = startup_bytes
    calls = []
    responses = {
        upgrade.DEFAULT_MANIFEST: upgrade.canonical(manifest),
        upgrade.DEFAULT_STATUS: upgrade.canonical(_status(manifest)),
        manifest["policy"]["url"]: policy_raw,
        manifest["transport"]["url"]: transport_raw,
    }
    monkeypatch.setattr(upgrade, "fetch", lambda url, *_args, **_kwargs: responses[url])
    monkeypatch.setattr(upgrade, "ROOT", root)
    monkeypatch.setattr(upgrade, "RUNTIME_ROOT", tmp_path / "runtimes")
    monkeypatch.setattr(upgrade, "discover_miner", lambda: miner)
    monkeypatch.setattr(
        upgrade,
        "miner_identity",
        lambda *_args: ("miner-hotkey", "10" * 32, "https://miner.example"),
    )
    monkeypatch.setattr(upgrade.pwd, "getpwnam", lambda *_args: account)
    monkeypatch.setattr(upgrade.sys, "platform", "linux")
    monkeypatch.setattr(upgrade.shutil, "which", lambda *_args: "/bin/systemctl")
    monkeypatch.setattr(upgrade.os, "geteuid", lambda: 0)
    monkeypatch.setattr(upgrade.os, "chown", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(upgrade, "secure_root", lambda p: p.mkdir(parents=True, exist_ok=True))
    monkeypatch.setattr(upgrade, "install_launcher", lambda *_args: None)
    monkeypatch.setattr(upgrade, "wait_health", lambda *_args, **_kwargs: {"ok": True})
    monkeypatch.setattr(
        upgrade, "install_runtime", lambda *_args: calls.append("runtime") or target_python
    )
    monkeypatch.setattr(upgrade, "prepare_sidecar", lambda command, *_args: (None, command, None))
    monkeypatch.setattr(
        upgrade, "activate_services", lambda **kwargs: calls.append(kwargs) or {"ok": True}
    )
    monkeypatch.setattr(
        upgrade,
        "install_endpoint_enrollment",
        lambda **kwargs: {"status": "retained_request_reused"},
    )
    monkeypatch.setattr(sys, "argv", [str(SCRIPT), "--public-model-track", public_track])
    upgrade.main()
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == (
        "already_upgraded" if prior_runtime == "current" else "miner_upgrade_verified"
    )
    assert len(calls) == (0 if prior_runtime == "current" else 2)
    if calls:
        command = json.loads((inputs / "miner-command.json").read_bytes())["arguments"]
        assert command[0] == str(target_python)
        assert upgrade.option(command, "--model-revision") == "10" * 32
        nonce_path = (
            custom / "nonces.sqlite3"
            if layout == "manual_cohort"
            else state / "protocol/nonces.sqlite3"
        )
        assert upgrade.option(command, "--nonce-db") == str(nonce_path)
        if layout == "manual_cohort":
            assert (inputs / "miner-startup.json").read_bytes() == startup_bytes
    assert all(path.read_bytes() == value for path, value in protected.items())


@pytest.mark.parametrize(
    "target,expected",
    [("x86_64", "x86_64-unknown-linux-gnu"), ("aarch64", "aarch64-unknown-linux-gnu")],
)
def test_upgrader_selects_host_specific_signed_runtime_pins(
    target, expected, tmp_path, monkeypatch
):
    monkeypatch.setattr(upgrade.platform, "system", lambda: "Linux")
    monkeypatch.setattr(upgrade.platform, "machine", lambda: target)
    monkeypatch.setattr(upgrade.platform, "libc_ver", lambda: ("glibc", "2.42"))
    raw = json.loads((ROOT / "docs/competition/C5_TRANSPORT_POLICY.json").read_bytes())
    pins = dict(raw["implementation_pins"]["scoring_by_target"]["x86_64-unknown-linux-gnu"])
    pins["python_version"] = "3.13.8"
    raw["implementation_pins"]["scoring_by_target"][expected] = pins
    path = tmp_path / "policy.json"
    path.write_bytes(upgrade.canonical(raw))
    assert upgrade.scoring_runtime_pins(path) == pins


@pytest.mark.parametrize(
    "field,value",
    [
        ("implementation_pins", []),
        ("scoring_by_target", []),
        ("python_version", "3.12"),
        ("regex_distribution_version", "2026.9.3;unsafe"),
    ],
)
def test_upgrader_rejects_invalid_runtime_pin_profiles(field, value, tmp_path):
    raw = json.loads((ROOT / "docs/competition/C5_TRANSPORT_POLICY.json").read_bytes())
    if field == "implementation_pins":
        raw[field] = value
    elif field == "scoring_by_target":
        raw["implementation_pins"][field] = value
    else:
        raw["implementation_pins"]["scoring_by_target"]["x86_64-unknown-linux-gnu"][field] = value
    path = tmp_path / "policy.json"
    path.write_bytes(upgrade.canonical(raw))
    with pytest.raises(ValueError):
        upgrade.scoring_runtime_pins(path)


def test_python_selection_skips_wrong_patch_and_uses_exact_policy(tmp_path, monkeypatch):
    old = tmp_path / "old-python"
    correct = tmp_path / "python3.12.14"
    for path in (old, correct):
        path.write_text("placeholder")
        path.chmod(0o755)
    monkeypatch.setattr(
        upgrade.shutil, "which", lambda name: str(correct) if name == "python3.12.14" else None
    )
    original_stat = Path.stat

    def root_owned(path, *args, **kwargs):
        info = original_stat(path, *args, **kwargs)
        return SimpleNamespace(st_mode=info.st_mode, st_uid=0, st_gid=0)

    monkeypatch.setattr(Path, "stat", root_owned)
    calls = []

    def run(*args, **kwargs):
        calls.append(args)
        assert "platform.python_version()" in args[-1]
        assert "3.12.14" in args[-1]
        return SimpleNamespace(returncode=0 if args[0] == str(correct) else 1)

    monkeypatch.setattr(upgrade, "run", run)
    assert upgrade.policy_python(
        str(old), {"python_implementation": "CPython", "python_version": "3.12.14"}
    ) == str(correct)
    assert [call[0] for call in calls] == [str(old), str(correct)]


@pytest.mark.parametrize("fail_verification", [False, True])
def test_runtime_exact_pins_are_verified_before_promotion(tmp_path, monkeypatch, fail_verification):
    policy = ROOT / "docs/competition/C5_TRANSPORT_POLICY.json"
    manifest = _manifest()
    runtime_root = tmp_path / "runtimes"
    runtime_root.mkdir()
    legacy = runtime_root / manifest["runtime"]["revision"]
    legacy.mkdir()
    sentinel = legacy / "retained-live-runtime"
    sentinel.write_bytes(b"keep existing service runtime")
    monkeypatch.setattr(upgrade, "RUNTIME_ROOT", runtime_root)
    monkeypatch.setattr(upgrade, "secure_root", lambda path: None)
    monkeypatch.setattr(upgrade, "seal_tree", lambda path: None)
    monkeypatch.setattr(upgrade, "policy_python", lambda *_args: "/root-owned/python3.12.14")
    target = upgrade.runtime_directory(manifest["runtime"], policy)
    calls = []
    shadow_bin = tmp_path / "shadow-bin"
    shadow_bin.mkdir()
    shadow_marker = tmp_path / "shadow-env-ran"
    shadow_env = shadow_bin / "env"
    shadow_env.write_text(f"#!/bin/sh\ntouch '{shadow_marker}'\nexit 0\n")
    shadow_env.chmod(0o755)
    monkeypatch.setenv("PATH", str(shadow_bin) + os.pathsep + os.environ.get("PATH", ""))

    def run(*args, **kwargs):
        calls.append((args, kwargs))
        if "install" in args:
            interpreter_index = next(
                index for index, value in enumerate(args) if value.endswith("/venv/bin/python")
            )
            subprocess.run([*args[:interpreter_index], "/usr/bin/true"], check=True)
            assert not shadow_marker.exists()
        if "venv" in args:
            python = Path(args[-1]) / "bin/python"
            python.parent.mkdir(parents=True)
            python.write_bytes(b"test interpreter")
        if "validate_scoring_runtime" in " ".join(args):
            assert args[:4] == ("runuser", "--user", "miner", "--")
            if not target.exists():
                assert target.with_name(target.name + ".pending").exists()
            if fail_verification:
                raise ValueError("scoring runtime does not match policy pin")
        return SimpleNamespace(stdout="verified import", returncode=0)

    monkeypatch.setattr(upgrade, "run", run)
    account = SimpleNamespace(pw_name="miner")
    if fail_verification:
        with pytest.raises(ValueError, match="does not match"):
            upgrade.install_runtime("/old/python", manifest["runtime"], account, policy)
        assert not target.exists()
    else:
        assert (
            upgrade.install_runtime("/old/python", manifest["runtime"], account, policy)
            == target / "venv/bin/python"
        )
        assert target.exists()
    pip_args, pip_options = next(
        (args, opts) for args, opts in calls if "install" in args and "uv" in args
    )
    assert set(pip_args[-4:]) == {
        "regex==2026.9.3",
        "rfc8785==0.1.4",
        "pydantic==2.13.5",
        "pydantic-core==2.46.5",
    }
    assert pip_options["timeout"] == 3600
    assert sentinel.read_bytes() == b"keep existing service runtime"


def test_manual_cohort_upgrade_retains_exact_startup_and_custom_paths(tmp_path):
    manifest = _manifest()
    raw = upgrade.startup(manifest, tmp_path / "custom", "miner-hotkey", "10" * 32, "https://miner")
    config = tmp_path / "existing.json"
    config.write_bytes(raw)
    args = [
        "/old/python",
        "-m",
        "umi.miner",
        "--competition-cohort-config",
        str(config),
        "--nonce-db",
        "/root/custom/nonces.sqlite3",
        "--assignment-db",
        "/root/custom/assignments.sqlite3",
        "--finality-state",
        "/root/custom/finality.sqlite3",
    ]
    result, kind = upgrade.migration_startup(
        args, manifest, tmp_path / "new", "miner-hotkey", "10" * 32, "https://miner"
    )
    assert result == raw and kind == "cohort_runtime_in_place"
    updated = upgrade.miner_command(args, "/new/python", tmp_path / "new", manifest)
    for flag in ("--nonce-db", "--assignment-db", "--finality-state"):
        assert upgrade.option(updated, flag) == upgrade.option(args, flag)
    assert config.read_bytes() == raw


@pytest.mark.parametrize("field", ["policy_sha256", "cohorts", "miner_hotkey", "schema"])
def test_manual_upgrade_rejects_unqualified_authority_changes_before_writes(tmp_path, field):
    manifest = _manifest()
    raw = upgrade.startup(manifest, tmp_path / "custom", "miner-hotkey", "10" * 32, "https://miner")
    value = json.loads(raw)
    if field == "schema":
        value["schema"] = "unknown-startup/9"
    else:
        value["authority"][field] = [] if field == "cohorts" else "00" * 32
    config = tmp_path / "existing.json"
    old = upgrade.canonical(value)
    config.write_bytes(old)
    args = ["--competition-cohort-config", str(config)]
    with pytest.raises(ValueError, match="unsupported installed cohort"):
        upgrade.migration_startup(
            args, manifest, tmp_path / "new", "miner-hotkey", "10" * 32, "https://miner"
        )
    assert config.read_bytes() == old and not (tmp_path / "new").exists()


def test_root_run_miner_is_discovered_without_account_migration(monkeypatch):
    monkeypatch.setattr(
        upgrade, "run", lambda *a, **kw: SimpleNamespace(stdout="MainPID=123\nUser=root\n")
    )
    args = ["/old/python", "-m", "umi.miner"]
    monkeypatch.setattr(upgrade, "cmdline", lambda pid: args)
    monkeypatch.setattr(upgrade.os, "readlink", lambda path: "/")
    found = upgrade.service("umi.miner.service")
    assert found.user == "root" and found.pid == 123 and found.arguments == args


def test_manual_relative_paths_use_running_service_working_directory(tmp_path):
    manifest = _manifest()
    raw = upgrade.startup(manifest, Path("state"), "miner-hotkey", "10" * 32, "https://miner")
    (tmp_path / "startup.json").write_bytes(raw)
    arguments = [
        "/old/python",
        "-m",
        "umi.miner",
        "--competition-cohort-config",
        "startup.json",
        "--model-revision",
        "10" * 32,
        "--serving-origin",
        "https://miner",
        "--wallet-name",
        "miner",
        "--hotkey",
        "miner",
        "--wallet-path",
        "wallets",
        "--nonce-db",
        "state/nonces.sqlite3",
        "--assignment-db",
        "state/assignments.sqlite3",
        "--finality-state",
        "state/finality.sqlite3",
    ]
    identity = upgrade.miner_identity(arguments, "root", tmp_path)
    retained, kind = upgrade.migration_startup(
        arguments, manifest, tmp_path / "new", *identity, tmp_path
    )
    assert retained == raw and kind == "cohort_runtime_in_place"
    enrollment = json.loads(
        upgrade.endpoint_enrollment_config(arguments, manifest, *identity, False, tmp_path)
    )
    assert enrollment["wallet_path"] == str(tmp_path / "wallets")
    updated = upgrade.miner_command(arguments, "/new/python", tmp_path / "new", manifest)
    assert upgrade.option(updated, "--assignment-db") == "state/assignments.sqlite3"
