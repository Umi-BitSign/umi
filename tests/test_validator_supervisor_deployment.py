from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

from tests.factories import dev_wallet
from umi.validator_supervisor import ValidatorSupervisorConfig

ROOT = Path(__file__).resolve().parents[1]
DEPLOYMENT = ROOT / "deploy" / "linux-validator-supervisor"


def test_linux_supervisor_example_matches_fixed_deployment_profile() -> None:
    values = json.loads((DEPLOYMENT / "validator-supervisor.json.example").read_bytes())
    values.update(
        {
            "channel_id": "11" * 32,
            "finality_verifier_sha256": "22" * 32,
            "validator_hotkey": dev_wallet("//DeploymentValidator").hotkey.ss58_address,
        }
    )
    values["trusted_authorities"][0]["hotkey"] = dev_wallet(
        "//DeploymentAuthority"
    ).hotkey.ss58_address
    values["wallet"].update({"name": "validator", "hotkey": "default"})
    values["directive_url"] = "https://api.umi.vision/api/v1/validator-directives/" + "33" * 32

    config = ValidatorSupervisorConfig.model_validate(values)

    assert config.state_root == "/var/lib/umi-validator-supervisor/state"
    assert config.worker_state_root == "/var/lib/umi-validator-worker-state"
    assert config.release_root == "/var/lib/umi-validator-supervisor/releases"
    assert config.operator_input_root == "/var/lib/umi-validator-operator-inputs"
    assert config.wallet.path == "/var/lib/umi-validator-runtime-wallets"
    assert config.finality_verifier_binary == (
        "/opt/umi-validator-supervisor/artifacts/umi-grandpa-finality-observer"
    )
    assert config.finality_chain_spec_path == (
        "/opt/umi-validator-supervisor/artifacts/raw_spec_finney.json"
    )
    assert config.worker_memory_bytes == 12 * 1024**3
    assert config.worker_pids_limit == 512


def test_linux_supervisor_installer_has_valid_shell_and_safe_transition_order() -> None:
    installer = DEPLOYMENT / "install.sh"
    subprocess.run(["sh", "-n", str(installer)], check=True)
    source = installer.read_text()

    initial_hold_preflight = source.index(
        'supervisor preflight-initial-hold --config "$config_stage"'
    )
    legacy_stop = source.index('systemctl disable --now "$legacy_unit"')
    mask = source.index('systemctl mask "$legacy_unit"')
    survivor_check = source.index('require_empty_unit_control_group "$legacy_control_group"')
    config_install = source.index('mv -- "$config_stage" "$config_destination"')
    service_start = source.index('systemctl enable --now "$service_name"')
    assert initial_hold_preflight < legacy_stop < mask
    assert mask < survivor_check < config_install < service_start
    assert "--kill-whom=all --signal=SIGKILL" in source
    assert 'supervisor status --config "$config_destination" --require-hold' in source
    assert "--require-hold" in source
    assert source.count('"$supervisor_executable" "$@"') == 1
    assert "HOME=/var/lib/umi-validator-supervisor/home" in source
    assert "XDG_CONFIG_HOME=/var/lib/umi-validator-supervisor/container-config" in source
    assert "XDG_DATA_HOME=/var/lib/umi-validator-supervisor/container-data" in source
    assert "XDG_RUNTIME_DIR=/run/umi-validator-supervisor" in source
    assert source.count("-- env -i \\\n") == 2
    assert "/var/lib/umi-validator-supervisor/state \\\n" in source
    assert "/var/lib/umi-validator-worker-state\n" in source
    assert 'find "$initially_empty_directory" -mindepth 1 -maxdepth 1' in source
    assert 'while [ "$readiness_attempt" -lt 180 ]' in source
    assert 'stable_hold_observations" -ge 5' in source
    assert 'find "$supervisor_root" -xdev ! -type l' in source
    assert 'find "$supervisor_root" -xdev -type l ! -user root' in source
    assert 'target=$(readlink -f -- "$link")' in source
    assert '"$root"/*' in source
    assert "(--fresh-install | --legacy-unit EXACT_SYSTEM_SERVICE.service)" in source
    assert "--bootstrap-result-upload-key" in source
    assert "slirp4netns_binary=/usr/bin/slirp4netns" in source
    assert "rootless Podman networking is not installed at /usr/bin/slirp4netns" in source
    assert 'mv -- "$credential_stage" "$bootstrap_upload_credential"' in source
    assert source.index(
        'supervisor preflight-initial-hold --config "$config_stage"'
    ) < source.index('mv -- "$credential_stage" "$bootstrap_upload_credential"')
    assert (
        'if [ "$install_mode" = legacy ]; then\n  systemctl disable --now "$legacy_unit"' in source
    )
    assert "printf 'legacy_action=none\\n'" in source


def test_linux_supervisor_fresh_install_is_explicit_and_mutually_exclusive(
    tmp_path: Path,
) -> None:
    installer = DEPLOYMENT / "install.sh"
    mock_bin = tmp_path / "bin"
    mock_bin.mkdir()
    fake_id = mock_bin / "id"
    fake_id.write_text("#!/bin/sh\n[ \"$1\" = -u ] && { printf '0\\n'; exit 0; }\nexit 2\n")
    fake_id.chmod(0o755)
    environment = {**os.environ, "PATH": f"{mock_bin}:/usr/bin:/bin"}
    missing_config = tmp_path / "missing.json"
    upload_key = tmp_path / "bootstrap-result-upload.key"
    upload_key.write_text("11" * 32)
    upload_key.chmod(0o600)

    fresh = subprocess.run(
        [
            "sh",
            str(installer),
            "--config",
            str(missing_config),
            "--bootstrap-result-upload-key",
            str(upload_key),
            "--fresh-install",
        ],
        text=True,
        capture_output=True,
        check=False,
        env=environment,
    )
    assert fresh.returncode == 2
    assert "config source is not a regular file" in fresh.stderr
    assert "legacy unit" not in fresh.stderr

    missing_mode = subprocess.run(
        [
            "sh",
            str(installer),
            "--config",
            str(missing_config),
            "--bootstrap-result-upload-key",
            str(upload_key),
        ],
        text=True,
        capture_output=True,
        check=False,
        env=environment,
    )
    assert missing_mode.returncode == 2
    assert "choose exactly one of --fresh-install or --legacy-unit" in missing_mode.stderr

    conflicting = subprocess.run(
        [
            "sh",
            str(installer),
            "--config",
            str(missing_config),
            "--bootstrap-result-upload-key",
            str(upload_key),
            "--fresh-install",
            "--legacy-unit",
            "old-validator.service",
        ],
        text=True,
        capture_output=True,
        check=False,
        env=environment,
    )
    assert conflicting.returncode == 2
    assert "choose exactly one of --fresh-install or --legacy-unit" in conflicting.stderr

    missing_key = subprocess.run(
        ["sh", str(installer), "--config", str(missing_config), "--fresh-install"],
        text=True,
        capture_output=True,
        check=False,
        env=environment,
    )
    assert missing_key.returncode == 2
    assert "--bootstrap-result-upload-key is required" in missing_key.stderr


def test_subordinate_range_checker_rejects_shared_or_malformed_ranges() -> None:
    checker = DEPLOYMENT / "check-subordinate-ranges.awk"

    def result(contents: str) -> int:
        completed = subprocess.run(
            ["awk", "-F:", "-v", "account=umi-validator", "-v", "uid=995", "-f", str(checker)],
            input=contents,
            text=True,
            capture_output=True,
            check=False,
        )
        return completed.returncode

    assert result("other:100000:65536\numi-validator:200000:65536\n") == 0
    assert result("other:100000:65536\n") != 0
    assert result("umi-validator:200000:65535\n") != 0
    assert result("umi-validator:not-a-number:65536\n") != 0
    assert result("other:250000:65536\numi-validator:200000:65536\n") != 0
    assert result("umi-validator:200000:65536\n995:250000:65536\n") != 0


def test_systemd_unit_keeps_wallet_read_only_and_worker_state_separate() -> None:
    source = (DEPLOYMENT / "umi-validator-supervisor.service").read_text()

    assert "User=umi-validator\n" in source
    assert "Group=umi-validator\n" in source
    assert "ExecStart=/usr/bin/env -i \\\n" in source
    assert "PYTHONUTF8=1 \\\n" in source
    assert "ProtectSystem=strict\n" in source
    assert "/var/lib/umi-validator-runtime-wallets" in source.split("ReadOnlyPaths=", 1)[1]
    assert "/var/lib/umi-validator-bootstrap-upload" in source.split("ReadOnlyPaths=", 1)[1]
    read_write = source.split("ReadWritePaths=", 1)[1].splitlines()[0]
    assert "/var/lib/umi-validator-worker-state" in read_write
    assert "/var/lib/umi-validator-runtime-wallets" not in read_write
    assert "MemoryMax=17179869184\n" in source
    assert "TasksMax=640\n" in source
    assert "TimeoutStopSec=180s\n" in source
