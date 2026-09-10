from __future__ import annotations

import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEPLOYMENT = ROOT / "deploy" / "linux-validator-supervisor"


def test_linux_supervisor_installer_has_valid_shell_and_safe_transition_order() -> None:
    installer = DEPLOYMENT / "install.sh"
    subprocess.run(["sh", "-n", str(installer)], check=True)
    source = installer.read_text()

    release_preflight = source.index('supervisor preflight-common-switch --config "$config_stage"')
    legacy_stop = source.index('systemctl disable --now "$legacy_unit"')
    survivor_check = source.index('require_empty_unit_control_group "$legacy_control_group"')
    config_install = source.index('mv -- "$config_stage" "$config_destination"')
    service_start = source.index('systemctl enable --now "$service_name"')
    assert release_preflight < legacy_stop < survivor_check < config_install < service_start
    assert "--kill-whom=all --signal=SIGKILL" in source
    assert "--wallet-name NAME --hotkey-name NAME --wallet-path /ABSOLUTE/WALLET/ROOT" in source
    assert "--legacy-unit EXACT_SYSTEM_SERVICE.service" in source
    usage = source.split("cat <<'EOF'", 1)[1].split("\nEOF", 1)[0]
    assert "--config" not in usage
    assert "bootstrap-result-upload" not in source
    assert source.count('"$supervisor_executable" "$@"') == 1
    assert "HOME=/var/lib/umi-validator-supervisor/home" in source
    assert "XDG_CONFIG_HOME=/var/lib/umi-validator-supervisor/container-config" in source
    assert "XDG_DATA_HOME=/var/lib/umi-validator-supervisor/container-data" in source
    assert "XDG_RUNTIME_DIR=/run/umi-validator-supervisor" in source
    assert source.count("-- env -i \\\n") == 2
    assert 'while [ "$readiness_attempt" -lt 180 ]' in source
    assert 'find "$supervisor_root" -xdev ! -type l' in source
    assert 'find "$supervisor_root" -xdev -type l ! -user root' in source
    assert 'target=$(readlink -f -- "$link")' in source
    assert '"$root"/*' in source
    assert "apt-get install -y --no-install-recommends" in source
    assert "linux/amd64" in source and "linux/arm64" in source
    assert "a3ca19a108fe7d1a8e53a2db76f480ebe237b7942595f23135d6e11889ed40c0" in source
    assert "85ea6ef2c7e4f24d9d0eefa367425119b509e8604ce1675443efcbacc7bb4461" in source
    assert '"$hotkey_source" "$runtime_hotkeys/$hotkey_name"' in source
    assert "coldkey" in usage
    assert "install-common-host-artifacts" in source
    assert '"$artifacts_directory/uv" --version' in source
    assert source.index("supervisor_created=true") < source.index(
        'git -c safe.directory="$source_root" clone'
    )
    assert source.index("runtime_wallet_created=true") < source.index(
        'install -d -o "$service_account" -g "$service_account" -m 0700 \\\n  "$runtime_wallet"'
    )
    assert 'if [ "$retain_installation" = false ]; then' in source
    assert 'systemctl mask "$legacy_unit"' in source
    assert "printf 'legacy_action=none\\n'" in source


def test_linux_supervisor_installer_requires_only_local_wallet_arguments(
    tmp_path: Path,
) -> None:
    installer = DEPLOYMENT / "install.sh"
    mock_bin = tmp_path / "bin"
    mock_bin.mkdir()
    fake_id = mock_bin / "id"
    fake_id.write_text("#!/bin/sh\n[ \"$1\" = -u ] && { printf '0\\n'; exit 0; }\nexit 2\n")
    fake_id.chmod(0o755)
    environment = {**os.environ, "PATH": f"{mock_bin}:/usr/bin:/bin"}
    missing_wallet = subprocess.run(
        ["sh", str(installer), "--hotkey-name", "default", "--wallet-path", "/wallets"],
        text=True,
        capture_output=True,
        check=False,
        env=environment,
    )
    assert missing_wallet.returncode == 2
    assert "--wallet-name is required" in missing_wallet.stderr


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
    assert "/var/lib/umi-validator-bootstrap-upload" not in source
    read_write = source.split("ReadWritePaths=", 1)[1].splitlines()[0]
    assert "/var/lib/umi-validator-worker-state" in read_write
    assert "/var/lib/umi-validator-runtime-wallets" not in read_write
    assert "MemoryMax=17179869184\n" in source
    assert "TasksMax=640\n" in source
    assert "TimeoutStopSec=180s\n" in source
