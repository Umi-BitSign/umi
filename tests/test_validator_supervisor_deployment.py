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
    runtime_smoke_stage = source.index(
        'install -o root -g root -m 0644 "$service_source" "$runtime_service_destination"'
    )
    runtime_smoke_start = source.index('systemctl start "$service_name"')
    runtime_smoke_remove = source.index("remove_runtime_smoke_unit", runtime_smoke_start)
    legacy_stop = source.index('systemctl disable --now "$legacy_unit"')
    survivor_check = source.index('require_empty_unit_control_group "$legacy_control_group"')
    config_install = source.index('mv -- "$config_stage" "$config_destination"')
    service_start = source.index('systemctl enable --now "$service_name"')
    assert (
        release_preflight
        < runtime_smoke_stage
        < runtime_smoke_start
        < runtime_smoke_remove
        < legacy_stop
        < survivor_check
        < config_install
        < service_start
    )
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
    assert (
        source.count(
            "CONTAINERS_CONF_OVERRIDE=/opt/umi-validator-supervisor/deploy/"
            "linux-validator-supervisor/containers.conf"
        )
        == 2
    )
    assert source.count("-- env -i \\\n") == 2
    assert "/usr/bin/timeout --signal=TERM --kill-after=5s 30s" in source
    assert 'while [ "$readiness_attempt" -lt 180 ]' in source
    assert 'find "$supervisor_root" -xdev ! -type l' in source
    assert 'find "$supervisor_root" -xdev -type l ! -user root' in source
    assert 'target=$(readlink -f -- "$link")' in source
    assert '"$root"/*' in source
    assert "apt-get install -y --no-install-recommends" in source
    assert "--no-upgrade" in source
    assert "--no-remove" in source
    assert " util-linux systemd " not in source
    assert "tar timeout useradd" in source
    assert "podman --version | awk '{print $3}'" in source
    assert 'fail "Podman 4.3.0 or later is required; found $podman_version"' in source
    assert source.index("podman_version=") < source.index("script_directory=")
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
    assert 'containers_conf_source="$installed_deploy/containers.conf"' in source
    assert 'chmod 0444 "$containers_conf_source"' in source
    assert 'chmod 0555 "$podman_smoke_source"' in source
    assert 'chmod 0444 "$runtime_smoke_dropin_source"' in source


def test_runtime_smoke_unit_is_exact_inert_and_always_cleaned() -> None:
    source = (DEPLOYMENT / "install.sh").read_text()
    dropin = (DEPLOYMENT / "runtime-smoke.conf").read_text()

    assert dropin == ("[Service]\nType=oneshot\nExecStart=\nExecStart=/usr/bin/true\nRestart=no\n")
    assert 'runtime_service_destination="/run/systemd/system/$service_name"' in source
    assert 'runtime_service_dropin_directory="/run/systemd/system/$service_name.d"' in source
    runtime_path_guard = source.index(
        '[ ! -e "$runtime_service_destination" ] && [ ! -L "$runtime_service_destination" ]'
    )
    runtime_dropin_guard = source.index('[ ! -e "$runtime_service_dropin_directory" ]')
    loaded_name_guard = source.index(
        'service_load_state=$(systemctl show "$service_name" --property=LoadState --value)'
    )
    installer_mutation = source.index(
        "temporary_root=$(mktemp -d /tmp/umi-validator-supervisor-install.XXXXXXXX)"
    )
    assert runtime_path_guard < installer_mutation
    assert runtime_dropin_guard < installer_mutation
    assert loaded_name_guard < installer_mutation
    assert "runtime_smoke_staged=true\ninstall -o root" in source
    assert "cleanup() {\n  cleanup_runtime_smoke_unit" in source
    assert "trap cleanup EXIT HUP INT TERM" in source

    cleanup_function = source.split("remove_runtime_smoke_unit() {", 1)[1].split("\n}\n", 1)[0]
    stop = cleanup_function.index('systemctl stop "$service_name"')
    remove_dropin = cleanup_function.index('rm -f -- "$runtime_service_dropin_destination"')
    remove_unit = cleanup_function.index('rm -f -- "$runtime_service_destination"')
    reset = cleanup_function.index('systemctl reset-failed "$service_name"')
    reload = cleanup_function.index("systemctl daemon-reload")
    assert stop < remove_dropin < remove_unit < reset < reload

    stage = source.split("# Rehearse the exact production unit name", 1)[1].split(
        'if [ -n "$legacy_unit" ]', 1
    )[0]
    assert '"$service_source" "$runtime_service_destination"' in stage
    assert '"$runtime_smoke_dropin_source" "$runtime_service_dropin_destination"' in stage
    assert 'sha256sum "$service_source"' in stage
    assert 'sha256sum "$runtime_service_destination"' in stage
    assert 'sha256sum "$runtime_smoke_dropin_source"' in stage
    assert 'sha256sum "$runtime_service_dropin_destination"' in stage
    assert "FragmentPath" in stage and "DropInPaths" in stage
    assert "Type --value" in stage and "Restart --value" in stage
    assert "RuntimeDirectoryPreserve --value" in stage
    assert "path=/usr/bin/true" in stage and "argv[]=/usr/bin/true" in stage
    assert stage.index('systemctl start "$service_name"') < stage.index("remove_runtime_smoke_unit")


def test_linux_supervisor_service_user_wrappers_start_from_public_cwd() -> None:
    source = (DEPLOYMENT / "install.sh").read_text()

    for function_name in ("supervisor", "podman_as_service"):
        function = source.split(f"{function_name}() {{", 1)[1].split("\n}\n", 1)[0]
        assert function.index("CDPATH= cd -- /") < function.index("runuser -u")


def test_documented_status_command_starts_from_public_cwd() -> None:
    source = (ROOT / "docs" / "PERMANENT_VALIDATOR_SUPERVISOR.md").read_text()
    status_block = (
        source.split("## Check the service", 1)[1].split("```sh", 1)[1].split("```", 1)[0]
    )

    assert status_block.index("cd /") < status_block.index("sudo -u umi-validator env -i")


def test_operator_guide_requires_supported_podman_and_distributions() -> None:
    source = (ROOT / "docs" / "PERMANENT_VALIDATOR_SUPERVISOR.md").read_text()

    assert "Ubuntu 24.04 or later" in source
    assert "Debian 12 or later" in source
    assert "Podman 4.3.0 or later" in source


def test_podman_runtime_configuration_and_service_smoke_are_fixed() -> None:
    containers_conf = (DEPLOYMENT / "containers.conf").read_text()
    assert '[engine]\ncgroup_manager = "cgroupfs"' in containers_conf
    assert containers_conf.splitlines()[-2:] == ["[containers]", "default_sysctls = []"]

    smoke = DEPLOYMENT / "podman-runtime-smoke.sh"
    subprocess.run(["sh", "-n", str(smoke)], check=True)
    smoke_source = smoke.read_text()
    assert "CONTAINERS_CONF_OVERRIDE=" in smoke_source
    assert "/usr/bin/timeout --signal=TERM --kill-after=5s 60s" in smoke_source
    assert "--network slirp4netns:allow_host_loopback=false" in smoke_source
    assert "--entrypoint /bin/sh" in smoke_source
    assert "/sys/fs/cgroup/memory.max" in smoke_source
    assert "/sys/fs/cgroup/pids.max" in smoke_source
    assert "/sys/fs/cgroup/cpu.max" in smoke_source
    mount_lines = [
        line.strip() for line in smoke_source.splitlines() if line.strip().startswith("--mount")
    ]
    assert mount_lines == [
        '--mount "type=bind,src=$readonly_mount,dst=/run/umi-smoke-readonly,'
        'ro=true,bind-propagation=private" \\',
        '--mount "type=bind,src=$readwrite_mount,dst=/run/umi-smoke-readwrite,'
        'ro=false,bind-propagation=private" \\',
    ]
    for forbidden_source in (
        "umi-validator-runtime-wallets",
        "umi-validator-operator-inputs",
        "umi-validator-worker-state",
    ):
        assert forbidden_source not in smoke_source
    assert "require_empty_dummy_mounts" in smoke_source

    service = (DEPLOYMENT / "umi-validator-supervisor.service").read_text()
    assert (
        "ExecStartPre=/opt/umi-validator-supervisor/deploy/"
        "linux-validator-supervisor/podman-runtime-smoke.sh\n" in service
    )
    assert (
        "CONTAINERS_CONF_OVERRIDE=/opt/umi-validator-supervisor/deploy/"
        "linux-validator-supervisor/containers.conf" in service
    )
    for incompatible_directive in (
        "ProtectHostname=true",
        "ProtectKernelLogs=true",
        "ProtectKernelTunables=true",
    ):
        assert incompatible_directive not in service
    assert "User=umi-validator\n" in service
    assert "AmbientCapabilities=\n" in service
    assert "ProtectKernelModules=true\n" in service
    assert "ProtectProc=invisible\n" in service
    assert "RuntimeDirectoryPreserve=yes\n" in service
    assert "TimeoutStartSec=180s\n" in service
    assert "Delegate=true\n" in service
    assert "/var/lib/umi-validator-runtime-smoke/readonly" in service
    assert "/var/lib/umi-validator-runtime-smoke/readwrite" in service


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
