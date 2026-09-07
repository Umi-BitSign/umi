from __future__ import annotations

import json
import os
import plistlib
import re
import stat
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEPLOYMENT = ROOT / "deploy" / "macos-validator"


def test_management_scripts_are_executable_and_parse_as_posix_shell() -> None:
    for name in (
        "manage.sh",
        "container-entrypoint.sh",
        "clean-compose-environment.sh",
    ):
        path = DEPLOYMENT / name
        mode = stat.S_IMODE(path.stat().st_mode)
        assert mode & 0o111 == 0o111
        assert mode & 0o022 == 0
        parsed = subprocess.run(
            ["/bin/sh", "-n", str(path)],
            check=False,
            capture_output=True,
            text=True,
        )
        assert parsed.returncode == 0, parsed.stderr


def test_compose_contract_is_bounded_and_wallet_is_absent_from_publisher() -> None:
    compose = (DEPLOYMENT / "compose.yaml").read_text(encoding="utf-8")
    required = (
        "name: umi-macos-validator-${UMI_DEPLOYMENT_ID:?set UMI_DEPLOYMENT_ID}",
        "platform: ${UMI_VALIDATOR_PLATFORM:-linux/amd64}",
        "pull_policy: never",
        "read_only: true",
        "no-new-privileges:true",
        "pids_limit: 512",
        "mem_limit: ${UMI_VALIDATOR_MEMORY_LIMIT:-12g}",
        "cap_drop:",
        "source: ${UMI_WALLET_ROOT:?set UMI_WALLET_ROOT}",
        "target: /wallets",
        "source: validator-state",
        "target: /private",
        "create_host_path: false",
        "source: audit-publication",
        "subpath: public",
    )
    assert all(value in compose for value in required)
    publisher = compose.split("  audit-publisher:\n", 1)[1]
    assert "UMI_WALLET_ROOT" not in publisher
    assert "target: /wallets" not in publisher
    assert "source: validator-state\n        target: /private\n        read_only: true" in publisher


def test_bootstrap_commands_have_no_wallet_mount_and_runtime_logs_are_bounded() -> None:
    compose = (DEPLOYMENT / "compose.yaml").read_text(encoding="utf-8")
    bootstrap = compose.split("  bootstrap:\n", 1)[1].split("  validator:\n", 1)[0]
    assert "UMI_WALLET_ROOT" not in bootstrap
    assert "target: /wallets" not in bootstrap
    assert "max-size: 10m" in compose
    assert 'max-file: "5"' in compose
    assert compose.count("pull_policy: never") == 3


def test_audit_publication_uses_one_atomic_volume_and_a_public_only_origin_mount() -> None:
    compose = (DEPLOYMENT / "compose.yaml").read_text(encoding="utf-8")
    publisher = compose.split("  audit-publisher:\n", 1)[1].split("  audit-origin:\n", 1)[0]
    origin = compose.split("  audit-origin:\n", 1)[1].split("\nvolumes:\n", 1)[0]
    entrypoint = (DEPLOYMENT / "container-entrypoint.sh").read_text(encoding="utf-8")
    assert "source: audit-publication\n        target: /publication" in publisher
    assert "source: audit-publication\n        target: /srv/www/umi-audits" in origin
    assert "subpath: public" in origin
    assert "UMI_WALLET_ROOT" not in origin
    assert "/publication/staging" in entrypoint
    assert "/publication/public" in entrypoint


def test_container_audit_origin_is_host_loopback_only_but_container_reachable() -> None:
    compose = (DEPLOYMENT / "compose.yaml").read_text(encoding="utf-8")
    origin = compose.split("  audit-origin:\n", 1)[1].split("\nvolumes:\n", 1)[0]
    caddyfile = (DEPLOYMENT / "Caddyfile").read_text(encoding="utf-8")
    assert '"127.0.0.1:${UMI_AUDIT_ORIGIN_PORT:-8093}:8093"' in compose
    assert "source: ./Caddyfile" in compose
    assert "mode=0700,uid=${UMI_HOST_UID:?set UMI_HOST_UID}" in compose
    assert "gid=${UMI_HOST_GID:?set UMI_HOST_GID}" in compose
    assert "bind 0.0.0.0" in caddyfile
    assert "bind 127.0.0.1" not in caddyfile
    assert "@non_read not method GET HEAD" in caddyfile
    assert "cap_add:" not in origin

    caddy_dockerfile = (DEPLOYMENT / "Caddy.Dockerfile").read_text(encoding="utf-8")
    assert re.search(r"caddy:2[.]10[.]2-alpine@sha256:[0-9a-f]{64}", caddy_dockerfile)
    assert "setcap -r /usr/bin/caddy" in caddy_dockerfile
    assert 'test -z "$(getcap /usr/bin/caddy)"' in caddy_dockerfile


def test_macos_audit_tunnel_is_token_file_only_and_supervised() -> None:
    template_path = DEPLOYMENT / "launchd" / "vision.umi.validator-audit-tunnel.plist.in"
    tunnel = plistlib.loads(template_path.read_bytes())
    arguments = tunnel["ProgramArguments"]
    assert tunnel["Label"] == "vision.umi.validator-audit-tunnel"
    assert tunnel["RunAtLoad"] is True
    assert tunnel["KeepAlive"] is True
    assert "--token-file" in arguments
    assert "--token" not in arguments
    assert arguments[-1] == "REPLACE_WITH_TUNNEL_TOKEN_FILE"
    assert "127.0.0.1:49093" in arguments
    assert tunnel["StandardOutPath"] == "/dev/null"
    assert tunnel["StandardErrorPath"] == "/dev/null"
    runbook = (DEPLOYMENT / "launchd" / "README.md").read_text(encoding="utf-8")
    assert "http://127.0.0.1:8093" in runbook
    assert "PUBLIC_AUDIT_ORIGIN" in runbook
    assert "Do not post the token" in runbook


def test_compose_file_resolves_with_only_declared_public_configuration() -> None:
    docker = subprocess.run(
        ["docker", "compose", "version"],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if docker.returncode != 0:
        return
    environment = {
        **os.environ,
        "UMI_HOST_UID": str(os.getuid()),
        "UMI_HOST_GID": str(os.getgid()),
        "UMI_GIT_REVISION": "1" * 40,
        "UMI_DEPLOYMENT_ID": "test-" + "1" * 40,
        "UMI_VALIDATOR_IMAGE": "umi-validator:" + "1" * 40,
        "UMI_RELEASE_ROOT": "/tmp/umi-release",
        "UMI_OPERATOR_INPUT_ROOT": "/tmp/umi-inputs",
        "UMI_WALLET_ROOT": "/tmp/umi-wallets",
        "UMI_AUDIT_PUBLISHER_INPUT_ROOT": "/tmp/umi-publisher-inputs",
        "UMI_EXPECTED_AUTHORITY_HOTKEY": "5ExpectedAuthority",
        "UMI_VALIDATOR_HOTKEY": "5ExpectedValidator",
        "UMI_VALIDATOR_ACCOUNT_HEX": "2" * 64,
    }
    result = subprocess.run(
        [
            "docker",
            "compose",
            "-f",
            str(DEPLOYMENT / "compose.yaml"),
            "config",
            "--format",
            "json",
        ],
        cwd=ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    resolved = json.loads(result.stdout)
    assert resolved["name"] == "umi-macos-validator-test-" + "1" * 40
    assert {
        name: resolved["services"][name].get("pull_policy")
        for name in ("volume-init", "bootstrap", "validator", "audit-publisher")
    } == {
        "volume-init": "never",
        "bootstrap": "never",
        "validator": "never",
        "audit-publisher": "never",
    }
    assert resolved["services"]["audit-origin"].get("pull_policy") == "never"
    assert resolved["services"]["audit-origin"]["image"] == (
        "umi-validator-audit-origin:" + "1" * 40
    )


def test_runner_image_is_revision_bound_and_contains_no_secret_interface() -> None:
    dockerfile = (DEPLOYMENT / "Dockerfile").read_text(encoding="utf-8")
    entrypoint = (DEPLOYMENT / "container-entrypoint.sh").read_text(encoding="utf-8")
    assert re.search(r"python:3[.]12[.]12-slim-bookworm@sha256:[0-9a-f]{64}", dockerfile)
    assert re.search(r"ghcr[.]io/astral-sh/uv:0[.]12[.]9@sha256:[0-9a-f]{64}", dockerfile)
    assert 'test "$(uv --version)" = "uv 0.12.9 (x86_64-unknown-linux-musl)"' in dockerfile
    assert "UMI_GIT_REVISION" in dockerfile
    assert "image/release revision mismatch" in entrypoint
    assert "runtime wallet tree contains an unexpected file" in entrypoint
    assert "runtime wallet tree contains an unexpected directory" in entrypoint
    assert 'wallet_path != "/wallets"' in entrypoint
    assert 'wallet_root / wallet_name / "hotkeys" / hotkey_name' in entrypoint
    assert "runtime wallet directory ownership or mode is unsafe" in entrypoint
    assert "runtime wallet file ownership, links, or mode are unsafe" in entrypoint
    forbidden = ("WALLET_PASSWORD", "SEED_PHRASE", "PRIVATE_KEY", "--password")
    assert not any(value in entrypoint for value in forbidden)


def test_management_script_never_deletes_runtime_state() -> None:
    manager = (DEPLOYMENT / "manage.sh").read_text(encoding="utf-8")
    assert "down -v" not in manager
    assert "docker volume rm" not in manager
    assert "/bin/rm" not in manager
    assert "rm -r" not in manager
    assert "run --rm --no-deps --pull never" in manager
    assert "compose build --pull validator audit-origin" in manager
    assert "up --detach --no-deps --no-build --pull never validator" in manager
    assert '--env "UMI_RECOVERY_WINDOW_ID=$recovery_window_id" bootstrap reconcile' in manager
    assert '--project-name "$compose_project"' in manager
    assert "UMI_DEPLOYMENT_ID must use lowercase letters" in manager
    assert "stop the validator before reconcile" in manager
    assert "stop the audit publisher before reconcile" in manager
    assert "--status running --status restarting --status paused" in manager


def test_env_file_wins_over_hostile_ambient_compose_values(tmp_path: Path) -> None:
    docker = subprocess.run(
        ["docker", "compose", "version"],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if docker.returncode != 0:
        return
    deployment_id = "reviewed-release"
    revision = "1" * 40
    values = {
        "UMI_GIT_REVISION": revision,
        "UMI_VALIDATOR_IMAGE": f"umi-validator:{revision}",
        "UMI_DEPLOYMENT_ID": deployment_id,
        "UMI_VALIDATOR_PLATFORM": "linux/amd64",
        "UMI_VALIDATOR_MEMORY_LIMIT": "12g",
        "UMI_VALIDATOR_CPUS": "8.0",
        "UMI_AUDIT_ORIGIN_PORT": "18093",
        "UMI_RELEASE_ROOT": "/tmp/reviewed-release",
        "UMI_OPERATOR_INPUT_ROOT": "/tmp/reviewed-input",
        "UMI_WALLET_ROOT": "/tmp/reviewed-wallet",
        "UMI_AUDIT_PUBLISHER_INPUT_ROOT": "/tmp/reviewed-publisher",
        "UMI_EXPECTED_AUTHORITY_HOTKEY": "5ReviewedAuthority",
        "UMI_VALIDATOR_HOTKEY": "5ReviewedValidator",
        "UMI_VALIDATOR_ACCOUNT_HEX": "2" * 64,
    }
    env_file = tmp_path / "operator.env"
    env_file.write_text(
        "".join(f"{key}={value}\n" for key, value in values.items()),
        encoding="utf-8",
    )
    environment = {
        **os.environ,
        **{key: "hostile-ambient-value" for key in values},
        "COMPOSE_PROJECT_NAME": "hostile-ambient-project",
    }
    result = subprocess.run(
        [
            str(DEPLOYMENT / "clean-compose-environment.sh"),
            "docker",
            "compose",
            "--project-name",
            f"umi-macos-validator-{deployment_id}",
            "--env-file",
            str(env_file),
            "--file",
            str(DEPLOYMENT / "compose.yaml"),
            "config",
            "--format",
            "json",
        ],
        cwd=ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    resolved = json.loads(result.stdout)
    assert resolved["name"] == f"umi-macos-validator-{deployment_id}"
    assert resolved["services"]["validator"]["image"] == values["UMI_VALIDATOR_IMAGE"]
    assert resolved["services"]["validator"]["environment"] == {
        "BITTENSOR_RUNTIME_CACHE_DIR": "/private/cache/bittensor-runtime",
        "HOME": "/private/home",
        "PYTHONUNBUFFERED": "1",
        "UMI_EXPECTED_AUTHORITY_HOTKEY": "5ReviewedAuthority",
        "UMI_VALIDATOR_ACCOUNT_HEX": "2" * 64,
        "UMI_VALIDATOR_HOTKEY": "5ReviewedValidator",
    }


def test_certificate_breach_recovery_is_wallet_free_and_path_constrained() -> None:
    compose = (DEPLOYMENT / "compose.yaml").read_text(encoding="utf-8")
    entrypoint = (DEPLOYMENT / "container-entrypoint.sh").read_text(encoding="utf-8")
    manager = (DEPLOYMENT / "manage.sh").read_text(encoding="utf-8")
    bootstrap = compose.split("  bootstrap:\n", 1)[1].split("  validator:\n", 1)[0]
    assert "UMI_WALLET_ROOT" not in bootstrap
    assert "reconcile 64_LOWERCASE_HEX_WINDOW_ID" in (
        ROOT / "docs" / "MACOS_VALIDATOR_OPERATOR.md"
    ).read_text(encoding="utf-8")
    assert "certificate-breach-recovery/$UMI_RECOVERY_WINDOW_ID" in entrypoint
    assert "incident-bundles/$UMI_RECOVERY_WINDOW_ID" in entrypoint
    assert "exec umi-validator-live-reconcile" in entrypoint
    assert "reconcile requires one 64-character window ID" in manager


def test_docker_context_is_allowlisted_and_excludes_ignored_credentials() -> None:
    dockerignore = (ROOT / ".dockerignore").read_text(encoding="utf-8")
    required = (
        "**",
        "!pyproject.toml",
        "!uv.lock",
        "!src/**",
        "!deploy/macos-validator/Caddy.Dockerfile",
        "!deploy/macos-validator/container-entrypoint.sh",
        "**/.env.*",
        "**/.envrc",
        "**/.bittensor/",
        "**/wallets/",
        "**/*.pem",
        "**/*.egg-info/",
        "**/.mypy_cache/",
        "**/build/",
        "**/target/",
    )
    assert all(pattern in dockerignore for pattern in required)


def test_apple_silicon_validator_docs_name_one_initial_cohort_target() -> None:
    validator_guide = (ROOT / "docs" / "MACOS_VALIDATOR_OPERATOR.md").read_text(encoding="utf-8")
    miner_guide = (ROOT / "docs" / "MACOS_MINER_OPERATOR.md").read_text(encoding="utf-8")
    assert "bounded `linux/amd64` Docker Desktop route" in miner_guide
    assert "colima start" not in miner_guide
    assert "Do not substitute a native ARM64 Linux VM" in miner_guide
    assert "real Apple Silicon run" in validator_guide
    assert "UMI_DEPLOYMENT_ID" in validator_guide
    assert "does not implement release rotation" in validator_guide
    assert "initialize a fresh deployment as an upgrade" in validator_guide
