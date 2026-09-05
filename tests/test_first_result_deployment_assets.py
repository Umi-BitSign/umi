import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "deploy" / "first-public-result"


def test_caddy_origin_is_read_only_exact_and_media_free() -> None:
    config = (ROOT / "caddy" / "Caddyfile.audit-origin.example").read_text()

    assert "bind 127.0.0.1" in config
    assert "@non_read not method GET HEAD" in config
    assert 'header @non_read Allow "GET, HEAD"' in config
    assert "respond @non_read 405" in config
    assert "disable_canonical_uris" in config
    assert "no-transform" in config
    assert "no-cache, no-store, must-revalidate" in config
    assert "max-age=31536000, immutable" in config
    assert "Content-Encoding identity" in config
    assert "file_server browse" not in config
    assert "precompressed" not in config
    assert "encode " not in config
    assert "reverse_proxy" not in config
    assert "/media/" not in config


def test_cloudflared_examples_are_loopback_only_and_fail_closed() -> None:
    configs = sorted((ROOT / "cloudflared").glob("*.yml.example"))
    assert len(configs) == 2

    for path in configs:
        config = path.read_text()
        assert "service: http://127.0.0.1:" in config
        assert config.rstrip().endswith("- service: http_status:404")
        assert "token:" not in config.lower()
        assert "secret:" not in config.lower()


def test_systemd_units_are_unprivileged_and_have_no_wallet_capability() -> None:
    units = sorted((ROOT / "systemd").glob("*.service"))
    assert len(units) == 2

    for path in units:
        unit = path.read_text()
        assert "User=root" not in unit
        assert "NoNewPrivileges=true" in unit
        assert "ProtectHome=true" in unit
        assert "ProtectSystem=strict" in unit
        assert "StateDirectoryMode=0700" in unit
        assert "RuntimeDirectoryMode=0700" in unit
        assert "CapabilityBoundingSet=\n" in unit
        assert "AmbientCapabilities=\n" in unit

    publisher = (ROOT / "systemd" / "umi-validator-audit-publish.service").read_text()
    assert "User=umi-validator" in publisher
    assert "InaccessiblePaths=/REPLACE_WITH_ABSOLUTE_WALLET_PARENT" in publisher
    assert "User=umi-audit-publisher" not in publisher


def test_environment_examples_contain_no_secret_fields() -> None:
    environments = sorted((ROOT / "systemd").glob("*.env.example"))
    assert len(environments) == 2

    forbidden = ("private_key=", "secret=", "token=", "password=", "mnemonic=")
    for path in environments:
        content = path.read_text().lower()
        assert not any(item in content for item in forbidden)


def test_local_observer_probe_uses_the_configured_trusted_host() -> None:
    runbook = (ROOT / "README.md").read_text()

    assert "-H 'Host: api.umi.vision'" in runbook
    assert "http://127.0.0.1:8092/healthz" in runbook


def test_runbook_delegates_owner_activity_cutoff_to_verified_handoff() -> None:
    runbook = (ROOT / "README.md").read_text()
    handoff = (ROOT / "owner-cutoff" / "README.md").read_text()

    assert "[`owner-cutoff/README.md`](owner-cutoff/README.md)" in runbook
    assert "btcli sudo set --network" not in runbook
    assert '"$BTCLI" tx set-hyperparameter' in handoff
    assert "--name activity_cutoff_factor" in handoff
    assert "--value 1000" in handoff
    assert "--dry-run" in handoff
    assert "deliberately omits `--yes`" in handoff
    assert "Do not substitute a\nbest-head read" in handoff
    assert "first live UMI weight-build snapshot" in handoff


def test_runbook_preserves_owner_only_validator_bundle_modes() -> None:
    runbook = (ROOT / "README.md").read_text()

    assert "Do not add ACLs, group access, or relaxed modes" in runbook
    assert "sudo -u umi-validator" in runbook
    assert "sudo install -d -o root -g root -m 0755 /etc/umi" in runbook
    assert "remaining `REPLACE_WITH` token is a deployment failure" in runbook
    assert "does not provide a fake production-bundle generator" in runbook
    assert "database binds that\nentire sorted set on first open" in runbook
    assert "/solutions?validator=<account_id32>" in runbook


def test_runbook_has_fail_closed_install_and_service_checks() -> None:
    runbook = (ROOT / "README.md").read_text()

    assert "python3 check-placeholders.py" in runbook
    assert "--observer-feed /etc/umi/observer-bundle-feed.json" in runbook
    assert "cloudflared --config /etc/cloudflared/config.yml service install" in runbook
    assert "systemctl is-active --quiet umi-observer.service" in runbook
    assert "systemctl is-active --quiet umi-validator-audit-publish.service" in runbook
    assert 'nsenter --mount="/proc/${UMI_PUBLISHER_PID}/ns/mnt"' in runbook


def test_runbook_static_probe_is_disposable_unindexed_and_exact() -> None:
    runbook = (ROOT / "README.md").read_text()

    assert "UMI_PROBE_ACCOUNT=" + ("0" * 64) in runbook
    assert "never creates an index entry" in runbook
    assert 'test ! -e "${UMI_PROBE_FILE}"' in runbook
    assert "trap cleanup_umi_static_probe EXIT" in runbook
    assert "Accept-Encoding: identity" in runbook
    assert 'test "${status}" = 200' in runbook
    assert 'test -w "${UMI_PROBE_DIRECTORY}"' in runbook
    assert "not-a-protocol-route" in runbook
    assert "fake production-bundle generator" in runbook


def test_runbook_clean_replay_starts_from_empty_state_and_public_origins() -> None:
    runbook = (ROOT / "README.md").read_text()

    assert "Do not copy the\nproduction observer database" in runbook
    assert 'test ! -e "${UMI_REPLAY_ROOT}/bundle-feed.sqlite3"' in runbook
    assert 'payload["state_database_path"]' in runbook
    assert 'payload["temporary_root"]' in runbook
    assert "UMI_REPLAY_OUTPUT=" in runbook
    assert '-o "${UMI_REPLAY_OUTPUT}/windows.json"' in runbook
    assert '--unit="${UMI_REPLAY_UNIT}" --collect' in runbook
    assert '.status == "current" and .accepted_entries > 0' in runbook
    assert '.protocol_state.phase == "shadow_calibration"' in runbook
    assert "REPLACE_WITH_WINDOW_ID" in runbook
    assert "REPLACE_WITH_VALIDATOR_ACCOUNT_ID32" in runbook


def test_placeholder_checker_rejects_examples_and_expands_observer_targets(
    tmp_path: Path,
) -> None:
    checker = ROOT / "check-placeholders.py"
    publication = tmp_path / "publication.json"
    publication.write_text('{"public_origin":"https://audits.example.org"}')
    feed = tmp_path / "feed.json"
    feed.write_text(
        json.dumps(
            {
                "targets": [
                    {"publication_config_path": str(publication)},
                ]
            }
        )
    )
    installed = tmp_path / "installed.conf"
    installed.write_text("tunnel: 00000000-0000-0000-0000-000000000001")

    failed = subprocess.run(
        [
            sys.executable,
            str(checker),
            "--observer-feed",
            str(feed),
            str(installed),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert failed.returncode == 1
    assert "https://audits.example.org" in failed.stderr

    publication.write_text('{"public_origin":"https://audit-validator-1.umi.vision"}')
    passed = subprocess.run(
        [
            sys.executable,
            str(checker),
            "--observer-feed",
            str(feed),
            str(installed),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert passed.returncode == 0
    assert "deployment_files_resolved=3" in passed.stdout


def test_macos_launchd_assets_pass_their_self_test() -> None:
    completed = subprocess.run(
        [sys.executable, str(ROOT / "launchd" / "test_assets.py")],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
