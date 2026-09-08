from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "deploy" / "public-pilot-automation" / "systemd"


def test_controller_unit_keeps_wallet_and_github_write_boundaries_separate() -> None:
    unit = (ASSETS / "umi-public-pilot-controller.service").read_text()

    assert "User=sam" in unit
    assert "Group=sam" in unit
    assert "SupplementaryGroups=umi-pilot" in unit
    assert "LoadCredential=github-auth-hmac:" in unit
    assert "LoadCredential=result-hmac:" in unit
    assert "LoadCredential=upload-hmac:" in unit
    assert "--github-token-file" not in unit
    assert "ReadOnlyPaths=/etc/umi /opt/umi-public-pilot " in unit
    assert "/home/sam/umi-coordinator/private/wallets" in unit
    assert "ReadWritePaths=/var/lib/umi-public-pilot-controller " in unit
    assert "/var/spool/umi-public-pilot/incoming" in unit
    assert "InaccessiblePaths=/var/lib/umi-observer " in unit
    assert "/var/spool/umi-public-pilot/consumer" in unit


def test_spool_unit_is_the_observer_owned_single_writer() -> None:
    unit = (ASSETS / "umi-public-pilot-spool.service").read_text()

    assert "Type=oneshot" in unit
    assert "User=umi-observer" in unit
    assert "Group=umi-observer" in unit
    assert "SupplementaryGroups=umi-pilot" in unit
    for option in (
        "--incoming-dir",
        "--processing-dir",
        "--processed-dir",
        "--quarantine-dir",
        "--receipts-dir",
        "--work-root",
        "--publication-root",
        "--config",
        "--lock",
        "--spool-lock",
        "--public-origin",
        "--expected-coordinator-hotkey",
        "--producer-uid",
        "--producer-gid",
    ):
        assert option in unit
    assert "--config /var/lib/umi-observer/pilot-feed/observer-pilot-feed.json" in unit
    assert "--publication-root /var/lib/umi-observer/pilots" in unit
    assert "--processing-dir /var/spool/umi-public-pilot/consumer/processing" in unit
    assert "--processed-dir /var/spool/umi-public-pilot/consumer/processed" in unit
    assert "--quarantine-dir /var/spool/umi-public-pilot/consumer/quarantine" in unit
    assert "--receipts-dir /var/spool/umi-public-pilot/consumer/receipts" in unit
    assert "--work-root /var/spool/umi-public-pilot/consumer/work" in unit
    assert "--lock /var/spool/umi-public-pilot/consumer/publication.lock" in unit
    assert "--spool-lock /var/spool/umi-public-pilot/consumer/consumer.lock" in unit
    assert "ReadWritePaths=/var/spool/umi-public-pilot " in unit
    assert unit.count("ReadWritePaths=/var/spool/umi-public-pilot") == 1
    assert "ReadWritePaths=/var/spool/umi-public-pilot/incoming " not in unit
    assert "/var/lib/umi-public-pilot-spool" not in unit
    assert "ExecStartPost=+/usr/bin/systemctl try-restart umi-observer.service" in unit
    assert "InaccessiblePaths=/home/sam/umi-coordinator/private " in unit
    assert "/var/lib/umi-public-pilot-controller" in unit


def test_spool_handoff_directories_have_exact_owners_and_modes() -> None:
    tmpfiles = (ASSETS / "umi-public-pilot.tmpfiles").read_text()
    sysusers = (ASSETS / "umi-public-pilot.sysusers").read_text()

    assert "g umi-pilot -" in sysusers
    assert "m sam umi-pilot" in sysusers
    assert "m umi-observer umi-pilot" in sysusers
    assert "d /var/spool/umi-public-pilot/incoming 2770 sam umi-pilot -" in tmpfiles
    assert "d /var/spool/umi-public-pilot/consumer 0700 umi-observer umi-observer -" in tmpfiles
    for name in ("processing", "processed", "quarantine", "receipts", "work"):
        assert (
            f"d /var/spool/umi-public-pilot/consumer/{name} 0700 umi-observer umi-observer -"
        ) in tmpfiles
    assert "d /var/lib/umi-public-pilot-controller 0700 sam sam -" in tmpfiles
    assert "/var/lib/umi-public-pilot-spool" not in tmpfiles
    assert "d /var/lib/umi-observer/pilot-feed 0700 umi-observer umi-observer -" in tmpfiles


def test_observer_drop_in_makes_spool_managed_paths_read_only() -> None:
    drop_in = (ASSETS / "umi-observer-public-pilot.conf").read_text()

    assert "[Service]" in drop_in
    assert "ExecStart=\n" in drop_in
    assert "ExecStart=/opt/umi-observer/.venv/bin/python -m umi.observer" in drop_in
    assert "--pilot-feed-config ${UMI_OBSERVER_PILOT_FEED_CONFIG}" in drop_in
    assert "ReadOnlyPaths=/var/lib/umi-observer/pilot-feed /var/lib/umi-observer/pilots" in drop_in


def test_install_runbook_matches_the_actual_host_and_pinned_checkout() -> None:
    runbook = (ASSETS / "README.md").read_text()

    assert "Four GiB of RAM is the recommended production size" in runbook
    assert "available memory remains below 150 MiB" in runbook
    assert "ssh -A sam@172.239.57.201" in runbook
    assert "git@github.com:Umi-BitSign/umi.git" in runbook
    assert 'git -C "$release_checkout" checkout --detach "$umi_revision"' in runbook
    assert "uv==0.12.9" in runbook
    assert "UV_PROJECT_ENVIRONMENT=/opt/umi-public-pilot/.venv" in runbook
    assert "observer_python=/opt/umi-observer/.venv/bin/python" in runbook
    assert "observer_base_python=" in runbook
    assert '--python "$observer_base_python"' in runbook
    assert 'test "$observer_environment" = "$automation_environment"' in runbook
    assert "jq -cSj --arg revision" in runbook
    assert "/opt/umi-public-pilot/source/deploy/public-pilot-automation/systemd/" in runbook
    assert "/var/lib/umi-observer/pilot-feed/observer-pilot-feed.json" in runbook
    assert "UMI_OBSERVER_PILOT_FEED_CONFIG" in runbook
    assert "umi-observer-public-pilot.conf" in runbook
    assert "grep -Fzxq -- '--pilot-feed-config'" in runbook
    assert "https://api.umi.vision/api/v1/network" in runbook
