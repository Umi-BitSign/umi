from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

SOURCE = Path(__file__).parents[1] / "deploy/miner-upgrade/upgrade.py"
spec = importlib.util.spec_from_file_location("package_restart_policy_upgrade", SOURCE)
assert spec is not None and spec.loader is not None
upgrade = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = upgrade
spec.loader.exec_module(upgrade)


def install(root):
    return upgrade.install_package_restart_policy(root, owner=(os.geteuid(), os.getegid()))


def test_first_and_repeat_install_preserve_exact_control(tmp_path):
    first = install(tmp_path)
    target = Path(first["path"])
    before = target.stat()
    assert target.read_bytes() == upgrade.PACKAGE_RESTART_POLICY
    assert first["status"] == "installed"
    assert first["services_restarted"] is False
    assert first["security_package_updates_enabled"] is True
    again = install(tmp_path)
    assert again["status"] == "reused"
    assert target.stat().st_ino == before.st_ino
    assert target.stat().st_mtime_ns == before.st_mtime_ns
    assert not target.stat().st_mode & 0o022


@pytest.mark.parametrize(
    "kind",
    ["symlink_directory", "symlink_file", "different", "hardlink", "writable", "pending_conflict"],
)
def test_refuses_existing_unsafe_or_conflicting_controls(tmp_path, kind):
    other = tmp_path / "other"
    other.mkdir()
    if kind == "symlink_directory":
        (tmp_path / "needrestart").symlink_to(other, target_is_directory=True)
    else:
        installed = install(tmp_path)
        target = Path(installed["path"])
        if kind == "symlink_file":
            target.unlink()
            target.symlink_to(other / "not-present")
        elif kind == "different":
            target.write_bytes(b"administrator policy\n")
        elif kind == "hardlink":
            os.link(target, other / "link")
        elif kind == "writable":
            target.chmod(0o666)
        else:
            (target.parent / ".90-umi-controlled-restarts.conf.pending").write_bytes(
                upgrade.PACKAGE_RESTART_POLICY
            )
    with pytest.raises((ValueError, OSError)):
        install(tmp_path)
    if kind == "different":
        assert target.read_bytes() == b"administrator policy\n"


@pytest.mark.parametrize("published", [False, True])
def test_recovers_only_exact_interrupted_publication(tmp_path, published):
    directory = tmp_path / "needrestart/conf.d"
    directory.parent.mkdir(mode=0o755)
    directory.mkdir(mode=0o755)
    pending = directory / ".90-umi-controlled-restarts.conf.pending"
    pending.write_bytes(upgrade.PACKAGE_RESTART_POLICY)
    pending.chmod(0o644)
    target = directory / "90-umi-controlled-restarts.conf"
    if published:
        os.link(pending, target)
    result = install(tmp_path)
    assert result["status"] == "repaired_interrupted_publish"
    assert target.read_bytes() == upgrade.PACKAGE_RESTART_POLICY
    assert target.stat().st_nlink == 1
    assert not pending.exists()
    assert install(tmp_path)["status"] == "reused"


def test_partial_pending_needs_explicit_repair(tmp_path):
    directory = tmp_path / "needrestart/conf.d"
    directory.parent.mkdir(mode=0o755)
    directory.mkdir(mode=0o755)
    pending = directory / ".90-umi-controlled-restarts.conf.pending"
    pending.write_bytes(upgrade.PACKAGE_RESTART_POLICY[:20])
    with pytest.raises(ValueError, match="incomplete"):
        install(tmp_path)
    assert pending.read_bytes() == upgrade.PACKAGE_RESTART_POLICY[:20]
    assert not (directory / "90-umi-controlled-restarts.conf").exists()


def test_cli_rejects_nonroot_before_mutation(monkeypatch):
    monkeypatch.setattr(upgrade.os, "geteuid", lambda: 1000)
    with pytest.raises(ValueError, match="requires root on Linux"):
        upgrade.package_restart_policy_command()


@pytest.mark.skipif(
    shutil.which("perl") is None, reason="Perl needrestart config interpreter unavailable"
)
def test_perl_policy_defers_only_umi_services():
    code = r"""our %nrconf; eval $ARGV[0]; die $@ if $@;
    for my $unit (qw(umi-validator@54.service umi-validator-supervisor.service umi-miner.service
                      umi-standing-reward-artifact-delivery.service
                      umi-reference-publication.service)) {
        my @m=grep {$unit =~ $_} keys %{$nrconf{override_rc}};
        die "UMI restart not deferred" unless @m==1 && $nrconf{override_rc}->{$m[0]}==0;
    }
    for my $unit (qw(sshd.service unrelated-umi.service umi-fake.timer umi-no-service)) {
        die "unrelated service changed" if grep {$unit =~ $_} keys %{$nrconf{override_rc}};
    }
    """
    subprocess.run(["perl", "-e", code, upgrade.PACKAGE_RESTART_POLICY.decode()], check=True)


def test_policy_refusal_precedes_any_service_or_dropin_change(tmp_path, monkeypatch):
    calls = []

    def refuse(*args, **kwargs):
        calls.append(args)
        raise RuntimeError("package policy conflicts")

    monkeypatch.setattr(upgrade, "run", refuse)
    monkeypatch.setattr(upgrade, "SYSTEMD_RUNTIME_ROOT", tmp_path)
    service = upgrade.Service("umi-miner.service", 123, "miner", ["/bin/true"])
    with (
        pytest.raises(RuntimeError, match="policy conflicts"),
        upgrade.cooperative_upgrade((service,)),
    ):
        pytest.fail("refused policy cannot enter upgrade")
    assert len(calls) == 1 and "--install-restart-policy" in calls[0]
    assert not list(tmp_path.rglob("*.conf"))


@pytest.mark.parametrize("name", ["custom-translator.service", "model@revision-2.service"])
def test_custom_service_policy_is_exact_and_repeatable(tmp_path, name):
    result = upgrade.install_package_restart_policy(
        tmp_path, owner=(os.geteuid(), os.getegid()), service_name=name
    )
    target = Path(result["path"])
    assert result["status"] == "installed"
    raw = target.read_text()
    if shutil.which("perl"):
        program = r"""our %nrconf; eval $ARGV[0]; die $@ if $@;
        my @m=grep {$ARGV[1] =~ $_} keys %{$nrconf{override_rc}};
        die "custom unit missing" unless @m==1 && $nrconf{override_rc}->{$m[0]}==0;
        die "different unit matched"
            if grep {"different.service" =~ $_} keys %{$nrconf{override_rc}};
        """
        subprocess.run(["perl", "-e", program, raw, name], check=True)
    inode = target.stat().st_ino
    assert (
        upgrade.install_package_restart_policy(
            tmp_path, owner=(os.geteuid(), os.getegid()), service_name=name
        )["status"]
        == "reused"
    )
    assert target.stat().st_ino == inode


@pytest.mark.parametrize("name", ["bad;service.service", "../unit.service", "unit.timer"])
def test_bad_unit_is_refused_before_directory_creation(tmp_path, name):
    with pytest.raises(ValueError, match="service name"):
        upgrade.install_package_restart_policy(
            tmp_path, owner=(os.geteuid(), os.getegid()), service_name=name
        )
    assert not list(tmp_path.iterdir())


def test_installer_protects_package_transaction_and_precedes_smoke():
    script = SOURCE.parents[1] / "linux-validator-supervisor/install.sh"
    text = script.read_text()
    assert "NEEDRESTART_MODE=l apt-get update" in text
    assert "NEEDRESTART_MODE=l apt-get install" in text
    assert text.index("--install-restart-policy") < text.index('systemctl start "$service_name"')
    assert text.index("--install-restart-policy") < text.index(
        'systemctl disable --now "$legacy_unit"'
    )


@pytest.mark.skipif(shutil.which("perl") is None, reason="Perl unavailable")
@pytest.mark.parametrize("conflict", [False, True])
def test_complete_configuration_refuses_conflicting_admin_rule(tmp_path, conflict):
    config = tmp_path / "needrestart.conf"
    raw = "our %nrconf; $nrconf{override_rc}={qr(^umi-.*\\.service$)=>0"
    if conflict:
        raw += ",qr(^umi-miner\\.service$)=>1"
    config.write_text(raw + "};\n")
    config.chmod(0o600)
    if conflict:
        with pytest.raises(RuntimeError, match="conflicting"):
            upgrade.qualify_package_restart_configuration(
                ("umi-miner.service",), config, owner=(os.geteuid(), os.getegid())
            )
    else:
        upgrade.qualify_package_restart_configuration(
            ("umi-miner.service",), config, owner=(os.geteuid(), os.getegid())
        )
