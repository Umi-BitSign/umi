import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from umi.competition_bridge_recovery import audit_bridge_history
from umi.competition_coordinator_namespace import CoordinatorLayout

from . import coordinator_rehearsal as rehearsal
from .test_registration_bridge import signed_policy as signed_policy


def test_fixture_validators_have_different_synthetic_identities():
    assert rehearsal.fixture_validator_hotkey("0") != rehearsal.fixture_validator_hotkey("54")


def test_fixture_podman_uses_successor_store_and_selected_user_bus(monkeypatch):
    commands = []
    monkeypatch.setattr(rehearsal, "_command", lambda *args, **kw: commands.append((args, kw)))
    layout = CoordinatorLayout("umi-validator@54.service")
    user = SimpleNamespace(pw_name=layout.service_user, pw_uid=993)
    rehearsal.rooted_podman(layout, user, "ps", "--format=json", timeout=17)
    ((args, kwargs),) = commands
    assert f"--property=RootDirectory={layout.root_directory}" in args
    assert "--property=BindPaths=/run/user/993" in args
    assert args[-6:] == (
        "/usr/bin/env",
        "HOME=/var/lib/umi-validator-supervisor",
        "/usr/bin/podman",
        "--cgroup-manager=systemd",
        "ps",
        "--format=json",
    )
    assert kwargs == {"timeout": 17}


@pytest.mark.parametrize("instance", ["0", "54"])
def test_signed_migration_bridge_fixture_has_valid_preservable_history(
    tmp_path, signed_policy, instance
):
    from .test_competition_migration_linux import _prepare_legacy

    class LocalLayout:
        def physical(self, path):
            return tmp_path / str(path).lstrip("/")

    layout = LocalLayout()
    layout.instance = instance
    for name in ("state", "releases"):
        layout.physical(Path("/var/lib/umi-validator-supervisor") / name).mkdir(parents=True)
    layout.physical(Path("/var/lib/umi-validator-worker-state")).mkdir(parents=True)
    user = SimpleNamespace(pw_uid=os.geteuid(), pw_gid=os.getegid())
    item = _prepare_legacy(layout, user, "linux/amd64", signed_policy)
    audit = audit_bridge_history(item.files, hotkey=item.config.validator_hotkey)
    assert not audit.holds
    assert audit.attempts[-1][1].weight_call.block_number == 161
    assert item.owned.validator_uid == int(instance)
