from types import SimpleNamespace

from umi.competition_coordinator_namespace import CoordinatorLayout

from . import coordinator_rehearsal as rehearsal


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
