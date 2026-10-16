"""Podman commands retain the exact installed account in a private host view."""

import asyncio
from dataclasses import replace
from types import SimpleNamespace

import pytest

from umi import competition_container as containers
from umi import competition_coordinator_namespace as namespace
from umi.competition_host_upgrade import HostUpgradeError


@pytest.fixture
def account(monkeypatch):
    identity = SimpleNamespace(
        pw_name="umi-validator-uid54",
        pw_uid=993,
        pw_gid=993,
        pw_dir="/var/lib/umi-validator-hosts/uid54/var/lib/umi-validator-supervisor",
    )
    monkeypatch.setattr(containers.pwd, "getpwuid", lambda _: identity)
    monkeypatch.setattr(containers.os, "geteuid", lambda: 993)
    monkeypatch.setattr(namespace, "_ACTIVE", None)
    return identity


@pytest.fixture
def selected_view(account, monkeypatch):
    checked = []
    view = namespace.CoordinatorHostView(
        layout=namespace.CoordinatorLayout("umi-validator@54.service"),
        service_uid=993,
        service_gid=993,
        pid=0,
        namespace=(0, 0),
        identities=(),
    )
    monkeypatch.setattr(namespace.CoordinatorHostView, "recheck", lambda self: checked.append(self))
    monkeypatch.setattr(namespace, "_ACTIVE", view)
    return view, checked


def test_ordinary_command_keeps_account_database_identity(account):
    assert containers._command_environment() == {
        "PATH": "/usr/bin:/bin",
        "HOME": account.pw_dir,
        "USER": account.pw_name,
        "LOGNAME": account.pw_name,
        "LANG": "C.UTF-8",
        "XDG_RUNTIME_DIR": "/run/user/993",
        "DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/993/bus",
    }


def test_selected_view_uses_installed_logical_account_without_env_overrides(
    selected_view, monkeypatch
):
    view, checked = selected_view
    for name in (
        "HOME",
        "USER",
        "LOGNAME",
        "PATH",
        "XDG_RUNTIME_DIR",
        "DBUS_SESSION_BUS_ADDRESS",
        "CONTAINER_HOST",
        "AWS_SECRET_ACCESS_KEY",
        "LD_PRELOAD",
        "PYTHONPATH",
    ):
        monkeypatch.setenv(name, "untrusted")
    assert containers._command_environment() == {
        "PATH": "/usr/bin:/bin",
        "HOME": "/var/lib/umi-validator-supervisor",
        "USER": "umi-validator",
        "LOGNAME": "umi-validator",
        "LANG": "C.UTF-8",
        "XDG_RUNTIME_DIR": "/run/user/993",
        "DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/993/bus",
    }
    assert checked == [view]


@pytest.mark.parametrize("field", ["pw_name", "pw_uid", "pw_gid", "pw_dir"])
def test_mismatched_outer_account_is_refused(account, selected_view, field):
    setattr(account, field, 994 if field in {"pw_uid", "pw_gid"} else "/wrong")
    with pytest.raises((containers.SuccessorContainerError, HostUpgradeError)):
        containers._command_environment()


@pytest.mark.parametrize("changed", ["root", "other_uid", "other_instance"])
def test_view_cannot_select_another_service_identity(selected_view, monkeypatch, changed):
    view, _ = selected_view
    if changed == "other_instance":
        monkeypatch.setattr(
            namespace,
            "_ACTIVE",
            replace(view, layout=namespace.CoordinatorLayout("umi-validator@0.service")),
        )
    else:
        monkeypatch.setattr(containers.os, "geteuid", lambda: 0 if changed == "root" else 994)
    with pytest.raises(containers.SuccessorContainerError, match="account differs"):
        containers._command_environment()


async def test_stale_view_fails_before_any_child_is_spawned(selected_view, monkeypatch):
    def stale(_):
        raise HostUpgradeError("coordinator view changed")

    async def forbidden(*_, **__):
        pytest.fail("spawned before rechecking the active view")

    monkeypatch.setattr(namespace.CoordinatorHostView, "recheck", stale)
    monkeypatch.setattr(asyncio, "create_subprocess_exec", forbidden)
    with pytest.raises(HostUpgradeError, match="view changed"):
        await containers._run_command(
            ("/usr/bin/podman", "info"), timeout_seconds=1, maximum_output_bytes=32
        )


@pytest.mark.parametrize("active", [False, True])
async def test_command_uses_safe_cwd_and_exact_environment(selected_view, monkeypatch, active):
    if not active:
        monkeypatch.setattr(namespace, "_ACTIVE", None)
    calls = []
    stream = asyncio.StreamReader()
    stream.feed_data(b"ok")
    stream.feed_eof()
    errors = asyncio.StreamReader()
    errors.feed_eof()

    async def done():
        return 0

    async def spawn(*args, **kwargs):
        calls.append((args, kwargs))
        return SimpleNamespace(stdout=stream, stderr=errors, wait=done, returncode=0)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", spawn)
    assert (
        await containers._run_command(
            ("/usr/bin/podman", "info"), timeout_seconds=1, maximum_output_bytes=32
        )
        == b"ok"
    )
    assert calls[0][1]["cwd"] == "/"
    assert calls[0][1]["env"] == containers._command_environment()


async def test_real_command_does_not_inherit_unavailable_parent_cwd(tmp_path, monkeypatch):
    hidden = tmp_path / "hidden"
    hidden.mkdir()
    monkeypatch.chdir(hidden)
    hidden.rmdir()
    assert (
        await containers._run_command(
            ("/usr/bin/pwd",), timeout_seconds=10, maximum_output_bytes=32
        )
        == b"/\n"
    )
