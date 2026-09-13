from pathlib import Path

import pytest

from umi import competition_coordinator_namespace as namespace
from umi.competition_host_upgrade import HostUpgradeError


@pytest.mark.parametrize("uid", [0, 54])
def test_exact_instance_paths(uid):
    layout = namespace.CoordinatorLayout(f"umi-validator@{uid}.service")
    assert layout.root_directory == Path(f"/var/lib/umi-validator-hosts/uid{uid}")
    assert layout.service_user == f"umi-validator-uid{uid}"
    assert layout.fragment == Path("/etc/systemd/system/umi-validator@.service")
    assert layout.cgroup == f"/umi.slice/umi-validators.slice/umi-validator@{uid}.service"
    logical = Path("/var/lib/umi-validator-supervisor/state/supervisor-process.lock")
    assert layout.physical(logical) == layout.root_directory / logical.relative_to("/")
    assert layout.bind_source(logical) == layout.physical(logical)
    assert layout.logical_home(str(layout.physical(layout.account_home))) == layout.service_home
    staged = Path("/opt/umi-validator-supervisor-hosts/" + "a" * 40)
    assert layout.bind_source(staged) == staged


@pytest.mark.parametrize(
    "unit",
    [
        "umi-validator@.service",
        "umi-validator@00.service",
        "umi-validator@1.service",
        "umi-validator@255.service",
        "umi-validator@54.service --now",
        "other.service",
    ],
)
def test_rejects_unreviewed_units(unit):
    with pytest.raises(HostUpgradeError, match="unsupported"):
        namespace.CoordinatorLayout(unit)


@pytest.mark.parametrize(
    "path",
    [
        "/",
        "/etc/shadow",
        "/var/lib/umi-validator-hosts/uid54/etc/umi",
        "/var/lib/umi-validator-supervisor/../other",
        "/tmp/x y",
        "relative/path",
    ],
)
def test_rejects_paths_outside_preserved_instance(path):
    with pytest.raises(HostUpgradeError):
        namespace.CoordinatorLayout("umi-validator@0.service").physical(Path(path))


def test_no_cross_instance_or_logical_account_home():
    left = namespace.CoordinatorLayout("umi-validator@0.service")
    right = namespace.CoordinatorLayout("umi-validator@54.service")
    for wrong in (str(left.service_home), str(right.physical(right.service_home))):
        with pytest.raises(HostUpgradeError, match="account home"):
            left.logical_home(wrong)
    with pytest.raises(HostUpgradeError, match="physical validator"):
        left.bind_source(right.physical(right.service_home))


def test_constructed_view_grants_no_namespace_access():
    view = namespace.CoordinatorHostView(
        namespace.CoordinatorLayout("umi-validator@0.service"),
        1001,
        1,
        (1, 2),
        (),
    )
    with pytest.raises(HostUpgradeError, match="not active"):
        view.recheck()


@pytest.mark.parametrize("uid", [0, 54])
def test_coordinator_service_operations_require_an_active_view(monkeypatch, uid):
    from umi import competition_host_upgrade as upgrade

    monkeypatch.setattr(namespace, "_ACTIVE", None)
    unit = f"umi-validator@{uid}.service"
    assert upgrade._UNIT_RE.fullmatch(unit)
    with pytest.raises(HostUpgradeError, match="private namespace view"):
        upgrade._expected_cgroup(unit)
    with pytest.raises(HostUpgradeError, match="private namespace view"):
        upgrade._check_service_namespace(unit, {"RootDirectory": "/"})


@pytest.mark.parametrize("uid", [0, 54])
def test_namespace_boundary_checks_root_account_slice_and_cleanup(monkeypatch, uid):
    from umi import competition_host_upgrade as upgrade

    layout = namespace.CoordinatorLayout(f"umi-validator@{uid}.service")
    monkeypatch.setattr(upgrade, "_service_layout", lambda unit: layout)
    values = dict(
        RootDirectory=str(layout.root_directory),
        RootImage="",
        Slice="umi-validators.slice",
        User=layout.service_user,
    )
    assert upgrade._check_service_namespace(layout.unit_name, values) == layout
    for key, wrong in (
        ("RootDirectory", "/"),
        ("RootImage", "/image"),
        ("Slice", "system.slice"),
        ("User", "root"),
    ):
        with pytest.raises(HostUpgradeError):
            upgrade._check_service_namespace(layout.unit_name, dict(values, **{key: wrong}))
    assert upgrade._expected_cgroup(layout.unit_name) == layout.cgroup
    cleanup = layout.unit_name.removesuffix(".service") + "-successor-cleanup.service"
    assert (
        upgrade._expected_cgroup(cleanup)
        == layout.cgroup.removesuffix(".service") + "-successor-cleanup.service"
    )


def test_missing_coordinator_account_is_a_bounded_hold(monkeypatch):
    import pwd

    def missing(name):
        raise KeyError(name)

    monkeypatch.setattr(namespace, "_ACTIVE", None)
    monkeypatch.setattr(namespace, "_require_root_linux", lambda: None)
    monkeypatch.setattr(pwd, "getpwnam", missing)
    with pytest.raises(HostUpgradeError, match="account is unavailable"):
        namespace.ensure_coordinator_host_view(
            unit_name="umi-validator@0.service",
            config_path=Path("/etc/umi/validator-supervisor.json"),
        )


def test_coordinator_command_rejects_physical_config_before_mounts():
    with pytest.raises(HostUpgradeError, match="logical config"):
        namespace.ensure_coordinator_host_view(
            unit_name="umi-validator@0.service",
            config_path=Path("/var/lib/umi-validator-hosts/uid0/etc/umi/validator-supervisor.json"),
        )
