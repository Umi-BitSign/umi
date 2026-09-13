from __future__ import annotations

import asyncio
import json
import os
import subprocess
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from umi import competition_initial_upgrade as upgrade
from umi import competition_switch_recovery as recovery
from umi.competition_host_artifacts import HostArtifactFile
from umi.protocol import canonical_json_bytes
from umi.validator_supervisor import ValidatorSupervisorError

from .test_competition_host_anchor import activation_case as activation_case
from .test_competition_host_anchor import anchor_case as anchor_case
from .test_competition_host_anchor import chain_config as chain_config
from .test_competition_host_anchor import explicit as explicit
from .test_competition_host_anchor import limits as limits
from .test_competition_host_anchor import package_case as package_case
from .test_competition_host_anchor import package_limits as package_limits
from .test_competition_host_anchor import policy as policy
from .test_competition_host_anchor import release_identity as release_identity
from .test_competition_host_anchor import replay_limits as replay_limits
from .test_competition_host_anchor import successor_release as successor_release
from .test_competition_host_anchor import trusted_ports as trusted_ports
from .test_competition_host_anchor import worker_capacity as worker_capacity
from .test_competition_host_artifacts import sign as sign_host_artifact


def test_controls_authenticate_actual_signed_inputs(anchor_case):
    case = anchor_case
    result = upgrade._controls(case.paths.config, case.controls)
    assert result.config == case.base.config
    assert result.page == case.base.initial_page
    assert result.consent == case.base.consent
    assert result.signed_host == case.host.signed
    assert result.paths()["config_path"] == case.paths.config
    result.recheck()


@pytest.mark.parametrize("machine,target", [("x86_64", "linux/amd64"), ("aarch64", "linux/arm64")])
def test_rehearsal_host_identity_is_verified_as_nonroot(machine, target, monkeypatch):
    from umi import competition_supervisor_cli as cli

    root = upgrade._STAGE_PARENT / ("a" * 40)
    source, interpreter = root / "src/umi/competition_initial_upgrade.py", root / ".venv/bin/python"
    identity = (1, 2, 3)
    control = SimpleNamespace(
        config=SimpleNamespace(target_platform=target),
        signed_host=SimpleNamespace(manifest=SimpleNamespace(umi_git_revision=root.name)),
    )
    monkeypatch.setattr(upgrade.sys, "platform", "linux")
    monkeypatch.setattr(upgrade.os, "geteuid", lambda: 1001)
    monkeypatch.setattr(upgrade.platform, "machine", lambda: machine)
    monkeypatch.setattr(upgrade, "__file__", str(source))
    monkeypatch.setattr(upgrade.sys, "executable", str(interpreter))
    monkeypatch.setattr(upgrade.sys, "prefix", str(root / ".venv"))
    monkeypatch.setattr(cli, "_stable_file_identity", lambda path: identity)
    monkeypatch.setattr(cli, "_running_executable_identity", lambda path: identity)
    monkeypatch.setattr(upgrade, "_ancestor_identity", lambda path: identity)
    monkeypatch.setattr(
        upgrade, "_read_tree", lambda *args: ({source: identity, interpreter: identity}, None)
    )
    upgrade._verify_rehearsal_host(control)
    monkeypatch.setattr(upgrade.os, "geteuid", lambda: 0)
    with pytest.raises(ValueError, match="exact signed host"):
        upgrade._verify_rehearsal_host(control)
    monkeypatch.setattr(upgrade.os, "geteuid", lambda: 1001)
    monkeypatch.setattr(upgrade.platform, "machine", lambda: "riscv64")
    with pytest.raises(ValueError, match="exact signed host"):
        upgrade._verify_rehearsal_host(control)


@pytest.fixture
def complete_host_controls(anchor_case):
    control = upgrade._controls(anchor_case.paths.config, anchor_case.controls)
    observer = anchor_case.base.observer_config.chain
    records = {record.path: record for record in control.signed_host.manifest.files}
    for name, sha, mode in (
        (
            "artifacts/umi-grandpa-finality-observer",
            observer.finality_pin.release_sha256_by_target[observer.target_triple],
            0o555,
        ),
        ("artifacts/umi-substrate-proof-verifier", observer.proof_binary_sha256, 0o555),
        ("artifacts/raw_spec_finney.json", observer.finality_pin.chain_spec_sha256, 0o444),
        (".venv/bin/umi-competition-supervisor-cleanup", "aa" * 32, 0o555),
        ("src/umi/competition_initial_upgrade.py", "bb" * 32, 0o444),
        ("src/umi/competition_supervisor_cli.py", "cc" * 32, 0o444),
        ("src/umi/competition_supervisor_cleanup.py", "dd" * 32, 0o444),
    ):
        records[name] = HostArtifactFile(path=name, sha256=sha, mode=mode, size_bytes=1)
    manifest = control.signed_host.manifest.model_copy(
        update={
            "files": sorted(records.values(), key=lambda r: r.path),
            "total_size_bytes": sum(r.size_bytes for r in records.values()),
        }
    )
    # No files are executed here. This is a signed manifest cross-binding test;
    # the bundle/tree tests separately verify its files and immutable metadata.
    return replace(control, signed_host=sign_host_artifact(manifest))


def test_complete_host_requirements_recheck_before_acceptance(complete_host_controls):
    calls = []
    upgrade._prestop_host_requirements(
        complete_host_controls, SimpleNamespace(recheck=lambda: calls.append("tree"))
    )
    assert calls == ["tree"]


@pytest.mark.parametrize(
    "path",
    [
        "artifacts/umi-grandpa-finality-observer",
        "artifacts/umi-substrate-proof-verifier",
        "artifacts/raw_spec_finney.json",
        ".venv/bin/umi-competition-supervisor-cleanup",
        "src/umi/competition_initial_upgrade.py",
        "src/umi/competition_supervisor_cli.py",
        "src/umi/competition_supervisor_cleanup.py",
    ],
)
@pytest.mark.parametrize("change", ["absent", "mode"])
def test_incomplete_host_refused_before_stop(complete_host_controls, path, change):
    control = complete_host_controls
    records = []
    for record in control.signed_host.manifest.files:
        if record.path == path:
            if change == "absent":
                continue
            record = record.model_copy(update={"mode": 0o444 if record.mode == 0o555 else 0o555})
        records.append(record)
    signed = sign_host_artifact(
        control.signed_host.manifest.model_copy(
            update={"files": records, "total_size_bytes": sum(r.size_bytes for r in records)}
        )
    )
    with pytest.raises(ValueError, match=r"host (manifest|lacks)"):
        upgrade._prestop_host_requirements(
            replace(control, signed_host=signed), SimpleNamespace(recheck=lambda: None)
        )


@pytest.mark.parametrize(
    "path",
    [
        "artifacts/umi-grandpa-finality-observer",
        "artifacts/umi-substrate-proof-verifier",
        "artifacts/raw_spec_finney.json",
    ],
)
def test_signed_helper_hash_must_match_observer_pin(complete_host_controls, path):
    control = complete_host_controls
    records = [
        r.model_copy(update={"sha256": "ef" * 32}) if r.path == path else r
        for r in control.signed_host.manifest.files
    ]
    signed = sign_host_artifact(control.signed_host.manifest.model_copy(update={"files": records}))
    with pytest.raises(ValueError, match="exact installed observer"):
        upgrade._prestop_host_requirements(
            replace(control, signed_host=signed), SimpleNamespace(recheck=lambda: None)
        )


@pytest.mark.parametrize(
    "name", ["config", "consent", "legacy", "initial", "host", "limits", "observer"]
)
def test_controls_refuse_changed_sealed_bytes(anchor_case, name):
    case = anchor_case
    result = upgrade._controls(case.paths.config, case.controls)
    path = getattr(case.paths, name)
    path.chmod(0o600)
    path.write_bytes(b"{}")
    path.chmod(0o400)
    with pytest.raises(ValueError):
        result.recheck()
    with pytest.raises((ValueError, ValidatorSupervisorError)):
        upgrade._controls(case.paths.config, case.controls)


def test_production_unit_sandbox_parses_without_lifecycle_or_shared_directory_managers():
    template = (
        Path(__file__).parents[1]
        / "deploy/linux-validator-supervisor/umi-validator-supervisor.service"
    )
    result = upgrade._sandbox_properties(template.read_bytes())
    assert "ProtectSystem=strict" in result
    assert "Delegate=true" in result
    assert "MemoryMax=12884901888" in result
    assert all(
        not item.startswith(
            ("Exec", "Restart", "StateDirectory", "RuntimeDirectory", "ProtectHome")
        )
        for item in result
    )


@pytest.mark.parametrize(
    "addition",
    [
        "RootDirectory=/other",
        "BindPaths=/",
        "ExecStop=/bin/false",
        "NoNewPrivileges=yes",
        "ReadOnlyPaths=/space path",
        "ReadWritePaths=%h",
        "User=root\nUser=sam",
        "ProtectSystem=strict\nProtectSystem=no",
    ],
)
def test_unreviewed_sandbox_is_rejected(addition):
    # Unknown settings require an adapter; a rehearsal cannot silently drop them.
    with pytest.raises(ValueError):
        upgrade._sandbox_properties(
            ("[Service]\nExecStart=/bin/false\n" + addition + "\n").encode()
        )


@pytest.mark.parametrize("uid", [0, 54])
def test_coordinator_sandbox_expands_only_reviewed_template_fields(uid):
    from umi.competition_coordinator_namespace import CoordinatorLayout

    layout = CoordinatorLayout(f"umi-validator@{uid}.service")
    fragment = b"""[Unit]
Description=UMI validator UID %i on coordinator
ConditionPathExists=/var/lib/umi-validator-hosts/uid%i/etc/umi/migration-approved
[Service]
User=umi-validator-uid%i
Group=umi-validator-uid%i
RootDirectory=/var/lib/umi-validator-hosts/uid%i
MountAPIVFS=true
RuntimeDirectory=umi-validator-uid%i
BindPaths=/run/umi-validator-uid%i:/run/umi-validator-supervisor
BindReadOnlyPaths=/etc/resolv.conf:/etc/resolv.conf
Slice=umi-validators.slice
ExecStart=/bin/false
ProtectSystem=strict
ReadWritePaths=+/var/lib/umi-validator-supervisor +/run/umi-validator-supervisor
"""
    properties = upgrade._sandbox_properties(fragment, coordinator=layout)
    assert properties == [
        "ProtectSystem=strict",
        "ReadWritePaths=+/var/lib/umi-validator-supervisor",
    ]
    with pytest.raises(ValueError):
        upgrade._sandbox_properties(fragment)
    for old, new in (
        (b"uid%i", b"uid54"),
        (b"/etc/resolv.conf", b"/etc/shadow"),
        (b"umi-validators.slice", b"system.slice"),
        (b"+/var/lib", b"/var/lib"),
    ):
        with pytest.raises(ValueError):
            upgrade._sandbox_properties(fragment.replace(old, new), coordinator=layout)


def test_directory_creation_preserves_existing_paths_and_explicit_modes(tmp_path):
    tmp_path.chmod(0o700)
    path = tmp_path / "new"
    args = dict(
        owner=os.getuid(),
        group=os.getgid(),
        mode=0o555,
        parent_owner=os.getuid(),
        parent_modes={0o700},
    )
    previous = os.umask(0o077)
    try:
        upgrade._directory(path, **args)
    finally:
        os.umask(previous)
    try:
        identity = path.stat().st_ino
        upgrade._directory(path, **args)
        assert path.stat().st_ino == identity
        assert path.stat().st_mode & 0o777 == 0o555
        path.chmod(0o755)
        with pytest.raises(ValueError, match="existing upgrade directory"):
            upgrade._directory(path, **args)
        assert path.stat().st_mode & 0o777 == 0o755
    finally:
        path.chmod(0o700)


def test_directory_creation_refuses_links(tmp_path):
    tmp_path.chmod(0o700)
    target = tmp_path / "target"
    target.mkdir(mode=0o700)
    link = tmp_path / "link"
    link.symlink_to(target, target_is_directory=True)
    with pytest.raises(OSError):
        upgrade._directory(
            link,
            owner=os.getuid(),
            group=os.getgid(),
            mode=0o700,
            parent_owner=os.getuid(),
            parent_modes={0o700},
        )
    assert target.stat().st_mode & 0o777 == 0o700


@pytest.fixture
def flow(monkeypatch):
    events = []
    lock = {"held": False, "writer": False}

    def record(name):
        def call(*args, **kwargs):
            assert lock["held"]
            events.append(name)

        return call

    @contextmanager
    def mutex(unit):
        assert not lock["held"]
        lock["held"] = True
        events.append("mutex-enter")
        try:
            yield
        finally:
            lock["held"] = False
            events.append("mutex-exit")

    @contextmanager
    def stopped(**kwargs):
        events.append("writer-enter")
        lock["writer"] = True
        try:
            yield object()
        finally:
            lock["writer"] = False
            events.append("writer-exit")

    class Observer:
        def __init__(self, **kwargs):
            assert lock["writer"]
            events.append("observer-open")

        async def observe(self):
            assert lock["writer"]
            events.append("observe")
            return object()

        async def aclose(self):
            events.append("observer-close")

    config = SimpleNamespace(validator_hotkey="fixture-hotkey")
    control = SimpleNamespace(
        config=config,
        consent=SimpleNamespace(approved_host_manifest_sha256="a" * 64),
        signed_host=object(),
        sources={
            upgrade.activation.LEGACY_SIGNED_DIRECTIVE_FILENAME: SimpleNamespace(payload=b"legacy")
        },
        paths=lambda: {},
        recheck=record("controls-recheck"),
    )
    tree = SimpleNamespace(recheck=record("tree-recheck"))
    unit = dict.fromkeys(
        (
            "Id",
            "User",
            "FragmentPath",
            "ExecStart",
            "DropInPaths",
            "OnFailure",
            "RootDirectory",
            "RootImage",
            "Slice",
        ),
        "fixture",
    )
    user = SimpleNamespace(pw_uid=1001)
    limits = upgrade.RecoveryLimits(
        schema="umi-legacy-bootstrap-recovery-limits/1",
        maximum_files=10,
        maximum_directories=10,
        maximum_depth=3,
        maximum_file_bytes=1024,
        maximum_total_bytes=10240,
        maximum_checkpoint_bytes=1024,
        maximum_checkpoints=4,
    )
    monkeypatch.setattr(upgrade, "_require_root_linux", lambda: None)
    monkeypatch.setattr(upgrade, "exclusive_upgrade_operation", mutex)
    monkeypatch.setattr(upgrade, "_controls", lambda *args: control)
    monkeypatch.setattr(
        upgrade.anchors,
        "_read_source",
        lambda *args, **kwargs: SimpleNamespace(payload=canonical_json_bytes(limits)),
    )
    monkeypatch.setattr(upgrade.anchors, "_recheck_source", record("source-recheck"))
    monkeypatch.setattr(upgrade, "_service_identity", lambda *args: (user, unit.copy()))
    monkeypatch.setattr(upgrade, "_prepare_layout", record("layout"))
    monkeypatch.setattr(
        upgrade,
        "stage_successor_host_bundle",
        lambda *args, **kwargs: events.append("stage-host") or tree,
    )
    monkeypatch.setattr(upgrade, "_rehearse_service", record("rehearse"))
    monkeypatch.setattr(upgrade, "_prestop_host_requirements", record("host-requirements"))
    monkeypatch.setattr(upgrade, "prepare_upgrade_observer_namespace", record("namespace"))
    monkeypatch.setattr(upgrade, "_systemctl", lambda verb, name: events.append(verb))
    monkeypatch.setattr(upgrade, "hold_stopped_supervisor", stopped)
    monkeypatch.setattr(upgrade, "StoppedUpgradeObserver", Observer)
    monkeypatch.setattr(upgrade, "_retained_anchor", lambda *args: None)
    monkeypatch.setattr(
        upgrade,
        "prepare_recovery_checkpoint",
        lambda *args, **kwargs: (
            events.append("archive")
            or SimpleNamespace(checkpoint_path="/archive/checkpoint", checkpoint_sha256="a" * 64)
        ),
    )
    monkeypatch.setattr(
        upgrade,
        "verify_recovery_checkpoint",
        lambda *args, **kwargs: events.append("verify") or object(),
    )
    monkeypatch.setattr(
        upgrade.anchors,
        "materialize_successor_anchor",
        lambda **kwargs: events.append("anchor") or object(),
    )

    def commit(**kwargs):
        assert lock["writer"] and lock["held"]
        events.append("commit")
        return object()

    def start(value):
        assert not lock["writer"] and lock["held"]
        events.append("start")
        return SimpleNamespace(
            unit_name="umi-validator-supervisor.service",
            main_pid=123,
            host_manifest_sha256="a" * 64,
            checkpoint_sha256="b" * 64,
        )

    monkeypatch.setattr(upgrade, "commit_successor_service_switch", commit)
    monkeypatch.setattr(upgrade, "start_committed_successor_service", start)
    args = dict(
        config_path=Path("/config"),
        unit_name="umi-validator-supervisor.service",
        controls_path=Path("/controls"),
        host_bundle=Path("/host"),
        oci_bundle=Path("/oci"),
        recovery_root=Path("/archive"),
        recovery_limits_path=Path("/limits"),
    )
    return SimpleNamespace(events=events, args=args, lock=lock)


def test_initial_command_connects_rehearsal_two_proofs_commit_unlock_and_start(flow):
    result = upgrade.upgrade_successor_service(**flow.args)
    stages = [
        item
        for item in flow.events
        if item not in {"controls-recheck", "tree-recheck", "source-recheck"}
    ]
    assert stages == [
        "mutex-enter",
        "layout",
        "stage-host",
        "host-requirements",
        "rehearse",
        "namespace",
        "stop",
        "writer-enter",
        "observer-open",
        "observe",
        "archive",
        "observe",
        "verify",
        "observer-close",
        "anchor",
        "commit",
        "writer-exit",
        "start",
        "mutex-exit",
    ]
    assert result["service_started"] is True
    assert result["chain_submission_authorized"] is False
    assert flow.lock == {"held": False, "writer": False}


@pytest.mark.parametrize(
    "port,forbidden",
    [
        ("_prestop_host_requirements", "stop"),
        ("_rehearse_service", "stop"),
        ("prepare_upgrade_observer_namespace", "stop"),
        ("prepare_recovery_checkpoint", "verify"),
        ("verify_recovery_checkpoint", "anchor"),
        ("commit_successor_service_switch", "start"),
    ],
)
def test_failure_retains_locks_until_unwind_and_never_advances(flow, monkeypatch, port, forbidden):
    def fail(*args, **kwargs):
        raise OSError("injected failure")

    monkeypatch.setattr(upgrade, port, fail)
    with pytest.raises(OSError):
        upgrade.upgrade_successor_service(**flow.args)
    assert forbidden not in flow.events
    assert flow.events[-1] == "mutex-exit"
    assert flow.lock == {"held": False, "writer": False}
    assert "restart" not in flow.events
    if "observer-open" in flow.events:
        assert "observer-close" in flow.events


def test_cli_routes_initial_command_and_bounds_errors(monkeypatch, capsys):
    args = [
        "upgrade",
        "--config",
        "/config",
        "--unit",
        "umi-validator-supervisor.service",
        "--controls",
        "/controls",
        "--host-bundle",
        "/host",
        "--oci-bundle",
        "/oci",
        "--recovery-root",
        "/archive",
        "--recovery-limits",
        "/limits",
    ]
    seen = []
    monkeypatch.setattr(
        upgrade,
        "upgrade_successor_service",
        lambda **kwargs: seen.append(kwargs) or {"status": "fixture"},
    )
    assert recovery.main(args) == 0
    assert json.loads(capsys.readouterr().out) == {"status": "fixture"}
    assert seen[0]["oci_bundle"] == Path("/oci")
    for error in (OSError("private-detail"), subprocess.TimeoutExpired("private-command", 12)):

        def fail(error=error, **kwargs):
            raise error

        monkeypatch.setattr(upgrade, "upgrade_successor_service", fail)
        assert recovery.main(args) == 1
        output = capsys.readouterr().out
        assert "private-" not in output
        result = json.loads(output)
        assert result["service_state"] == "unconfirmed"
        assert result["reason_code"] == "initial_host_upgrade_failed"
        assert result["chain_submission_authorized"] is False


def test_child_refuses_root_without_wallet_or_container_calls(monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    with pytest.raises(ValueError, match="non-root"):
        asyncio.run(upgrade._rehearse_child(Path("/nonexistent")))


def test_retained_anchor_is_reconciled_again_before_commit(flow, monkeypatch):
    retained = SimpleNamespace(receipt=SimpleNamespace(checkpoint_sha256="e" * 64))
    monkeypatch.setattr(upgrade, "_retained_anchor", lambda *args: retained)
    verified = []

    def verify(path, **kwargs):
        verified.append((path, kwargs))
        return object()

    monkeypatch.setattr(upgrade, "verify_recovery_checkpoint", verify)
    assert upgrade.upgrade_successor_service(**flow.args)["service_started"] is True
    assert verified[0][0] == Path("/archive") / ("e" * 64)
    assert "archive" not in flow.events and "anchor" not in flow.events
    assert flow.events.count("observe") == 1
    assert "commit" in flow.events


def test_failed_start_does_not_restore_legacy_under_operator_mutex(flow, monkeypatch):
    def fail(switch):
        assert flow.lock == {"held": True, "writer": False}
        raise OSError("start containment performed by existing start routine")

    monkeypatch.setattr(upgrade, "start_committed_successor_service", fail)
    with pytest.raises(OSError):
        upgrade.upgrade_successor_service(**flow.args)
    assert flow.events[-1] == "mutex-exit"
    assert "restart" not in flow.events


def test_corrupt_existing_anchor_is_rejected_before_stopping_legacy(flow, monkeypatch):
    def reject(*args):
        raise ValueError("retained anchor failed verification")

    monkeypatch.setattr(upgrade, "_retained_anchor", reject)
    with pytest.raises(ValueError, match="retained anchor"):
        upgrade.upgrade_successor_service(**flow.args)
    assert "stop" not in flow.events and "writer-enter" not in flow.events


def test_empty_historical_context_is_explicit_and_canonical(tmp_path, monkeypatch):
    monkeypatch.setattr(upgrade.anchors, "_root_owner_uid", os.getuid)
    path = tmp_path / "context.json"
    path.write_bytes(b'{"leases":[],"manifests":[]}')
    path.chmod(0o400)
    _, manifests, leases = upgrade._historical_context(path)
    assert manifests == leases == ()
    path.chmod(0o600)
    path.write_bytes(b'{"leases":[],"manifests":[],"bypass":true}')
    path.chmod(0o400)
    with pytest.raises(ValueError):
        upgrade._historical_context(path)
