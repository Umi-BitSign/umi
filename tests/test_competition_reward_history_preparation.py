"""Genuine anchor and root controls, isolated ownership only; no history replay."""

import fcntl
import hashlib
import json
import os
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from umi import competition_reward_history_preparation as preparation
from umi import competition_reward_history_preparation_runtime as runtime
from umi import competition_supervisor_runtime as supervisor
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from .test_competition_materializer import (
    activation_case as activation_case,
)
from .test_competition_materializer import (
    anchor_case as anchor_case,
)
from .test_competition_materializer import case as installed_case  # noqa: F401
from .test_competition_materializer import (
    chain_config as chain_config,
)
from .test_competition_materializer import (
    explicit as explicit,
)
from .test_competition_materializer import (
    limits as limits,
)
from .test_competition_materializer import (
    package_case as package_case,
)
from .test_competition_materializer import (
    package_limits as package_limits,
)
from .test_competition_materializer import (
    policy as policy,
)
from .test_competition_materializer import (
    release_identity as release_identity,
)
from .test_competition_materializer import (
    replay_limits as replay_limits,
)
from .test_competition_materializer import (
    successor_release as successor_release,
)
from .test_competition_materializer import (
    trusted_ports as trusted_ports,
)
from .test_competition_materializer import (
    worker_capacity as worker_capacity,
)
from .test_competition_reward_boot import inputs as boot_inputs  # noqa: F401
from .test_competition_reward_decisions import (
    chain as chain,
)
from .test_competition_reward_decisions import (
    control as control,
)
from .test_competition_reward_decisions import (
    series_case as series_case,
)


@pytest.fixture
def case(installed_case, boot_inputs, tmp_path, monkeypatch):  # noqa: F811
    anchor = installed_case.anchor
    config = boot_inputs.value
    series = config.series.model_copy(update={"validators": (anchor.config.validator_hotkey,)})
    config = config.model_copy(
        update={
            "series": series,
            "handoff": config.handoff.model_copy(update={"series_sha256": digest(series)}),
        }
    )
    boot_inputs.save(boot_inputs.path, canonical_json_bytes(config))
    held = Path(config.approval_path).with_suffix(".held")
    Path(config.approval_path).rename(held)
    hold_bytes = held.read_bytes()
    root = tmp_path / "staging-broker"
    root.mkdir(mode=0o700)
    (root / "history").mkdir(mode=0o700)
    approval = preparation.StandingHistoryPreparationApproval(
        schema="umi-standing-history-preparation/1",
        source_config_sha256=digest(anchor.config),
        installation_receipt_sha256=anchor.receipt_sha256,
        standing_boot_raw_sha256=hashlib.sha256(canonical_json_bytes(config)).hexdigest(),
        series_sha256=digest(series),
        chain_config_sha256=digest(config.chain),
        verifier_semantics=preparation.runtime_identity(),
        history="current",
        through_block=200,
        preparation_directory=str(root),
        service_gid=os.getgid() or 1,
        reason="independent history preparation",
    )
    if os.getgid() == 0:
        os.chown(root / "history", os.getuid(), 1)
    path = tmp_path / "preparation-approval.json"
    boot_inputs.save(path, canonical_json_bytes(approval))
    # Portable root filesystem port only; native anchor issuer/signatures and
    # staging lease issuer, file identities and actual flock remain genuine.
    monkeypatch.setattr(preparation, "_root_owner_uid", os.getuid)
    lock = Path(anchor.config.state_root) / "supervisor-process.lock"
    lock.write_bytes(b"original live writer lock bytes")
    lock.chmod(0o600)

    def open_scope():
        return preparation.hold_history_preparation_lease(
            anchor, standing_boot=boot_inputs.path, approval_path=path
        )

    return SimpleNamespace(
        anchor=anchor,
        config=config,
        approval=approval,
        path=path,
        boot=boot_inputs.path,
        root=root,
        held=held,
        hold_bytes=hold_bytes,
        writer_lock=lock,
        open=open_scope,
        save=boot_inputs.save,
    )


def test_authentic_staging_lease_coexists_with_original_writer_and_held_approval(case, caplog):
    descriptor = os.open(case.writer_lock, os.O_RDWR)
    before = case.writer_lock.stat()
    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    caplog.set_level("INFO", logger="umi.competition.progress")
    try:
        with case.open() as lease:
            lease.recheck()
            assert lease.logical_history == (
                Path(case.anchor.config.state_root)
                / "standing-rewards"
                / digest(case.config.series)
                / "history"
            )
            assert lease.staged_history == case.root / "history"
            assert lease.first_block == case.config.series.recovery.authority.issued_at_block
            assert list(lease.staged_history.iterdir()) == []
            with pytest.raises(BlockingIOError), case.open():
                pytest.fail("staging broker accepted two owners")
            with pytest.raises(supervisor.SuccessorRuntimeError):
                supervisor._validate_startup_lease(lease)
        with pytest.raises(preparation.HistoryPreparationError, match="closed"):
            lease.recheck()
        with case.open() as reopened:
            reopened.recheck()
        assert case.writer_lock.stat() == before
        assert os.pread(descriptor, 1000, 0) == b"original live writer lock bytes"
        assert case.held.read_bytes() == case.hold_bytes
        assert not Path(case.config.approval_path).exists()
        assert '"stage":"history_preparation_broker"' in caplog.text
        assert '"completed":3' in caplog.text
        assert '"eta_seconds":0.0' in caplog.text
        planning = [
            json.loads(record.message)
            for record in caplog.records
            if '"state":"planning"' in record.message
        ]
        assert planning
        assert planning[0]["eta_scope"] == "broker_admission_only_excluding_native_replay"
        assert planning[0]["planning_eta_seconds"] == [0.05, 5.0]
    finally:
        os.close(descriptor)


@pytest.mark.parametrize(
    "field",
    [
        "source_config_sha256",
        "installation_receipt_sha256",
        "standing_boot_raw_sha256",
        "series_sha256",
        "chain_config_sha256",
        "verifier_semantics",
    ],
)
def test_wrong_authenticated_scope_refuses_before_creating_lock(case, field):
    changed = case.approval.model_copy(update={field: "ab" * 32})
    case.save(case.path, canonical_json_bytes(changed))
    with (
        pytest.raises(preparation.HistoryPreparationError, match="installed native scope"),
        case.open(),
    ):
        pytest.fail("wrong scope accepted")
    assert not (case.root / "preparation.lock").exists()
    assert list((case.root / "history").iterdir()) == []


@pytest.mark.parametrize(
    "fault", ["control", "directory", "lock_bytes", "unlock", "issuer", "binding"]
)
def test_recheck_rejects_lost_or_altered_staging_ownership(case, fault):
    with case.open() as lease:
        changed = lease
        if fault == "control":
            case.save(
                case.path,
                canonical_json_bytes(case.approval.model_copy(update={"reason": "changed"})),
            )
        elif fault == "directory":
            lease.staged_history.rename(case.root / "retained")
            lease.staged_history.mkdir(mode=0o700)
        elif fault == "lock_bytes":
            os.pwrite(lease._descriptor, b"X", 0)
        elif fault == "unlock":
            fcntl.flock(lease._descriptor, fcntl.LOCK_UN)
        elif fault == "issuer":
            changed = replace(lease, _issuer=object())
        else:
            changed = replace(lease, _binding="ab" * 32)
        with pytest.raises(preparation.HistoryPreparationError):
            changed.recheck()


def test_resume_cannot_retarget_prior_staging_scope(case):
    with case.open():
        pass
    prior = (case.root / "preparation.lock").read_bytes()
    case.save(
        case.path, canonical_json_bytes(case.approval.model_copy(update={"through_block": 201}))
    )
    with (
        pytest.raises(preparation.HistoryPreparationError, match="cannot change scope"),
        case.open(),
    ):
        pytest.fail("retargeted completed work")
    assert (case.root / "preparation.lock").read_bytes() == prior


def test_plain_anchor_or_json_never_grants_staging_ownership(case):
    with (
        pytest.raises(preparation.HistoryPreparationError, match="genuine"),
        preparation.hold_history_preparation_lease(
            SimpleNamespace(config=case.anchor.config),
            standing_boot=case.boot,
            approval_path=case.path,
        ),
    ):
        pytest.fail("plain anchor accepted")
    with pytest.raises(preparation.HistoryPreparationError, match="absent"):
        preparation.validate_history_preparation_lease(case.approval.model_dump())
    assert not (case.root / "preparation.lock").exists()


def test_staging_cannot_overlap_live_owner_state(case):
    root = Path(case.anchor.config.state_root) / "wrong-staging"
    root.mkdir(mode=0o700)
    (root / "history").mkdir(mode=0o700)
    if os.getgid() == 0:
        os.chown(root / "history", os.getuid(), 1)
    case.save(
        case.path,
        canonical_json_bytes(case.approval.model_copy(update={"preparation_directory": str(root)})),
    )
    with pytest.raises(preparation.HistoryPreparationError, match="overlaps"), case.open():
        pytest.fail("live owner namespace accepted")
    assert not (root / "preparation.lock").exists()


def test_service_group_must_match_installed_account(case):
    case.save(
        case.path,
        canonical_json_bytes(
            case.approval.model_copy(update={"service_gid": case.approval.service_gid + 1})
        ),
    )
    with pytest.raises(preparation.HistoryPreparationError, match="account group"), case.open():
        pytest.fail("unrelated group accepted")
    assert not (case.root / "preparation.lock").exists()


@pytest.mark.parametrize("native_started", [False, True])
def test_interrupted_first_scope_write_repairs_only_before_native_history(case, native_started):
    with case.open():
        pass
    path = case.root / "preparation.lock"
    complete = path.read_bytes()
    path.write_bytes(complete[:17])
    if native_started:
        (case.root / "history" / "retained").write_bytes(b"native work must remain untouched")
        with (
            pytest.raises(preparation.HistoryPreparationError, match="requires empty"),
            case.open(),
        ):
            pytest.fail("lost scope binding reconstructed over native history")
        assert path.read_bytes() == complete[:17]
    else:
        with case.open() as lease:
            lease.recheck()
        assert path.read_bytes() == complete


def test_preparation_mount_guard_decodes_kernel_paths(monkeypatch):
    root = Path("/private preparation")
    original = Path.read_text
    monkeypatch.setattr(
        Path,
        "read_text",
        lambda p, *a, **kw: (
            "25 24 8:1 / /private\\040preparation/history rw - ext4 /dev/root rw\n"
            if str(p) == "/proc/self/mountinfo"
            else original(p, *a, **kw)
        ),
    )
    with pytest.raises(preparation.HistoryPreparationError, match="contains a mount"):
        preparation._no_preparation_mounts(root)


def test_ambiguous_stacked_backing_mount_refuses():
    mounts = [
        ("8:1", Path("/"), Path("/")),
        ("8:1", Path("/harmless"), Path("/alias")),
        ("8:1", Path("/protected/subtree"), Path("/alias")),
    ]
    with pytest.raises(preparation.HistoryPreparationError, match="ambiguous"):
        preparation._backing_path(Path("/alias/staging"), mounts)


def test_benchmark_work_target_extends_without_changing_approved_staging(launch_case):
    item, case = launch_case, launch_case.case
    sample = item.launch.model_copy(update={"through_block": case.approval.through_block - 1})
    case.save(item.path, canonical_json_bytes(sample))
    with case.open() as lease:
        runtime.preparation_command(lease, launch_path=item.path, standing_boot=case.boot)
    binding = (case.root / "preparation.lock").read_bytes()
    marker = case.root / "history" / "retained-native-owner"
    marker.write_bytes(b"completed native history must be preserved")
    before = marker.stat()
    extended = sample.model_copy(update={"through_block": case.approval.through_block})
    case.save(item.path, canonical_json_bytes(extended))
    with case.open() as lease:
        command, chosen = runtime.preparation_command(
            lease, launch_path=item.path, standing_boot=case.boot
        )
    assert chosen.through_block == case.approval.through_block
    assert (case.root / "preparation.lock").read_bytes() == binding
    assert marker.stat() == before
    assert str(case.root / "history") in command
    case.save(
        item.path,
        canonical_json_bytes(
            extended.model_copy(update={"through_block": case.approval.through_block + 1})
        ),
    )
    with case.open() as lease, pytest.raises(preparation.HistoryPreparationError, match="exceeds"):
        runtime.preparation_command(lease, launch_path=item.path, standing_boot=case.boot)


@pytest.fixture
def launch_case(case, monkeypatch, tmp_path):
    monkeypatch.setattr(runtime, "_root_owner_uid", os.getuid)
    passwd = tmp_path / "passwd"
    passwd.write_text(
        f"native-worker:x:{case.anchor.service_uid}:{case.approval.service_gid}:"
        ":/var/lib/native-worker:/usr/sbin/nologin\n"
    )
    passwd.chmod(0o644)
    monkeypatch.setattr(runtime, "PASSWD_PATH", passwd)
    source = tmp_path / "native-source"
    (source / "src" / "umi").mkdir(parents=True)
    (source / "src" / "umi" / "selected.py").write_text("# sealed code fixture\n")
    for path in (source, source / "src", source / "src" / "umi"):
        path.chmod(0o755)
    (source / "src" / "umi" / "selected.py").chmod(0o444)
    python = tmp_path / "python"
    python.mkdir(mode=0o755)
    archive = tmp_path / "portable-proofs"
    archive.mkdir(mode=0o700)
    (archive / "history").mkdir(mode=0o700)
    (case.root / "work").mkdir(mode=0o700)
    resources = {}
    for field in runtime.CompetitionChainResources.model_fields:
        if field == "state_directory":
            resources[field] = str(runtime.WORK / "finality")
        elif getattr(case.config.chain, field) is None:
            resources[field] = None
        else:
            path = tmp_path / field
            path.write_bytes(b"native executable input fixture")
            path.chmod(0o444)
            resources[field] = str(path)
    launch = runtime.HistoryPreparationLaunch(
        schema="umi-history-preparation-launch/1",
        preparation_approval_sha256=digest(case.approval),
        source_root=str(source),
        source_tree_sha256=runtime.preparation_source_identity(source),
        python_root=str(python),
        resources=resources,
        input_archive=str(archive),
    )
    path = tmp_path / "launch.json"
    case.save(path, canonical_json_bytes(launch))
    return SimpleNamespace(case=case, path=path, launch=launch, archive=archive, source=source)


def test_genuine_broker_command_exposes_only_staged_writes(launch_case):
    item, case = launch_case, launch_case.case
    with case.open() as lease:
        command, selected = runtime.preparation_command(
            lease, launch_path=item.path, standing_boot=case.boot
        )
    assert selected == item.launch
    assert "--die-with-parent" in command and "--unshare-pid" in command
    assert "--bounding-set=-all" in command
    temporary = command.index("--tmpfs")
    assert command[temporary - 2 : temporary + 2] == ["--perms", "1777", "--tmpfs", "/tmp"]
    writable = [command[i + 1 : i + 3] for i, value in enumerate(command) if value == "--bind"]
    assert writable == [
        [str(case.root / "work"), str(runtime.WORK)],
        [str(case.root / "history"), str(lease.logical_history)],
    ]
    assert str(case.held) not in command
    assert str(case.writer_lock) not in command
    assert str(case.anchor.config.wallet.path) not in command
    assert item.archive.as_posix() in command
    readonly = [command[i + 1 : i + 3] for i, value in enumerate(command) if value == "--ro-bind"]
    assert [str(runtime.PASSWD_PATH), "/etc/passwd"] in readonly
    assert "HOME" not in command
    assert "/var/lib/native-worker" not in command


@pytest.mark.parametrize("fault", ["missing", "duplicate", "gid", "home", "writable"])
def test_launcher_rejects_incompatible_account_metadata(launch_case, fault):
    item, case = launch_case, launch_case.case
    path = runtime.PASSWD_PATH
    original = path.read_text()
    if fault == "writable":
        path.chmod(0o666)
    elif fault == "duplicate":
        path.write_text(original * 2)
    elif fault == "missing":
        path.write_text("another:x:4294967294:4294967294::/:/usr/sbin/nologin\n")
    else:
        fields = original.strip().split(":")
        fields[3 if fault == "gid" else 5] = "4294967294" if fault == "gid" else "relative"
        path.write_text(":".join(fields) + "\n")
    with case.open() as lease, pytest.raises(preparation.HistoryPreparationError):
        runtime.preparation_command(lease, launch_path=item.path, standing_boot=case.boot)


@pytest.mark.parametrize("fault", ["source", "live_database", "scope", "finality_state"])
def test_launcher_rejects_changed_or_unisolated_selection(launch_case, fault):
    item, case = launch_case, launch_case.case
    if fault == "source":
        (item.source / "src" / "umi" / "selected.py").chmod(0o644)
        (item.source / "src" / "umi" / "selected.py").write_text("# changed\n")
    elif fault == "live_database":
        (item.archive / "rounds.sqlite3").write_bytes(b"not portable proof data")
    else:
        changed = (
            item.launch.model_copy(update={"preparation_approval_sha256": "ab" * 32})
            if fault == "scope"
            else item.launch.model_copy(
                update={
                    "resources": item.launch.resources.model_copy(
                        update={"state_directory": str(case.root)}
                    )
                }
            )
        )
        case.save(item.path, canonical_json_bytes(changed))
    with case.open() as lease, pytest.raises(preparation.HistoryPreparationError):
        runtime.preparation_command(lease, launch_path=item.path, standing_boot=case.boot)
    assert list((case.root / "history").iterdir()) == []


@pytest.mark.parametrize("after_acquire", [False, True])
def test_ancestor_mount_alias_to_protected_subtree_refuses(case, monkeypatch, after_acquire):
    original = Path.read_text
    source = Path(case.anchor.config.state_root) / "nested-protected-root"
    alias = case.root / "alias"
    root = alias / "staging"
    alias.mkdir(mode=0o700)
    root.mkdir(mode=0o700)
    (root / "history").mkdir(mode=0o700)
    case.save(
        case.path,
        canonical_json_bytes(case.approval.model_copy(update={"preparation_directory": str(root)})),
    )
    mountinfo = (
        f"20 1 8:1 / / rw - ext4 /dev/root rw\n21 20 8:1 {source} {alias} rw - ext4 /dev/root rw\n"
    )

    def replace_mounts():
        monkeypatch.setattr(
            Path,
            "read_text",
            lambda p, *a, **kw: (
                mountinfo if str(p) == "/proc/self/mountinfo" else original(p, *a, **kw)
            ),
        )

    if after_acquire:
        with case.open() as lease:
            replace_mounts()
            with pytest.raises(preparation.HistoryPreparationError, match="overlaps"):
                lease.recheck()
    else:
        replace_mounts()
        with pytest.raises(preparation.HistoryPreparationError, match="overlaps"), case.open():
            pytest.fail("ancestor-mounted protected subtree accepted")
        assert not (root / "preparation.lock").exists()


def test_coordinator_physical_installation_is_protected(case, monkeypatch):
    from umi import competition_coordinator_namespace as namespace

    checked = []
    layout = namespace.CoordinatorLayout("umi-validator@54.service")
    view = SimpleNamespace(layout=layout, recheck=lambda: checked.append(True))
    monkeypatch.setattr(namespace, "active_coordinator_view", lambda: view)
    protected = preparation._protected_roots(case.anchor, case.config)
    assert layout.root_directory in protected
    assert checked
    with pytest.raises(preparation.HistoryPreparationError, match="overlaps"):
        preparation._disjoint_preparation(layout.root_directory / "nested" / "staging", protected)


@pytest.mark.parametrize("fault", [None, "changed_control", "credential_mode"])
def test_readiness_preserves_selected_transport_without_reading_credential(
    launch_case, monkeypatch, fault
):
    item, case = launch_case, launch_case.case
    directory = case.root / "transport"
    directory.mkdir(mode=0o700)
    path, credential = directory / "transport.json", directory / "header.key"
    raw = canonical_json_bytes(
        {
            "schema": "umi-rpc-transport/1",
            "routes": [
                {
                    "source": "wss://archive.example.org",
                    "endpoint": "wss://proxy.example.org",
                    "authorization_file": "header.key",
                }
            ],
        }
    )
    path.write_bytes(raw)
    path.chmod(0o600)
    credential.write_bytes(b"fixture-only")
    credential.chmod(0o600)
    selected = item.launch.model_copy(
        update={"rpc_transport": str(path), "rpc_transport_sha256": hashlib.sha256(raw).hexdigest()}
    )
    case.save(item.path, canonical_json_bytes(selected))
    original = Path.read_bytes

    def read_bytes(p):
        if p == credential:
            pytest.fail("broker read a credential body")
        return original(p)

    monkeypatch.setattr(Path, "read_bytes", read_bytes)
    if fault == "changed_control":
        path.write_bytes(raw + b"\n")
    elif fault == "credential_mode":
        credential.chmod(0o644)
    with case.open() as lease:
        if fault is not None:
            with pytest.raises(preparation.HistoryPreparationError):
                runtime.preparation_command(
                    lease, launch_path=item.path, standing_boot=case.boot, action="readiness"
                )
        else:
            command, _ = runtime.preparation_command(
                lease, launch_path=item.path, standing_boot=case.boot, action="readiness"
            )
            at = command.index("UMI_RPC_TRANSPORT_CONFIG")
            assert command[at - 1 : at + 2] == ["--setenv", "UMI_RPC_TRANSPORT_CONFIG", str(path)]
            assert str(credential) in command
            assert command[-3] == "readiness"
            assert command[-2:] == [
                os.readlink("/proc/self/ns/mnt"),
                os.readlink("/proc/self/ns/pid"),
            ]
    assert list((case.root / "history").iterdir()) == []
