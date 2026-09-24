from __future__ import annotations

import ast
import asyncio
import json
import os
from dataclasses import replace
from types import SimpleNamespace

import pytest
from bittensor.keyfiles import serialized_keypair_to_keyfile_data

from tests.test_competition_release import artifact, extract  # noqa: F401
from tests.test_validator_supervisor import dev_wallet
from umi import competition_container as containers


@pytest.mark.parametrize("source_hash", [None, "00" * 32])
async def test_linux_rehearsal_rejects_an_image_from_another_source_tree(
    tmp_path, monkeypatch, source_hash
):
    from tests import test_competition_container_linux as rehearsal

    archive = tmp_path / "synthetic.oci.tar"
    archive.write_bytes(b"synthetic archive, never loaded")
    monkeypatch.setenv("UMI_REHEARSAL_OCI_ARCHIVE", str(archive))
    labels = {} if source_hash is None else {"vision.umi.source-tree-sha256": source_hash}
    calls = []

    def inspect(arguments, **kwargs):
        calls.append(arguments)
        assert arguments[:3] == ["/usr/bin/podman", "image", "inspect"]
        return SimpleNamespace(stdout=json.dumps([{"Config": {"Labels": labels}}]).encode())

    monkeypatch.setattr(rehearsal.subprocess, "run", inspect)
    with pytest.raises(AssertionError, match="rebuild the rehearsal image from this checkout"):
        await rehearsal.test_real_signed_oci_load_and_inert_sandbox(tmp_path)
    assert len(calls) == 1
    assert not (tmp_path / "release-cache").exists()


def _limits(**updates):
    values = dict(
        maximum_cache_entries=4,
        maximum_cache_bytes=16 * 1024 * 1024,
        maximum_input_entries=100,
        maximum_input_bytes=8 * 1024 * 1024,
        maximum_state_entries=100,
        maximum_state_bytes=8 * 1024 * 1024,
    )
    return containers.SuccessorContainerLimits(**(values | updates))


class FakePodman:
    """Command recorder only. It cannot execute subprocesses or image contents."""

    def __init__(self, artifact):  # noqa: F811
        target = artifact.target
        self.calls = []
        self.image_present = True
        self.image = {
            "Architecture": target.target_platform.split("/")[1],
            "Os": "linux",
            "Digest": "sha256:" + target.oci_manifest_sha256,
            "Config": {
                "Labels": {
                    "org.opencontainers.image.revision": target.umi_git_revision,
                    "vision.umi.source-tree-sha256": target.umi_source_tree_sha256,
                    "vision.umi.entrypoint-profile": target.entrypoint_profile,
                }
            },
        }
        self.info = {
            "host": {
                "security": {"rootless": True},
                "cgroupVersion": "v2",
                "cgroupManager": "systemd",
                "ociRuntime": {"name": "crun"},
            }
        }
        self.container = None
        self.exit_after_start = None
        self.leave_running = False
        self.corrupt_created = None
        self.extra_rows = False
        self.rehearsal_error = None
        self.rehearsal = {"schema": "umi-successor-sandbox-rehearsal/1", "ok": True}

    async def __call__(self, arguments, **kwargs):
        assert arguments[:2] == ("/usr/bin/podman", "--cgroup-manager=systemd")
        self.calls.append(arguments)
        args = arguments[2:]
        if args[0] == "info":
            value = self.info
        elif args[:2] == ("image", "inspect"):
            if not self.image_present:
                raise containers.SuccessorContainerError("not loaded")
            value = [self.image]
        elif args[0] == "load":
            self.image_present = True
            return b"loaded"
        elif args[0] == "ps":
            value = [] if self.container is None else [{"Id": self.container["Id"]}]
            if (
                self.container is not None
                and f"--filter=name=^{self.container['Name']}$" not in args
            ):
                value = []
            if self.extra_rows:
                value *= 2
        elif args[0] == "create":
            labels = self.image["Config"]["Labels"] | dict(
                args[i + 1].split("=", 1) for i, item in enumerate(args) if item == "--label"
            )
            mounts = []
            for index, item in enumerate(args):
                if item == "--mount":
                    data = dict(pair.split("=", 1) for pair in args[index + 1].split(","))
                    mounts.append(
                        {
                            "Source": data["src"],
                            "Destination": data["dst"],
                            "RW": data["ro"] == "false",
                        }
                    )
            entry = args.index("--entrypoint")
            self.container = {
                "Id": "ab" * 32,
                "Name": args[args.index("--name") + 1],
                "Config": {
                    "Labels": labels,
                    "Cmd": list(args[entry + 3 :]),
                    "Entrypoint": [args[entry + 1]],
                },
                "ImageName": args[entry + 2],
                "Mounts": mounts,
                "HostConfig": {"ReadonlyRootfs": True},
                "State": {"Status": "created", "Running": False, "ExitCode": 0, "Pid": 0},
            }
            if (
                self.corrupt_created
                and labels.get(containers._LABEL + "purpose") != "inert-rehearsal"
            ):
                self.corrupt_created(self.container)
            return self.container["Id"].encode()
        elif args[:2] == ("container", "inspect"):
            assert args[-1] == self.container["Id"]
            value = [self.container]
        elif args[0] == "start":
            self.container["State"] = {
                "Status": "running",
                "Running": True,
                "ExitCode": 0,
                "Pid": 900,
            }
            if "--attach" in args:
                if self.rehearsal_error:
                    raise self.rehearsal_error
                self.container["State"] = {
                    "Status": "exited",
                    "Running": False,
                    "ExitCode": 0,
                    "Pid": 0,
                }
                return json.dumps(self.rehearsal).encode()
            if self.exit_after_start is not None:
                self.container["State"] = {
                    "Status": "exited",
                    "Running": False,
                    "ExitCode": self.exit_after_start,
                    "Pid": 0,
                }
            return b"started"
        elif args[0] == "stop":
            if not self.leave_running:
                self.container["State"] = {
                    "Status": "exited",
                    "Running": False,
                    "ExitCode": 143,
                    "Pid": 0,
                }
            return b"stopped"
        elif args[0] == "rm":
            assert args[-1] == self.container["Id"]
            self.container = None
            return b"removed"
        else:
            pytest.fail(f"unexpected fake command: {args[0]}")
        return json.dumps(value).encode()


@pytest.fixture
def setup(artifact, monkeypatch):  # noqa: F811
    release = extract(artifact)
    runner = FakePodman(artifact)
    adapter = containers.PodmanSuccessorContainer(
        artifact.config, limits=_limits(), command_runner=runner
    )
    # Only the OS port is replaced: signed release verification remains real.
    monkeypatch.setattr(containers.platform, "system", lambda: "Linux")
    monkeypatch.setattr(
        containers.platform,
        "machine",
        lambda: "x86_64" if artifact.config.target_platform == "linux/amd64" else "aarch64",
    )
    monkeypatch.setattr(containers, "_require_safe_executable", lambda path: None)
    # Fake Podman has no kernel scope. Real descriptor-walk tests are separate.
    monkeypatch.setattr(containers, "_require_empty_container_cgroup", lambda cid: None)
    return SimpleNamespace(release=release, runner=runner, adapter=adapter, artifact=artifact)


@pytest.fixture
def launch_setup(setup, monkeypatch, tmp_path):
    # State-machine fixture, not an authentic receipt. Separate tests verify
    # forged activation rejection and the real filesystem ownership boundary.
    cap = SimpleNamespace(
        profile="competition_replay",
        config_sha256=setup.adapter._config_sha256,
        directive_sha256="de" * 32,
        package_sha256="ef" * 32,
        authorization_sha256=None,
        directive=SimpleNamespace(release=setup.release.target),
        _inputs=SimpleNamespace(receipt_sha256="bc" * 32),
    )
    monkeypatch.setattr(setup.adapter, "_validate_activation", lambda *args: None)
    mounts = (
        containers._bind_mount(tmp_path / "activation", containers.ACTIVATION_PATH, read_only=True),
        containers._bind_mount(tmp_path / "state", containers.STATE_PATH, read_only=False),
    )
    monkeypatch.setattr(setup.adapter, "_worker_mounts", lambda activation: mounts)
    setup.cap = cap
    return setup


@pytest.mark.asyncio
async def test_exact_release_load_and_inert_rehearsal(setup):
    setup.runner.image_present = False
    await setup.adapter.prepare_image(setup.release)
    load = next(call for call in setup.runner.calls if call[2] == "load")
    assert load == (
        "/usr/bin/podman",
        "--cgroup-manager=systemd",
        "load",
        "--input",
        str(setup.release.archive_path),
    )
    run = next(call for call in setup.runner.calls if call[2] == "create")
    assert "--network=none" in run and "--cgroups=enabled" in run
    assert "--read-only" in run and "--security-opt=no-new-privileges" in run
    assert "--cap-drop=ALL" in run and "--mount" not in run
    assert "--entrypoint" in run and containers.PYTHON in run
    assert "--image-volume=ignore" in run and "--log-driver=none" in run
    assert any(arg.startswith("--tmpfs=/tmp:rw,noexec,") for arg in run)
    assert (
        "--tmpfs=/run/umi-pinned-artifacts:rw,exec,nosuid,nodev,size=134217728,mode=1777"
    ) in run
    assert "--env=UMI_PINNED_ARTIFACT_STAGE=/run/umi-pinned-artifacts/private" in run
    assert containers.HOTKEY_PATH not in run
    assert "-I" in run and not any(
        isinstance(node, ast.Assert) for node in ast.walk(ast.parse(containers._REHEARSAL))
    )
    assert setup.runner.container is None


@pytest.mark.parametrize("field", ["Architecture", "Digest", "revision", "source", "profile"])
@pytest.mark.asyncio
async def test_wrong_image_identity_never_runs(setup, field):
    if field in {"Architecture", "Digest"}:
        setup.runner.image[field] = "wrong"
    else:
        label = {
            "revision": "org.opencontainers.image.revision",
            "source": "vision.umi.source-tree-sha256",
            "profile": "vision.umi.entrypoint-profile",
        }[field]
        setup.runner.image["Config"]["Labels"][label] = "wrong"
    with pytest.raises(containers.SuccessorContainerError, match="authenticated release"):
        await setup.adapter.prepare_image(setup.release)
    assert not any(call[2] in {"run", "create", "start"} for call in setup.runner.calls)


@pytest.mark.parametrize("fault", ["rootless", "cgroup", "manager", "runtime"])
@pytest.mark.asyncio
async def test_host_requirements_fail_before_image_load(setup, fault):
    host = setup.runner.info["host"]
    if fault == "rootless":
        host["security"]["rootless"] = False
    elif fault == "cgroup":
        host["cgroupVersion"] = "v1"
    elif fault == "manager":
        host["cgroupManager"] = "cgroupfs"
    else:
        host["ociRuntime"]["name"] = "runc"
    with pytest.raises(containers.SuccessorContainerError, match="rootless Podman"):
        await setup.adapter.prepare_image(setup.release)
    assert len(setup.runner.calls) == 1


@pytest.mark.asyncio
async def test_rehearsal_failure_prevents_launch(launch_setup):
    value = launch_setup
    value.runner.rehearsal["ok"] = False
    with pytest.raises(containers.SuccessorContainerError, match="rehearsal failed"):
        await value.adapter.prepare_image(value.release)
    with pytest.raises(containers.SuccessorContainerError, match="not passed"):
        await value.adapter.launch(value.cap, value.release)


@pytest.mark.parametrize(
    "failure", [TimeoutError, asyncio.CancelledError, containers.SuccessorContainerError]
)
@pytest.mark.asyncio
async def test_failed_rehearsal_stops_exact_container_before_return(setup, failure):
    setup.runner.rehearsal_error = failure("simulated attach failure")
    with pytest.raises(failure):
        await setup.adapter.prepare_image(setup.release)
    assert setup.runner.container is None
    stops = [call for call in setup.runner.calls if call[2] == "stop"]
    assert len(stops) == 1 and stops[0][-1] == "ab" * 32
    assert not setup.adapter._rehearsed


@pytest.mark.asyncio
async def test_failed_rehearsal_cleanup_cannot_be_silently_accepted(setup):
    setup.runner.rehearsal_error = TimeoutError("simulated attach failure")
    setup.runner.leave_running = True
    with pytest.raises(containers.SuccessorContainerError, match="absence is unconfirmed"):
        await setup.adapter.prepare_image(setup.release)
    assert setup.runner.container is not None
    assert not setup.adapter._rehearsed
    with pytest.raises(containers.SuccessorContainerError, match="earlier sandbox rehearsal"):
        await setup.adapter.prepare_image(setup.release)


@pytest.mark.parametrize(
    "exit_code,phase", [(None, "running"), (0, "completed"), (3, "held"), (2, "failed")]
)
@pytest.mark.asyncio
async def test_one_shot_lifecycle_is_not_chain_proof(launch_setup, exit_code, phase):
    value = launch_setup
    await value.adapter.prepare_image(value.release)
    value.runner.exit_after_start = exit_code
    status = await value.adapter.launch(value.cap, value.release)
    assert status.phase == phase
    assert not hasattr(status, "applied") and not hasattr(status, "healthy")
    create = next(call for call in reversed(value.runner.calls) if call[2] == "create")
    assert "--rm" not in create
    assert create[-1] == "competition_replay" and "--network=none" in create
    assert "umi-validator-supervised-worker" not in create
    stopped = await value.adapter.stop()
    assert stopped.phase != "running" and value.runner.container is not None
    await value.adapter.remove_stopped()
    assert (await value.adapter.status()).phase == "absent"
    assert all("--force" not in call and "--volumes" not in call for call in value.runner.calls)


@pytest.mark.asyncio
async def test_weight_command_uses_finney_clients_without_firewall_claim(launch_setup):
    value = launch_setup
    # The launch fixture replaces authentication; this test covers fixed argv only.
    value.cap.profile = "competition_weights"
    await value.adapter.prepare_image(value.release)
    await value.adapter.launch(value.cap, value.release)
    create = next(call for call in reversed(value.runner.calls) if call[2] == "create")
    assert create[-1] == "competition_weights"
    assert "--network=slirp4netns:allow_host_loopback=false" in create
    assert "--network=host" not in create
    assert "firewall" not in " ".join(create)


@pytest.mark.asyncio
async def test_inherited_image_labels_do_not_block_managed_identity(launch_setup):
    value = launch_setup
    value.runner.image["Config"]["Labels"]["org.opencontainers.image.description"] = (
        "fixed test image"
    )
    await value.adapter.prepare_image(value.release)
    assert (await value.adapter.launch(value.cap, value.release)).phase == "running"
    assert "org.opencontainers.image.revision" in value.runner.container["Config"]["Labels"]


@pytest.mark.parametrize("fault", ["hotkey", "config", "name", "id", "mount", "cmd", "image"])
@pytest.mark.asyncio
async def test_created_identity_mismatch_never_starts(launch_setup, fault):
    value = launch_setup
    await value.adapter.prepare_image(value.release)

    def corrupt(record):
        if fault in {"hotkey", "config"}:
            record["Config"]["Labels"][containers._LABEL + fault] = "00" * 32
        elif fault == "name":
            record["Name"] = "umi-validator-supervised-worker"
        elif fault == "id":
            record["Id"] = "short-id"
        elif fault == "mount":
            record["Mounts"][0]["RW"] = True
        elif fault == "cmd":
            record["Config"]["Cmd"] = ["sh"]
        else:
            record["ImageName"] = "unrelated:latest"

    value.runner.corrupt_created = corrupt
    with pytest.raises(containers.SuccessorContainerError):
        await value.adapter.launch(value.cap, value.release)
    assert not any(call[2] == "start" and "--attach" not in call for call in value.runner.calls)


@pytest.mark.asyncio
async def test_unrelated_container_cannot_be_stopped_or_removed(launch_setup):
    value = launch_setup
    await value.adapter.prepare_image(value.release)
    await value.adapter.launch(value.cap, value.release)
    value.runner.container["Config"]["Labels"][containers._LABEL + "hotkey"] = "00" * 32
    before = len(value.runner.calls)
    for action in (value.adapter.stop, value.adapter.remove_stopped):
        with pytest.raises(containers.SuccessorContainerError, match="unrelated"):
            await action()
    assert not any(call[2] in {"stop", "rm"} for call in value.runner.calls[before:])


@pytest.mark.asyncio
async def test_stop_failure_retains_container_and_state(launch_setup):
    value = launch_setup
    await value.adapter.prepare_image(value.release)
    await value.adapter.launch(value.cap, value.release)
    value.runner.leave_running = True
    with pytest.raises(containers.SuccessorContainerError, match="absence"):
        await value.adapter.stop()
    with pytest.raises(containers.SuccessorContainerError, match="running"):
        await value.adapter.remove_stopped()
    assert value.runner.container is not None


@pytest.mark.parametrize("pid", [1, None, True, -1])
@pytest.mark.asyncio
async def test_exited_container_with_unconfirmed_pid_cannot_be_removed(launch_setup, pid):
    value = launch_setup
    await value.adapter.prepare_image(value.release)
    value.runner.exit_after_start = 0
    await value.adapter.launch(value.cap, value.release)
    value.runner.container["State"]["Pid"] = pid
    before = len(value.runner.calls)
    with pytest.raises(containers.SuccessorContainerError):
        await value.adapter.remove_stopped()
    assert not any(call[2] == "rm" for call in value.runner.calls[before:])


@pytest.mark.asyncio
async def test_forged_activation_rejected(setup):
    with pytest.raises(containers.SuccessorContainerError, match="authenticated successor"):
        await setup.adapter.launch(SimpleNamespace(profile="competition_weights"), setup.release)


@pytest.mark.parametrize(
    "fault", ["symlink", "hardlink", "fifo", "writable", "bytes", "entries", "depth", "owner"]
)
def test_bounded_tree_rejects_unsafe_inputs(tmp_path, fault):
    root = tmp_path / "tree"
    root.mkdir(mode=0o700)
    item = root / "one"
    item.write_bytes(b"example")
    item.chmod(0o400)
    owner, entries, size, depth = os.geteuid(), 20, 100, 4
    if fault == "symlink":
        (root / "two").symlink_to(item)
    elif fault == "hardlink":
        os.link(item, root / "two")
    elif fault == "fifo":
        os.mkfifo(root / "fifo", 0o600)
    elif fault == "writable":
        item.chmod(0o666)
    elif fault == "bytes":
        size = 1
    elif fault == "entries":
        entries = 0
    elif fault == "depth":
        (root / "nested").mkdir(mode=0o700)
        depth = 0
    else:
        owner += 1
    with pytest.raises(containers.SuccessorContainerError):
        containers._bounded_tree(root, owner, entries, size, depth)


def test_tree_parent_symlink_rejected(tmp_path):
    real = tmp_path / "real"
    real.mkdir(mode=0o700)
    (real / "nested").mkdir(mode=0o700)
    alias = tmp_path / "alias"
    alias.symlink_to(real)
    with pytest.raises((OSError, ValueError)):
        containers._bounded_tree(alias / "nested", os.geteuid(), 10, 10, 5)


@pytest.fixture
def kernel_tree(tmp_path, monkeypatch):
    # A fake kernel filesystem for descriptor operations, not a cgroup proof.
    root = tmp_path / "cgroup"
    root.mkdir()
    monkeypatch.setattr(containers, "_CGROUP_ROOT", root)
    cid = "a1" * 32
    scope = root / containers._container_cgroup(cid).lstrip("/")
    scope.mkdir(parents=True)
    (scope / "cgroup.procs").write_bytes(b"")
    return SimpleNamespace(root=root, scope=scope, cid=cid)


def test_stopped_scope_and_all_descendants_must_be_empty(kernel_tree):
    value = kernel_tree
    nested = value.scope / "child"
    nested.mkdir()
    (nested / "cgroup.procs").write_bytes(b"913\n")
    with pytest.raises(containers.SuccessorContainerError, match="still contains processes"):
        containers._require_empty_container_cgroup(value.cid)
    (nested / "cgroup.procs").write_bytes(b"")
    containers._require_empty_container_cgroup(value.cid)


def test_missing_exact_scope_is_absent_but_missing_kernel_root_is_not(kernel_tree):
    value = kernel_tree
    containers._require_empty_container_cgroup("a2" * 32)
    value.root.rename(value.root.with_name("unavailable"))
    with pytest.raises(FileNotFoundError):
        containers._require_empty_container_cgroup(value.cid)


@pytest.mark.parametrize("fault", ["ancestor-link", "child-link", "process-fifo"])
def test_kernel_inspection_rejects_links_and_special_files(kernel_tree, fault):
    value = kernel_tree
    if fault == "ancestor-link":
        retained = value.scope.with_name("retained")
        value.scope.rename(retained)
        value.scope.symlink_to(retained)
    elif fault == "child-link":
        (value.scope / "linked").symlink_to(value.scope)
    else:
        procs = value.scope / "cgroup.procs"
        procs.rename(value.scope / "retained-procs")
        os.mkfifo(procs)
    with pytest.raises((OSError, containers.SuccessorContainerError)):
        containers._require_empty_container_cgroup(value.cid)


def test_kernel_inspection_depth_is_bounded(kernel_tree):
    nested = kernel_tree.scope
    for _ in range(17):
        nested = nested / "child"
        nested.mkdir()
        (nested / "cgroup.procs").write_bytes(b"")
    with pytest.raises(containers.SuccessorContainerError, match="depth"):
        containers._require_empty_container_cgroup(kernel_tree.cid)


def test_exact_staged_release_reopens_without_cleanup(setup):
    reopened = setup.adapter.stage_release(setup.artifact.source, setup.release.target)
    assert reopened.archive_path.read_bytes() == setup.artifact.archive
    assert len(list(setup.release.path.iterdir())) == 3


def test_cache_limit_does_not_remove_existing_release(setup):
    setup.adapter.limits = replace(_limits(), maximum_cache_bytes=1)
    with pytest.raises(containers.SuccessorContainerError, match="byte bound"):
        setup.adapter.stage_release(setup.artifact.source, setup.release.target)
    assert setup.release.archive_path.exists()


@pytest.mark.parametrize(
    "name,value",
    [
        ("maximum_input_entries", 1.5),
        ("maximum_input_bytes", float("nan")),
        ("maximum_state_bytes", float("inf")),
        ("maximum_cache_entries", True),
        ("command_timeout_seconds", float("nan")),
        ("command_timeout_seconds", float("inf")),
    ],
)
def test_limits_cannot_disable_bounds(name, value):
    with pytest.raises(ValueError, match="positive bounds"):
        _limits(**{name: value})


@pytest.fixture
def mounted_files(setup, tmp_path, monkeypatch):
    state = tmp_path / "worker-state"
    state.mkdir(mode=0o700)
    wallets = tmp_path / "wallets"
    key_directory = wallets / "validator" / "hotkeys"
    key_directory.mkdir(parents=True, mode=0o700)
    key = key_directory / "default"
    key.write_bytes(
        bytes(serialized_keypair_to_keyfile_data(dev_wallet("//SupervisorValidator").hotkey))
    )
    key.chmod(0o400)
    # This deliberately broken coldkey path must neither be inspected nor mounted.
    (wallets / "validator" / "coldkey").symlink_to(tmp_path / "NEVER_READ")
    config = setup.artifact.config.model_copy(
        update={
            "worker_state_root": str(state),
            "wallet": setup.artifact.config.wallet.model_copy(update={"path": str(wallets)}),
        }
    )
    adapter = containers.PodmanSuccessorContainer(
        config, limits=_limits(), command_runner=setup.runner
    )
    source = tmp_path / "controls"
    source.mkdir(mode=0o700)
    # Only the root-installed receipt source boundary is replaced for mount tests.
    monkeypatch.setattr(adapter, "_activation_sources", lambda activation: source)
    return SimpleNamespace(adapter=adapter, key=key, source=source, state=state)


def test_replay_mounts_never_read_or_mount_any_wallet(mounted_files, monkeypatch):
    def forbidden(*args):
        pytest.fail("wallet-free replay read a key")

    monkeypatch.setattr(containers, "_require_wallet_hotkey_identity", forbidden)
    mounts = mounted_files.adapter._worker_mounts(SimpleNamespace(profile="competition_replay"))
    assert len(mounts) == 2 and all(
        "wallet" not in item and "hotkey" not in item for item in mounts
    )


def test_weight_mounts_only_named_readonly_hotkey(mounted_files):
    mounts = mounted_files.adapter._worker_mounts(SimpleNamespace(profile="competition_weights"))
    assert len(mounts) == 3
    assert mounts[-1] == containers._bind_mount(
        mounted_files.key, containers.HOTKEY_PATH, read_only=True
    )
    assert all("coldkey" not in item for item in mounts)


@pytest.mark.parametrize("fault", ["writable", "hardlink", "symlink", "wrong-key"])
def test_weight_hotkey_boundary_is_exact(mounted_files, fault, tmp_path):
    key = mounted_files.key
    if fault == "writable":
        key.chmod(0o600)
    elif fault == "hardlink":
        os.link(key, tmp_path / "linked-key")
    elif fault == "symlink":
        moved = key.with_name("retained-fixture")
        key.rename(moved)
        key.symlink_to(moved)
    else:
        key.chmod(0o600)
        key.write_bytes(
            bytes(serialized_keypair_to_keyfile_data(dev_wallet("//OtherValidator").hotkey))
        )
        key.chmod(0o400)
    with pytest.raises(ValueError):
        mounted_files.adapter._worker_mounts(SimpleNamespace(profile="competition_weights"))


def test_host_anchor_provenance_cannot_be_faked_by_service_ownership(setup, tmp_path, monkeypatch):
    source = tmp_path / "activation"
    source.mkdir(mode=0o700)
    (source / "anchor").mkdir(mode=0o700)
    (source / "current").mkdir(mode=0o700)
    source.chmod(0o555)
    monkeypatch.setattr(containers, "ACTIVATION_PATH", str(source))
    cap = SimpleNamespace(_inputs=SimpleNamespace(mount_root=source))
    with pytest.raises(containers.SuccessorContainerError):
        setup.adapter._activation_sources(cap)
    source.chmod(0o700)


def test_activation_parent_matches_installer_and_keeps_root_anchor_check(setup, tmp_path, monkeypatch):
    source = tmp_path / "activation"
    source.mkdir(mode=0o755)
    (source / "anchor").mkdir()
    (source / "current").mkdir()
    source.chmod(0o555)
    monkeypatch.setattr(containers, "ACTIVATION_PATH", str(source))
    checked = []
    monkeypatch.setattr(containers, "_bounded_tree", lambda path, owner, *limits: checked.append((path, owner)))
    cap = SimpleNamespace(_inputs=SimpleNamespace(mount_root=source))
    assert setup.adapter._activation_sources(cap) == source
    assert checked == [(source / "anchor", 0), (source / "current", os.geteuid())]
    source.chmod(0o755)
    with pytest.raises(containers.SuccessorContainerError, match="installed service owner"):
        setup.adapter._activation_sources(cap)


def test_activation_parent_rejects_another_service_owner(setup, tmp_path, monkeypatch):
    source = tmp_path / "activation"
    source.mkdir(mode=0o555)
    monkeypatch.setattr(containers, "ACTIVATION_PATH", str(source))
    monkeypatch.setattr(containers.os, "geteuid", lambda: source.stat().st_uid + 1)
    cap = SimpleNamespace(_inputs=SimpleNamespace(mount_root=source))
    with pytest.raises(containers.SuccessorContainerError, match="installed service owner"):
        setup.adapter._activation_sources(cap)
    source.chmod(0o700)


def test_child_environment_drops_credentials_and_remote_overrides(monkeypatch):
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret")
    monkeypatch.setenv("CONTAINER_HOST", "ssh://not-local")
    monkeypatch.setenv("LD_PRELOAD", "/tmp/injected")
    monkeypatch.setenv("PYTHONPATH", "/tmp/injected")
    environment = containers._command_environment()
    assert (
        not {"AWS_SECRET_ACCESS_KEY", "CONTAINER_HOST", "LD_PRELOAD", "PYTHONPATH"}
        & environment.keys()
    )
    assert environment["PATH"] == "/usr/bin:/bin"


class FakeProcess:
    def __init__(self, output=b"ok", exit_code=0, hangs=False):
        self.stdout = self
        self.output, self.exit_code, self.hangs = output, exit_code, hangs
        self.returncode = None
        self.killed = False

    async def read(self, amount):
        if self.hangs:
            await asyncio.Event().wait()
        result, self.output = self.output[:amount], self.output[amount:]
        return result

    async def wait(self):
        self.returncode = self.exit_code
        return self.returncode

    def kill(self):
        self.killed = True
        self.returncode = -9


@pytest.mark.parametrize("fault", ["oversized", "failed", "timeout", "cancelled"])
@pytest.mark.asyncio
async def test_command_failure_kills_child_and_never_inherits_environment(monkeypatch, fault):
    process = FakeProcess(
        output=b"x" * 20 if fault == "oversized" else b"ok",
        exit_code=2 if fault == "failed" else 0,
        hangs=fault in {"timeout", "cancelled"},
    )

    async def spawn(*args, **kwargs):
        assert kwargs["stdin"] == asyncio.subprocess.DEVNULL
        assert kwargs["stderr"] == asyncio.subprocess.DEVNULL
        assert kwargs["env"] == containers._command_environment()
        return process

    monkeypatch.setattr(asyncio, "create_subprocess_exec", spawn)
    task = asyncio.create_task(
        containers._run_command(
            ("/usr/bin/podman", "info"), timeout_seconds=0.01, maximum_output_bytes=8
        )
    )
    if fault == "cancelled":
        await asyncio.sleep(0)
        task.cancel()
    with pytest.raises(
        (containers.SuccessorContainerError, asyncio.TimeoutError, asyncio.CancelledError)
    ):
        await task
    if fault != "failed":
        assert process.killed
