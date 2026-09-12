from __future__ import annotations

import fcntl
import hashlib
import os
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests.test_competition_host_artifacts import sign
from tests.test_validator_supervisor import _config
from umi import competition_host_artifacts as artifacts
from umi import competition_host_bundle as bundle


@pytest.fixture(params=["linux/amd64", "linux/arm64"])
def case(tmp_path, monkeypatch, request):
    actual_root = os.environ.get("UMI_RUN_HOST_BUNDLE_REHEARSAL") == "1"
    root_ports = (
        (bundle, "_require_root_linux"),
        (artifacts, "_current_platform"),
        (bundle, "_root_directory"),
        (bundle, "_validate_input_info"),
        (artifacts, "_immutable_owner"),
        (artifacts, "_ancestor_owner"),
        (artifacts, "_ancestor_paths"),
    )
    originals = [(module, name, getattr(module, name)) for module, name in root_ports]
    if actual_root:
        assert os.uname().sysname == "Linux" and os.geteuid() == 0
        assert str(tmp_path).startswith("/var/lib/umi-successor-hostbundle-pytest-")
        if request.param != artifacts._current_platform():
            pytest.skip("real root rehearsal only covers this machine's native architecture")
    config = _config(target_platform=request.param)
    root = tmp_path / "host-stages"
    root.mkdir(mode=0o755)
    content = {name: ("inert fixture " + name).encode() for name in artifacts._REQUIRED_FILES}
    records = [
        artifacts.HostArtifactFile(
            path=name,
            sha256=hashlib.sha256(data).hexdigest(),
            size_bytes=len(data),
            mode=0o555 if name.startswith(".venv/bin/") else 0o444,
        )
        for name, data in sorted(content.items())
    ]
    manifest = artifacts.SuccessorHostArtifactManifest(
        schema=artifacts.HOST_ARTIFACT_SCHEMA,
        channel_id=config.channel_id,
        umi_git_revision="ab" * 20,
        target_platform=request.param,
        host_entrypoint_profile="umi-competition-supervisor-host/1",
        total_size_bytes=sum(item.size_bytes for item in records),
        files=records,
    )
    source = tmp_path / "host.bundle"
    payload = bundle.HOST_BUNDLE_MAGIC + b"".join(content[item.path] for item in records)
    source.write_bytes(payload)
    source.chmod(0o400)
    monkeypatch.setattr(bundle, "_require_root_linux", lambda: None)
    monkeypatch.setattr(artifacts, "_current_platform", lambda: request.param)
    monkeypatch.setattr(artifacts, "_STAGE_PARENT", root)
    # Only Linux/root filesystem ports are replaced. Signatures, every byte
    # hash, manifest bounds, exact file sets and no-replace behavior stay real.
    monkeypatch.setattr(bundle, "_root_directory", lambda path: os.open(path, os.O_RDONLY))
    original_input = bundle._validate_input_info
    monkeypatch.setattr(
        bundle,
        "_validate_input_info",
        lambda info, size: original_input(
            SimpleNamespace(
                st_uid=0, st_mode=info.st_mode, st_nlink=info.st_nlink, st_size=info.st_size
            ),
            size,
        ),
    )
    original_owner = artifacts._immutable_owner
    monkeypatch.setattr(
        artifacts,
        "_immutable_owner",
        lambda info, mode, *, directory: original_owner(
            SimpleNamespace(st_uid=0, st_mode=info.st_mode, st_nlink=info.st_nlink),
            mode,
            directory=directory,
        ),
    )
    original_ancestor = artifacts._ancestor_owner
    monkeypatch.setattr(
        artifacts,
        "_ancestor_owner",
        lambda info: original_ancestor(SimpleNamespace(st_uid=0, st_mode=info.st_mode)),
    )
    monkeypatch.setattr(artifacts, "_ancestor_paths", lambda path: (root,))
    if actual_root:
        for module, name, original in originals:
            monkeypatch.setattr(module, name, original)
    if os.uname().sysname != "Linux":

        def no_replace(parent, source_name, target_name):
            if os.path.lexists(root / target_name):
                raise FileExistsError(target_name)
            os.rename(source_name, target_name, src_dir_fd=parent, dst_dir_fd=parent)

        monkeypatch.setattr(bundle, "_rename_noreplace", no_replace)
    result = SimpleNamespace(
        config=config,
        root=root,
        target=root / manifest.umi_git_revision,
        source=source,
        payload=payload,
        content=content,
        signed=sign(manifest),
    )
    yield result
    for path in sorted(root.rglob("*"), key=lambda path: len(path.parts)):
        if path.is_dir() and not path.is_symlink():
            path.chmod(0o755)


def _stage(case, **changes):
    arguments = dict(
        signed=case.signed, config=case.config, expected_manifest_sha256=case.signed.manifest_sha256
    )
    arguments.update(changes)
    return bundle.stage_successor_host_bundle(case.source, **arguments)


def test_exact_host_bundle_stages_verified_tree_without_execution(case, monkeypatch):
    monkeypatch.setattr(os, "system", lambda *args: pytest.fail("staging executed a command"))
    result = _stage(case)
    result.recheck()
    assert result.path == case.target
    assert set(case.root.iterdir()) == {case.target}
    for name, body in case.content.items():
        assert (case.target / name).read_bytes() == body
    before = case.target.stat().st_ino
    reused = _stage(case)
    assert reused.path.stat().st_ino == before
    assert not Path(case.config.wallet.path).exists()


@pytest.mark.parametrize("damage", ["header", "short", "long", "content"])
def test_bad_bundle_never_publishes_target(case, damage):
    payload = case.payload
    if damage == "header":
        payload = b"X" + payload[1:]
    elif damage == "short":
        payload = payload[:-1]
    elif damage == "long":
        payload += b"X"
    else:
        payload = payload[:-1] + bytes([payload[-1] ^ 1])
    case.source.chmod(0o600)
    case.source.write_bytes(payload)
    case.source.chmod(0o400)
    with pytest.raises(ValueError):
        _stage(case)
    assert not case.target.exists()
    if damage == "content":
        assert len(list(case.root.iterdir())) == 1  # retained failed stage
    else:
        assert not list(case.root.iterdir())


def test_existing_invalid_tree_is_preserved(case):
    case.target.mkdir(mode=0o700)
    marker = case.target / "operator-file"
    marker.write_bytes(b"retain me")
    with pytest.raises(ValueError):
        _stage(case)
    assert marker.read_bytes() == b"retain me"


def test_stage_slot_bound_rejects_before_new_directory(case):
    for index in range(bundle.MAX_HOST_STAGE_SLOTS):
        (case.root / f"retained-{index}").mkdir(mode=0o700)
    with pytest.raises(ValueError, match="slots exhausted"):
        _stage(case)
    assert len(list(case.root.iterdir())) == bundle.MAX_HOST_STAGE_SLOTS


def test_directory_bound_rejects_before_allocating_any_stage(case, monkeypatch):
    monkeypatch.setattr(artifacts, "MAX_HOST_DIRECTORIES", 2)
    monkeypatch.setattr(bundle, "_input", lambda *args: pytest.fail("opened oversized tree input"))
    with pytest.raises(ValueError, match="directory count"):
        _stage(case)
    assert not list(case.root.iterdir())


def test_parent_lock_serializes_global_stage_capacity(case):
    descriptor = os.open(case.root, os.O_RDONLY)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(ValueError, match="parent is busy"):
            _stage(case)
        assert not list(case.root.iterdir())
    finally:
        os.close(descriptor)


def test_permissive_umask_cannot_create_writable_intermediate_parents(case):
    previous = os.umask(0o002)
    try:
        result = _stage(case)
    finally:
        os.umask(previous)
    result.recheck()
    assert stat.S_IMODE((case.target / ".venv").stat().st_mode) == 0o555
    assert stat.S_IMODE((case.target / ".venv/bin").stat().st_mode) == 0o555


def test_wrong_approval_rejected_before_source_or_stage(case, monkeypatch):
    monkeypatch.setattr(bundle, "_input", lambda *args: pytest.fail("opened unapproved bundle"))
    with pytest.raises(ValueError, match="approved"):
        _stage(case, expected_manifest_sha256="00" * 32)
    assert not list(case.root.iterdir())


def test_changed_source_retains_partial_without_publication(case, monkeypatch):
    write = bundle._write_file
    changed = False

    def swap(root, record, descriptor):
        nonlocal changed
        write(root, record, descriptor)
        if not changed:
            case.source.chmod(0o600)
            case.source.write_bytes(case.payload)
            case.source.chmod(0o400)
            changed = True

    monkeypatch.setattr(bundle, "_write_file", swap)
    with pytest.raises(ValueError, match="changed during"):
        _stage(case)
    assert not case.target.exists()
    assert len(list(case.root.iterdir())) == 1


@pytest.mark.parametrize(
    "field,value",
    [
        ("st_uid", 1001),
        ("st_nlink", 2),
        ("st_size", 101),
        ("st_mode", stat.S_IFREG | 0o600),
        ("st_mode", stat.S_IFIFO | 0o400),
        ("st_mode", stat.S_IFLNK | 0o444),
        ("st_mode", stat.S_IFDIR | 0o444),
    ],
)
def test_input_metadata_rejects_mutable_nonroot_or_special_file(field, value):
    fields = dict(st_uid=0, st_nlink=1, st_size=100, st_mode=stat.S_IFREG | 0o400)
    fields[field] = value
    with pytest.raises(ValueError, match="root-sealed"):
        bundle._validate_input_info(SimpleNamespace(**fields), 100)
