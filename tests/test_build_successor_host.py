"""Exercise the release builder against real signed miniature host artifacts."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests.test_competition_host_artifacts import sign
from tests.test_validator_supervisor import _config
from umi import competition_host_artifacts as artifacts
from umi.competition_host_bundle import HOST_BUNDLE_MAGIC
from umi.competition_host_entrypoints import HOST_ENTRYPOINTS, render_host_entrypoint
from umi.protocol import canonical_json_bytes

SPEC = importlib.util.spec_from_file_location(
    "build_successor_host",
    Path(__file__).parents[1] / "tools/build_successor_host.py",
)
assert SPEC and SPEC.loader
builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(builder)


def _inventory(root):
    return {
        str(p.relative_to(root)): (p.read_bytes(), p.stat().st_mode, p.stat().st_ino)
        for p in root.rglob("*")
        if p.is_file()
    }


@pytest.fixture
def case(tmp_path, monkeypatch):
    config = _config(target_platform="linux/amd64")
    previous_revision = "ab" * 20
    hosts = tmp_path / "hosts"
    previous = hosts / previous_revision
    previous.mkdir(parents=True)
    source = tmp_path / "source"
    source.mkdir()
    content = {name: ("fixture: " + name).encode() for name in artifacts._REQUIRED_FILES}
    content.update(
        {
            "uv.lock": b"retained dependencies\n",
            "pyproject.toml": b"same project\n",
            "README.md": b"readme\n",
            "LICENSE": b"license\n",
            ".venv/pyvenv.cfg": f"command = {previous}/.venv/bin/python\n".encode(),
            ".venv/lib/python3.12/site-packages/umi.pth": f"{previous}/src\n".encode(),
            ".venv/lib/python3.12/site-packages/retained.py": b"dependency = 1\n",
        }
    )
    for name, module in HOST_ENTRYPOINTS.items():
        content[f".venv/bin/{name}"] = (
            f"#!{previous}/.venv/bin/python -I\nfrom {module} import main\nmain()\n"
        ).encode()
    records = []
    for name, data in sorted(content.items()):
        path = previous / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        mode = 0o555 if name.startswith(".venv/bin/") else 0o444
        path.chmod(mode)
        records.append(
            artifacts.HostArtifactFile(
                path=name,
                sha256=hashlib.sha256(data).hexdigest(),
                size_bytes=len(data),
                mode=mode,
            )
        )
    manifest = artifacts.SuccessorHostArtifactManifest(
        schema=artifacts.HOST_ARTIFACT_SCHEMA,
        channel_id=config.channel_id,
        umi_git_revision=previous_revision,
        target_platform=config.target_platform,
        host_entrypoint_profile="umi-competition-supervisor-host/1",
        total_size_bytes=sum(row.size_bytes for row in records),
        files=records,
    )
    signed = sign(manifest)
    shutil.copytree(previous / "src", source / "src")
    for name in ("pyproject.toml", "uv.lock", "README.md", "LICENSE"):
        shutil.copyfile(previous / name, source / name)
    (source / "src/umi/new_module.py").write_text("new_release = True\n")
    config_path, maintenance_path = tmp_path / "config.json", tmp_path / "maintenance.json"
    config_path.write_bytes(canonical_json_bytes(config))
    maintenance_path.write_bytes(
        canonical_json_bytes({"signed_host": signed.model_dump(mode="json", by_alias=True)})
    )
    # Only the OS ownership boundary is replaced. Manifest signatures and file
    # hashes, locks, source identity, bytes, no-overwrite and migrations stay real.
    monkeypatch.setattr(builder, "_require_build_owner", lambda path: None)
    events = []
    arguments = dict(
        source=source,
        output_root=tmp_path / "build",
        revision="cd" * 20,
        source_hash=builder.source_sha256(source / "src/umi"),
        previous_revision=previous_revision,
        previous_manifest_sha256=signed.manifest_sha256,
        config_path=config_path,
        maintenance_path=maintenance_path,
        hosts_root=hosts,
        minimum_build_available_bytes=1,
        emit=events.append,
    )
    return SimpleNamespace(
        arguments=arguments,
        source=source,
        previous=previous,
        signed=signed,
        events=events,
        hosts=hosts,
    )


def _build(case, **changes):
    return builder.build_successor_host(**(case.arguments | changes))


def test_signed_dependency_clone_repairs_both_launchers_without_changing_installation(case):
    before = _inventory(case.previous)
    result = _build(case)
    root = case.arguments["output_root"]
    tree = root / "unsigned-host/tree"
    destination = case.hosts / case.arguments["revision"]
    for name, module in HOST_ENTRYPOINTS.items():
        assert (tree / ".venv/bin" / name).read_bytes() == render_host_entrypoint(
            destination / ".venv/bin/python",
            module,
        )
    assert _inventory(case.previous) == before
    assert not destination.exists()
    assert result["signed"] is False and result["service_changed"] is False
    assert result["guarded_entrypoints"] == sorted(HOST_ENTRYPOINTS)
    manifest_raw = (root / "unsigned-host/host-manifest.unsigned.json").read_bytes()
    manifest = artifacts.SuccessorHostArtifactManifest.model_validate_json(manifest_raw)
    payload = (root / "unsigned-host/host.bundle.unsigned").read_bytes()
    assert hashlib.sha256(manifest_raw).hexdigest() == result["manifest_sha256"]
    assert hashlib.sha256(payload).hexdigest() == result["bundle_sha256"]
    assert payload == HOST_BUNDLE_MAGIC + b"".join(
        (tree / row.path).read_bytes() for row in manifest.files
    )
    assert (
        tree / ".venv/lib/python3.12/site-packages/retained.py"
    ).read_bytes() == b"dependency = 1\n"
    assert (tree / "src/umi/new_module.py").read_text() == "new_release = True\n"
    assert case.events[-1]["percent"] == 100 and case.events[-1]["eta_seconds"] == 0
    assert all(
        {"elapsed_seconds", "eta_basis", "stalled", "retrying"} <= event.keys()
        for event in case.events
    )
    with pytest.raises(FileExistsError, match="fresh root"):
        _build(case)


def test_guarded_successor_supports_another_dependency_preserving_upgrade(case):
    first = _build(case)
    root = case.arguments["output_root"]
    prior = case.hosts / case.arguments["revision"]
    shutil.copytree(root / "unsigned-host/tree", prior)
    manifest = artifacts.SuccessorHostArtifactManifest.model_validate_json(
        (root / "unsigned-host/host-manifest.unsigned.json").read_bytes(),
    )
    case.arguments["maintenance_path"].write_bytes(
        canonical_json_bytes({"signed_host": sign(manifest).model_dump(mode="json", by_alias=True)})
    )
    before = _inventory(prior)
    second = _build(
        case,
        previous_revision=case.arguments["revision"],
        revision="ef" * 20,
        previous_manifest_sha256=first["manifest_sha256"],
        output_root=root.with_name("second-build"),
    )
    assert second["guarded_entrypoints"] == sorted(HOST_ENTRYPOINTS)
    assert _inventory(prior) == before
    assert not (case.hosts / ("ef" * 20)).exists()


def test_wrapper_repair_checks_every_wrapper_before_writing_any(case):
    target = case.previous / ".venv/bin/umi-competition-supervisor-cleanup"
    target.chmod(0o755)
    target.write_bytes(target.read_bytes() + b"main()\n")
    before = _inventory(case.previous)
    with pytest.raises(ValueError, match="separate migration"):
        builder.repair_candidate_entrypoints(case.previous, case.previous, case.hosts / ("ef" * 20))
    assert _inventory(case.previous) == before
    with pytest.raises(ValueError, match="separate migration"):
        _build(case)
    assert not case.arguments["output_root"].exists()


@pytest.mark.parametrize("change", ["source", "lock", "previous", "signature", "manifest"])
def test_mismatched_inputs_fail_closed(case, change):
    if change == "source":
        (case.source / "src/umi/new_module.py").write_text("unexpected change\n")
    elif change == "lock":
        (case.source / "uv.lock").write_text("different dependency\n")
    elif change == "previous":
        path = case.previous / ".venv/lib/python3.12/site-packages/retained.py"
        path.chmod(0o644)
        path.write_text("dependency = 2\n")
        path.chmod(0o444)
    elif change == "signature":
        value = json.loads(case.arguments["maintenance_path"].read_bytes())
        value["signed_host"]["signatures"][0]["signature"] = "00" * 64
        case.arguments["maintenance_path"].write_bytes(canonical_json_bytes(value))
    else:
        case.arguments["previous_manifest_sha256"] = "00" * 32
    before = _inventory(case.previous)
    with pytest.raises((ValueError, artifacts.HostUpgradeError)):
        _build(case)
    assert _inventory(case.previous) == before
    assert case.events[-1]["status"] == "failed"
    assert case.events[-1]["eta_seconds"] is None
    assert not (case.arguments["output_root"] / "unsigned-host-build.json").exists()


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "unsigned", "installed", "overlap"])
def test_unsupported_layouts_refused(case, kind):
    if kind == "symlink":
        (case.source / "src/alias").symlink_to("umi", target_is_directory=True)
    elif kind == "hardlink":
        os.link(case.source / "src/umi/new_module.py", case.source / "src/umi/linked.py")
    elif kind == "unsigned":
        (case.previous / "surprise").write_text("unsigned\n")
    elif kind == "installed":
        (case.hosts / case.arguments["revision"]).mkdir()
    else:
        case.arguments["output_root"] = case.previous / "build"
    with pytest.raises((ValueError, FileExistsError)):
        _build(case)
    assert not case.arguments["output_root"].exists()


def test_build_refuses_insufficient_local_headroom(case, monkeypatch):
    monkeypatch.setattr(builder.shutil, "disk_usage", lambda path: SimpleNamespace(free=0))
    with pytest.raises(ValueError, match="headroom"):
        _build(case)
    assert not (case.arguments["output_root"] / "unsigned-host").exists()
