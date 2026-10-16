"""Build an unsigned dependency-cloned successor host; never install or sign it.

The previous manifest and installed authority authenticate the dependency tree.
Source qualification, artifact signing, installation and native boot qualification
remain separate release steps. An incomplete output is retained for inspection;
repeat builds require a fresh output root and never replace a completed artifact.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import time
from collections.abc import Callable
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10 uses the locked compatibility reader.
    import tomli as tomllib

from umi.competition_host_artifacts import (
    HostArtifactFile,
    SignedSuccessorHostArtifact,
    SuccessorHostArtifactManifest,
    verify_host_artifact_authority,
)
from umi.competition_host_bundle import HOST_BUNDLE_MAGIC
from umi.competition_host_entrypoints import (
    HOST_ENTRYPOINTS,
    render_host_entrypoint,
    repair_host_entrypoint,
)
from umi.protocol import canonical_json_bytes
from umi.validator_supervisor import ValidatorSupervisorConfig

HOSTS_ROOT = Path("/opt/umi-validator-supervisor-hosts")


def source_sha256(root: Path) -> str:
    """Retained release source identity, compatible with existing build receipts."""
    value = hashlib.sha256(b"umi-source-tree-v1\0")
    for path in sorted(root.rglob("*.py"), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix().encode()
        value.update(len(relative).to_bytes(4, "big"))
        value.update(relative)
        value.update(hashlib.sha256(path.read_bytes()).digest())
    return value.hexdigest()


def compatible_project_scripts(previous: bytes, candidate: bytes) -> list[str]:
    """Permit added CLI declarations without changing cloned dependencies.

    This artifact installs only HOST_ENTRYPOINTS. Added miner/operator commands
    belong to their ordinary package installation, not the supervisor host.
    Existing declarations and all other project metadata must stay equivalent.
    """
    if previous == candidate:
        return []
    try:
        old, new = (tomllib.loads(raw.decode("utf-8")) for raw in (previous, candidate))
        old_scripts = old["project"].pop("scripts")
        new_scripts = new["project"].pop("scripts")
    except (ValueError, KeyError, TypeError) as error:
        raise ValueError("candidate project metadata needs a supported migration") from error
    if (
        not isinstance(old_scripts, dict)
        or not isinstance(new_scripts, dict)
        or old != new
        or any(new_scripts.get(name) != target for name, target in old_scripts.items())
        or any(
            old_scripts.get(name) != module + ":main" for name, module in HOST_ENTRYPOINTS.items()
        )
    ):
        raise ValueError("candidate project metadata changes dependencies or existing commands")
    added = sorted(new_scripts.keys() - old_scripts.keys())
    if any(
        not re.fullmatch(r"umi-[a-z0-9-]+", name)
        or not isinstance(new_scripts[name], str)
        or not re.fullmatch(
            r"umi(?:\.[A-Za-z_][A-Za-z_0-9]*)+:[A-Za-z_][A-Za-z_0-9]*", new_scripts[name]
        )
        for name in added
    ):
        raise ValueError("candidate added command declaration is unsupported")
    return added


def _emit(event: dict) -> None:
    print(json.dumps(event, sort_keys=True), flush=True)


class _Progress:
    def __init__(self, emit: Callable[[dict], None]):
        self.emit = emit
        self.started = time.monotonic()
        self.stage_started = self.started
        self.stage = "preflight"
        self.last_emit = 0.0

    def update(self, stage: str, completed: int, total: int) -> None:
        now = time.monotonic()
        changed = stage != self.stage
        if changed:
            self.stage, self.stage_started = stage, now
        if not changed and completed not in (0, total) and now - self.last_emit < 1:
            return
        self.last_emit = now
        elapsed = now - self.stage_started
        rate = completed / elapsed if completed and elapsed > 0 else None
        self.emit(
            {
                "stage": stage,
                "completed": completed,
                "total": total,
                "percent": completed / total * 100 if total else 100,
                "elapsed_seconds": now - self.started,
                "stage_elapsed_seconds": elapsed,
                "eta_seconds": 0
                if completed == total
                else (total - completed) / rate
                if rate
                else None,
                "planning_eta_seconds": [15, 120] if not rate and completed != total else None,
                "eta_basis": "stage complete"
                if completed == total
                else "measured stage items/second"
                if rate
                else "planning only: local dependency clone, no package resolution",
                "eta_scope": "current build substage",
                "stalled": False,
                "retrying": False,
            }
        )

    def failed(self, error: Exception) -> None:
        self.emit(
            {
                "stage": self.stage,
                "status": "failed",
                "elapsed_seconds": time.monotonic() - self.started,
                "eta_seconds": None,
                "eta_basis": "build stopped; retained output requires inspection",
                "stalled": True,
                "retrying": False,
                "error_type": type(error).__name__,
            }
        )


def _normalized(path: Path) -> None:
    if not path.is_absolute() or ".." in path.parts or path.resolve() != path:
        raise ValueError(f"build path must be absolute without symlinks: {path}")


def _regular_tree(root: Path) -> None:
    if not root.is_dir() or root.is_symlink():
        raise ValueError(f"build tree must be a directory: {root}")
    for path in root.rglob("*"):
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            continue
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError(f"build tree contains a linked or unsupported entry: {path}")


def _require_build_owner(root: Path) -> None:
    if os.geteuid() != 0:
        raise PermissionError("run unsigned host builds as root")
    info = root.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError("task build root must be root-owned mode 0700")


def _replace(path: Path, body: bytes) -> None:
    mode = stat.S_IMODE(path.stat().st_mode)
    path.chmod(0o600)
    path.write_bytes(body)
    path.chmod(mode)


def repair_candidate_entrypoints(tree: Path, previous: Path, destination: Path) -> list[str]:
    """Validate both supported wrappers before writing either unsigned wrapper."""
    replacements = []
    for name, module in HOST_ENTRYPOINTS.items():
        path = tree / ".venv/bin" / name
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not info.st_mode & 0o111:
            raise ValueError(f"unsupported host launcher metadata: {name}")
        repair_host_entrypoint(path.read_bytes(), previous / ".venv/bin/python", module)
        replacements.append(
            (path, render_host_entrypoint(destination / ".venv/bin/python", module))
        )
    for path, body in replacements:
        _replace(path, body)
    return [path.relative_to(tree).as_posix() for path, _ in replacements]


def build_successor_host(
    *,
    source: Path,
    output_root: Path,
    revision: str,
    source_hash: str,
    previous_revision: str,
    previous_manifest_sha256: str,
    config_path: Path,
    maintenance_path: Path,
    hosts_root: Path = HOSTS_ROOT,
    minimum_build_available_bytes: int = 3 * 1024**3,
    emit: Callable[[dict], None] = _emit,
) -> dict:
    """Prepare output_root/unsigned-host and unsigned-host-build.json.

    Output must be fresh. The source is a qualified, frozen snapshot; its Python
    identity is checked before and after copying and dependency locks must match
    the selected signed installation. hosts_root is explicit for isolated release
    qualification; production defaults to the fixed installed host parent.
    """
    progress = _Progress(emit)
    try:
        return _build(
            source=source,
            output_root=output_root,
            revision=revision,
            source_hash=source_hash,
            previous_revision=previous_revision,
            previous_manifest_sha256=previous_manifest_sha256,
            config_path=config_path,
            maintenance_path=maintenance_path,
            hosts_root=hosts_root,
            minimum_build_available_bytes=minimum_build_available_bytes,
            progress=progress,
        )
    except Exception as error:
        progress.failed(error)
        raise


def _build(
    *,
    source: Path,
    output_root: Path,
    revision: str,
    source_hash: str,
    previous_revision: str,
    previous_manifest_sha256: str,
    config_path: Path,
    maintenance_path: Path,
    hosts_root: Path,
    minimum_build_available_bytes: int,
    progress: _Progress,
) -> dict:
    progress.update("preflight", 0, 1)
    for value, length in (
        (revision, 40),
        (previous_revision, 40),
        (source_hash, 64),
        (previous_manifest_sha256, 64),
    ):
        if not re.fullmatch(rf"[0-9a-f]{{{length}}}", value):
            raise ValueError("invalid pinned revision or digest")
    if revision == previous_revision:
        raise ValueError("successor requires a new immutable revision")
    if minimum_build_available_bytes <= 0:
        raise ValueError("minimum build headroom must be positive")
    for path in (source, output_root, hosts_root):
        _normalized(path)
    for other in (source, hosts_root):
        if output_root == other or output_root in other.parents or other in output_root.parents:
            raise ValueError("build output must be separate from source and installed hosts")
    for path in (config_path, maintenance_path):
        if not path.is_absolute() or output_root == path or output_root in path.parents:
            raise ValueError("build output must not contain installed control inputs")
    if os.path.lexists(output_root):
        raise FileExistsError("build root exists; inspect retained output and choose a fresh root")
    previous, destination = hosts_root / previous_revision, hosts_root / revision
    if os.path.lexists(destination):
        raise FileExistsError("candidate host is already installed")
    for name in ("pyproject.toml", "uv.lock", "README.md", "LICENSE"):
        info = (source / name).lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError(f"source metadata must be an unlinked regular file: {name}")
    _regular_tree(source / "src")
    _regular_tree(previous)
    if source_sha256(source / "src/umi") != source_hash:
        raise ValueError("candidate source tree differs")
    config_raw = config_path.read_bytes()
    config = ValidatorSupervisorConfig.model_validate_json(config_raw)
    if canonical_json_bytes(config) != config_raw:
        raise ValueError("installed validator config is not canonical")
    maintenance = json.loads(maintenance_path.read_bytes())
    signed = SignedSuccessorHostArtifact.model_validate(maintenance["signed_host"])
    if signed.manifest.umi_git_revision != previous_revision:
        raise ValueError("currently approved host revision differs")
    verify_host_artifact_authority(
        signed,
        config=config,
        expected_manifest_sha256=previous_manifest_sha256,
    )
    if (source / "uv.lock").read_bytes() != (previous / "uv.lock").read_bytes():
        raise ValueError("candidate dependency lock changed: uv.lock")
    added_scripts = compatible_project_scripts(
        (previous / "pyproject.toml").read_bytes(), (source / "pyproject.toml").read_bytes()
    )
    signed_paths = {item.path for item in signed.manifest.files}
    actual_paths = {p.relative_to(previous).as_posix() for p in previous.rglob("*") if p.is_file()}
    extras = actual_paths - signed_paths
    if any("/__pycache__/" not in f"/{p}" or not p.endswith(".pyc") for p in extras):
        raise ValueError(f"selected host has unexpected unsigned entries: {sorted(extras)}")
    if signed_paths - actual_paths:
        raise ValueError("selected host is missing signed entries")
    # Refuse unknown launchers before making even the unsigned candidate.
    for name, module in HOST_ENTRYPOINTS.items():
        repair_host_entrypoint(
            (previous / ".venv/bin" / name).read_bytes(),
            previous / ".venv/bin/python",
            module,
        )
    output_root.mkdir(mode=0o700, parents=True)
    _require_build_owner(output_root)
    if shutil.disk_usage(output_root).free < minimum_build_available_bytes:
        raise ValueError("insufficient build headroom")
    output = output_root / "unsigned-host"
    output.mkdir(mode=0o700)
    tree = output / "tree"
    progress.update("preflight", 1, 1)
    progress.update("dependency_clone", 0, len(signed_paths))
    copied = 0

    def copy_file(src, dst):
        nonlocal copied
        result = shutil.copy2(src, dst)
        copied += 1
        progress.update("dependency_clone", copied, len(signed_paths))
        return result

    shutil.copytree(
        previous,
        tree,
        copy_function=copy_file,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
    )
    progress.update("copied_signed_files", 0, len(signed.manifest.files))
    for index, item in enumerate(signed.manifest.files, 1):
        path = tree / item.path
        info = path.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != item.mode
            or info.st_size != item.size_bytes
            or hashlib.sha256(path.read_bytes()).hexdigest() != item.sha256
        ):
            raise ValueError(f"copied signed host differs: {item.path}")
        progress.update("copied_signed_files", index, len(signed.manifest.files))
    for path in (tree, *tree.rglob("*")):
        if path.is_dir():
            path.chmod(0o700)
    progress.update("source_and_launcher_migration", 0, 1)
    shutil.rmtree(tree / "src")
    shutil.copytree(
        source / "src", tree / "src", ignore=shutil.ignore_patterns("__pycache__", "*.pyc")
    )
    for name in ("pyproject.toml", "uv.lock", "README.md", "LICENSE"):
        target = tree / name
        target.chmod(0o600)
        shutil.copyfile(source / name, target)
    if (
        source_sha256(tree / "src/umi") != source_hash
        or source_sha256(source / "src/umi") != source_hash
    ):
        raise ValueError("candidate source changed during build")
    rewritten = repair_candidate_entrypoints(tree, previous, destination)
    old, new = str(previous).encode(), str(destination).encode()
    candidates = [
        tree / ".venv/pyvenv.cfg",
        *(tree / ".venv/lib").glob("python*/site-packages/umi.pth"),
        *(tree / ".venv/bin").iterdir(),
    ]
    pth_paths = [path for path in candidates if path.name == "umi.pth"]
    if len(pth_paths) != 1:
        raise ValueError("unsupported virtual environment import layout")
    for path in candidates:
        if not path.is_file() or path.name in HOST_ENTRYPOINTS:
            continue
        body = path.read_bytes()
        if (
            path.name in {"pyvenv.cfg", "umi.pth"}
            or body.startswith(b"#!")
            or path.name.startswith("activate")
        ) and old in body:
            _replace(path, body.replace(old, new))
            if old in path.read_bytes():
                raise ValueError(f"old immutable host path remains: {path}")
            rewritten.append(path.relative_to(tree).as_posix())
    if pth_paths[0].read_text().strip() != str(destination / "src"):
        raise ValueError("candidate import path differs")
    progress.update("source_and_launcher_migration", 1, 1)
    _regular_tree(tree)
    paths = sorted(
        (p for p in tree.rglob("*") if p.is_file()), key=lambda p: p.relative_to(tree).as_posix()
    )
    files = []
    progress.update("manifest_files", 0, len(paths))
    for index, path in enumerate(paths, 1):
        mode = 0o555 if path.stat().st_mode & 0o111 else 0o444
        path.chmod(mode)
        files.append(
            HostArtifactFile(
                path=path.relative_to(tree).as_posix(),
                sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                size_bytes=path.stat().st_size,
                mode=mode,
            )
        )
        progress.update("manifest_files", index, len(paths))
    manifest = SuccessorHostArtifactManifest(
        schema="umi-successor-host-artifact/1",
        channel_id=signed.manifest.channel_id,
        umi_git_revision=revision,
        target_platform=signed.manifest.target_platform,
        host_entrypoint_profile=signed.manifest.host_entrypoint_profile,
        total_size_bytes=sum(item.size_bytes for item in files),
        files=files,
    )
    manifest_raw = canonical_json_bytes(manifest)
    manifest_path = output / "host-manifest.unsigned.json"
    manifest_path.write_bytes(manifest_raw)
    bundle_path = output / "host.bundle.unsigned"
    bundle_digest = hashlib.sha256()
    progress.update("bundle_files", 0, len(files))
    with bundle_path.open("xb") as stream:
        stream.write(HOST_BUNDLE_MAGIC)
        bundle_digest.update(HOST_BUNDLE_MAGIC)
        for index, item in enumerate(files, 1):
            body = (tree / item.path).read_bytes()
            if hashlib.sha256(body).hexdigest() != item.sha256:
                raise ValueError(f"host file changed during build: {item.path}")
            stream.write(body)
            bundle_digest.update(body)
            progress.update("bundle_files", index, len(files))
        stream.flush()
        os.fsync(stream.fileno())
    manifest_path.chmod(0o400)
    bundle_path.chmod(0o400)
    result = {
        "status": "unsigned_successor_host_prepared",
        "source_revision": revision,
        "source_sha256": source_hash,
        "previous_revision": previous_revision,
        "previous_manifest_sha256": previous_manifest_sha256,
        "manifest_sha256": hashlib.sha256(manifest_raw).hexdigest(),
        "bundle_sha256": bundle_digest.hexdigest(),
        "file_count": len(files),
        "tree_size_bytes": manifest.total_size_bytes,
        "rewritten_paths": sorted(rewritten),
        "guarded_entrypoints": sorted(HOST_ENTRYPOINTS),
        "uninstalled_added_project_scripts": added_scripts,
        "wallet_accessed": False,
        "signed": False,
        "staged": False,
        "service_changed": False,
    }
    result_path = output_root / "unsigned-host-build.json"
    result_path.write_bytes(canonical_json_bytes(result))
    result_path.chmod(0o444)
    progress.update("unsigned_host_complete", 1, 1)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "output-root", "config-path", "maintenance-path"):
        parser.add_argument(f"--{name}", type=Path, required=True)
    for name in ("revision", "source-hash", "previous-revision", "previous-manifest-sha256"):
        parser.add_argument(f"--{name}", required=True)
    parser.add_argument("--hosts-root", type=Path, default=HOSTS_ROOT)
    parser.add_argument("--minimum-build-available-bytes", type=int, default=3 * 1024**3)
    os.umask(0o077)
    _emit(build_successor_host(**vars(parser.parse_args())))


if __name__ == "__main__":
    main()
