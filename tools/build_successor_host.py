"""Build an unsigned dependency-cloned successor host; never install or sign it.

The previous manifest and installed authority authenticate the dependency tree.
Source qualification, artifact signing, installation and native boot qualification
remain separate release steps. An incomplete output is retained for inspection;
repeat builds require a fresh output root and never replace a completed artifact.
"""

from __future__ import annotations

import argparse
import base64
import csv
import email.parser
import hashlib
import io
import json
import os
import re
import shutil
import stat
import time
from collections.abc import Callable
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit
from zipfile import ZipFile

from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

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


def _wheel_path(value: str) -> str:
    path = PurePosixPath(value)
    if (
        not value
        or path.is_absolute()
        or ".." in path.parts
        or "\\" in value
        or path.as_posix() != value
        or path.suffix == ".pth"
        or any(part.endswith(".data") for part in path.parts)
    ):
        raise ValueError("dependency wheel has an unsupported path")
    return value


def locked_wheel_migration(
    previous: Path,
    source: Path,
    wheels: tuple[Path, ...],
    signed_files: dict[str, HostArtifactFile],
) -> list[dict]:
    """Plan explicit pure-Python wheel replacements against both complete locks.

    Dependency edges, registry and all unrelated lock semantics stay identical.
    Installation scripts, namespace/shared roots and binary wheels need a separate
    supported builder; never run package installation code in the selected host.
    """
    old_raw, new_raw = ((root / "uv.lock").read_bytes() for root in (previous, source))
    if hashlib.sha256(old_raw).hexdigest() != signed_files["uv.lock"].sha256:
        raise ValueError("selected signed dependency lock differs")
    if old_raw == new_raw:
        if wheels:
            raise ValueError("dependency wheels supplied without a lock transition")
        return []
    if not wheels:
        raise ValueError("candidate dependency lock changed: supply exact locked dependency wheels")
    old, new = (tomllib.loads(raw.decode()) for raw in (old_raw, new_raw))
    old_packages, new_packages = (value.pop("package") for value in (old, new))
    old_by_name, new_by_name = (
        {p["name"]: p for p in rows} for rows in (old_packages, new_packages)
    )
    if (
        old != new
        or len(old_by_name) != len(old_packages)
        or len(new_by_name) != len(new_packages)
        or old_by_name.keys() != new_by_name.keys()
    ):
        raise ValueError("dependency lock graph or resolution semantics changed")
    changed = [name for name in old_by_name if old_by_name[name] != new_by_name[name]]
    if len(changed) != len(wheels):
        raise ValueError("supply exactly one locked wheel for every changed dependency")
    sites = list(previous.glob(".venv/lib/python*/site-packages"))
    if len(sites) != 1:
        raise ValueError("unsupported dependency installation layout")
    site = sites[0]
    plans = []
    remaining = set(wheels)
    for name in changed:
        old_package, new_package = old_by_name[name], new_by_name[name]

        def keep(package):
            return {k: v for k, v in package.items() if k not in {"version", "wheels", "sdist"}}

        if (
            keep(old_package) != keep(new_package)
            or old_package["version"] == new_package["version"]
            or set(new_package.get("source", {})) != {"registry"}
        ):
            raise ValueError("dependency migration changes edges or source semantics")
        candidates = [
            (path, row)
            for path in remaining
            for row in new_package.get("wheels", [])
            if path.name == Path(urlsplit(row["url"]).path).name
        ]
        if len(candidates) != 1:
            raise ValueError("dependency wheel is absent or ambiguous in target lock")
        wheel, locked = candidates[0]
        if (
            wheel.resolve(strict=True) != wheel
            or not stat.S_ISREG(wheel.lstat().st_mode)
            or wheel.stat().st_nlink != 1
            or not 0 < wheel.stat().st_size <= 32 * 1024**2
            or not wheel.name.endswith("-py3-none-any.whl")
        ):
            raise ValueError("dependency wheel must be one bounded unlinked pure Python wheel")
        raw = wheel.read_bytes()
        if (
            len(raw) != locked["size"]
            or "sha256:" + hashlib.sha256(raw).hexdigest() != locked["hash"]
        ):
            raise ValueError("dependency wheel differs from target lock hash or size")
        old_info = f"{name.replace('-', '_')}-{old_package['version']}.dist-info"
        new_info = f"{name.replace('-', '_')}-{new_package['version']}.dist-info"
        record = site / old_info / "RECORD"
        record_raw = record.read_bytes()
        record_key = record.relative_to(previous).as_posix()
        if (
            record_key not in signed_files
            or hashlib.sha256(record_raw).hexdigest() != signed_files[record_key].sha256
        ):
            raise ValueError("selected signed dependency RECORD differs")
        old_paths = {_wheel_path(row[0]) for row in csv.reader(io.StringIO(record_raw.decode()))}
        old_roots = {PurePosixPath(p).parts[0] for p in old_paths} - {old_info}
        if not old_roots or any(root.endswith(".dist-info") for root in old_roots):
            raise ValueError("dependency owns unsupported shared metadata")
        for root in old_roots | {old_info}:
            files = {
                p.relative_to(site).as_posix() for p in (site / root).rglob("*") if p.is_file()
            }
            if not files <= old_paths:
                raise ValueError("dependency has shared or unrecorded installed files")
        with ZipFile(io.BytesIO(raw)) as archive:
            entries = archive.infolist()
            if len({p.filename for p in entries}) != len(entries):
                raise ValueError("dependency wheel contains duplicate paths")
            if sum(p.file_size for p in entries) > 64 * 1024**2:
                raise ValueError("dependency wheel expansion exceeds bounded working set")
            files = {}
            for entry in entries:
                if entry.is_dir():
                    _wheel_path(entry.filename.rstrip("/"))
                    continue
                path = _wheel_path(entry.filename)
                if stat.S_ISLNK(entry.external_attr >> 16):
                    raise ValueError("dependency wheel contains a symlink")
                files[path] = archive.read(entry)
        if {PurePosixPath(p).parts[0] for p in files} != old_roots | {new_info}:
            raise ValueError("dependency wheel changes package ownership roots")
        metadata = email.parser.BytesParser().parsebytes(files[new_info + "/METADATA"])
        wheel_metadata = email.parser.BytesParser().parsebytes(files[new_info + "/WHEEL"])
        if (
            metadata["Name"] != name
            or metadata["Version"] != new_package["version"]
            or wheel_metadata["Root-Is-Purelib"] != "true"
            or wheel_metadata.get_all("Tag") != ["py3-none-any"]
            or new_info + "/entry_points.txt" in files
        ):
            raise ValueError("dependency wheel metadata or entry points are unsupported")
        rows = list(csv.reader(io.StringIO(files[new_info + "/RECORD"].decode())))
        if len(rows) != len(files) or {row[0] for row in rows} != files.keys():
            raise ValueError("dependency wheel RECORD inventory differs")
        for path, digest, length in rows:
            if path == new_info + "/RECORD" and digest == length == "":
                continue
            expected = "sha256=" + base64.urlsafe_b64encode(
                hashlib.sha256(files[path]).digest()
            ).decode().rstrip("=")
            if digest != expected or length != str(len(files[path])):
                raise ValueError("dependency wheel RECORD integrity differs")
        plans.append(
            {
                "site": site.relative_to(previous),
                "remove": old_paths,
                "files": files,
                "report": {
                    "name": name,
                    "previous_version": old_package["version"],
                    "version": new_package["version"],
                    "wheel_sha256": locked["hash"][7:],
                    "wheel_bytes": len(raw),
                    "removed_files": len(old_paths),
                    "installed_files": len(files),
                },
            }
        )
        remaining.remove(wheel)
    if remaining:
        raise ValueError("unused dependency wheel")
    return plans


def source_sha256(root: Path) -> str:
    """Retained release source identity, compatible with existing build receipts."""
    value = hashlib.sha256(b"umi-source-tree-v1\0")
    for path in sorted(root.rglob("*.py"), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix().encode()
        value.update(len(relative).to_bytes(4, "big"))
        value.update(relative)
        value.update(hashlib.sha256(path.read_bytes()).digest())
    return value.hexdigest()


def compatible_project_scripts(
    previous: bytes, candidate: bytes, *, promoted_requirements: tuple[str, ...] = ()
) -> list[str]:
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
        if promoted_requirements:
            new["project"]["dependencies"] = [
                item for item in new["project"]["dependencies"] if item not in promoted_requirements
            ]
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


def _signed_metadata(previous, relative, signed_files, maximum=1024**2):
    path = previous / relative
    item = signed_files.get(relative)
    try:
        info = path.lstat()
    except OSError as error:
        raise ValueError("selected signed project/dependency metadata is unavailable") from error
    if (
        item is None
        or not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or info.st_size != item.size_bytes
        or info.st_size > maximum
        or stat.S_IMODE(info.st_mode) != item.mode
    ):
        raise ValueError("selected signed project/dependency metadata differs")
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != item.sha256:
        raise ValueError("selected signed project/dependency metadata differs")
    return raw


def _promoted_requirements(previous, candidate):
    old, new = (tomllib.loads(raw.decode())["project"] for raw in (previous, candidate))
    old_dependencies, new_dependencies = (item.get("dependencies", []) for item in (old, new))
    if old_dependencies == new_dependencies:
        return old, ()
    if not all(
        isinstance(values, list) and all(isinstance(item, str) for item in values)
        for values in (old_dependencies, new_dependencies)
    ):
        raise ValueError("candidate project metadata has unsupported requirements")
    added = tuple(item for item in new_dependencies if item not in old_dependencies)
    if not added or [item for item in new_dependencies if item not in added] != old_dependencies:
        raise ValueError("candidate project metadata changes existing requirements")
    try:
        parsed = [Requirement(item) for item in new_dependencies]
    except InvalidRequirement as error:
        raise ValueError("candidate project metadata has invalid requirements") from error
    names = [canonicalize_name(item.name) for item in parsed]
    if len(names) != len(set(names)):
        raise ValueError("candidate project metadata has ambiguous requirements")
    for raw in added:
        item = Requirement(raw)
        if item.marker is not None or item.extras or item.url is not None:
            raise ValueError("promoted requirements cannot introduce markers, extras or URLs")
    return old, added


def _promotion_packages(old_raw, new_raw, project, requirements):
    old, new = (tomllib.loads(raw.decode()) for raw in (old_raw, new_raw))
    old_rows, new_rows = (value.pop("package") for value in (old, new))
    packages = [
        {canonicalize_name(row["name"]): row for row in rows} for rows in (old_rows, new_rows)
    ]
    before, after = packages
    if (
        old != new
        or len(before) != len(old_rows)
        or len(after) != len(new_rows)
        or before.keys() != after.keys()
    ):
        raise ValueError("dependency promotion changes lock resolution or package membership")
    name = canonicalize_name(project["name"])
    if name not in before:
        raise ValueError("dependency promotion lacks the exact locked project")
    root, replacement = before[name], after[name]
    if (
        root.get("source") != {"editable": "."}
        or root.get("version") != project.get("version")
        or any(before[key] != after[key] for key in before if key != name)
    ):
        raise ValueError("dependency promotion changes a resolved package or project identity")
    added = {canonicalize_name(Requirement(raw).name): Requirement(raw) for raw in requirements}
    original_edges = root.get("dependencies", [])
    if any(canonicalize_name(row["name"]) in added for row in original_edges):
        raise ValueError("promoted dependency was already a direct locked dependency")
    # Only unconditional original paths establish transitive reachability here.
    # Existing conditional paths remain unchanged but do not grant a promotion.
    reachable, pending = set(), [name]
    while pending:
        current = pending.pop()
        if current in reachable:
            continue
        reachable.add(current)
        pending.extend(
            canonicalize_name(row["name"])
            for row in before.get(current, {}).get("dependencies", [])
            if set(row) == {"name"}
        )
    for promoted, requirement in added.items():
        package = before.get(promoted)
        if (
            package is None
            or promoted not in reachable
            or set(package.get("source", {})) != {"registry"}
            or not requirement.specifier.contains(Version(package["version"]), prereleases=True)
        ):
            raise ValueError(
                "promoted requirement is not satisfied by an existing transitive package"
            )
    # Remove precisely the newly declared unconditional root edges/requirements;
    # every other field, including optional requirements and markers, stays exact.
    for field, rows in (
        ("edges", replacement.get("dependencies", [])),
        ("requirements", replacement.get("metadata", {}).get("requires-dist", [])),
    ):
        promoted_rows = [row for row in rows if canonicalize_name(row["name"]) in added]
        if len(promoted_rows) != len(added) or {
            canonicalize_name(row["name"]) for row in promoted_rows
        } != set(added):
            raise ValueError("dependency promotion has missing or duplicate root declarations")
        for row in promoted_rows:
            requirement = added[canonicalize_name(row["name"])]
            if field == "edges":
                valid = set(row) == {"name"}
            else:
                valid = (
                    set(row) <= {"name", "specifier"}
                    and SpecifierSet(row.get("specifier", "")) == requirement.specifier
                )
            if not valid:
                raise ValueError("dependency promotion has unsupported root declaration semantics")
        retained = [row for row in rows if row not in promoted_rows]
        if field == "edges":
            replacement["dependencies"] = retained
        else:
            replacement["metadata"]["requires-dist"] = retained
    if replacement != root:
        raise ValueError("dependency promotion changes other project lock semantics")
    return {key: before[key] for key in added}


def project_metadata_migration(previous, metadata_bytes, signed_files):
    """Admit only direct declarations of already installed transitive packages.

    No package resolution or payload reads occur here. The native signed clone
    verifies unchanged payload bytes later in its ordinary first copy pass.
    """
    old_project = _signed_metadata(previous, "pyproject.toml", signed_files)
    try:
        project, requirements = _promoted_requirements(
            old_project, metadata_bytes["pyproject.toml"]
        )
        scripts = compatible_project_scripts(
            old_project, metadata_bytes["pyproject.toml"], promoted_requirements=requirements
        )
        if not requirements:
            return scripts, []
        packages = _promotion_packages(
            _signed_metadata(previous, "uv.lock", signed_files),
            metadata_bytes["uv.lock"],
            project,
            requirements,
        )
    except (
        KeyError,
        TypeError,
        tomllib.TOMLDecodeError,
        InvalidSpecifier,
        InvalidVersion,
    ) as error:
        raise ValueError("candidate dependency promotion metadata is unsupported") from error
    sites = list(previous.glob(".venv/lib/python*/site-packages"))
    if len(sites) != 1:
        raise ValueError("dependency promotion needs one installed site-packages directory")
    site = sites[0]
    # Supported signed hosts expose UMI through umi.pth and do not install their
    # own distribution metadata. Never leave a present Requires-Dist stale.
    project_name = canonicalize_name(project["name"])
    installed_entries = {}
    for entry in site.iterdir():
        if entry.name.endswith((".dist-info", ".egg-info")):
            base = entry.name.rsplit(".", 1)[0]
            distribution = canonicalize_name(base.rsplit("-", 1)[0])
            installed_entries.setdefault(distribution, []).append(entry)
            if any(
                canonicalize_name(value) == project_name for value in (base, base.rsplit("-", 1)[0])
            ):
                raise ValueError(
                    "installed project distribution metadata needs a supported migration"
                )
    if _signed_metadata(
        previous, (site / "umi.pth").relative_to(previous).as_posix(), signed_files
    ).decode().strip() != str(previous / "src"):
        raise ValueError("dependency promotion needs the supported source-only project layout")
    reports = []
    for requirement in requirements:
        parsed = Requirement(requirement)
        name = canonicalize_name(parsed.name)
        version = packages[name]["version"]
        distribution = site / f"{name.replace('-', '_')}-{version}.dist-info"
        if installed_entries.get(name) != [distribution]:
            raise ValueError("promoted dependency installation is missing or ambiguous")
        relative = (distribution / "METADATA").relative_to(previous).as_posix()
        raw = _signed_metadata(previous, relative, signed_files)
        installed = email.parser.BytesParser().parsebytes(raw)
        if (
            len(installed.get_all("Name", [])) != 1
            or len(installed.get_all("Version", [])) != 1
            or canonicalize_name(installed["Name"]) != name
            or installed["Version"] != version
            or not parsed.specifier.contains(Version(installed["Version"]), prereleases=True)
        ):
            raise ValueError("installed dependency metadata does not satisfy promoted requirement")
        reports.append(
            {
                "requirement": requirement,
                "name": name,
                "version": version,
                "installed_metadata_path": relative,
                "installed_metadata_sha256": signed_files[relative].sha256,
                "project_metadata_layout": "source_only_umi_pth",
                "dependency_payloads_changed": False,
            }
        )
    return scripts, reports


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
    dependency_wheels: tuple[Path, ...] = (),
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
            dependency_wheels=dependency_wheels,
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
    dependency_wheels: tuple[Path, ...],
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
    metadata_bytes = {
        name: (source / name).read_bytes()
        for name in ("pyproject.toml", "uv.lock", "README.md", "LICENSE")
    }
    signed_files = {item.path: item for item in signed.manifest.files}
    added_scripts, promotions = project_metadata_migration(previous, metadata_bytes, signed_files)
    if promotions:
        if dependency_wheels:
            raise ValueError("dependency promotion cannot be combined with wheel changes")
        migration = []
    else:
        migration = locked_wheel_migration(previous, source, tuple(dependency_wheels), signed_files)
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
    if migration:
        progress.update("locked_dependency_migration", 0, len(migration))
        for index, plan in enumerate(migration, 1):
            site = tree / plan["site"]
            for relative in plan["remove"]:
                (site / relative).unlink()
            for relative, raw in plan["files"].items():
                target = site / relative
                if target.exists():
                    raise ValueError("dependency wheel conflicts with retained installation")
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                target.write_bytes(raw)
            parents = {
                parent
                for relative in plan["remove"]
                for parent in (site / relative).parents
                if site in parent.parents
            }
            for directory in sorted(parents, key=lambda p: len(p.parts), reverse=True):
                if directory.is_dir() and not any(directory.iterdir()):
                    directory.rmdir()
            progress.update("locked_dependency_migration", index, len(migration))
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
            target.read_bytes() != metadata_bytes[name]
            or (source / name).read_bytes() != metadata_bytes[name]
        ):
            raise ValueError("candidate metadata changed during build")
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
        "locked_dependency_migrations": [plan["report"] for plan in migration],
        "direct_dependency_promotions": promotions,
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
    parser.add_argument(
        "--dependency-wheel", dest="dependency_wheels", type=Path, action="append", default=[]
    )
    os.umask(0o077)
    _emit(build_successor_host(**vars(parser.parse_args())))


if __name__ == "__main__":
    main()
