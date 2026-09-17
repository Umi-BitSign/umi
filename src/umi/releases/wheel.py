"""Wheel metadata, source correspondence, and canonical source-tree hashing."""

from __future__ import annotations

import base64
import csv
import hashlib
import io
import re
import stat
import zipfile
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path, PurePosixPath
from typing import Any

from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.utils import canonicalize_name

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - exercised on Python 3.10
    import tomli as tomllib

from .layout import (
    MAX_WHEEL_UNCOMPRESSED_BYTES,
    ShadowReleaseError,
)


def _strict_metadata_headers(
    payload: bytes,
    *,
    label: str,
    body_required: bool,
) -> tuple[dict[str, list[str]], bytes]:
    if not payload or b"\r" in payload or b"\x00" in payload:
        raise ShadowReleaseError(f"{label}_invalid")
    if body_required:
        header_bytes, separator, body = payload.partition(b"\n\n")
        if not separator:
            raise ShadowReleaseError(f"{label}_invalid")
    else:
        header_bytes = payload[:-1] if payload.endswith(b"\n") else payload
        body = b""
        if b"\n\n" in header_bytes:
            raise ShadowReleaseError(f"{label}_invalid")

    headers: dict[str, list[str]] = {}
    for line in header_bytes.split(b"\n"):
        if not line or line[:1] in {b" ", b"\t"} or b": " not in line:
            raise ShadowReleaseError(f"{label}_invalid")
        raw_name, raw_value = line.split(b": ", 1)
        try:
            name = raw_name.decode("ascii")
            value = raw_value.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ShadowReleaseError(f"{label}_invalid") from error
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9-]*", name):
            raise ShadowReleaseError(f"{label}_invalid")
        headers.setdefault(name, []).append(value)
    return headers, body


def _single_metadata_header(headers: Mapping[str, list[str]], name: str, *, label: str) -> str:
    values = headers.get(name, [])
    if len(values) != 1:
        raise ShadowReleaseError(f"{label}_invalid")
    return values[0]


def _wheel_project_metadata(pyproject_bytes: bytes) -> Mapping[str, Any]:
    try:
        parsed = tomllib.loads(pyproject_bytes.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise ShadowReleaseError("python_project_metadata_invalid") from error
    build_system = parsed.get("build-system")
    project = parsed.get("project")
    tool = parsed.get("tool")
    hatch = tool.get("hatch") if isinstance(tool, dict) else None
    build = hatch.get("build") if isinstance(hatch, dict) else None
    targets = build.get("targets") if isinstance(build, dict) else None
    wheel_config = targets.get("wheel") if isinstance(targets, dict) else None
    if (
        not isinstance(build_system, dict)
        or build_system.get("build-backend") != "hatchling.build"
        or build_system.get("requires") != ["hatchling==1.32.0"]
        or not isinstance(project, dict)
        or not isinstance(wheel_config, dict)
        or wheel_config.get("packages") != ["src/umi"]
    ):
        raise ShadowReleaseError("python_project_build_config_invalid")
    return project


def _project_string(project: Mapping[str, Any], name: str) -> str:
    value = project.get(name)
    if not isinstance(value, str) or not value:
        raise ShadowReleaseError("python_project_metadata_invalid")
    return value


def _project_string_list(project: Mapping[str, Any], name: str) -> list[str]:
    value = project.get(name)
    if (
        not isinstance(value, list)
        or not value
        or any(not isinstance(item, str) or not item for item in value)
    ):
        raise ShadowReleaseError("python_project_metadata_invalid")
    return value


def _parsed_requirement(value: str) -> Requirement:
    try:
        return Requirement(value)
    except InvalidRequirement as error:
        raise ShadowReleaseError("python_project_requirement_invalid") from error


def _expected_project_requirements(project: Mapping[str, Any]) -> Counter[Requirement]:
    expected: Counter[Requirement] = Counter()
    for raw_requirement in _project_string_list(project, "dependencies"):
        requirement = _parsed_requirement(raw_requirement)
        if requirement.url is not None:
            raise ShadowReleaseError("python_project_requirement_unsupported")
        expected[requirement] += 1

    optional = project.get("optional-dependencies")
    if not isinstance(optional, dict) or not optional:
        raise ShadowReleaseError("python_project_metadata_invalid")
    for extra, requirements in optional.items():
        if (
            not isinstance(extra, str)
            or canonicalize_name(extra) != extra
            or not isinstance(requirements, list)
            or not requirements
        ):
            raise ShadowReleaseError("python_project_metadata_invalid")
        for raw_requirement in requirements:
            if not isinstance(raw_requirement, str) or not raw_requirement:
                raise ShadowReleaseError("python_project_metadata_invalid")
            requirement = _parsed_requirement(raw_requirement)
            if requirement.marker is not None or requirement.url is not None:
                raise ShadowReleaseError("python_project_requirement_unsupported")
            expected[_parsed_requirement(f'{raw_requirement}; extra == "{extra}"')] += 1
    return expected


def _verify_core_metadata(
    payload: bytes,
    *,
    project: Mapping[str, Any],
    readme_bytes: bytes,
) -> None:
    headers, body = _strict_metadata_headers(
        payload,
        label="python_wheel_metadata",
        body_required=True,
    )
    allowed_headers = {
        "Description-Content-Type",
        "License-Expression",
        "License-File",
        "Metadata-Version",
        "Name",
        "Provides-Extra",
        "Requires-Dist",
        "Requires-Python",
        "Summary",
        "Version",
    }
    if set(headers) != allowed_headers:
        raise ShadowReleaseError("python_wheel_metadata_fields_mismatch")
    expected_singles = {
        "Description-Content-Type": "text/markdown",
        "License-Expression": _project_string(project, "license"),
        "Metadata-Version": "2.5",
        "Name": _project_string(project, "name"),
        "Summary": _project_string(project, "description"),
        "Version": _project_string(project, "version"),
    }
    for name, expected in expected_singles.items():
        if _single_metadata_header(headers, name, label="python_wheel_metadata") != expected:
            raise ShadowReleaseError("python_wheel_metadata_mismatch")

    if project.get("readme") != "README.md" or project.get("license-files") != ["LICENSE"]:
        raise ShadowReleaseError("python_project_metadata_invalid")
    if headers["License-File"] != ["LICENSE"] or body != readme_bytes:
        raise ShadowReleaseError("python_wheel_metadata_mismatch")
    try:
        actual_python = SpecifierSet(
            _single_metadata_header(headers, "Requires-Python", label="python_wheel_metadata")
        )
        expected_python = SpecifierSet(_project_string(project, "requires-python"))
    except InvalidSpecifier as error:
        raise ShadowReleaseError("python_wheel_metadata_invalid") from error
    if actual_python != expected_python:
        raise ShadowReleaseError("python_wheel_metadata_mismatch")

    actual_requirements: Counter[Requirement] = Counter()
    for value in headers["Requires-Dist"]:
        actual_requirements[_parsed_requirement(value)] += 1
    if actual_requirements != _expected_project_requirements(project):
        raise ShadowReleaseError("python_wheel_requirements_mismatch")

    optional = project["optional-dependencies"]
    expected_extras = Counter(canonicalize_name(value) for value in optional)
    actual_extras = Counter(canonicalize_name(value) for value in headers["Provides-Extra"])
    if actual_extras != expected_extras:
        raise ShadowReleaseError("python_wheel_extras_mismatch")


def _verify_wheel_metadata(payload: bytes) -> None:
    headers, body = _strict_metadata_headers(
        payload,
        label="python_wheel_wheel_metadata",
        body_required=False,
    )
    if body or set(headers) != {"Generator", "Root-Is-Purelib", "Tag", "Wheel-Version"}:
        raise ShadowReleaseError("python_wheel_wheel_metadata_mismatch")
    expected = {
        "Generator": "hatchling 1.32.0",
        "Root-Is-Purelib": "true",
        "Tag": "py3-none-any",
        "Wheel-Version": "1.0",
    }
    for name, value in expected.items():
        if (
            _single_metadata_header(
                headers,
                name,
                label="python_wheel_wheel_metadata",
            )
            != value
        ):
            raise ShadowReleaseError("python_wheel_wheel_metadata_mismatch")


def _expected_console_scripts(project: Mapping[str, Any]) -> bytes:
    scripts = project.get("scripts")
    if not isinstance(scripts, dict) or not scripts:
        raise ShadowReleaseError("python_project_scripts_invalid")
    lines = ["[console_scripts]"]
    for name, target in sorted(scripts.items()):
        if (
            not isinstance(name, str)
            or not re.fullmatch(r"[a-z0-9][a-z0-9-]*", name)
            or not isinstance(target, str)
            or not re.fullmatch(
                r"umi(?:\.[A-Za-z_][A-Za-z0-9_]*)+:[A-Za-z_][A-Za-z0-9_]*",
                target,
            )
        ):
            raise ShadowReleaseError("python_project_scripts_invalid")
        lines.append(f"{name} = {target}")
    return ("\n".join(lines) + "\n").encode()


def _expected_record(
    ordered_names: Sequence[str],
    members: Mapping[str, bytes],
    *,
    record_name: str,
) -> bytes:
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    for name in ordered_names:
        if name == record_name:
            writer.writerow((name, "", ""))
            continue
        payload = members[name]
        digest = base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).rstrip(b"=").decode()
        writer.writerow((name, f"sha256={digest}", str(len(payload))))
    return output.getvalue().encode("utf-8")


def _verify_wheel_matches_source(
    wheel_path: Path,
    wheel_bytes: bytes,
    source_root: Path,
    *,
    pyproject_bytes: bytes,
    readme_bytes: bytes,
    license_bytes: bytes,
) -> str:
    project = _wheel_project_metadata(pyproject_bytes)
    project_name = _project_string(project, "name")
    version = _project_string(project, "version")
    wheel_distribution = canonicalize_name(project_name).replace("-", "_")
    if not re.fullmatch(r"[a-z0-9_]+", wheel_distribution) or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9._+!-]*", version
    ):
        raise ShadowReleaseError("python_project_metadata_invalid")
    expected_filename = f"{wheel_distribution}-{version}-py3-none-any.whl"
    if wheel_path.name != expected_filename:
        raise ShadowReleaseError("python_wheel_filename_mismatch")

    if not source_root.is_dir() or source_root.is_symlink():
        raise ShadowReleaseError("python_source_tree_unsafe")
    source_paths = sorted(
        source_root.rglob("*.py"),
        key=lambda path: path.relative_to(source_root).as_posix(),
    )
    if any(path.is_symlink() or not path.is_file() for path in source_paths):
        raise ShadowReleaseError("python_source_tree_unsafe")
    if not source_paths:
        raise ShadowReleaseError("python_source_tree_empty")
    package_members = {
        "umi/" + path.relative_to(source_root).as_posix(): path.read_bytes()
        for path in source_paths
    }

    dist_info = f"{wheel_distribution}-{version}.dist-info"
    metadata_name = f"{dist_info}/METADATA"
    wheel_metadata_name = f"{dist_info}/WHEEL"
    entry_points_name = f"{dist_info}/entry_points.txt"
    license_name = f"{dist_info}/licenses/LICENSE"
    record_name = f"{dist_info}/RECORD"
    expected_order = [
        *sorted(package_members),
        metadata_name,
        wheel_metadata_name,
        entry_points_name,
        license_name,
        record_name,
    ]

    if (
        len(wheel_bytes) < 22
        or not wheel_bytes.startswith(b"PK\x03\x04")
        or wheel_bytes[-22:-18] != b"PK\x05\x06"
    ):
        raise ShadowReleaseError("python_wheel_container_invalid")
    try:
        with zipfile.ZipFile(io.BytesIO(wheel_bytes)) as archive:
            if archive.comment:
                raise ShadowReleaseError("python_wheel_archive_comment")
            infos = archive.infolist()
            if not infos or sum(item.file_size for item in infos) > MAX_WHEEL_UNCOMPRESSED_BYTES:
                raise ShadowReleaseError("python_wheel_size_limit")
            if [info.filename for info in infos] != expected_order:
                raise ShadowReleaseError("python_wheel_archive_layout_mismatch")
            archive_names: set[str] = set()
            members: dict[str, bytes] = {}
            for info in infos:
                name = PurePosixPath(info.filename)
                if (
                    info.is_dir()
                    or name.is_absolute()
                    or ".." in name.parts
                    or "\\" in info.filename
                    or info.filename in archive_names
                    or info.flag_bits & 0x1
                    or info.comment
                    or info.extra
                    or info.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
                ):
                    raise ShadowReleaseError("python_wheel_archive_member_invalid")
                archive_names.add(info.filename)
                mode = info.external_attr >> 16
                if mode and stat.S_ISLNK(mode):
                    raise ShadowReleaseError("python_wheel_symlink")
                members[info.filename] = archive.read(info)
    except ShadowReleaseError:
        raise
    except (OSError, RuntimeError, zipfile.BadZipFile, zipfile.LargeZipFile) as error:
        raise ShadowReleaseError("python_wheel_invalid") from error

    if any(members[name] != payload for name, payload in package_members.items()):
        raise ShadowReleaseError("python_wheel_source_mismatch")
    if members[license_name] != license_bytes:
        raise ShadowReleaseError("python_wheel_license_mismatch")
    _verify_core_metadata(members[metadata_name], project=project, readme_bytes=readme_bytes)
    _verify_wheel_metadata(members[wheel_metadata_name])
    if members[entry_points_name] != _expected_console_scripts(project):
        raise ShadowReleaseError("python_wheel_entry_points_mismatch")
    if members[record_name] != _expected_record(
        expected_order,
        members,
        record_name=record_name,
    ):
        raise ShadowReleaseError("python_wheel_record_mismatch")
    return _umi_source_tree_sha256_from_members({name: members[name] for name in package_members})


def _umi_source_tree_sha256_from_members(package_members: Mapping[str, bytes]) -> str:
    """Hash exact wheel-resident UMI modules with the runtime source-tree domain."""

    names = sorted(package_members)
    if not names:
        raise ShadowReleaseError("python_wheel_source_tree_empty")
    digest = hashlib.sha256(b"umi-source-tree-v1\0")
    for name in names:
        path = PurePosixPath(name)
        if (
            path.is_absolute()
            or len(path.parts) < 2
            or path.parts[0] != "umi"
            or path.suffix != ".py"
            or ".." in path.parts
            or "." in path.parts
            or path.as_posix() != name
        ):
            raise ShadowReleaseError("python_wheel_source_member_invalid")
        relative = PurePosixPath(*path.parts[1:]).as_posix().encode()
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        digest.update(hashlib.sha256(package_members[name]).digest())
    return digest.hexdigest()


def _umi_source_tree_sha256_from_wheel(wheel_bytes: bytes) -> str:
    """Recompute the UMI source pin directly from an installed wheel artifact."""

    if len(wheel_bytes) < 22 or not wheel_bytes.startswith(b"PK\x03\x04"):
        raise ShadowReleaseError("python_wheel_container_invalid")
    try:
        with zipfile.ZipFile(io.BytesIO(wheel_bytes)) as archive:
            if archive.comment:
                raise ShadowReleaseError("python_wheel_archive_comment")
            infos = archive.infolist()
            if not infos or sum(item.file_size for item in infos) > MAX_WHEEL_UNCOMPRESSED_BYTES:
                raise ShadowReleaseError("python_wheel_size_limit")
            seen: set[str] = set()
            package_members: dict[str, bytes] = {}
            for info in infos:
                path = PurePosixPath(info.filename)
                if (
                    info.is_dir()
                    or path.is_absolute()
                    or ".." in path.parts
                    or "\\" in info.filename
                    or info.filename in seen
                    or info.flag_bits & 0x1
                    or info.comment
                    or info.extra
                    or info.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
                ):
                    raise ShadowReleaseError("python_wheel_archive_member_invalid")
                seen.add(info.filename)
                mode = info.external_attr >> 16
                if mode and stat.S_ISLNK(mode):
                    raise ShadowReleaseError("python_wheel_symlink")
                if len(path.parts) >= 2 and path.parts[0] == "umi" and path.suffix == ".py":
                    package_members[info.filename] = archive.read(info)
    except ShadowReleaseError:
        raise
    except (OSError, RuntimeError, zipfile.BadZipFile, zipfile.LargeZipFile) as error:
        raise ShadowReleaseError("python_wheel_invalid") from error
    return _umi_source_tree_sha256_from_members(package_members)
