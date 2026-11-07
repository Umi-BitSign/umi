"""Render an isolated preparation service from an inspected installed namespace.

Rendering grants no service or writer authority. The maintenance controller owns
root-control publication, admission, invocation verification and native handoff.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, field_validator, model_validator

from .competition_reward_preparation_selection import (
    LegacyPreparationSelection,
    legacy_preparation_selection_sha256,
)
from .private_files import Directory
from .protocol import StrictProtocolModel, canonical_json_bytes

_MAINTENANCE = "/etc/umi/validator-supervisor-maintenance.json"
_ENVIRONMENT = {"UMI_NATIVE_VERIFICATION_DIRECTORY", "UMI_RPC_TRANSPORT_CONFIG"}


def _literal(value: str) -> str:
    if not value or any(ord(c) < 32 or ord(c) == 127 or c in "$%" for c in value):
        raise ValueError("literal systemd value required")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _path(value: str) -> str:
    _literal(value)
    path = Path(value)
    if not path.is_absolute() or str(path) != value or ".." in path.parts or ":" in value:
        raise ValueError("canonical absolute systemd path required")
    return value


def _identity(value: str) -> str:
    if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,63}", value) or value == "root":
        raise ValueError("explicit non-root installed service identity required")
    return value


class PreparationMount(StrictProtocolModel):
    source: Annotated[str, Field(min_length=1, max_length=4096)]
    target: Annotated[str, Field(min_length=1, max_length=4096)]
    recursive: bool = True

    @field_validator("source", "target")
    @classmethod
    def literal_path(cls, value: str) -> str:
        return _path(value)

    def systemd(self) -> str:
        return (
            _literal(self.source)
            + ":"
            + _literal(self.target)
            + (":rbind" if self.recursive else ":norbind")
        )


class LegacyPreparationNamespace(StrictProtocolModel):
    """Exact inspected namespace fields; no writer lifetime directives are accepted."""

    schema_: Literal["umi-legacy-preparation-namespace/1"] = Field(alias="schema")
    user: str
    group: str
    supplementary_groups: tuple[str, ...] = ()
    root_directory: Directory
    bind_paths: Annotated[tuple[PreparationMount, ...], Field(max_length=256)]
    bind_read_only_paths: Annotated[tuple[PreparationMount, ...], Field(max_length=1024)]
    environment: dict[str, str]
    tasks_max: Annotated[int, Field(strict=True, gt=0, le=1048576)] | Literal["infinity"]

    @field_validator("user", "group")
    @classmethod
    def account(cls, value: str) -> str:
        return _identity(value)

    @model_validator(mode="after")
    def bindings(self) -> LegacyPreparationNamespace:
        _path(self.root_directory)
        for group in self.supplementary_groups:
            _identity(group)
        if len(set(self.supplementary_groups)) != len(self.supplementary_groups):
            raise ValueError("duplicate supplementary service group")
        targets = [m.target for m in (*self.bind_paths, *self.bind_read_only_paths)]
        if len(set(targets)) != len(targets):
            raise ValueError("ambiguous installed mount target")
        if set(self.environment) != _ENVIRONMENT:
            raise ValueError("exact installed verification and RPC environment paths required")
        for path in self.environment.values():
            _path(path)
        return self


def _overlap(left: str, right: str) -> bool:
    a, b = Path(left), Path(right)
    return a == b or a in b.parents or b in a.parents


def render_legacy_preparation_service(
    selection: LegacyPreparationSelection,
    namespace: LegacyPreparationNamespace,
    *,
    unit_name: str,
    selection_path: str,
    maintenance_path: str,
    previous_maintenance_path: str,
    provider_host_directory: str,
    config_path: str = "/etc/umi/validator-supervisor.json",
) -> bytes:
    """Select target source only in this service; preserve installed data mappings.

    The caller verifies root controls and signed maintenance, enforces aggregate
    admission for selection.maximum_memory_bytes and inspects this exact unit
    before launch. No writer dependencies, RuntimeDirectory or cleanup commands
    are inherited. Durable providers survive failures; systemd owns scratch.
    """
    if (
        type(selection) is not LegacyPreparationSelection
        or type(namespace) is not LegacyPreparationNamespace
    ):
        raise TypeError("typed native preparation selection and namespace required")
    # model_copy/model_construct and mutable mappings must not bypass the unit
    # boundary's literal-value and namespace checks.
    selection = LegacyPreparationSelection.model_validate_json(canonical_json_bytes(selection))
    namespace = LegacyPreparationNamespace.model_validate_json(canonical_json_bytes(namespace))
    if not re.fullmatch(r"umi-[a-z0-9-]{1,100}-preparation\.service", unit_name):
        raise ValueError("dedicated preparation service name required")
    for path in (
        selection_path,
        maintenance_path,
        previous_maintenance_path,
        provider_host_directory,
        config_path,
        selection.provider_directory,
    ):
        _path(path)
    mounts = (*namespace.bind_paths, *namespace.bind_read_only_paths)
    # A preparation directory must not cover or reuse an original mounted store,
    # control or binary on either side of the namespace mapping.
    for mount in mounts:
        if _overlap(mount.source, provider_host_directory) or _overlap(
            mount.target, selection.provider_directory
        ):
            raise ValueError("independent preparation directory overlaps installed bindings")
    if _overlap(namespace.root_directory, provider_host_directory):
        raise ValueError("independent preparation storage must be outside the installed root")
    for path in (selection_path, maintenance_path, previous_maintenance_path, config_path):
        if _overlap(path, selection.provider_directory) or _overlap(path, provider_host_directory):
            raise ValueError("preparation controls overlap writable provider storage")
    current = [m for m in namespace.bind_read_only_paths if m.target == _MAINTENANCE]
    if len(current) != 1 or current[0].source != previous_maintenance_path:
        raise ValueError("exact original signed maintenance mount required")
    source = "/opt/umi-validator-supervisor-hosts/" + selection.source_revision
    additions = (selection_path, source)
    if any(m.target in additions for m in mounts) or _overlap(*additions):
        raise ValueError("preparation source or control conflicts with installed mount")
    if any(
        _overlap(source, path) for path in (provider_host_directory, selection.provider_directory)
    ):
        raise ValueError("preparation provider storage overlaps selected source")
    readonly = [
        PreparationMount(source=maintenance_path, target=m.target, recursive=m.recursive)
        if m.target == _MAINTENANCE
        else m
        for m in namespace.bind_read_only_paths
    ]
    readonly.extend(PreparationMount(source=path, target=path) for path in additions)
    writable = [
        *namespace.bind_paths,
        PreparationMount(source=provider_host_directory, target=selection.provider_directory),
    ]
    argv = [
        source + "/.venv/bin/python",
        "-I",
        "-B",
        source + "/.venv/bin/umi-competition-supervisor",
        "--config",
        config_path,
        "--prepare-legacy-provider-root",
        selection.provider_directory,
        "--legacy-preparation-selection",
        selection_path,
        "--legacy-preparation-selection-sha256",
        legacy_preparation_selection_sha256(selection),
    ]
    lines = [
        "[Unit]",
        "Description=UMI retained legacy handoff preparation",
        "After=network-online.target",
        "Wants=network-online.target",
        "StartLimitIntervalSec=0",
        "",
        "[Service]",
        "Type=exec",
        "User=" + namespace.user,
        "Group=" + namespace.group,
        "SupplementaryGroups=" + " ".join(namespace.supplementary_groups),
        "RootDirectory=" + namespace.root_directory,
        "BindPaths=" + " ".join(m.systemd() for m in writable),
        "BindReadOnlyPaths=" + " ".join(m.systemd() for m in readonly),
        "Environment="
        + " ".join(_literal(k + "=" + v) for k, v in sorted(namespace.environment.items())),
        # Native pinned artifacts execute from private temporary copies. /run
        # may be mounted noexec; systemd owns and cleans this service's /tmp.
        "Environment=" + _literal("TMPDIR=/tmp"),
        "ExecStart=" + " ".join(_literal(arg) for arg in argv),
        "MemoryMax=" + str(selection.maximum_memory_bytes),
        "MemorySwapMax=0",
        "AllowedCPUs=" + " ".join(map(str, selection.background_cpus)),
        "TasksMax=" + str(namespace.tasks_max),
        "RuntimeDirectory=" + unit_name.removesuffix(".service"),
        "RuntimeDirectoryMode=0700",
        "PrivateTmp=yes",
        "UMask=0077",
        "Restart=on-failure",
        "RestartSec=15",
        "RemainAfterExit=no",
        "TimeoutStopSec=infinity",
        "SendSIGKILL=no",
        "KillMode=control-group",
        "OOMPolicy=stop",
        "",
    ]
    return "\n".join(lines).encode()
