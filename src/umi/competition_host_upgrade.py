"""Host-owned leases for preserving an already stopped legacy supervisor.

The stopped lease is process-local and cannot be reconstructed from a status
document. This module does not stop, replace, start, or authorize a successor
worker. The staged host upgrade must obtain this lease after its own preflight.
"""

from __future__ import annotations

import fcntl
import hashlib
import os
import pwd
import re
import stat
import subprocess
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

if TYPE_CHECKING:
    from .competition_host_activation import (
        AuthenticatedSuccessorActivation,
        AuthenticatedSuccessorWorkerInputs,
    )

from .competition_upgrade import _fingerprint, _open_without_links, _Reader, _verify_release
from .encoding import account_id32
from .protocol import canonical_json_bytes
from .registration_bridge import registration_bridge_policy_sha256
from .validator_supervisor import (
    MAX_SUPERVISOR_DOCUMENT_BYTES,
    advance_supervisor_directive_history_state,
    parse_canonical_signed_supervisor_directive,
    parse_canonical_supervisor_directive_state,
    parse_canonical_validator_supervisor_config,
)
from .validator_supervisor_adapters import (
    SupervisorRegistrationBridgeInputBundle,
    _parse_bootstrap_input_bundle,
)
from .validator_supervisor_runtime import DIRECTIVE_STATE_FILENAME

_ISSUER = object()
_SUCCESSOR_HANDOFFS: dict[int, Any] = {}
_UNIT_RE = re.compile(r"^umi-validator-supervisor(?:-[a-z0-9-]{1,48})?\.service$")
_PROPERTIES = (
    "Id",
    "LoadState",
    "ActiveState",
    "SubState",
    "MainPID",
    "ControlPID",
    "ControlGroup",
    "User",
    "FragmentPath",
    "ExecStart",
    "DropInPaths",
    "OnFailure",
    "RootDirectory",
    "RootImage",
    "Slice",
)


class HostUpgradeError(ValueError):
    pass


def load_successor_worker_inputs() -> AuthenticatedSuccessorWorkerInputs:
    from .competition_host_activation import load_successor_worker_inputs as load

    return load()


def load_authenticated_successor_activation(
    *, owned_observation: Any | None = None
) -> AuthenticatedSuccessorActivation:
    from .competition_host_activation import load_authenticated_successor_activation as load

    return load(owned_observation=owned_observation)


def validate_authenticated_successor_activation(
    activation: AuthenticatedSuccessorActivation,
    *,
    validator_hotkey: str,
    directive_sha256: str,
    package_sha256: str,
    authorization_sha256: str | None,
    expected_profile: Literal["competition_replay", "competition_weights"],
) -> None:
    from .competition_host_activation import validate_authenticated_successor_activation as validate

    validate(
        activation,
        validator_hotkey=validator_hotkey,
        directive_sha256=directive_sha256,
        package_sha256=package_sha256,
        authorization_sha256=authorization_sha256,
        expected_profile=expected_profile,
    )


def _require_root_linux() -> None:
    if sys.platform != "linux" or os.geteuid() != 0:
        raise HostUpgradeError("host recovery requires root on the target Linux host")


def _root_file(path: Path) -> None:
    descriptor = _open_without_links(path)
    try:
        info = os.fstat(descriptor)
        if (
            info.st_uid != 0
            or not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) & 0o022
        ):
            raise HostUpgradeError("host control file must be root-owned and not publicly writable")
    finally:
        os.close(descriptor)


def _unit_snapshot(unit_name: str, *, successor_cleanup: bool = False) -> dict[str, str]:
    # The unit grammar and fixed property list prohibit options or arbitrary calls.
    checked_name = unit_name
    if successor_cleanup:
        suffix = "-successor-cleanup.service"
        if not unit_name.endswith(suffix):
            raise HostUpgradeError("unsupported successor cleanup unit name")
        checked_name = unit_name.removesuffix(suffix) + ".service"
    if not _UNIT_RE.fullmatch(checked_name):
        raise HostUpgradeError("unsupported supervisor unit name")
    result = subprocess.run(
        [
            "/usr/bin/systemctl",
            "show",
            "--no-pager",
            "--property=" + ",".join(_PROPERTIES),
            "--",
            unit_name,
        ],
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=20,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"},
    )
    if result.returncode != 0 or len(result.stdout) > 128 * 1024:
        raise HostUpgradeError("could not inspect exact supervisor unit")
    values = {}
    for line in result.stdout.decode("utf-8", errors="strict").splitlines():
        key, separator, value = line.partition("=")
        if not separator or key not in _PROPERTIES or key in values:
            raise HostUpgradeError("unexpected systemd unit observation")
        values[key] = value
    if set(values) != set(_PROPERTIES):
        raise HostUpgradeError("incomplete systemd unit observation")
    return values


def _require_empty_cgroup(unit_name: str, reported: str) -> None:
    # A stopped service may have lost its cgroup. Never treat / as its group.
    expected = "/system.slice/" + unit_name
    if reported not in {"", expected}:
        raise HostUpgradeError("supervisor cgroup is outside its fixed system slice")
    root = Path("/sys/fs/cgroup") / expected.lstrip("/")
    try:
        initial = _open_without_links(root)
    except FileNotFoundError:
        if reported:
            raise HostUpgradeError("reported supervisor cgroup is unavailable") from None
        return
    pending = [(initial, 0)]
    seen = 0
    try:
        while pending:
            descriptor, depth = pending.pop()
            try:
                seen += 1
                if seen > 1024 or depth > 16:
                    raise HostUpgradeError("supervisor cgroup inspection exceeds its bound")
                flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
                procs = os.open("cgroup.procs", flags, dir_fd=descriptor)
                try:
                    if os.read(procs, 262145).strip():
                        raise HostUpgradeError("supervisor cgroup still contains processes")
                finally:
                    os.close(procs)
                with os.scandir(descriptor) as entries:
                    for entry in entries:
                        if entry.is_symlink():
                            raise HostUpgradeError("unexpected cgroup symlink")
                        if entry.is_dir(follow_symlinks=False):
                            if len(pending) + seen >= 1024:
                                raise HostUpgradeError("too many supervisor cgroups")
                            child = os.open(entry.name, flags | os.O_DIRECTORY, dir_fd=descriptor)
                            pending.append((child, depth + 1))
            finally:
                os.close(descriptor)
    finally:
        for descriptor, _ in pending:
            os.close(descriptor)


def _check_unit(unit_name: str, config_path: Path, service_uid: int) -> dict[str, str]:
    values = _unit_snapshot(unit_name)
    # This adapter reads paths in the host namespace. A RootDirectory/RootImage
    # service would resolve the same config and state paths to different bytes.
    # Such installations need their own authenticated namespace migration.
    if (
        values.get("RootDirectory", "")
        or values.get("RootImage", "")
        or values.get("Slice", "system.slice") != "system.slice"
    ):
        raise HostUpgradeError("supervisor filesystem or slice needs a namespace-aware upgrade")
    if (
        values["Id"] != unit_name
        or values["LoadState"] != "loaded"
        or values["ActiveState"] not in {"inactive", "failed"}
        or values["SubState"] not in {"dead", "failed"}
        or values["MainPID"] != "0"
        or values["ControlPID"] != "0"
    ):
        raise HostUpgradeError("exact supervisor unit is not stopped")
    try:
        user_uid = pwd.getpwnam(values["User"]).pw_uid
    except KeyError:
        raise HostUpgradeError("supervisor service user is unavailable") from None
    if user_uid != service_uid:
        raise HostUpgradeError("supervisor unit service user differs from the installation")
    if any(character.isspace() for character in str(config_path)):
        raise HostUpgradeError("host recovery requires an unambiguous config path")
    if ("--config " + str(config_path) + " ;") not in values["ExecStart"]:
        raise HostUpgradeError("supervisor unit is not bound to the exact installed config")
    fragment = Path(values["FragmentPath"])
    if fragment != Path("/etc/systemd/system") / unit_name:
        raise HostUpgradeError("unexpected supervisor unit fragment")
    _root_file(fragment)
    # An unexamined override could change execution or the process boundary.
    if values["DropInPaths"]:
        raise HostUpgradeError("legacy supervisor has unreviewed systemd drop-ins")
    for root in ("/etc/systemd/system", "/run/systemd/system"):
        try:
            (Path(root) / (unit_name + ".d")).lstat()
        except FileNotFoundError:
            continue
        raise HostUpgradeError("legacy supervisor has an unloaded or pending systemd drop-in")
    _require_empty_cgroup(unit_name, values["ControlGroup"])
    return values


@dataclass(slots=True)
class _StoppedLease:
    reader: _Reader
    config_path: Path
    lock_path: Path
    lock_fd: int
    lock_identity: tuple[int, ...]
    unit_snapshot: dict[str, str]
    active: bool = True
    successor_handoff: Any | None = None


@dataclass(frozen=True, slots=True)
class StoppedSupervisor:
    validator_hotkey: str
    accepted_sequence: int
    accepted_at_finalized_block: int
    accepted_directive_sha256: str
    accepted_signed_directive_sha256: str
    state_root: Path
    worker_state_root: Path
    config_sha256: str
    service_uid: int
    unit_name: str
    installation_sha256: str
    expected_manifest_sha256: str | None
    _lease: _StoppedLease = field(repr=False, compare=False)
    _issuer: object = field(default=None, repr=False, compare=False)
    _binding: str = field(default="", repr=False, compare=False)
    expected_registration_bridge_policy_sha256: str | None = None

    def recheck_stopped(self) -> None:
        if (
            type(self) is not StoppedSupervisor
            or self._issuer is not _ISSUER
            or not self._lease.active
            or self._binding != _stopped_binding(self)
            or self._lease.successor_handoff is not None
            or id(self._lease) in _SUCCESSOR_HANDOFFS
        ):
            raise HostUpgradeError("stopped-host lease is absent, altered, or closed")
        if _fingerprint(os.fstat(self._lease.lock_fd)) != self._lease.lock_identity:
            raise HostUpgradeError("supervisor process lock changed")
        descriptor = _open_without_links(self._lease.lock_path)
        try:
            if _fingerprint(os.fstat(descriptor)) != self._lease.lock_identity:
                raise HostUpgradeError("supervisor process lock was replaced")
        finally:
            os.close(descriptor)
        current = _check_unit(self.unit_name, self._lease.config_path, self.service_uid)
        if current != self._lease.unit_snapshot:
            raise HostUpgradeError("stopped supervisor unit changed during recovery")
        self._lease.reader.unchanged()


def _stopped_binding(stopped: StoppedSupervisor) -> str:
    values = {
        key: str(getattr(stopped, key))
        for key in stopped.__dataclass_fields__
        if not key.startswith("_")
    }
    return hashlib.sha256(canonical_json_bytes(values)).hexdigest()


def _consume_stopped_lease_for_successor(stopped: StoppedSupervisor) -> None:
    stopped.recheck_stopped()
    # Consumption lives outside the caller-reachable dataclass. Clearing or
    # replacing successor_handoff cannot restore legacy recovery authority.
    _SUCCESSOR_HANDOFFS[id(stopped._lease)] = None


def _bind_successor_handoff(stopped: StoppedSupervisor, handoff: Any) -> None:
    key = id(stopped._lease)
    if key not in _SUCCESSOR_HANDOFFS or _SUCCESSOR_HANDOFFS[key] is not None:
        raise HostUpgradeError("stopped lease is not awaiting its one successor handoff")
    _SUCCESSOR_HANDOFFS[key] = handoff
    stopped._lease.successor_handoff = handoff


def _successor_handoff_matches(stopped: StoppedSupervisor, handoff: Any) -> bool:
    if stopped._lease.active:
        return _SUCCESSOR_HANDOFFS.get(id(stopped._lease)) is handoff
    return stopped._lease.successor_handoff is handoff


@contextmanager
def hold_stopped_supervisor(
    *,
    config_path: Path,
    accepted_directive_bytes: bytes,
    expected_hotkey: str,
    service_uid: int,
    unit_name: str = "umi-validator-supervisor.service",
) -> Iterator[StoppedSupervisor]:
    """Authenticate one stopped legacy installation and hold its existing lock.

    No stop/restart call or wallet access occurs. Recovery outputs must live
    outside all installed roots, since the original tree must remain unchanged.
    A caller must not restart the service until this context has closed.
    """
    _require_root_linux()
    if type(service_uid) is not int or service_uid <= 0:
        raise HostUpgradeError("a dedicated non-root service UID is required")
    _root_file(config_path)
    reader = _Reader(service_uid)
    raw_config = reader.file(
        config_path,
        "config",
        MAX_SUPERVISOR_DOCUMENT_BYTES,
        modes={0o400, 0o440, 0o600, 0o640},
        root_owned=True,
    )
    config = parse_canonical_validator_supervisor_config(raw_config)
    if account_id32(config.validator_hotkey) != account_id32(expected_hotkey):
        raise HostUpgradeError("stopped installation belongs to another validator hotkey")
    unit = _check_unit(unit_name, config_path, service_uid)
    for root in (
        config.state_root,
        config.worker_state_root,
        config.release_root,
        config.operator_input_root,
    ):
        reader.directory(Path(root))
    lock_path = Path(config.state_root) / "supervisor-process.lock"
    descriptor = _open_without_links(lock_path)
    lease = None
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != service_uid
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_size > 4096
        ):
            raise HostUpgradeError("existing supervisor lock is unsafe")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise HostUpgradeError(
                "another supervisor process still holds the installation"
            ) from None
        state = parse_canonical_supervisor_directive_state(
            reader.file(
                Path(config.state_root) / DIRECTIVE_STATE_FILENAME,
                "highwater",
                MAX_SUPERVISOR_DOCUMENT_BYTES,
                modes={0o600},
            ),
            trust_policy=config.trust_policy(),
        )
        signed = parse_canonical_signed_supervisor_directive(accepted_directive_bytes)
        if (
            advance_supervisor_directive_history_state(
                signed,
                config=config,
                finalized_block=state.accepted_at_finalized_block,
                prior_state=state,
            )
            != state
        ):
            raise HostUpgradeError("retained legacy directive does not match high-water state")
        expected_manifest = None
        expected_bridge_policy = None
        if signed.directive.release is not None:
            release_root = Path(config.release_root) / state.accepted_directive_sha256
            _verify_release(reader, release_root, signed, "installed")
            if signed.directive.operator_inputs is not None:
                target = signed.directive.operator_inputs
                bundle = _parse_bootstrap_input_bundle(
                    reader.file(
                        release_root / "operator-input-bundle.json",
                        "legacy_inputs",
                        target.bundle_size_bytes,
                        modes={0o400},
                        expected_size=target.bundle_size_bytes,
                        expected_sha256=target.bundle_sha256,
                    )
                )
                if isinstance(bundle, SupervisorRegistrationBridgeInputBundle):
                    expected_bridge_policy = registration_bridge_policy_sha256(bundle.signed_policy)
                else:
                    expected_manifest = bundle.signed_manifest.manifest_sha256
        # Include the exact root-owned unit fragment in the retained identity.
        reader.file(
            Path(unit["FragmentPath"]),
            "unit_fragment",
            128 * 1024,
            modes={0o400, 0o444, 0o600, 0o644},
            root_owned=True,
        )
        lease = _StoppedLease(reader, config_path, lock_path, descriptor, _fingerprint(info), unit)
        identity = {
            "config_sha256": hashlib.sha256(raw_config).hexdigest(),
            "accepted_directive_sha256": state.accepted_directive_sha256,
            "signed_directive_bytes_sha256": hashlib.sha256(accepted_directive_bytes).hexdigest(),
            "unit_name": unit_name,
            "files": [
                {"label": item.label, "sha256": item.sha256, "size": item.size_bytes}
                for item in reader.observations
            ],
        }
        stopped = StoppedSupervisor(
            config.validator_hotkey,
            state.accepted_sequence,
            state.accepted_at_finalized_block,
            state.accepted_directive_sha256,
            hashlib.sha256(accepted_directive_bytes).hexdigest(),
            Path(config.state_root),
            Path(config.worker_state_root),
            hashlib.sha256(raw_config).hexdigest(),
            service_uid,
            unit_name,
            hashlib.sha256(canonical_json_bytes(identity)).hexdigest(),
            expected_manifest,
            lease,
            _ISSUER,
            expected_registration_bridge_policy_sha256=expected_bridge_policy,
        )
        object.__setattr__(stopped, "_binding", _stopped_binding(stopped))
        stopped.recheck_stopped()
        yield stopped
        if id(lease) not in _SUCCESSOR_HANDOFFS:
            stopped.recheck_stopped()
        else:
            # A committed source switch consumes legacy recovery authority, but
            # retains this same process lock until the context has closed.
            from .competition_host_switch import recheck_committed_successor_switch

            recheck_committed_successor_switch(_SUCCESSOR_HANDOFFS[id(lease)], require_held=True)
    finally:
        if lease is not None:
            lease.active = False
            _SUCCESSOR_HANDOFFS.pop(id(lease), None)
        os.close(descriptor)
