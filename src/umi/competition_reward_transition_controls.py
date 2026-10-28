"""Existing progression holds and exact signed operator release requests."""

from __future__ import annotations

import fcntl
import os
import stat
import threading
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field

from . import competition_host_activation as root_controls
from .competition_cohort_settlement_config import load_settlement_service_config
from .competition_service import CompetitionServiceConfig
from .open_competition import Signature, digest, identity, verify_signature
from .private_files import Directory, lock_private_file
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

MAX_CONFIG_BYTES = 8 * 1024**2
MAX_APPROVAL_BYTES = 16 * 1024


class RewardTransitionControls(StrictProtocolModel):
    admission_config: Directory
    settlement_config: Directory
    operator_approval_directory: Directory


class RewardTransitionApproval(StrictProtocolModel):
    schema_: Literal["umi-reward-transition-approval/1"] = Field(alias="schema")
    series_sha256: Hex32
    predecessor_decision_sha256: Hex32
    successor_cohort_sha256: Hex32
    successor_package_sha256: Hex32
    reason: Annotated[str, Field(min_length=1, max_length=1024)]


class SignedRewardTransitionApproval(StrictProtocolModel):
    approval: RewardTransitionApproval
    signature: Signature


def approval_path(config: RewardTransitionControls, cohort: str, package: str) -> Path:
    # Validate the identifiers before deriving a fixed filename; never scan the
    # directory or permit a caller-provided path component.
    for value in (cohort, package):
        if (
            type(value) is not str
            or len(value) != 64
            or any(c not in "0123456789abcdef" for c in value)
        ):
            raise ValueError("operator approval requires exact cohort and package digests")
    return Path(config.operator_approval_directory) / f"{cohort}-{package}.json"


def verify_transition_approval(signed, *, series, proposal=None):
    signed = SignedRewardTransitionApproval.model_validate_json(canonical_json_bytes(signed))
    if (
        signed.approval.series_sha256 != digest(series)
        or signed.approval.successor_cohort_sha256 not in {digest(p) for p in series.cohorts[1:]}
        or identity(signed.signature.hotkey) != identity(series.control_hotkey)
    ):
        raise ValueError("operator approval differs from selected series or control authority")
    verify_signature(signed.approval, signed.signature)
    if proposal is not None:
        body, release = signed.approval, proposal.early_release
        if (
            release is None
            or body.series_sha256 != proposal.series_sha256
            or body.predecessor_decision_sha256 != release.predecessor_decision_sha256
            or body.successor_cohort_sha256 != proposal.cohort_sha256
            or body.successor_package_sha256 != proposal.package_sha256
            or body.reason != release.reason
        ):
            raise ValueError("operator approval differs from its exact proposed release")
    return signed


def _identity(path, maximum):
    path = Path(path)
    parent = root_controls._open_absolute_directory(path.parent)
    try:
        info = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
    finally:
        os.close(parent)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or info.st_uid != root_controls._root_owner_uid()
        or stat.S_IMODE(info.st_mode) != 0o444
        or not 0 < info.st_size <= maximum
    ):
        raise ValueError("reward transition control must be a bounded root-owned 0444 regular file")
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _admission(path):
    # The same full model parser used by serve-intake, with the stricter native
    # root-control reader instead of an unprotected general command-line read.
    raw = root_controls._read_root_control_path(path, MAX_CONFIG_BYTES, modes={0o444})
    return CompetitionServiceConfig.model_validate_json(raw)


def publish_reward_transition_approval(config, signed, *, series) -> Path:
    """Atomically retain one control-key-signed request; never overwrite another."""
    signed = verify_transition_approval(signed, series=series)
    body = signed.approval
    path = approval_path(config, body.successor_cohort_sha256, body.successor_package_sha256)
    raw = canonical_json_bytes(signed)
    if len(raw) > MAX_APPROVAL_BYTES or os.geteuid() != root_controls._root_owner_uid():
        raise ValueError("operator approval publication requires its root owner and byte bound")
    parent = root_controls._open_absolute_directory(path.parent)
    lock = None
    try:
        info = os.fstat(parent)
        if info.st_uid != root_controls._root_owner_uid() or info.st_mode & 0o022:
            raise ValueError("operator approval directory must be root owned and protected")
        lock = lock_private_file(path.parent / ".operator-approval.lock")
        if path.exists() or path.is_symlink():
            existing = root_controls._read_root_control_path(
                path, MAX_APPROVAL_BYTES, modes={0o444}
            )
            if existing != raw:
                raise ValueError("operator approval already retains a different signed request")
            os.fsync(parent)
            return path
        temporary = path.with_name(path.name + ".pending")
        try:
            previous = temporary.lstat()
        except FileNotFoundError:
            previous = None
        if previous is not None:
            if (
                not stat.S_ISREG(previous.st_mode)
                or previous.st_nlink != 1
                or previous.st_uid != root_controls._root_owner_uid()
            ):
                raise ValueError("operator approval pending file is not independently owned")
            temporary.chmod(0o600)
        fd = os.open(temporary, os.O_CREAT | os.O_WRONLY | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        owned = False
        try:
            info = os.fstat(fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or info.st_uid != root_controls._root_owner_uid()
            ):
                raise ValueError("operator approval pending file is not independently owned")
            owned = True
            os.ftruncate(fd, 0)
            with os.fdopen(fd, "wb", closefd=False) as stream:
                stream.write(raw)
                stream.flush()
                os.fchmod(fd, 0o444)
                os.fsync(fd)
            os.replace(temporary, path)
            os.fsync(parent)
        finally:
            os.close(fd)
            if owned:
                temporary.unlink(missing_ok=True)
    finally:
        if lock is not None:
            fcntl.flock(lock, fcntl.LOCK_UN)
            os.close(lock)
        os.close(parent)
    return path


class RewardTransitionControlReader:
    def __init__(self, config: RewardTransitionControls, *, series, policy):
        if series.policy_sha256 != digest(policy):
            raise ValueError("reward transition controls differ from selected policy")
        self.config, self.series, self.policy = config, series, policy
        self.cohorts = {digest(plan): plan for plan in series.cohorts}
        self.authority = digest(series.recovery.authority)
        self._cache = {}
        self._hold_identity = None
        self._holds = frozenset()
        self._serial = threading.RLock()

    def _cached(self, path, maximum, loader):
        before = _identity(path, maximum)
        old = self._cache.get(path)
        if old is not None and old[0] == before:
            return old[1]
        value = loader(path)
        if _identity(path, maximum) != before:
            raise ValueError("reward transition control changed during its bounded read")
        self._cache[path] = (before, value)
        return value

    def _series(self, selected):
        if (
            selected.policy_sha256 != digest(self.policy)
            or selected.genesis_hash != self.series.genesis_hash
            or selected.netuid != self.series.netuid
            or identity(selected.control_hotkey) != identity(self.series.control_hotkey)
            or digest(selected.recovery.authority) != self.authority
            or not self.cohorts.keys() <= {digest(p) for p in selected.cohorts}
        ):
            raise ValueError("progression hold source differs from selected cohort authority")

    def held(self, cohort: str) -> bool:
        if cohort not in self.cohorts:
            raise ValueError("progression hold query names an unselected cohort")
        with self._serial:
            admission = self._cached(
                Path(self.config.admission_config), MAX_CONFIG_BYTES, _admission
            )
            settlement = self._cached(
                Path(self.config.settlement_config),
                MAX_CONFIG_BYTES,
                load_settlement_service_config,
            )
            stamps = tuple(
                self._cache[Path(path)][0]
                for path in (self.config.admission_config, self.config.settlement_config)
            )
            if stamps == self._hold_identity:
                return cohort in self._holds
            service = admission.recoverable_service
            if (
                service is None
                or service.lifecycle is None
                or admission.recoverable_intake is None
                or admission.policy_sha256 != digest(self.policy)
                or settlement.role != "coordinator"
                or digest(settlement.policy) != digest(self.policy)
            ):
                raise ValueError(
                    "reward transition requires authoritative admission and settlement holds"
                )
            self._series(service.series)
            self._series(settlement.series)
            bindings = {
                item.cohort_sha256: item.authority_sha256
                for item in admission.recoverable_intake.cohorts
            }
            lifecycle_bindings = {
                item.cohort_sha256: item.authority_sha256
                for item in service.lifecycle.sources.intake.cohorts
            }
            if any(
                bindings.get(key) != self.authority or lifecycle_bindings.get(key) != self.authority
                for key in self.cohorts
            ):
                raise ValueError("admission hold source changed a cohort's intake authority")
            self._holds = frozenset(
                service.lifecycle.automatic_progression_hold_cohorts
            ) | frozenset(settlement.automatic_progression_hold_cohorts)
            self._hold_identity = stamps
            return cohort in self._holds

    def approval(self, cohort: str, predecessor_sha256: str, package_sha256: str):
        if cohort not in self.cohorts:
            raise ValueError("operator approval query names an unselected cohort")
        path = approval_path(self.config, cohort, package_sha256)

        def load(path):
            raw = root_controls._read_root_control_path(path, MAX_APPROVAL_BYTES, modes={0o444})
            signed = SignedRewardTransitionApproval.model_validate_json(raw)
            if canonical_json_bytes(signed) != raw:
                raise ValueError("operator approval must retain its canonical signed bytes")
            signed = verify_transition_approval(signed, series=self.series)
            previous = self._cache.get(path)
            if previous is not None and previous[1] != signed:
                raise ValueError("operator approval replaced its previously accepted request")
            return signed

        with self._serial:
            try:
                signed = self._cached(path, MAX_APPROVAL_BYTES, load)
            except FileNotFoundError:
                if path in self._cache:
                    raise ValueError(
                        "operator approval lost its previously accepted request"
                    ) from None
                return None
            body = signed.approval
            if (
                body.successor_cohort_sha256 != cohort
                or body.successor_package_sha256 != package_sha256
                or body.predecessor_decision_sha256 != predecessor_sha256
            ):
                raise ValueError(
                    "operator approval differs from exact predecessor or successor package"
                )
            return signed
