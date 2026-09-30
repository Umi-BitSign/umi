"""Bind standing execution to an approved installation and its retained journal.

Approval is a root-owned local input. It cannot replace native package, chain,
handoff or transaction verification. Durable journal identity survives copying
preserved state to another host; device/inode checks apply only within a process.
"""

from __future__ import annotations

import hashlib
import os
import secrets
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from pydantic import Field

from .competition_host_activation import _read_root_control_path
from .competition_reward_handoff_models import (
    LegacyRewardHandoffPlan,
    VerifiedLegacyRewardHandoff,
    validate_legacy_handoff,
)
from .competition_reward_preparation import PreparedStandingReward, StandingRewardPreparation
from .competition_reward_transactions import StandingWeightJournal
from .competition_supervisor_runtime import SuccessorSupervisorRuntime
from .open_competition import Hotkey, digest
from .private_files import lock_private_file, private_path
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

_MAX_BYTES = 8192
_ISSUER = object()


def _root_control(path: Path, maximum: int) -> bytes:
    return _read_root_control_path(path, maximum, modes={0o444})


class StandingRewardHostApproval(StrictProtocolModel):
    schema_: Literal["umi-standing-reward-host-approval/1"] = Field(alias="schema")
    source_config_sha256: Hex32
    installation_receipt_sha256: Hex32
    host_manifest_sha256: Hex32
    validator_hotkey: Hotkey
    series_sha256: Hex32
    policy_sha256: Hex32
    manifest_sha256: Hex32
    chain_config_sha256: Hex32
    legacy_handoff_plan_sha256: Hex32


class _StateBinding(StrictProtocolModel):
    schema_: Literal["umi-standing-reward-state-binding/1"] = Field(alias="schema")
    approval_sha256: Hex32
    journal_binding_sha256: Hex32
    journal_id: Hex32


def _retained_binding(runtime):
    with runtime._db() as db:
        if not db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='standing_execution'"
        ).fetchone():
            return None
        count, size = db.execute(
            "SELECT COUNT(*),COALESCE(SUM(length(body)),0) FROM standing_execution"
        ).fetchone()
        if count != 1 or not 0 < size <= _MAX_BYTES:
            raise ValueError("standing execution binding is incomplete")
        row = db.execute("SELECT body FROM standing_execution WHERE id=1").fetchone()
    if row is None or type(row[0]) is not bytes:
        raise ValueError("standing execution binding is malformed")
    value = _StateBinding.model_validate_json(row[0])
    if canonical_json_bytes(value) != row[0]:
        raise ValueError("standing execution binding is not canonical")
    return value


def _identities(journal):
    paths = (
        journal.journal.root,
        journal.journal.path,
        journal.journal.lock_path,
        journal.journal.root / "standing-writer.lock",
    )
    result = []
    for path in paths:
        private_path(str(path))
        info = path.stat()
        if (
            info.st_uid != os.getuid()
            or info.st_mode & 0o077
            or (
                path != journal.journal.root
                and (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1)
            )
        ):
            raise ValueError("standing journal ownership or file type changed")
        result.append((info.st_dev, info.st_ino))
    journal.journal._check_files()
    return tuple(result)


@dataclass(frozen=True, slots=True)
class BoundStandingRewardHost:
    """Process-local ownership; never reconstruct this from serialized flags."""

    journal: StandingWeightJournal
    _runtime: SuccessorSupervisorRuntime = field(repr=False)
    _preparation: StandingRewardPreparation = field(repr=False)
    _first: PreparedStandingReward = field(repr=False)
    _handoff: VerifiedLegacyRewardHandoff = field(repr=False)
    _approval_path: Path = field(repr=False)
    _approval: StandingRewardHostApproval = field(repr=False)
    _retained: _StateBinding = field(repr=False)
    _identities: tuple = field(repr=False)
    _issuer: object = field(default=None, repr=False)
    _seal: tuple = field(default=(), repr=False)

    def _selection(self):
        return (
            id(self.journal),
            id(self._runtime),
            id(self._preparation),
            id(self._first),
            id(self._handoff),
            str(self._approval_path),
            digest(self._approval),
            digest(self._retained),
            self._identities,
        )

    def recheck(self, *, journal, preparation, first, handoff):
        if (
            self._issuer is not _ISSUER
            or self._selection() != self._seal
            or journal is not self.journal
            or preparation is not self._preparation
            or first is not self._first
            or handoff is not self._handoff
        ):
            raise ValueError("standing execution lost its approved host binding")
        _check_context(self._runtime, preparation, first, handoff, self._approval)
        if (
            _root_control(self._approval_path, _MAX_BYTES) != canonical_json_bytes(self._approval)
            or _retained_binding(self._runtime) != self._retained
            or digest(journal.binding) != self._retained.journal_binding_sha256
            or journal.journal.get("standing_host_identity", "original")
            != self._retained.journal_id
            or _identities(journal) != self._identities
        ):
            raise ValueError("standing execution approval or retained journal changed")


def _check_selection(runtime, preparation, first, plan, approval):
    runtime._require_lease()
    preparation._authority()
    if first is not None:
        preparation._check_prepared(first)
    expected = StandingRewardHostApproval(
        schema="umi-standing-reward-host-approval/1",
        source_config_sha256=digest(runtime.config),
        installation_receipt_sha256=runtime.installation.receipt_sha256,
        host_manifest_sha256=runtime.installation.host_manifest_sha256,
        validator_hotkey=runtime.config.validator_hotkey,
        series_sha256=preparation.series_sha256,
        policy_sha256=preparation.policy_sha256,
        manifest_sha256=digest(preparation.manifest),
        chain_config_sha256=preparation.reader.chain_config_sha256,
        legacy_handoff_plan_sha256=digest(plan),
    )
    if approval != expected:
        raise ValueError("standing execution differs from the approved installation")


def check_standing_reward_host_selection(
    runtime: SuccessorSupervisorRuntime,
    *,
    approval_path: Path,
    preparation: StandingRewardPreparation,
    first: PreparedStandingReward | None,
    plan: LegacyRewardHandoffPlan,
) -> None:
    """Check approved inputs before bootstrap or retaining a C4 stop intent.

    During bootstrap the first package is not prepared yet. The same approval
    is checked again with native preparation before the handoff can stop C4.
    """
    if (
        type(runtime) is not SuccessorSupervisorRuntime
        or type(preparation) is not StandingRewardPreparation
    ):
        raise TypeError("standing host requires native runtime and preparation")
    raw = _root_control(approval_path, _MAX_BYTES)
    approval = StandingRewardHostApproval.model_validate_json(raw)
    if canonical_json_bytes(approval) != raw:
        raise ValueError("standing host approval is not canonical")
    _check_selection(runtime, preparation, first, plan, approval)


def _check_context(runtime, preparation, first, handoff, approval):
    _check_selection(runtime, preparation, first, handoff.intent.plan, approval)
    if not runtime._mutex.locked():
        raise ValueError("standing execution requires the original writer handoff")
    validate_legacy_handoff(
        handoff,
        series=preparation.reader.series,
        activation=first.activation,
        validator_hotkey=runtime.config.validator_hotkey,
        block=handoff.through_block,
    )
    if runtime._standing_handoff_intent() != handoff.intent:
        raise ValueError("standing execution differs from the retained handoff")


def bind_standing_reward_host(
    runtime: SuccessorSupervisorRuntime,
    *,
    approval_path: Path,
    preparation: StandingRewardPreparation,
    first: PreparedStandingReward,
    handoff: VerifiedLegacyRewardHandoff,
    maximum_journal_bytes: int,
) -> BoundStandingRewardHost:
    """Open the one approved journal while the C4 locks remain held.

    Missing state after a retained binding is an error, never fresh startup.
    Before the binding commits, a crash may leave an empty initialized journal;
    its original identity is reused. No pending transaction can precede binding.
    """
    if (
        type(runtime) is not SuccessorSupervisorRuntime
        or type(preparation) is not StandingRewardPreparation
    ):
        raise TypeError("standing host requires native runtime and preparation")
    raw = _root_control(approval_path, _MAX_BYTES)
    approval = StandingRewardHostApproval.model_validate_json(raw)
    if canonical_json_bytes(approval) != raw:
        raise ValueError("standing host approval is not canonical")
    _check_context(runtime, preparation, first, handoff, approval)
    root = (
        Path(runtime.config.state_root) / "standing-rewards" / preparation.series_sha256 / "weights"
    )
    prior = _retained_binding(runtime)
    if prior is not None:
        if prior.approval_sha256 != hashlib.sha256(raw).hexdigest():
            raise ValueError("standing execution cannot replace its approved selection")
        # Check before RoundJournal can create a file or directory on reopen.
        for name in ("rounds.sqlite3", "rounds.lock", "standing-writer.lock"):
            private_path(str(root / name))
            if not (root / name).is_file():
                raise ValueError("standing execution retained journal is missing")
    journal = StandingWeightJournal(
        root,
        series_sha256=approval.series_sha256,
        validator_hotkey=approval.validator_hotkey,
        chain_config_sha256=approval.chain_config_sha256,
        maximum_bytes=maximum_journal_bytes,
    )
    fd = lock_private_file(root / "standing-writer.lock")
    try:
        identity = journal.journal.get("standing_host_identity", "original")
        if prior is not None:
            if (
                identity != prior.journal_id
                or digest(journal.binding) != prior.journal_binding_sha256
            ):
                raise ValueError("standing execution retained journal identity differs")
        else:
            if journal.pending() is not None:
                raise ValueError("unbound standing journal already contains a transaction")
            if identity is None:
                identity = secrets.token_hex(32)
                journal.journal.put("standing_host_identity", "original", identity)
            candidate = _StateBinding(
                schema="umi-standing-reward-state-binding/1",
                approval_sha256=hashlib.sha256(raw).hexdigest(),
                journal_binding_sha256=digest(journal.binding),
                journal_id=identity,
            )
            _check_context(runtime, preparation, first, handoff, approval)
            with runtime._db() as db:
                db.execute(
                    "CREATE TABLE standing_execution "
                    "(id INTEGER PRIMARY KEY CHECK(id=1), body BLOB NOT NULL)"
                )
                db.execute(
                    "INSERT INTO standing_execution VALUES (1,?)",
                    (canonical_json_bytes(candidate),),
                )
            prior = candidate
        bound = BoundStandingRewardHost(
            journal,
            runtime,
            preparation,
            first,
            handoff,
            approval_path,
            approval,
            prior,
            _identities(journal),
            _issuer=_ISSUER,
        )
        object.__setattr__(bound, "_seal", bound._selection())
        bound.recheck(journal=journal, preparation=preparation, first=first, handoff=handoff)
        return bound
    finally:
        os.close(fd)
