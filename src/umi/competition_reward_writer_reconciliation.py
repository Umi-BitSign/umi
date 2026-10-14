"""Native stopped-writer ownership and non-signing pending-state review.

The caller already owns the real supervisor startup lease. No service is stopped
or started here, no approval is restored, and no signed record is replaced.
This module does not install a staged history directory or authorize rewards.
"""

from __future__ import annotations

import fcntl
import os
import pwd
from contextlib import ExitStack, asynccontextmanager, contextmanager, nullcontext
from dataclasses import dataclass, field
from pathlib import Path

from .competition_container import _require_empty_container_cgroup
from .competition_host_upgrade import (
    _check_service_namespace,
    _require_empty_cgroup,
    _unit_snapshot,
)
from .competition_reward_control_archive import HistoricalRewardControlProvider
from .competition_reward_decisions import (
    StandingRewardControlReader,
    StandingRewardSeries,
    retained_reward_decisions,
    verify_reward_decisions,
)
from .competition_reward_history import OwnedRewardControlHistory, validate_control_history
from .competition_reward_host import _identities
from .competition_reward_transaction_outcome import resolve_standing_transaction
from .competition_reward_transactions import StandingWeightJournal
from .competition_reward_writer_service import authenticate_writer_service
from .competition_supervisor_runtime import SuccessorStartupLease, _validate_startup_lease
from .competition_work_progress import WorkProgress
from .concurrency import run_owned_thread
from .open_competition import digest, identity
from .private_files import private_path

_ISSUER = object()


def _unit_stopped(unit: str, anchor, config_path: Path):
    values = _unit_snapshot(unit)
    _check_service_namespace(unit, values)
    if (
        values["Id"] != unit
        or values["LoadState"] != "loaded"
        or values["ActiveState"] not in {"inactive", "failed"}
        or values["SubState"] not in {"dead", "failed"}
        or values["MainPID"] != "0"
        or values["ControlPID"] != "0"
        or pwd.getpwnam(values["User"]).pw_uid != anchor.service_uid
    ):
        raise ValueError("writer reconciliation requires its exact stopped service")
    _require_empty_cgroup(unit, values["ControlGroup"])
    return values, authenticate_writer_service(anchor, unit, config_path, values)


@dataclass(frozen=True, slots=True)
class StoppedStandingWriter:
    """Scoped absence checks backed by the untransferred native startup lease."""

    startup: SuccessorStartupLease
    unit: str
    config_path: Path
    _container: object = field(repr=False)
    _unit_selection: tuple = field(repr=False)
    _active: list[bool] = field(repr=False)
    _issuer: object = field(default=None, repr=False)
    _binding: str = field(default="", repr=False)

    def _selection(self):
        return digest(
            {
                "startup": self.startup._binding,
                "unit": self.unit,
                "config_path": str(self.config_path),
                "unit_selection": self._unit_selection,
                "container": str(id(self._container)),
                "lifetime": str(id(self._active)),
            }
        )

    async def recheck(self):
        if (
            type(self) is not StoppedStandingWriter
            or self._issuer is not _ISSUER
            or self._active != [True]
            or self._binding != self._selection()
        ):
            raise ValueError("stopped writer ownership is absent, altered or closed")
        _validate_startup_lease(self.startup)
        if (os.getuid(), os.geteuid()) != (self.startup._anchor.service_uid,) * 2:
            raise ValueError("writer reconciliation must use the actual service account")
        if (
            await run_owned_thread(_unit_stopped, self.unit, self.startup._anchor, self.config_path)
            != self._unit_selection
        ):
            raise ValueError("stopped writer service selection changed")
        status = await self._container.status()
        if status.phase not in {"absent", "created", "completed", "held", "failed"}:
            raise ValueError("writer reconciliation still has a live container")
        if status.container_id is not None:
            await run_owned_thread(_require_empty_container_cgroup, status.container_id)
        _validate_startup_lease(self.startup)


@asynccontextmanager
async def hold_stopped_standing_writer(
    startup: SuccessorStartupLease, *, unit: str, config_path: Path
):
    """Inspect real systemd and Podman state while the original lock stays held.

    Root-owned drop-ins are allowed: this does not reinterpret a successor as a
    legacy installation. The entire observed unit selection stays pinned during
    the review. Native Podman inspection checks its exact labels and config.
    """
    from .competition_supervisor_cli import _new_container

    _validate_startup_lease(startup)
    if (os.getuid(), os.geteuid()) != (startup._anchor.service_uid,) * 2:
        raise ValueError("writer reconciliation must use the actual service account")
    value = None
    try:
        selection = await run_owned_thread(_unit_stopped, unit, startup._anchor, config_path)
        value = StoppedStandingWriter(
            startup,
            unit,
            Path(config_path),
            _new_container(startup.config),
            selection,
            [True],
            _ISSUER,
        )
        object.__setattr__(value, "_binding", value._selection())
        await value.recheck()
    except BaseException:
        startup.preserve_on_failure()
        raise
    try:
        yield value
    finally:
        try:
            # A caller exception is not itself proof of a live writer. Confirm
            # absence once more before releasing the original startup lock.
            await value.recheck()
        except BaseException:
            startup.preserve_on_failure()
            raise
        finally:
            value._active[0] = False


@contextmanager
def _weight_journal_ownership(owner, journal):
    # Require the original writer locks; never create missing state as part of
    # recovery. The rounds.lock remains available to native compound reads.
    global_path = (
        Path(owner.startup.config.state_root) / "standing-rewards" / "standing-writer.lock"
    )
    paths = (global_path, journal.journal.root / "standing-writer.lock")
    expected = _identities(journal, global_path)
    with ExitStack() as stack:
        descriptors = []
        for path in paths:
            fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
            stack.callback(os.close, fd)
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            descriptors.append(fd)

        def recheck():
            _validate_startup_lease(owner.startup)
            if _identities(journal, global_path) != expected:
                raise ValueError("standing writer journal identity changed during review")
            for path, fd in zip(paths, descriptors, strict=True):
                named, held = path.stat(), os.fstat(fd)
                if (named.st_dev, named.st_ino) != (held.st_dev, held.st_ino):
                    raise ValueError("standing writer lock identity changed during review")
                other = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
                try:
                    try:
                        fcntl.flock(other, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    except BlockingIOError:
                        pass
                    else:
                        raise ValueError("standing writer lost its original lock")
                finally:
                    os.close(other)

        recheck()
        yield recheck
        recheck()


async def reconcile_stopped_control_history(
    owner: StoppedStandingWriter,
    reader: StandingRewardControlReader,
    *,
    original: OwnedRewardControlHistory,
    candidate: OwnedRewardControlHistory,
    candidate_original_prefix: OwnedRewardControlHistory,
    observation,
    decisions,
):
    """Compare native histories and retained signed controls without rewriting.

    Each history must be issued by its genuine reader in this process under
    its original path/owner. Obtaining both capabilities across private mount
    views is the cutover broker's job; a serialized receipt cannot substitute.
    This function does not make the directory-selection decision itself.
    """
    if type(owner) is not StoppedStandingWriter or type(reader) is not StandingRewardControlReader:
        raise TypeError("writer reconciliation requires native ownership and control reader")
    await owner.recheck()
    root = Path(owner.startup.config.state_root) / "standing-rewards" / digest(reader.series)
    if reader.journal.root != root / "control":
        raise ValueError("writer control reader is not the retained original owner")
    with WorkProgress("writer_history_reconciliation", 4, unit="checks") as progress:
        reader._historical_proof(observation)
        from .competition_reward_writer_prefix import EmptyOriginalWriterHistory

        empty_original = type(original) is EmptyOriginalWriterHistory
        if empty_original:
            original.validate()
            if candidate_original_prefix is not None or (
                original.first_block != reader.series.recovery.authority.issued_at_block
                or identity(original.control_hotkey) != identity(reader.series.control_hotkey)
                or original.chain_config_sha256 != reader.admission_chain_config_sha256
            ):
                raise ValueError("empty original history binding differs")
        histories = (
            (candidate,) if empty_original else (original, candidate, candidate_original_prefix)
        )
        for history in histories:
            validate_control_history(
                history,
                first_block=reader.series.recovery.authority.issued_at_block,
                tip=history.tip,
                control_hotkey=reader.series.control_hotkey,
                chain_config_sha256=reader.admission_chain_config_sha256,
            )
            if history.unresolved_blocks:
                raise ValueError("writer history has unresolved native effects")
        if candidate.tip != observation.snapshot or (
            not empty_original
            and (
                candidate_original_prefix.tip != original.tip
                or candidate.tip.block_number < original.tip.block_number
                or candidate_original_prefix.writes != original.writes
                or tuple(w for w in candidate.writes if w.block_number <= original.tip.block_number)
                != original.writes
            )
        ):
            raise ValueError("candidate history differs from the original native prefix")
        progress.advance()
        from .competition_reward_adoption import bootstrap_admission

        bootstrap = bootstrap_admission(reader.reward_adoptions)
        empty = not candidate.writes and observation.control_sha256 is None
        if not candidate.writes and not decisions and bootstrap is not None:
            # Only the authenticated historical slot is pre-admission. Native
            # unresolved effects were rejected above; retained signed decisions
            # still have to agree below. No admission result is manufactured.
            bootstrap[1].check_control(observation)
            empty = True
        checked = (
            ()
            if empty and not decisions
            else verify_reward_decisions(
                reader.series,
                reader.policy,
                tuple(decisions),
                reward_adoptions=reader.reward_adoptions,
            )
        )
        retained = await run_owned_thread(retained_reward_decisions, reader)
        if len(checked) < len(retained) or checked[: len(retained)] != retained:
            raise ValueError("candidate history conflicts with retained signed controls")
        progress.advance()
        committed = (
            ()
            if empty and not checked
            else reader._history_committed_blocks(candidate, observation, checked)
        )
        progress.advance()
        await owner.recheck()
        if await run_owned_thread(retained_reward_decisions, reader) != retained:
            raise ValueError("retained signed controls changed during history review")
        progress.advance()
        return {
            "schema": "umi-stopped-writer-history-review/1",
            "series_sha256": digest(reader.series),
            "original_through_block": original.first_block - 1
            if empty_original
            else original.tip.block_number,
            "original_history_empty": empty_original,
            "candidate_through_block": candidate.tip.block_number,
            "retained_decisions": len(retained),
            "verified_decisions": len(checked),
            "admission_status": "absent_in_verified_interval" if empty else "verified",
            "committed_blocks": list(committed),
            "original_records_preserved": True,
            "chain_submission_authorized": False,
        }


async def review_stopped_standing_attempt(
    owner: StoppedStandingWriter,
    journal: StandingWeightJournal,
    provider: HistoricalRewardControlProvider,
    *,
    series,
    journal_owner=None,
):
    """Reconcile the retained attempt using native original-proof recovery.

    This result is diagnostic. An expired attempt's outcome remains unknown;
    neither expiry nor absence clears its intent or authorizes replacement.
    The ordinary native executor must still reconcile the same attempt when
    it eventually reserves another transaction.
    """
    if (
        type(owner) is not StoppedStandingWriter
        or type(journal) is not StandingWeightJournal
        or not isinstance(provider, HistoricalRewardControlProvider)
        or type(series) is not StandingRewardSeries
    ):
        raise TypeError("writer reconciliation requires native owners and journal")
    await owner.recheck()
    root = Path(owner.startup.config.state_root) / "standing-rewards" / digest(series)
    private_path(str(root))
    if (
        journal.journal.root != root / "weights"
        or journal.binding["series_sha256"] != digest(series)
        or journal.binding["validator_account"] != identity(owner.startup.config.validator_hotkey)
        or journal.binding["chain_config_sha256"] != digest(provider.config)
        or identity(owner.startup.config.validator_hotkey)
        not in {identity(key) for key in series.validators}
    ):
        raise ValueError("writer reconciliation changed its native state binding")
    if journal_owner is not None:
        from .competition_reward_writer_journals import StoppedWriterJournals

        if type(journal_owner) is not StoppedWriterJournals or journal_owner._owner is not owner:
            raise TypeError("pending writer review differs from original journal ownership")
        journal_owner.recheck(journal)
    with (
        WorkProgress("writer_pending_attempt_reconciliation", 4, unit="checks") as progress,
        (
            _weight_journal_ownership(owner, journal)
            if journal_owner is None
            else nullcontext(lambda: journal_owner.recheck(journal))
        ) as recheck,
    ):
        pending = await run_owned_thread(journal.pending)
        progress.advance()
        end = (
            None
            if pending is None
            else await resolve_standing_transaction(
                provider, journal, control_hotkey=series.control_hotkey
            )
        )
        progress.advance()
        await owner.recheck()
        recheck()
        progress.advance()
        if await run_owned_thread(journal.pending) != pending:
            raise ValueError("writer reconciliation changed its retained pending attempt")
        progress.advance()
    return {
        "schema": "umi-stopped-standing-attempt-review/1",
        "series_sha256": digest(series),
        "pending_intent_sha256": None if pending is None else digest(pending.intent),
        "signed_extrinsic_hash": None
        if pending is None or pending.signed is None
        else pending.signed.extrinsic_hash,
        "status": "absent" if pending is None else "live_unresolved" if end is None else end.reason,
        "original_records_preserved": True,
        "legacy_handoff_recheck_required": True,
        "chain_submission_authorized": False,
    }
