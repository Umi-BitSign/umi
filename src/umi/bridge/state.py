"""Private bridge state and crash-safe journal publication.

Policy and chain I/O stay outside this module. Historical bytes are retained;
archival must preserve their recovery bindings before hot history can rotate.
"""

from __future__ import annotations

import fcntl
import hashlib
import os
import stat
from datetime import datetime
from pathlib import Path

from ..bootstrap_weight_operator import _datetime_ms
from ..protocol import canonical_json_bytes
from ..signed_extrinsic import MAX_SIGNED_EXTRINSIC_BYTES
from ..simple_bootstrap_validator import SIMPLE_BOOTSTRAP_MANIFEST_SHA256, SimpleBootstrapJournal
from .journal import REGISTRATION_BRIDGE_JOURNAL_SCHEMA, RegistrationBridgeJournal
from .journal_history import MAX_HISTORY_FILES as MAX_HISTORY_FILES
from .journal_history import HistoryContinuity, reconcile_archived_transition, validate_next_journal
from .policy import MAX_DOCUMENT_BYTES, _canonical_object, _require
from .selection import RegistrationBridgeObservation
from .transactions import BridgeJournal, RegistrationBridgeTransactionJournal, parse_bridge_journal

MAX_HISTORY_BYTES = 512 * 1024 * 1024


def _read_bytes(path: Path, *, private: bool, optional: bool = False) -> bytes | None:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        if optional:
            return None
        raise
    with os.fdopen(fd, "rb") as handle:
        before = os.fstat(handle.fileno())
        _require(
            stat.S_ISREG(before.st_mode)
            and before.st_nlink == 1
            and 0 < before.st_size <= MAX_DOCUMENT_BYTES,
            "state_file_unsafe",
        )
        if private:
            _require(
                before.st_uid == os.geteuid() and stat.S_IMODE(before.st_mode) == 0o600,
                "state_file_permissions",
            )
        payload = handle.read(MAX_DOCUMENT_BYTES + 1)
        after = os.fstat(handle.fileno())
        _require(
            (before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            == (after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
            and len(payload) == before.st_size,
            "state_file_changed",
        )
        return payload


def _write_new(path: Path, payload: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())


def _fsync(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class RegistrationBridgeState:
    """Same service.lock inode as the old worker, with separate durable journals."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.path = root / "registration-bridge-journal.json"
        self.descriptor = -1
        self._root_identity = None
        self._expected = None

    def __enter__(self) -> RegistrationBridgeState:
        _require(self.root.is_absolute() and self.root.resolve() == self.root, "state_path_unsafe")
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        metadata = self.root.lstat()
        _require(
            stat.S_ISDIR(metadata.st_mode)
            and metadata.st_uid == os.geteuid()
            and stat.S_IMODE(metadata.st_mode) == 0o700,
            "state_root_unsafe",
        )
        self._root_identity = (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_uid,
            metadata.st_gid,
            metadata.st_mode,
        )
        self.descriptor = os.open(
            self.root / "service.lock", os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600
        )
        try:
            meta = os.fstat(self.descriptor)
            _require(
                stat.S_ISREG(meta.st_mode)
                and meta.st_uid == os.geteuid()
                and meta.st_nlink == 1
                and stat.S_IMODE(meta.st_mode) == 0o600,
                "service_lock_unsafe",
            )
            fcntl.flock(self.descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self._expected = self._snapshot()
        except BaseException:
            os.close(self.descriptor)
            self.descriptor = -1
            raise
        return self

    def __exit__(self, *_args) -> None:
        if self.descriptor >= 0:
            os.close(self.descriptor)
            self.descriptor = -1

    def require_locked(self) -> None:
        _require(self.descriptor >= 0, "state_lock_not_held")
        root = self.root.lstat()
        _require(
            self.root.resolve() == self.root
            and (root.st_dev, root.st_ino, root.st_uid, root.st_gid, root.st_mode)
            == self._root_identity,
            "state_root_changed",
        )
        actual = (self.root / "service.lock").lstat()
        held = os.fstat(self.descriptor)
        _require(
            (actual.st_dev, actual.st_ino) == (held.st_dev, held.st_ino)
            and stat.S_ISREG(actual.st_mode)
            and actual.st_uid == os.geteuid()
            and actual.st_nlink == held.st_nlink == 1
            and stat.S_IMODE(actual.st_mode) == 0o600,
            "state_lock_replaced",
        )

    def _snapshot(self) -> dict[str, tuple[int | str, ...] | None]:
        self.require_locked()
        result = {}
        paths = [
            self.path,
            self.root / "journal.json",
            self.root / "registration-bridge-legacy-journal.json",
        ]
        history = self.root / "registration-bridge-history"
        if os.path.lexists(history):
            meta = history.lstat()
            _require(
                stat.S_ISDIR(meta.st_mode)
                and meta.st_uid == os.geteuid()
                and stat.S_IMODE(meta.st_mode) == 0o700,
                "history_root_unsafe",
            )
            result[history.name] = (
                meta.st_dev,
                meta.st_ino,
                meta.st_uid,
                meta.st_gid,
                meta.st_mode,
            )
            with os.scandir(history) as entries:
                for count, entry in enumerate(entries, 1):
                    _require(count <= MAX_HISTORY_FILES, "history_capacity_reached")
                    paths.append(Path(entry.path))
        total = 0
        for path in paths:
            raw = _read_bytes(path, private=True, optional=True)
            if raw is None:
                result[str(path.relative_to(self.root))] = None
                continue
            total += len(raw)
            _require(total <= MAX_HISTORY_BYTES, "history_byte_capacity_reached")
            meta = path.lstat()
            result[str(path.relative_to(self.root))] = (
                meta.st_dev,
                meta.st_ino,
                meta.st_uid,
                meta.st_gid,
                meta.st_mode,
                meta.st_nlink,
                meta.st_size,
                meta.st_mtime_ns,
                meta.st_ctime_ns,
                hashlib.sha256(raw).hexdigest(),
            )
        return result

    def require_unchanged(self) -> None:
        _require(
            self._expected is not None and self._snapshot() == self._expected,
            "retained_state_changed",
        )

    def _audit_history(self, current: BridgeJournal, legacy_raw: bytes | None) -> BridgeJournal:
        archive = _read_bytes(
            self.root / "registration-bridge-legacy-journal.json", private=True, optional=True
        )
        _require(archive == legacy_raw, "legacy_archive_changed")
        after = HistoryContinuity()
        if legacy_raw is not None:
            legacy = SimpleBootstrapJournal.model_validate_json(legacy_raw)
            _require(
                canonical_json_bytes(legacy) == legacy_raw
                and legacy.validator_hotkey == current.validator_hotkey
                and legacy.phase == "applied"
                and legacy.weight_call is not None,
                "legacy_attempt_not_proven_terminal",
            )
            after = HistoryContinuity(
                last_update=legacy.weight_call.block_number,
                observed_block=max(legacy.observation_block or 0, legacy.weight_call.block_number),
            )
        history = self.root / "registration-bridge-history"
        groups = {}
        if history.exists():
            with os.scandir(history) as entries:
                for count, entry in enumerate(entries, 1):
                    _require(count <= MAX_HISTORY_FILES, "history_capacity_reached")
                    raw = _read_bytes(Path(entry.path), private=True)
                    retained = parse_bridge_journal(raw)
                    _require(
                        canonical_json_bytes(retained) == raw
                        and retained.attempt is not None
                        and retained.validator_hotkey == current.validator_hotkey
                        and retained.legacy_journal_sha256 == current.legacy_journal_sha256,
                        "history_binding_changed",
                    )
                    _require(
                        entry.name == f"{retained.attempt.attempt_id}-{retained.phase}.json",
                        "history_filename_changed",
                    )
                    groups.setdefault(retained.attempt.attempt_id, {})[retained.phase] = retained
        return reconcile_archived_transition(current, groups, after=after)

    def load(self) -> BridgeJournal | None:
        self.require_unchanged()
        raw = _read_bytes(self.path, private=True, optional=True)
        if raw is None:
            return None
        return parse_bridge_journal(raw)

    def legacy(self) -> tuple[bytes | None, str | None]:
        self.require_unchanged()
        raw = _read_bytes(self.root / "journal.json", private=True, optional=True)
        return raw, None if raw is None else hashlib.sha256(raw).hexdigest()

    def store(self, journal: BridgeJournal, *, archive: bool = False) -> None:
        self.require_unchanged()
        raw = canonical_json_bytes(journal)
        journal = parse_bridge_journal(raw)
        previous_raw = _read_bytes(self.path, private=True, optional=True)
        previous = None if previous_raw is None else parse_bridge_journal(previous_raw)
        validate_next_journal(
            previous,
            journal,
            archive=archive,
        )
        history = self.root / "registration-bridge-history"
        path = None
        existing = None
        if archive and journal.attempt is not None:
            path = history / f"{journal.attempt.attempt_id}-{journal.phase}.json"
            existing = _read_bytes(path, private=True, optional=True)
            _require(existing is None or existing == raw, "history_record_changed")
        if type(journal) is RegistrationBridgeTransactionJournal and (
            previous.attempt is None or previous.attempt.attempt_id != journal.attempt.attempt_id
        ):
            self._require_transaction_headroom(raw, retained_preparing=existing is not None)
        count, used = self._history_usage()
        new_archive = path is not None and existing is None
        _require(count + int(new_archive) <= MAX_HISTORY_FILES, "history_capacity_reached")
        _require(
            used - len(previous_raw or b"") + len(raw) * (1 + int(new_archive))
            <= MAX_HISTORY_BYTES,
            "history_byte_capacity_reached",
        )
        if path is not None:
            history.mkdir(mode=0o700, exist_ok=True)
            meta = history.lstat()
            _require(
                stat.S_ISDIR(meta.st_mode)
                and meta.st_uid == os.geteuid()
                and stat.S_IMODE(meta.st_mode) == 0o700,
                "history_root_unsafe",
            )
            if existing is None:
                _write_new(path, raw)
            # A retry may observe a file whose preceding directory sync failed.
            # Matching bytes alone do not establish durable publication.
            _fsync(history)
        temporary = self.root / f".registration-bridge-{os.getpid()}-{os.urandom(8).hex()}.tmp"
        _write_new(temporary, raw)
        # All runtime state writers share service.lock; existing legacy bytes are never touched.
        os.replace(temporary, self.path)
        _fsync(self.root)
        self._expected = self._snapshot()

    def _history_usage(self) -> tuple[int, int]:
        """Use the snapshot just authenticated by require_unchanged under service.lock."""
        return (
            sum(name.startswith("registration-bridge-history/") for name in self._expected),
            sum(
                item[6]
                for name, item in self._expected.items()
                if item is not None and name != "registration-bridge-history"
            ),
        )

    def _require_transaction_headroom(self, preparing: bytes, *, retained_preparing: bool) -> None:
        """Reserve configured capacity before any new-format signing intent.

        The service lock and unchanged-state check serialize all writers. Seven
        archive slots cover every phase (including both exclusive resolutions).
        The byte allowance includes maximum encoded bytes and bounded receipt,
        expiry and counter fields. Disk space can still be consumed externally;
        I/O failures retain the existing journal and never authorize a retry.
        """
        maximum_record = len(preparing) + 2 * MAX_SIGNED_EXTRINSIC_BYTES + 4096
        _require(maximum_record <= MAX_DOCUMENT_BYTES, "transaction_document_headroom_insufficient")
        history_count, used = self._history_usage()
        _require(
            history_count + 7 - int(retained_preparing) <= MAX_HISTORY_FILES,
            "transaction_history_file_headroom_insufficient",
        )
        _require(
            used + 8 * maximum_record - len(preparing) * int(retained_preparing)
            <= MAX_HISTORY_BYTES,
            "transaction_history_byte_headroom_insufficient",
        )
        available = os.statvfs(self.root)
        _require(
            available.f_bavail * available.f_frsize >= 9 * maximum_record,
            "transaction_disk_headroom_insufficient",
        )

    def initialize(
        self, observation: RegistrationBridgeObservation, *, now: datetime
    ) -> BridgeJournal:
        raw, digest = self.legacy()
        existing = self.load()
        if existing is not None:
            _require(existing.legacy_journal_sha256 == digest, "legacy_journal_changed")
            recovered = self._audit_history(existing, raw)
            if recovered != existing:
                self.store(recovered, archive=True)
            return recovered
        # A missing current journal never resets retained attempts or a prior
        # completed handoff, including a crash between archive and journal write.
        _require(
            not (self.root / "registration-bridge-history").exists()
            and not (self.root / "registration-bridge-legacy-journal.json").exists(),
            "bridge_journal_missing_with_retained_state",
        )
        if raw is not None:
            _canonical_object(raw)
            legacy = SimpleBootstrapJournal.model_validate_json(raw)
            _require(
                canonical_json_bytes(legacy) == raw
                and legacy.validator_hotkey == observation.validator_hotkey
                and legacy.manifest_sha256 == SIMPLE_BOOTSTRAP_MANIFEST_SHA256,
                "legacy_journal_binding_changed",
            )
            _require(
                legacy.phase == "applied" and legacy.weight_call is not None,
                "legacy_attempt_not_proven_terminal",
            )
            writer = next(
                p for p in observation.participants if p.hotkey == observation.validator_hotkey
            )
            old_row = [[uid, 65535 if uid in {6, 247} else 0] for uid in range(256)]
            _require(
                observation.validator_row == old_row
                and writer.last_update > legacy.prior_last_update
                and writer.last_update >= legacy.preflight_block
                and observation.block_number
                >= (legacy.observation_block or legacy.preflight_block),
                "legacy_terminal_effect_not_visible",
            )
            if legacy.weight_call is not None:
                _require(
                    writer.last_update == legacy.weight_call.block_number,
                    "legacy_receipt_lastupdate_changed",
                )
            archive = self.root / "registration-bridge-legacy-journal.json"
            prior = _read_bytes(archive, private=True, optional=True)
            if prior is None:
                _write_new(archive, raw)
                _fsync(self.root)
                self._expected = self._snapshot()
            else:
                _require(prior == raw, "legacy_archive_changed")
        else:
            writer = next(
                p for p in observation.participants if p.hotkey == observation.validator_hotkey
            )
            _require(
                not observation.validator_row and writer.last_update <= writer.registered_at_block,
                "legacy_journal_missing_for_existing_writer",
            )
        journal = RegistrationBridgeJournal(
            schema=REGISTRATION_BRIDGE_JOURNAL_SCHEMA,
            validator_hotkey=observation.validator_hotkey,
            legacy_journal_sha256=digest,
            phase="idle",
            attempt=None,
            weight_call=None,
            last_observed_block=observation.block_number,
            last_observed_block_hash=observation.block_hash,
            updated_at_unix_ms=_datetime_ms(now),
        )
        self.store(journal)
        return journal
