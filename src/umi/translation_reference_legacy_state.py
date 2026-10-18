"""Original worker mutex and durable verification of unchanged legacy inputs.

The fixed driver retains this lease through every native read and write. New
follower state is separate; original signed inputs and bridge journals are never
rewritten. Warm restart checks immutable file identities without payload reads.
"""

from __future__ import annotations

import hashlib
import os
import stat
import time
from pathlib import Path

from .bridge.journal_history import MAX_HISTORY_FILES
from .bridge.state import MAX_HISTORY_BYTES, _read_bytes
from .open_competition import digest, identity
from .private_files import ensure_private_directory, lock_private_file, private_path
from .translation_reference_legacy import inspect_translation_legacy
from .translation_reference_state import TranslationReferenceError

FOLLOWER_STATE_DIRECTORY = "reference-weights"
_RULE = "umi-reference-terminal-v1-legacy-adoption/1"
_ADOPTION = "reference_legacy_adoption"
_CHUNK = "reference_legacy_file_identities"
_FILES = {
    "service.lock",
    "journal.json",
    "registration-bridge-journal.json",
    "registration-bridge-legacy-journal.json",
}
_HISTORY = "registration-bridge-history"


def _file_identity(path, *, directory=False):
    value = path.lstat()
    if value.st_uid != os.geteuid() or (
        (directory and (not stat.S_ISDIR(value.st_mode) or stat.S_IMODE(value.st_mode) != 0o700))
        or (
            not directory
            and (
                not stat.S_ISREG(value.st_mode)
                or value.st_nlink != 1
                or stat.S_IMODE(value.st_mode) != 0o600
            )
        )
    ):
        raise TranslationReferenceError("reference_legacy_state_permissions_invalid")
    result = [value.st_dev, value.st_ino, value.st_uid, value.st_gid, value.st_mode]
    if not directory:
        result.extend([value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns])
    # Inodes and nanosecond clocks exceed canonical JSON's exact integer range.
    return [str(item) for item in result]


class ReferenceLegacyState:
    """One real service.lock, with a separate follower journal directory."""

    def __init__(self, root: Path, *, progress=None):
        self.root = root
        self.follower_root = root / FOLLOWER_STATE_DIRECTORY
        self._progress = progress
        self.descriptor = -1
        self._root_identity = None
        self._initial = None
        self.payload_reads = 0

    def __enter__(self):
        private_path(str(self.root))
        ensure_private_directory(self.root)
        # Bootstrap-only layouts own different mutexes. Adding service.lock
        # would change their historical recovery inputs even without a write.
        names = set()
        with os.scandir(self.root) as entries:
            for count, entry in enumerate(entries, 1):
                if count > len(_FILES) + 2:
                    raise TranslationReferenceError("reference_legacy_unclassified_state")
                names.add(entry.name)
        if names - (_FILES | {_HISTORY, FOLLOWER_STATE_DIRECTORY}):
            raise TranslationReferenceError("reference_legacy_layout_requires_supported_recovery")
        if "service.lock" not in names and names - {FOLLOWER_STATE_DIRECTORY}:
            raise TranslationReferenceError("reference_legacy_original_lock_missing")
        self.descriptor = lock_private_file(self.root / "service.lock")
        try:
            self._root_identity = _file_identity(self.root, directory=True)
            self._initial = self._capture()
        except BaseException:
            os.close(self.descriptor)
            self.descriptor = -1
            raise
        return self

    def __exit__(self, *_):
        if self.descriptor >= 0:
            os.close(self.descriptor)
            self.descriptor = -1

    def _capture(self):
        if self.descriptor < 0 or self._root_identity != _file_identity(self.root, directory=True):
            raise TranslationReferenceError("reference_legacy_owner_not_held")
        held = os.fstat(self.descriptor)
        named = (self.root / "service.lock").lstat()
        if (held.st_dev, held.st_ino) != (named.st_dev, named.st_ino) or held.st_size:
            raise TranslationReferenceError("reference_legacy_lock_replaced_or_nonempty")
        result = {}
        with os.scandir(self.root) as entries:
            for count, entry in enumerate(entries, 1):
                if count > len(_FILES) + 2:
                    raise TranslationReferenceError("reference_legacy_unclassified_state")
                name = entry.name
                if name == FOLLOWER_STATE_DIRECTORY:
                    _file_identity(Path(entry.path), directory=True)
                elif name == _HISTORY:
                    result[name] = _file_identity(Path(entry.path), directory=True)
                    with os.scandir(entry.path) as history:
                        for index, item in enumerate(history, 1):
                            if index > MAX_HISTORY_FILES:
                                raise TranslationReferenceError(
                                    "reference_legacy_history_capacity_exceeded"
                                )
                            result[name + "/" + item.name] = _file_identity(Path(item.path))
                elif name in _FILES:
                    result[name] = _file_identity(Path(entry.path))
                else:
                    raise TranslationReferenceError(
                        "reference_legacy_layout_requires_supported_recovery"
                    )
        total = sum(int(value[6]) for name, value in result.items() if name != _HISTORY)
        if total > MAX_HISTORY_BYTES:
            raise TranslationReferenceError("reference_legacy_history_capacity_exceeded")
        return result

    def require_owner(self):
        if self._capture() != self._initial:
            raise TranslationReferenceError("reference_legacy_immutable_inputs_changed")

    def _emit(self, stage, completed, total, started, *, retrying=False):
        if self._progress is not None:
            elapsed = time.monotonic() - started
            self._progress(
                {
                    "stage": stage,
                    "completed": completed,
                    "total": total,
                    "percent": 100 * completed / total if total else 100,
                    "elapsed_seconds": elapsed,
                    "eta_seconds": (total - completed) * elapsed / completed
                    if completed and not retrying
                    else None,
                    "planning_seconds": [5, 300] if not completed and not retrying else None,
                    "eta_basis": "legacy input items; semantic audit forecast separate",
                    "stalled": retrying,
                    "retrying": retrying,
                }
            )

    def approve(self, state, policy, journal, *, verifier_semantics_sha256, now):
        self.require_owner()
        if identity(journal.hotkey) != identity(state.signing.validator_hotkey):
            raise TranslationReferenceError("reference_legacy_signer_binding_invalid")
        expected = {
            "schema": _RULE,
            "validator_account": identity(journal.hotkey),
            "root_identity": self._root_identity,
            "verifier_semantics_sha256": verifier_semantics_sha256,
        }
        retained = journal.journal.get(_ADOPTION, "accepted")
        if retained is not None:
            if not isinstance(retained, dict) or set(retained) != set(expected) | {
                "chunks",
                "inspection",
            }:
                raise TranslationReferenceError("reference_legacy_verification_repair_required")
            if any(retained.get(key) != value for key, value in expected.items()):
                raise TranslationReferenceError("reference_legacy_verification_repair_required")
            facts = {}
            chunks = retained["chunks"]
            if (
                not isinstance(chunks, list)
                or not 1 <= len(chunks) <= (MAX_HISTORY_FILES + 133) // 128
            ):
                raise TranslationReferenceError("reference_legacy_verification_repair_required")
            for key in chunks:
                chunk = journal.journal.get(_CHUNK, key)
                if not isinstance(chunk, dict) or digest(chunk) != key or set(facts) & set(chunk):
                    raise TranslationReferenceError("reference_legacy_verification_repair_required")
                facts.update(chunk)
            if facts != self._initial:
                raise TranslationReferenceError("reference_legacy_verification_repair_required")
            inspection = retained["inspection"]
            if (
                not isinstance(inspection, dict)
                or inspection.get("status")
                not in {
                    "fresh_registered_writer_without_prior_weight_effect",
                    "terminal_v1_bridge_bound_to_native_current_state",
                }
                or not isinstance(inspection.get("retained_files_sha256"), str)
                or len(inspection["retained_files_sha256"]) != 64
            ):
                raise TranslationReferenceError("reference_legacy_verification_repair_required")
            self.require_owner()
            return inspection
        if journal.pending() is not None:
            # This publication precedes the very first follower intent. Losing
            # it after that point is a repair, never a fresh empty installation.
            raise TranslationReferenceError("reference_legacy_verification_repair_required")
        started = time.monotonic()
        paths = [name for name in sorted(self._initial) if name != _HISTORY]
        files = {}
        self._emit("reference_legacy_input_capture", 0, len(paths), started)
        try:
            for index, name in enumerate(paths, 1):
                if name == "service.lock":
                    files[name] = b""
                else:
                    files[name] = _read_bytes(self.root / name, private=True)
                    self.payload_reads += 1
                self._emit("reference_legacy_input_capture", index, len(paths), started)
            self.require_owner()
            self._emit("reference_legacy_semantic_audit", 0, 1, time.monotonic())
            if set(files) == {"service.lock"}:
                decision = state.decision(policy, now=now)
                if decision.writer_last_update:
                    raise TranslationReferenceError(
                        "reference_empty_legacy_state_has_prior_chain_effects"
                    )
                inspection = {
                    "status": "fresh_registered_writer_without_prior_weight_effect",
                    "retained_files_sha256": digest(
                        {name: hashlib.sha256(raw).hexdigest() for name, raw in files.items()}
                    ),
                }
            else:
                value = inspect_translation_legacy(files, state, policy, now=now)
                inspection = {
                    "status": "terminal_v1_bridge_bound_to_native_current_state",
                    "retained_files_sha256": value.retained_files_sha256,
                    "terminal_attempts": value.terminal_attempts,
                    "last_weight_update": value.last_weight_update,
                    "observed_block": value.observed_block,
                }
            names, records, keys = sorted(self._initial), [], []
            for offset in range(0, len(names), 128):
                chunk = {name: self._initial[name] for name in names[offset : offset + 128]}
                key = digest(chunk)
                keys.append(key)
                records.append((_CHUNK, key, chunk))
            records.append(
                (_ADOPTION, "accepted", {**expected, "chunks": keys, "inspection": inspection})
            )
            self.require_owner()
            journal.journal.put_many(records)
            self._emit("reference_legacy_semantic_audit", 1, 1, started)
            return inspection
        except BaseException:
            self._emit("reference_legacy_semantic_audit", 0, 1, started, retrying=True)
            raise
