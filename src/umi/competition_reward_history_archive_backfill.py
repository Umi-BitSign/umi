"""Bounded native archive delivery and separately selected online local release.

This copies transport bytes for an already owned interval. It never creates a
native block verdict or makes storage migration a reward-admission condition.
The immutable object-completion ledger, file intents and per-frame cursor survive
restart. A selected consumer ABI and cross-process leases are required to evict.
"""

from __future__ import annotations

import os
import time
from datetime import datetime, timezone

from .competition_evidence_codec import MAX_EVIDENCE_BYTES, MAX_RECIPE_BYTES, inspect_recipe
from .competition_reward_history_checkpoint import HistoryCheckpointRepairRequired
from .competition_reward_proof_archive import (
    RewardProofArchive,
    _publication_clock_ns,
    history_archive_key,
)
from .open_competition import digest
from .private_files import PrivateStateBusyError

_HEADS = "history_archive_backfill_heads"
_FILES = "history_archive_backfill_files"
_OWNER = "history_archive_backfill_owner"
_STEP = "history_archive_backfill_step"
_GRAPH = "history_archive_backfill_graph"
_FILE = "history_archive_backfill_file"
_INTENT = "history_archive_backfill_unlink_intent"
_DONE = "history_archive_backfill_unlink_done"
_SCHEMA = {
    _HEADS: f"CREATE TABLE {_HEADS}(scope TEXT PRIMARY KEY,head TEXT NOT NULL)",
    _FILES: f"CREATE TABLE {_FILES}(scope TEXT,path TEXT,key TEXT NOT NULL,done INTEGER NOT NULL,"
    "PRIMARY KEY(scope,path))",
}
_INDEX = f"CREATE INDEX history_archive_backfill_pending ON {_FILES}(scope,done,path)"


def _fences():
    kinds = ",".join("'" + kind + "'" for kind in (_OWNER, _STEP, _GRAPH, _FILE, _INTENT, _DONE))
    return {
        "history_archive_backfill_" + action.lower(): "CREATE TRIGGER history_archive_backfill_"
        + action.lower()
        + " BEFORE "
        + action
        + " ON records WHEN OLD.kind IN ("
        + kinds
        + ") BEGIN SELECT RAISE(ABORT,"
        "'archive migration metadata is immutable; explicit repair required'); END"
        for action in ("UPDATE", "DELETE")
    }


class HistoryArchiveBackfill:
    def __init__(self, reader, field_limits):
        self.reader, self.archive = reader, reader.export_archive
        self.remote = self.archive.remote
        self.journal = self.remote.journal
        root = self.archive.root.stat()
        self.context = dict(
            schema="umi-history-archive-background/1",
            owner=reader.checkpoints.owner,
            root=str(self.archive.root),
            identity=[root.st_dev, root.st_ino, root.st_uid],
            remote=self.remote.namespace_sha256,
            first_block=reader.first_block,
            chain=reader.config_sha256,
            hotkey=reader.hotkey,
            release_abi=self.remote.config.archive_release_consumer_abi
            if self.remote.config.archive_release_batch_files
            else None,
        )
        self.scope = digest(self.context)
        self.fields = field_limits
        self.original = RewardProofArchive(self.archive.root)
        self.fences = _fences()
        prior = self.journal.get(_OWNER, self.scope)
        if prior is not None and prior != self.context:
            raise HistoryCheckpointRepairRequired("archive migration original owner changed")

        def initialize(db):
            installed = db.execute("SELECT 1 FROM sqlite_master WHERE name=?", (_HEADS,)).fetchone()
            if not installed:
                if (
                    prior is not None
                    or db.execute(
                        "SELECT 1 FROM records WHERE kind IN (?,?) LIMIT 1", (_STEP, _FILE)
                    ).fetchone()
                ):
                    raise HistoryCheckpointRepairRequired("archive migration indexes are missing")
                for sql in _SCHEMA.values():
                    db.execute(sql)
                db.execute(_INDEX)
                for sql in self.fences.values():
                    db.execute(sql)
            self._schema(db)
            row = db.execute(f"SELECT head FROM {_HEADS} WHERE scope=?", (self.scope,)).fetchone()
            if row is None:
                if prior is not None:
                    raise HistoryCheckpointRepairRequired("archive migration cursor is missing")
                start = self._initial()
                raw_key = digest(start)
                self.journal.insert_completion_record(db, _STEP, raw_key, self._raw(start))
                db.execute(f"INSERT INTO {_HEADS} VALUES (?,?)", (self.scope, raw_key))

        self.journal.put_many(((_OWNER, self.scope, self.context),), index=initialize)
        self.started = time.monotonic()
        self.attempt_started_utc = datetime.now(timezone.utc).isoformat()
        self.completed_attempt = 0
        self.released_attempt = 0
        _, saved = self._state()
        first = reader.first_block
        last = saved["next_block"]
        reader._archive_export_progress_next = last
        reader.progress.durable["exported"].update(range(first, last))
        reader.progress.retained_local_exports.difference_update(range(first, last))
        target = reader.progress.target
        reader.progress.counts["exported"] = (
            sum(h <= target for h in reader.progress.durable["exported"]) if target else 0
        )
        reader.progress.retained_local_export_count = (
            sum(h <= target for h in reader.progress.retained_local_exports) if target else 0
        )

    @staticmethod
    def _raw(value):
        from .protocol import canonical_json_bytes

        return canonical_json_bytes(value)

    def _initial(self):
        return dict(
            scope=self.scope,
            next_block=self.reader.first_block,
            through_block=self.reader.first_block - 1,
            copied_frames=0,
            reused_frames=0,
            removed_files=0,
            queued_files=0,
            reclaimed_allocated_bytes=0,
            started_utc=datetime.now(timezone.utc).isoformat(),
            prior=None,
        )

    def _schema(self, db):
        tables = dict(
            db.execute("SELECT name,sql FROM sqlite_master WHERE name IN (?,?)", tuple(_SCHEMA))
        )
        fences = dict(
            db.execute(
                "SELECT name,sql FROM sqlite_master WHERE type='trigger' AND "
                "name LIKE 'history_archive_backfill_%'"
            )
        )
        index = db.execute(
            "SELECT sql FROM sqlite_master WHERE name='history_archive_backfill_pending'"
        ).fetchone()
        if tables != _SCHEMA or fences != self.fences or index != (_INDEX,):
            raise HistoryCheckpointRepairRequired(
                "archive migration schema or mutation fences changed"
            )
        if self.journal.get(_OWNER, self.scope, db=db) != self.context:
            raise HistoryCheckpointRepairRequired("archive migration owner marker changed")

    def _state(self):
        with self.journal.read_transaction() as db:
            self._schema(db)
            row = db.execute(f"SELECT head FROM {_HEADS} WHERE scope=?", (self.scope,)).fetchone()
            value = None if row is None else self.journal.get(_STEP, row[0], db=db)
            if (
                not isinstance(value, dict)
                or digest(value) != row[0]
                or value.get("scope") != self.scope
            ):
                raise HistoryCheckpointRepairRequired("archive migration completed cursor damaged")
        return row[0], value

    def _commit(self, head, value, records=(), files=(), done=None):
        if files:
            with self.journal.read_transaction() as db:
                added = sum(
                    db.execute(
                        f"SELECT 1 FROM {_FILES} WHERE scope=? AND path=?", (self.scope, path)
                    ).fetchone()
                    is None
                    for path in dict(files)
                )
            value = dict(value, queued_files=value["queued_files"] + added)
        key = digest(value)

        def commit(db):
            self._schema(db)
            current = db.execute(
                f"SELECT head FROM {_HEADS} WHERE scope=?", (self.scope,)
            ).fetchone()
            if current != (head,):
                raise HistoryCheckpointRepairRequired(
                    "archive migration owner advanced concurrently"
                )
            for path, file_key in files:
                old = db.execute(
                    f"SELECT key FROM {_FILES} WHERE scope=? AND path=?", (self.scope, path)
                ).fetchone()
                if old is None:
                    db.execute(
                        f"INSERT INTO {_FILES} VALUES (?,?,?,0)", (self.scope, path, file_key)
                    )
                elif old != (file_key,):
                    raise HistoryCheckpointRepairRequired(
                        "archive migration local file generation changed"
                    )
            if done is not None:
                db.execute(
                    f"UPDATE {_FILES} SET done=1 WHERE scope=? AND key=?", (self.scope, done)
                )
            db.execute(f"UPDATE {_HEADS} SET head=? WHERE scope=?", (key, self.scope))

        self.journal.put_many([(_STEP, key, value), *records], index=commit)

    def _file(self, relative, reference):
        path = self.archive.root / relative
        if not path.exists():
            return None
        stamp = [str(v) for v in self.original._object_stamp(path)]
        tick = _publication_clock_ns()
        if tick is None or int(stamp[-1]) >= tick:
            raise OSError("archive release requires a qualified settled source timestamp")
        return dict(
            scope=self.scope,
            path=relative,
            stamp=stamp,
            reference=reference,
            allocated_bytes=path.stat().st_blocks * 512,
        )

    def _copy(self, height, release):
        key = history_archive_key(self.reader.config_sha256, self.reader.hotkey, height)
        wire = "frames/history/" + key
        reference = self.remote.reference_for_path(wire)
        graph_key = digest([self.scope, height])
        graph = self.journal.get(_GRAPH, graph_key)
        if graph is not None:
            if reference is None or graph["reference"] != reference:
                raise HistoryCheckpointRepairRequired("archive migration completed frame changed")
            return True, [], []
        if reference is not None and (
            not release or not self.original._path("history", key).exists()
        ):
            return True, [], []
        plans = []
        if reference is None and not self.original._path("history", key).exists():
            # A newly selected destination can have no original archive frame.
            # Copy checkpoint-bound compact source recipes; this does not
            # reconstruct the ordered fold or replay native proofs.
            from .competition_reward_history_export import export_completed_checkpoint

            checkpoint = self.reader.checkpoints.load(height)
            if checkpoint is None:
                raise HistoryCheckpointRepairRequired(
                    "admitted legacy archive frame is missing; restore its retained transport"
                )
            if not export_completed_checkpoint(self.reader, checkpoint, field_limits=self.fields):
                raise HistoryCheckpointRepairRequired(
                    "compact archive destination encoding needs repair"
                )
            reference = self.remote.reference_for_path(wire)
            if reference is None:
                raise HistoryCheckpointRepairRequired("compact archive publication lost completion")
            return (
                False,
                [
                    (
                        _GRAPH,
                        graph_key,
                        dict(scope=self.scope, height=height, reference=reference, files=[]),
                    )
                ],
                [],
            )
        with self.original.read_release_lease():
            frame = self.original._frame("history", key)
            if frame.context != self.reader._archive_context(height) or set(frame.fields) != set(
                self.fields
            ):
                raise HistoryCheckpointRepairRequired("legacy archive frame domain changed")
            fields = {}
            names = {"history/" + key + ".json": wire}
            for name, parts in frame.fields.items():
                if (
                    not 0
                    < len(parts)
                    <= (self.fields[name] + MAX_EVIDENCE_BYTES - 1) // MAX_EVIDENCE_BYTES
                    or sum(p.expanded_bytes for p in parts) > self.fields[name]
                ):
                    raise HistoryCheckpointRepairRequired(
                        "legacy archive frame exceeds native field bounds"
                    )
                encoded = []
                for part in parts:
                    recipe_path = self.archive.root / "objects" / (part.recipe_sha256 + ".json")
                    source = self.original if recipe_path.exists() else self.archive
                    recipe = source._bytes(part.recipe_sha256, MAX_RECIPE_BYTES)
                    segments = inspect_recipe(
                        recipe, expanded_bytes=part.expanded_bytes, kind="proof"
                    )
                    names["objects/" + part.recipe_sha256 + ".json"] = (
                        "objects/" + part.recipe_sha256
                    )
                    for _, sha, _ in segments:
                        names["objects/" + sha + ".json"] = "objects/" + sha
                    encoded.append((part.sha256, part.expanded_bytes, recipe))
                fields[name] = tuple(encoded)
            stamps = {
                name: [str(v) for v in self.original._object_stamp(self.archive.root / name)]
                for name in names
                if (self.archive.root / name).exists()
            }
            reused = reference is not None
            if reference is None:
                copied = self.archive.copy_encoded_transport(
                    "history",
                    key,
                    context=frame.context,
                    fields=fields,
                    resolve=self.original._bytes,
                )
                if not copied:
                    raise HistoryCheckpointRepairRequired(
                        "legacy archive transport encoding conflict"
                    )
                reference = self.remote.reference_for_path(wire)
                if reference is None:
                    raise HistoryCheckpointRepairRequired("archive publication lost receipt")
            if release:
                for relative, remote_path in names.items():
                    ref = self.remote.reference_for_path(remote_path)
                    if ref is None:
                        raise HistoryCheckpointRepairRequired(
                            "archive dependency lacks completed delivery"
                        )
                    plan = self._file(relative, ref)
                    if plan is not None:
                        if plan["stamp"] != stamps.get(relative):
                            raise HistoryCheckpointRepairRequired(
                                "archive source changed during publication"
                            )
                        plans.append(plan)
        records = [(_FILE, digest(plan), plan) for plan in plans]
        records.append(
            (
                _GRAPH,
                graph_key,
                dict(
                    scope=self.scope,
                    height=height,
                    reference=reference,
                    files=[digest(plan) for plan in plans],
                ),
            )
        )
        return reused, records, [(p["path"], digest(p)) for p in plans]

    def _release(self, maximum):
        with self.journal.read_transaction() as db:
            self._schema(db)
            pending = db.execute(
                f"SELECT path,key FROM {_FILES} WHERE scope=? AND done=0 ORDER BY path LIMIT ?",
                (self.scope, maximum),
            ).fetchall()
        for relative, key in pending:
            plan = self.journal.get(_FILE, key)
            if (
                plan is None
                or digest(plan) != key
                or plan["scope"] != self.scope
                or plan["path"] != relative
            ):
                raise HistoryCheckpointRepairRequired("archive local release plan damaged")
            self.remote.validate_reference(plan["reference"])
            try:
                with self.archive.read_release_lease(exclusive=True):
                    path = self.archive.root / relative
                    intent = self.journal.get(_INTENT, key)
                    if intent is not None and intent != plan:
                        raise HistoryCheckpointRepairRequired("archive unlink intent changed")
                    if path.exists():
                        if [str(v) for v in self.original._object_stamp(path)] != plan["stamp"]:
                            raise HistoryCheckpointRepairRequired("archive unlink source changed")
                        if intent is None:
                            self.journal.put(_INTENT, key, plan)
                        path.unlink()
                    elif intent is None:
                        raise HistoryCheckpointRepairRequired(
                            "archive source disappeared without unlink intent"
                        )
                    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
                    try:
                        os.fsync(fd)
                    finally:
                        os.close(fd)
                    head, state = self._state()
                    value = dict(
                        state,
                        prior=head,
                        removed_files=state["removed_files"] + 1,
                        reclaimed_allocated_bytes=state["reclaimed_allocated_bytes"]
                        + plan["allocated_bytes"],
                    )
                    self._commit(
                        head, value, ((_DONE, key, dict(intent_sha256=digest(plan))),), done=key
                    )
                    self.released_attempt += 1
            except PrivateStateBusyError:
                return "waiting_for_active_archive_reader"
        return "pending" if len(pending) == maximum else "idle"

    def run(self, maximum_frames, maximum_files):
        if self.reader._tip is None:
            return None
        through = self.reader._next - 1
        head, state = self._state()
        through = max(through, state["through_block"])
        release = bool(maximum_files)
        try:
            for height in range(
                state["next_block"], min(through + 1, state["next_block"] + maximum_frames)
            ):
                if self.reader._shutdown_requested():
                    break
                reused, records, files = self._copy(height, release)
                head, state = self._state()
                value = dict(
                    state,
                    prior=head,
                    next_block=height + 1,
                    through_block=through,
                    copied_frames=state["copied_frames"] + int(not reused),
                    reused_frames=state["reused_frames"] + int(reused),
                )
                self._commit(head, value, records, files)
                self.completed_attempt += 1
            release_state = self._release(maximum_files) if maximum_files else "not_selected"
            head, state = self._state()
            return self.report(state, through, release_state)
        except BaseException:
            head, state = self._state()
            self.reader.progress.archive_delivery = self.report(state, through, "retrying")
            raise

    def report(self, state, through, release_state):
        elapsed = time.monotonic() - self.started
        total = through - self.reader.first_block + 1
        completed = min(total, state["next_block"] - self.reader.first_block)
        remaining = total - completed
        measured = (
            self.completed_attempt / elapsed if self.completed_attempt and elapsed >= 1 else None
        )
        return dict(
            stage="history_archive_delivery_migration",
            state="completed" if not remaining else "pending",
            first_block=self.reader.first_block,
            through_block=through,
            next_block=state["next_block"],
            completed_blocks=completed,
            total_blocks=total,
            percent=100 * completed / total if total else 100,
            elapsed_seconds=(
                datetime.now(timezone.utc) - datetime.fromisoformat(state["started_utc"])
            ).total_seconds(),
            attempt_elapsed_seconds=elapsed,
            attempt_started_utc=self.attempt_started_utc,
            rate_window_scope="current_process_archive_migration_attempt",
            started_utc=state["started_utc"],
            attempt_completed_blocks=self.completed_attempt,
            blocks_per_second=measured,
            eta_seconds=remaining / measured if measured else 0 if not remaining else None,
            planning_eta_seconds=[remaining / 100, remaining]
            if remaining and measured is None
            else None,
            eta_basis="measured_current_process_archive_frames_per_second"
            if measured
            else "complete_archive_delivery"
            if not remaining
            else "planning_unmeasured_1_to_100_frames_per_second",
            eta_scope="archive_delivery_only_not_native_history_or_rewards",
            stalled=False,
            retrying=release_state == "retrying",
            copied_frames=state["copied_frames"],
            reused_frames=state["reused_frames"],
            local_release_state=release_state,
            queued_files=state["queued_files"],
            local_release_percent=100 * state["removed_files"] / state["queued_files"]
            if state["queued_files"]
            else 100,
            local_release_eta_seconds=(state["queued_files"] - state["removed_files"])
            * elapsed
            / self.released_attempt
            if self.released_attempt
            and elapsed >= 1
            and release_state not in {"retrying", "waiting_for_active_archive_reader"}
            else None,
            local_release_eta_basis="withdrawn_waiting_for_active_archive_reader_or_retry"
            if release_state in {"retrying", "waiting_for_active_archive_reader"}
            else "measured_current_process_files_per_second"
            if self.released_attempt and elapsed >= 1
            else "waiting_for_qualified_release_or_initial_samples",
            local_release_eta_scope="currently_queued_files_only_excludes_unscanned_frames",
            removed_files=state["removed_files"],
            reclaimed_allocated_bytes=state["reclaimed_allocated_bytes"],
        )
