"""Owner-managed retirement of imported objects with original R2 completion receipts.

Only receipt metadata and local inode metadata are read. Frames, recipes and
native verification are deliberately outside this operation. A separate bounded
journal allocates each admitted batch's intent and completion slots before any
unlink; the original producer index is opened read-only and never extended here.
Selecting the final aggregate cursor also compacts that completed retirement
batch, leaving a bounded working set without discarding original proof receipts.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone

from .competition_journal_physical_budget import JournalPhysicalBudget
from .competition_reward_history_archive_backfill import unlink_completed_archive_file
from .competition_reward_history_checkpoint import HistoryCheckpointRepairRequired
from .competition_reward_proof_archive import RewardProofArchive, _publication_clock_ns
from .competition_round_journal import RoundJournal
from .open_competition import digest
from .private_files import PrivateStateBusyError, private_path
from .protocol import canonical_json_bytes

_OWNER = "imported_object_retirement_owner"
_STATE = "imported_object_retirement_state"
_BATCH = "imported_object_retirement_batch"
_HEAD = "imported_object_retirement_head"
_HEAD_SQL = f"CREATE TABLE {_HEAD}(id INTEGER PRIMARY KEY CHECK(id=1),head TEXT NOT NULL)"
_FILES = "imported_object_retirement_files"
_FILES_SQL = (
    f"CREATE TABLE {_FILES}(batch TEXT NOT NULL,key TEXT NOT NULL,"
    "intent INTEGER NOT NULL CHECK(intent IN (0,1)),"
    "done INTEGER NOT NULL CHECK(done IN (0,1) AND done<=intent),PRIMARY KEY(batch,key))"
)
_COMPACT = "umi_imported_retirement_compaction"
_ENROLLMENT = "imported_object_retirement_enrollment"
_ENROLLMENT_KEY = "imported-object-retirement"


def _enrollment_fences():
    return {
        "imported_retirement_enrollment_"
        + action.lower(): "CREATE TRIGGER imported_retirement_enrollment_"
        + action.lower()
        + " BEFORE "
        + action
        + f" ON records WHEN OLD.kind='{_ENROLLMENT}' BEGIN SELECT "
        "RAISE(ABORT,'imported retirement enrollment is immutable; restore original metadata'); END"
        for action in ("UPDATE", "DELETE")
    }


def _fences():
    kinds = ",".join("'" + kind + "'" for kind in (_OWNER, _STATE, _BATCH))
    fences = {
        "imported_retirement_" + action.lower(): "CREATE TRIGGER imported_retirement_"
        + action.lower()
        + " BEFORE "
        + action
        + " ON records WHEN OLD.kind IN ("
        + kinds
        + ")"
        + (f" AND {_COMPACT}(OLD.kind,OLD.id) IS NOT 1" if action == "DELETE" else "")
        + " BEGIN SELECT RAISE(ABORT,"
        "'imported retirement metadata is immutable; explicit repair required'); END"
        for action in ("UPDATE", "DELETE")
    }
    fences["imported_retirement_files_delete"] = (
        f"CREATE TRIGGER imported_retirement_files_delete BEFORE DELETE ON {_FILES} "
        f"WHEN OLD.done!=1 OR {_COMPACT}('{_FILES}',OLD.batch) IS NOT 1 "
        "BEGIN SELECT RAISE(ABORT,'unfinished imported retirement slots cannot be deleted'); END"
    )
    fences["imported_retirement_files_update"] = (
        f"CREATE TRIGGER imported_retirement_files_update BEFORE UPDATE ON {_FILES} "
        "WHEN NEW.batch!=OLD.batch OR NEW.key!=OLD.key OR NEW.intent<OLD.intent "
        "OR NEW.done<OLD.done BEGIN SELECT "
        "RAISE(ABORT,'imported retirement completion slots cannot regress'); END"
    )
    return fences


class ImportedProofRetirement:
    def __init__(self, reader):
        self.reader, self.archive = reader, reader.archive
        exported = reader.export_archive
        self.remote = None if self.archive is None else self.archive.remote
        producer = None if exported is None else exported.remote
        if (
            self.remote is None
            or producer is None
            or not self.archive.legacy_read_through
            or not self.remote.config.read_only
            or self.remote.receipt_source is None
            or producer.config.read_only
            or not exported.legacy_read_through
            or producer.config.archive_release_consumer_abi != "umi-proof-read-release-lease/1"
            or self.remote.namespace_sha256 != producer.namespace_sha256
            or self.remote.receipt_source.path.resolve() != producer.journal.path.resolve()
            or self.archive.root.resolve() == exported.root.resolve()
        ):
            raise HistoryCheckpointRepairRequired(
                "imported release requires the selected leased consumer and original receipt owner"
            )
        self.archive._ensure_root()
        root = self.archive.root.stat()
        self.context = dict(
            schema="umi-imported-object-retirement/1",
            owner=reader.checkpoints.owner,
            root=str(self.archive.root),
            identity=[root.st_dev, root.st_ino, root.st_uid],
            remote=self.remote.namespace_sha256,
            receipt_owner=str(self.remote.receipt_source.path),
            chain=reader.config_sha256,
            hotkey=reader.hotkey,
            release_abi=producer.config.archive_release_consumer_abi,
        )
        self.scope = digest(self.context)
        self.enrollment = self._retained_enrollment()
        retirement_root = self.archive.root / ".object-retirement"
        if self.enrollment is not None:
            self._check_enrollment(retirement_root, self.enrollment)
        # This journal is local retirement bookkeeping, not a second proof index.
        # Bound physical growth separately. Actual fixed-size completion slots
        # and the final cursor are allocated before unlink, avoiding a growing
        # generic reservation table scan on each small-object release.
        allowance = producer.config.imported_object_release_maximum_metadata_bytes
        self.journal = RoundJournal(
            retirement_root,
            self.context,
            maximum_rounds=65536,
            maximum_bytes=allowance,
            maximum_record_bytes=512 * 1024,
            existing_only=self.enrollment is not None,
            physical_budget=JournalPhysicalBudget(
                maximum_database_bytes=4 * allowance + 16 * 1024**2,
                minimum_free_bytes=0,
                allocation_overhead_bytes=8 * 1024**2,
            ),
        )
        self.original = RewardProofArchive(self.archive.root)
        self.fences = _fences()
        prior = self.journal.get(_OWNER, self.scope)

        def initialize(db):
            if not db.execute("SELECT 1 FROM sqlite_master WHERE name=?", (_HEAD,)).fetchone():
                if (
                    prior is not None
                    or db.execute(
                        "SELECT 1 FROM records WHERE kind IN (?,?) LIMIT 1", (_STATE, _BATCH)
                    ).fetchone()
                ):
                    raise HistoryCheckpointRepairRequired("imported retirement cursor is missing")
                db.execute(_HEAD_SQL)
                db.execute(_FILES_SQL)
                for sql in self.fences.values():
                    db.execute(sql)
                value = dict(
                    scope=self.scope,
                    cursor=None,
                    pending=None,
                    removed_files=0,
                    absent_objects=0,
                    ignored_receipts=0,
                    reclaimed_allocated_bytes=0,
                    completed_total=0,
                    caught_up=False,
                    started_utc=datetime.now(timezone.utc).isoformat(),
                    prior=None,
                )
                key = digest(value)
                db.execute(
                    "INSERT INTO records VALUES (?,?,?)", (_STATE, key, canonical_json_bytes(value))
                )
                db.execute(f"INSERT INTO {_HEAD} VALUES (1,?)", (key,))
            self._schema(db)

        self.journal.put_many(((_OWNER, self.scope, self.context),), index=initialize)
        self.started = time.monotonic()
        self.attempt_scanned = self.attempt_released = 0
        self.attempt_started_utc = datetime.now(timezone.utc).isoformat()
        _, state = self._state()
        if self.enrollment is None:
            if (
                state["cursor"] is not None
                or state["pending"] is not None
                or state["removed_files"]
            ):
                raise HistoryCheckpointRepairRequired("imported retirement enrollment is missing")
            enrollment = dict(
                schema="umi-imported-retirement-enrollment/1",
                scope=self.scope,
                root=str(retirement_root),
                identity=self._retirement_identity(retirement_root),
            )

            def enroll(db):
                for name, sql in _enrollment_fences().items():
                    prior = db.execute(
                        "SELECT sql FROM sqlite_master WHERE name=?", (name,)
                    ).fetchone()
                    if prior is None:
                        db.execute(sql)
                    elif prior != (sql,):
                        raise HistoryCheckpointRepairRequired(
                            "imported retirement enrollment fence changed"
                        )

            # Independent consumer metadata only: original producer receipts and
            # native completed history are never mutated for cleanup enrollment.
            self.remote.journal.put_many(
                ((_ENROLLMENT, _ENROLLMENT_KEY, enrollment),), index=enroll
            )
            self.enrollment = enrollment

    def _retained_enrollment(self):
        with self.remote.journal.read_transaction() as db:
            value = self.remote.journal.get(_ENROLLMENT, _ENROLLMENT_KEY, db=db)
            fences = dict(
                db.execute(
                    "SELECT name,sql FROM sqlite_master WHERE type='trigger' "
                    "AND name LIKE 'imported_retirement_enrollment_%'"
                )
            )
            if (value is None and fences) or (value is not None and fences != _enrollment_fences()):
                raise HistoryCheckpointRepairRequired(
                    "imported retirement enrollment metadata damaged"
                )
            if value is not None and not isinstance(value, dict):
                raise HistoryCheckpointRepairRequired(
                    "imported retirement enrollment value damaged"
                )
            return value

    @staticmethod
    def _retirement_identity(root):
        path = root / "rounds.sqlite3"
        private_path(str(path))
        try:
            directory, journal = root.lstat(), path.lstat()
        except FileNotFoundError as error:
            raise HistoryCheckpointRepairRequired(
                "enrolled imported retirement journal is missing"
            ) from error
        return [
            directory.st_dev,
            directory.st_ino,
            directory.st_uid,
            journal.st_dev,
            journal.st_ino,
            journal.st_uid,
        ]

    def _check_enrollment(self, root, enrollment):
        if (
            enrollment.get("schema") != "umi-imported-retirement-enrollment/1"
            or enrollment.get("scope") != self.scope
            or enrollment.get("root") != str(root)
            or enrollment.get("identity") != self._retirement_identity(root)
        ):
            raise HistoryCheckpointRepairRequired("enrolled imported retirement owner changed")

    def _schema(self, db):
        table = db.execute("SELECT sql FROM sqlite_master WHERE name=?", (_HEAD,)).fetchone()
        files = db.execute("SELECT sql FROM sqlite_master WHERE name=?", (_FILES,)).fetchone()
        fences = dict(
            db.execute(
                "SELECT name,sql FROM sqlite_master WHERE type='trigger' "
                "AND name LIKE 'imported_retirement_%'"
            )
        )
        if table != (_HEAD_SQL,) or files != (_FILES_SQL,) or fences != self.fences:
            raise HistoryCheckpointRepairRequired("imported retirement metadata fences changed")
        if self.journal.get(_OWNER, self.scope, db=db) != self.context:
            raise HistoryCheckpointRepairRequired("imported retirement owner changed")

    def _state(self):
        self._check_selected()
        with self.journal.read_transaction() as db:
            self._schema(db)
            row = db.execute(f"SELECT head FROM {_HEAD} WHERE id=1").fetchone()
            value = None if row is None else self.journal.get(_STATE, row[0], db=db)
            if (
                not isinstance(value, dict)
                or digest(value) != row[0]
                or value["scope"] != self.scope
            ):
                raise HistoryCheckpointRepairRequired("imported retirement cursor damaged")
        return row[0], value

    def _check_archive_root(self):
        private_path(str(self.archive.root))
        root = self.archive.root.lstat()
        if [root.st_dev, root.st_ino, root.st_uid] != self.context["identity"]:
            raise HistoryCheckpointRepairRequired("imported retirement archive root changed")

    def _check_selected(self):
        self._check_archive_root()
        if self.enrollment is not None:
            if self._retained_enrollment() != self.enrollment:
                raise HistoryCheckpointRepairRequired("imported retirement enrollment changed")
            self._check_enrollment(self.journal.root, self.enrollment)
        if (
            self.reader.archive is not self.archive
            or self.archive.remote is not self.remote
            or self.remote.receipt_source is None
            or str(self.remote.receipt_source.path) != self.context["receipt_owner"]
            or self.reader.export_archive.remote is None
            or self.reader.export_archive.remote.journal.path.resolve()
            != self.remote.receipt_source.path.resolve()
            or self.reader.export_archive.remote.namespace_sha256 != self.context["remote"]
            or self.reader.export_archive.remote.config.archive_release_consumer_abi
            != self.context["release_abi"]
        ):
            raise HistoryCheckpointRepairRequired("imported retirement selected consumer changed")

    def _commit(self, head, value, records=(), slots=None, completed_batch=None):
        key = digest(value)

        def commit(db):
            self._schema(db)
            if db.execute(f"SELECT head FROM {_HEAD} WHERE id=1").fetchone() != (head,):
                raise HistoryCheckpointRepairRequired(
                    "imported retirement owner advanced concurrently"
                )
            if slots is not None:
                self._admit_finish_slots(db, *slots)
            db.execute(f"UPDATE {_HEAD} SET head=? WHERE id=1", (key,))
            if slots is None:
                self._compact(db, head, value, completed_batch)

        self.journal.put_many([(_STATE, key, value), *records], index=commit)

    def _compact(self, db, previous, selected, completed_batch):
        """Publish the retained aggregate and retire only its terminal scratch.

        These private cursor records are not native completion evidence. The
        selected aggregate retains all counts and the exact original-receipt
        anchor; pending plans and unfinished slots cannot enter this path.
        """
        authorized = {(_STATE, previous)}
        if selected["pending"] is not None:
            raise HistoryCheckpointRepairRequired("cannot compact an unfinished retirement batch")
        if completed_batch is not None:
            batch = self.journal.get(_BATCH, completed_batch, db=db)
            if (
                batch is None
                or digest(batch) != completed_batch
                or selected["cursor"] != batch["cursor"]
                or db.execute(
                    f"SELECT COUNT(*),COALESCE(SUM(done),0) FROM {_FILES} WHERE batch=?",
                    (completed_batch,),
                ).fetchone()
                != (len(batch["plans"]), len(batch["plans"]))
            ):
                raise HistoryCheckpointRepairRequired(
                    "retirement compaction requires completed slots"
                )
            authorized.update(
                {(_BATCH, completed_batch), (_FILES, completed_batch), (_STATE, batch["prior"])}
            )
        if (_STATE, digest(selected)) in authorized:
            raise HistoryCheckpointRepairRequired(
                "retirement compaction would remove selected cursor"
            )
        db.create_function(_COMPACT, 2, lambda kind, key: int((kind, key) in authorized))
        try:
            if completed_batch is not None:
                db.execute(f"DELETE FROM {_FILES} WHERE batch=?", (completed_batch,))
            db.executemany(
                "DELETE FROM records WHERE kind=? AND id=?",
                sorted((kind, key) for kind, key in authorized if kind != _FILES),
            )
        finally:
            db.create_function(_COMPACT, 2, None)

    def _admit_finish_slots(self, db, batch_key, plans):
        # Each row's two 0/1 flags have equal SQLite storage widths. No new
        # rows, indexes, record bodies or keys are needed after intent admission.
        # The immutable batch charges 512 bytes per slot to logical capacity,
        # beyond its actual identity metadata; physical pages have their own cap.
        db.executemany(
            f"INSERT INTO {_FILES} VALUES (?,?,0,0)",
            ((batch_key, self._item(batch_key, i, p)[0]) for i, p in enumerate(plans)),
        )

    def _slot(self, batch_key, key, *, intent=False, done=False):
        with self.journal.transaction() as db:
            self._schema(db)
            row = db.execute(
                f"SELECT intent,done FROM {_FILES} WHERE batch=? AND key=?", (batch_key, key)
            ).fetchone()
            if row is None:
                raise HistoryCheckpointRepairRequired("imported retirement finish slot missing")
            if done and not row[0]:
                raise HistoryCheckpointRepairRequired("imported retirement completion lacks intent")
            db.execute(
                f"UPDATE {_FILES} SET intent=?,done=? WHERE batch=? AND key=?",
                (int(bool(intent or row[0])), int(bool(done or row[1])), batch_key, key),
            )

    def _plan(self, reference):
        prefix = self.remote.config.prefix + "/objects/"
        key = reference["key"]
        if not key.startswith(prefix):
            return None, "ignored"
        sha = key[len(prefix) :]
        if len(sha) != 64 or any(c not in "0123456789abcdef" for c in sha):
            raise HistoryCheckpointRepairRequired("imported object receipt path is not canonical")
        if reference["content_sha256"] != sha:
            raise HistoryCheckpointRepairRequired(
                "imported object receipt content identity changed"
            )
        relative = "objects/" + sha + ".json"
        path = self.archive.root / relative
        try:
            stamp = [str(v) for v in self.original._object_stamp(path)]
        except FileNotFoundError:
            return None, "absent"
        tick = _publication_clock_ns()
        if tick is None or int(stamp[-1]) >= tick:
            raise OSError("imported release requires a qualified settled source timestamp")
        # Local envelopes contain a hex rendering; R2 receipts bind the raw
        # bytes. The filename supplies their immutable content address.
        if int(stamp[-3]) != 2 * reference["size_bytes"] + 10:
            raise HistoryCheckpointRepairRequired(
                "imported object envelope size differs from receipt"
            )
        info = path.lstat()
        if [str(v) for v in self.original._object_stamp(path)] != stamp:
            raise HistoryCheckpointRepairRequired("imported object changed during admission")
        return dict(
            path=relative,
            stamp=stamp,
            reference=reference,
            allocated_bytes=info.st_blocks * 512,
        ), "eligible"

    @staticmethod
    def _item(batch_key, offset, plan):
        value = dict(batch=batch_key, index=offset, plan_sha256=digest(plan))
        return digest(value), value

    def _finished(self, head, state, batch):
        return dict(
            state,
            prior=head,
            pending=None,
            cursor=batch["cursor"],
            completed_total=batch["completed_total"],
            caught_up=batch["caught_up"],
            removed_files=state["removed_files"] + len(batch["plans"]),
            absent_objects=state["absent_objects"] + batch["absent_objects"],
            ignored_receipts=state["ignored_receipts"] + batch["ignored_receipts"],
            reclaimed_allocated_bytes=state["reclaimed_allocated_bytes"]
            + sum(plan["allocated_bytes"] for plan in batch["plans"]),
        )

    def _admit(self, maximum):
        head, state = self._state()
        if state["pending"] is not None:
            raise HistoryCheckpointRepairRequired("pending imported intents must drain first")
        page = self.remote.completion_page(state["cursor"], maximum_records=maximum)
        plans, absent, ignored = [], 0, 0
        with self.archive.read_release_lease():
            for reference in page["references"]:
                plan, kind = self._plan(reference)
                if plan is not None:
                    plans.append(plan)
                absent += kind == "absent"
                ignored += kind == "ignored"
        batch = dict(
            scope=self.scope,
            prior=head,
            cursor=page["cursor"],
            completed_total=page["completed_total"],
            caught_up=page["caught_up"],
            absent_objects=absent,
            ignored_receipts=ignored,
            plans=plans,
            finish_slot_allowance=" " * (512 * len(plans)),
        )
        if not plans:
            finished = self._finished(head, state, batch)
            # Polling a caught-up unchanged ledger writes no additional records.
            if {k: v for k, v in finished.items() if k != "prior"} != {
                k: v for k, v in state.items() if k != "prior"
            }:
                self._commit(head, finished)
        else:
            batch_key = digest(batch)
            pending = dict(state, pending=batch_key, prior=head, caught_up=False)
            finished = self._finished(digest(pending), pending, batch)
            self._commit(
                head,
                pending,
                ((_BATCH, batch_key, batch), (_STATE, digest(finished), finished)),
                slots=(batch_key, plans),
            )
        self.attempt_scanned += len(page["references"])

    def _drain(self, maximum):
        head, state = self._state()
        batch_key = state["pending"]
        if batch_key is None:
            return "idle"
        batch = self.journal.get(_BATCH, batch_key)
        if batch is None or digest(batch) != batch_key or batch["scope"] != self.scope:
            raise HistoryCheckpointRepairRequired("imported retirement batch damaged")
        with self.journal.read_transaction() as db:
            slots = dict(
                (key, (intent, done))
                for key, intent, done in db.execute(
                    f"SELECT key,intent,done FROM {_FILES} WHERE batch=?", (batch_key,)
                )
            )
        expected = {self._item(batch_key, i, p)[0] for i, p in enumerate(batch["plans"])}
        if set(slots) != expected:
            raise HistoryCheckpointRepairRequired(
                "imported retirement finish slots missing or changed"
            )
        finished = self._finished(head, state, batch)
        if self.journal.get(_STATE, digest(finished)) != finished:
            raise HistoryCheckpointRepairRequired(
                "imported retirement reserved final cursor missing"
            )
        processed = 0
        for offset, plan in enumerate(batch["plans"]):
            key, _ = self._item(batch_key, offset, plan)
            intent, done = slots[key]
            if done:
                continue
            if processed >= maximum or self.reader._shutdown_requested():
                return "pending"
            try:
                unlink_completed_archive_file(
                    self.archive,
                    self.original,
                    self.remote,
                    plan,
                    intent=bool(intent),
                    remember_intent=lambda key=key: self._slot(batch_key, key, intent=True),
                    finish=lambda key=key: self._slot(batch_key, key, done=True),
                    independent_bookkeeping=True,
                    validate_target=self._check_selected,
                )
            except PrivateStateBusyError:
                return "waiting_for_active_archive_reader"
            processed += 1
            self.attempt_released += 1
        self._commit(head, finished, completed_batch=batch_key)
        return "idle"

    def _report(self, status):
        _, state = self._state()
        completed = 0 if state["cursor"] is None else state["cursor"]["completed_seen"]
        removed, reclaimed = state["removed_files"], state["reclaimed_allocated_bytes"]
        total = state["completed_total"]
        if state["pending"] is not None:
            batch = self.journal.get(_BATCH, state["pending"])
            total = batch["completed_total"]
            with self.journal.read_transaction() as db:
                done = {
                    row[0]
                    for row in db.execute(
                        f"SELECT key FROM {_FILES} WHERE batch=? AND done=1", (state["pending"],)
                    )
                }
            for offset, plan in enumerate(batch["plans"]):
                key, _ = self._item(state["pending"], offset, plan)
                if key in done:
                    removed += 1
                    reclaimed += plan["allocated_bytes"]
        attempt_elapsed = time.monotonic() - self.started
        elapsed = max(
            0,
            (
                datetime.now(timezone.utc) - datetime.fromisoformat(state["started_utc"])
            ).total_seconds(),
        )
        rate = self.attempt_scanned / attempt_elapsed if attempt_elapsed else 0
        remaining = max(0, total - completed)
        finished = state["caught_up"] and state["pending"] is None
        blocked = status == "waiting_for_active_archive_reader"
        return dict(
            stage="imported_object_retirement",
            state="completed" if finished else "waiting" if blocked else "running",
            local_release_state=status,
            completed=completed,
            total=total,
            percent=100 * completed / total if total else 100 if finished else 0,
            removed_files=removed,
            reclaimed_allocated_bytes=reclaimed,
            absent_objects=state["absent_objects"],
            ignored_receipts=state["ignored_receipts"],
            elapsed_seconds=elapsed,
            attempt_elapsed_seconds=attempt_elapsed,
            started_utc=state["started_utc"],
            attempt_started_utc=self.attempt_started_utc,
            eta_seconds=0 if finished else remaining / rate if rate and not blocked else None,
            planning_eta_seconds=[remaining / 100, remaining] if not rate and not blocked else None,
            eta_basis="completed_scope"
            if finished
            else "withdrawn_active_reader_wait"
            if blocked
            else "current_process_receipts_per_second_excludes_new_publications_and_other_stages"
            if rate
            else "planning_metadata_retirement_1_to_100_receipts_per_second_unmeasured",
            stalled_or_retrying=blocked,
            eta_scope="current_original_receipt_ledger_retirement_only",
        )

    def run(self, maximum):
        if type(maximum) is not int or not 1 <= maximum <= 256:
            raise ValueError("imported retirement batch must be between 1 and 256")
        # The mutex is inside the archive. Refuse a replaced root before opening
        # its lock path; _state() retains the owner check after serialization.
        self._check_archive_root()
        with self.journal.locked():
            # A retry drains its admitted generation before even reading the next
            # producer page. Do not let new claims consume finish headroom.
            _, state = self._state()
            had_pending = state["pending"] is not None
            status = self._drain(maximum)
            if not had_pending and not self.reader._shutdown_requested():
                self._admit(maximum)
                status = self._drain(maximum)
            return self._report(status)
