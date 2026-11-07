"""Owned incremental migration and archival of original forecast ledger rows."""

import hashlib
import json
import sqlite3
import time
from collections.abc import Mapping

from .competition_forecast_archive import ForecastSegment
from .competition_forecast_compaction import ForecastCompaction
from .competition_forecast_health import write_health
from .competition_forecast_io import encode_forecast_json
from .competition_forecast_segments import ForecastSegments
from .competition_forecast_summary import ForecastSummary
from .competition_transport_verification import TransferProgress


class ForecastSummaries(Mapping):
    def __init__(self, retention):
        self.retention = retention

    def __getitem__(self, scope):
        self.retention.ensure_ready()
        result = self.retention.index.summary(scope)
        if result is None:
            raise KeyError(scope)
        return result

    def __iter__(self):
        self.retention.ensure_ready()
        with self.retention.index.lock:
            rows = self.retention.index.db.execute("SELECT scope FROM summaries ORDER BY scope")
            yield from (row[0] for row in rows)

    def __len__(self):
        self.retention.ensure_ready()
        with self.retention.index.lock:
            return self.retention.index.db.execute("SELECT COUNT(*) FROM summaries").fetchone()[0]


class ForecastRetention:
    page_events = 256

    def __init__(self, ledger, remote, ledger_sha256, *, maximum_index_bytes):
        self.started = time.monotonic()
        self.last_archive = self.started
        self.initial_indexed = None
        self.ledger = ledger
        self.compaction = ForecastCompaction(ledger)
        if (
            ledger.db.execute("PRAGMA user_version").fetchone() == (2,)
            and not (ledger.directory / "retention").exists()
        ):
            raise ValueError("forecast archive state missing; explicit repair required")
        self.segments = ForecastSegments(
            ledger.directory / "retention",
            ledger_sha256,
            remote,
            maximum_index_bytes=maximum_index_bytes,
        )
        try:
            self.index = self.segments.index
            self.initial_indexed = self.index.head[0]
            self.ledger_sha256 = ledger_sha256
            self.summaries = ForecastSummaries(self)
            heads = ledger.db.execute("SELECT digest,sequence FROM head").fetchall()
            if len(heads) != 1 or type(heads[0][1]) is not int or heads[0][1] < 0:
                raise ValueError("forecast original checkpoint requires explicit repair")
            ledger.head = heads[0]
            if self.index.head[0] > ledger.head[1] or (
                self.index.head[0] == ledger.head[1] and self.index.head[1] != ledger.head[0]
            ):
                raise ValueError("forecast index differs from original checkpoint; repair required")
            archive = self.index.latest_archive()
            after = 0 if archive is None else archive["last_sequence"]
            tail = ledger.db.execute(
                "SELECT COUNT(*) FROM events WHERE sequence>?", (after,)
            ).fetchone()[0]
            if tail != ledger.head[1] - after:
                raise ValueError("forecast original/archive coverage requires explicit repair")
            if ledger.db.execute("PRAGMA user_version").fetchone() not in {(1,), (2,)}:
                raise ValueError("forecast original schema requires explicit repair")
        except BaseException:
            self.segments.close()
            raise

    def close(self):
        self.segments.close()

    def ensure_ready(self):
        if self.index.head != (self.ledger.head[1], self.ledger.head[0]):
            raise ValueError("forecast retained migration pending; run owned maintenance")

    def advance(self):
        """One bounded page, owned by the lifecycle maintenance worker."""
        ledger = self.ledger
        # A committed archive owns all inputs needed for publication/retry;
        # do not fetch its original rows or replay their summaries again.
        metadata = self.index.latest_archive()
        if metadata is None or self.index.archive_state(metadata["first_sequence"])[2]:
            with ledger.lock:
                after = 0 if metadata is None else metadata["last_sequence"]
                remaining = ledger.head[1] - after
                migrating = self.index.head[0] < ledger.head[1]
                if remaining == 0 or (
                    not migrating
                    and not ledger.capacity_required
                    and remaining < self.page_events
                    and time.monotonic() - self.last_archive < 30
                ):
                    return self.compaction.advance()
                rows = tuple(
                    ledger.db.execute(
                        "SELECT sequence,identity,scope,body,previous,digest FROM events "
                        "WHERE sequence>? ORDER BY sequence LIMIT ?",
                        (after, self.page_events),
                    )
                )
                if not rows or rows[0][0] != after + 1:
                    raise ValueError(
                        "forecast migration originals missing; explicit repair required"
                    )
                previous = "0" * 64 if metadata is None else metadata["last_sha256"]
                segment = ForecastSegment(self.ledger_sha256, after + 1, previous, rows)
                with TransferProgress(
                    "forecast_retained_migration_page", len(rows), unit="events"
                ) as work:
                    metadata = self.segments.stage(segment)
                    work.advance(len(rows))
        first = metadata["first_sequence"]
        self.segments.publish(first)
        # Publication is complete before any original row is released. The
        # bounded original cache retains active exact retries independently.
        with ledger.lock, ledger.db:
            ledger.db.execute(
                "DELETE FROM events WHERE sequence>=? AND sequence<=?",
                (first, metadata["last_sequence"]),
            )
            ledger.db.execute("PRAGMA user_version=2")
        self.segments.release(first)
        self.last_archive = time.monotonic()
        with ledger.lock:
            if ledger.capacity_required:
                free = ledger.db.execute("PRAGMA freelist_count").fetchone()[0]
                page = ledger.db.execute("PRAGMA page_size").fetchone()[0]
                if free * page >= 64 * 1024:
                    ledger.health = {**ledger.health, "blocked_capacity_bytes": None}
                    write_health(ledger.health_path, ledger.health)
                    ledger.capacity_required = False
        self.compaction.advance()
        return True

    def diagnostics(self, *, error=None):
        elapsed = time.monotonic() - self.started
        indexed, total = self.index.head[0], self.ledger.head[1]
        metadata = self.index.latest_archive()
        archived = 0
        if metadata is not None:
            _, receipt, _ = self.index.archive_state(metadata["first_sequence"])
            archived = (
                metadata["last_sequence"] if receipt is not None else metadata["first_sequence"] - 1
            )
        completed = min(indexed, archived)
        native = max(0, indexed - self.initial_indexed)
        remaining = max(0, total - completed)
        flush_wait = (
            max(0, 30 - (time.monotonic() - self.last_archive))
            if indexed == total and 0 < remaining < self.page_events
            else 0
        )
        return dict(
            stage="forecast_history_retention",
            status="repair_required"
            if isinstance(error, (ValueError, sqlite3.DatabaseError))
            else "retrying"
            if error is not None
            else "migrating"
            if indexed < total
            else "buffering"
            if remaining
            else "current",
            completed=completed,
            total=total,
            indexed_events=indexed,
            archived_events=archived,
            elapsed_seconds=elapsed,
            eta_seconds=(
                flush_wait + remaining * elapsed / native if native and error is None else None
            ),
            planning_eta_seconds=[flush_wait + remaining / 6000, flush_wait + remaining / 500]
            if not native and remaining and error is None
            else None,
            eta_basis="withdrawn_retrying"
            if error is not None
            else "current_run_events_per_elapsed_second_including_publication"
            if native
            else "planning_500_to_6000_events_per_second_excludes_remote_retries",
            eta_scope="forecast_retention_only_not_cohort_completion",
            stalled_or_retrying=error is not None,
            error_type=None if error is None else type(error).__name__,
            compaction=dict(self.compaction.status),
            certification_authority=False,
        )

    def original(self, sequence):
        ledger = self.ledger
        row = ledger.db.execute("SELECT body FROM events WHERE sequence=?", (sequence,)).fetchone()
        if row is not None:
            return json.loads(row[0])
        cached = self.index.cached_original(sequence)
        if cached is not None:
            return json.loads(cached)
        metadata, _, _ = self.index.archive_for(sequence)
        segment = self.segments.read(metadata["first_sequence"])
        body = segment.rows[sequence - segment.first_sequence][3]
        self.index.cache_original(sequence, body)
        return json.loads(body)

    def append(self, identity, scope, kind, values):
        ledger = self.ledger
        self.ensure_ready()
        with ledger.lock, self.index.lock:
            old = self.index.db.execute(
                "SELECT sequence,scope,kind FROM identities WHERE identity=?", (identity,)
            ).fetchone()
            if old is not None:
                if old[1:] != (scope, kind):
                    raise ValueError("forecast event identity conflicts")
                return self.original(old[0])
            event = dict(
                values,
                schema="umi-forecast-event/1",
                identity=identity,
                scope=scope,
                kind=kind,
                certification_authority=False,
            )
            body = encode_forecast_json(event)
            if len(body) > 16 * 1024:
                raise ValueError("forecast event exceeds its selected capacity")
            summary = self.index.summary(scope) or ForecastSummary()
            summary.prepare(event)
            checksum = hashlib.sha256(ledger.head[0].encode() + body).hexdigest()
            row = (ledger.head[1] + 1, identity, scope, body, ledger.head[0], checksum)
            original_committed = False
            try:
                with ledger.db:
                    current = ledger.db.execute("SELECT digest,sequence FROM head").fetchall()
                    if current != [ledger.head]:
                        raise ValueError("forecast original changed outside its owner")
                    ledger.db.execute("INSERT INTO events VALUES(?,?,?,?,?,?)", row)
                    ledger.db.execute("UPDATE head SET digest=?,sequence=?", (checksum, row[0]))
                original_committed = True
                ledger.head = checksum, row[0]
                self.index.accept(row)
            except BaseException as error:
                if isinstance(error, sqlite3.OperationalError) and (
                    getattr(error, "sqlite_errorcode", None) == 13
                    or error.args == ("database or disk is full",)
                ):
                    if original_committed:
                        ledger.note_failure("retained_index_capacity_exhausted", error=error)
                    else:
                        ledger.capacity_required = True
                        ledger.note_failure(
                            "capacity_exhausted", error=error, capacity_bytes=ledger.maximum_bytes
                        )
                else:
                    ledger.note_failure("unretained_observation", error=error)
                raise
            return event

    def rows(self, scope, *, after_sequence=0, limit=1000):
        self.ensure_ready()
        with self.index.lock:
            selected = self.index.db.execute(
                "SELECT sequence,identity,previous,digest FROM identities "
                "WHERE scope=? AND sequence>? ORDER BY sequence LIMIT ?",
                (scope, after_sequence, limit),
            ).fetchall()
        cache = {}
        result = []
        for sequence, identity, previous, checksum in selected:
            row = self.ledger.db.execute(
                "SELECT body FROM events WHERE sequence=?", (sequence,)
            ).fetchone()
            if row is None:
                metadata, _, _ = self.index.archive_for(sequence)
                first = metadata["first_sequence"]
                if first not in cache:
                    cache[first] = self.segments.read(first)
                body = cache[first].rows[sequence - first][3]
            else:
                body = row[0]
            result.append((sequence, identity, scope, body, previous, checksum))
        return result
