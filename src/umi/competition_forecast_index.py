"""Durable compact forecast summaries and original-event identities.

Archive segments own the full original history. At most 512 original events
remain cached for exact retries. Indexed deadline multiplicities avoid growing
Python heaps. Restart and ordinary status queries use only retained metadata.
"""

import hashlib
import json
import os
import re
import sqlite3
from collections import Counter
from pathlib import Path
from threading import RLock

from .competition_forecast_archive import ForecastSegment, encode_segment
from .competition_forecast_io import encode_forecast_json
from .competition_forecast_summary import ForecastSummary
from .private_files import _write_private_bytes, ensure_private_directory, lock_private_file

_ZERO = "0" * 64
_SCHEMA = "umi-forecast-summary-index/1"
_SUMMARY_FIELDS = set(ForecastSummary.__dataclass_fields__) - {"pending", "expired"}


class ForecastIndex:
    def __init__(self, root, ledger_sha256, *, maximum_bytes=512 * 1024**2):
        if type(ledger_sha256) is not str or re.fullmatch(r"[0-9a-f]{64}", ledger_sha256) is None:
            raise ValueError("forecast index owner identity is invalid")
        if type(maximum_bytes) is not int or not 64 * 1024 <= maximum_bytes <= 1024**3:
            raise ValueError("forecast index requires a bounded metadata budget")
        self.maximum_bytes = maximum_bytes
        self.root = Path(root)
        self.ledger_sha256 = ledger_sha256
        existing_root = self.root.exists()
        ensure_private_directory(self.root)
        self.lock = RLock()
        self.owner = lock_private_file(self.root / "owner.lock")
        self.db = None
        path, binding = self.root / "index.sqlite3", self.root / "binding.json"
        expected = encode_forecast_json(dict(schema=_SCHEMA, ledger_sha256=ledger_sha256))
        try:
            existing = binding.exists()
            if (
                path.is_symlink()
                or binding.is_symlink()
                or (existing != path.exists())
                or (existing_root and not existing)
            ):
                raise ValueError("forecast index files require explicit repair")
            if existing and (
                binding.stat().st_size != len(expected) or binding.read_bytes() != expected
            ):
                raise ValueError("forecast index owner binding changed")
            self.db = sqlite3.connect(path, timeout=1, check_same_thread=False)
            os.chmod(path, 0o600)
            self.db.execute("PRAGMA synchronous=FULL")
            self.db.execute("PRAGMA journal_mode=DELETE")
            size = self.db.execute("PRAGMA page_size").fetchone()[0]
            if path.stat().st_size > maximum_bytes:
                raise ValueError("forecast index exceeds its metadata budget")
            self.db.execute(f"PRAGMA max_page_count={maximum_bytes // size}")
            if not existing:
                with self.db:
                    self.db.execute("CREATE TABLE head (sequence INTEGER, digest TEXT)")
                    self.db.execute("INSERT INTO head VALUES(0,?)", (_ZERO,))
                    self.db.execute(
                        "CREATE TABLE identities (sequence INTEGER PRIMARY KEY, "
                        "identity TEXT UNIQUE, scope TEXT NOT NULL, kind TEXT NOT NULL, "
                        "previous TEXT NOT NULL, digest TEXT NOT NULL)"
                    )
                    self.db.execute(
                        "CREATE TABLE summaries (scope TEXT PRIMARY KEY, "
                        "body BLOB NOT NULL, digest TEXT NOT NULL)"
                    )
                    self.db.execute("CREATE INDEX identity_scope ON identities(scope,sequence)")
                    self.db.execute(
                        "CREATE TABLE deadlines (scope TEXT, finish INTEGER, "
                        "count INTEGER NOT NULL, "
                        "PRIMARY KEY(scope,finish))"
                    )
                    self.db.execute(
                        "CREATE TABLE archives (first_sequence INTEGER PRIMARY KEY, "
                        "last_sequence INTEGER NOT NULL, metadata BLOB NOT NULL, "
                        "body BLOB, receipt BLOB, released INTEGER NOT NULL DEFAULT 0)"
                    )
                    self.db.execute(
                        "CREATE TABLE originals (sequence INTEGER PRIMARY KEY, body BLOB NOT NULL, "
                        "used INTEGER NOT NULL)"
                    )
                    self.db.execute("CREATE INDEX original_recency ON originals(used)")
                    self.db.execute("PRAGMA user_version=1")
                _write_private_bytes(binding, expected)
            if self.db.execute("PRAGMA user_version").fetchone() != (1,):
                raise ValueError("forecast index schema requires explicit repair")
            heads = self.db.execute("SELECT sequence,digest FROM head").fetchall()
            latest = self.db.execute(
                "SELECT sequence,digest FROM identities ORDER BY sequence DESC LIMIT 1"
            ).fetchone() or (0, _ZERO)
            count = self.db.execute("SELECT COUNT(*) FROM identities").fetchone()[0]
            if heads != [latest] or count != latest[0]:
                raise ValueError("forecast index checkpoint requires explicit repair")
            self.head = latest
            previous, checksum, pending = 0, _ZERO, False
            for (first,) in self.db.execute(
                "SELECT first_sequence FROM archives ORDER BY first_sequence"
            ):
                metadata, _, released = self.archive_state(first)
                if pending or first != previous + 1 or metadata["previous_sha256"] != checksum:
                    raise ValueError("forecast archive chain requires explicit repair")
                previous, checksum, pending = (
                    metadata["last_sequence"],
                    metadata["last_sha256"],
                    not released,
                )
        except BaseException:
            self.close()
            raise

    def close(self):
        with self.lock:
            if self.db is not None:
                self.db.close()
                self.db = None
            if self.owner is not None:
                os.close(self.owner)
                self.owner = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def summary(self, scope):
        with self.lock:
            row = self.db.execute(
                "SELECT body,digest FROM summaries WHERE scope=?", (scope,)
            ).fetchone()
            if row is None:
                if self.db.execute(
                    "SELECT 1 FROM identities WHERE scope=? LIMIT 1", (scope,)
                ).fetchone():
                    raise ValueError("forecast summary is missing; explicit repair required")
                return None
            body, checksum = row
            if len(body) > 16 * 1024 or hashlib.sha256(body).hexdigest() != checksum:
                raise ValueError("retained forecast summary requires explicit repair")
            value = json.loads(body)
            if set(value) != _SUMMARY_FIELDS or encode_forecast_json(value) != body:
                raise ValueError("retained forecast summary schema requires explicit repair")
            if value["completion_range"] is not None:
                value["completion_range"] = tuple(value["completion_range"])
            for name in ("first_point", "first_range"):
                if value[name] is not None:
                    value[name]["predicted_range_unix_ms"] = tuple(
                        value[name]["predicted_range_unix_ms"]
                    )
            return ForecastSummary(**value)

    def accept(self, row):
        """Verify and checkpoint one original row, or reuse its retained identity."""
        return self.accept_many((row,))[0]

    def accept_segment(self, segment):
        """Reuse the immutable segment's first-pass verification while indexing."""
        if type(segment) is not ForecastSegment or segment.ledger_sha256 != self.ledger_sha256:
            raise ValueError("forecast segment belongs to another index")
        segment.checked()
        return self._accept_page(segment.rows, segment._validated_events)

    def accept_many(self, rows):
        """Commit a bounded migration page; interrupted pages remain unfinished.

        Every event's identity and summary share the transaction with its head.
        Successful pages survive restart without re-reading their payloads.
        """
        if type(rows) not in {tuple, list} or not 1 <= len(rows) <= 4096:
            raise ValueError("forecast index page exceeds its event bound")
        if sum(len(row[3]) for row in rows if type(row[3]) is bytes) > 8 * 1024**2:
            raise ValueError("forecast index page exceeds its payload bound")
        return self._accept_page(rows)

    def _accept_page(self, rows, events=None):
        with self.lock:
            previous_head = self.head
            try:
                with self.db:
                    return self._accept_rows(rows, events)
            except BaseException:
                self.head = previous_head
                raise

    def _insert_rows(self, statement, rows, *, suffix=""):
        # Stay below SQLite's historical 999-variable limit. One SQL statement
        # per bounded group avoids a GIL handoff for every small row operation.
        for start in range(0, len(rows), 128):
            page = rows[start : start + 128]
            placeholders = "(" + ",".join("?" for _ in page[0]) + ")"
            self.db.execute(
                statement + ",".join(placeholders for _ in page) + suffix,
                tuple(value for row in page for value in row),
            )

    def _accept_rows(self, rows, events=None):
        """Prepare one bounded page, then persist it in the caller's transaction."""
        head = self.head
        retained = {}
        sequences = sorted(
            {row[0] for row in rows if type(row[0]) is int and 0 < row[0] <= head[0]}
        )
        for start in range(0, len(sequences), 128):
            page = sequences[start : start + 128]
            retained.update(
                (row[0], row[1:])
                for row in self.db.execute(
                    "SELECT sequence,identity,scope,previous,digest FROM identities "
                    "WHERE sequence IN (" + ",".join("?" for _ in page) + ")",
                    page,
                )
            )
        summaries, identities, originals, accepted = {}, [], [], []
        for position, row in enumerate(rows):
            sequence, identity, scope, body, previous, checksum = row
            if type(sequence) is not int or sequence < 1:
                raise ValueError("forecast index input sequence is invalid")
            if sequence <= head[0]:
                if retained.get(sequence) != (identity, scope, previous, checksum):
                    raise ValueError("completed forecast index entry changed or is missing")
                accepted.append(False)
                continue
            event = None if events is None else events[position]
            if (
                sequence != head[0] + 1
                or previous != head[1]
                or type(body) is not bytes
                or not 0 < len(body) <= 16 * 1024
                or (
                    event is None
                    and hashlib.sha256(previous.encode() + body).hexdigest() != checksum
                )
            ):
                raise ValueError("forecast index input chain is damaged")
            if event is None:
                event = json.loads(body)
                if (
                    encode_forecast_json(event) != body
                    or event.get("schema") != "umi-forecast-event/1"
                    or (event.get("identity"), event.get("scope")) != (identity, scope)
                    or event.get("certification_authority") is not False
                ):
                    raise ValueError("forecast index input identity is damaged")
            if scope not in summaries:
                summaries[scope] = self.summary(scope) or ForecastSummary()
            summaries[scope].accept(event, sequence=sequence)
            identities.append((sequence, identity, scope, event["kind"], previous, checksum))
            retained[sequence] = identity, scope, previous, checksum
            if event["kind"] != "forecast":
                originals.append((sequence, body))
            head = sequence, checksum
            accepted.append(True)

        encoded_summaries, deadlines = [], []
        for scope, summary in summaries.items():
            value = {key: getattr(summary, key) for key in _SUMMARY_FIELDS}
            encoded = encode_forecast_json(value)
            if len(encoded) > 16 * 1024:
                raise ValueError("forecast summary exceeds its metadata bound")
            encoded_summaries.append((scope, encoded, hashlib.sha256(encoded).hexdigest()))
            deadlines.extend(
                (scope, finish, count) for finish, count in Counter(summary.pending).items()
            )
        self._insert_rows("INSERT INTO identities VALUES", identities)
        self._insert_rows(
            "INSERT INTO summaries VALUES",
            encoded_summaries,
            suffix=" ON CONFLICT(scope) DO UPDATE SET body=excluded.body,digest=excluded.digest",
        )
        self._insert_rows(
            "INSERT INTO deadlines VALUES",
            deadlines,
            suffix=" ON CONFLICT(scope,finish) DO UPDATE SET count=count+excluded.count",
        )
        if originals:
            used = self.db.execute("SELECT COALESCE(MAX(used),0) FROM originals").fetchone()[0]
            self._insert_rows(
                "INSERT INTO originals VALUES",
                [
                    (sequence, body, used + offset)
                    for offset, (sequence, body) in enumerate(originals, 1)
                ][-512:],
            )
            self.db.execute(
                "DELETE FROM originals WHERE sequence IN (SELECT sequence FROM originals "
                "ORDER BY used DESC LIMIT -1 OFFSET 512)"
            )
        if identities:
            self.db.execute("UPDATE head SET sequence=?,digest=?", head)
        self.head = head
        return accepted

    def _cache_original(self, sequence, body):
        used = self.db.execute("SELECT COALESCE(MAX(used),0)+1 FROM originals").fetchone()[0]
        self.db.execute(
            "INSERT INTO originals VALUES(?,?,?) ON CONFLICT(sequence) "
            "DO UPDATE SET body=excluded.body,used=excluded.used",
            (sequence, body, used),
        )
        self.db.execute(
            "DELETE FROM originals WHERE sequence=(SELECT sequence FROM originals "
            "ORDER BY used LIMIT 1) AND (SELECT COUNT(*) FROM originals)>512"
        )

    def cached_original(self, sequence):
        with self.lock, self.db:
            row = self.db.execute(
                "SELECT o.body,i.previous,i.digest FROM originals o "
                "JOIN identities i ON i.sequence=o.sequence WHERE o.sequence=?",
                (sequence,),
            ).fetchone()
            if row is None:
                return None
            body, previous, checksum = row
            if (
                len(body) > 16 * 1024
                or hashlib.sha256(previous.encode() + body).hexdigest() != checksum
            ):
                raise ValueError("cached forecast original damaged; explicit repair required")
            used = self.db.execute("SELECT COALESCE(MAX(used),0)+1 FROM originals").fetchone()[0]
            self.db.execute("UPDATE originals SET used=? WHERE sequence=?", (used, sequence))
            return body

    def cache_original(self, sequence, body):
        with self.lock, self.db:
            row = self.db.execute(
                "SELECT previous,digest,kind FROM identities WHERE sequence=?", (sequence,)
            ).fetchone()
            if (
                row is None
                or len(body) > 16 * 1024
                or hashlib.sha256(row[0].encode() + body).hexdigest() != row[1]
            ):
                raise ValueError("restored forecast original differs from its retained identity")
            if row[2] != "forecast":
                self._cache_original(sequence, body)

    def latest_archive(self):
        with self.lock:
            row = self.db.execute(
                "SELECT first_sequence FROM archives ORDER BY first_sequence DESC LIMIT 1"
            ).fetchone()
            return None if row is None else self.archive_state(row[0])[0]

    def stage_archive(self, segment):
        """Commit original segment bytes, verified identities and summaries together."""
        if type(segment) is not ForecastSegment or segment.ledger_sha256 != self.ledger_sha256:
            raise ValueError("forecast segment belongs to another index")
        with self.lock:
            old = self.db.execute(
                "SELECT metadata FROM archives WHERE first_sequence=?", (segment.first_sequence,)
            ).fetchone()
            binding = dict(
                ledger_sha256=segment.ledger_sha256,
                first_sequence=segment.first_sequence,
                last_sequence=segment.last_sequence,
                previous_sha256=segment.previous_sha256,
                last_sha256=segment.last_sha256,
            )
            if old is not None:
                metadata = json.loads(old[0])
                if any(metadata[key] != value for key, value in binding.items()):
                    raise ValueError("retained forecast segment binding conflicts")
                return metadata
            latest = self.latest_archive()
            expected = (
                (1, _ZERO)
                if latest is None
                else (latest["last_sequence"] + 1, latest["last_sha256"])
            )
            if (segment.first_sequence, segment.previous_sha256) != expected:
                raise ValueError("forecast archives must retain a contiguous original chain")
            if latest is not None and self.archive_state(latest["first_sequence"])[2] is False:
                raise ValueError("publish and release the pending forecast segment first")
            segment.checked()
            raw = encode_segment(segment)
            metadata = dict(
                binding,
                sha256=hashlib.sha256(raw).hexdigest(),
                bytes=len(raw),
                remote_path=segment.key,
            )
            previous_head = self.head
            try:
                with self.db:
                    self._accept_rows(segment.rows, segment._validated_events)
                    self.db.execute(
                        "INSERT INTO archives(first_sequence,last_sequence,metadata,body) "
                        "VALUES(?,?,?,?)",
                        (
                            segment.first_sequence,
                            segment.last_sequence,
                            encode_forecast_json(metadata),
                            raw,
                        ),
                    )
            except BaseException:
                self.head = previous_head
                raise
            return metadata

    def archive_state(self, first_sequence):
        with self.lock:
            row = self.db.execute(
                "SELECT metadata,receipt,released,last_sequence,body IS NOT NULL "
                "FROM archives WHERE first_sequence=?",
                (first_sequence,),
            ).fetchone()
            if row is None:
                raise ValueError("forecast archive metadata missing; explicit repair required")
            raw, reference, released, last, has_body = row
            try:
                metadata = json.loads(raw)
                receipt = None if reference is None else json.loads(reference)
                valid = (
                    type(first_sequence) is int
                    and type(last) is int
                    and 1 <= first_sequence <= last <= self.head[0]
                    and last - first_sequence < 4096
                    and released in (0, 1)
                    and isinstance(metadata, dict)
                    and metadata["ledger_sha256"] == self.ledger_sha256
                    and metadata["first_sequence"] == first_sequence
                    and metadata["last_sequence"] == last
                    and type(metadata["bytes"]) is int
                    and 0 < metadata["bytes"] <= 8 * 1024**2
                    and all(
                        type(metadata[key]) is str and re.fullmatch(r"[0-9a-f]{64}", metadata[key])
                        for key in ("sha256", "previous_sha256", "last_sha256")
                    )
                    and metadata["remote_path"]
                    == (
                        f"forecasts/{self.ledger_sha256}/{first_sequence:016x}-"
                        f"{last:016x}-{metadata['last_sha256']}"
                    )
                    and self.db.execute(
                        "SELECT previous FROM identities WHERE sequence=?", (first_sequence,)
                    ).fetchone()
                    == (metadata["previous_sha256"],)
                    and self.db.execute(
                        "SELECT digest FROM identities WHERE sequence=?", (last,)
                    ).fetchone()
                    == (metadata["last_sha256"],)
                    and (not released or (receipt is not None and not has_body))
                    and (receipt is not None or has_body)
                    and (
                        receipt is None
                        or (
                            receipt["content_sha256"] == metadata["sha256"]
                            and receipt["size_bytes"] == metadata["bytes"]
                        )
                    )
                )
            except (ValueError, TypeError, KeyError):
                valid = False
            if not valid:
                raise ValueError("forecast archive checkpoint requires explicit repair")
            return metadata, receipt, bool(released)

    def archive_body(self, first_sequence):
        with self.lock:
            row = self.db.execute(
                "SELECT body FROM archives WHERE first_sequence=?", (first_sequence,)
            ).fetchone()
            if row is None or row[0] is None:
                raise ValueError("forecast staged archive missing; explicit repair required")
            return row[0]

    def retain_archive_receipt(self, first_sequence, receipt):
        with self.lock, self.db:
            metadata, previous, _ = self.archive_state(first_sequence)
            if (receipt["content_sha256"], receipt["size_bytes"]) != (
                metadata["sha256"],
                metadata["bytes"],
            ) or (previous is not None and previous != receipt):
                raise ValueError("forecast publication differs from its retained segment")
            self.db.execute(
                "UPDATE archives SET receipt=? WHERE first_sequence=?",
                (encode_forecast_json(receipt), first_sequence),
            )

    def release_archive(self, first_sequence):
        with self.lock, self.db:
            _, receipt, _ = self.archive_state(first_sequence)
            if receipt is None:
                raise ValueError("forecast segment has no completed durable publication")
            self.db.execute(
                "UPDATE archives SET body=NULL,released=1 WHERE first_sequence=?", (first_sequence,)
            )

    def archive_for(self, sequence):
        with self.lock:
            row = self.db.execute(
                "SELECT first_sequence,last_sequence FROM archives WHERE first_sequence<=? "
                "ORDER BY first_sequence DESC LIMIT 1",
                (sequence,),
            ).fetchone()
            if row is None or sequence > row[1]:
                raise ValueError("forecast original is missing; explicit repair required")
            return self.archive_state(row[0])

    def status(self, scope, now):
        with self.lock:
            summary = self.summary(scope)
            if summary is None:
                raise ValueError("forecast scope has no retained summary")
            value = summary.status(scope, now)
            terminal = summary.completion_range[0] if summary.completion_range is not None else now
            missed = self.db.execute(
                "SELECT COALESCE(SUM(count),0) FROM deadlines WHERE scope=? AND finish<?",
                (scope, terminal),
            ).fetchone()[0]
            count = self.db.execute(
                "SELECT COALESCE(SUM(count),0) FROM deadlines WHERE scope=?", (scope,)
            ).fetchone()[0]
            if count != summary.forecasts:
                raise ValueError("forecast deadline index requires explicit repair")
            if not value["clock_regression"]:
                value["missed_forecasts"] = missed if summary.completed is not None else 0
                value["overdue_unfinished_forecasts"] = missed if summary.completed is None else 0
            return value
