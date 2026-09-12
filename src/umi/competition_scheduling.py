"""Local, weight-disabled publication scheduling with one dispatch per assignment.

Callers supply concrete blocks from their process-owned finality verifier. This
module checks those attestations and their pinned chain identity; it does not
replay an offline finality proof or accept an operator JSON finality claim.
The journal's first-observation time is local evidence. Independent publication
timing, chain-announced serving origin and protected-suite release remain gates.

A claim commits before transmission and is never issued twice. A crash after
claiming leaves uncertain work, even when no request reached the miner. Expired
assignments remain recorded without attributing a failure to the miner.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import sqlite3
import stat
import time
from collections import Counter, defaultdict
from contextlib import contextmanager
from dataclasses import asdict, dataclass, replace
from pathlib import Path

from .competition_authorization import (
    EndpointAssignment,
    SignedEndpointAuthorization,
    validate_publication,
)
from .config import Limits
from .open_competition import CompetitionPolicy, digest, identity
from .policy import (
    LiveChainObservationPin,
    ScoringPolicy,
    require_live_chain_observation,
    scoring_policy_hash,
)
from .protocol import canonical_json_bytes, request_digest
from .validator_plans import VerifiedFinalizedBlock
from .window import QUICKNET_GENESIS_MS, QUICKNET_PERIOD_MS, WindowClock

_APPLICATION_ID = 0x554D4953
_SCHEMA = "umi-assignment-publication-journal/1"
_EVENT_RESERVE_BYTES = 8192


def assignment_key(publication, assignment: EndpointAssignment) -> str:
    """Stable across attempted wire retiming or publication re-signing."""
    body = publication.publication
    return hashlib.sha256(
        b"umi-scheduled-endpoint-assignment-v1\0"
        + canonical_json_bytes(
            [
                body.policy_sha256,
                digest(body.round),
                assignment.submission_sha256,
                identity(assignment.evaluator_hotkey),
                assignment.case_sha256,
            ]
        )
    ).hexdigest()


@dataclass(frozen=True, slots=True)
class AssignmentClaim:
    assignment_key: str
    claim_id: str
    publication_sha256: str
    assignment: EndpointAssignment
    miner_hotkey: str
    serving_origin: str
    no_weight: bool = True


def _clock(policy):
    return WindowClock(
        activation_block=policy.activation_block,
        **{
            name: getattr(policy.clock, name)
            for name in (
                "window_stride_blocks",
                "proposal_blocks",
                "anchor_blocks",
                "target_block_interval_seconds",
                "selection_finality_buffer_seconds",
                "issue_allowance_seconds",
                "response_window_seconds",
                "delivery_grace_seconds",
                "reveal_margin_seconds",
            )
        },
    )


def _round_ms(round_: int) -> int:
    return QUICKNET_GENESIS_MS + (round_ - 1) * QUICKNET_PERIOD_MS


def _private_directory(directory: Path) -> None:
    if (
        not isinstance(directory, Path)
        or not directory.is_absolute()
        or directory == Path(directory.anchor)
        or any(part.is_symlink() for part in (directory, *directory.parents))
    ):
        raise ValueError("scheduling journal requires a dedicated absolute nonsymlink directory")
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = directory.stat()
    if info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError("scheduling directory must be owned by this user and mode 0700")


class AssignmentPublicationJournal:
    """Private append-only evidence with bounded logical capacity.

    Capacity reserves each assignment's outcome and events before publication.
    SQLite/filesystem overhead is outside that logical bound. There is no
    eviction, retiming, retry release or external assignment-discovery service.
    """

    def __init__(
        self,
        directory: Path,
        policy: CompetitionPolicy,
        legacy_policy: ScoringPolicy,
        *,
        maximum_publications: int = 1024,
        maximum_assignments: int = 16384,
        maximum_bytes: int = 1024**3,
        maximum_outcome_bytes: int = 1024**2,
        maximum_observation_age_seconds: int = 60,
        maximum_future_skew_seconds: int = 5,
    ):
        self.policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
        self.legacy_policy = ScoringPolicy.model_validate_json(canonical_json_bytes(legacy_policy))
        for value, lower, upper in (
            (maximum_publications, 1, 65536),
            (maximum_assignments, 1, 262144),
            (maximum_bytes, 1024, 16 * 1024**3),
            (maximum_outcome_bytes, 1, 16 * 1024**2),
            (maximum_observation_age_seconds, 1, 600),
            (maximum_future_skew_seconds, 0, 30),
        ):
            if type(value) is not int or not lower <= value <= upper:
                raise ValueError("invalid scheduling capacity or freshness bound")
        self.maximum_publications = maximum_publications
        self.maximum_assignments = maximum_assignments
        self.maximum_bytes = maximum_bytes
        self.maximum_outcome_bytes = maximum_outcome_bytes
        self.maximum_observation_age_seconds = maximum_observation_age_seconds
        self.maximum_future_skew_seconds = maximum_future_skew_seconds
        pins = self.legacy_policy.implementation_pins
        if (
            pins.pin_profile != "live_shadow_calibration"
            or pins.live_chain is None
            or pins.finality_verifier is None
        ):
            raise ValueError("scheduling requires the actual legacy chain and finality pins")
        self._clock = _clock(self.legacy_policy)
        _private_directory(directory)
        self.path = directory / "scheduling.sqlite3"
        for suffix in ("", "-journal", "-wal", "-shm"):
            path = Path(str(self.path) + suffix)
            if path.is_symlink():
                raise ValueError("scheduling database must not be a symlink")
            if path.exists():
                info = path.stat()
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_nlink != 1
                    or info.st_uid != os.getuid()
                    or info.st_mode & 0o077
                ):
                    raise ValueError("scheduling database must be a private regular file")
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        with self._transaction() as db:
            application_id = db.execute("PRAGMA application_id").fetchone()[0]
            tables = db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
            if application_id != _APPLICATION_ID:
                if application_id or tables:
                    raise ValueError("unrecognized scheduling database")
                self._initialize(db)
            if db.execute("PRAGMA user_version").fetchone()[0] != 1:
                raise ValueError("unsupported scheduling schema")
            metadata = dict(db.execute("SELECT key,value FROM metadata"))
            if any(
                metadata.get(key) != value
                for key, value in {
                    "schema": _SCHEMA,
                    "policy": digest(self.policy),
                    "legacy_policy": scoring_policy_hash(self.legacy_policy),
                    "maximum_outcome_bytes": str(maximum_outcome_bytes),
                }.items()
            ):
                raise ValueError("scheduling journal schema, policy or outcome capacity mismatch")
            if db.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                raise ValueError("scheduling database is corrupt")
            self._capacity(db)

    @contextmanager
    def _transaction(self):
        db = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        db.row_factory = sqlite3.Row
        try:
            db.execute("PRAGMA synchronous=FULL")
            db.execute("PRAGMA foreign_keys=ON")
            db.execute("BEGIN IMMEDIATE")
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def _initialize(self, db):
        db.execute(f"PRAGMA application_id={_APPLICATION_ID}")
        db.execute("PRAGMA user_version=1")
        db.execute("CREATE TABLE metadata (key TEXT PRIMARY KEY,value TEXT NOT NULL)")
        db.executemany(
            "INSERT INTO metadata VALUES (?,?)",
            {
                "schema": _SCHEMA,
                "policy": digest(self.policy),
                "legacy_policy": scoring_policy_hash(self.legacy_policy),
                "maximum_outcome_bytes": str(self.maximum_outcome_bytes),
            }.items(),
        )
        db.execute(
            "CREATE TABLE blocks (height INTEGER PRIMARY KEY,document BLOB NOT NULL,"
            "evidence BLOB NOT NULL)"
        )
        db.execute("CREATE TABLE rounds (sequence INTEGER PRIMARY KEY,sha256 TEXT NOT NULL)")
        db.execute(
            "CREATE TABLE publications (id TEXT PRIMARY KEY,signed BLOB NOT NULL,"
            "observed_height INTEGER NOT NULL REFERENCES blocks(height),"
            "observed_ms INTEGER NOT NULL,reserved INTEGER NOT NULL)"
        )
        db.execute(
            "CREATE TABLE assignments (id TEXT PRIMARY KEY,publication_id TEXT NOT NULL "
            "REFERENCES publications(id),body BLOB NOT NULL,announcement INTEGER NOT NULL "
            "REFERENCES blocks(height),window_index INTEGER NOT NULL,selection_ms INTEGER NOT NULL,"
            "issue_close_ms INTEGER NOT NULL,issued_block INTEGER NOT NULL,"
            "deadline_block INTEGER NOT NULL,miner TEXT NOT NULL,evaluator TEXT NOT NULL)"
        )
        db.execute(
            "CREATE TABLE events (ordinal INTEGER PRIMARY KEY,assignment_id TEXT NOT NULL "
            "REFERENCES assignments(id),kind TEXT NOT NULL "
            "CHECK(kind IN ('published','expired','dispatched','completed')),"
            "observed_height INTEGER NOT NULL "
            "REFERENCES blocks(height),observed_ms INTEGER NOT NULL,body BLOB NOT NULL,"
            "evidence BLOB NOT NULL,UNIQUE(assignment_id,kind))"
        )
        db.execute("CREATE INDEX assignment_miner ON assignments(miner,id)")
        db.execute("CREATE INDEX assignment_expiry ON assignments(issue_close_ms)")
        db.execute("CREATE INDEX assignment_issuance ON assignments(issued_block)")
        db.execute("CREATE INDEX assignment_events ON events(assignment_id,ordinal)")
        for table in ("blocks", "rounds", "publications", "assignments", "events"):
            for operation in ("UPDATE", "DELETE"):
                db.execute(
                    f"CREATE TRIGGER immutable_{table}_{operation.lower()} BEFORE {operation} "
                    f"ON {table} BEGIN SELECT RAISE(ABORT,'append-only scheduling evidence'); END"
                )

    def _capacity(self, db, *, publications=0, assignments=0, reserved=0):
        count, used = db.execute(
            "SELECT COUNT(*),COALESCE(SUM(reserved),0) FROM publications"
        ).fetchone()
        block_bytes = db.execute(
            "SELECT COALESCE(SUM(LENGTH(document)+LENGTH(evidence)),0) FROM blocks"
        ).fetchone()[0]
        assignment_count = db.execute("SELECT COUNT(*) FROM assignments").fetchone()[0]
        if (
            count + publications > self.maximum_publications
            or assignment_count + assignments > self.maximum_assignments
            or used + block_bytes + reserved > self.maximum_bytes
        ):
            raise ValueError("scheduling capacity exhausted; retain history and provision capacity")

    def _block(self, block: VerifiedFinalizedBlock) -> VerifiedFinalizedBlock:
        if not isinstance(block, VerifiedFinalizedBlock):
            raise TypeError("scheduling requires concrete process-owned verified blocks")
        block = replace(
            block,
            chain_observation=LiveChainObservationPin.model_validate_json(
                canonical_json_bytes(block.chain_observation)
            ),
        )
        if block.scoring_policy_hash != scoring_policy_hash(self.legacy_policy):
            raise ValueError("scheduling block transport policy mismatch")
        try:
            require_live_chain_observation(self.legacy_policy, block.chain_observation)
        except (TypeError, RuntimeError) as error:
            raise ValueError("scheduling verified block chain mismatch") from error
        pin = self.legacy_policy.implementation_pins.finality_verifier
        if block.finality_verifier_sha256 not in pin.release_sha256_by_target.values():
            raise ValueError("scheduling finality verifier mismatch")
        return block

    @staticmethod
    def _block_document(block):
        fields = asdict(block)
        fields.pop("finality_evidence")
        fields["chain_observation"] = block.chain_observation.model_dump(mode="json", by_alias=True)
        return canonical_json_bytes(fields)

    def _retain_block(self, db, block):
        document = self._block_document(block)
        existing = db.execute(
            "SELECT document,evidence FROM blocks WHERE height=?", (block.height,)
        ).fetchone()
        if existing:
            if (
                bytes(existing["document"]) != document
                or bytes(existing["evidence"]) != block.finality_evidence
            ):
                raise ValueError("verified block changed at a retained height")
            return
        self._capacity(db, reserved=len(document) + len(block.finality_evidence))
        db.execute(
            "INSERT INTO blocks VALUES (?,?,?)", (block.height, document, block.finality_evidence)
        )

    def _retained_block(self, db, height):
        row = db.execute("SELECT * FROM blocks WHERE height=?", (height,)).fetchone()
        if row is None:
            raise ValueError("exact verified issuance or announcement is not retained")
        fields = json.loads(bytes(row["document"]))
        if canonical_json_bytes(fields) != bytes(row["document"]) or fields.get("height") != height:
            raise ValueError("corrupt retained scheduling block")
        fields["chain_observation"] = LiveChainObservationPin.model_validate(
            fields["chain_observation"]
        )
        return self._block(
            VerifiedFinalizedBlock(**fields, finality_evidence=bytes(row["evidence"]))
        )

    def _observation(self, db, observed):
        observed = self._block(observed)
        now = time.time_ns() // 1_000_000
        if type(now) is not int or not QUICKNET_GENESIS_MS <= now <= 2**53 - 1:
            raise ValueError("invalid local observation time")
        if not (
            now - self.maximum_observation_age_seconds * 1000
            <= observed.timestamp_ms
            <= now + self.maximum_future_skew_seconds * 1000
        ):
            raise ValueError("verified observation is stale or from the future")
        highwater = dict(db.execute("SELECT key,value FROM metadata"))
        if now < int(highwater.get("last_observed_ms", "0")) or observed.height < int(
            highwater.get("last_observed_height", "0")
        ):
            raise ValueError("scheduling observation rolled back")
        self._retain_block(db, observed)
        for key, value in (("last_observed_ms", now), ("last_observed_height", observed.height)):
            db.execute(
                "INSERT INTO metadata VALUES (?,?) ON CONFLICT(key) "
                "DO UPDATE SET value=excluded.value",
                (key, str(value)),
            )
        return observed, now

    @staticmethod
    def _event(db, key, kind, observed_height, now, body=None, evidence=b""):
        body = canonical_json_bytes(body or {})
        if len(body) > 2048:
            raise ValueError("scheduling event exceeds reserved capacity")
        db.execute(
            "INSERT INTO events (assignment_id,kind,observed_height,observed_ms,body,evidence) "
            "VALUES (?,?,?,?,?,?)",
            (key, kind, observed_height, now, body, evidence),
        )

    @staticmethod
    def _last(db, key):
        rows = db.execute(
            "SELECT * FROM events WHERE assignment_id=? ORDER BY ordinal", (key,)
        ).fetchall()
        if not rows:
            return None
        if tuple(row["kind"] for row in rows) not in {
            ("published",),
            ("expired",),
            ("published", "expired"),
            ("published", "dispatched"),
            ("published", "dispatched", "completed"),
        }:
            raise ValueError("corrupt scheduling event history")
        return rows[-1]

    def _schedule(self, assignment, announcement):
        request = assignment.request
        index = (
            request.issued_block - self.legacy_policy.activation_block
        ) // self.legacy_policy.clock.window_stride_blocks
        expected = (
            self.legacy_policy.activation_block
            + index * self.legacy_policy.clock.window_stride_blocks
        )
        if announcement.height != expected:
            raise ValueError("assignment announcement height mismatch")
        schedule = self._clock.derive(
            index,
            netuid=self.legacy_policy.netuid,
            announcement_block_hash=announcement.block_hash,
            announcement_timestamp_ms=announcement.timestamp_ms,
            scoring_policy_hash=scoring_policy_hash(self.legacy_policy),
        )
        if (
            request.issued_block <= schedule.closing_block
            or request.window_id != schedule.window_id
            or request.deadline_block != request.issued_block + schedule.response_deadline_blocks
            or request.response_close_round != schedule.response_close_round
            or request.reveal_round != schedule.reveal_round
        ):
            raise ValueError("assignment differs from verified legacy schedule")
        return schedule

    def _quotas(self, db, additions):
        counts, totals = Counter(), Counter()
        videos, total_videos = defaultdict(dict), defaultdict(dict)
        existing = [
            (
                row["miner"],
                row["evaluator"],
                row["window_index"],
                EndpointAssignment.model_validate_json(bytes(row["body"])),
            )
            for row in db.execute("SELECT * FROM assignments")
        ]
        for miner, evaluator, window, assignment in [*existing, *additions]:
            key, miner_key = (miner, evaluator, window), (miner, window)
            counts[key] += 1
            totals[miner_key] += 1
            video = assignment.request.video
            for bucket in (videos[key], total_videos[miner_key]):
                if video.sha256 in bucket and bucket[video.sha256] != video.size_bytes:
                    raise ValueError("same video digest has inconsistent byte size")
                bucket[video.sha256] = video.size_bytes
        limits = Limits.from_policy(self.legacy_policy)
        if (
            any(n > limits.maximum_assignments_per_validator_window for n in counts.values())
            or any(n > limits.maximum_total_assignments_per_window for n in totals.values())
            or any(
                len(v) > limits.maximum_unique_videos_per_validator_window
                or sum(v.values()) > limits.maximum_retained_video_bytes_per_validator_window
                for v in videos.values()
            )
            or any(
                len(v) > limits.maximum_unique_videos_per_window
                or sum(v.values()) > limits.maximum_retained_video_bytes
                for v in total_videos.values()
            )
        ):
            raise ValueError("aggregate scheduling assignments exceed legacy window quotas")

    def publish(
        self,
        publication: SignedEndpointAuthorization,
        *,
        observed: VerifiedFinalizedBlock,
        announcements: tuple[VerifiedFinalizedBlock, ...],
    ) -> dict:
        """Retain signed publication and mark already unusable cases as expired.

        Re-signing the same body keeps the exact first signed bytes and original
        observation. No duplicate invocation refreshes a publication's lifetime.
        """
        publication = validate_publication(publication, self.policy, self.legacy_policy)
        body, key = publication.publication, digest(publication.publication)
        raw = canonical_json_bytes(publication)
        with self._transaction() as db:
            existing = db.execute("SELECT signed FROM publications WHERE id=?", (key,)).fetchone()
            if existing:
                retained = SignedEndpointAuthorization.model_validate_json(bytes(existing[0]))
                if canonical_json_bytes(retained.publication) != canonical_json_bytes(body):
                    raise ValueError("publication digest collision or corrupt retained bytes")
                self._expire_elapsed(db)
                return self._publication_status(db, key)
            if not isinstance(announcements, tuple) or not 1 <= len(announcements) <= len(
                body.assignments
            ):
                raise ValueError("publication requires a bounded tuple of verified announcements")
            blocks = {b.height: self._block(b) for b in announcements}
            if len(blocks) != len(announcements):
                raise ValueError("duplicate verified announcement heights")
            observed, now = self._observation(db, observed)
            round_sha = digest(body.round)
            prior_round = db.execute(
                "SELECT sha256 FROM rounds WHERE sequence=?", (body.round.sequence,)
            ).fetchone()
            if prior_round and prior_round[0] != round_sha:
                raise ValueError("round sequence already binds another immutable round")
            required = set()
            additions, rows = [], []
            submissions = {digest(s.submission): s.submission for s in body.submissions}
            for assignment in body.assignments:
                assignment_id = assignment_key(publication, assignment)
                if db.execute("SELECT 1 FROM assignments WHERE id=?", (assignment_id,)).fetchone():
                    raise ValueError(
                        "assignment identity already published; retiming or reuse refused"
                    )
                index = (
                    assignment.request.issued_block - self.legacy_policy.activation_block
                ) // self.legacy_policy.clock.window_stride_blocks
                height = (
                    self.legacy_policy.activation_block
                    + index * self.legacy_policy.clock.window_stride_blocks
                )
                required.add(height)
                if height not in blocks or height > observed.height:
                    raise ValueError("publication lacks an already finalized announcement")
                schedule = self._schedule(assignment, blocks[height])
                sub = submissions[assignment.submission_sha256]
                miner, evaluator = identity(sub.hotkey), identity(assignment.evaluator_hotkey)
                additions.append((miner, evaluator, index, assignment))
                rows.append(
                    (
                        assignment_id,
                        key,
                        canonical_json_bytes(assignment),
                        height,
                        index,
                        _round_ms(schedule.selection_round),
                        _round_ms(schedule.issue_close_round),
                        assignment.request.issued_block,
                        assignment.request.deadline_block,
                        miner,
                        evaluator,
                    )
                )
            if required != set(blocks):
                raise ValueError("publication includes unrelated verified announcements")
            self._quotas(db, additions)
            reserved = len(raw) + sum(
                len(row[2]) + self.maximum_outcome_bytes + _EVENT_RESERVE_BYTES for row in rows
            )
            for block in blocks.values():
                self._retain_block(db, block)
            self._capacity(db, publications=1, assignments=len(rows), reserved=reserved)
            db.execute(
                "INSERT OR IGNORE INTO rounds VALUES (?,?)", (body.round.sequence, round_sha)
            )
            db.execute(
                "INSERT INTO publications VALUES (?,?,?,?,?)",
                (key, raw, observed.height, now, reserved),
            )
            db.executemany("INSERT INTO assignments VALUES (?,?,?,?,?,?,?,?,?,?,?)", rows)
            for row, assignment in zip(rows, body.assignments, strict=True):
                expired = now >= row[6] or observed.height > assignment.request.deadline_block
                self._event(
                    db,
                    row[0],
                    "expired" if expired else "published",
                    observed.height,
                    now,
                    {
                        "reason": "publication_window_elapsed"
                        if expired
                        else "signed_publication_observed",
                        "miner_fault": False,
                    },
                )
            self._expire_elapsed(db)
            return self._publication_status(db, key)

    def observe(
        self,
        *,
        observed: VerifiedFinalizedBlock,
        issuances: tuple[VerifiedFinalizedBlock, ...] = (),
    ) -> dict:
        """Retain fresh verifier observations without claiming or dispatching work."""
        if not isinstance(issuances, tuple) or len(issuances) > 256:
            raise ValueError("scheduling observations require at most 256 exact issuances")
        with self._transaction() as db:
            observed, now = self._observation(db, observed)
            seen = set()
            for block in issuances:
                block = self._block(block)
                if (
                    block.height in seen
                    or block.height > observed.height
                    or block.timestamp_ms > observed.timestamp_ms
                ):
                    raise ValueError("duplicate or not-yet-finalized issuance observation")
                seen.add(block.height)
                rows = db.execute(
                    "SELECT * FROM assignments WHERE issued_block=?", (block.height,)
                ).fetchall()
                matches = False
                for row in rows:
                    assignment = EndpointAssignment.model_validate_json(bytes(row["body"]))
                    announcement = self._retained_block(db, row["announcement"])
                    schedule = self._schedule(assignment, announcement)
                    if assignment.request.issued_block_hash == block.block_hash and (
                        _round_ms(schedule.selection_round)
                        <= block.timestamp_ms
                        < _round_ms(schedule.issue_close_round)
                    ):
                        matches = True
                if not matches:
                    raise ValueError(
                        "issuance observation does not match an existing exact assignment"
                    )
                self._retain_block(db, block)
            self._expire_elapsed(db)
            return {
                "observed_finalized_height": observed.height,
                "observed_unix_ms": now,
                "retained_issuance_heights": sorted(seen),
                "evidence_class": "verifier_attested_finality",
                "publication_timing_proven": False,
                "chain_submission_authorized": False,
                "no_weight": True,
            }

    def releasable_publication(self, key: str) -> SignedEndpointAuthorization:
        """Return exact signed bytes only after every included task's release gate.

        This gate uses observed finality and the signed legacy schedule. It does
        not establish an independent publication timestamp or suite-wide release
        proof. Audience authentication remains the feed integration's duty.
        """
        rejection = None
        with self._transaction() as db:
            publication = self._publication(db, key)
            self._expire_elapsed(db)
            metadata = dict(db.execute("SELECT key,value FROM metadata"))
            now = int(metadata["last_observed_ms"])
            head = self._retained_block(db, int(metadata["last_observed_height"]))
            try:
                if (
                    not now - self.maximum_observation_age_seconds * 1000
                    <= head.timestamp_ms
                    <= now + self.maximum_future_skew_seconds * 1000
                ):
                    raise ValueError(
                        "publication release needs a fresh retained verified observation"
                    )
                for assignment in publication.publication.assignments:
                    row = db.execute(
                        "SELECT * FROM assignments WHERE id=?",
                        (assignment_key(publication, assignment),),
                    ).fetchone()
                    if row is None or bytes(row["body"]) != canonical_json_bytes(assignment):
                        raise ValueError(
                            "retained publication has an inconsistent assignment index"
                        )
                    schedule = self._schedule(
                        assignment, self._retained_block(db, row["announcement"])
                    )
                    request = assignment.request
                    if (
                        now < _round_ms(schedule.selection_round)
                        or head.height < request.issued_block
                    ):
                        raise ValueError("publication contains a future unreleased assignment")
                    issuance = self._retained_block(db, request.issued_block)
                    if (
                        issuance.block_hash != request.issued_block_hash
                        or not _round_ms(schedule.selection_round)
                        <= issuance.timestamp_ms
                        < _round_ms(schedule.issue_close_round)
                        or issuance.timestamp_ms > head.timestamp_ms
                    ):
                        raise ValueError(
                            "publication issuance differs from the exact verified schedule"
                        )
                now = self._expire_elapsed(db)
                if not db.execute(
                    "SELECT 1 FROM assignments a WHERE publication_id=? "
                    "AND issue_close_ms>? AND deadline_block>=? "
                    "AND (SELECT kind FROM events e WHERE e.assignment_id=a.id "
                    "ORDER BY ordinal DESC LIMIT 1)='published' LIMIT 1",
                    (key, now, head.height),
                ).fetchone():
                    raise ValueError("publication has no usable unclaimed issue slots")
                if (
                    not now - self.maximum_observation_age_seconds * 1000
                    <= head.timestamp_ms
                    <= now + self.maximum_future_skew_seconds * 1000
                ):
                    raise ValueError(
                        "publication release needs a fresh retained verified observation"
                    )
            except ValueError as error:
                # Expiry evidence remains committed even when release is denied.
                rejection = error
        if rejection is not None:
            raise rejection
        return publication

    def claim(
        self,
        key: str,
        *,
        observed: VerifiedFinalizedBlock,
        issuance: VerifiedFinalizedBlock | None = None,
    ) -> AssignmentClaim | None:
        """Commit one dispatch token or return None for scheduled/expired work.

        Completed or uncertain work raises before consulting supplied finality.
        The caller must obtain fresh btauth authentication only after this claim.
        """
        with self._transaction() as db:
            row = db.execute("SELECT * FROM assignments WHERE id=?", (key,)).fetchone()
            if row is None:
                raise ValueError("unknown scheduled assignment")
            last = self._last(db, key)
            if last["kind"] == "expired":
                return None
            if last["kind"] in {"dispatched", "completed"}:
                raise ValueError("assignment already dispatched; uncertain work is never retried")
            assignment = EndpointAssignment.model_validate_json(bytes(row["body"]))
            observed, now = self._observation(db, observed)
            request = assignment.request
            if now >= row["issue_close_ms"] or observed.height > request.deadline_block:
                self._event(
                    db,
                    key,
                    "expired",
                    observed.height,
                    now,
                    {"reason": "claim_window_elapsed", "miner_fault": False},
                )
                return None
            if now < row["selection_ms"] or observed.height < request.issued_block:
                return None
            issuance = self._block(issuance)
            if (
                issuance.height != request.issued_block
                or issuance.block_hash != request.issued_block_hash
                or not row["selection_ms"] <= issuance.timestamp_ms < row["issue_close_ms"]
                or issuance.timestamp_ms > observed.timestamp_ms
            ):
                raise ValueError("verified issuance differs from the exact scheduled request")
            self._retain_block(db, issuance)
            publication = self._publication(db, row["publication_id"])
            sub = next(
                s.submission
                for s in publication.publication.submissions
                if digest(s.submission) == assignment.submission_sha256
            )
            claim_id = secrets.token_hex(32)
            now = self._expire_elapsed(db)
            if self._last(db, key)["kind"] == "expired":
                return None
            if (
                not now - self.maximum_observation_age_seconds * 1000
                <= observed.timestamp_ms
                <= now + self.maximum_future_skew_seconds * 1000
            ):
                raise ValueError("verified observation became stale before assignment dispatch")
            self._event(
                db,
                key,
                "dispatched",
                observed.height,
                now,
                {
                    "claim_id": claim_id,
                    "request_sha256": request_digest(request),
                    "issuance_height": issuance.height,
                },
            )
            return AssignmentClaim(
                key, claim_id, row["publication_id"], assignment, sub.hotkey, sub.endpoint_url
            )

    def complete(self, claim: AssignmentClaim, *, evidence: bytes) -> dict:
        """Append a bounded opaque transcript; this does not certify its contents."""
        if not isinstance(claim, AssignmentClaim) or claim.no_weight is not True:
            raise TypeError("completion requires the original no-weight assignment claim")
        if not isinstance(evidence, bytes) or not 1 <= len(evidence) <= self.maximum_outcome_bytes:
            raise ValueError("outcome evidence must fit its reserved byte capacity")
        evidence_sha = hashlib.sha256(evidence).hexdigest()
        with self._transaction() as db:
            row = db.execute(
                "SELECT * FROM assignments WHERE id=?", (claim.assignment_key,)
            ).fetchone()
            if (
                row is None
                or row["publication_id"] != claim.publication_sha256
                or bytes(row["body"]) != canonical_json_bytes(claim.assignment)
            ):
                raise ValueError("completion changed its assignment binding")
            publication = self._publication(db, claim.publication_sha256)
            sub = next(
                s.submission
                for s in publication.publication.submissions
                if digest(s.submission) == claim.assignment.submission_sha256
            )
            if (
                identity(claim.miner_hotkey) != identity(sub.hotkey)
                or claim.serving_origin != sub.endpoint_url
            ):
                raise ValueError("completion changed its miner or serving-origin binding")
            last = self._last(db, claim.assignment_key)
            details = json.loads(bytes(last["body"]))
            if details.get("claim_id") != claim.claim_id or last["kind"] not in {
                "dispatched",
                "completed",
            }:
                raise ValueError("completion does not match the dispatched claim")
            if last["kind"] == "completed":
                if bytes(last["evidence"]) != evidence:
                    raise ValueError("completed assignment already retains different evidence")
                return self._assignment_status(db, claim.assignment_key)
            now = time.time_ns() // 1_000_000
            highwater = int(
                db.execute("SELECT value FROM metadata WHERE key='last_observed_ms'").fetchone()[0]
            )
            if type(now) is not int or not highwater <= now <= 2**53 - 1:
                raise ValueError("scheduling completion time rolled back")
            db.execute("UPDATE metadata SET value=? WHERE key='last_observed_ms'", (str(now),))
            self._event(
                db,
                claim.assignment_key,
                "completed",
                last["observed_height"],
                now,
                {
                    "claim_id": claim.claim_id,
                    "evidence_sha256": evidence_sha,
                    "evidence_verified": False,
                },
                evidence,
            )
            return self._assignment_status(db, claim.assignment_key)

    def _publication(self, db, key):
        row = db.execute("SELECT signed FROM publications WHERE id=?", (key,)).fetchone()
        if row is None:
            raise ValueError("unknown publication")
        publication = validate_publication(
            SignedEndpointAuthorization.model_validate_json(bytes(row[0])),
            self.policy,
            self.legacy_policy,
        )
        if digest(publication.publication) != key:
            raise ValueError("corrupt publication digest")
        return publication

    def publication(self, key: str) -> SignedEndpointAuthorization:
        with self._transaction() as db:
            return self._publication(db, key)

    def _assignment_status(self, db, key):
        row = db.execute("SELECT publication_id FROM assignments WHERE id=?", (key,)).fetchone()
        if row is None:
            raise ValueError("unknown scheduled assignment")
        last = self._last(db, key)
        return {
            "assignment_key": key,
            "publication_sha256": row[0],
            "state": "uncertain_dispatched" if last["kind"] == "dispatched" else last["kind"],
            "dispatch_allowed": False,
            "miner_fault": False if last["kind"] == "expired" else None,
            "outcome_evidence_sha256": hashlib.sha256(bytes(last["evidence"])).hexdigest()
            if last["kind"] == "completed"
            else None,
            "no_weight": True,
            "publication_timing_proven": False,
            "chain_submission_authorized": False,
        }

    def status(self, key: str) -> dict:
        """Historical state only; eligibility is rechecked solely by claim()."""
        with self._transaction() as db:
            self._expire_elapsed(db)
            return self._assignment_status(db, key)

    def _expire_elapsed(self, db):
        now = time.time_ns() // 1_000_000
        highwater = dict(db.execute("SELECT key,value FROM metadata"))
        if (
            type(now) is not int
            or not max(QUICKNET_GENESIS_MS, int(highwater.get("last_observed_ms", "0")))
            <= now
            <= 2**53 - 1
        ):
            raise ValueError("scheduling read time rolled back")
        for row in db.execute(
            "SELECT id,issue_close_ms FROM assignments a "
            "WHERE (issue_close_ms<=? OR deadline_block<?) "
            "AND (SELECT kind FROM events e WHERE e.assignment_id=a.id "
            "ORDER BY ordinal DESC LIMIT 1)='published'",
            (now, int(highwater.get("last_observed_height", "0"))),
        ).fetchall():
            self._event(
                db,
                row[0],
                "expired",
                int(highwater["last_observed_height"]),
                now,
                {
                    "reason": "local_issue_window_elapsed"
                    if now >= row["issue_close_ms"]
                    else "verified_block_deadline_elapsed",
                    "miner_fault": False,
                    "local_clock_only": now >= row["issue_close_ms"],
                },
            )
        db.execute(
            "INSERT INTO metadata VALUES ('last_observed_ms',?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (str(now),),
        )
        return now

    def list_assignments(
        self,
        *,
        miner_hotkey: str,
        after: str | None = None,
        limit: int = 50,
        include_history: bool = False,
    ) -> dict:
        """Reference-free summaries; only claim() may grant a dispatch token.

        Publication retrieval is a separate local API. A publication contains
        video delivery URLs and must not be exposed by an unauthenticated feed
        without a separate release/access policy for those exact signed bytes.
        """
        miner = identity(miner_hotkey)
        if type(limit) is not int or not 1 <= limit <= 100 or type(include_history) is not bool:
            raise ValueError("invalid scheduling page limit or history flag")
        if after is not None and (
            not isinstance(after, str)
            or len(after) != 64
            or any(c not in "0123456789abcdef" for c in after)
        ):
            raise ValueError("invalid assignment page cursor")
        with self._transaction() as db:
            self._expire_elapsed(db)
            query = "SELECT * FROM assignments a WHERE miner=? AND id>?"
            if not include_history:
                query += (
                    " AND (SELECT kind FROM events e WHERE e.assignment_id=a.id "
                    "ORDER BY ordinal DESC LIMIT 1)='published'"
                )
            query += " ORDER BY id LIMIT ?"
            rows = db.execute(query, (miner, after or "", limit + 1)).fetchall()
            items = []
            for row in rows[:limit]:
                assignment = EndpointAssignment.model_validate_json(bytes(row["body"]))
                items.append(
                    {
                        **self._assignment_status(db, row["id"]),
                        "submission_sha256": assignment.submission_sha256,
                        "case_sha256": assignment.case_sha256,
                        "evaluator_hotkey": assignment.evaluator_hotkey,
                        "issue_close_unix_ms": row["issue_close_ms"],
                    }
                )
            return {
                "items": items,
                "next_cursor": rows[limit - 1]["id"] if len(rows) > limit else None,
                "no_weight": True,
                "publication_timing_proven": False,
                "chain_submission_authorized": False,
            }

    def _publication_status(self, db, key):
        row = db.execute("SELECT * FROM publications WHERE id=?", (key,)).fetchone()
        return {
            "publication_sha256": key,
            "signed_publication_sha256": hashlib.sha256(bytes(row["signed"])).hexdigest(),
            "first_observed_unix_ms": row["observed_ms"],
            "first_observed_finalized_height": row["observed_height"],
            "assignments": [
                self._assignment_status(db, r[0])
                for r in db.execute(
                    "SELECT id FROM assignments WHERE publication_id=? ORDER BY id", (key,)
                ).fetchall()
            ],
            "no_weight": True,
            "publication_timing_proven": False,
            "chain_submission_authorized": False,
        }

    def publication_status(self, key: str) -> dict:
        with self._transaction() as db:
            self._publication(db, key)
            self._expire_elapsed(db)
            return self._publication_status(db, key)

    def observation_evidence(self, height: int) -> dict:
        """Local retained attestation bytes, with no offline proof claim."""
        if type(height) is not int or height < 0:
            raise ValueError("invalid observation height")
        with self._transaction() as db:
            row = db.execute("SELECT * FROM blocks WHERE height=?", (height,)).fetchone()
            if row is None:
                raise ValueError("unknown retained observation")
            return {
                "document": bytes(row["document"]),
                "evidence": bytes(row["evidence"]),
                "evidence_class": "verifier_attested_finality",
                "offline_finality_proof": False,
                "publication_timing_proven": False,
                "chain_submission_authorized": False,
            }

    def outcome(self, key: str) -> bytes:
        with self._transaction() as db:
            last = self._last(db, key)
            if last is None or last["kind"] != "completed":
                raise ValueError("assignment has no retained completed outcome")
            return bytes(last["evidence"])

    def events(self, key: str) -> tuple[dict, ...]:
        with self._transaction() as db:
            self._assignment_status(db, key)
            return tuple(
                {
                    "ordinal": row["ordinal"],
                    "kind": row["kind"],
                    "observed_height": row["observed_height"],
                    "observed_unix_ms": row["observed_ms"],
                    "body": bytes(row["body"]),
                    "evidence_sha256": hashlib.sha256(bytes(row["evidence"])).hexdigest()
                    if row["evidence"]
                    else None,
                }
                for row in db.execute(
                    "SELECT * FROM events WHERE assignment_id=? ORDER BY ordinal", (key,)
                )
            )
