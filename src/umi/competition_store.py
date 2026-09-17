"""Durable no-weight admission and compare-and-swap model promotion."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from contextlib import contextmanager, nullcontext
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, ValidationError

from .competition_artifacts import verify_preserved_bundle
from .competition_evidence import (
    IndependentEvaluationEvidence,
    independent_evidence_digest,
    replay_independent_evaluation,
)
from .competition_launch import PublicLaunchIdentity, PublicRoundSchedule
from .competition_outcomes import (
    OutcomeEvidence,
    binding_ids,
    outcome_binding,
    outcome_decision_digest,
    outcome_digest,
    outcome_storage,
    parse_outcome,
    replay_outcome,
)
from .competition_publication import (
    CutoffPublication,
    PublicationReplayLimits,
    build_cutoff_publication,
)
from .competition_settlement import (
    CompetitionSettlement,
    EvidenceCutoffSchedule,
    PromotionHeadBinding,
    competition_settlement_digest,
    evidence_cutoff_schedule_digest,
)
from .competition_submission_checkpoint import (
    MAXIMUM_CHECKPOINT_SUBMISSIONS,
    SubmissionCheckpointError,
    SubmissionHeadCheckpoint,
    SubmissionHeadCheckpointFile,
    build_submission_checkpoint,
    submission_head_body,
)
from .competition_void import VoidEvaluationEvidence
from .competition_void_retention import VoidEvidenceRetention, hold_outcome_conflict
from .open_competition import (
    AttestedResult,
    CompetitionPolicy,
    EvaluationResult,
    EvaluationRound,
    EvaluationSuite,
    Hex32,
    ModelBundle,
    RegistrationSnapshot,
    Signature,
    SignedSubmission,
    StrictProtocolModel,
    Track,
    WeightProjection,
    authenticate_evaluation,
    digest,
    identity,
    model_content_digest,
    project_weights,
    qualifies_for_promotion,
    replay_evaluation,
    validate_admission,
    validate_evaluation_suite,
    validate_suite_profile,
    verify_signature,
)
from .protocol import canonical_json_bytes


class PromotionReview(StrictProtocolModel):
    schema_: Literal["umi-model-promotion-review/1"] = Field(alias="schema")
    policy_sha256: Hex32
    model_sha256: Hex32
    incumbent_model_sha256: Hex32
    evaluation_result_sha256: Hex32
    reconstruction_evidence_sha256: Hex32
    rights_review_sha256: Hex32
    offline_reconstruction_passed: Literal[True]
    rights_review_passed: Literal[True]


class AgreedPromotionReview(PromotionReview):
    """Portable reviewed decision; local receipt times are stored separately."""

    schema_: Literal["umi-model-promotion-review/2"] = Field(alias="schema")
    round_sha256: Hex32
    submission_sha256: Hex32
    previous_promotion_sha256: Hex32
    sequence: Annotated[int, Field(ge=1, le=2**53 - 1)]


class AttestedPromotionReview(StrictProtocolModel):
    review: PromotionReview | AgreedPromotionReview
    signatures: Annotated[tuple[Signature, ...], Field(min_length=1, max_length=64)]


class AdmissionCapacity(StrictProtocolModel):
    """Operational bounds for the append-only admission ledger."""

    maximum_records: Annotated[int, Field(ge=1, le=1_000_000)] = 65_536
    maximum_bytes: Annotated[int, Field(ge=1, le=64 * 1024**3)] = 2 * 1024**3


class AdmissionCapacityError(ValueError):
    """A new admission would exceed its configured durable capacity."""


class SettlementNotReadyError(ValueError):
    """A frozen roster entry has no complete independent evidence by cutoff."""


class RoundPreparationCapacity(StrictProtocolModel):
    maximum_records: Annotated[int, Field(ge=1, le=65_536)] = 1024
    maximum_bytes: Annotated[int, Field(ge=1, le=16 * 1024**3)] = 1024**3


def verify_review(review: AttestedPromotionReview, policy: CompetitionPolicy) -> None:
    groups = {identity(e.hotkey): e.control_group for e in policy.evaluators}
    seen: set[str] = set()
    for sig in review.signatures:
        key = identity(sig.hotkey)
        if key not in groups or groups[key] in seen:
            raise ValueError("unauthorized or duplicate promotion review group")
        verify_signature(review.review, sig)
        seen.add(groups[key])
    if len(seen) < policy.required_evaluator_groups:
        raise ValueError("insufficient independent promotion review")
    if review.review.policy_sha256 != digest(policy):
        raise ValueError("promotion review belongs to another policy")
    if "0" * 64 in {
        review.review.reconstruction_evidence_sha256,
        review.review.rights_review_sha256,
    }:
        raise ValueError("promotion review requires evidence identities")


class CompetitionStore(VoidEvidenceRetention):
    """One policy-bound SQLite store; never a source of chain authorization."""

    _WRITER_GENERATION = 2
    _WRITER_FENCED_TABLES = (
        "metadata",
        "round_preparations",
        "submissions",
        "admission_usage",
        "rounds",
        "promotions",
        "model_identities",
        "suite_usage",
        "public_schedule_usage",
        "public_launch_history",
        "evaluation_results",
        "evaluation_signatures",
        "round_conflicts",
        "promotion_sources",
        "promotion_receipts",
        "evidence_cutoff_schedules",
        "independent_evaluation_evidence",
        "void_evaluation_evidence",
        "competition_settlements",
        "settlement_heads",
        "settlement_disputes",
    )

    def __init__(
        self,
        directory: Path,
        policy: CompetitionPolicy,
        *,
        admission_capacity: AdmissionCapacity | None = None,
        preparation_capacity: RoundPreparationCapacity | None = None,
        role: Literal["intake", "evaluator_review"] = "intake",
        public_launch: PublicLaunchIdentity | None = None,
        migrate_writer_generation: bool = False,
        submission_head_checkpoint_directory: Path | None = None,
        initial_checkpoint_submission_sha256s: tuple[str, ...] | None = None,
        initial_checkpoint_baseline_promotion_sha256: str | None = None,
        initialize_submission_checkpoint: bool = False,
    ):
        if not directory.is_absolute() or directory.is_symlink():
            raise ValueError("competition state directory must be absolute and not a symlink")
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        if directory.stat().st_mode & 0o077:
            raise ValueError("competition state directory must be private")
        self.policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
        if public_launch is not None:
            public_launch = PublicLaunchIdentity.model_validate_json(
                canonical_json_bytes(public_launch)
            )
        launch_id = None if public_launch is None else digest(public_launch)
        self.public_launch = public_launch
        self.public_launch_id = launch_id
        if role not in {"intake", "evaluator_review"}:
            raise ValueError("unknown competition store role")
        self.role = role
        self.admission_capacity = AdmissionCapacity.model_validate_json(
            canonical_json_bytes(admission_capacity or AdmissionCapacity())
        )
        self.preparation_capacity = RoundPreparationCapacity.model_validate_json(
            canonical_json_bytes(preparation_capacity or RoundPreparationCapacity())
        )
        self.directory = directory
        self.path = directory / "competition.sqlite3"
        self._submission_checkpoint: SubmissionHeadCheckpointFile | None = None
        self._submission_checkpoint_binding: str | None = None
        if submission_head_checkpoint_directory is None:
            if (
                initial_checkpoint_submission_sha256s is not None
                or initial_checkpoint_baseline_promotion_sha256 is not None
                or initialize_submission_checkpoint
            ):
                raise ValueError("checkpoint initialization requires a checkpoint directory")
        else:
            if role != "intake" or launch_id is None:
                raise ValueError("submission checkpoint requires a launch-bound intake store")
            checkpoint_directory = submission_head_checkpoint_directory
            if not checkpoint_directory.is_absolute():
                raise ValueError("submission checkpoint directory must be absolute")
            state_root = directory.resolve()
            checkpoint_root = checkpoint_directory.resolve()
            if (
                state_root == checkpoint_root
                or state_root in checkpoint_root.parents
                or checkpoint_root in state_root.parents
            ):
                raise ValueError("competition state and submission checkpoint must not overlap")
            self._submission_checkpoint = SubmissionHeadCheckpointFile(
                checkpoint_directory,
                policy_sha256=digest(self.policy),
                public_launch_sha256=launch_id,
            )
            self._submission_checkpoint_binding = self._submission_checkpoint.binding_sha256
            if self.admission_capacity.maximum_records > MAXIMUM_CHECKPOINT_SUBMISSIONS:
                raise ValueError("admission capacity exceeds submission checkpoint capacity")
            if initialize_submission_checkpoint and (
                initial_checkpoint_submission_sha256s is None
                or initial_checkpoint_baseline_promotion_sha256 is None
            ):
                raise ValueError("checkpoint initialization requires exact retained intake state")
        if self.path.is_symlink():
            raise ValueError("competition database cannot be a symlink")
        # Constructor-time launch binding and checkpoint rotation are one
        # compound operation. Nested connections reuse this outer file lock.
        self._hold_submission_checkpoint_lock = self._submission_checkpoint is not None
        self._submission_checkpoint_lock_depth = 0
        database_existed = self.path.is_file()
        if database_existed:
            # A detect-only open must not create tables, switch journal modes,
            # or install the generation fence in a live legacy writer.  The
            # explicit migration path is reserved for a quiesced store.
            with sqlite3.connect(f"file:{self.path}?mode=ro", uri=True) as probe:
                metadata_exists = probe.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name='metadata'"
                ).fetchone()
                bound = (
                    probe.execute("SELECT value FROM metadata WHERE key='policy'").fetchone()
                    if metadata_exists
                    else None
                )
                checkpoint_bound = (
                    probe.execute(
                        "SELECT value FROM metadata WHERE key='submission_head_checkpoint_binding'"
                    ).fetchone()
                    if metadata_exists
                    else None
                )
                checkpoint_required = (
                    probe.execute(
                        "SELECT value FROM metadata WHERE key='submission_head_checkpoint_required'"
                    ).fetchone()
                    if metadata_exists
                    else None
                )
            policy_id = digest(policy)
            if bound is None and not migrate_writer_generation:
                raise ValueError("legacy competition store requires explicit quiesced migration")
            if bound is not None and bound[0] == policy_id and not migrate_writer_generation:
                raise ValueError("legacy competition store requires explicit quiesced migration")
            if bound is not None and bound[0] not in {
                policy_id,
                f"writer-{self._WRITER_GENERATION}:{policy_id}",
            }:
                raise ValueError("state directory is bound to a different competition policy")
            if checkpoint_bound is not None and checkpoint_bound[0] != (
                self._submission_checkpoint_binding
            ):
                raise ValueError("competition state requires its configured submission checkpoint")
            if checkpoint_required is not None and checkpoint_required[0] != (
                self._submission_checkpoint_binding
            ):
                raise ValueError("competition state requires its configured submission checkpoint")
        with self._connection() as connection:
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS round_preparations (
                    suite TEXT PRIMARY KEY, body BLOB NOT NULL
                );
                CREATE TABLE IF NOT EXISTS submissions (
                    digest TEXT PRIMARY KEY, hotkey TEXT NOT NULL, track TEXT NOT NULL,
                    sequence INTEGER NOT NULL, accepted_block INTEGER NOT NULL,
                    expires_block INTEGER NOT NULL, body BLOB NOT NULL, receipt BLOB NOT NULL,
                    writer_generation INTEGER NOT NULL CHECK(writer_generation = 2),
                    UNIQUE(hotkey, track, sequence)
                );
                CREATE TABLE IF NOT EXISTS admission_usage (
                    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                    records INTEGER NOT NULL CHECK(records >= 0),
                    payload_bytes INTEGER NOT NULL CHECK(payload_bytes >= 0)
                );
                CREATE TABLE IF NOT EXISTS rounds (
                    digest TEXT PRIMARY KEY, sequence INTEGER UNIQUE NOT NULL, body BLOB NOT NULL
                );
                CREATE TABLE IF NOT EXISTS promotions (
                    sequence INTEGER PRIMARY KEY, digest TEXT UNIQUE NOT NULL,
                    model TEXT UNIQUE NOT NULL, contributor TEXT, body BLOB NOT NULL
                );
                CREATE TABLE IF NOT EXISTS model_identities (
                    content TEXT PRIMARY KEY, model TEXT UNIQUE NOT NULL
                );
                CREATE TABLE IF NOT EXISTS suite_usage (
                    suite TEXT PRIMARY KEY, round TEXT UNIQUE NOT NULL
                );
                CREATE TABLE IF NOT EXISTS public_schedule_usage (
                    schedule TEXT PRIMARY KEY, suite TEXT UNIQUE NOT NULL,
                    round TEXT UNIQUE NOT NULL
                );
                CREATE TABLE IF NOT EXISTS public_launch_history (
                    sequence INTEGER PRIMARY KEY,
                    digest TEXT UNIQUE NOT NULL,
                    schedule TEXT UNIQUE NOT NULL,
                    body BLOB NOT NULL
                );
                CREATE TABLE IF NOT EXISTS evaluation_results (
                    digest TEXT PRIMARY KEY, round TEXT NOT NULL, submission TEXT NOT NULL,
                    body BLOB NOT NULL, observed_block INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS evaluation_slot
                    ON evaluation_results (round, submission);
                CREATE TABLE IF NOT EXISTS evaluation_signatures (
                    result TEXT NOT NULL, signer TEXT NOT NULL, control_group TEXT NOT NULL,
                    body BLOB NOT NULL, PRIMARY KEY(result, signer)
                );
                CREATE TABLE IF NOT EXISTS round_conflicts (
                    round TEXT PRIMARY KEY, detected_block INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS promotion_sources (
                    sequence INTEGER PRIMARY KEY, round TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS promotion_receipts (
                    sequence INTEGER PRIMARY KEY, observed_block INTEGER NOT NULL,
                    evaluation BLOB NOT NULL, review BLOB NOT NULL
                );
                CREATE TABLE IF NOT EXISTS evidence_cutoff_schedules (
                    round TEXT PRIMARY KEY, round_sequence INTEGER UNIQUE NOT NULL,
                    cutoff_block INTEGER NOT NULL, digest TEXT UNIQUE NOT NULL,
                    body BLOB NOT NULL, fixed_observed_block INTEGER NOT NULL,
                    receipt BLOB NOT NULL
                );
                CREATE TABLE IF NOT EXISTS independent_evaluation_evidence (
                    digest TEXT PRIMARY KEY, round TEXT NOT NULL, submission TEXT NOT NULL,
                    result TEXT NOT NULL, body BLOB NOT NULL,
                    first_observed_block INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS independent_evidence_slot
                    ON independent_evaluation_evidence (round, submission, result);
                CREATE TABLE IF NOT EXISTS void_evaluation_evidence (
                    digest TEXT PRIMARY KEY, round TEXT NOT NULL, submission TEXT NOT NULL,
                    decision TEXT NOT NULL, body BLOB NOT NULL,
                    first_observed_block INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS void_evidence_slot
                    ON void_evaluation_evidence (round, submission, decision);
                CREATE TABLE IF NOT EXISTS competition_settlements (
                    round TEXT PRIMARY KEY, digest TEXT UNIQUE NOT NULL, body BLOB NOT NULL
                );
                CREATE TABLE IF NOT EXISTS settlement_heads (
                    round TEXT PRIMARY KEY, promotion_sequence INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS settlement_disputes (
                    round TEXT PRIMARY KEY, detected_block INTEGER NOT NULL
                );
            """)
            connection.execute("BEGIN IMMEDIATE")
            try:
                self._preflight_submission_checkpoint_launch(
                    connection,
                    database_existed=database_existed,
                    migrate_writer_generation=migrate_writer_generation,
                    initialize_submission_checkpoint=initialize_submission_checkpoint,
                )
                submission_columns = connection.execute(
                    "SELECT name FROM pragma_table_info('submissions') ORDER BY cid"
                ).fetchall()
                if [name for (name,) in submission_columns] == [
                    "digest",
                    "hotkey",
                    "track",
                    "sequence",
                    "accepted_block",
                    "expires_block",
                    "body",
                    "receipt",
                ]:
                    connection.execute(
                        "ALTER TABLE submissions ADD COLUMN writer_generation INTEGER "
                        "NOT NULL DEFAULT 2 CHECK(writer_generation = 2)"
                    )
                    submission_columns.append(("writer_generation",))
                if [name for (name,) in submission_columns] != [
                    "digest",
                    "hotkey",
                    "track",
                    "sequence",
                    "accepted_block",
                    "expires_block",
                    "body",
                    "receipt",
                    "writer_generation",
                ] or connection.execute(
                    "SELECT 1 FROM submissions WHERE writer_generation != 2 LIMIT 1"
                ).fetchone():
                    raise ValueError("submission writer generation is corrupt")
                self._install_writer_fence(connection)
                self._install_submission_checkpoint_fence(connection)
                bound = connection.execute(
                    "SELECT value FROM metadata WHERE key='policy'"
                ).fetchone()
                policy_binding = f"writer-2:{digest(policy)}"
                if bound is None:
                    connection.execute(
                        "INSERT INTO metadata VALUES ('policy', ?)", (policy_binding,)
                    )
                elif bound[0] == digest(policy):
                    if not migrate_writer_generation:
                        raise ValueError(
                            "legacy competition store requires explicit quiesced migration"
                        )
                    connection.execute(
                        "UPDATE metadata SET value=? WHERE key='policy'", (policy_binding,)
                    )
                elif bound[0] != policy_binding:
                    raise ValueError("state directory is bound to a different competition policy")
                prior_role = connection.execute(
                    "SELECT value FROM metadata WHERE key='role'"
                ).fetchone()
                if prior_role is None:
                    if (
                        role != "intake"
                        and connection.execute(
                            "SELECT 1 FROM submissions UNION ALL SELECT 1 FROM rounds LIMIT 1"
                        ).fetchone()
                    ):
                        raise ValueError("existing intake history cannot become evaluator receipts")
                    connection.execute("INSERT INTO metadata VALUES ('role', ?)", (role,))
                elif prior_role[0] != role:
                    raise ValueError("competition state is bound to a different store role")
                self._hydrate_public_schedule_usage(connection)
                if role != "intake" and launch_id is not None:
                    raise ValueError("evaluator receipt state cannot bind a public launch")
                if role == "intake":
                    self._bind_public_launch(connection, public_launch)
                self._bind_required_submission_checkpoint(connection)
                actual_usage = connection.execute(
                    "SELECT COUNT(*), COALESCE(SUM("
                    "length(CAST(body AS BLOB)) + length(CAST(receipt AS BLOB))"
                    "), 0) FROM submissions"
                ).fetchone()
                connection.execute(
                    "INSERT INTO admission_usage VALUES (1, ?, ?) "
                    "ON CONFLICT(singleton) DO UPDATE SET records=excluded.records, "
                    "payload_bytes=excluded.payload_bytes",
                    actual_usage,
                )
                self._bind_submission_head(
                    connection,
                    initialize=not database_existed or migrate_writer_generation,
                )
                if initialize_submission_checkpoint:
                    self._verify_retained_intake_state_locked(
                        connection,
                        baseline_promotion_sha256=(
                            initial_checkpoint_baseline_promotion_sha256 or ""
                        ),
                        required_submission_sha256s=(initial_checkpoint_submission_sha256s or ()),
                    )
                self._hydrate_promotion_evidence(connection)
                self._hydrate_settlement_heads(connection)
                connection.commit()
            except BaseException:
                connection.rollback()
                raise
            if self._submission_checkpoint is not None:
                self._synchronize_submission_checkpoint_locked(
                    allow_initialize=initialize_submission_checkpoint,
                    initial_submission_sha256s=initial_checkpoint_submission_sha256s,
                )
        self._hold_submission_checkpoint_lock = False
        os.chmod(self.path, 0o600)

    @contextmanager
    def _connection(self):
        owns_checkpoint_lock = bool(
            self._hold_submission_checkpoint_lock
            and self._submission_checkpoint is not None
            and self._submission_checkpoint_lock_depth == 0
        )
        checkpoint_lock = (
            self._submission_checkpoint.locked() if owns_checkpoint_lock else nullcontext()
        )
        with checkpoint_lock:
            if owns_checkpoint_lock:
                self._submission_checkpoint_lock_depth += 1
            connection = sqlite3.connect(self.path, timeout=10, isolation_level=None)
            try:
                connection.create_function(
                    "umi_writer_generation",
                    0,
                    lambda: self._WRITER_GENERATION,
                    deterministic=True,
                )
                connection.create_function(
                    "umi_submission_checkpoint_binding",
                    0,
                    lambda: self._submission_checkpoint_binding,
                    deterministic=True,
                )
                connection.execute("PRAGMA journal_mode=WAL")
                connection.execute("PRAGMA synchronous=FULL")
                yield connection
            finally:
                connection.close()
                if owns_checkpoint_lock:
                    self._submission_checkpoint_lock_depth -= 1

    def _preflight_submission_checkpoint_launch(
        self,
        connection: sqlite3.Connection,
        *,
        database_existed: bool,
        migrate_writer_generation: bool,
        initialize_submission_checkpoint: bool,
    ) -> None:
        """Compare external and SQLite launch heads before changing either one."""

        checkpoint_file = self._submission_checkpoint
        if checkpoint_file is None:
            return
        checkpoint = checkpoint_file.load()
        stored_binding = connection.execute(
            "SELECT value FROM metadata WHERE key='submission_head_checkpoint_binding'"
        ).fetchone()
        required_binding = connection.execute(
            "SELECT value FROM metadata WHERE key='submission_head_checkpoint_required'"
        ).fetchone()
        if checkpoint is None:
            explicit_migration_recovery = (
                database_existed
                and migrate_writer_generation
                and initialize_submission_checkpoint
                and stored_binding is None
                and required_binding == (self._submission_checkpoint_binding,)
            )
            if stored_binding is not None or (
                required_binding is not None and not explicit_migration_recovery
            ):
                raise SubmissionCheckpointError("submission checkpoint is missing")
            if database_existed and not initialize_submission_checkpoint:
                raise SubmissionCheckpointError(
                    "submission checkpoint requires explicit initial retained state"
                )
            return

        current = connection.execute(
            "SELECT value FROM metadata WHERE key='public_launch_identity'"
        ).fetchone()
        if current is None:
            if not (
                database_existed
                and migrate_writer_generation
                and initialize_submission_checkpoint
                and stored_binding is None
                and required_binding is None
                and checkpoint.public_launch_sha256 == self.public_launch_id
            ):
                raise SubmissionCheckpointError(
                    "submission checkpoint public launch is ahead of the durable ledger"
                )
            return
        if checkpoint.public_launch_sha256 == current[0]:
            return

        history = self._public_launch_history(connection)
        if (
            self.public_launch_id != current[0]
            or len(history) < 2
            or history[-1][1] != current[0]
            or history[-2][1] != checkpoint.public_launch_sha256
        ):
            raise SubmissionCheckpointError(
                "submission checkpoint public launch is not the immediate predecessor"
            )
        submission_ids, record_ids = self._submission_checkpoint_records(connection)
        if (
            checkpoint.submission_sha256s != submission_ids
            or checkpoint.admission_record_sha256s != record_ids
        ):
            raise SubmissionCheckpointError(
                "submission checkpoint cannot advance launches with changed records"
            )

    @classmethod
    def _install_writer_fence(cls, connection: sqlite3.Connection) -> None:
        """Make pre-generation writers fail, including processes already running."""

        for table in cls._WRITER_FENCED_TABLES:
            for operation in ("INSERT", "UPDATE", "DELETE"):
                trigger = f"writer_2_{operation.lower()}_{table}"
                connection.execute(
                    f"CREATE TRIGGER IF NOT EXISTS {trigger} BEFORE {operation} ON {table} "
                    "BEGIN SELECT CASE WHEN umi_writer_generation() != 2 "
                    "THEN RAISE(ABORT, 'competition writer generation mismatch') END; END"
                )

    @staticmethod
    def _install_submission_checkpoint_fence(connection: sqlite3.Connection) -> None:
        """Keep an already running uncheckpointed writer from bypassing the head."""

        for operation in ("INSERT", "UPDATE", "DELETE"):
            trigger = f"submission_checkpoint_{operation.lower()}_submissions"
            connection.execute(f"DROP TRIGGER IF EXISTS {trigger}")
            connection.execute(
                f"CREATE TRIGGER {trigger} BEFORE {operation} ON submissions "
                "WHEN (SELECT value FROM metadata "
                "WHERE key='submission_head_checkpoint_required') IS NOT NULL "
                "AND umi_submission_checkpoint_binding() IS NOT "
                "(SELECT value FROM metadata "
                "WHERE key='submission_head_checkpoint_required') "
                "BEGIN SELECT RAISE(ABORT, "
                "'competition submission checkpoint writer mismatch'); END"
            )

    def _bind_required_submission_checkpoint(self, connection: sqlite3.Connection) -> None:
        """Persist the external checkpoint requirement before initialization can crash."""

        required = connection.execute(
            "SELECT value FROM metadata WHERE key='submission_head_checkpoint_required'"
        ).fetchone()
        if self._submission_checkpoint_binding is None:
            if required is not None:
                raise ValueError("competition state requires its configured submission checkpoint")
            return
        if required is None:
            connection.execute(
                "INSERT INTO metadata VALUES ('submission_head_checkpoint_required', ?)",
                (self._submission_checkpoint_binding,),
            )
        elif required != (self._submission_checkpoint_binding,):
            raise ValueError("competition state requires another submission checkpoint")

    @contextmanager
    def _transaction(self):
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                yield connection
                connection.commit()
            except BaseException:
                connection.rollback()
                raise

    @staticmethod
    def _round_public_launch(round_: EvaluationRound) -> PublicLaunchIdentity:
        return PublicLaunchIdentity(
            schema="umi-competition-public-launch/1",
            round_schedule=round_.public_schedule,
            eligible_tracks=round_.eligible_tracks,
        )

    @classmethod
    def _hydrate_public_schedule_usage(cls, connection: sqlite3.Connection) -> None:
        """Recover the schedule index from canonical retained rounds."""

        for round_id, body in connection.execute("SELECT digest, body FROM rounds").fetchall():
            try:
                decoded = json.loads(body)
            except (TypeError, ValidationError, ValueError) as error:
                raise ValueError("stored competition round is corrupt") from error
            if isinstance(decoded, dict) and decoded.get("schema") == "umi-competition-round/1":
                raise ValueError("legacy retained round lacks an exact public launch schedule")
            try:
                round_ = EvaluationRound.model_validate_json(body)
            except (TypeError, ValidationError, ValueError) as error:
                raise ValueError("stored competition round is corrupt") from error
            if digest(round_) != round_id or canonical_json_bytes(round_) != body:
                raise ValueError("stored competition round is corrupt")
            suite_usage = connection.execute(
                "SELECT round FROM suite_usage WHERE suite=?", (round_.suite_sha256,)
            ).fetchone()
            if suite_usage != (round_id,):
                raise ValueError("stored round suite usage is corrupt")
            schedule_id = digest(round_.public_schedule)
            schedule_usage = connection.execute(
                "SELECT suite, round FROM public_schedule_usage WHERE schedule=?",
                (schedule_id,),
            ).fetchone()
            expected = (round_.suite_sha256, round_id)
            if schedule_usage is None:
                try:
                    connection.execute(
                        "INSERT INTO public_schedule_usage VALUES (?, ?, ?)",
                        (schedule_id, *expected),
                    )
                except sqlite3.IntegrityError as error:
                    raise ValueError("stored public schedule usage is corrupt") from error
            elif schedule_usage != expected:
                raise ValueError("stored public schedule usage is corrupt")

    @staticmethod
    def _public_launch_history(
        connection: sqlite3.Connection,
    ) -> list[tuple[int, str, str, PublicLaunchIdentity]]:
        rows = connection.execute(
            "SELECT sequence, digest, schedule, body FROM public_launch_history ORDER BY sequence"
        ).fetchall()
        parsed = []
        previous = None
        for expected_sequence, (sequence, launch_id, schedule_id, body) in enumerate(rows, start=1):
            try:
                launch = PublicLaunchIdentity.model_validate_json(body)
            except (TypeError, ValidationError, ValueError) as error:
                raise ValueError("stored public launch history is corrupt") from error
            if (
                sequence != expected_sequence
                or digest(launch) != launch_id
                or digest(launch.round_schedule) != schedule_id
                or canonical_json_bytes(launch) != body
            ):
                raise ValueError("stored public launch history is corrupt")
            if (
                previous is not None
                and launch.round_schedule.intake_opened_block
                <= previous.round_schedule.round_valid_through_block
            ):
                raise ValueError("stored public launch history overlaps or rolls back")
            parsed.append((sequence, launch_id, schedule_id, launch))
            previous = launch
        return parsed

    @classmethod
    def _bind_public_launch(
        cls,
        connection: sqlite3.Connection,
        supplied: PublicLaunchIdentity | None,
    ) -> None:
        bound = connection.execute(
            "SELECT value FROM metadata WHERE key='public_launch_identity'"
        ).fetchone()
        history = cls._public_launch_history(connection)
        if supplied is None:
            if bound is not None or history:
                raise ValueError("state directory requires its public launch identity")
            return

        launch_id = digest(supplied)
        schedule_id = digest(supplied.round_schedule)
        body = canonical_json_bytes(supplied)
        if bound is None:
            if history:
                raise ValueError("public launch history has no current identity")
            latest = connection.execute(
                "SELECT body FROM rounds ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            if latest is not None:
                try:
                    latest_round = EvaluationRound.model_validate_json(latest[0])
                except (TypeError, ValidationError, ValueError) as error:
                    raise ValueError("stored competition round is corrupt") from error
                if cls._round_public_launch(latest_round) != supplied:
                    raise ValueError(
                        "legacy intake history requires the latest round public launch"
                    )
            connection.execute(
                "INSERT INTO public_launch_history VALUES (1, ?, ?, ?)",
                (launch_id, schedule_id, body),
            )
            connection.execute(
                "INSERT INTO metadata VALUES ('public_launch_identity', ?)",
                (launch_id,),
            )
            return

        if not history:
            if bound[0] != launch_id:
                raise ValueError("state directory is bound to a different public launch")
            connection.execute(
                "INSERT INTO public_launch_history VALUES (1, ?, ?, ?)",
                (launch_id, schedule_id, body),
            )
            return
        if bound[0] != history[-1][1]:
            raise ValueError("current public launch differs from immutable history")
        if bound[0] == launch_id:
            if history[-1][3] != supplied:
                raise ValueError("stored public launch digest has non-canonical semantics")
            return
        if any(prior_id == launch_id for _, prior_id, _, _ in history):
            raise ValueError("public launch rollback is forbidden")
        if any(prior_schedule == schedule_id for _, _, prior_schedule, _ in history):
            raise ValueError("public round schedule reuse is forbidden")

        current = history[-1][3]
        if (
            supplied.round_schedule.intake_opened_block
            <= current.round_schedule.round_valid_through_block
        ):
            raise ValueError("successor public launch overlaps or rolls back")
        usage = connection.execute(
            "SELECT suite, round FROM public_schedule_usage WHERE schedule=?",
            (digest(current.round_schedule),),
        ).fetchall()
        if len(usage) != 1:
            raise ValueError("current public launch must be consumed by exactly one round")
        suite_id, round_id = usage[0]
        retained = connection.execute(
            "SELECT body FROM rounds WHERE digest=?", (round_id,)
        ).fetchone()
        if retained is None:
            raise ValueError("current public launch round is missing")
        try:
            round_ = EvaluationRound.model_validate_json(retained[0])
        except (TypeError, ValidationError, ValueError) as error:
            raise ValueError("current public launch round is corrupt") from error
        if (
            digest(round_) != round_id
            or round_.suite_sha256 != suite_id
            or cls._round_public_launch(round_) != current
        ):
            raise ValueError("current public launch usage is corrupt")
        settlement_row = connection.execute(
            "SELECT digest, body FROM competition_settlements WHERE round=?", (round_id,)
        ).fetchone()
        if settlement_row is None:
            raise ValueError("current public launch must be finalized before succession")
        if connection.execute(
            "SELECT 1 FROM round_conflicts UNION ALL SELECT 1 FROM settlement_disputes LIMIT 1"
        ).fetchone() or cls._baseline_conflicted(connection):
            raise ValueError("current public launch has unresolved conflicts")
        try:
            settlement = CompetitionSettlement.model_validate_json(settlement_row[1])
        except (TypeError, ValidationError, ValueError) as error:
            raise ValueError("current public launch settlement is corrupt") from error
        if (
            settlement.round_sha256 != round_id
            or competition_settlement_digest(settlement) != settlement_row[0]
        ):
            raise ValueError("current public launch settlement is corrupt")
        if connection.execute(
            "SELECT 1 FROM public_schedule_usage WHERE schedule=?", (schedule_id,)
        ).fetchone():
            raise ValueError("public round schedule was already consumed")
        connection.execute(
            "INSERT INTO public_launch_history VALUES (?, ?, ?, ?)",
            (history[-1][0] + 1, launch_id, schedule_id, body),
        )
        connection.execute(
            "UPDATE metadata SET value=? WHERE key='public_launch_identity'", (launch_id,)
        )

    def _require_current_public_launch(
        self, connection: sqlite3.Connection
    ) -> PublicLaunchIdentity | None:
        bound = connection.execute(
            "SELECT value FROM metadata WHERE key='public_launch_identity'"
        ).fetchone()
        if bound is None:
            if self.public_launch_id is not None:
                raise ValueError("configured public launch binding is missing")
            return None
        if self.public_launch_id is None or bound[0] != self.public_launch_id:
            raise ValueError("competition store instance has a stale public launch")
        history = self._public_launch_history(connection)
        if not history or history[-1][1] != bound[0]:
            raise ValueError("current public launch differs from immutable history")
        return history[-1][3]

    def admit(
        self,
        signed: SignedSubmission,
        snapshot: RegistrationSnapshot,
        current_block: int,
        *,
        registration_source: Literal[
            "rehearsal_snapshot", "verifier_attested_finality"
        ] = "rehearsal_snapshot",
    ) -> dict:
        self._require_intake()
        if registration_source not in {"rehearsal_snapshot", "verifier_attested_finality"}:
            raise ValueError("unsupported registration source")
        signed = SignedSubmission.model_validate_json(canonical_json_bytes(signed))
        snapshot = RegistrationSnapshot.model_validate_json(canonical_json_bytes(snapshot))
        sub = signed.submission
        if sub.policy_sha256 != digest(self.policy):
            raise ValueError("submission belongs to another policy")
        sub_id, key = digest(sub), identity(sub.hotkey)
        checkpoint_lock = (
            self._submission_checkpoint.locked()
            if self._submission_checkpoint is not None
            else nullcontext()
        )
        with checkpoint_lock:
            if self._submission_checkpoint is not None:
                # Resolve a prior DB-commit/checkpoint-write crash before this
                # request can return either a new or historical receipt.
                self._synchronize_submission_checkpoint_locked()
            with self._transaction() as connection:
                launch = self._require_current_public_launch(connection)
                old = connection.execute(
                    "SELECT receipt FROM submissions WHERE digest=?", (sub_id,)
                ).fetchone()
                if old:
                    return json.loads(old[0])  # Historical retry, never an expiry renewal.
                if launch is not None and (
                    sub.track not in launch.eligible_tracks
                    or current_block < launch.round_schedule.intake_opened_block
                    or current_block > launch.round_schedule.roster_close_latest_block
                ):
                    raise ValueError("submission is outside the current public launch")
                _advance_block(connection, current_block)
                closed = connection.execute(
                    "SELECT body FROM rounds ORDER BY sequence DESC LIMIT 1"
                ).fetchone()
                if closed and current_block <= json.loads(closed[0])["submission_close_block"]:
                    raise ValueError(
                        "the admission boundary is already closed; retry in a later block"
                    )
                uid = validate_admission(signed, self.policy, snapshot, current_block)
                latest = connection.execute(
                    "SELECT sequence, accepted_block FROM submissions WHERE hotkey=? AND track=? "
                    "ORDER BY sequence DESC LIMIT 1",
                    (key, sub.track),
                ).fetchone()
                if latest:
                    if sub.sequence <= latest[0]:
                        raise ValueError("submission sequence must increase")
                    if current_block - latest[1] < self.policy.minimum_submission_interval_blocks:
                        raise ValueError("submission replacement is rate limited")
                receipt = {
                    "schema": "umi-competition-admission/2",
                    "policy_sha256": digest(self.policy),
                    "submission_sha256": sub_id,
                    "accepted_block": current_block,
                    "registration_snapshot_sha256": digest(snapshot),
                    "registration_snapshot": snapshot.model_dump(mode="json", by_alias=True),
                    "registration_source": registration_source,
                    "observed_uid": uid,
                    "status": "accepted_no_weight",
                    "chain_submission_authorized": False,
                }
                body_bytes = canonical_json_bytes(signed)
                receipt_bytes = canonical_json_bytes(receipt)
                usage = connection.execute(
                    "SELECT records, payload_bytes FROM admission_usage WHERE singleton=1"
                ).fetchone()
                if usage is None:
                    raise ValueError("admission usage ledger is unavailable")
                next_records = usage[0] + 1
                next_bytes = usage[1] + len(body_bytes) + len(receipt_bytes)
                if (
                    next_records > self.admission_capacity.maximum_records
                    or next_bytes > self.admission_capacity.maximum_bytes
                ):
                    raise AdmissionCapacityError("admission capacity is exhausted")
                self._insert_admission(
                    connection,
                    (
                        sub_id,
                        key,
                        sub.track,
                        sub.sequence,
                        current_block,
                        sub.valid_through_block,
                        body_bytes,
                        receipt_bytes,
                    ),
                    records=next_records,
                    payload_bytes=next_bytes,
                )
            if self._submission_checkpoint is not None:
                # SQLite commits first. The receipt is returned only after the
                # independently located head and its parent directory are fsynced.
                self._synchronize_submission_checkpoint_locked()
            return receipt

    def _insert_admission(
        self,
        connection: sqlite3.Connection,
        values: tuple,
        *,
        records: int,
        payload_bytes: int,
    ) -> None:
        connection.execute(
            "INSERT INTO submissions "
            "(digest, hotkey, track, sequence, accepted_block, expires_block, body, receipt, "
            "writer_generation) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 2)",
            values,
        )
        connection.execute(
            "UPDATE admission_usage SET records=?, payload_bytes=? WHERE singleton=1",
            (records, payload_bytes),
        )
        self._write_submission_head(connection)

    def _submission_head_body(self, connection: sqlite3.Connection) -> dict:
        return submission_head_body(digest(self.policy), self._submission_ids(connection))

    @staticmethod
    def _submission_ids(connection: sqlite3.Connection) -> tuple[str, ...]:
        return tuple(
            row[0]
            for row in connection.execute(
                "SELECT digest FROM submissions ORDER BY digest"
            ).fetchall()
        )

    def _write_submission_head(self, connection: sqlite3.Connection) -> dict:
        head = self._submission_head_body(connection)
        body = canonical_json_bytes(head).decode("utf-8")
        updated = connection.execute(
            "UPDATE metadata SET value=? WHERE key='retained_submission_head'",
            (body,),
        )
        if updated.rowcount != 1:
            raise ValueError("retained submission head is missing")
        return head

    def _bind_submission_head(
        self, connection: sqlite3.Connection, *, initialize: bool = False
    ) -> dict:
        expected = self._submission_head_body(connection)
        expected_body = canonical_json_bytes(expected).decode("utf-8")
        retained = connection.execute(
            "SELECT value FROM metadata WHERE key='retained_submission_head'"
        ).fetchone()
        if retained is None:
            if not initialize:
                raise ValueError("retained submission head is missing")
            connection.execute(
                "INSERT INTO metadata VALUES ('retained_submission_head', ?)",
                (expected_body,),
            )
        elif retained != (expected_body,):
            raise ValueError("retained submission head differs from the durable ledger")
        return expected

    @staticmethod
    def _submission_checkpoint_records(
        connection: sqlite3.Connection,
    ) -> tuple[tuple[str, ...], tuple[str, ...]]:
        rows = connection.execute(
            "SELECT digest, hotkey, track, sequence, accepted_block, expires_block, "
            "body, receipt, writer_generation FROM submissions ORDER BY digest"
        ).fetchall()
        submission_ids: list[str] = []
        record_ids: list[str] = []
        for row in rows:
            submission_ids.append(row[0])
            record = {
                "schema": "umi-competition-admission-record-commitment/1",
                "submission_sha256": row[0],
                "hotkey": row[1],
                "track": row[2],
                "sequence": row[3],
                "accepted_block": row[4],
                "expires_block": row[5],
                "body_sha256": hashlib.sha256(row[6]).hexdigest(),
                "receipt_sha256": hashlib.sha256(row[7]).hexdigest(),
                "writer_generation": row[8],
            }
            record_ids.append(hashlib.sha256(canonical_json_bytes(record)).hexdigest())
        return tuple(submission_ids), tuple(record_ids)

    def _synchronize_submission_checkpoint_locked(
        self,
        *,
        allow_initialize: bool = False,
        initial_submission_sha256s: tuple[str, ...] | None = None,
    ) -> SubmissionHeadCheckpoint:
        checkpoint_file = self._submission_checkpoint
        checkpoint_binding = self._submission_checkpoint_binding
        if checkpoint_file is None or checkpoint_binding is None:
            raise RuntimeError("submission checkpoint is not configured")
        with self._transaction() as connection:
            self._require_current_public_launch(connection)
            self._bind_submission_head(connection)
            submission_ids, record_ids = self._submission_checkpoint_records(connection)
            stored_binding = connection.execute(
                "SELECT value FROM metadata WHERE key='submission_head_checkpoint_binding'"
            ).fetchone()
            required_binding = connection.execute(
                "SELECT value FROM metadata WHERE key='submission_head_checkpoint_required'"
            ).fetchone()
            if required_binding != (checkpoint_binding,):
                raise SubmissionCheckpointError(
                    "competition state has no matching submission checkpoint requirement"
                )
            if stored_binding is not None and stored_binding != (checkpoint_binding,):
                raise SubmissionCheckpointError(
                    "competition state requires another submission checkpoint"
                )
            checkpoint = checkpoint_file.load()
            if checkpoint is None:
                if stored_binding is not None:
                    raise SubmissionCheckpointError("submission checkpoint is missing")
                if (
                    not allow_initialize
                    or initial_submission_sha256s is None
                    or submission_ids != initial_submission_sha256s
                ):
                    raise SubmissionCheckpointError(
                        "submission checkpoint requires explicit initial retained state"
                    )
                for submission_id in submission_ids:
                    self._verify_retained_submission(connection, submission_id)
                checkpoint = build_submission_checkpoint(
                    policy_sha256=digest(self.policy),
                    public_launch_sha256=self.public_launch_id or "",
                    submission_sha256s=submission_ids,
                    admission_record_sha256s=record_ids,
                )
                checkpoint_file.replace(checkpoint)
            else:
                retained_records = dict(
                    zip(
                        checkpoint.submission_sha256s,
                        checkpoint.admission_record_sha256s,
                        strict=True,
                    )
                )
                current_records = dict(zip(submission_ids, record_ids, strict=True))
                if any(
                    current_records.get(submission_id) != record_id
                    for submission_id, record_id in retained_records.items()
                ):
                    raise SubmissionCheckpointError(
                        "submission checkpoint is ahead of or differs from the durable ledger"
                    )
                if checkpoint.public_launch_sha256 != self.public_launch_id:
                    history = self._public_launch_history(connection)
                    if (
                        len(history) < 2
                        or history[-1][1] != self.public_launch_id
                        or history[-2][1] != checkpoint.public_launch_sha256
                    ):
                        raise SubmissionCheckpointError(
                            "submission checkpoint public launch is not the immediate predecessor"
                        )
                    if (
                        checkpoint.submission_sha256s != submission_ids
                        or checkpoint.admission_record_sha256s != record_ids
                    ):
                        raise SubmissionCheckpointError(
                            "submission checkpoint cannot advance launches with changed records"
                        )
                    checkpoint = build_submission_checkpoint(
                        policy_sha256=digest(self.policy),
                        public_launch_sha256=self.public_launch_id,
                        submission_sha256s=submission_ids,
                        admission_record_sha256s=record_ids,
                    )
                    checkpoint_file.replace(checkpoint)
                elif checkpoint.submission_sha256s != submission_ids:
                    # The only recoverable cross-resource state is a verified
                    # append-only DB extension whose receipt was not yet returned.
                    for submission_id in submission_ids:
                        self._verify_retained_submission(connection, submission_id)
                    checkpoint = build_submission_checkpoint(
                        policy_sha256=digest(self.policy),
                        public_launch_sha256=self.public_launch_id or "",
                        submission_sha256s=submission_ids,
                        admission_record_sha256s=record_ids,
                    )
                    checkpoint_file.replace(checkpoint)
            if stored_binding is None:
                connection.execute(
                    "INSERT INTO metadata VALUES ('submission_head_checkpoint_binding', ?)",
                    (checkpoint_binding,),
                )
            return checkpoint

    def retained_submission_head(self) -> dict:
        """Return the verified rolling head and its external durability proof."""

        if self._submission_checkpoint is not None:
            with self._submission_checkpoint.locked():
                checkpoint = self._synchronize_submission_checkpoint_locked()
            return self._submission_checkpoint.status(checkpoint)
        with self._connection() as connection:
            head = self._bind_submission_head(connection)
            submission_ids = self._submission_ids(connection)
        return {
            **head,
            "head_sha256": hashlib.sha256(
                canonical_json_bytes(submission_head_body(digest(self.policy), submission_ids))
            ).hexdigest(),
        }

    def admission_capacity_status(self) -> dict:
        """Return bounded logical usage, excluding SQLite and journal overhead."""

        with self._connection() as connection:
            return self._admission_capacity_status(connection)

    def _admission_capacity_status(self, connection: sqlite3.Connection) -> dict:
        usage = connection.execute(
            "SELECT records, payload_bytes FROM admission_usage WHERE singleton=1"
        ).fetchone()
        if usage is None:
            raise ValueError("admission usage ledger is unavailable")
        return {
            "records": usage[0],
            "maximum_records": self.admission_capacity.maximum_records,
            "payload_bytes": usage[1],
            "maximum_payload_bytes": self.admission_capacity.maximum_bytes,
            "accepting_new": usage[0] < self.admission_capacity.maximum_records
            and usage[1] < self.admission_capacity.maximum_bytes,
        }

    def durable_admission_status(self) -> dict:
        """Read capacity and the durable head from one checkpoint-locked state."""

        if self._submission_checkpoint is not None:
            with self._submission_checkpoint.locked():
                checkpoint = self._synchronize_submission_checkpoint_locked()
                with self._connection() as connection:
                    admission = self._admission_capacity_status(connection)
            head = self._submission_checkpoint.status(checkpoint)
        else:
            with self._connection() as connection:
                connection.execute("BEGIN")
                admission = self._admission_capacity_status(connection)
                retained = self._bind_submission_head(connection)
                submission_ids = self._submission_ids(connection)
            head = {
                **retained,
                "head_sha256": hashlib.sha256(
                    canonical_json_bytes(submission_head_body(digest(self.policy), submission_ids))
                ).hexdigest(),
            }
        return {"admission_capacity": admission, "retained_submission_head": head}

    def submissions(self, *, offset: int = 0, limit: int = 100) -> list[dict]:
        if not 0 <= offset <= 10_000_000 or not 1 <= limit <= 100:
            raise ValueError("invalid admission-log page")
        checkpoint_lock = (
            self._submission_checkpoint.locked()
            if self._submission_checkpoint is not None
            else nullcontext()
        )
        with checkpoint_lock:
            if self._submission_checkpoint is not None:
                self._synchronize_submission_checkpoint_locked()
            with self._connection() as connection:
                rows = connection.execute(
                    "SELECT body, receipt FROM submissions "
                    "ORDER BY accepted_block, digest LIMIT ? OFFSET ?",
                    (limit, offset),
                ).fetchall()
        return [
            {"signed_submission": json.loads(body), "receipt": json.loads(receipt)}
            for body, receipt in rows
        ]

    def admission_summaries(self, *, offset: int = 0, limit: int = 20) -> list[dict]:
        if not 0 <= offset <= 10_000_000 or not 1 <= limit <= 100:
            raise ValueError("invalid admission-log page")
        checkpoint_lock = (
            self._submission_checkpoint.locked()
            if self._submission_checkpoint is not None
            else nullcontext()
        )
        with checkpoint_lock:
            if self._submission_checkpoint is not None:
                self._synchronize_submission_checkpoint_locked()
            with self._connection() as connection:
                rows = connection.execute(
                    "SELECT digest, hotkey, track, sequence, accepted_block, expires_block "
                    "FROM submissions ORDER BY accepted_block, digest LIMIT ? OFFSET ?",
                    (limit, offset),
                ).fetchall()
        return [
            dict(
                zip(
                    (
                        "submission_sha256",
                        "hotkey_account_id32",
                        "track",
                        "sequence",
                        "accepted_block",
                        "valid_through_block",
                    ),
                    row,
                    strict=True,
                )
            )
            for row in rows
        ]

    def submission_by_digest(self, submission_sha256: str) -> dict | None:
        if len(submission_sha256) != 64 or any(
            c not in "0123456789abcdef" for c in submission_sha256
        ):
            raise ValueError("invalid submission digest")
        checkpoint_lock = (
            self._submission_checkpoint.locked()
            if self._submission_checkpoint is not None
            else nullcontext()
        )
        with checkpoint_lock:
            if self._submission_checkpoint is not None:
                self._synchronize_submission_checkpoint_locked()
            with self._connection() as connection:
                row = connection.execute(
                    "SELECT body, receipt FROM submissions WHERE digest=?", (submission_sha256,)
                ).fetchone()
        return (
            None
            if row is None
            else {"signed_submission": json.loads(row[0]), "receipt": json.loads(row[1])}
        )

    def verify_retained_intake_state(
        self,
        *,
        baseline_promotion_sha256: str,
        required_submission_sha256s: tuple[str, ...],
    ) -> None:
        """Bind and replay every retained launch anchor, then audit later rows too."""

        self._require_intake()
        with self._transaction() as connection:
            self._verify_retained_intake_state_locked(
                connection,
                baseline_promotion_sha256=baseline_promotion_sha256,
                required_submission_sha256s=required_submission_sha256s,
            )

    def _verify_retained_intake_state_locked(
        self,
        connection: sqlite3.Connection,
        *,
        baseline_promotion_sha256: str,
        required_submission_sha256s: tuple[str, ...],
    ) -> None:
        _require_hex32(baseline_promotion_sha256, "baseline promotion digest")
        if (
            not required_submission_sha256s
            or tuple(sorted(set(required_submission_sha256s))) != required_submission_sha256s
        ):
            raise ValueError("required submission digests must be sorted and unique")
        for submission_id in required_submission_sha256s:
            _require_hex32(submission_id, "submission digest")
        anchor = {
            "schema": "umi-competition-retained-intake-anchor/1",
            "policy_sha256": digest(self.policy),
            "baseline_promotion_sha256": baseline_promotion_sha256,
            "required_submission_sha256s": list(required_submission_sha256s),
        }
        anchor_bytes = canonical_json_bytes(anchor)
        self._require_current_public_launch(connection)
        self._verify_retained_baseline(connection, baseline_promotion_sha256)
        self._bind_submission_head(connection)
        current = tuple(
            row[0]
            for row in connection.execute(
                "SELECT digest FROM submissions ORDER BY digest"
            ).fetchall()
        )
        if any(submission_id not in current for submission_id in required_submission_sha256s):
            raise ValueError("intake durable ledger is missing required submissions")
        retained = connection.execute(
            "SELECT value FROM metadata WHERE key='retained_intake_anchor'"
        ).fetchone()
        if retained is None:
            if current != required_submission_sha256s:
                raise ValueError("first retained-state binding must name every current submission")
            connection.execute(
                "INSERT INTO metadata VALUES ('retained_intake_anchor', ?)",
                (anchor_bytes.decode("utf-8"),),
            )
        elif retained != (anchor_bytes.decode("utf-8"),):
            raise ValueError("retained intake anchor differs from its first binding")
        for submission_id in current:
            self._verify_retained_submission(connection, submission_id)

    def _verify_retained_submission(
        self, connection: sqlite3.Connection, submission_id: str
    ) -> None:
        row = connection.execute(
            "SELECT digest, hotkey, track, sequence, accepted_block, expires_block, "
            "body, receipt, writer_generation FROM submissions WHERE digest=?",
            (submission_id,),
        ).fetchone()
        if row is None:
            raise ValueError("required retained submission is missing")
        try:
            signed = SignedSubmission.model_validate_json(row[6])
            receipt = json.loads(row[7])
            snapshot = RegistrationSnapshot.model_validate_json(
                canonical_json_bytes(receipt["registration_snapshot"])
            )
        except (KeyError, TypeError, ValidationError, ValueError) as error:
            raise ValueError("retained submission record is corrupt") from error
        submission = signed.submission
        expected_receipt_keys = {
            "schema",
            "policy_sha256",
            "submission_sha256",
            "accepted_block",
            "registration_snapshot_sha256",
            "registration_snapshot",
            "registration_source",
            "observed_uid",
            "status",
            "chain_submission_authorized",
        }
        try:
            observed_uid = validate_admission(signed, self.policy, snapshot, row[4])
        except (TypeError, ValidationError, ValueError) as error:
            raise ValueError("retained submission record is corrupt") from error
        if (
            row[0] != submission_id
            or digest(submission) != submission_id
            or canonical_json_bytes(signed) != row[6]
            or row[1] != identity(submission.hotkey)
            or row[2] != submission.track
            or row[3] != submission.sequence
            or row[5] != submission.valid_through_block
            or row[8] != self._WRITER_GENERATION
            or not isinstance(receipt, dict)
            or set(receipt) != expected_receipt_keys
            or canonical_json_bytes(receipt) != row[7]
            or receipt["schema"] != "umi-competition-admission/2"
            or receipt["policy_sha256"] != digest(self.policy)
            or receipt["submission_sha256"] != submission_id
            or receipt["accepted_block"] != row[4]
            or receipt["registration_snapshot_sha256"] != digest(snapshot)
            or receipt["registration_source"]
            not in {"rehearsal_snapshot", "verifier_attested_finality"}
            or receipt["observed_uid"] != observed_uid
            or receipt["status"] != "accepted_no_weight"
            or receipt["chain_submission_authorized"] is not False
        ):
            raise ValueError("retained submission record is corrupt")

    def _verify_retained_baseline(self, connection: sqlite3.Connection, promotion_id: str) -> None:
        row = connection.execute(
            "SELECT sequence, digest, model, contributor, body FROM promotions WHERE digest=?",
            (promotion_id,),
        ).fetchone()
        if row is None:
            raise ValueError("intake durable ledger has another baseline")
        latest = connection.execute(
            "SELECT digest FROM promotions ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        if latest != (promotion_id,):
            raise ValueError("retained baseline is not the current promotion head")
        try:
            record = json.loads(row[4])
            model_id = record["model_sha256"]
            contributor = record.get("contributor_hotkey")
        except (KeyError, TypeError, ValueError) as error:
            raise ValueError("retained baseline record is corrupt") from error
        identities = connection.execute(
            "SELECT content FROM model_identities WHERE model=? ORDER BY content", (model_id,)
        ).fetchall()
        if (
            not isinstance(record, dict)
            or canonical_json_bytes(record) != row[4]
            or _record_digest(record) != promotion_id
            or row[0] != record.get("sequence")
            or row[1] != promotion_id
            or row[2] != model_id
            or row[3] != (None if contributor is None else identity(contributor))
            or record.get("policy_sha256") != digest(self.policy)
            or len(identities) != 1
        ):
            raise ValueError("retained baseline record is corrupt")
        _require_hex32(model_id, "retained baseline model digest")
        _require_hex32(identities[0][0], "retained baseline content digest")

    def baseline_summary(self) -> dict | None:
        with self._connection() as connection:
            connection.execute("BEGIN")
            row = connection.execute(
                "SELECT sequence, digest, model, contributor FROM promotions "
                "ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            held = self._baseline_conflicted(connection)
        return (
            None
            if row is None
            else {
                **dict(
                    zip(
                        (
                            "sequence",
                            "promotion_sha256",
                            "model_sha256",
                            "contributor_account_id32",
                        ),
                        row,
                        strict=True,
                    )
                ),
                "held_for_conflict": held,
            }
        )

    def _store_certificate(
        self, connection: sqlite3.Connection, attested: AttestedResult, observed_block: int
    ) -> dict:
        """Called only after authentication; never raises a conflict rejection."""
        result = attested.result
        result_id = digest(result)
        connection.execute(
            "INSERT OR IGNORE INTO evaluation_results VALUES (?, ?, ?, ?, ?)",
            (
                result_id,
                result.round_sha256,
                result.submission_sha256,
                canonical_json_bytes(result),
                observed_block,
            ),
        )
        groups = {identity(e.hotkey): e.control_group for e in self.policy.evaluators}
        for signature in attested.signatures:
            signer = identity(signature.hotkey)
            connection.execute(
                "INSERT OR IGNORE INTO evaluation_signatures VALUES (?, ?, ?, ?)",
                (result_id, signer, groups[signer], canonical_json_bytes(signature)),
            )
        # Certificates may have disjoint quorums. Detect conflicting result
        # identities, not just two statements by the same signing key.
        alternatives = connection.execute(
            "SELECT COUNT(*) FROM evaluation_results WHERE round=? AND submission=?",
            (result.round_sha256, result.submission_sha256),
        ).fetchone()[0]
        if (
            alternatives > 1
            or connection.execute(
                "SELECT 1 FROM void_evaluation_evidence WHERE round=? AND submission=? LIMIT 1",
                (result.round_sha256, result.submission_sha256),
            ).fetchone()
        ):
            hold_outcome_conflict(connection, result.round_sha256, observed_block)
        return {
            "round_sha256": result.round_sha256,
            "submission_sha256": result.submission_sha256,
            "result_sha256": result_id,
            "conflicted": bool(
                connection.execute(
                    "SELECT 1 FROM round_conflicts WHERE round=?", (result.round_sha256,)
                ).fetchone()
            ),
            "chain_submission_authorized": False,
        }

    def record_evaluation(
        self,
        *,
        signed: SignedSubmission,
        attested: AttestedResult,
        round_: EvaluationRound,
        suite: EvaluationSuite,
        observed_block: int,
    ) -> dict:
        """Commit historical quorum evidence independently of any reward action."""
        signed = SignedSubmission.model_validate_json(canonical_json_bytes(signed))
        attested = AttestedResult.model_validate_json(canonical_json_bytes(attested))
        round_ = EvaluationRound.model_validate_json(canonical_json_bytes(round_))
        authenticate_evaluation(attested, signed, round_, self.policy)
        validate_evaluation_suite(attested, round_, suite, self.policy)
        if (
            type(observed_block) is not int
            or not round_.reveal_block <= observed_block <= 2**53 - 1
        ):
            raise ValueError("evidence observation must be at or after reveal in a valid block")
        with self._transaction() as connection:
            closed = connection.execute(
                "SELECT body FROM rounds WHERE digest=?", (digest(round_),)
            ).fetchone()
            if closed is None or closed[0] != canonical_json_bytes(round_):
                raise ValueError("evaluation round has not been closed in the admission log")
            if not connection.execute(
                "SELECT 1 FROM submissions WHERE digest=?", (digest(signed.submission),)
            ).fetchone():
                raise ValueError("evaluation submission is absent from the admission log")
            _advance_block(connection, observed_block)
            # This transaction commits even when a following project/promote
            # transaction fails. Never raise a conflict error in this scope.
            return self._store_certificate(connection, attested, observed_block)

    def record_independent_evaluation(
        self,
        *,
        signed: SignedSubmission,
        evidence: IndependentEvaluationEvidence,
        round_: EvaluationRound,
        suite: EvaluationSuite,
        observed_block: int,
    ) -> dict:
        """Retain a quorum certificate before checking its independent run evidence."""

        self.record_evaluation(
            signed=signed,
            attested=evidence.attested_result,
            round_=round_,
            suite=suite,
            observed_block=observed_block,
        )
        return self._store_independent_evaluation(
            signed=signed,
            evidence=evidence,
            round_=round_,
            suite=suite,
            observed_block=observed_block,
        )

    def _store_independent_evaluation(
        self,
        *,
        signed: SignedSubmission,
        evidence: IndependentEvaluationEvidence,
        round_: EvaluationRound,
        suite: EvaluationSuite,
        observed_block: int,
    ) -> dict:
        signed = SignedSubmission.model_validate_json(canonical_json_bytes(signed))
        evidence = IndependentEvaluationEvidence.model_validate_json(
            canonical_json_bytes(evidence), strict=True
        )
        round_ = EvaluationRound.model_validate_json(canonical_json_bytes(round_))
        suite = EvaluationSuite.model_validate_json(canonical_json_bytes(suite))
        replay_independent_evaluation(
            evidence,
            signed,
            round_,
            suite,
            self.policy,
            current_block=observed_block,
        )
        round_id = digest(round_)
        submission_id = digest(signed.submission)
        result_id = digest(evidence.attested_result.result)
        evidence_id = independent_evidence_digest(evidence)
        body = canonical_json_bytes(evidence)
        with self._transaction() as connection:
            # Intake uses its pre-fixed ledger schedule. Evaluator review stores
            # obtain the same deadline from their independently verified cutoff.
            self._fixed_cutoff(connection, round_id)
            _advance_block(connection, observed_block)
            prior = connection.execute(
                "SELECT round, submission, result, body, first_observed_block "
                "FROM independent_evaluation_evidence WHERE digest=?",
                (evidence_id,),
            ).fetchone()
            expected = (round_id, submission_id, result_id, body)
            if prior is not None:
                if prior[:4] != expected:
                    raise ValueError("independent evidence digest conflicts with stored evidence")
                first_observed_block = prior[4]
            else:
                connection.execute(
                    "INSERT INTO independent_evaluation_evidence VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        evidence_id,
                        round_id,
                        submission_id,
                        result_id,
                        body,
                        observed_block,
                    ),
                )
                first_observed_block = observed_block
        return {
            "schema": "umi-competition-independent-evidence-receipt/1",
            "policy_sha256": digest(self.policy),
            "round_sha256": round_id,
            "submission_sha256": submission_id,
            "result_sha256": result_id,
            "independent_evidence_sha256": evidence_id,
            "first_observed_block": first_observed_block,
            "chain_submission_authorized": False,
        }

    def accepted_review(self, value):
        """Verify an existing decision and its local receipt without retiming it."""
        review = value.review
        verify_review(review, self.policy)
        with self._connection() as connection:
            self._assert_action_allowed(connection, digest(value.round))
            row = connection.execute(
                "SELECT length(body) FROM promotions WHERE sequence=?", (review.review.sequence,)
            ).fetchone()
            if row is None:
                return None
            if not 0 < row[0] <= 16 * 1024**2:
                raise ValueError("retained promotion exceeds its byte bound")
            raw = connection.execute(
                "SELECT body FROM promotions WHERE sequence=?", (review.review.sequence,)
            ).fetchone()[0]
            record = json.loads(raw)
            if (
                canonical_json_bytes(record) != raw
                or record.get("schema") != "umi-model-baseline/2"
            ):
                raise ValueError("retained promotion is not an agreed canonical decision")
            attested, _ = self._read_agreed_promotion_receipt(connection, record)
            if record != _agreed_promotion_record(value.submission, attested, review.review):
                raise ValueError("review delivery changes an already accepted promotion")
            return record

    def promotion_evidence(self, *, round_, signed, suite, current_block):
        """Load bounded independent evidence already retained by this operator."""
        round_id, sub_id = digest(round_), digest(signed.submission)
        with self._connection() as connection:
            self._assert_action_allowed(connection, round_id)
            cutoff = self._fixed_cutoff(connection, round_id)
            if not round_.reveal_block <= current_block <= cutoff.evidence_cutoff_block:
                raise ValueError("reviewed promotion arrived outside its evidence window")
            retained, attested = self._recorded_evaluation(connection, round_id, sub_id)
            if retained != signed:
                raise ValueError("promotion differs from retained submission")
            result_id = digest(attested.result)
            row = connection.execute(
                "SELECT digest,length(body),first_observed_block "
                "FROM independent_evaluation_evidence WHERE round=? AND submission=? AND result=? "
                "ORDER BY first_observed_block,digest LIMIT 1",
                (round_id, sub_id, result_id),
            ).fetchone()
            if (
                row is None
                or not 0 < row[1] <= 16 * 1024**2
                or (
                    not round_.reveal_block
                    <= row[2]
                    <= min(current_block, cutoff.evidence_cutoff_block)
                )
            ):
                raise ValueError("promotion requires timely retained independent evidence")
            raw = connection.execute(
                "SELECT body FROM independent_evaluation_evidence WHERE digest=?", (row[0],)
            ).fetchone()[0]
        evidence = IndependentEvaluationEvidence.model_validate_json(raw)
        if canonical_json_bytes(evidence) != raw or (
            independent_evidence_digest(evidence) != row[0]
            or evidence.attested_result.result != attested.result
        ):
            raise ValueError("promotion independent evidence differs from its retained identity")
        replay_independent_evaluation(
            evidence, signed, round_, suite, self.policy, current_block=current_block
        )
        return evidence

    def round_status(self, round_sha256: str, *, offset: int = 0, limit: int = 100) -> dict:
        if not 0 <= offset <= 10_000_000 or not 1 <= limit <= 100:
            raise ValueError("invalid round-evidence page")
        with self._connection() as connection:
            connection.execute("BEGIN")
            if not connection.execute(
                "SELECT 1 FROM rounds WHERE digest=?", (round_sha256,)
            ).fetchone():
                raise ValueError("unknown round")
            conflict = connection.execute(
                "SELECT detected_block FROM round_conflicts WHERE round=?", (round_sha256,)
            ).fetchone()
            results = connection.execute(
                "SELECT digest, submission, observed_block FROM evaluation_results "
                "WHERE round=? ORDER BY digest LIMIT ? OFFSET ?",
                (round_sha256, limit, offset),
            ).fetchall()
            equivocations = connection.execute(
                "SELECT r.submission, v.control_group FROM evaluation_signatures v "
                "JOIN evaluation_results r ON r.digest=v.result WHERE r.round=? "
                "GROUP BY r.submission, v.control_group HAVING COUNT(DISTINCT r.digest)>1 "
                "ORDER BY r.submission, v.control_group LIMIT ? OFFSET ?",
                (round_sha256, limit, offset),
            ).fetchall()
        return {
            "round_sha256": round_sha256,
            "conflicted": conflict is not None,
            "conflict_detected_block": None if conflict is None else conflict[0],
            "results": [
                dict(
                    zip(
                        ("result_sha256", "submission_sha256", "first_observed_block"),
                        row,
                        strict=True,
                    )
                )
                for row in results
            ],
            "equivocations": [
                dict(zip(("submission_sha256", "control_group"), row, strict=True))
                for row in equivocations
            ],
            "offset": offset,
            "limit": limit,
            "chain_submission_authorized": False,
        }

    def settlement_status(self, round_sha256: str) -> dict | None:
        _require_hex32(round_sha256, "round digest")
        with self._connection() as connection:
            connection.execute("BEGIN")
            row = connection.execute(
                "SELECT digest, body FROM competition_settlements WHERE round=?",
                (round_sha256,),
            ).fetchone()
            if row is None:
                return None
            conflict = connection.execute(
                "SELECT detected_block FROM round_conflicts WHERE round=?",
                (round_sha256,),
            ).fetchone()
            dispute = connection.execute(
                "SELECT detected_block FROM settlement_disputes WHERE round=?",
                (round_sha256,),
            ).fetchone()
        settlement = CompetitionSettlement.model_validate_json(row[1])
        if competition_settlement_digest(settlement) != row[0]:
            raise ValueError("stored competition settlement is corrupt")
        detected = dispute or conflict
        return {
            "settlement_sha256": row[0],
            "settlement": settlement.model_dump(mode="json", by_alias=True),
            "disputed": detected is not None,
            "dispute_detected_block": None if detected is None else detected[0],
            "chain_submission_authorized": False,
        }

    @staticmethod
    def _baseline_conflicted(connection: sqlite3.Connection) -> bool:
        # The preserved history is a single parent-linked chain. Holding all
        # descendants prevents a new round from laundering a disputed promotion.
        return bool(
            connection.execute(
                "SELECT 1 FROM promotion_sources p "
                "JOIN round_conflicts c ON p.round=c.round LIMIT 1"
            ).fetchone()
        )

    def _assert_action_allowed(self, connection: sqlite3.Connection, round_sha256: str) -> None:
        if connection.execute(
            "SELECT 1 FROM round_conflicts WHERE round=?", (round_sha256,)
        ).fetchone():
            raise ValueError("round has conflicting quorum evidence")
        if self._baseline_conflicted(connection):
            raise ValueError("baseline history contains a conflicted promotion")
        if connection.execute("SELECT 1 FROM settlement_disputes LIMIT 1").fetchone():
            raise ValueError("settlement history contains conflicting quorum evidence")

    @staticmethod
    def _recorded_evaluation(
        connection: sqlite3.Connection, round_sha256: str, submission_sha256: str
    ) -> tuple[SignedSubmission, AttestedResult]:
        rows = connection.execute(
            "SELECT digest, body FROM evaluation_results WHERE round=? AND submission=?",
            (round_sha256, submission_sha256),
        ).fetchall()
        if len(rows) != 1:
            raise ValueError("evaluation evidence is missing or conflicting")
        result_id, body = rows[0]
        votes = connection.execute(
            "SELECT control_group, body FROM evaluation_signatures WHERE result=? "
            "ORDER BY control_group, signer",
            (result_id,),
        ).fetchall()
        # Preserve every signed statement in the ledger, but count one key per
        # control group when reconstructing a certificate for replay.
        groups: dict[str, Signature] = {}
        for group, signature in votes:
            groups.setdefault(group, Signature.model_validate_json(signature))
        submission_row = connection.execute(
            "SELECT body FROM submissions WHERE digest=?",
            (submission_sha256,),
        ).fetchone()
        if submission_row is None:
            raise ValueError("recorded evaluation lacks its admitted submission")
        return (
            SignedSubmission.model_validate_json(submission_row[0]),
            AttestedResult(
                result=EvaluationResult.model_validate_json(body), signatures=tuple(groups.values())
            ),
        )

    def _hydrate_promotion_evidence(self, connection: sqlite3.Connection) -> None:
        """Recover certificates retained by earlier, no-ledger rehearsal stores."""
        for sequence, record_id, model, body in connection.execute(
            "SELECT sequence, digest, model, body FROM promotions ORDER BY sequence"
        ).fetchall():
            record = json.loads(body)
            if _record_digest(record) != record_id or record["model_sha256"] != model:
                raise ValueError("preserved promotion history is corrupt")
            if sequence == 0:
                continue
            if record["schema"] == "umi-model-baseline/2":
                if record["sequence"] != sequence:
                    raise ValueError("agreed promotion sequence is corrupt")
                attested, observed = self._read_agreed_promotion_receipt(connection, record)
                evaluation = attested.model_dump(mode="json", by_alias=True)
            else:
                evaluation = dict(record["evaluation"])
                observed = record["promoted_at_block"]
            result_body = dict(evaluation["result"])
            # Earlier prototype records used Pydantic field names in this
            # embedded object. Verify the original record hash above and only
            # normalize a copy for certificate authentication. Never rewrite it.
            if "schema_" in result_body and "schema" not in result_body:
                result_body["schema"] = result_body.pop("schema_")
            evaluation["result"] = result_body
            attested = AttestedResult.model_validate_json(canonical_json_bytes(evaluation))
            result = attested.result
            round_row = connection.execute(
                "SELECT body FROM rounds WHERE digest=?", (result.round_sha256,)
            ).fetchone()
            sub_row = connection.execute(
                "SELECT body FROM submissions WHERE digest=?", (result.submission_sha256,)
            ).fetchone()
            if round_row is None or sub_row is None or model != result.model_revision:
                raise ValueError("preserved promotion lacks its closed round or submission")
            round_ = EvaluationRound.model_validate_json(round_row[0])
            signed = SignedSubmission.model_validate_json(sub_row[0])
            authenticate_evaluation(attested, signed, round_, self.policy)
            if (
                type(observed) is not int
                or not round_.reveal_block <= observed <= round_.valid_through_block
            ):
                raise ValueError("preserved promotion has an invalid observation block")
            self._store_certificate(connection, attested, observed)
            connection.execute(
                "INSERT OR IGNORE INTO promotion_sources VALUES (?, ?)",
                (sequence, result.round_sha256),
            )

    def _read_agreed_promotion_receipt(self, connection, record, *, maximum_bytes=None):
        sequence = record["sequence"]
        size = connection.execute(
            "SELECT length(CAST(evaluation AS BLOB)) + length(CAST(review AS BLOB)) "
            "FROM promotion_receipts WHERE sequence=?",
            (sequence,),
        ).fetchone()
        if size is None:
            raise ValueError("agreed promotion is missing its local receipt")
        if (
            type(size[0]) is not int
            or size[0] <= 0
            or (maximum_bytes is not None and size[0] > maximum_bytes)
        ):
            raise ValueError("agreed promotion receipt exceeds its byte bound")
        observed, evaluation_bytes, review_bytes = connection.execute(
            "SELECT observed_block, evaluation, review FROM promotion_receipts WHERE sequence=?",
            (sequence,),
        ).fetchone()
        attested = AttestedResult.model_validate_json(evaluation_bytes)
        review = AttestedPromotionReview.model_validate_json(review_bytes)
        if (
            canonical_json_bytes(attested) != evaluation_bytes
            or canonical_json_bytes(review) != review_bytes
        ):
            raise ValueError("agreed promotion receipt is not canonical")
        verify_review(review, self.policy)
        if not isinstance(review.review, AgreedPromotionReview):
            raise ValueError("agreed promotion requires a versioned local review")
        previous = connection.execute(
            "SELECT digest FROM promotions WHERE sequence=?",
            (sequence - 1,),
        ).fetchone()
        if previous is None or record["previous_promotion_sha256"] != previous[0]:
            raise ValueError("agreed promotion history has an invalid parent")
        result = attested.result
        round_row = connection.execute(
            "SELECT body FROM rounds WHERE digest=?",
            (result.round_sha256,),
        ).fetchone()
        sub_row = connection.execute(
            "SELECT body FROM submissions WHERE digest=?",
            (result.submission_sha256,),
        ).fetchone()
        if round_row is None or sub_row is None:
            raise ValueError("agreed promotion lacks its admitted submission or round")
        round_ = EvaluationRound.model_validate_json(round_row[0])
        signed = SignedSubmission.model_validate_json(sub_row[0])
        authenticate_evaluation(attested, signed, round_, self.policy)
        _validate_agreed_review(review.review, signed, attested, round_)
        if record != _agreed_promotion_record(signed, attested, review.review):
            raise ValueError("agreed promotion differs from its local certificates")
        high_water = connection.execute(
            "SELECT value FROM metadata WHERE key='observed_block'"
        ).fetchone()
        if (
            type(observed) is not int
            or not round_.reveal_block <= observed <= round_.valid_through_block
            or high_water is None
            or observed > int(high_water[0])
        ):
            raise ValueError("promotion receipt exceeds the local observation history")
        return attested, observed

    @staticmethod
    def _hydrate_settlement_heads(connection: sqlite3.Connection) -> None:
        """Recover the query index without rewriting immutable settlement bodies."""
        orphan = connection.execute(
            "SELECT h.round FROM settlement_heads h "
            "LEFT JOIN competition_settlements s ON s.round=h.round "
            "WHERE s.round IS NULL LIMIT 1"
        ).fetchone()
        if orphan is not None:
            raise ValueError("settlement head index references a missing settlement")
        for round_id, settlement_id, body in connection.execute(
            "SELECT round, digest, body FROM competition_settlements"
        ).fetchall():
            settlement = CompetitionSettlement.model_validate_json(body)
            if (
                settlement.round_sha256 != round_id
                or competition_settlement_digest(settlement) != settlement_id
            ):
                raise ValueError("stored competition settlement is corrupt")
            indexed = connection.execute(
                "SELECT promotion_sequence FROM settlement_heads WHERE round=?",
                (round_id,),
            ).fetchone()
            sequence = settlement.promotion_head.sequence
            if indexed is None:
                connection.execute(
                    "INSERT INTO settlement_heads VALUES (?, ?)", (round_id, sequence)
                )
            elif indexed[0] != sequence:
                raise ValueError("settlement head index is corrupt")

        connection.execute(
            "INSERT OR IGNORE INTO settlement_disputes "
            "SELECT s.round, c.detected_block FROM competition_settlements s "
            "JOIN round_conflicts c ON c.round=s.round"
        )
        connection.execute(
            "INSERT OR IGNORE INTO settlement_disputes "
            "SELECT h.round, MIN(c.detected_block) FROM settlement_heads h "
            "JOIN promotion_sources p ON h.promotion_sequence>=p.sequence "
            "JOIN round_conflicts c ON c.round=p.round GROUP BY h.round"
        )

    def fix_evidence_cutoff(
        self,
        round_: EvaluationRound,
        schedule: EvidenceCutoffSchedule,
        *,
        observed_block: int,
    ) -> dict:
        """Fix one explicit evidence cutoff before the corresponding round closes."""

        self._require_intake()

        round_ = EvaluationRound.model_validate_json(canonical_json_bytes(round_))
        schedule = EvidenceCutoffSchedule.model_validate_json(canonical_json_bytes(schedule))
        round_id = digest(round_)
        if round_.policy_sha256 != digest(self.policy):
            raise ValueError("round belongs to another policy")
        if schedule.policy_sha256 != digest(self.policy) or schedule.round_sha256 != round_id:
            raise ValueError("evidence cutoff schedule binding mismatch")
        if round_.runtime_sha256 != self.policy.evaluation_runtime_sha256:
            raise ValueError("round runtime does not match policy")
        schedule_id = evidence_cutoff_schedule_digest(schedule)
        schedule_body = canonical_json_bytes(schedule)
        with self._transaction() as connection:
            prior = connection.execute(
                "SELECT body, receipt FROM evidence_cutoff_schedules WHERE round=?",
                (round_id,),
            ).fetchone()
            if prior is not None:
                if prior[0] == schedule_body:
                    return json.loads(prior[1])
                raise ValueError("round already has a different evidence cutoff schedule")
            if not (
                round_.submission_close_block
                < round_.evaluation_close_block
                < round_.reveal_block
                < schedule.evidence_cutoff_block
                == round_.public_schedule.evidence_cutoff_block
                <= round_.valid_through_block
                <= self.policy.valid_through_block
            ):
                raise ValueError("evidence cutoff schedule has an invalid window")
            if (
                type(observed_block) is not int
                or not self.policy.valid_from_block
                <= observed_block
                <= round_.submission_close_block
            ):
                raise ValueError("evidence cutoff schedule has an invalid observation")
            if connection.execute(
                "SELECT 1 FROM evidence_cutoff_schedules WHERE round_sequence=?",
                (round_.sequence,),
            ).fetchone():
                raise ValueError("round sequence already has an evidence cutoff schedule")
            if connection.execute(
                "SELECT 1 FROM rounds WHERE digest=? OR sequence=?",
                (round_id, round_.sequence),
            ).fetchone():
                raise ValueError("evidence cutoff must be fixed before its round closes")
            _advance_block(connection, observed_block)
            receipt = {
                "schema": "umi-competition-evidence-cutoff-receipt/1",
                "policy_sha256": digest(self.policy),
                "round_sha256": round_id,
                "schedule_sha256": schedule_id,
                "evidence_cutoff_block": schedule.evidence_cutoff_block,
                "fixed_observed_block": observed_block,
                "chain_submission_authorized": False,
            }
            connection.execute(
                "INSERT INTO evidence_cutoff_schedules VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    round_id,
                    round_.sequence,
                    schedule.evidence_cutoff_block,
                    schedule_id,
                    schedule_body,
                    observed_block,
                    canonical_json_bytes(receipt),
                ),
            )
            return receipt

    def prepare_round(
        self,
        *,
        snapshot: RegistrationSnapshot,
        suite: EvaluationSuite,
        public_schedule: PublicRoundSchedule,
        eligible_tracks: tuple[Track, ...],
        intake_opened_block: int,
        evaluation_close_block: int,
        reveal_block: int,
        evidence_cutoff_block: int,
        valid_through_block: int,
        limits: PublicationReplayLimits,
    ) -> dict:
        """Freeze the complete current roster and cutoff in one transaction.

        This produces unsigned publication inputs. The caller must obtain the
        snapshot from its owned provider; this store has no finality port or key.
        An exact retry returns the original preparation without retiming it.
        """
        self._require_intake()
        snapshot = RegistrationSnapshot.model_validate_json(canonical_json_bytes(snapshot))
        suite = EvaluationSuite.model_validate_json(canonical_json_bytes(suite))
        public_schedule = PublicRoundSchedule.model_validate_json(
            canonical_json_bytes(public_schedule)
        )
        limits = PublicationReplayLimits.model_validate_json(canonical_json_bytes(limits))
        try:
            validate_suite_profile(suite, self.policy)
        except ValueError as error:
            raise ValueError(
                "round suite has the wrong policy or insufficient stratum coverage"
            ) from error
        if tuple(sorted(set(eligible_tracks))) != eligible_tracks or not eligible_tracks:
            raise ValueError("eligible tracks must be sorted and unique")
        if (
            type(intake_opened_block) is not int
            or intake_opened_block != public_schedule.intake_opened_block
            or not self.policy.valid_from_block <= intake_opened_block <= snapshot.block
        ):
            raise ValueError("round intake opening is outside the public schedule")
        window = {
            "evaluation_close_block": evaluation_close_block,
            "reveal_block": reveal_block,
            "valid_through_block": valid_through_block,
        }
        if any(
            type(v) is not int or not 0 <= v <= 2**53 - 1
            for v in (*window.values(), evidence_cutoff_block)
        ):
            raise ValueError("round window requires integer block numbers")
        if (
            evaluation_close_block != public_schedule.evaluation_close_block
            or reveal_block != public_schedule.protected_reference_reveal_block
            or evidence_cutoff_block != public_schedule.evidence_cutoff_block
            or valid_through_block != public_schedule.round_valid_through_block
        ):
            raise ValueError("round window differs from the public schedule")
        suite_id, policy_id = digest(suite), digest(self.policy)
        with self._transaction() as connection:
            launch = self._require_current_public_launch(connection)
            if launch is not None and (
                launch.round_schedule != public_schedule
                or launch.eligible_tracks != eligible_tracks
            ):
                raise ValueError("round preparation differs from the current public launch")
            prepared = self._prepared_round(connection, suite_id, limits)
            if prepared is not None:
                cutoff = prepared["cutoff_publication"]
                if prepared["intake_opened_block"] != intake_opened_block:
                    raise ValueError("suite already has a frozen intake opening")
                if (
                    cutoff["round"]["public_schedule"]
                    != public_schedule.model_dump(mode="json", by_alias=True)
                    or tuple(cutoff["round"]["eligible_tracks"]) != eligible_tracks
                ):
                    raise ValueError("suite already has a different public eligibility schedule")
                if any(cutoff["round"][key] != value for key, value in window.items()) or (
                    cutoff["cutoff_schedule"]["evidence_cutoff_block"] != evidence_cutoff_block
                ):
                    raise ValueError("suite already has a frozen round window")
                return prepared
            if not (
                public_schedule.roster_close_earliest_block
                <= snapshot.block
                <= public_schedule.roster_close_latest_block
            ):
                raise ValueError("round close is outside the public schedule")
            if self._baseline_conflicted(connection):
                raise ValueError("round preparation requires an unconflicted baseline")
            if connection.execute(
                "SELECT 1 FROM suite_usage WHERE suite=?", (suite_id,)
            ).fetchone():
                raise ValueError("evaluation suite was already used by a closed round")
            schedule_id = digest(public_schedule)
            if connection.execute(
                "SELECT 1 FROM public_schedule_usage WHERE schedule=?", (schedule_id,)
            ).fetchone():
                raise ValueError("public round schedule was already used by another round")
            if connection.execute(
                "SELECT 1 FROM evidence_cutoff_schedules s WHERE NOT EXISTS "
                "(SELECT 1 FROM rounds r WHERE r.digest=s.round)"
            ).fetchone():
                raise ValueError("a previously fixed cutoff still needs its round closed")
            head = connection.execute(
                "SELECT model FROM promotions ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            if head is None:
                raise ValueError("round preparation requires a preserved baseline")
            latest = connection.execute(
                "SELECT sequence, body FROM rounds ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            if latest and snapshot.block <= json.loads(latest[1])["submission_close_block"]:
                raise ValueError("round preparation must advance the admission boundary")
            keys = [
                identity(r.hotkey)
                for r in snapshot.registrations
                if r.uid < self.policy.maximum_uids
            ]
            placeholders = ",".join("?" for _ in keys) or "NULL"
            track_placeholders = ",".join("?" for _ in eligible_tracks)
            selected = connection.execute(
                "SELECT s.digest, length(s.body) FROM submissions s "
                "WHERE s.accepted_block>=? AND s.accepted_block<=? "
                f"AND s.hotkey IN ({placeholders}) "
                f"AND s.track IN ({track_placeholders}) "
                "AND s.expires_block>=? AND NOT EXISTS "
                "(SELECT 1 FROM submissions n WHERE n.hotkey=s.hotkey AND n.track=s.track "
                "AND n.sequence>s.sequence AND n.accepted_block<=?) ORDER BY s.digest LIMIT 513",
                (
                    intake_opened_block,
                    snapshot.block,
                    *keys,
                    *eligible_tracks,
                    evaluation_close_block,
                    snapshot.block,
                ),
            ).fetchall()
            if len(selected) > 512 or sum(size + 1 for _, size in selected) + 2 > min(
                limits.maximum_roster_bytes, limits.maximum_certificate_bytes
            ):
                raise ValueError("round preparation roster exceeds its byte or count bound")
            ids = [record[0] for record in selected]
            placeholders = ",".join("?" for _ in ids) or "NULL"
            rows = connection.execute(
                f"SELECT body FROM submissions WHERE digest IN ({placeholders}) ORDER BY digest",
                ids,
            ).fetchall()
            submissions = tuple(SignedSubmission.model_validate_json(row[0]) for row in rows)
            round_ = EvaluationRound(
                schema="umi-competition-round/2",
                policy_sha256=policy_id,
                sequence=1 if latest is None else latest[0] + 1,
                suite_sha256=suite_id,
                incumbent_model_sha256=head[0],
                runtime_sha256=self.policy.evaluation_runtime_sha256,
                public_schedule=public_schedule,
                eligible_tracks=eligible_tracks,
                roster=tuple(digest(s.submission) for s in submissions),
                submission_close_block=snapshot.block,
                **window,
            )
            round_id = digest(round_)
            schedule = EvidenceCutoffSchedule(
                schema="umi-competition-evidence-cutoff/1",
                policy_sha256=policy_id,
                round_sha256=round_id,
                evidence_cutoff_block=evidence_cutoff_block,
            )
            publication = build_cutoff_publication(
                round_=round_,
                cutoff_schedule=schedule,
                registration_snapshot=snapshot,
                submissions=submissions,
                policy=self.policy,
                limits=limits,
            )
            _advance_block(connection, snapshot.block)
            receipt = {
                "schema": "umi-competition-evidence-cutoff-receipt/1",
                "policy_sha256": policy_id,
                "round_sha256": round_id,
                "schedule_sha256": evidence_cutoff_schedule_digest(schedule),
                "evidence_cutoff_block": schedule.evidence_cutoff_block,
                "fixed_observed_block": snapshot.block,
                "chain_submission_authorized": False,
            }
            connection.execute(
                "INSERT INTO evidence_cutoff_schedules VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    round_id,
                    round_.sequence,
                    schedule.evidence_cutoff_block,
                    receipt["schedule_sha256"],
                    canonical_json_bytes(schedule),
                    snapshot.block,
                    canonical_json_bytes(receipt),
                ),
            )
            connection.execute(
                "INSERT INTO rounds VALUES (?, ?, ?)",
                (round_id, round_.sequence, canonical_json_bytes(round_)),
            )
            connection.execute("INSERT INTO suite_usage VALUES (?, ?)", (suite_id, round_id))
            connection.execute(
                "INSERT INTO public_schedule_usage VALUES (?, ?, ?)",
                (schedule_id, suite_id, round_id),
            )
            prepared = {
                "schema": "umi-competition-round-preparation/2",
                "intake_opened_block": intake_opened_block,
                "cutoff_publication": publication.model_dump(mode="json", by_alias=True),
                "submissions": [s.model_dump(mode="json", by_alias=True) for s in submissions],
                "cutoff_receipt": receipt,
                "chain_submission_authorized": False,
            }
            body = canonical_json_bytes(prepared)
            if len(body) > limits.maximum_certificate_bytes:
                raise ValueError("round preparation exceeds its byte bound")
            records, size = connection.execute(
                "SELECT COUNT(*), COALESCE(SUM(length(body)), 0) FROM round_preparations"
            ).fetchone()
            if (
                records >= self.preparation_capacity.maximum_records
                or size + len(body) > self.preparation_capacity.maximum_bytes
            ):
                raise ValueError("round preparation storage capacity is exhausted")
            connection.execute("INSERT INTO round_preparations VALUES (?, ?)", (suite_id, body))
            return prepared

    def prepared_round(self, suite_sha256: str, limits: PublicationReplayLimits) -> dict | None:
        """Recover original preparation after a caller crash, without advancing it."""
        _require_hex32(suite_sha256, "suite digest")
        limits = PublicationReplayLimits.model_validate_json(canonical_json_bytes(limits))
        with self._connection() as connection:
            return self._prepared_round(connection, suite_sha256, limits)

    def _prepared_round(self, connection, suite_id, limits):
        prior = connection.execute(
            "SELECT length(body) FROM round_preparations WHERE suite=?", (suite_id,)
        ).fetchone()
        if prior is None:
            return None
        if not 0 < prior[0] <= limits.maximum_certificate_bytes:
            raise ValueError("retained preparation exceeds its byte bound")
        raw = connection.execute(
            "SELECT body FROM round_preparations WHERE suite=?", (suite_id,)
        ).fetchone()[0]
        prepared = json.loads(raw)
        if (
            not isinstance(prepared, dict)
            or set(prepared)
            != {
                "schema",
                "intake_opened_block",
                "cutoff_publication",
                "submissions",
                "cutoff_receipt",
                "chain_submission_authorized",
            }
            or prepared["schema"] != "umi-competition-round-preparation/2"
            or type(prepared["intake_opened_block"]) is not int
            or prepared["chain_submission_authorized"] is not False
            or canonical_json_bytes(prepared) != raw
        ):
            raise ValueError("retained round preparation is corrupt")
        cutoff = CutoffPublication.model_validate_json(
            canonical_json_bytes(prepared["cutoff_publication"])
        )
        if not (
            self.policy.valid_from_block
            <= prepared["intake_opened_block"]
            == cutoff.round.public_schedule.intake_opened_block
            <= cutoff.round.submission_close_block
        ):
            raise ValueError("retained round preparation has an invalid intake opening")
        retained_submissions = prepared["submissions"]
        if not isinstance(retained_submissions, list):
            raise ValueError("retained round preparation submissions are not an array")
        try:
            submissions = tuple(
                SignedSubmission.model_validate_json(canonical_json_bytes(s))
                for s in retained_submissions
            )
        except (KeyError, TypeError, ValidationError, ValueError) as error:
            raise ValueError("retained round preparation has invalid submissions") from error
        expected = build_cutoff_publication(
            round_=cutoff.round,
            cutoff_schedule=cutoff.cutoff_schedule,
            registration_snapshot=cutoff.registration_snapshot,
            submissions=submissions,
            policy=self.policy,
            limits=limits,
        )
        round_id = digest(cutoff.round)
        round_row = connection.execute(
            "SELECT body FROM rounds WHERE digest=?", (round_id,)
        ).fetchone()
        schedule = connection.execute(
            "SELECT body, receipt FROM evidence_cutoff_schedules WHERE round=?", (round_id,)
        ).fetchone()
        usage = connection.execute(
            "SELECT round FROM suite_usage WHERE suite=?", (suite_id,)
        ).fetchone()
        schedule_usage = connection.execute(
            "SELECT suite, round FROM public_schedule_usage WHERE schedule=?",
            (digest(cutoff.round.public_schedule),),
        ).fetchone()
        if (
            cutoff != expected
            or cutoff.round.suite_sha256 != suite_id
            or round_row != (canonical_json_bytes(cutoff.round),)
            or schedule
            != (
                canonical_json_bytes(cutoff.cutoff_schedule),
                canonical_json_bytes(prepared["cutoff_receipt"]),
            )
            or usage != (round_id,)
            or schedule_usage != (suite_id, round_id)
        ):
            raise ValueError("retained round preparation differs from its frozen records")
        return prepared

    def close_round(
        self,
        round_: EvaluationRound,
        *,
        current_block: int,
    ) -> str:
        self._require_intake()
        round_ = EvaluationRound.model_validate_json(canonical_json_bytes(round_))
        if round_.policy_sha256 != digest(self.policy):
            raise ValueError("round belongs to another policy")
        if not (
            self.policy.valid_from_block
            <= round_.public_schedule.intake_opened_block
            < round_.submission_close_block
            <= current_block
            < round_.evaluation_close_block
            < round_.reveal_block
            <= round_.valid_through_block
            <= self.policy.valid_through_block
        ):
            raise ValueError("round cannot be published with an unusable or invalid window")
        if round_.runtime_sha256 != self.policy.evaluation_runtime_sha256:
            raise ValueError("round runtime does not match policy")
        with self._transaction() as connection:
            launch = self._require_current_public_launch(connection)
            if launch is not None and (
                launch.round_schedule != round_.public_schedule
                or launch.eligible_tracks != round_.eligible_tracks
            ):
                raise ValueError("round differs from the current public launch")
            prior = connection.execute(
                "SELECT body FROM rounds WHERE sequence=?", (round_.sequence,)
            ).fetchone()
            if prior:
                if prior[0] == canonical_json_bytes(round_):
                    return digest(round_)
                raise ValueError("round sequence is already closed")
            if launch is not None:
                raise ValueError(
                    "launch-bound rounds must be frozen from a finalized registration snapshot"
                )
            _advance_block(connection, current_block)
            latest_sequence = connection.execute("SELECT MAX(sequence) FROM rounds").fetchone()[0]
            if latest_sequence is not None and round_.sequence <= latest_sequence:
                raise ValueError("round sequence must increase")
            scheduled = connection.execute(
                "SELECT round FROM evidence_cutoff_schedules WHERE round_sequence=?",
                (round_.sequence,),
            ).fetchone()
            if scheduled is not None and scheduled[0] != digest(round_):
                raise ValueError("round differs from its fixed evidence cutoff schedule")
            if connection.execute(
                "SELECT 1 FROM suite_usage WHERE suite=?", (round_.suite_sha256,)
            ).fetchone():
                raise ValueError("evaluation suite was already used by a closed round")
            schedule_id = digest(round_.public_schedule)
            if connection.execute(
                "SELECT 1 FROM public_schedule_usage WHERE schedule=?", (schedule_id,)
            ).fetchone():
                raise ValueError("public round schedule was already used by another round")
            rows = connection.execute(
                "SELECT s.digest, s.expires_block FROM submissions s "
                "WHERE s.accepted_block>=? AND s.accepted_block<=? "
                f"AND s.track IN ({','.join('?' for _ in round_.eligible_tracks)}) "
                "AND NOT EXISTS (SELECT 1 FROM submissions n WHERE n.hotkey=s.hotkey "
                "AND n.track=s.track AND n.sequence>s.sequence AND n.accepted_block<=?)",
                (
                    round_.public_schedule.intake_opened_block,
                    round_.submission_close_block,
                    *round_.eligible_tracks,
                    round_.submission_close_block,
                ),
            ).fetchall()
            roster = sorted(d for d, expiry in rows if expiry >= round_.evaluation_close_block)
            if list(round_.roster) != roster:
                raise ValueError("round roster omits or adds an accepted current submission")
            baseline = connection.execute(
                "SELECT model FROM promotions ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            if baseline is None or baseline[0] != round_.incumbent_model_sha256:
                raise ValueError("round incumbent is not the preserved current baseline")
            connection.execute(
                "INSERT INTO rounds VALUES (?, ?, ?)",
                (digest(round_), round_.sequence, canonical_json_bytes(round_)),
            )
            connection.execute(
                "INSERT INTO suite_usage VALUES (?, ?)", (round_.suite_sha256, digest(round_))
            )
            connection.execute(
                "INSERT INTO public_schedule_usage VALUES (?, ?, ?)",
                (schedule_id, round_.suite_sha256, digest(round_)),
            )
            return digest(round_)

    def baseline(self) -> dict | None:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT body FROM promotions ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            return None if row is None else json.loads(row[0])

    def _require_intake(self):
        if self.role != "intake":
            raise ValueError("evaluator review receipts cannot authorize intake operations")

    def reviewed_promotion_head(self, round_sha256: str, *, maximum_bytes: int):
        """Read the local accepted promotion head; never import a caller's head."""
        _require_hex32(round_sha256, "round")
        if type(maximum_bytes) is not int or not 1 <= maximum_bytes <= 16 * 1024**2:
            raise ValueError("invalid promotion head byte bound")
        with self._connection() as connection:
            connection.execute("BEGIN")
            self._assert_action_allowed(connection, round_sha256)
            head = connection.execute(
                "SELECT sequence,digest,model,contributor FROM promotions "
                "ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            if head is None:
                raise ValueError("independently reviewed promotion history is missing")
            raw = _bounded_stored_body(connection, "promotions", "sequence", head[0], maximum_bytes)
            record = json.loads(raw)
            if not isinstance(record, dict):
                raise ValueError("independently reviewed promotion head is corrupt")
            contributor = record.get("contributor_hotkey")
            if (
                _record_digest(record) != head[1]
                or record.get("policy_sha256") != digest(self.policy)
                or record.get("sequence") != head[0]
                or record.get("model_sha256") != head[2]
                or head[3] != (None if contributor is None else identity(contributor))
            ):
                raise ValueError("independently reviewed promotion head is corrupt")
            if record["schema"] == "umi-model-baseline/2":
                self._read_agreed_promotion_receipt(connection, record, maximum_bytes=maximum_bytes)
            return PromotionHeadBinding(
                sequence=head[0],
                promotion_sha256=head[1],
                model_sha256=head[2],
                contributor_hotkey=contributor,
            )

    def project(
        self,
        *,
        round_: EvaluationRound,
        suite: EvaluationSuite,
        evaluations: tuple[tuple[SignedSubmission, AttestedResult], ...],
        snapshot: RegistrationSnapshot,
        current_block: int,
    ) -> WeightProjection:
        """Project only a durably closed round with one consistent baseline head."""
        self._require_intake()
        invalid: ValueError | None = None
        for signed, attested in evaluations:
            try:
                self.record_evaluation(
                    signed=signed,
                    attested=attested,
                    round_=round_,
                    suite=suite,
                    observed_block=current_block,
                )
            except ValueError as error:
                # An unrelated invalid entry must not discard a valid conflict
                # elsewhere in this batch. Each valid intake commits separately.
                invalid = error
        if invalid is not None:
            raise ValueError(
                "projection contains invalid evaluation evidence: " + str(invalid)
            ) from invalid
        with self._transaction() as connection:
            closed = connection.execute(
                "SELECT body FROM rounds WHERE digest=?", (digest(round_),)
            ).fetchone()
            if closed is None or closed[0] != canonical_json_bytes(round_):
                raise ValueError("projection round has not been closed in the admission log")
            self._assert_action_allowed(connection, digest(round_))
            _advance_block(connection, current_block)
            head = connection.execute(
                "SELECT body FROM promotions ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            if head is None:
                raise ValueError("projection requires a preserved baseline")
            baseline = json.loads(head[0])
            return project_weights(
                policy=self.policy,
                round_=round_,
                suite=suite,
                evaluations=tuple(
                    self._recorded_evaluation(connection, digest(round_), digest(signed.submission))
                    for signed, _ in evaluations
                ),
                snapshot=snapshot,
                current_block=current_block,
                promoted_model_sha256=baseline["model_sha256"],
                promoted_hotkey=baseline["contributor_hotkey"],
            )

    def settlement_material(
        self, round_: EvaluationRound, *, limits: PublicationReplayLimits
    ) -> dict:
        """Read a complete, bounded settlement input set in one SQLite snapshot.

        Select the earliest retained independent evidence for each roster entry.
        A prior settlement instead pins the exact evidence already used. Missing
        and late entries block the whole round; they never become miner failures.
        """
        round_ = EvaluationRound.model_validate_json(canonical_json_bytes(round_))
        limits = PublicationReplayLimits.model_validate_json(canonical_json_bytes(limits))
        round_id = digest(round_)
        with self._connection() as connection:
            connection.execute("BEGIN")
            self._assert_action_allowed(connection, round_id)
            raw = _bounded_stored_body(
                connection, "rounds", "digest", round_id, limits.maximum_certificate_bytes
            )
            if raw != canonical_json_bytes(round_) or round_.policy_sha256 != digest(self.policy):
                raise ValueError("settlement material differs from the closed round")
            _bounded_stored_body(
                connection,
                "evidence_cutoff_schedules",
                "round",
                round_id,
                limits.maximum_certificate_bytes,
            )
            cutoff = self._fixed_cutoff(connection, round_id)
            raw = _bounded_stored_body(
                connection,
                "competition_settlements",
                "round",
                round_id,
                limits.maximum_certificate_bytes,
                optional=True,
            )
            retained = None if raw is None else CompetitionSettlement.model_validate_json(raw)
            if retained is not None:
                stored_digest = connection.execute(
                    "SELECT digest FROM competition_settlements WHERE round=?", (round_id,)
                ).fetchone()[0]
                if (
                    competition_settlement_digest(retained) != stored_digest
                    or retained.round_sha256 != round_id
                    or retained.roster != round_.roster
                    or retained.cutoff_schedule != cutoff
                ):
                    raise ValueError("retained settlement material binding mismatch")
            prior = {} if retained is None else {r.submission_sha256: r for r in retained.results}
            submissions, evidence = [], []
            roster_bytes, evidence_bytes = 2, 2
            for submission_id in round_.roster:
                raw = _bounded_stored_body(
                    connection,
                    "submissions",
                    "digest",
                    submission_id,
                    limits.maximum_roster_bytes - roster_bytes,
                )
                roster_bytes += len(raw) + 1
                signed = SignedSubmission.model_validate_json(raw)
                if digest(signed.submission) != submission_id:
                    raise ValueError("settlement material submission binding mismatch")
                binding = prior.get(submission_id)
                if binding is None:
                    selected = connection.execute(
                        "SELECT kind,digest FROM ("
                        "SELECT 'scored' AS kind,digest,first_observed_block "
                        "FROM independent_evaluation_evidence WHERE round=? AND submission=? "
                        "UNION ALL SELECT 'void',digest,first_observed_block "
                        "FROM void_evaluation_evidence WHERE round=? AND submission=?) "
                        "ORDER BY first_observed_block,digest LIMIT 1",
                        (round_id, submission_id, round_id, submission_id),
                    ).fetchone()
                    if selected is None:
                        raise SettlementNotReadyError("complete roster evidence is not retained")
                    kind, evidence_id = selected
                    table, decision_column = (
                        ("void_evaluation_evidence", "decision")
                        if kind == "void"
                        else ("independent_evaluation_evidence", "result")
                    )
                else:
                    evidence_id = binding_ids(binding)[1]
                    table, decision_column = outcome_storage(binding)
                raw = _bounded_stored_body(
                    connection,
                    table,
                    "digest",
                    evidence_id,
                    limits.maximum_evidence_bytes - evidence_bytes,
                )
                evidence_bytes += len(raw) + 1
                independent = parse_outcome(json.loads(raw))
                row = connection.execute(
                    f"SELECT round,submission,{decision_column},first_observed_block "
                    f"FROM {table} WHERE digest=?",
                    (evidence_id,),
                ).fetchone()
                result_id = outcome_decision_digest(independent)
                if row[:3] != (round_id, submission_id, result_id) or (
                    outcome_digest(independent) != evidence_id
                    or outcome_storage(independent) != (table, decision_column)
                ):
                    raise ValueError("settlement material evidence binding mismatch")
                if type(row[3]) is not int or not round_.reveal_block <= row[3]:
                    raise ValueError("settlement evidence has an invalid first observation")
                if row[3] > cutoff.evidence_cutoff_block:
                    raise SettlementNotReadyError("roster evidence was first observed after cutoff")
                if binding is not None and (
                    binding_ids(binding)[0] != result_id or binding.first_observed_block != row[3]
                ):
                    raise ValueError("retained settlement evidence observation changed")
                submissions.append(signed)
                evidence.append((signed, independent))
        return {
            "submissions": tuple(submissions),
            "evidence": tuple(evidence),
            "cutoff_schedule": cutoff,
            "retained_settlement": retained,
        }

    def settle(
        self,
        *,
        round_: EvaluationRound,
        suite: EvaluationSuite,
        evidence: tuple[tuple[SignedSubmission, OutcomeEvidence], ...],
        snapshot: RegistrationSnapshot,
        current_block: int,
    ) -> dict:
        """Persist one immutable no-weight settlement after its fixed evidence cutoff."""

        self._require_intake()

        invalid: ValueError | None = None
        for signed, independent in evidence:
            try:
                if isinstance(independent, VoidEvaluationEvidence):
                    self.record_void_evaluation(
                        evidence=independent,
                        suite=suite,
                        observed_block=current_block,
                    )
                    continue
                # The old quorum certificate is useful conflict evidence even
                # when the stronger per-evaluator run record later fails.
                self.record_evaluation(
                    signed=signed,
                    attested=independent.attested_result,
                    round_=round_,
                    suite=suite,
                    observed_block=current_block,
                )
            except ValueError as error:
                invalid = error
        if invalid is not None:
            raise ValueError(
                "settlement contains invalid quorum evidence: " + str(invalid)
            ) from invalid

        round_ = EvaluationRound.model_validate_json(canonical_json_bytes(round_))
        suite = EvaluationSuite.model_validate_json(canonical_json_bytes(suite))
        normalized = tuple(
            (
                SignedSubmission.model_validate_json(canonical_json_bytes(signed)),
                parse_outcome(independent),
            )
            for signed, independent in evidence
        )
        round_id = digest(round_)
        with self._connection() as connection:
            cutoff = self._fixed_cutoff(connection, round_id)

        if type(current_block) is not int:
            raise ValueError("settlement observation block must be an integer")
        if current_block <= cutoff.evidence_cutoff_block:
            invalid = None
            for signed, independent in normalized:
                try:
                    if isinstance(independent, VoidEvaluationEvidence):
                        continue  # Already retained with the actual observation above.
                    self._store_independent_evaluation(
                        signed=signed,
                        evidence=independent,
                        round_=round_,
                        suite=suite,
                        observed_block=current_block,
                    )
                except ValueError as error:
                    invalid = error
            if invalid is not None:
                raise ValueError(
                    "settlement contains invalid independent evidence: " + str(invalid)
                ) from invalid

        snapshot = RegistrationSnapshot.model_validate_json(canonical_json_bytes(snapshot))
        supplied: dict[str, tuple[SignedSubmission, OutcomeEvidence, str]] = {}
        for signed, independent in normalized:
            submission_id = digest(signed.submission)
            if submission_id in supplied:
                raise ValueError("settlement contains duplicate roster evidence")
            supplied[submission_id] = (
                signed,
                independent,
                outcome_digest(independent),
            )

        with self._transaction() as connection:
            closed = connection.execute(
                "SELECT body FROM rounds WHERE digest=?", (round_id,)
            ).fetchone()
            if closed is None or closed[0] != canonical_json_bytes(round_):
                raise ValueError("settlement round has not been closed in the admission log")
            cutoff = self._fixed_cutoff(connection, round_id)
            self._assert_action_allowed(connection, round_id)
            if set(supplied) != set(round_.roster):
                raise ValueError("settlement requires the exact complete round roster")

            existing = connection.execute(
                "SELECT digest, body FROM competition_settlements WHERE round=?", (round_id,)
            ).fetchone()
            if existing is not None:
                settlement = CompetitionSettlement.model_validate_json(existing[1])
                if competition_settlement_digest(settlement) != existing[0]:
                    raise ValueError("stored competition settlement is corrupt")
                if not _same_settlement_request(
                    settlement,
                    suite=suite,
                    snapshot=snapshot,
                    supplied=supplied,
                ):
                    raise ValueError("round already has a settlement with different inputs")
                return settlement.model_dump(mode="json", by_alias=True)

            if not (cutoff.evidence_cutoff_block <= current_block <= round_.valid_through_block):
                raise ValueError("settlement observation is outside its fixed usable window")
            _advance_block(connection, current_block)

            replay_entries = []
            bindings = []
            for submission_id in round_.roster:
                caller_signed, caller_evidence, evidence_id = supplied[submission_id]
                table, decision_column = outcome_storage(caller_evidence)
                row = connection.execute(
                    f"SELECT round, submission, {decision_column}, body, first_observed_block "
                    f"FROM {table} WHERE digest=?",
                    (evidence_id,),
                ).fetchone()
                if row is None:
                    raise ValueError("independent evidence was not durably recorded by cutoff")
                stored_evidence = parse_outcome(json.loads(row[3]))
                expected = (
                    round_id,
                    submission_id,
                    outcome_decision_digest(caller_evidence),
                    canonical_json_bytes(caller_evidence),
                )
                if row[:4] != expected or outcome_digest(stored_evidence) != evidence_id:
                    raise ValueError("stored independent evidence binding is corrupt")
                if row[4] > cutoff.evidence_cutoff_block:
                    raise ValueError("independent evidence was first observed after cutoff")
                if isinstance(stored_evidence, VoidEvaluationEvidence):
                    raw = connection.execute(
                        "SELECT body FROM submissions WHERE digest=?", (submission_id,)
                    ).fetchone()
                    recorded_signed = SignedSubmission.model_validate_json(raw[0])
                else:
                    recorded_signed, recorded_attested = self._recorded_evaluation(
                        connection, round_id, submission_id
                    )
                    if digest(recorded_attested.result) != row[2]:
                        raise ValueError("independent evidence differs from recorded quorum result")
                if recorded_signed != caller_signed:
                    raise ValueError("settlement changes the retained signed submission")
                replay_outcome(
                    stored_evidence,
                    recorded_signed,
                    round_,
                    suite,
                    self.policy,
                    current_block=current_block,
                )
                replay_entries.append((recorded_signed, stored_evidence))
                bindings.append(outcome_binding(submission_id, stored_evidence, row[4]))

            head = connection.execute(
                "SELECT sequence, digest, model, contributor, body FROM promotions "
                "ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            if head is None:
                raise ValueError("settlement requires a preserved promotion head")
            baseline = json.loads(head[4])
            contributor = baseline.get("contributor_hotkey")
            if (
                _record_digest(baseline) != head[1]
                or baseline.get("sequence") != head[0]
                or baseline.get("model_sha256") != head[2]
                or head[3] != (None if contributor is None else identity(contributor))
            ):
                raise ValueError("preserved promotion head is corrupt")

            projection = project_weights(
                policy=self.policy,
                round_=round_,
                suite=suite,
                evaluations=tuple(
                    (signed, independent.attested_result)
                    for signed, independent in replay_entries
                    if isinstance(independent, IndependentEvaluationEvidence)
                ),
                voids=tuple(e for _, e in replay_entries if isinstance(e, VoidEvaluationEvidence)),
                snapshot=snapshot,
                current_block=current_block,
                promoted_model_sha256=baseline["model_sha256"],
                promoted_hotkey=contributor,
            )
            settlement = CompetitionSettlement(
                schema=(
                    "umi-competition-settlement/2"
                    if any(isinstance(e, VoidEvaluationEvidence) for _, e in replay_entries)
                    else "umi-competition-settlement/1"
                ),
                policy_sha256=digest(self.policy),
                round_sha256=round_id,
                cutoff_schedule=cutoff,
                roster=round_.roster,
                results=tuple(bindings),
                suite=suite,
                registration_snapshot=snapshot,
                promotion_head=PromotionHeadBinding(
                    sequence=head[0],
                    promotion_sha256=head[1],
                    model_sha256=head[2],
                    contributor_hotkey=contributor,
                ),
                projection=projection,
                observed_block=current_block,
            )
            settlement_id = competition_settlement_digest(settlement)
            connection.execute(
                "INSERT INTO competition_settlements VALUES (?, ?, ?)",
                (round_id, settlement_id, canonical_json_bytes(settlement)),
            )
            connection.execute("INSERT INTO settlement_heads VALUES (?, ?)", (round_id, head[0]))
            return settlement.model_dump(mode="json", by_alias=True)

    @staticmethod
    def _fixed_cutoff(connection: sqlite3.Connection, round_sha256: str) -> EvidenceCutoffSchedule:
        row = connection.execute(
            "SELECT cutoff_block, digest, body FROM evidence_cutoff_schedules WHERE round=?",
            (round_sha256,),
        ).fetchone()
        if row is None:
            raise ValueError("round has no pre-fixed evidence cutoff schedule")
        schedule = EvidenceCutoffSchedule.model_validate_json(row[2])
        if (
            schedule.round_sha256 != round_sha256
            or schedule.evidence_cutoff_block != row[0]
            or evidence_cutoff_schedule_digest(schedule) != row[1]
        ):
            raise ValueError("stored evidence cutoff schedule is corrupt")
        return schedule

    def initialize_baseline(self, bundle: ModelBundle, archive: Path) -> dict:
        """Import an operator-selected historical baseline with no reward attribution."""
        verify_preserved_bundle(bundle, archive, self.policy)
        record = {
            "schema": "umi-model-baseline/1",
            "sequence": 0,
            "policy_sha256": digest(self.policy),
            "model_sha256": digest(bundle),
            "contributor_hotkey": None,
            "previous_promotion_sha256": None,
            "kind": "initial_reference_no_reward",
        }
        with self._transaction() as connection:
            prior = connection.execute(
                "SELECT body FROM promotions ORDER BY sequence LIMIT 1"
            ).fetchone()
            if prior:
                if json.loads(prior[0]) == record:
                    return record
                raise ValueError("initial baseline is already set")
            record_hash = _record_digest(record)
            connection.execute(
                "INSERT INTO promotions VALUES (?, ?, ?, ?, ?)",
                (0, record_hash, digest(bundle), None, canonical_json_bytes(record)),
            )
            connection.execute(
                "INSERT INTO model_identities VALUES (?, ?)",
                (model_content_digest(bundle), digest(bundle)),
            )
        return record

    def promote(
        self,
        *,
        signed: SignedSubmission,
        attested: AttestedResult,
        round_: EvaluationRound,
        suite: EvaluationSuite,
        review: AttestedPromotionReview,
        archive: Path,
        snapshot: RegistrationSnapshot,
        current_block: int,
    ) -> dict:
        self.record_evaluation(
            signed=signed,
            attested=attested,
            round_=round_,
            suite=suite,
            observed_block=current_block,
        )
        with self._connection() as connection:
            self._assert_action_allowed(connection, digest(round_))
            signed, attested = self._recorded_evaluation(
                connection, digest(round_), digest(signed.submission)
            )
        sub = signed.submission
        if sub.track != "model" or sub.model_bundle is None:
            raise ValueError("only contributed offline bundles can be promoted")
        validate_admission(signed, self.policy, snapshot, current_block)
        candidate, incumbent = replay_evaluation(
            attested,
            signed,
            round_,
            suite,
            self.policy,
            current_block=current_block,
        )
        if not qualifies_for_promotion(candidate, incumbent, self.policy):
            raise ValueError("candidate did not clear every promotion quality gate")
        review = AttestedPromotionReview.model_validate_json(canonical_json_bytes(review))
        verify_review(review, self.policy)
        if (
            review.review.model_sha256 != sub.model_revision
            or review.review.incumbent_model_sha256 != round_.incumbent_model_sha256
            or review.review.evaluation_result_sha256 != digest(attested.result)
        ):
            raise ValueError("promotion review does not bind this paired evaluation")
        agreed = isinstance(review.review, AgreedPromotionReview)
        if agreed:
            _validate_agreed_review(review.review, signed, attested, round_)
        if sub.model_bundle.parent_baseline_sha256 not in {None, round_.incumbent_model_sha256}:
            raise ValueError("candidate declares a different parent baseline")
        verify_preserved_bundle(sub.model_bundle, archive, self.policy)
        with self._transaction() as connection:
            self._assert_action_allowed(connection, digest(round_))
            if not connection.execute(
                "SELECT 1 FROM rounds WHERE digest=?", (digest(round_),)
            ).fetchone():
                raise ValueError("promotion round has not been closed in the admission log")
            _advance_block(connection, current_block)
            submitted = connection.execute(
                "SELECT 1 FROM submissions WHERE digest=?", (digest(sub),)
            ).fetchone()
            if submitted is None:
                raise ValueError("promotion submission is absent from the admission log")
            prior = connection.execute(
                "SELECT body FROM promotions WHERE model=?", (sub.model_revision,)
            ).fetchone()
            if prior:
                record = json.loads(prior[0])
                if record.get("submission_sha256") == digest(sub):
                    if (agreed or record["schema"] == "umi-model-baseline/2") and (
                        not agreed
                        or record != _agreed_promotion_record(signed, attested, review.review)
                    ):
                        raise ValueError("agreed promotion retry changes its decision")
                    if agreed:
                        self._read_agreed_promotion_receipt(connection, record)
                    return record
                raise ValueError("model was already promoted; attribution cannot be reassigned")
            if connection.execute(
                "SELECT 1 FROM model_identities WHERE content=?",
                (model_content_digest(sub.model_bundle),),
            ).fetchone():
                raise ValueError("runnable model content was already preserved as a baseline")
            head = connection.execute(
                "SELECT sequence, digest, model FROM promotions ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            if head is None or head[2] != round_.incumbent_model_sha256:
                raise ValueError("baseline changed; a fresh paired evaluation is required")
            if agreed and (
                review.review.previous_promotion_sha256 != head[1]
                or review.review.sequence != head[0] + 1
            ):
                raise ValueError("agreed promotion does not extend the reviewed history head")
            record = {
                "schema": "umi-model-baseline/1",
                "sequence": head[0] + 1,
                "policy_sha256": digest(self.policy),
                "model_sha256": sub.model_revision,
                "contributor_hotkey": sub.hotkey,
                "previous_promotion_sha256": head[1],
                "submission_sha256": digest(sub),
                "evaluation": attested.model_dump(mode="json", by_alias=True),
                "review": review.model_dump(mode="json", by_alias=True),
                "promoted_at_block": current_block,
                "kind": "verified_model_promotion_no_weight",
            }
            if agreed:
                record = _agreed_promotion_record(signed, attested, review.review)
                connection.execute(
                    "INSERT INTO promotion_receipts VALUES (?, ?, ?, ?)",
                    (
                        head[0] + 1,
                        current_block,
                        canonical_json_bytes(attested),
                        canonical_json_bytes(review),
                    ),
                )
            connection.execute(
                "INSERT INTO promotions VALUES (?, ?, ?, ?, ?)",
                (
                    head[0] + 1,
                    _record_digest(record),
                    sub.model_revision,
                    identity(sub.hotkey),
                    canonical_json_bytes(record),
                ),
            )
            connection.execute(
                "INSERT INTO model_identities VALUES (?, ?)",
                (model_content_digest(sub.model_bundle), sub.model_revision),
            )
            connection.execute(
                "INSERT INTO promotion_sources VALUES (?, ?)",
                (head[0] + 1, digest(round_)),
            )
            return record


def _validate_agreed_review(review, signed, attested, round_) -> None:
    if (
        review.round_sha256 != digest(round_)
        or review.submission_sha256 != digest(signed.submission)
        or review.evaluation_result_sha256 != digest(attested.result)
        or review.model_sha256 != signed.submission.model_revision
        or review.incumbent_model_sha256 != round_.incumbent_model_sha256
    ):
        raise ValueError("agreed promotion review does not bind its local evaluation")


def _agreed_promotion_record(signed, attested, review: AgreedPromotionReview) -> dict:
    # Quorum certificates and actual observation blocks belong in the local
    # receipt. Valid signature ordering/supersets cannot fork the shared head.
    return {
        "schema": "umi-model-baseline/2",
        "sequence": review.sequence,
        "policy_sha256": review.policy_sha256,
        "model_sha256": signed.submission.model_revision,
        "contributor_hotkey": signed.submission.hotkey,
        "previous_promotion_sha256": review.previous_promotion_sha256,
        "submission_sha256": digest(signed.submission),
        "evaluation_result": attested.result.model_dump(mode="json", by_alias=True),
        "review": review.model_dump(mode="json", by_alias=True),
        "kind": "verified_model_promotion_no_weight",
    }


def _bounded_stored_body(connection, table, key_name, key, maximum_bytes, *, optional=False):
    # Table/column names are fixed internal call sites, never HTTP input.
    size = connection.execute(
        f"SELECT length(CAST(body AS BLOB)) FROM {table} WHERE {key_name}=?", (key,)
    ).fetchone()
    if size is None:
        if optional:
            return None
        raise ValueError("settlement material is missing a retained record")
    if type(size[0]) is not int or not 0 < size[0] <= maximum_bytes:
        raise ValueError("settlement material exceeds its byte bound")
    raw = connection.execute(f"SELECT body FROM {table} WHERE {key_name}=?", (key,)).fetchone()[0]
    if isinstance(raw, str):
        raw = raw.encode("utf-8")
    if raw != canonical_json_bytes(json.loads(raw)):
        raise ValueError("settlement material is not canonical")
    return raw


def _same_settlement_request(
    settlement: CompetitionSettlement,
    *,
    suite: EvaluationSuite,
    snapshot: RegistrationSnapshot,
    supplied: dict[str, tuple[SignedSubmission, OutcomeEvidence, str]],
) -> bool:
    if settlement.suite != suite or settlement.registration_snapshot != snapshot:
        return False
    expected = {item.submission_sha256: binding_ids(item) for item in settlement.results}
    actual = {
        submission_id: (outcome_decision_digest(evidence), evidence_id)
        for submission_id, (_signed, evidence, evidence_id) in supplied.items()
    }
    return expected == actual


def _require_hex32(value: str, label: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"invalid {label}")


def _record_digest(record: dict) -> str:
    import hashlib

    return hashlib.sha256(b"umi-baseline-history-v1\0" + canonical_json_bytes(record)).hexdigest()


def _advance_block(connection: sqlite3.Connection, block: int) -> None:
    previous = connection.execute(
        "SELECT value FROM metadata WHERE key='observed_block'"
    ).fetchone()
    if previous and block < int(previous[0]):
        raise ValueError("competition state cannot move to an earlier finalized block")
    connection.execute(
        "INSERT OR REPLACE INTO metadata VALUES ('observed_block', ?)", (str(block),)
    )
