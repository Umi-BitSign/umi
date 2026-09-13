"""Owned-head round preparation and independent cutoff endorsement transport.

The coordinator has no wallet. Each evaluator rechecks the proposal's exact
registration snapshot through its own provider and durably binds its vote before
signing. Cutoff certificates alone do not authorize execution or weights.
"""

from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import stat
import time
from contextlib import asynccontextmanager, contextmanager
from pathlib import Path
from typing import Annotated, Literal

import httpx
from fastapi import FastAPI, HTTPException, Request
from pydantic import Field, model_validator
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.responses import Response

from .competition_chain import CompetitionChainConfig, FinalizedRegistrationProvider
from .competition_client import validate_intake_origin
from .competition_evaluator import Directory, _lock_file, _private, _publish, _read
from .competition_execution import execution_boundary
from .competition_publication import (
    CutoffPublication,
    PublicationReplayLimits,
    SignedCutoffPublication,
    build_cutoff_publication,
    cutoff_publication_digest,
    sign_cutoff_publication,
    verify_cutoff_publication,
)
from .competition_store import CompetitionStore
from .competition_work_plans import RoundWorkConfig
from .crypto import verify_response_signature
from .nonce import SQLiteNonceStore
from .open_competition import (
    CompetitionPolicy,
    EvaluationSuite,
    Hotkey,
    Signature,
    SignedSubmission,
    digest,
    identity,
    sign_object,
    verify_signature,
)
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

MAX_BYTES = 16 * 1024**2
ROUTE = "/v1/competition/rounds"
Block = Annotated[int, Field(ge=0, le=2**53 - 1)]


class RoundPlan(StrictProtocolModel):
    """Private operator input with explicit windows, never a remote request."""

    schema_: Literal["umi-round-plan/1"] = Field(alias="schema")
    suite: EvaluationSuite
    not_before_block: Block
    admission_close_by_block: Block
    signing_close_block: Block
    evaluation_close_block: Block
    reveal_block: Block
    evidence_cutoff_block: Block
    valid_through_block: Block

    @model_validator(mode="after")
    def windows(self):
        if not (
            self.not_before_block
            <= self.admission_close_by_block
            < self.signing_close_block
            < self.evaluation_close_block
            < self.reveal_block
            <= self.evidence_cutoff_block
            <= self.valid_through_block
        ):
            raise ValueError("round plan windows are not ordered")
        return self


class RoundProposal(StrictProtocolModel):
    schema_: Literal["umi-round-proposal/1"] = Field(alias="schema")
    cutoff: CutoffPublication
    submissions: Annotated[tuple[SignedSubmission, ...], Field(min_length=1, max_length=512)]
    signing_close_block: Block
    chain_submission_authorized: Literal[False] = False


class CutoffEndorsement(StrictProtocolModel):
    proposal_sha256: Hex32
    signature: Signature


class RoundQuery(StrictProtocolModel):
    schema_: Literal["umi-round-query/1"] = Field(alias="schema")
    policy_sha256: Hex32
    hotkey: Hotkey
    nonce_unix_ns: Annotated[str, Field(pattern=r"^[1-9][0-9]{0,18}$")]
    after_sequence: Block = 0
    vote: CutoffEndorsement | None = None

    @model_validator(mode="after")
    def parameters(self):
        if int(self.nonce_unix_ns) > 2**63 - 1 or (
            self.vote is not None and self.after_sequence != 0
        ):
            raise ValueError("invalid round query parameters")
        return self


class SignedRoundQuery(StrictProtocolModel):
    query: RoundQuery
    signature: Signature

    @model_validator(mode="after")
    def authenticate(self):
        if identity(self.query.hotkey) != identity(self.signature.hotkey):
            raise ValueError("round query signer mismatch")
        verify_signature(self.query, self.signature)
        return self


class RoundReply(StrictProtocolModel):
    query_sha256: Hex32
    policy_sha256: Hex32
    proposals: Annotated[tuple[RoundProposal, ...], Field(max_length=4)] = ()
    accepted_proposal_sha256: Hex32 | None = None
    chain_submission_authorized: Literal[False] = False


class RoundCoordinatorConfig(StrictProtocolModel):
    schema_: Literal["umi-round-coordinator-config/1"] = Field(alias="schema")
    policy_sha256: Hex32
    chain: CompetitionChainConfig
    state_directory: Directory
    intake_directory: Directory
    plan_directory: Directory
    certificate_directory: Directory
    replay_limits: PublicationReplayLimits
    work: RoundWorkConfig | None = None
    maximum_rounds: Annotated[int, Field(ge=1, le=65536)] = 1024
    maximum_journal_bytes: Annotated[int, Field(ge=1024, le=16 * 1024**3)] = 1024**3
    poll_seconds: Annotated[int, Field(ge=1, le=30)] = 5
    host: Literal["127.0.0.1", "::1"] = "127.0.0.1"
    port: Annotated[int, Field(ge=1024, le=65535)] = 8101
    no_weight: Literal[True] = True

    @model_validator(mode="after")
    def bindings(self):
        paths = [
            Path(p).resolve()
            for p in (
                self.state_directory,
                self.intake_directory,
                self.plan_directory,
                self.certificate_directory,
                self.chain.state_directory,
            )
        ]
        if self.work is not None:
            paths.extend(
                Path(p).resolve()
                for p in (
                    self.work.state_directory,
                    self.work.asset_directory,
                    self.work.order_directory,
                    self.work.publication_directory,
                    self.work.transport_chain.state_directory,
                )
            )
            if self.work.transport_chain.policy_sha256 != self.policy_sha256 or (
                self.work.transport_chain.collection_timeout_seconds > 15
            ):
                raise ValueError("work preparation requires bounded matching transport finality")
        if any(
            a == b or a in b.parents or b in a.parents
            for i, a in enumerate(paths)
            for b in paths[i + 1 :]
        ):
            raise ValueError("round coordinator directories must not overlap")
        if self.chain.policy_sha256 != self.policy_sha256 or (
            self.chain.collection_timeout_seconds > 15
        ):
            raise ValueError("round coordinator requires a matching bounded finality provider")
        if (
            max(
                self.replay_limits.maximum_certificate_bytes,
                self.replay_limits.maximum_roster_bytes,
            )
            > MAX_BYTES // 4
        ):
            raise ValueError("round replay limits exceed the bounded transport profile")
        return self


def validate_proposal(proposal, policy, limits):
    raw = canonical_json_bytes(proposal)
    if len(raw) > MAX_BYTES // 4:
        raise ValueError("round proposal exceeds its byte bound")
    proposal = RoundProposal.model_validate_json(raw)
    cutoff = proposal.cutoff
    if build_cutoff_publication(
        round_=cutoff.round,
        cutoff_schedule=cutoff.cutoff_schedule,
        registration_snapshot=cutoff.registration_snapshot,
        submissions=proposal.submissions,
        policy=policy,
        limits=limits,
    ) != cutoff or not (
        cutoff.registration_snapshot.block
        == cutoff.round.submission_close_block
        < proposal.signing_close_block
        < cutoff.round.evaluation_close_block
    ):
        raise ValueError("round proposal bindings or signing window differ")
    return proposal


def eligible_signer(hotkey, proposal, policy):
    groups = {identity(e.hotkey): e.control_group for e in policy.evaluators}
    miners = {identity(s.submission.hotkey) for s in proposal.submissions}
    forbidden = {groups[k] for k in miners if k in groups}
    key = identity(hotkey)
    return key in groups and key not in miners and groups[key] not in forbidden


def verify_endorsement(vote, proposal, policy):
    vote = CutoffEndorsement.model_validate_json(canonical_json_bytes(vote))
    sig = vote.signature
    if (
        vote.proposal_sha256 != digest(proposal)
        or not eligible_signer(sig.hotkey, proposal, policy)
        or not verify_response_signature(
            cutoff_publication_digest(proposal.cutoff),
            hotkey_ss58=sig.hotkey,
            scheme=sig.scheme,
            signature=sig.signature,
        )
    ):
        raise ValueError("invalid, unauthorized or self-interested cutoff endorsement")
    return vote


class RoundJournal:
    """Bounded immutable records and durable conflict holds, shared by both roles."""

    def __init__(self, root, binding, *, maximum_rounds=1024, maximum_bytes=1024**3):
        if (
            type(maximum_rounds) is not int
            or not 1 <= maximum_rounds <= 65536
            or (type(maximum_bytes) is not int or not 1024 <= maximum_bytes <= 16 * 1024**3)
        ):
            raise ValueError("round journal requires bounded capacity")
        self.root, self.maximum_rounds, self.maximum_bytes = root, maximum_rounds, maximum_bytes
        _private(root)
        self.path = root / "rounds.sqlite3"
        self._check_files()
        os.close(os.open(self.path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600))
        with self.transaction() as db:
            db.execute("CREATE TABLE IF NOT EXISTS binding (body BLOB NOT NULL)")
            raw = canonical_json_bytes(binding)
            if len(raw) > MAX_BYTES:
                raise ValueError("round journal binding exceeds its byte bound")
            sizes = db.execute("SELECT LENGTH(body) FROM binding LIMIT 2").fetchall()
            if len(sizes) > 1 or (sizes and sizes[0][0] != len(raw)):
                raise ValueError("round journal configuration changed")
            old = db.execute("SELECT body FROM binding LIMIT 1").fetchall()
            if old and (len(old) != 1 or bytes(old[0][0]) != raw):
                raise ValueError("round journal configuration changed")
            if not old:
                db.execute("INSERT INTO binding VALUES (?)", (raw,))
            db.execute(
                "CREATE TABLE IF NOT EXISTS records (kind TEXT, id TEXT, body BLOB NOT NULL, "
                "PRIMARY KEY(kind,id))"
            )
            db.execute("CREATE TABLE IF NOT EXISTS holds (id TEXT PRIMARY KEY)")
            db.execute("CREATE TABLE IF NOT EXISTS highwater (block INTEGER NOT NULL)")
            db.execute(
                "CREATE TABLE IF NOT EXISTS round_index "
                "(sequence INTEGER PRIMARY KEY, suite TEXT UNIQUE, proposal TEXT UNIQUE, "
                "snapshot_block INTEGER NOT NULL, signing_close INTEGER NOT NULL)"
            )
            db.execute(
                "CREATE TABLE IF NOT EXISTS plan_index "
                "(suite TEXT PRIMARY KEY, opens INTEGER NOT NULL, closes INTEGER NOT NULL)"
            )
            if "execution_close" not in {
                r[1] for r in db.execute("PRAGMA table_info(round_index)")
            }:
                db.execute(
                    "ALTER TABLE round_index ADD COLUMN execution_close INTEGER NOT NULL DEFAULT 0"
                )
                rows = db.execute(
                    "SELECT sequence,suite FROM round_index LIMIT ?", (maximum_rounds + 1,)
                ).fetchall()
                if len(rows) > maximum_rounds:
                    raise ValueError("round journal index capacity exhausted")
                for sequence, suite in rows:
                    raw = self._record(db, "prepared", suite)
                    if raw is None:
                        raise ValueError("round index is missing its prepared record")
                    proposal = RoundProposal.model_validate_json(raw)
                    if (
                        proposal.cutoff.round.sequence != sequence
                        or proposal.cutoff.round.suite_sha256 != suite
                    ):
                        raise ValueError("round index migration binding mismatch")
                    db.execute(
                        "UPDATE round_index SET execution_close=? WHERE sequence=?",
                        (proposal.cutoff.round.evaluation_close_block, sequence),
                    )

    def _check_files(self):
        _private(self.root)
        for suffix in ("", "-journal", "-wal", "-shm"):
            p = Path(str(self.path) + suffix)
            if p.is_symlink():
                raise ValueError("round journal symlink")
            if p.exists():
                s = p.stat()
                if (
                    not stat.S_ISREG(s.st_mode)
                    or s.st_nlink != 1
                    or (s.st_uid != os.getuid() or s.st_mode & 0o077)
                ):
                    raise ValueError("round journal must be private and owned")

    @contextmanager
    def transaction(self):
        self._check_files()
        db = sqlite3.connect(self.path, isolation_level=None, timeout=5)
        try:
            db.execute("PRAGMA synchronous=FULL")
            db.execute(f"PRAGMA max_page_count={(self.maximum_bytes + 16 * 1024**2) // 4096}")
            db.execute("BEGIN IMMEDIATE")
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def put(self, kind, key, value):
        raw = canonical_json_bytes(value)
        if len(raw) > MAX_BYTES:
            raise ValueError("round journal object exceeds its byte bound")
        conflict = False
        with self.transaction() as db:
            if db.execute("SELECT 1 FROM holds WHERE id=?", (key,)).fetchone():
                raise ValueError("round journal conflict held")
            prior = self._record(db, kind, key)
            if prior:
                conflict = prior != raw
                if conflict:
                    db.execute("INSERT OR IGNORE INTO holds VALUES (?)", (key,))
            else:
                if kind in {"plan", "prepared", "intent", "suite", "certificate"} and (
                    db.execute("SELECT COUNT(*) FROM records WHERE kind=?", (kind,)).fetchone()[0]
                    >= self.maximum_rounds
                ):
                    raise ValueError("round journal record capacity exhausted")
                count, used = db.execute(
                    "SELECT COUNT(*),COALESCE(SUM(LENGTH(body)),0) FROM records"
                ).fetchone()
                if used + len(raw) > self.maximum_bytes or (count >= self.maximum_rounds * 80):
                    raise ValueError("round journal capacity exhausted")
                db.execute("INSERT INTO records VALUES (?,?,?)", (kind, key, raw))
                if kind == "prepared":
                    proposal = RoundProposal.model_validate_json(raw)
                    if key != proposal.cutoff.round.suite_sha256:
                        raise ValueError("round index suite binding mismatch")
                    db.execute(
                        "INSERT INTO round_index VALUES (?,?,?,?,?,?)",
                        (
                            proposal.cutoff.round.sequence,
                            key,
                            digest(proposal),
                            proposal.cutoff.registration_snapshot.block,
                            proposal.signing_close_block,
                            proposal.cutoff.round.evaluation_close_block,
                        ),
                    )
                elif kind == "plan":
                    plan = RoundPlan.model_validate_json(raw)
                    if key != digest(plan.suite):
                        raise ValueError("round plan suite binding mismatch")
                    db.execute(
                        "INSERT INTO plan_index VALUES (?,?,?)",
                        (key, plan.not_before_block, plan.admission_close_by_block),
                    )
        if conflict:
            raise ValueError("round journal conflict retained")

    @staticmethod
    def _record(db, kind, key):
        size = db.execute(
            "SELECT length(body) FROM records WHERE kind=? AND id=?", (kind, key)
        ).fetchone()
        if size is None:
            return None
        if type(size[0]) is not int or not 1 <= size[0] <= MAX_BYTES:
            raise ValueError("retained round object exceeds its byte bound")
        row = db.execute("SELECT body FROM records WHERE kind=? AND id=?", (kind, key)).fetchone()
        raw = bytes(row[0])
        if raw != canonical_json_bytes(json.loads(raw)):
            raise ValueError("retained round object is not canonical")
        return raw

    def get(self, kind, key):
        with self.transaction() as db:
            if db.execute("SELECT 1 FROM holds WHERE id=?", (key,)).fetchone():
                raise ValueError("round journal conflict held")
            raw = self._record(db, kind, key)
        return json.loads(raw) if raw is not None else None

    def keys(self, kind):
        with self.transaction() as db:
            rows = db.execute(
                "SELECT id FROM records WHERE kind=? ORDER BY id LIMIT ?",
                (kind, self.maximum_rounds + 1),
            ).fetchall()
        if len(rows) > self.maximum_rounds:
            raise ValueError("round journal record limit")
        return [row[0] for row in rows]

    def observe(self, block):
        with self.transaction() as db:
            old = db.execute("SELECT block FROM highwater LIMIT 2").fetchall()
            if (
                type(block) is not int
                or not 0 <= block <= 2**53 - 1
                or (old and (len(old) != 1 or old[0][0] > block))
            ):
                raise ValueError("round finalized head regressed")
            db.execute("DELETE FROM highwater")
            db.execute("INSERT INTO highwater VALUES (?)", (block,))

    def due_plans(self, block):
        with self.transaction() as db:
            rows = db.execute(
                "SELECT suite FROM plan_index WHERE opens<=? AND closes>=? "
                "AND suite NOT IN (SELECT suite FROM round_index) "
                "AND suite NOT IN (SELECT id FROM holds) ORDER BY closes,suite LIMIT 4",
                (block, block),
            ).fetchall()
        return [r[0] for r in rows]

    def prepared_entries(
        self, after_sequence=0, proposal_id=None, *, block=None, maximum_age=360, for_work=False
    ):
        with self.transaction() as db:
            if proposal_id is not None:
                rows = db.execute(
                    "SELECT sequence,suite,proposal,snapshot_block,signing_close "
                    "FROM round_index WHERE proposal=?",
                    (proposal_id,),
                ).fetchall()
            elif for_work and block is not None:
                rows = db.execute(
                    "SELECT sequence,suite,proposal,snapshot_block,signing_close FROM round_index "
                    "WHERE sequence>? AND snapshot_block<=? AND execution_close>? "
                    "AND suite NOT IN (SELECT id FROM holds) ORDER BY sequence LIMIT 4",
                    (after_sequence, block, block),
                ).fetchall()
            else:
                rows = db.execute(
                    "SELECT sequence,suite,proposal,snapshot_block,signing_close "
                    "FROM round_index WHERE sequence>? "
                    "AND (? IS NULL OR suite NOT IN (SELECT id FROM holds)) "
                    "AND (? IS NULL OR (snapshot_block<=? AND signing_close>=? "
                    "AND snapshot_block+?>=?)) ORDER BY sequence LIMIT 4",
                    (after_sequence, block, block, block, block, maximum_age, block),
                ).fetchall()
        return rows


class RoundCoordinator:
    def __init__(self, config, policy, provider, *, legacy=None, transport_provider=None):
        self.config = RoundCoordinatorConfig.model_validate_json(canonical_json_bytes(config))
        self.policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
        if digest(self.policy) != config.policy_sha256:
            raise ValueError("coordinator policy mismatch")
        self.provider = provider
        self.store = CompetitionStore(Path(config.intake_directory), self.policy)
        self.journal = RoundJournal(
            Path(config.state_directory),
            config.model_dump(
                mode="json",
                by_alias=True,
                exclude={
                    "maximum_rounds",
                    "maximum_journal_bytes",
                    "poll_seconds",
                    "host",
                    "port",
                    *({"work"} if config.work is None else set()),
                },
            ),
            maximum_rounds=config.maximum_rounds,
            maximum_bytes=config.maximum_journal_bytes,
        )
        self.serial = asyncio.Lock()
        self.cursor = ""
        self.new_cursor = ""
        self.work_cursor = 0
        self.work_queue = None
        self.transport_provider = transport_provider
        if config.work is not None:
            from .competition_dispatch import DispatchFinalityProvider
            from .competition_work_queue import WorkQueue
            from .policy import scoring_policy_hash

            work = config.work
            if legacy is None or work.legacy_policy_sha256 != scoring_policy_hash(legacy):
                raise ValueError("round work requires its matching transport policy")
            self.transport_provider = transport_provider or DispatchFinalityProvider(
                work.transport_chain, policy, legacy
            )
            self.work_queue = WorkQueue(
                Path(work.state_directory),
                policy,
                provider,
                order_directory=work.order_directory,
                publication_directory=work.publication_directory,
                minimum_issue_ms=work.minimum_issue_ms,
                legacy=legacy,
                transport_provider=self.transport_provider,
                maximum_orders=config.maximum_rounds,
                maximum_bytes=config.maximum_journal_bytes,
            )

    async def prepare_work(self, proposal):
        if self.work_queue is None:
            return
        from .competition_work_plans import RoundWorkAssets, prepare_work_plan

        certificate = self.publish_certificate(proposal)
        if certificate is None:
            return
        suite_id = proposal.cutoff.round.suite_sha256
        private = RoundPlan.model_validate_json(
            canonical_json_bytes(self.journal.get("plan", suite_id))
        )
        assets = _read(
            Path(self.config.work.asset_directory) / (suite_id + ".json"), RoundWorkAssets
        )
        if assets.suite_sha256 != suite_id or digest(private.suite) != suite_id:
            raise ValueError("round work assets differ from the private committed suite")
        plan = prepare_work_plan(
            cutoff=certificate,
            submissions=proposal.submissions,
            suite=private.suite,
            incumbent=assets.incumbent,
            runtime=assets.runtime,
            policy=self.policy,
        )
        await self.work_queue.prepare(plan, videos=assets.videos)

    async def capture(self):
        capture = await self.provider.collect()
        block = execution_boundary(capture).block
        if not self.policy.valid_from_block <= block <= self.policy.valid_through_block:
            raise ValueError("round policy is not current")
        self.journal.observe(block)
        return capture

    async def cycle(self):
        async with self.serial:
            capture = await self.capture()
            root = Path(self.config.plan_directory)
            _private(root)
            names = []
            with os.scandir(root) as entries:
                for entry in entries:
                    if len(names) >= self.config.maximum_rounds:
                        raise ValueError("round plan inbox capacity exhausted")
                    names.append(entry.name)
            names = sorted(n for n in names if n.endswith(".json"))
            block = capture.snapshot.block
            known = {k + ".json" for k in self.journal.keys("plan")}
            fresh = [n for n in names if n not in known]
            fresh = [n for n in fresh if n > self.new_cursor] or fresh
            if fresh:
                self.new_cursor = fresh[min(1, len(fresh) - 1)]
            maintenance = ([n for n in names if n > self.cursor] or names)[:1]
            if maintenance:
                self.cursor = maintenance[0]
            active = self.journal.prepared_entries(
                block=block, maximum_age=self.policy.maximum_snapshot_age_blocks
            )
            if self.work_queue is not None:
                working = self.journal.prepared_entries(
                    self.work_cursor, block=block, for_work=True
                )
                if not working:
                    working = self.journal.prepared_entries(block=block, for_work=True)
                if working:
                    self.work_cursor = working[-1][0]
                active += working
            pending = list(
                dict.fromkeys(
                    [key + ".json" for key in self.journal.due_plans(block)]
                    + [r[1] + ".json" for r in active]
                    + fresh[:2]
                    + maintenance
                )
            )
            counts = {"prepared": 0, "waiting": 0, "expired": 0, "held": 0}
            for name in pending:
                try:
                    plan = _read(root / name, RoundPlan)
                    suite_id = digest(plan.suite)
                    if name != suite_id + ".json" or plan.suite.policy_sha256 != digest(
                        self.policy
                    ):
                        raise ValueError("round plan filename or policy mismatch")
                    if not self.policy.valid_from_block <= plan.not_before_block or (
                        plan.valid_through_block > self.policy.valid_through_block
                    ):
                        raise ValueError("round plan lies outside the policy")
                    # Keep the protected plan private and never retime a used suite.
                    self.journal.put("plan", suite_id, plan)
                    existing = self.journal.get("prepared", suite_id)
                    if existing is not None:
                        proposal = RoundProposal.model_validate_json(canonical_json_bytes(existing))
                        self.publish_certificate(proposal)
                        await self.prepare_work(proposal)
                        counts["prepared"] += 1
                        continue
                    prepared = self.store.prepared_round(suite_id, self.config.replay_limits)
                    if prepared is None and block < plan.not_before_block:
                        counts["waiting"] += 1
                        continue
                    if prepared is None and block > plan.admission_close_by_block:
                        counts["expired"] += 1
                        continue
                    prepared = prepared or self.store.prepare_round(
                        snapshot=capture.snapshot,
                        suite=plan.suite,
                        evaluation_close_block=plan.evaluation_close_block,
                        reveal_block=plan.reveal_block,
                        evidence_cutoff_block=plan.evidence_cutoff_block,
                        valid_through_block=plan.valid_through_block,
                        limits=self.config.replay_limits,
                    )
                    proposal = validate_proposal(
                        RoundProposal(
                            schema="umi-round-proposal/1",
                            cutoff=CutoffPublication.model_validate_json(
                                canonical_json_bytes(prepared["cutoff_publication"])
                            ),
                            submissions=tuple(
                                SignedSubmission.model_validate_json(canonical_json_bytes(s))
                                for s in prepared["submissions"]
                            ),
                            signing_close_block=plan.signing_close_block,
                        ),
                        self.policy,
                        self.config.replay_limits,
                    )
                    prepared_round = proposal.cutoff.round
                    if (
                        not (
                            plan.not_before_block
                            <= prepared_round.submission_close_block
                            <= plan.admission_close_by_block
                        )
                        or any(
                            getattr(prepared_round, field) != getattr(plan, field)
                            for field in (
                                "evaluation_close_block",
                                "reveal_block",
                                "valid_through_block",
                            )
                        )
                        or proposal.cutoff.cutoff_schedule.evidence_cutoff_block
                        != plan.evidence_cutoff_block
                    ):
                        raise ValueError("recovered round differs from its original plan window")
                    self.journal.put("prepared", suite_id, proposal)
                    await self.prepare_work(proposal)
                    counts["prepared"] += 1
                except (OSError, ValueError, sqlite3.Error):
                    counts["held"] += 1
            return {
                "status": "round_poll_complete",
                "finalized_block": block,
                **counts,
                "chain_submission_authorized": False,
            }

    def proposals(self, after_sequence=0, proposal_id=None, *, block=None):
        result = []
        for (
            sequence,
            key,
            proposal_hash,
            snapshot_block,
            signing_close,
        ) in self.journal.prepared_entries(
            after_sequence,
            proposal_id,
            block=block,
            maximum_age=self.policy.maximum_snapshot_age_blocks,
        ):
            proposal = validate_proposal(
                RoundProposal.model_validate_json(
                    canonical_json_bytes(self.journal.get("prepared", key))
                ),
                self.policy,
                self.config.replay_limits,
            )
            if (
                proposal.cutoff.round.sequence != sequence
                or proposal.cutoff.round.suite_sha256 != key
                or digest(proposal) != proposal_hash
                or proposal.cutoff.registration_snapshot.block != snapshot_block
                or proposal.signing_close_block != signing_close
            ):
                raise ValueError("retained round index binding mismatch")
            result.append(proposal)
        return sorted(result, key=lambda p: p.cutoff.round.sequence)

    def publish_certificate(self, proposal):
        proposal = validate_proposal(proposal, self.policy, self.config.replay_limits)
        signatures, groups = [], set()
        for evaluator in sorted(self.policy.evaluators, key=lambda e: identity(e.hotkey)):
            raw = self.journal.get("vote", digest(proposal) + ":" + identity(evaluator.hotkey))
            if raw is None:
                continue
            vote = verify_endorsement(
                CutoffEndorsement.model_validate_json(canonical_json_bytes(raw)),
                proposal,
                self.policy,
            )
            if evaluator.control_group not in groups:
                groups.add(evaluator.control_group)
                signatures.append(vote.signature)
        if len(groups) < self.policy.required_evaluator_groups:
            return None
        key = proposal.cutoff.round_sha256
        prior = self.journal.get("certificate", key)
        certificate = (
            SignedCutoffPublication.model_validate_json(canonical_json_bytes(prior))
            if prior
            else SignedCutoffPublication(publication=proposal.cutoff, signatures=tuple(signatures))
        )
        verify_cutoff_publication(
            certificate,
            policy=self.policy,
            submissions=proposal.submissions,
            limits=self.config.replay_limits,
        )
        if certificate.publication != proposal.cutoff:
            raise ValueError("retained cutoff certificate differs")
        self.journal.put("certificate", key, certificate)
        _publish(Path(self.config.certificate_directory) / (key + ".cutoff.json"), certificate)
        return certificate

    async def query(self, query):
        async with self.serial:
            block = (await self.capture()).snapshot.block
            if query.vote is None:
                selected = tuple(self.proposals(after_sequence=query.after_sequence, block=block))
                return RoundReply(
                    query_sha256=digest(query),
                    policy_sha256=digest(self.policy),
                    proposals=selected,
                )
            proposals = self.proposals(proposal_id=query.vote.proposal_sha256)
            proposal = next((p for p in proposals if digest(p) == query.vote.proposal_sha256), None)
            if proposal is None or identity(query.hotkey) != identity(query.vote.signature.hotkey):
                raise ValueError("unknown proposal or different endorsement signer")
            vote = verify_endorsement(query.vote, proposal, self.policy)
            key = digest(proposal) + ":" + identity(query.hotkey)
            old = self.journal.get("vote", key)
            if (
                old is None
                and not proposal.cutoff.round.submission_close_block
                <= block
                <= proposal.signing_close_block
            ):
                raise ValueError("new endorsement outside its original signing window")
            self.journal.put("vote", key, vote)
            self.publish_certificate(proposal)
            await self.prepare_work(proposal)
            return RoundReply(
                query_sha256=digest(query),
                policy_sha256=digest(self.policy),
                accepted_proposal_sha256=digest(proposal),
            )


def create_round_app(
    config,
    policy,
    *,
    provider_factory=FinalizedRegistrationProvider,
    report=None,
    legacy=None,
    transport_provider=None,
):
    config = RoundCoordinatorConfig.model_validate_json(canonical_json_bytes(config))
    provider = provider_factory(config.chain, policy)
    coordinator = RoundCoordinator(
        config, policy, provider, legacy=legacy, transport_provider=transport_provider
    )
    nonces = SQLiteNonceStore(
        Path(config.state_directory) / "nonces.sqlite3",
        allowed_hotkeys=[e.hotkey for e in policy.evaluators],
        maximum_nonces_per_hotkey=256,
        maximum_total_nonces=256 * len(policy.evaluators),
        maximum_database_bytes=16 * 1024**2,
    )

    async def polling():
        while True:
            try:
                result = await coordinator.cycle()
            except (OSError, ValueError, RuntimeError, sqlite3.Error, asyncio.TimeoutError):
                result = {"status": "round_poll_failed", "chain_submission_authorized": False}
            if report is not None:
                # Never emit protected references, request bytes or exception text.
                report(result)
            await asyncio.sleep(config.poll_seconds)

    @asynccontextmanager
    async def lifespan(_app):
        lease = _lock_file(Path(config.state_directory) / "coordinator.lock")
        task = None
        try:
            await provider.start()
            if coordinator.transport_provider is not None:
                await coordinator.transport_provider.start()
            task = asyncio.create_task(polling())
            yield
        finally:
            if task is not None:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
            try:
                try:
                    if coordinator.transport_provider is not None:
                        await coordinator.transport_provider.aclose()
                finally:
                    await provider.aclose()
            finally:
                os.close(lease)

    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    if coordinator.work_queue is not None:
        from .competition_work_transport import attach_work_route

        attach_work_route(app, coordinator.work_queue)
    capacity = asyncio.Semaphore(2)

    @app.exception_handler(StarletteHTTPException)
    async def rejected(_request, exc):
        return Response(
            canonical_json_bytes({"detail": exc.detail}),
            status_code=exc.status_code,
            media_type="application/json",
            headers={"Cache-Control": "no-store"},
        )

    @app.post(ROUTE)
    async def control(request: Request):
        acquired = False
        try:
            await asyncio.wait_for(capacity.acquire(), timeout=0.1)
            acquired = True
            if request.headers.get("content-encoding", "identity") != "identity" or (
                request.headers.get("content-type", "").split(";", 1)[0] != "application/json"
                or sum(len(k) + len(v) for k, v in request.scope["headers"]) > 8192
            ):
                raise HTTPException(400, "round request rejected")

            async def read_body():
                raw = bytearray()
                async for chunk in request.stream():
                    if len(raw) + len(chunk) > 16 * 1024:
                        raise HTTPException(413, "round request byte limit")
                    raw.extend(chunk)
                return bytes(raw)

            raw = await asyncio.wait_for(read_body(), timeout=10)
            try:
                signed = SignedRoundQuery.model_validate_json(raw)
            except ValueError:
                raise HTTPException(401, "round authentication rejected") from None
            q, now = signed.query, time.time_ns()
            if (
                raw != canonical_json_bytes(signed)
                or q.policy_sha256 != digest(policy)
                or (
                    identity(q.hotkey) not in {identity(e.hotkey) for e in policy.evaluators}
                    or not now - 30_000_000_000 <= int(q.nonce_unix_ns) <= now + 5_000_000_000
                )
            ):
                raise HTTPException(401, "round authentication rejected")
            if not nonces.check_and_store(q.hotkey, int(q.nonce_unix_ns)):
                raise HTTPException(401, "round nonce rejected")
            reply = await asyncio.wait_for(coordinator.query(q), timeout=25)
            body = canonical_json_bytes(reply)
            if len(body) > MAX_BYTES:
                raise ValueError("round reply exceeds its byte bound")
            return Response(
                body, media_type="application/json", headers={"Cache-Control": "no-store"}
            )
        except HTTPException:
            raise
        except Exception:
            raise HTTPException(503, "round coordinator unavailable or request rejected") from None
        finally:
            if acquired:
                capacity.release()

    return app


async def request_round(origin, signed, *, transport=None):
    origin = validate_intake_origin(origin)
    signed = SignedRoundQuery.model_validate_json(canonical_json_bytes(signed))
    raw = canonical_json_bytes(signed)
    if len(raw) > 16 * 1024:
        raise ValueError("round query too large")

    async def fetch():
        async with (
            httpx.AsyncClient(
                transport=transport,
                timeout=httpx.Timeout(30, connect=5),
                follow_redirects=False,
                trust_env=False,
            ) as client,
            client.stream(
                "POST",
                origin + ROUTE,
                content=raw,
                headers={"Content-Type": "application/json", "Accept-Encoding": "identity"},
            ) as response,
        ):
            if response.status_code != 200 or (
                response.headers.get("content-type", "").split(";", 1)[0] != "application/json"
                or response.headers.get("content-encoding", "identity") != "identity"
            ):
                raise ValueError("round request rejected")
            result = bytearray()
            async for chunk in response.aiter_bytes():
                if len(result) + len(chunk) > MAX_BYTES:
                    raise ValueError("round reply too large")
                result.extend(chunk)
            return bytes(result)

    try:
        raw = await asyncio.wait_for(fetch(), timeout=35)
    except (httpx.HTTPError, asyncio.TimeoutError):
        raise ValueError("round request failed") from None
    reply = RoundReply.model_validate_json(raw)
    if (
        raw != canonical_json_bytes(reply)
        or reply.query_sha256 != digest(signed.query)
        or (reply.policy_sha256 != signed.query.policy_sha256)
    ):
        raise ValueError("round reply binding mismatch")
    sequences = [p.cutoff.round.sequence for p in reply.proposals]
    if signed.query.vote is None:
        if reply.accepted_proposal_sha256 is not None or (
            sequences != sorted(set(sequences))
            or any(s <= signed.query.after_sequence for s in sequences)
        ):
            raise ValueError("round discovery cursor or reply kind mismatch")
    elif reply.proposals or (reply.accepted_proposal_sha256 != signed.query.vote.proposal_sha256):
        raise ValueError("round endorsement acknowledgment mismatch")
    return reply


class RoundSigningClient:
    def __init__(self, worker, origin, *, transport=None):
        self.worker, self.origin, self.transport = worker, validate_intake_origin(origin), transport
        self.journal = RoundJournal(
            Path(worker.config.state_directory) / "round-signing",
            {
                "policy": digest(worker.policy),
                "hotkey": identity(worker.config.evaluator_hotkey),
                "origin": self.origin,
            },
            maximum_rounds=worker.config.maximum_orders,
            maximum_bytes=worker.config.maximum_journal_bytes,
        )
        self.cursor, self.nonce = 0, 0
        self.limits = PublicationReplayLimits(
            maximum_roster_bytes=MAX_BYTES // 4,
            maximum_certificate_bytes=MAX_BYTES // 4,
            maximum_evidence_bytes=MAX_BYTES // 4,
        )

    async def query(self, **fields):
        self.nonce = max(self.nonce + 1, time.time_ns())
        query = RoundQuery(
            schema="umi-round-query/1",
            policy_sha256=digest(self.worker.policy),
            hotkey=self.worker.config.evaluator_hotkey,
            nonce_unix_ns=str(self.nonce),
            **fields,
        )
        return await request_round(
            self.origin,
            SignedRoundQuery(query=query, signature=sign_object(query, self.worker.wallet)),
            transport=self.transport,
        )

    async def endorse(self, proposal):
        worker = self.worker
        proposal = validate_proposal(proposal, worker.policy, self.limits)
        if not eligible_signer(worker.config.evaluator_hotkey, proposal, worker.policy):
            return "ineligible"
        slot = str(proposal.cutoff.round.sequence)
        # Existing statements remain binding. A proposal that fails its initial
        # independent proof must not poison an unreserved sequence or suite.
        if self.journal.get("intent", slot) is not None:
            self.journal.put("intent", slot, proposal)
        old = self.journal.get("vote", slot)
        if old is None:
            current = await worker.boundary()
            self.journal.observe(current.block)
            if current.block > proposal.signing_close_block:
                return "expired"
            snapshot = proposal.cutoff.registration_snapshot
            if (
                not snapshot.block
                <= current.block
                <= snapshot.block + worker.policy.maximum_snapshot_age_blocks
            ):
                raise ValueError("round proposal snapshot is not recent")
            capture = await worker.provider.collect_at(snapshot.block)
            execution_boundary(capture)
            if capture.snapshot != snapshot:
                raise ValueError("independent registration snapshot differs from proposal")
            current = await worker.boundary()
            self.journal.observe(current.block)
            if (
                not snapshot.block
                <= current.block
                <= min(
                    proposal.signing_close_block,
                    snapshot.block + worker.policy.maximum_snapshot_age_blocks,
                )
            ):
                raise ValueError("round signing window elapsed during proof collection")
            self.journal.put("intent", slot, proposal)
            self.journal.put(
                "suite", proposal.cutoff.round.suite_sha256, {"proposal": digest(proposal)}
            )
            vote = CutoffEndorsement(
                proposal_sha256=digest(proposal),
                signature=sign_cutoff_publication(proposal.cutoff, worker.wallet),
            )
            verify_endorsement(vote, proposal, worker.policy)
            self.journal.put("vote", slot, vote)
        else:
            if self.journal.get("intent", slot) is None or self.journal.get(
                "suite", proposal.cutoff.round.suite_sha256
            ) != {"proposal": digest(proposal)}:
                raise ValueError("retained endorsement is missing its signing reservation")
            vote = verify_endorsement(
                CutoffEndorsement.model_validate_json(canonical_json_bytes(old)),
                proposal,
                worker.policy,
            )
        reply = await self.query(vote=vote)
        if reply.accepted_proposal_sha256 != digest(proposal):
            raise ValueError("round endorsement acknowledgment mismatch")
        return "endorsed"

    async def sync_once(self):
        reply = await self.query(after_sequence=self.cursor)
        if not reply.proposals and self.cursor:
            self.cursor = 0
            reply = await self.query(after_sequence=0)
        if not reply.proposals:
            return
        for proposal in reply.proposals:
            try:
                await self.endorse(proposal)
            except (OSError, ValueError, RuntimeError, sqlite3.Error, asyncio.TimeoutError):
                # A failed peer proof must not stop other current proposals.
                # The bounded cursor wraps, so this proposal can be retried.
                pass
            finally:
                self.cursor = proposal.cutoff.round.sequence


def serve_rounds(config, policy, *, legacy=None):
    import uvicorn

    config = RoundCoordinatorConfig.model_validate_json(canonical_json_bytes(config))
    uvicorn.run(
        create_round_app(
            config,
            policy,
            legacy=legacy,
            report=lambda value: print(canonical_json_bytes(value).decode("utf-8"), flush=True),
        ),
        host=config.host,
        port=config.port,
        workers=1,
        proxy_headers=False,
        access_log=False,
        limit_concurrency=4,
        backlog=8,
    )
