"""Independent artifact approvals with durable original vote intents.

Reviewers select reviewed rights/reconstruction documents privately and verify
their own preserved bundle. An owner-supplied proposal cannot approve its own
documents. Certified participant admission supplies the independent membership
decision; this vote supplies only artifact acceptance, never reward authority.
"""

import asyncio
from collections.abc import Awaitable, Callable
from functools import partial
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, model_validator

from .competition_artifacts import verify_preserved_bundle
from .competition_cohort_history import CohortRecoveryHistory, verify_cohort_history
from .competition_cohort_intake import CohortIntakeBinding, history_tip
from .competition_cohort_intake_records import replay_participation
from .competition_cohort_model_acceptance import (
    ModelAcceptanceIntent,
    ModelArtifactReviewInputs,
    ModelArtifactVote,
    ModelReviewRequest,
    check_model_vote,
    verify_model_acceptance_body,
)
from .competition_cohort_recovery import verify_recovery_quorum
from .competition_execution import execution_boundary
from .competition_round_journal import RoundJournal
from .concurrency import run_owned_thread, wait_for_owned
from .open_competition import CompetitionPolicy, Hotkey, digest, identity
from .private_files import Directory, read_private_model
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes


class ModelReviewConfig(StrictProtocolModel):
    schema_: Literal["umi-cohort-model-review-config/1"] = Field(alias="schema")
    directory: Directory
    approvals_directory: Directory
    archive_directory: Directory
    policy_sha256: Hex32
    signer: Hotkey
    cohorts: Annotated[tuple[CohortIntakeBinding, ...], Field(min_length=1, max_length=512)]
    maximum_votes: Annotated[int, Field(ge=1, le=65536)] = 4096
    maximum_bytes: Annotated[int, Field(ge=1024, le=16 * 1024**3)] = 1024**3
    signing_timeout_seconds: Annotated[int, Field(ge=1, le=1200)] = 30

    @model_validator(mode="after")
    def ordered(self):
        keys = tuple(c.cohort_sha256 for c in self.cohorts)
        if keys != tuple(sorted(set(keys))):
            raise ValueError("model reviewer cohorts must be unique and ordered")
        roots = [
            Path(p) for p in (self.directory, self.approvals_directory, self.archive_directory)
        ]
        if any(
            a == b or a in b.parents or b in a.parents
            for i, a in enumerate(roots)
            for b in roots[i + 1 :]
        ):
            raise ValueError("model review journal, approvals and artifacts must be disjoint")
        return self


class ModelArtifactReviewer:
    def __init__(
        self,
        config: ModelReviewConfig,
        policy,
        capture,
        history,
        sign,
        *,
        direct_review: Callable[[ModelReviewRequest], Awaitable[ModelArtifactReviewInputs]]
        | None = None,
    ):
        self.config = ModelReviewConfig.model_validate_json(canonical_json_bytes(config))
        self.policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
        c = self.config
        if c.policy_sha256 != digest(self.policy) or identity(c.signer) not in {
            identity(e.hotkey) for e in self.policy.evaluators
        }:
            raise ValueError("model reviewer is outside policy")
        self.cohorts = {b.cohort_sha256: b.authority_sha256 for b in c.cohorts}
        self.capture, self.history, self.sign = capture, history, sign
        if direct_review is not None and not callable(direct_review):
            raise ValueError("direct model reviewer is not callable")
        self.direct_review = direct_review
        # Capacity and file placement may change on recovery; identity may not.
        self.journal = RoundJournal(
            Path(c.directory),
            {
                "schema": c.schema_,
                "policy_sha256": c.policy_sha256,
                "signer": identity(c.signer),
                "cohorts": [b.model_dump() for b in c.cohorts],
            },
            maximum_rounds=c.maximum_votes,
            maximum_bytes=c.maximum_bytes,
            maximum_record_bytes=40 * 1024**2,
        )
        with self.journal.transaction() as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS model_review_heads "
                "(cohort TEXT PRIMARY KEY, history TEXT NOT NULL)"
            )
        self.serial = asyncio.Lock()

    def _validate(self, request, history, block):
        a = request.acceptance
        if self.cohorts.get(a.cohort_sha256) != a.authority_sha256:
            raise ValueError("model review is outside configured cohort authority")
        view = verify_cohort_history(
            history, self.policy, expected_tip_sha256=history_tip(history), current_block=block
        )
        if view.state.phase != "intake":
            raise ValueError("new model acceptance requires open intake")
        verify_model_acceptance_body(a, request.record, history, self.policy, maximum_block=block)
        admission = replay_participation(request.record, history, self.policy)
        if request.admission.admission != admission:
            raise ValueError("model review changes certified participant admission")
        verify_recovery_quorum(admission, request.admission.signatures, self.policy)
        if identity(a.recipient_hotkey) == identity(self.config.signer):
            raise ValueError("model submitters cannot review their own artifacts")

    def _reserve(self, request, intent, history):
        a = request.acceptance
        slot = a.cohort_sha256 + ":" + a.submission_sha256

        def index(db):
            row = db.execute(
                "SELECT history FROM model_review_heads WHERE cohort=?", (a.cohort_sha256,)
            ).fetchone()
            if row:
                raw = self.journal.get("model_history", row[0], db=db)
                if raw is None or digest(raw) != row[0]:
                    raise ValueError("retained model review history is missing or changed")
                old = CohortRecoveryHistory.model_validate_json(canonical_json_bytes(raw))
                if (
                    old.genesis != history.genesis
                    or history.transitions[: len(old.transitions)] != old.transitions
                ):
                    raise ValueError("model review history rolled back or forked")
            db.execute(
                "INSERT INTO model_review_heads VALUES (?,?) ON CONFLICT(cohort) "
                "DO UPDATE SET history=excluded.history",
                (a.cohort_sha256, digest(history)),
            )
            count = db.execute(
                "SELECT COUNT(*) FROM records WHERE kind='model_request'"
            ).fetchone()[0]
            if count > self.config.maximum_votes:
                raise ValueError("model review vote capacity exhausted")

        self.journal.put_many(
            (
                ("model_history", digest(history), history),
                ("model_request", slot, request),
                ("model_intent", slot, intent),
                # One completion ordinal cannot be signed for two different entries.
                ("model_ordinal", a.cohort_sha256 + ":" + str(a.accepted_ordinal), a),
            ),
            index=index,
        )

    async def attest(self, request: ModelReviewRequest) -> ModelArtifactVote:
        request = ModelReviewRequest.model_validate_json(canonical_json_bytes(request))
        a = request.acceptance
        if self.cohorts.get(a.cohort_sha256) != a.authority_sha256:
            raise ValueError("model review is outside configured cohort authority")
        slot = a.cohort_sha256 + ":" + a.submission_sha256
        async with self.serial:
            with self.journal.locked():
                saved = await run_owned_thread(self.journal.get, "model_request", slot)
                if saved is not None and canonical_json_bytes(saved) != canonical_json_bytes(
                    request
                ):
                    raise ValueError("model review retry changes its original request")
                vote = await run_owned_thread(self.journal.get, "model_vote", slot)
                intent = None
                if saved is not None:
                    raw = await run_owned_thread(self.journal.get, "model_intent", slot)
                    if raw is None:
                        raise ValueError("model review lacks retained reviewed documents")
                    intent = ModelAcceptanceIntent.model_validate_json(canonical_json_bytes(raw))
                    if intent.acceptance != a:
                        raise ValueError("model review intent changed")
                if vote is not None:
                    if saved is None:
                        raise ValueError("model vote lacks its original intent")
                    vote = ModelArtifactVote.model_validate(vote)
                    check_model_vote(vote, a, self.policy, signer=self.config.signer)
                    return vote
                if saved is None:
                    sub = request.record.request.signed_submission.submission
                    if sub.track != "model" or sub.model_bundle is None:
                        raise ValueError("artifact review requires a complete model submission")
                    if request.direct_artifact is not None:
                        if self.direct_review is None:
                            raise ValueError("direct model review source is unavailable")
                        inputs = await self.direct_review(request)
                    else:
                        inputs = await run_owned_thread(
                            partial(
                                read_private_model,
                                Path(self.config.approvals_directory) / (a.model_sha256 + ".json"),
                                ModelArtifactReviewInputs,
                                maximum_bytes=33 * 1024**2,
                            )
                        )
                        await run_owned_thread(
                            verify_preserved_bundle,
                            request.record.request.signed_submission.submission.model_bundle,
                            Path(self.config.archive_directory),
                            self.policy,
                        )
                    if inputs.model_sha256 != a.model_sha256:
                        raise ValueError("model review documents differ from the artifact")
                    intent = ModelAcceptanceIntent(acceptance=a, inputs=inputs)
                source = await self.history(a.cohort_sha256)
                block = execution_boundary(await self.capture()).block
                self._validate(request, source.history, block)
                await run_owned_thread(self._reserve, request, intent, source.history)
                signature = await wait_for_owned(
                    self.sign(a), timeout=self.config.signing_timeout_seconds
                )
                vote = ModelArtifactVote(acceptance=a, signature=signature)
                check_model_vote(vote, a, self.policy, signer=self.config.signer)
                await run_owned_thread(self.journal.put, "model_vote", slot, vote)
                return vote
