"""Serve reviewed public score artifacts; never score private inputs in a GET."""

from __future__ import annotations

import hashlib
import json
import math
import sqlite3
from contextlib import closing
from fractions import Fraction
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, model_validator
from typing_extensions import Self

from .competition_public_results_artifact import normalize_public_results
from .competition_round_discovery import MAXIMUM_ROUND_BYTES
from .open_competition import (
    EvaluationRound,
    Hex32,
    Hotkey,
    Stratum,
    StrictProtocolModel,
    Track,
    digest,
    identity,
)
from .protocol import canonical_json_bytes

MAXIMUM_PUBLIC_RESULTS_BYTES = 8 * 1024 * 1024
MAXIMUM_SETTLEMENT_BYTES = 64 * 1024 * 1024
Block = Annotated[int, Field(ge=0, le=2**53 - 1)]


class PublicQuality(StrictProtocolModel):
    numerator: Annotated[str, Field(pattern=r"^(0|[1-9][0-9]*)$", max_length=4096)]
    denominator: Annotated[str, Field(pattern=r"^[1-9][0-9]*$", max_length=4096)]
    decimal: Annotated[float, Field(ge=0, le=1)]

    def fraction(self) -> Fraction:
        return Fraction(int(self.numerator), int(self.denominator))

    @model_validator(mode="after")
    def validate_value(self) -> Self:
        value = self.fraction()
        if not 0 <= value <= 1 or not math.isclose(
            self.decimal, float(value), rel_tol=0, abs_tol=1e-12
        ):
            raise ValueError("public quality decimal differs from its exact fraction")
        return self


class PublicQualityMetrics(StrictProtocolModel):
    aggregate: PublicQuality
    by_stratum: dict[Stratum, PublicQuality]

    @model_validator(mode="after")
    def validate_strata(self) -> Self:
        if set(self.by_stratum) not in (
            {"fingerspelling", "continuous"},
            {"fingerspelling", "short_utterance", "continuous"},
        ):
            raise ValueError("public quality requires the complete native scoring profile")
        return self


class PublicResult(StrictProtocolModel):
    submission_sha256: Hex32
    hotkey: Hotkey
    uid: Annotated[int, Field(ge=0, le=255)] | None
    track: Track
    status: Literal["scored", "void"]
    result_sha256: Hex32 | None
    independent_evidence_sha256: Hex32 | None
    void_decision_sha256: Hex32 | None
    void_evidence_sha256: Hex32 | None
    first_observed_block: Block
    candidate: PublicQualityMetrics | None
    incumbent: PublicQualityMetrics | None
    score_rank: Annotated[int, Field(ge=1, le=512)] | None

    @model_validator(mode="after")
    def validate_outcome(self) -> Self:
        scored = (
            self.result_sha256,
            self.independent_evidence_sha256,
            self.candidate,
            self.incumbent,
            self.score_rank,
        )
        void = (self.void_decision_sha256, self.void_evidence_sha256)
        present, absent = (scored, void) if self.status == "scored" else (void, scored)
        if any(value is None for value in present) or any(value is not None for value in absent):
            raise ValueError("public result mixes scored and void fields")
        return self


class PublicRoundResults(StrictProtocolModel):
    schema_: Literal["umi-competition-public-results/1"] = Field(alias="schema")
    round_sha256: Hex32
    policy_sha256: Hex32
    settlement_sha256: Hex32
    observed_block: Block
    scoring_method: Literal["native_replay_evaluation_at_settlement_observed_block"]
    provisional: Literal[True]
    certified: Literal[False]
    rewards_active: Literal[False]
    chain_submission_authorized: Literal[False]
    items: Annotated[tuple[PublicResult, ...], Field(min_length=1, max_length=512)]

    @model_validator(mode="after")
    def validate_ranks(self) -> Self:
        submissions = [item.submission_sha256 for item in self.items]
        if submissions != sorted(set(submissions)):
            raise ValueError("public results must be unique and in submission order")
        ranks = {}
        for track in ("endpoint", "model"):
            scores = sorted(
                (
                    item.candidate.aggregate.fraction()
                    for item in self.items
                    if item.track == track and item.candidate is not None
                ),
                reverse=True,
            )
            for position, score in enumerate(scores, 1):
                ranks.setdefault((track, score), position)
        for item in self.items:
            if (
                item.candidate is not None
                and item.score_rank != ranks[item.track, item.candidate.aggregate.fraction()]
            ):
                raise ValueError("public rank differs from exact candidate quality within track")
        return self


class PublicResultsSource(StrictProtocolModel):
    """Operator-reviewed artifact binding, separate from runtime/economic policy."""

    round_sha256: Hex32
    artifact_sha256: Hex32
    path: Annotated[str, Field(min_length=1, max_length=4096)]

    @model_validator(mode="after")
    def absolute_file(self) -> Self:
        path = Path(self.path)
        if not path.is_absolute() or path == Path(path.anchor):
            raise ValueError("public results need an absolute file path")
        return self


def public_results_page(
    database: Path,
    source: PublicResultsSource,
    *,
    offset: int = 0,
    limit: int = 20,
) -> dict:
    if not 0 <= offset <= 1_000_000 or not 1 <= limit <= 100:
        raise ValueError("invalid public results page")
    path = Path(source.path)
    if not path.is_file() or path.is_symlink():
        raise ValueError("public results artifact unavailable")
    with path.open("rb") as stream:
        raw = stream.read(MAXIMUM_PUBLIC_RESULTS_BYTES + 1)
    if len(raw) > MAXIMUM_PUBLIC_RESULTS_BYTES or hashlib.sha256(raw).hexdigest() != (
        source.artifact_sha256
    ):
        raise ValueError("public results artifact differs from its configured digest")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("public results must be an object")
    public = PublicRoundResults.model_validate_json(
        canonical_json_bytes(normalize_public_results(value))
    )
    if public.round_sha256 != source.round_sha256:
        raise ValueError("public results belong to another round")
    with closing(
        sqlite3.connect(
            database.resolve().as_uri() + "?mode=ro",
            uri=True,
            isolation_level=None,
        )
    ) as db:
        db.execute("PRAGMA query_only=ON")
        db.execute("BEGIN")
        row = db.execute(
            "SELECT CASE WHEN length(body)<=? THEN body END FROM rounds WHERE digest=?",
            (MAXIMUM_ROUND_BYTES, source.round_sha256),
        ).fetchone()
        if row is None or row[0] is None:
            raise ValueError("public results have no retained round")
        round_ = EvaluationRound.model_validate_json(row[0])
        if digest(round_) != public.round_sha256 or round_.policy_sha256 != public.policy_sha256:
            raise ValueError("public results round/policy binding differs")
        if tuple(item.submission_sha256 for item in public.items) != round_.roster:
            raise ValueError("public results must cover the frozen roster")
        # Extract only public binding metadata, never suite or hypothesis bodies.
        settlement = db.execute(
            "SELECT digest, CASE WHEN length(body)<=? "
            "THEN json_extract(body, '$.observed_block') END, "
            "CASE WHEN length(body)<=? THEN json_extract(body, '$.results') END, "
            "CASE WHEN length(body)<=? "
            "THEN json_extract(body, '$.registration_snapshot.registrations') END "
            "FROM competition_settlements WHERE round=?",
            (
                MAXIMUM_SETTLEMENT_BYTES,
                MAXIMUM_SETTLEMENT_BYTES,
                MAXIMUM_SETTLEMENT_BYTES,
                public.round_sha256,
            ),
        ).fetchone()
        if settlement is None or settlement[:2] != (
            public.settlement_sha256,
            public.observed_block,
        ):
            raise ValueError("public results settlement binding differs")
        bindings = {item["submission_sha256"]: item for item in json.loads(settlement[2])}
        registrations = {
            identity(item["hotkey"]): item["uid"] for item in json.loads(settlement[3])
        }
        for item in public.items:
            key = identity(item.hotkey)
            submission = db.execute(
                "SELECT hotkey, track FROM submissions WHERE digest=?",
                (item.submission_sha256,),
            ).fetchone()
            if submission != (key, item.track) or item.uid != registrations.get(key):
                raise ValueError("public result submission identity differs")
            if item.status == "scored":
                fields = {
                    "result_sha256": item.result_sha256,
                    "independent_evidence_sha256": item.independent_evidence_sha256,
                }
                retained = db.execute(
                    "SELECT round, submission, result, first_observed_block "
                    "FROM independent_evaluation_evidence WHERE digest=?",
                    (item.independent_evidence_sha256,),
                ).fetchone()
                decision = item.result_sha256
            else:
                fields = {
                    "void_decision_sha256": item.void_decision_sha256,
                    "void_evidence_sha256": item.void_evidence_sha256,
                }
                retained = db.execute(
                    "SELECT round, submission, decision, first_observed_block "
                    "FROM void_evaluation_evidence WHERE digest=?",
                    (item.void_evidence_sha256,),
                ).fetchone()
                decision = item.void_decision_sha256
            if retained != (
                public.round_sha256,
                item.submission_sha256,
                decision,
                item.first_observed_block,
            ) or bindings.get(item.submission_sha256) != {
                "submission_sha256": item.submission_sha256,
                "first_observed_block": item.first_observed_block,
                **fields,
            }:
                raise ValueError("public result differs from retained settlement evidence")
        conflicted = (
            db.execute(
                "SELECT 1 FROM round_conflicts WHERE round=?",
                (public.round_sha256,),
            ).fetchone()
            is not None
        )
        disputed = (
            conflicted
            or db.execute(
                "SELECT 1 FROM settlement_disputes WHERE round=?",
                (public.round_sha256,),
            ).fetchone()
            is not None
        )
    page = public.model_dump(mode="json", by_alias=True, exclude={"items"})
    page.update(
        {
            "source": "configured_public_results_artifact",
            "artifact_sha256": source.artifact_sha256,
            "state": "closed_computed_uncertified",
            "conflicted": conflicted,
            "disputed": disputed,
            "items": [
                item.model_dump(mode="json") for item in public.items[offset : offset + limit]
            ],
            "total": len(public.items),
            "offset": offset,
            "limit": limit,
            "next_offset": offset + limit if offset + limit < len(public.items) else None,
        }
    )
    return page
