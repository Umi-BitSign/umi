"""Prospective suite selection from private, provenance-bearing case metadata.

This is preparation, never admission or an amendment to a signed cohort. It
preserves the existing scoring profile and supplied publisher references. Source
metadata and exposure declarations remain operational claims, not native proof
that an upstream model never saw a public example.
"""

from __future__ import annotations

import hashlib
import hmac
from collections import Counter
from collections.abc import Callable
from typing import Annotated, Literal

from pydantic import Field, model_validator

from .open_competition import (
    CompetitionPolicy,
    EvaluationSuite,
    ReferenceText,
    SingleReferenceEvaluationCase,
    digest,
    validate_suite_profile,
)
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes
from .scoring import normalization_trace

Task = Literal["fingerspelling", "continuous"]
Name = Annotated[str, Field(min_length=1, max_length=256)]


class SuiteCandidate(StrictProtocolModel):
    case: SingleReferenceEvaluationCase
    dataset: Name
    dataset_version: Name
    source_group_sha256: Hex32
    provenance_sha256: Hex32
    license_id: Name
    attribution: Annotated[str, Field(min_length=1, max_length=4096)]
    training_exposure: Literal["known_public", "unknown", "documented_training_excluded"]
    training_exclusion_evidence_sha256: Hex32 | None = None
    signer_group_sha256: Hex32 | None = None
    topic: Name | None = None
    reference_qa_sha256: Hex32 | None = None

    @model_validator(mode="after")
    def documented_exclusion(self):
        if (self.training_exposure == "documented_training_excluded") != (
            self.training_exclusion_evidence_sha256 is not None
        ):
            raise ValueError("training exclusion requires its documented evidence identity")
        return self


class SuiteCandidateInventory(StrictProtocolModel):
    schema_: Literal["umi-private-suite-candidates/1"] = Field(alias="schema")
    cases: Annotated[tuple[SuiteCandidate, ...], Field(min_length=1, max_length=100_000)]


class SuiteExclusions(StrictProtocolModel):
    """Private references/groups from known training, development and prior suites."""

    schema_: Literal["umi-private-suite-exclusions/1"] = Field(alias="schema")
    source_metadata_sha256s: Annotated[tuple[Hex32, ...], Field(min_length=1, max_length=4096)]
    references: Annotated[tuple[ReferenceText, ...], Field(max_length=100_000)] = ()
    source_group_sha256s: Annotated[tuple[Hex32, ...], Field(max_length=100_000)] = ()
    signer_group_sha256s: Annotated[tuple[Hex32, ...], Field(max_length=100_000)] = ()


class SuiteSelectionCounts(StrictProtocolModel):
    fingerspelling: Annotated[int, Field(ge=1, le=1024)]
    continuous: Annotated[int, Field(ge=1, le=1024)]
    minimum_fingerspelling_datasets: Annotated[int, Field(ge=1, le=1024)] = 1
    minimum_continuous_datasets: Annotated[int, Field(ge=1, le=1024)] = 2
    minimum_fingerspelling_signers: Annotated[int, Field(ge=0, le=1024)] = 2
    minimum_continuous_signers: Annotated[int, Field(ge=0, le=1024)] = 2
    minimum_continuous_topics: Annotated[int, Field(ge=0, le=1024)] = 2
    near_sentence_token_jaccard_bps: Annotated[int, Field(ge=5000, le=10000)] = 8000
    require_qualified_cases: bool = True
    distinct_signer_per_case: bool = True

    @model_validator(mode="after")
    def diversity_fits(self):
        if (
            self.minimum_fingerspelling_datasets > self.fingerspelling
            or self.minimum_continuous_datasets > self.continuous
            or self.fingerspelling + self.continuous > 2048
            or self.minimum_fingerspelling_signers > self.fingerspelling
            or self.minimum_continuous_signers > self.continuous
            or self.minimum_continuous_topics > self.continuous
        ):
            raise ValueError("requested diversity must fit the suite case counts")
        return self


def reference_identities(text: str) -> frozenset[str]:
    """Reuse actual scorer normalization and exclude whitespace-equivalent FS text.

    This is conservative text overlap exclusion, not semantic paraphrase or
    near-duplicate video detection. Neither normalization changes a reference.
    """
    return _reference_metadata(text)[0]


def _reference_metadata(text):
    trace = normalization_trace(text)
    if not trace.normalized:
        raise ValueError("candidate reference lacks a scoring unit")
    identities = frozenset(
        hashlib.sha256(canonical_json_bytes(["umi-suite-reference/1", value])).hexdigest()
        for value in (trace.normalized, "".join(trace.graphemes_without_whitespace))
    )
    return identities, frozenset(trace.tokens)


class _SentenceExclusions:
    """Exact scorer text plus explicit lexical-near matching, not semantic truth."""

    def __init__(self, threshold):
        self.threshold = threshold
        self.exact = set()
        self.tokens = []
        self.index = {}

    def add(self, text):
        self.add_metadata(*_reference_metadata(text))

    def add_metadata(self, identities, tokens):
        self.exact.update(identities)
        if len(tokens) >= 4:
            row = len(self.tokens)
            self.tokens.append(tokens)
            for token in tokens:
                self.index.setdefault(token, set()).add(row)

    def near(self, tokens):
        if len(tokens) < 4:
            return False
        # A set with Jaccard >= t can omit at most floor((1-t)*n)
        # candidate tokens. Searching one more rare token cannot miss it.
        seeds = 1 + (10000 - self.threshold) * len(tokens) // 10000
        ordered = sorted(tokens, key=lambda token: (len(self.index.get(token, ())), token))
        rows = set().union(*(self.index.get(t, set()) for t in ordered[:seeds]))
        return any(
            10000 * len(tokens & self.tokens[row])
            >= self.threshold * len(tokens | self.tokens[row])
            for row in rows
        )


def select_future_suite(
    inventory: SuiteCandidateInventory,
    exclusions: SuiteExclusions,
    counts: SuiteSelectionCounts,
    policy: CompetitionPolicy,
    *,
    selection_key: bytes,
    observed: Callable[[], None] | None = None,
) -> tuple[EvaluationSuite, dict]:
    """Select diverse disjoint metadata; never relax exclusions to fill a quota."""
    if type(selection_key) is not bytes or len(selection_key) != 32:
        raise ValueError("private selection key must contain exactly 32 bytes")
    if policy.schema_ not in {"umi-open-competition-policy/2", "umi-open-competition-policy/3"}:
        raise ValueError("future selector requires the existing two-task scoring profile")
    text_exclusions = _SentenceExclusions(counts.near_sentence_token_jaccard_bps)
    for reference in exclusions.references:
        text_exclusions.add(reference)
    excluded_signers = set(exclusions.signer_group_sha256s)
    used_groups = set(exclusions.source_group_sha256s)
    used_signers = set(exclusions.signer_group_sha256s)
    seen_cases, seen_videos = set(), set()
    rejected = Counter()
    pool = []
    for candidate in inventory.cases:
        case = candidate.case
        if case.case_id in seen_cases or case.video_sha256 in seen_videos:
            raise ValueError("candidate inventory repeats a case or transformed video")
        seen_cases.add(case.case_id)
        seen_videos.add(case.video_sha256)
        texts, tokens = _reference_metadata(case.references[0])
        if counts.require_qualified_cases and (
            candidate.signer_group_sha256 is None or candidate.reference_qa_sha256 is None
        ):
            rejected["missing_reference_qa_or_signer_identity"] += 1
        elif candidate.source_group_sha256 in used_groups:
            rejected["known_source_group_overlap"] += 1
        elif candidate.signer_group_sha256 in excluded_signers:
            rejected["known_signer_overlap"] += 1
        elif texts & text_exclusions.exact:
            rejected["known_normalized_reference_overlap"] += 1
        elif text_exclusions.near(tokens):
            rejected["known_lexically_near_sentence_overlap"] += 1
        else:
            pool.append((candidate, texts, tokens))
        if observed is not None:
            observed()

    def rank(candidate):
        return hmac.new(
            selection_key,
            canonical_json_bytes(["umi-private-suite-selection/1", candidate.case.case_id]),
            hashlib.sha256,
        ).digest()

    selected = []
    for task in ("fingerspelling", "continuous"):
        wanted = getattr(counts, task)
        minimum = getattr(counts, "minimum_" + task + "_datasets")
        dataset_counts = Counter()
        signer_counts, topic_counts = Counter(), Counter()
        for _ in range(wanted):
            eligible = [
                (c, text, tokens)
                for c, text, tokens in pool
                if c.case.stratum == task
                and c.source_group_sha256 not in used_groups
                and (
                    not counts.distinct_signer_per_case
                    or c.signer_group_sha256 is None
                    or c.signer_group_sha256 not in used_signers
                )
                and not text & text_exclusions.exact
                and not text_exclusions.near(tokens)
            ]
            available = Counter(c.dataset for c, _, _ in eligible)
            need_new_dataset = len(dataset_counts) < minimum
            if need_new_dataset:
                eligible = [
                    (c, text, tokens)
                    for c, text, tokens in eligible
                    if not dataset_counts[c.dataset]
                ]
            if not eligible:
                raise ValueError("future suite disjoint diversity constraints are not satisfied")
            candidate, texts, tokens = min(
                eligible,
                key=lambda item: (
                    dataset_counts[item[0].dataset],
                    item[0].signer_group_sha256 is None,
                    signer_counts[item[0].signer_group_sha256],
                    item[0].topic is None,
                    topic_counts[item[0].topic],
                    available[item[0].dataset],
                    rank(item[0]),
                ),
            )
            selected.append(candidate)
            dataset_counts[candidate.dataset] += 1
            if candidate.signer_group_sha256 is not None:
                signer_counts[candidate.signer_group_sha256] += 1
                used_signers.add(candidate.signer_group_sha256)
            if candidate.topic is not None:
                topic_counts[candidate.topic] += 1
            used_groups.add(candidate.source_group_sha256)
            text_exclusions.add_metadata(texts, tokens)
        if len(signer_counts) < getattr(counts, "minimum_" + task + "_signers") or (
            task == "continuous" and len(topic_counts) < counts.minimum_continuous_topics
        ):
            raise ValueError("future suite known signer/topic diversity is not satisfied")
    suite = EvaluationSuite(
        schema="umi-competition-suite/2",
        policy_sha256=digest(policy),
        cases=tuple(sorted((c.case for c in selected), key=lambda case: case.case_id)),
    )
    validate_suite_profile(suite, policy)
    report = dict(
        schema="umi-future-suite-selection-report/1",
        status="unsigned_candidate_not_cohort_admission_or_suite_adoption",
        suite_sha256=digest(suite),
        inventory_sha256=digest(inventory),
        exclusions_sha256=digest(exclusions),
        counts=counts.model_dump(),
        considered_cases=len(inventory.cases),
        excluded_cases=dict(sorted(rejected.items())),
        selected_by_task_and_dataset={
            task: dict(
                sorted(Counter(c.dataset for c in selected if c.case.stratum == task).items())
            )
            for task in ("fingerspelling", "continuous")
        },
        selected_training_exposure=dict(
            sorted(Counter(c.training_exposure for c in selected).items())
        ),
        selected_diversity={
            task: dict(
                known_signers=len(
                    {
                        c.signer_group_sha256
                        for c in selected
                        if c.case.stratum == task and c.signer_group_sha256 is not None
                    }
                ),
                unknown_signer_cases=sum(
                    c.case.stratum == task and c.signer_group_sha256 is None for c in selected
                ),
                known_topics=len(
                    {c.topic for c in selected if c.case.stratum == task and c.topic is not None}
                ),
                unknown_topic_cases=sum(
                    c.case.stratum == task and c.topic is None for c in selected
                ),
            )
            for task in ("fingerspelling", "continuous")
        },
        unknown_or_public_exposure_is_not_verified_holdout=any(
            c.training_exposure != "documented_training_excluded" for c in selected
        ),
        selected_provenance=tuple(
            dict(
                case_id=c.case.case_id,
                dataset=c.dataset,
                dataset_version=c.dataset_version,
                source_group_sha256=c.source_group_sha256,
                provenance_sha256=c.provenance_sha256,
                license_id=c.license_id,
                attribution=c.attribution,
                training_exposure=c.training_exposure,
                training_exclusion_evidence_sha256=c.training_exclusion_evidence_sha256,
                signer_group_sha256=c.signer_group_sha256,
                topic=c.topic,
                reference_qa_sha256=c.reference_qa_sha256,
            )
            for c in sorted(selected, key=lambda item: item.case.case_id)
        ),
        media_payload_reads=0,
        original_references_changed=False,
        signed_inputs_changed=False,
    )
    return suite, report
