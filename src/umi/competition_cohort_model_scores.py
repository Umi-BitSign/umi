"""Public model scores from certified native allocation metadata only.

The independent publisher selects private native output roots and authenticates
one historical allocation certificate. It never visits the package's objects,
replays model/proof work or grants transaction authority. Completion receipts
retain the checked projection across restart and local source eviction.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import logging
import mmap
import os
import re
import stat
import time
from collections import OrderedDict
from contextlib import suppress
from copy import deepcopy
from fractions import Fraction
from pathlib import Path
from threading import RLock
from typing import Annotated, Literal

from pydantic import Field, model_serializer, model_validator

from .competition_cohort_coordinator import replay_cohort_decisions
from .competition_cohort_history import CohortRecoveryHistory
from .competition_cohort_intake import history_tip
from .competition_cohort_model_award import GeometricModelAward
from .competition_cohort_order_signer import CohortOrderHistory
from .competition_cohort_reward_allocation import CohortRewardAllocation
from .competition_cohort_roster import RecoverableRosterEvidence
from .competition_geometric_rewards import GeometricRewardParameters, baseline_eligibility_threshold
from .competition_public_results import PublicQuality
from .competition_public_results_directory import atomic_write, owned_directory, read_owned_file
from .competition_public_results_publisher import publisher_lease, read_config_file
from .competition_reward_adoption import RewardModelAdoption
from .competition_verification_snapshot import _Checksummed
from .competition_work_progress import WorkProgress
from .concurrency import run_owned_thread
from .json_spans import UnsplitJSON, string_end, value_end, whitespace
from .open_competition import CompetitionPolicy, Hotkey, digest, identity
from .private_files import Directory, private_path
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

_ID = re.compile(r"[0-9a-f]{64}")
MAX_PUBLIC_BYTES = 2 * 1024**2
SEMANTICS = hashlib.sha256(b"umi-native-certified-model-score-projection/1").hexdigest()
logger = logging.getLogger(__name__)


class ModelScore(PublicQuality):
    @classmethod
    def make(cls, value):
        f = Fraction(int(value.numerator), int(value.denominator))
        return cls(numerator=str(f.numerator), denominator=str(f.denominator), decimal=float(f))


class PublicModelScore(StrictProtocolModel):
    submission_sha256: Hex32
    model_sha256: Hex32
    uid: int = Field(ge=0, le=255)
    hotkey: Hotkey
    status: Literal["scored", "not_scored"]
    aggregate: ModelScore | None
    baseline_aggregate: ModelScore | None
    baseline_threshold: ModelScore | None = None
    score_rank: int | None = Field(default=None, ge=1, le=512)
    baseline_eligible: bool | None
    model_reward_status: Literal[
        "selected_by_certified_rule",
        "below_baseline",
        "not_selected_by_certified_rule",
        "not_scored",
    ]
    certified_raw_weight_for_hotkey: int = Field(ge=0, le=65535)

    @model_serializer(mode="wrap")
    def preserve_original_score(self, handler):
        value = handler(self)
        if self.baseline_threshold is None:
            value.pop("baseline_threshold", None)
        return value


class PublicModelScores(StrictProtocolModel):
    schema_: Literal[
        "umi-public-cohort-model-results/1",
        "umi-public-cohort-model-results/2",
        "umi-public-cohort-model-results/3",
    ] = Field(alias="schema")
    cohort_sha256: Hex32
    round_sha256: Hex32
    policy_sha256: Hex32
    allocation_sha256: Hex32
    certified_history_tip_sha256: Hex32
    source_metadata_sha256: Hex32
    certification: Literal[
        "quorum_certified_native_allocation",
        "quorum_certified_score_correction",
        "quorum_certified_reward_adoption",
    ]
    original_allocation_sha256: Hex32 | None = None
    original_source_metadata_sha256: Hex32 | None = None
    score_correction_statement_sha256: Hex32 | None = None
    reward_adoption_sha256: Hex32 | None = None
    reward_parameters: GeometricRewardParameters | None = None
    reward_activation: Literal["not_assessed_by_this_endpoint"] = "not_assessed_by_this_endpoint"
    raw_weight_scope: Literal["certified_cohort_all_tracks_per_hotkey"] = (
        "certified_cohort_all_tracks_per_hotkey"
    )
    score_semantics: Literal["normalized_quality_not_accuracy_or_reward_share"] = (
        "normalized_quality_not_accuracy_or_reward_share"
    )
    chain_submission_authorized: Literal[False] = False
    items: Annotated[tuple[PublicModelScore, ...], Field(max_length=512)]

    @model_serializer(mode="wrap")
    def preserve_original_publication(self, handler):
        value = handler(self)
        for key in (
            "original_allocation_sha256",
            "original_source_metadata_sha256",
            "score_correction_statement_sha256",
            "reward_adoption_sha256",
            "reward_parameters",
        ):
            if getattr(self, key) is None:
                value.pop(key, None)
        return value

    @model_validator(mode="after")
    def ranks(self):
        if self.reward_parameters is not None and self.reward_parameters.baseline_grace_bps is None:
            raise ValueError("explicit public reward parameters require a selected baseline grace")
        adopted = self.schema_ == "umi-public-cohort-model-results/3"
        corrected = self.schema_ == "umi-public-cohort-model-results/2"
        if adopted:
            if (
                self.certification != "quorum_certified_reward_adoption"
                or self.original_allocation_sha256 is None
                or self.original_source_metadata_sha256 is None
                or self.reward_adoption_sha256 is None
            ):
                raise ValueError("public reward adoption needs its exact signed source")
        elif self.certification != (
            "quorum_certified_score_correction"
            if corrected
            else "quorum_certified_native_allocation"
        ) or any(
            (getattr(self, key) is not None) != corrected
            for key in (
                "original_allocation_sha256",
                "score_correction_statement_sha256",
                "reward_adoption_sha256",
            )
        ):
            raise ValueError("public score correction needs an explicit signed source")
        if not adopted and self.original_source_metadata_sha256 is not None:
            raise ValueError("original public source binding requires a reward adoption")
        keys = [r.submission_sha256 for r in self.items]
        if len(keys) != len(set(keys)):
            raise ValueError("public model scores repeat a submission")
        scores = sorted(
            (
                Fraction(int(r.aggregate.numerator), int(r.aggregate.denominator))
                for r in self.items
                if r.aggregate
            ),
            reverse=True,
        )
        for r in self.items:
            if (r.status == "scored") != (
                r.aggregate is not None and r.baseline_aggregate is not None
            ):
                raise ValueError("public model score disposition differs")
            if r.aggregate is None and (
                r.score_rank is not None
                or r.baseline_eligible is not None
                or r.baseline_threshold is not None
                or r.model_reward_status != "not_scored"
            ):
                raise ValueError("unscored model cannot have a rank or reward eligibility")
            if r.aggregate is not None:
                f = Fraction(int(r.aggregate.numerator), int(r.aggregate.denominator))
                if r.score_rank != scores.index(f) + 1:
                    raise ValueError("public model rank differs from exact quality")
                baseline = Fraction(
                    int(r.baseline_aggregate.numerator), int(r.baseline_aggregate.denominator)
                )
                threshold = (
                    baseline
                    if self.reward_parameters is None
                    else baseline_eligibility_threshold(baseline, self.reward_parameters)
                )
                if (r.baseline_threshold is None) != (self.reward_parameters is None) or (
                    r.baseline_threshold is not None
                    and Fraction(
                        int(r.baseline_threshold.numerator), int(r.baseline_threshold.denominator)
                    )
                    != threshold
                ):
                    raise ValueError("public baseline threshold differs from selected grace")
                if r.baseline_eligible != (f >= threshold) or (
                    r.model_reward_status == "below_baseline"
                ) != (f < threshold):
                    raise ValueError("public model reward status differs from baseline eligibility")
        return self


def _public_reward_parameters(award):
    """Keep historical publication bytes; expose prospective signed grace explicitly."""
    return (
        award.parameters
        if isinstance(award, GeometricModelAward)
        and award.parameters.baseline_grace_bps is not None
        else None
    )


def project_corrected_model_scores(original, adoption, corrected):
    """Project one signed correction from retained public rows and allocation."""
    original = PublicModelScores.model_validate_json(canonical_json_bytes(original))
    adoption = RewardModelAdoption.model_validate_json(canonical_json_bytes(adoption))
    corrected = CohortRewardAllocation.model_validate_json(canonical_json_bytes(corrected))
    if adoption.signed_score_correction is None:
        raise ValueError("public correction requires explicit signed score evidence")
    evidence = adoption.score_correction_evidence
    statement = adoption.signed_score_correction.statement
    if (
        original.schema_ != "umi-public-cohort-model-results/1"
        or original.cohort_sha256 != adoption.cohort_sha256
        or original.policy_sha256 != adoption.policy_sha256
        or original.allocation_sha256 != adoption.allocation_sha256
        or digest(corrected) != adoption.effective_allocation_sha256
        or digest(corrected.model_award) != statement.corrected_model_award_sha256
        or digest(evidence) != statement.evidence_sha256
        or len(original.items) != len(evidence.rows)
    ):
        raise ValueError("public correction differs from signed native allocation")
    rows = {row.submission_sha256: row for row in evidence.rows}
    credits = {credit.submission_sha256 for credit in corrected.model_award.credits}
    weights = {identity(row.hotkey): row.raw_weight for row in corrected.recipients}
    parameters = _public_reward_parameters(corrected.model_award)
    changed = []
    for item in original.items:
        row = rows.pop(item.submission_sha256, None)
        if row is None or (row.uid, row.model_sha256) != (item.uid, item.model_sha256):
            raise ValueError("public correction changed a certified model identity")
        aggregate = Fraction(int(row.aggregate.numerator), int(row.aggregate.denominator))
        baseline = Fraction(
            int(evidence.baseline_aggregate.numerator),
            int(evidence.baseline_aggregate.denominator),
        )
        threshold = (
            baseline if parameters is None else baseline_eligibility_threshold(baseline, parameters)
        )
        eligible = aggregate >= threshold
        changed.append(
            item.model_copy(
                update={
                    "aggregate": ModelScore.make(row.aggregate),
                    "baseline_aggregate": ModelScore.make(evidence.baseline_aggregate),
                    "baseline_threshold": None
                    if parameters is None
                    else ModelScore.make(threshold),
                    "baseline_eligible": eligible,
                    "score_rank": None,
                    "model_reward_status": "below_baseline"
                    if not eligible
                    else "selected_by_certified_rule"
                    if item.submission_sha256 in credits
                    else "not_selected_by_certified_rule",
                    "certified_raw_weight_for_hotkey": weights.get(identity(item.hotkey), 0),
                }
            )
        )
    if rows:
        raise ValueError("public correction has a model outside certified public roster")
    scores = sorted(
        (
            Fraction(int(item.aggregate.numerator), int(item.aggregate.denominator))
            for item in changed
        ),
        reverse=True,
    )
    changed = [
        item.model_copy(
            update={
                "score_rank": scores.index(
                    Fraction(int(item.aggregate.numerator), int(item.aggregate.denominator))
                )
                + 1
            }
        )
        for item in changed
    ]
    changed.sort(key=lambda item: (item.score_rank, item.uid, item.submission_sha256))
    return PublicModelScores(
        schema="umi-public-cohort-model-results/2",
        cohort_sha256=original.cohort_sha256,
        round_sha256=original.round_sha256,
        policy_sha256=original.policy_sha256,
        allocation_sha256=digest(corrected),
        original_allocation_sha256=original.allocation_sha256,
        score_correction_statement_sha256=digest(statement),
        reward_adoption_sha256=digest(adoption),
        certified_history_tip_sha256=original.certified_history_tip_sha256,
        source_metadata_sha256=digest(
            {
                "original_publication": digest(original),
                "signed_statement": digest(statement),
                "corrected_allocation": digest(corrected),
            }
        ),
        certification="quorum_certified_score_correction",
        reward_parameters=parameters,
        items=tuple(changed),
    )


def project_adopted_model_scores(original, adoption, effective):
    """Project a selected signed adoption; the caller authenticates its full lineage.

    Start from the retained native publication, never an earlier adopted output.
    Ordinary reward adoption cannot change quality, roster or measured baseline.
    A score change requires the separate signed correction evidence path.
    """
    original = PublicModelScores.model_validate_json(canonical_json_bytes(original))
    adoption = RewardModelAdoption.model_validate_json(canonical_json_bytes(adoption))
    effective = CohortRewardAllocation.model_validate_json(canonical_json_bytes(effective))
    award = effective.model_award
    if (
        original.schema_ != "umi-public-cohort-model-results/1"
        or original.cohort_sha256 != adoption.cohort_sha256
        or original.policy_sha256 != adoption.policy_sha256
        or original.allocation_sha256 != adoption.allocation_sha256
        or original.round_sha256 != effective.round_sha256
        or original.policy_sha256 != effective.policy_sha256
        or digest(effective) != adoption.effective_allocation_sha256
        or not isinstance(award, GeometricModelAward)
        or award.parameters != adoption.parameters
        or award.authority_sha256 != adoption.authority_sha256
        or award.policy_sha256 != original.policy_sha256
        or award.round_sha256 != original.round_sha256
        or effective.service_certificate_sha256 != adoption.service_certificate_sha256
        or effective.quality_manifest_sha256
        != (
            adoption.quality_manifest_sha256
            if adoption.signed_score_correction is None
            else digest(adoption.score_correction_evidence)
        )
        or award.quality_manifest_sha256 != effective.quality_manifest_sha256
    ):
        raise ValueError("public reward adoption differs from its exact effective allocation")
    if adoption.signed_score_correction is not None:
        projected = project_corrected_model_scores(original, adoption, effective)
    else:
        candidates = {candidate.submission_sha256: candidate for candidate in award.candidates}
        selected = {credit.submission_sha256 for credit in award.credits}
        weights = {identity(row.hotkey): row.raw_weight for row in effective.recipients}
        parameters = _public_reward_parameters(award)
        rows = []
        for item in original.items:
            candidate = candidates.pop(item.submission_sha256, None)
            if candidate is None:
                if item.status != "not_scored":
                    raise ValueError("public adoption omitted a certified model score")
                rows.append(
                    item.model_copy(
                        update={
                            "certified_raw_weight_for_hotkey": weights.get(
                                identity(item.hotkey), 0
                            ),
                        }
                    )
                )
                continue
            if (
                item.status != "scored"
                or candidate.model_sha256 != item.model_sha256
                or identity(candidate.recipient_hotkey) != identity(item.hotkey)
                or ModelScore.make(candidate.aggregate) != item.aggregate
                or ModelScore.make(candidate.baseline_aggregate) != item.baseline_aggregate
            ):
                raise ValueError("ordinary reward adoption cannot change certified model quality")
            measured = Fraction(
                int(candidate.baseline_aggregate.numerator),
                int(candidate.baseline_aggregate.denominator),
            )
            threshold = baseline_eligibility_threshold(measured, award.parameters)
            eligible = (
                Fraction(int(candidate.aggregate.numerator), int(candidate.aggregate.denominator))
                >= threshold
            )
            rows.append(
                item.model_copy(
                    update={
                        "baseline_threshold": None
                        if parameters is None
                        else ModelScore.make(threshold),
                        "baseline_eligible": eligible,
                        "model_reward_status": "below_baseline"
                        if not eligible
                        else "selected_by_certified_rule"
                        if item.submission_sha256 in selected
                        else "not_selected_by_certified_rule",
                        "certified_raw_weight_for_hotkey": weights.get(identity(item.hotkey), 0),
                    }
                )
            )
        if candidates:
            raise ValueError("public adoption has a model outside its certified roster")
        projected = original.model_copy(
            update={
                "items": tuple(rows),
                "reward_parameters": parameters,
            }
        )
    return PublicModelScores.model_validate_json(
        canonical_json_bytes(
            projected.model_copy(
                update={
                    "schema_": "umi-public-cohort-model-results/3",
                    "certification": "quorum_certified_reward_adoption",
                    "allocation_sha256": digest(effective),
                    "original_allocation_sha256": original.allocation_sha256,
                    "original_source_metadata_sha256": original.source_metadata_sha256,
                    "reward_adoption_sha256": digest(adoption),
                    "source_metadata_sha256": digest(
                        {
                            "original_publication": digest(original),
                            "reward_adoption": digest(adoption),
                            "effective_allocation": digest(effective),
                        }
                    ),
                }
            )
        )
    )


def _stamp(path):
    private_path(str(path))
    s = path.lstat()
    if (
        not stat.S_ISREG(s.st_mode)
        or s.st_nlink != 1
        or s.st_uid != os.getuid()
        or s.st_mode & 0o077
    ):
        raise ValueError("native score source must be owned and private")
    return [
        s.st_dev,
        s.st_ino,
        s.st_mode,
        s.st_nlink,
        s.st_uid,
        s.st_gid,
        s.st_size,
        s.st_mtime_ns,
        s.st_ctime_ns,
    ]


def native_header(path, *, maximum_bytes, maximum_metadata_bytes):
    """Read canonical fields preceding objects; never traverse that inventory."""
    before = _stamp(path)
    if not 0 < before[6] <= maximum_bytes:
        raise ValueError("native score package exceeds selected capacity")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        opened = os.fstat(fd)
        if [
            opened.st_dev,
            opened.st_ino,
            opened.st_mode,
            opened.st_nlink,
            opened.st_uid,
            opened.st_gid,
            opened.st_size,
            opened.st_mtime_ns,
            opened.st_ctime_ns,
        ] != before:
            raise ValueError("native score package changed while opening")
        with mmap.mmap(fd, min(before[6], maximum_metadata_bytes), access=mmap.ACCESS_READ) as raw:
            if raw[0:1] != b"{":
                raise ValueError("native score source is not an aggregate package")
            position, result, previous = 1, {}, ""
            while True:
                position = whitespace(raw, position)
                end = string_end(raw, position)
                key = json.loads(raw[position:end])
                if key <= previous:
                    raise ValueError("native score metadata is not canonical field order")
                previous = key
                position = whitespace(raw, end)
                if raw[position : position + 1] != b":":
                    raise ValueError("native score metadata framing differs")
                position = whitespace(raw, position + 1)
                if key == "objects":
                    if not {"allocation", "inputs"} <= result.keys():
                        raise ValueError("native score metadata needs a supported aggregate layout")
                    break
                end = value_end(raw, position, 0)
                if key in {"allocation", "inputs"}:
                    result[key] = json.loads(raw[position:end])
                position = whitespace(raw, end)
                if raw[position : position + 1] != b",":
                    raise ValueError("native score metadata has no following object inventory")
                position += 1
    except (UnsplitJSON, IndexError) as error:
        raise ValueError(
            "native score metadata exceeds its bound or needs layout repair"
        ) from error
    finally:
        os.close(fd)
    if _stamp(path) != before:
        raise ValueError("native score package changed during metadata read")
    return result, before


def project_model_scores(header, history_packet, policy, *, cohort):
    """Authenticate historical public metadata once, without native payload replay."""
    allocation = CohortRewardAllocation.model_validate_json(
        canonical_json_bytes(header["allocation"])
    )
    inputs = header["inputs"]
    roster = RecoverableRosterEvidence.model_validate_json(canonical_json_bytes(inputs["roster"]))
    history = CohortRecoveryHistory.model_validate_json(canonical_json_bytes(inputs["history"]))
    if history_packet.history != history or digest(history.plan) != cohort:
        raise ValueError("public score history differs from selected native package")
    decisions = history_packet.inputs()
    replay_cohort_decisions(history, policy, decisions.__getitem__)
    closes = [
        t.transition
        for t in history.transitions
        if t.transition.phase == "certification" and t.transition.operation == "close_phase"
    ]
    if len(closes) != 1:
        raise ValueError("public scores require certified native allocation")
    progress = decisions[closes[0].evidence_sha256].progress.progress
    allocation_sha = digest(allocation)
    if progress.phase_result_sha256 != allocation_sha or progress.evidence_sha256 != allocation_sha:
        raise ValueError("public score allocation differs from its certified result")
    award = allocation.model_award
    if (
        award is None
        or (allocation.policy_sha256, award.roster_sha256, award.round_sha256)
        != (digest(policy), digest(roster), digest(roster.round))
        or roster.round.cohort_sha256 != cohort
    ):
        raise ValueError("public score roster or policy differs from certified model award")
    candidates = {c.submission_sha256: c for c in award.candidates}
    selected = {c.submission_sha256 for c in getattr(award, "credits", ())}
    winner = getattr(award, "winner_submission_sha256", None)
    if winner is not None:
        selected.add(winner)
    weights = {identity(r.hotkey): r.raw_weight for r in allocation.recipients}
    parameters = _public_reward_parameters(award)
    rows = []
    for participant in roster.participants:
        submission = participant.record.request.signed_submission.submission
        if submission.track != "model":
            continue
        admission = participant.admission.admission
        key = admission.submission_sha256
        candidate = candidates.pop(key, None)
        if candidate is not None and identity(candidate.recipient_hotkey) != identity(
            submission.hotkey
        ):
            raise ValueError("public model score recipient differs from retained admission")
        threshold = None
        eligible = None
        if candidate is not None:
            baseline = Fraction(
                int(candidate.baseline_aggregate.numerator),
                int(candidate.baseline_aggregate.denominator),
            )
            threshold = (
                baseline
                if parameters is None
                else baseline_eligibility_threshold(baseline, parameters)
            )
            eligible = (
                Fraction(int(candidate.aggregate.numerator), int(candidate.aggregate.denominator))
                >= threshold
            )
        rows.append(
            PublicModelScore(
                submission_sha256=key,
                model_sha256=digest(submission.model_bundle)
                if candidate is None
                else candidate.model_sha256,
                uid=admission.uid,
                hotkey=submission.hotkey,
                status="not_scored" if candidate is None else "scored",
                aggregate=None if candidate is None else ModelScore.make(candidate.aggregate),
                baseline_aggregate=None
                if candidate is None
                else ModelScore.make(candidate.baseline_aggregate),
                baseline_threshold=None
                if candidate is None or parameters is None
                else ModelScore.make(threshold),
                baseline_eligible=eligible,
                model_reward_status="not_scored"
                if candidate is None
                else "below_baseline"
                if not eligible
                else "selected_by_certified_rule"
                if key in selected
                else "not_selected_by_certified_rule",
                certified_raw_weight_for_hotkey=weights.get(identity(submission.hotkey), 0),
            )
        )
    if candidates:
        raise ValueError("certified model award has a candidate outside its retained roster")
    ordered = sorted(
        (
            Fraction(int(r.aggregate.numerator), int(r.aggregate.denominator))
            for r in rows
            if r.aggregate
        ),
        reverse=True,
    )
    rows = [
        row
        if row.aggregate is None
        else row.model_copy(
            update={
                "score_rank": ordered.index(
                    Fraction(int(row.aggregate.numerator), int(row.aggregate.denominator))
                )
                + 1
            }
        )
        for row in rows
    ]
    rows.sort(key=lambda r: (r.score_rank is None, r.score_rank or 0, r.uid, r.submission_sha256))
    metadata = dict(
        allocation=header["allocation"], roster=inputs["roster"], history=inputs["history"]
    )
    return PublicModelScores(
        schema="umi-public-cohort-model-results/1",
        cohort_sha256=cohort,
        round_sha256=award.round_sha256,
        policy_sha256=allocation.policy_sha256,
        allocation_sha256=allocation_sha,
        certified_history_tip_sha256=history_tip(history),
        source_metadata_sha256=hashlib.sha256(canonical_json_bytes(metadata)).hexdigest(),
        certification="quorum_certified_native_allocation",
        reward_parameters=parameters,
        items=tuple(rows),
    )


class NativeModelScoresConfig(StrictProtocolModel):
    source_directory: Directory
    history_directory: Directory
    output_directory: Directory
    state_directory: Directory
    policy_path: Directory
    policy_sha256: Hex32
    maximum_package_bytes: int = Field(gt=0)
    maximum_metadata_bytes: int = Field(default=128 * 1024**2, gt=0)
    poll_seconds: float = Field(default=15, ge=1, le=3600)
    reward_coordinator_config: Directory | None = None

    @model_serializer(mode="wrap")
    def preserve_original_config(self, handler):
        value = handler(self)
        if self.reward_coordinator_config is None:
            value.pop("reward_coordinator_config", None)
        return value

    @model_validator(mode="after")
    def disjoint(self):
        paths = tuple(
            map(
                Path,
                (
                    self.source_directory,
                    self.history_directory,
                    self.output_directory,
                    self.state_directory,
                ),
            )
        )
        if any(
            a.is_relative_to(b) or b.is_relative_to(a)
            for i, a in enumerate(paths)
            for b in paths[i + 1 :]
        ):
            raise ValueError(
                "native score source, history, output and completion state must be disjoint"
            )
        if self.reward_coordinator_config is not None:
            boot = Path(self.reward_coordinator_config)
            if any(boot == path or boot.is_relative_to(path) for path in paths):
                raise ValueError("selected reward boot must be outside mutable public score stores")
        return self


class ScoreCompletion(_Checksummed):
    schema_: Literal["umi-native-public-model-score-completion/1"] = Field(alias="schema")
    binding_sha256: Hex32
    semantics_sha256: Hex32
    source_stamp: tuple[str, ...]
    projection: PublicModelScores


class NativeModelScoresPublisher:
    def __init__(self, config):
        self.config = config
        self.source, self.history, self.output, self.state = map(
            Path,
            (
                config.source_directory,
                config.history_directory,
                config.output_directory,
                config.state_directory,
            ),
        )
        for p in (self.source, self.history):
            owned_directory(p)
        for p in (self.output, self.state):
            owned_directory(p, create=True)
        info = self.source.stat()
        self.binding = digest(
            dict(
                source=str(self.source),
                source_device=info.st_dev,
                source_inode=info.st_ino,
                owner=os.getuid(),
                history=str(self.history),
                policy=config.policy_sha256,
            )
        )
        self.policy = CompetitionPolicy.model_validate_json(
            read_config_file(Path(config.policy_path))
        )
        if digest(self.policy) != config.policy_sha256:
            raise ValueError("native score publisher policy selection differs")
        self.receipts, self.published = {}, {}
        self.source_identity = self._source_identity()
        self.adoptions = None
        if config.reward_coordinator_config is not None:
            # This boundary imports the public projection types above; defer it
            # until the complete module is loaded, not during schema definition.
            from .competition_cohort_model_score_adoption import SelectedModelScoreAdoptions

            self.adoptions = SelectedModelScoreAdoptions(
                Path(config.reward_coordinator_config), policy=self.policy, state=self.state
            )

    def _source_identity(self):
        identities = []
        for path in (self.source, self.history):
            owned_directory(path)
            info = path.stat()
            identities.append((info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode))
        return tuple(identities)

    def poll_once(self):
        with publisher_lease(self.state):
            return self._poll_once()

    def _poll_once(self):
        if self._source_identity() != self.source_identity:
            raise ValueError("selected native score namespace changed; explicit repair required")
        names = {
            p.stem
            for parent in (self.source, self.state)
            for p in parent.iterdir()
            if p.suffix == ".json" and _ID.fullmatch(p.stem)
        }
        report = dict(
            stage="native_model_score_publication",
            completed=0,
            total=len(names),
            published=[],
            retained=[],
            held=[],
            eta_scope="public_metadata_projection_only_excludes_rewards",
            chain_submission_authorized=False,
        )
        entered = time.monotonic()
        with WorkProgress("native_model_score_publication", len(names), unit="cohorts") as progress:
            for cohort in sorted(names):
                stage = "completion_metadata"
                try:
                    receipt_path = self.state / (cohort + ".json")
                    source = self.source / (cohort + ".json")
                    try:
                        receipt_stamp = tuple(_stamp(receipt_path))
                        cached = self.receipts.get(cohort)
                        receipt = (
                            cached[1]
                            if cached is not None and cached[0] == receipt_stamp
                            else ScoreCompletion.model_validate_json(
                                read_owned_file(receipt_path, 2 * MAX_PUBLIC_BYTES)
                            ).checked()
                        )
                    except FileNotFoundError:
                        if (self.output / (cohort + ".json")).exists():
                            raise ValueError(
                                "completed public score receipt missing; explicit repair required"
                            ) from None
                        stage = "native_public_metadata"
                        header, stamp = native_header(
                            source,
                            maximum_bytes=self.config.maximum_package_bytes,
                            maximum_metadata_bytes=self.config.maximum_metadata_bytes,
                        )
                        history = CohortRecoveryHistory.model_validate_json(
                            canonical_json_bytes(header["inputs"]["history"])
                        )
                        history_path = self.history / cohort / (history_tip(history) + ".json")
                        private_path(str(history_path))
                        stage = "certified_history"
                        packet = CohortOrderHistory.model_validate_json(
                            read_owned_file(
                                history_path,
                                8 * 1024**2,
                            )
                        )
                        stage = "public_projection"
                        projected = project_model_scores(header, packet, self.policy, cohort=cohort)
                        receipt = ScoreCompletion(
                            schema="umi-native-public-model-score-completion/1",
                            binding_sha256=self.binding,
                            semantics_sha256=SEMANTICS,
                            source_stamp=tuple(map(str, stamp)),
                            projection=projected,
                        ).sealed()
                        stage = "completion_publication"
                        atomic_write(receipt_path, canonical_json_bytes(receipt))
                        receipt_stamp = tuple(_stamp(receipt_path))
                    self.receipts[cohort] = (receipt_stamp, receipt)
                    stage = "retained_binding"
                    if (
                        receipt.binding_sha256 != self.binding
                        or receipt.semantics_sha256 != SEMANTICS
                        or receipt.projection.cohort_sha256 != cohort
                    ):
                        raise ValueError(
                            "completed public score binding differs; explicit repair required"
                        )
                    if source.exists() and tuple(map(str, _stamp(source))) != receipt.source_stamp:
                        raise ValueError(
                            "completed native score source changed; explicit repair required"
                        )
                    output = self.output / (cohort + ".json")
                    stage = "selected_reward_adoption"
                    projected = (
                        receipt.projection
                        if self.adoptions is None
                        else self.adoptions.project(receipt.projection, output=output)
                    )
                    stage = "public_artifact_publication"
                    present = output.exists()
                    if not present or self.published.get(cohort) != tuple(_stamp(output)):
                        atomic_write(
                            output,
                            canonical_json_bytes(projected),
                            immutable=projected == receipt.projection,
                        )
                        self.published[cohort] = tuple(_stamp(output))
                    report["retained" if present else "published"].append(cohort)
                    report["completed"] += 1
                    progress.advance()
                except (OSError, ValueError, KeyError) as error:
                    report["held"].append(
                        dict(cohort_sha256=cohort, stage=stage, error_type=type(error).__name__)
                    )
        report.update(
            elapsed_seconds=round(time.monotonic() - entered, 3),
            eta_seconds=0 if not report["held"] else None,
            eta_basis="all_public_metadata_published"
            if not report["held"]
            else "awaiting_native_package_history_or_explicit_metadata_repair",
            stalled_or_retrying=bool(report["held"]),
        )
        return report


class PublicModelScoreCache:
    """Background-only metadata reads; HTTP copies already checked public rows."""

    def __init__(self, root, *, maximum_bytes=64 * 1024**2, corrections=None):
        self.root, self.lock, self.cache = Path(root), RLock(), OrderedDict()
        self.maximum_bytes, self.failed = maximum_bytes, False
        self.corrections = dict(corrections or {})

    def sample(self):
        owned_directory(self.root)
        directory = self.root / "model-results"
        if not directory.exists():
            with self.lock:
                self.failed = bool(self.cache)
            return
        owned_directory(directory)
        corrected_directory = self.root / "model-results-corrections"
        if self.corrections:
            owned_directory(corrected_directory)
        paths = sorted(
            p for p in directory.iterdir() if p.suffix == ".json" and _ID.fullmatch(p.stem)
        )
        if len(paths) > 1024:
            raise ValueError("public model score metadata index needs additional capacity")
        current, size = {}, 0
        for path in paths:
            cohort = path.stem
            expected_statement = self.corrections.get(cohort)
            if expected_statement is not None:
                path = corrected_directory / path.name
            stamp = None
            try:
                stamp = tuple(_stamp(path))
                size += stamp[6]
                if size > self.maximum_bytes:
                    raise ValueError("public model score cache needs additional capacity")
                with self.lock:
                    previous = self.cache.get(cohort)
                if previous is not None and previous[0] == stamp:
                    current[cohort] = previous
                    continue
                value = PublicModelScores.model_validate_json(
                    read_owned_file(path, MAX_PUBLIC_BYTES)
                )
                if (
                    value.cohort_sha256 != cohort
                    or (
                        value.score_correction_statement_sha256 != expected_statement
                        and (
                            expected_statement is not None
                            or value.schema_ != "umi-public-cohort-model-results/3"
                        )
                    )
                    or tuple(_stamp(path)) != stamp
                ):
                    raise ValueError("public model score publication binding changed")
                current[cohort] = (stamp, value.model_dump(mode="json", by_alias=True))
            except (OSError, ValueError):
                current[cohort] = (stamp, None)
        with self.lock:
            # A previously published missing artifact is an explicit repair,
            # rather than a fresh never-published404 or stale successful rows.
            for cohort in self.cache.keys() - current.keys():
                current[cohort] = (None, None)
            self.cache, self.failed = current, False

    def read(self, cohort):
        with self.lock:
            if self.failed:
                raise ValueError("public model score cache needs metadata repair")
            selected = self.cache.get(cohort)
            if selected is None:
                raise FileNotFoundError("certified model results not published")
            if selected[1] is None:
                raise ValueError("completed public model score metadata needs repair")
            return deepcopy(selected[1])

    async def run(self, stop):
        while not stop.is_set():
            try:
                await run_owned_thread(self.sample)
            except (OSError, ValueError):
                with self.lock:
                    self.failed = True
            with suppress(asyncio.TimeoutError):
                await asyncio.wait_for(stop.wait(), timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--watch", action="store_true")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    config = NativeModelScoresConfig.model_validate_json(args.config.read_bytes())
    publisher = NativeModelScoresPublisher(config)
    while True:
        print(json.dumps(publisher.poll_once(), sort_keys=True), flush=True)
        if not args.watch:
            return
        time.sleep(config.poll_seconds)


if __name__ == "__main__":
    main()
