"""Exact private suite proposal and independently reusable native media review."""

import json
import os
import stat
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, model_validator

from .competition_cohort_suite_adoption import prepare_evaluation_suite_adoption
from .competition_suite_reference_qa import SuiteReferenceQA
from .competition_suite_selection import (
    SuiteCandidateInventory,
    SuiteExclusions,
    SuiteSelectionCounts,
    select_future_suite,
)
from .competition_transport_verification import ByteCheckpoints, TransferProgress
from .competition_verification_rules import runtime_identity
from .concurrency import run_owned_thread
from .file_identity import file_fingerprint
from .media import inspect_media_pinned
from .open_competition import EvaluationSuite, Hotkey, digest, identity, validate_suite_profile
from .private_files import Directory, _read_private_bytes, ensure_private_directory, private_path
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes


@dataclass(frozen=True)
class EvaluationSuiteQualification:
    candidate_sha256: str
    policy_sha256: str
    adoption_sha256: str
    files: tuple[tuple[str, ...], ...]


class EvaluationSuiteAdoptionCandidateConfig(StrictProtocolModel):
    schema_: Literal[
        "umi-evaluation-suite-adoption-candidate/1", "umi-evaluation-suite-adoption-candidate/2"
    ] = Field(default="umi-evaluation-suite-adoption-candidate/2", alias="schema")
    cohort_sha256: Hex32
    verification_owner_hotkey: Hotkey
    suite_file: Directory
    selection_manifest_file: Directory
    inventory_file: Directory
    exclusions_file: Directory
    selection_key_file: Directory
    videos_directory: Directory
    reference_qa_directory: Directory
    verification_directory: Directory
    ffmpeg_binary: Directory
    ffprobe_binary: Directory
    ffmpeg_sha256: Hex32
    ffprobe_sha256: Hex32
    maximum_metadata_bytes: Annotated[int, Field(ge=1024, le=64 * 1024**2)] = 16 * 1024**2
    maximum_video_bytes: Annotated[int, Field(ge=1024, le=512 * 1024**2)] = 64 * 1024**2
    verification_repair_reason: Annotated[str, Field(min_length=1, max_length=1024)] | None = None

    @model_validator(mode="after")
    def paths(self):
        files = self.metadata_paths()
        roots = tuple(
            Path(p)
            for p in (
                self.videos_directory,
                self.reference_qa_directory,
                self.verification_directory,
            )
        )
        if (
            len(set(files)) != len(files)
            or any(
                a == b or a in b.parents or b in a.parents
                for i, a in enumerate(roots)
                for b in roots[i + 1 :]
            )
            or any(p == r or r in p.parents or p in r.parents for p in files for r in roots)
        ):
            raise ValueError("suite candidate metadata, media and verification stores overlap")
        if (
            self.verification_repair_reason is not None
            and not self.verification_repair_reason.strip()
        ):
            raise ValueError("suite verification repair requires an explicit reason")
        return self

    def metadata_paths(self):
        return tuple(
            Path(getattr(self, key))
            for key in (
                "suite_file",
                "selection_manifest_file",
                "inventory_file",
                "exclusions_file",
                "selection_key_file",
            )
        )

    def stores(self):
        return (
            *self.metadata_paths(),
            Path(self.videos_directory),
            Path(self.reference_qa_directory),
            Path(self.verification_directory),
        )


EvaluationSuiteAdoptionCandidates = Annotated[
    tuple[EvaluationSuiteAdoptionCandidateConfig, ...], Field(max_length=512)
]


def require_successor_suite_diversity(
    sequence: int,
    counts: SuiteSelectionCounts,
    *,
    candidate_schema: str = "umi-evaluation-suite-adoption-candidate/2",
) -> None:
    """Apply new adoption rules without reinterpreting earlier signed suites."""
    if candidate_schema not in {
        "umi-evaluation-suite-adoption-candidate/1",
        "umi-evaluation-suite-adoption-candidate/2",
    }:
        raise ValueError("unsupported suite candidate qualification schema")
    if sequence >= 7 and (
        counts.maximum_continuous_dataset_share_bps is None
        or counts.maximum_continuous_dataset_share_bps > 5000
        or counts.minimum_continuous_topics < 4
    ):
        raise ValueError(
            "C7+ suite adoption requires a continuous source cap of 50% "
            "and at least four distinct topics"
        )
    if sequence >= 7 and (
        counts.minimum_fingerspelling_datasets < 2
        or counts.maximum_fingerspelling_dataset_share_bps is None
        or counts.maximum_fingerspelling_dataset_share_bps > 7500
    ):
        raise ValueError(
            "C7+ suite adoption requires at least two fingerspelling sources "
            "and a maximum 75% share from one source"
        )
    if (
        sequence >= 7
        and candidate_schema == "umi-evaluation-suite-adoption-candidate/1"
        and (
            counts.minimum_training_excluded_fingerspelling < counts.fingerspelling
            or counts.minimum_training_excluded_continuous < counts.continuous
        )
    ):
        raise ValueError(
            "C7+ suite adoption requires every scored case in both tasks "
            "to have documented training-exclusion evidence"
        )
    if (
        sequence >= 7
        and candidate_schema == "umi-evaluation-suite-adoption-candidate/2"
        and (counts.maximum_cases_per_dataset is None or counts.maximum_cases_per_dataset > 2)
    ):
        raise ValueError(
            "C7+ suite adoption requires maximum_cases_per_dataset of 1 or 2 "
            "across both tasks and every split/version of each source"
        )


def validate_suite_adoption_candidates(candidates, cohorts):
    keys = tuple(c.cohort_sha256 for c in candidates)
    if keys != tuple(sorted(set(keys))) or not set(keys) <= set(cohorts):
        raise ValueError("suite adoption candidates require unique configured cohorts")
    writable = tuple(Path(c.verification_directory) for c in candidates)
    if any(
        a == b or a in b.parents or b in a.parents
        for i, a in enumerate(writable)
        for b in writable[i + 1 :]
    ):
        raise ValueError("suite adoption verification owners require separate directories")


class EvaluationSuiteAdoptionCandidate:
    def __init__(self, config, policy):
        self.config, self.policy = config, policy

    def _document(self, path, model=None):
        raw = _read_private_bytes(Path(path), maximum_bytes=self.config.maximum_metadata_bytes)
        value = json.loads(raw) if model is None else model.model_validate_json(raw)
        if canonical_json_bytes(value) != raw:
            raise ValueError("suite candidate metadata is not exact canonical bytes")
        return value

    def selection(self):
        suite = self._document(self.config.suite_file, EvaluationSuite)
        manifest = self._document(self.config.selection_manifest_file)
        validate_suite_profile(suite, self.policy)
        if manifest.get("suite_sha256") != digest(suite):
            raise ValueError("suite selection manifest changes the selected suite")
        return suite, manifest

    def prepare(self, history, block):
        return self.prepare_qualified(history, block)[0]

    def prepare_qualified(self, history, block):
        stamps = [self._identity(p) for p in self.config.metadata_paths()]
        suite, manifest = self.selection()
        proposal = self._proposal(history, block, suite, manifest)
        _, qualified = self._verify(
            history,
            proposal,
            selected=(suite, manifest),
            metadata_identity=stamps,
            with_qualification=True,
        )
        return proposal, qualified

    def _proposal(self, history, block, suite, manifest):
        if digest(history.plan) != self.config.cohort_sha256:
            raise ValueError("suite candidate selects another cohort")
        tip = digest(history.transitions[-1].transition if history.transitions else history.genesis)
        return prepare_evaluation_suite_adoption(
            history,
            self.policy,
            expected_tip_sha256=tip,
            current_block=block,
            suite_sha256=digest(suite),
            selection_manifest_sha256=digest(manifest),
        )

    async def verify(self, history, transition):
        return await run_owned_thread(self._verify, history, transition)

    def qualify(self, history, transition):
        return self._verify(history, transition, with_qualification=True)[1]

    def require_qualification(self, qualified, transition):
        if (
            type(qualified) is not EvaluationSuiteQualification
            or qualified.candidate_sha256 != digest(self.config)
            or qualified.policy_sha256 != digest(self.policy)
            or qualified.adoption_sha256 != digest(transition.evaluation_suite_adoption)
        ):
            raise ValueError("suite qualification belongs to another candidate or adoption")
        for stamp in qualified.files:
            if self._identity(stamp[0]) != list(stamp):
                raise ValueError("qualified suite inputs changed before owner reservation")

    def _verify(
        self,
        history,
        transition,
        *,
        selected=None,
        metadata_identity=None,
        with_qualification=False,
    ):
        if metadata_identity is None:
            metadata_identity = [self._identity(p) for p in self.config.metadata_paths()]
        suite, manifest = self.selection() if selected is None else selected
        expected = self._proposal(history, transition.observed_at_block, suite, manifest)
        if expected != transition:
            raise ValueError("suite candidate differs from the exact native adoption")
        if metadata_identity != [self._identity(p) for p in self.config.metadata_paths()]:
            raise ValueError("suite metadata changed while selecting the native adoption")
        verified_files = list(metadata_identity)
        counts = SuiteSelectionCounts.model_validate(manifest["counts"])
        if not counts.require_qualified_cases or not counts.distinct_signer_per_case:
            raise ValueError("suite adoption requires qualified cases and distinct known signers")
        require_successor_suite_diversity(
            history.plan.sequence, counts, candidate_schema=self.config.schema_
        )
        if counts.fingerspelling_category_minimums is None:
            raise ValueError(
                "suite adoption requires explicit four-category fingerspelling minimums"
            )
        rows = manifest["selected_provenance"]
        by_case = {r["case_id"]: r for r in rows}
        if len(by_case) != len(rows) or set(by_case) != {c.case_id for c in suite.cases}:
            raise ValueError("suite qualification inventory changes selected cases")
        categories = Counter(
            by_case[c.case_id].get("fingerspelling_category")
            for c in suite.cases
            if c.stratum == "fingerspelling"
        )
        if (
            None in categories
            or any(
                categories[key] < minimum
                for key, minimum in counts.fingerspelling_category_minimums.model_dump().items()
            )
            or any(
                by_case[c.case_id].get("fingerspelling_category") is not None
                for c in suite.cases
                if c.stratum != "fingerspelling"
            )
        ):
            raise ValueError("suite adoption fingerspelling categories do not meet exact minimums")
        signers = tuple(r.get("signer_group_sha256") for r in rows)
        if (
            None in signers
            or len(set(signers)) != len(signers)
            or any(r.get("reference_qa_sha256") is None for r in rows)
        ):
            raise ValueError("suite adoption requires every known signer and retained reference QA")
        context = dict(
            schema="umi-native-suite-review/1",
            policy_sha256=digest(self.policy),
            verification_owner=identity(self.config.verification_owner_hotkey),
            semantics=runtime_identity(),
        )
        media_context = dict(
            context,
            ffmpeg_sha256=self.config.ffmpeg_sha256,
            ffprobe_sha256=self.config.ffprobe_sha256,
        )
        root = Path(self.config.verification_directory)
        ensure_private_directory(root)
        with TransferProgress(
            "evaluation_suite_adoption_review",
            2 * len(suite.cases) + 1,
            unit="selection_qa_and_videos",
            planning_unit_seconds=(0.01, 60),
        ) as progress:
            with ByteCheckpoints(root / "selection", context, progress) as saved:
                completed = self._completed(saved, "selection", metadata_identity)
                if completed is None:
                    inventory = self._document(self.config.inventory_file, SuiteCandidateInventory)
                    exclusions = self._document(self.config.exclusions_file, SuiteExclusions)
                    key = _read_private_bytes(
                        Path(self.config.selection_key_file), maximum_bytes=32
                    )
                    actual_suite, actual_manifest = select_future_suite(
                        inventory, exclusions, counts, self.policy, selection_key=key
                    )
                    if actual_suite != suite or canonical_json_bytes(
                        actual_manifest
                    ) != canonical_json_bytes(manifest):
                        raise ValueError(
                            "suite differs from provenance, exclusion or diversity selection"
                        )
                    if metadata_identity != [
                        self._identity(p) for p in self.config.metadata_paths()
                    ]:
                        raise ValueError("suite metadata changed during independent verification")
                    saved.remember("selection", metadata_identity, digest(manifest))
                elif completed != digest(manifest):
                    raise ValueError("completed suite selection identity changed")
                progress.advance(1, restored=completed is not None)
            with ByteCheckpoints(root / "reference-qa", context, progress) as saved:
                for case in suite.cases:
                    verified_files.append(
                        self._reference_qa(saved, progress, case, by_case[case.case_id])
                    )
            with ByteCheckpoints(root / "media", media_context, progress) as saved:
                for case in suite.cases:
                    path = Path(self.config.videos_directory) / (case.video_sha256 + ".mp4")
                    media_identity = self._identity(path)
                    verified_files.append(media_identity)
                    completed = self._completed(saved, case.video_sha256, media_identity)
                    if completed is not None:
                        if completed != case.video_sha256:
                            raise ValueError("completed suite media identity changed")
                        progress.advance(1, restored=True)
                        continue
                    inspected = inspect_media_pinned(
                        path,
                        expected_ffmpeg_sha256=self.config.ffmpeg_sha256,
                        expected_ffprobe_sha256=self.config.ffprobe_sha256,
                        ffmpeg=self.config.ffmpeg_binary,
                        ffprobe=self.config.ffprobe_binary,
                        maximum_clip_size=self.config.maximum_video_bytes,
                    )
                    if (
                        inspected.video_sha256 != case.video_sha256
                        or media_identity != self._identity(path)
                    ):
                        raise ValueError(
                            "suite media changed its committed content or original identity"
                        )
                    saved.remember(case.video_sha256, media_identity, case.video_sha256)
                    progress.advance(1)
            if any(stamp != self._identity(stamp[0]) for stamp in verified_files):
                raise ValueError("suite inputs changed during independent media review")
        audit = dict(
            suite_sha256=digest(suite),
            selection_manifest_sha256=digest(manifest),
            cases=len(suite.cases),
            private_source_exposure_not_proven_unseen=True,
            annotation_truth_not_established_by_format_checks=True,
        )
        qualified = EvaluationSuiteQualification(
            digest(self.config),
            digest(self.policy),
            digest(transition.evaluation_suite_adoption),
            tuple(tuple(stamp) for stamp in verified_files),
        )
        return (audit, qualified) if with_qualification else audit

    def _reference_qa(self, saved, progress, case, row):
        expected = dict(
            case_sha256=digest(case),
            source_group_sha256=row["source_group_sha256"],
            signer_group_sha256=row["signer_group_sha256"],
            provenance_sha256=row["provenance_sha256"],
            reference_sha256=digest(case.references),
        )
        if row.get("fingerspelling_category") is not None:
            expected["fingerspelling_category"] = row["fingerspelling_category"]
        key = row["reference_qa_sha256"]
        path = Path(self.config.reference_qa_directory) / (key + ".json")
        stamp = self._identity(path)
        bound_identity = [stamp, digest(expected)]
        completed = self._completed(saved, key, bound_identity)
        if completed is None:
            qualified = self._document(path, SuiteReferenceQA)
            if (
                digest(qualified) != key
                or qualified.fingerspelling_category != row.get("fingerspelling_category")
                or any(getattr(qualified, k) != v for k, v in expected.items())
            ):
                raise ValueError(
                    "retained reference QA changes case, reference, signer or provenance"
                )
            if stamp != self._identity(path):
                raise ValueError("reference QA changed during independent qualification")
            saved.remember(key, bound_identity, key)
        elif completed != key:
            raise ValueError("completed reference QA identity changed")
        progress.advance(1, restored=completed is not None)
        return stamp

    @staticmethod
    def _identity(path):
        path = Path(path)
        private_path(str(path))
        info = path.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_mode & 0o077
            or info.st_nlink != 1
        ):
            raise ValueError("suite inputs must be original owned private regular files")
        return [str(path), *[str(v) for v in file_fingerprint(info)]]

    def _completed(self, saved, slot, identity):
        completed = saved.load(slot, identity)
        if saved.repairs and self.config.verification_repair_reason is None:
            raise ValueError("completed suite verification requires explicit repair")
        return completed
