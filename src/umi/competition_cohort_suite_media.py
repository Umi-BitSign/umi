"""Restore absent evaluator media from the exact adopted private candidate."""

import os
from pathlib import Path

from .competition_cohort_suite_adoption_candidate import EvaluationSuiteAdoptionCandidate
from .competition_execution import read_case_video
from .competition_transport_verification import TransferProgress
from .open_competition import digest
from .private_files import _write_private_bytes, lock_private_file, private_path


def restore_selected_suite_video(*, policy, candidates, videos, job, case, maximum):
    selected = tuple(c for c in candidates if c.cohort_sha256 == job.round.cohort_sha256)
    if not selected:
        raise FileNotFoundError("no configured source for the missing selected case video")
    if len(selected) != 1:
        raise ValueError("selected case restoration requires one private suite candidate")
    candidate = selected[0]
    suite, _ = EvaluationSuiteAdoptionCandidate(candidate, policy).selection()
    if digest(suite) != job.round.suite_sha256 or not any(
        member.case_id == case.case_id and member.video_sha256 == case.video_sha256
        for member in suite.cases
    ):
        raise ValueError("private case source differs from the retained execution suite")
    videos = Path(private_path(str(videos)))
    if not videos.is_dir():
        raise FileNotFoundError("selected evaluator video directory must already exist")
    descriptor = lock_private_file(videos / ".selected-suite-videos.lock")
    try:
        # A peer may have finished restoration while this reader waited. The
        # native reader refuses damaged or unsafe existing evidence.
        try:
            return read_case_video(videos, case.video_sha256, maximum)
        except FileNotFoundError:
            pass
        with TransferProgress(
            "selected_suite_case_restoration", 1, unit="videos", planning_unit_seconds=(0.01, 30)
        ) as progress:
            data = read_case_video(
                Path(candidate.videos_directory),
                case.video_sha256,
                min(maximum, candidate.maximum_video_bytes),
            )
            _write_private_bytes(videos / (case.video_sha256 + ".mp4"), data)
            directory = os.open(videos, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
            published = read_case_video(videos, case.video_sha256, maximum)
            progress.advance(1)
            return published
    finally:
        os.close(descriptor)
