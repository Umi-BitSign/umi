"""Selected private media reaches native invocation storage without changing authority."""

import hashlib
from types import SimpleNamespace

import pytest

from umi import competition_cohort_suite_media as media
from umi.competition_cohort_sandbox import CohortCpuSandbox
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from .test_open_competition import policy as policy
from .test_open_competition import suite_for


@pytest.fixture
def selected(policy, tmp_path):
    source, videos = tmp_path / "source", tmp_path / "videos"
    source.mkdir(mode=0o700)
    videos.mkdir(mode=0o700)
    body = b"inert media bytes bound by the retained suite"
    suite = suite_for(policy)
    case = suite.cases[0].model_copy(update={"video_sha256": hashlib.sha256(body).hexdigest()})
    suite = suite.model_copy(update={"cases": (case, *suite.cases[1:])})
    suite_file, manifest = source / "suite.json", source / "manifest.json"
    suite_file.write_bytes(canonical_json_bytes(suite))
    manifest.write_bytes(canonical_json_bytes({"suite_sha256": digest(suite)}))
    suite_file.chmod(0o600)
    manifest.chmod(0o600)
    original = source / (case.video_sha256 + ".mp4")
    original.write_bytes(body)
    candidate = SimpleNamespace(
        cohort_sha256="ab" * 32,
        suite_file=str(suite_file),
        selection_manifest_file=str(manifest),
        maximum_metadata_bytes=1024**2,
        maximum_video_bytes=1024,
        videos_directory=str(source),
    )
    job = SimpleNamespace(
        round=SimpleNamespace(cohort_sha256=candidate.cohort_sha256, suite_sha256=digest(suite)),
        runtime=SimpleNamespace(maximum_video_bytes=1024),
    )

    def port(candidates=(candidate,)):
        return CohortCpuSandbox(
            policy,
            archive=tmp_path / "archive",
            videos=videos,
            workspace=tmp_path / "workspace",
            suite_candidates=candidates,
        )

    return SimpleNamespace(
        port=port,
        job=job,
        case=case,
        candidate=candidate,
        original=original,
        body=body,
        destination=videos / original.name,
    )


def test_missing_selected_video_restores_and_survives_restart_without_candidate(selected):
    s = selected
    assert s.port()._case_video(s.job, s.case) == s.body
    assert s.destination.read_bytes() == s.body
    assert s.destination.stat().st_nlink == 1
    assert s.destination.stat().st_mode & 0o777 == 0o600
    s.original.unlink()
    # Existing supported layouts and subsequent restarts need no source replay.
    assert s.port(())._case_video(s.job, s.case) == s.body


@pytest.mark.parametrize("change", ["cohort", "suite", "case", "source", "bound", "ambiguous"])
def test_restoration_refuses_changed_binding_or_source(selected, change):
    s = selected
    candidates = (s.candidate,)
    if change == "cohort":
        s.job.round.cohort_sha256 = "cd" * 32
    elif change == "suite":
        s.job.round.suite_sha256 = "cd" * 32
    elif change == "case":
        s.case = s.case.model_copy(update={"case_id": "cd" * 32})
    elif change == "source":
        s.original.write_bytes(b"changed")
    elif change == "bound":
        s.job.runtime.maximum_video_bytes = 1
    else:
        candidates *= 2
    with pytest.raises((ValueError, FileNotFoundError)):
        s.port(candidates)._case_video(s.job, s.case)
    assert not s.destination.exists()


def test_damaged_existing_video_is_not_replaced(selected):
    s = selected
    s.destination.write_bytes(b"damaged retained evidence")
    with pytest.raises(ValueError):
        s.port()._case_video(s.job, s.case)
    assert s.destination.read_bytes() == b"damaged retained evidence"


def test_interrupted_publication_can_retry_without_changing_inputs(selected, monkeypatch):
    s = selected
    publish = media._write_private_bytes

    def interrupted(*args):
        raise OSError("inert publication interruption")

    monkeypatch.setattr(media, "_write_private_bytes", interrupted)
    with pytest.raises(OSError, match="publication interruption"):
        s.port()._case_video(s.job, s.case)
    assert not s.destination.exists()
    monkeypatch.setattr(media, "_write_private_bytes", publish)
    assert s.port()._case_video(s.job, s.case) == s.body


def test_legacy_missing_video_without_candidate_remains_explicit(selected):
    s = selected
    with pytest.raises(FileNotFoundError):
        s.port(())._case_video(s.job, s.case)
    assert not s.destination.exists()
