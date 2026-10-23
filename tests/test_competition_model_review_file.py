import pytest

from umi import competition_model_review_file as source
from umi.competition_cohort_model_acceptance import ModelArtifactReviewInputs
from umi.competition_round_journal import RoundJournal
from umi.private_files import publish_private_model
from umi.protocol import canonical_json_bytes


@pytest.fixture
def review(tmp_path):
    value = ModelArtifactReviewInputs(
        model_sha256="ab" * 32,
        rights_evidence={"license": "CC-BY-SA-4.0"},
        reconstruction_evidence={"complete": True},
    )
    path = tmp_path / "reviews" / (value.model_sha256 + ".json")
    publish_private_model(path, value)
    root = tmp_path / "journal"
    binding = {"test": "review-file"}
    return path, value, root, binding


def test_unchanged_success_reused_after_reopen_without_reading_bytes(review, monkeypatch):
    path, value, root, binding = review
    journal = RoundJournal(root, binding)
    assert source.reviewed_file_ready(journal, path, value.model_sha256)
    reopened = RoundJournal(root, binding)

    def fail(*args, **kwargs):
        raise AssertionError("unchanged completed document must not be read again")

    monkeypatch.setattr(source, "read_private_model", fail)
    assert source.reviewed_file_ready(reopened, path, value.model_sha256)


@pytest.mark.parametrize("fault", ["missing", "documents", "public", "symlink", "model"])
def test_completed_evidence_changes_do_not_silently_succeed(review, fault):
    path, value, root, binding = review
    journal = RoundJournal(root, binding)
    assert source.reviewed_file_ready(journal, path, value.model_sha256)
    if fault == "missing":
        path.unlink()
    elif fault == "public":
        path.chmod(0o644)
    elif fault == "symlink":
        original = path.with_suffix(".original")
        path.rename(original)
        path.symlink_to(original)
    else:
        update = (
            {"rights_evidence": {"license": "different"}}
            if fault == "documents"
            else {
                "model_sha256": "cd" * 32,
            }
        )
        path.write_bytes(canonical_json_bytes(value.model_copy(update=update)))
    with pytest.raises((ValueError, OSError)):
        source.reviewed_file_ready(journal, path, value.model_sha256)


def test_identical_restoration_rechecks_only_changed_file_identity(review):
    path, value, root, binding = review
    journal = RoundJournal(root, binding)
    assert source.reviewed_file_ready(journal, path, value.model_sha256)
    original = path.read_bytes()
    path.unlink()
    path.write_bytes(original)
    path.chmod(0o600)
    assert source.reviewed_file_ready(journal, path, value.model_sha256)


def test_missing_first_document_is_pending_without_a_completion(review):
    path, value, root, binding = review
    path.unlink()
    assert not source.reviewed_file_ready(RoundJournal(root, binding), path, value.model_sha256)


def test_interrupted_receipt_pair_is_atomic_and_retryable(review, monkeypatch):
    path, value, root, binding = review
    journal = RoundJournal(root, binding)
    original = journal.put_many
    monkeypatch.setattr(
        journal, "put_many", lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("interrupted"))
    )
    with pytest.raises(OSError):
        source.reviewed_file_ready(journal, path, value.model_sha256)
    monkeypatch.setattr(journal, "put_many", original)
    assert source.reviewed_file_ready(journal, path, value.model_sha256)


def test_missing_completed_metadata_receipt_requires_repair(review, monkeypatch):
    path, value, root, binding = review
    journal = RoundJournal(root, binding)
    assert source.reviewed_file_ready(journal, path, value.model_sha256)
    original = journal.get
    monkeypatch.setattr(
        journal,
        "get",
        lambda kind, key: None if kind == "review-file-metadata" else original(kind, key),
    )
    with pytest.raises(ValueError, match="receipt is missing"):
        source.reviewed_file_ready(journal, path, value.model_sha256)
