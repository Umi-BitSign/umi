"""Settlement consumes the original model-review export without re-encoding it."""

import os

import pytest
from pydantic import JsonValue, RootModel

from umi.competition_cohort_settlement_delivery import ModelReviewEvidenceFiles
from umi.open_competition import digest
from umi.private_files import publish_private_model
from umi.protocol import canonical_json_bytes


@pytest.fixture
def document(tmp_path):
    value = {"rights_review": "fixture", "checks": [True, 3, None]}
    key = digest(value)
    path = tmp_path / "objects" / (key + ".json")
    publish_private_model(path, RootModel[dict[str, JsonValue]](value))
    return ModelReviewEvidenceFiles(path.parent), key, path, value


def test_original_model_review_bytes_survive_delivery_and_reopen(document):
    reader, key, path, value = document
    raw = path.read_bytes()
    assert reader(key) == raw == canonical_json_bytes(value)
    assert ModelReviewEvidenceFiles(path.parent)(key) == raw


def test_missing_review_is_pending_not_empty_evidence(document):
    reader, key, path, _ = document
    path.unlink()
    with pytest.raises(FileNotFoundError):
        reader(key)


@pytest.mark.parametrize("fault", ["digest", "canonical", "public", "hardlink", "symlink"])
def test_untrusted_review_cannot_be_rewritten_into_valid_evidence(document, fault):
    reader, key, path, _ = document
    if fault == "digest":
        path.write_bytes(canonical_json_bytes({"rights_review": "changed"}))
    elif fault == "canonical":
        path.write_bytes(path.read_bytes() + b"\n")
    elif fault == "public":
        path.chmod(0o644)
    elif fault == "hardlink":
        os.link(path, path.with_suffix(".linked"))
    else:
        moved = path.with_suffix(".original")
        path.rename(moved)
        path.symlink_to(moved)
    with pytest.raises(ValueError):
        reader(key)


@pytest.mark.parametrize("key", ["../private", "ab" * 33, "AA" * 32])
def test_review_identity_is_validated_before_filesystem_access(tmp_path, key):
    root = tmp_path / "absent"
    with pytest.raises(ValueError, match="identity"):
        ModelReviewEvidenceFiles(root)(key)
    assert not root.exists()


def test_oversized_model_review_is_rejected_before_read(document, monkeypatch):
    reader, key, _, _ = document
    monkeypatch.setattr("umi.competition_cohort_settlement_delivery.MAX_ARCHIVE_OBJECT_BYTES", 1)
    with pytest.raises(ValueError, match="byte bound"):
        reader(key)
