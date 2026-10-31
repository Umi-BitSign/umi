"""Frozen-reference restoration consumes the exact retained original certificate."""

from pathlib import Path
from types import SimpleNamespace

import pytest

from umi.competition_cohort_baseline_review import CertifiedCohortBaselineReview
from umi.competition_cohort_reference_preparation import (
    SettlementReferencePreparation,
    _original_source,
)
from umi.private_files import publish_private_model
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_recovery import signatures
from .test_competition_cohort_reference_source import (
    base_policy as base_policy,
)
from .test_competition_cohort_reference_source import (
    certified as certified,
)
from .test_competition_cohort_reference_source import (
    execution as execution,
)
from .test_competition_cohort_reference_source import (
    harness as harness,
)
from .test_competition_cohort_reference_source import (
    legacy_scenario as legacy_scenario,
)
from .test_competition_cohort_reference_source import (
    policy as policy,
)
from .test_competition_cohort_reference_source import (
    receipt_scenario as receipt_scenario,
)
from .test_competition_cohort_reference_source import (
    recovery as recovery,
)
from .test_competition_cohort_reference_source import (
    reference as reference,
)
from .test_competition_cohort_reference_source import (
    relay as relay,
)
from .test_competition_cohort_reference_source import (
    runtime as runtime,
)
from .test_competition_cohort_reference_source import (
    scenario as scenario,
)

pytestmark = [
    pytest.mark.parametrize("scenario", ["paired_model"], indirect=True),
    pytest.mark.parametrize("receipt_scenario", ["model-awards"], indirect=True),
    pytest.mark.parametrize("recovery", ["legacy6"], indirect=True),
]


def retained(reference, root, *, request=None, certificate=None):
    source = reference.value
    slot = Path(reference.review.source_cohort_sha256) / (
        reference.review.candidate.submission_sha256 + ".json"
    )
    for directory, value in (
        ("model-reward-preparation", source.request if request is None else request),
        ("model-reward-acceptances", source.certificate if certificate is None else certificate),
    ):
        publish_private_model(root / directory / slot, value)
    return SimpleNamespace(directory=root), slot


def test_frozen_source_preserves_individual_or_batch_certificate(reference, tmp_path):
    promotion, slot = retained(reference, tmp_path / "promotion")
    originals = {
        directory: (promotion.directory / directory / slot).read_bytes()
        for directory in ("model-reward-preparation", "model-reward-acceptances")
    }
    result = _original_source(promotion, reference.review)
    assert result == reference.value.request
    assert canonical_json_bytes(result) == originals["model-reward-preparation"]
    for directory, raw in originals.items():
        assert (promotion.directory / directory / slot).read_bytes() == raw
    assert not (promotion.directory / "model-reward-artifacts").exists()


@pytest.mark.parametrize("missing", ["model-reward-preparation", "model-reward-acceptances"])
def test_frozen_source_requires_both_originals_without_local_fallback(reference, tmp_path, missing):
    promotion, slot = retained(reference, tmp_path / "promotion")
    (promotion.directory / missing / slot).unlink()
    with pytest.raises(FileNotFoundError):
        _original_source(promotion, reference.review)


def test_frozen_source_refuses_changed_request_under_original_certificate(reference, tmp_path):
    source = reference.value
    altered = source.request.model_copy(
        update={
            "acceptance": source.request.acceptance.model_copy(update={"accepted_ordinal": 2}),
        }
    )
    promotion, _ = retained(reference, tmp_path / "promotion", request=altered)
    with pytest.raises(ValueError, match="original certified source"):
        _original_source(promotion, reference.review)


def test_frozen_source_refuses_replacement_certificate_for_same_bundle(reference, tmp_path):
    source = reference.value
    changed = source.certificate.acceptance.model_copy(update={"accepted_ordinal": 2})
    certificate = source.certificate.model_copy(update={"acceptance": changed})
    request = source.request.model_copy(update={"acceptance": changed})
    promotion, _ = retained(
        reference, tmp_path / "promotion", request=request, certificate=certificate
    )
    with pytest.raises(ValueError, match="original certified source"):
        _original_source(promotion, reference.review)


def test_frozen_source_cannot_borrow_authority_from_another_cohort(reference, tmp_path):
    promotion, _ = retained(reference, tmp_path / "promotion")
    review = reference.review.model_copy(
        update={
            "candidate": reference.review.candidate.model_copy(
                update={"authority_sha256": "ef" * 32}
            ),
        }
    )
    with pytest.raises(ValueError, match="original certified source"):
        _original_source(promotion, review)


@pytest.mark.parametrize("wrong_target", [False, True])
def test_reward_only_store_restores_source_from_original_replicated_certificate(
    reference, tmp_path, wrong_target
):
    promotion, _ = retained(reference, tmp_path / "reward-only-promotion")
    promotion.certified_cohort_baseline_reference = lambda *a, **k: None
    original = reference.review
    review = (
        original.model_copy(update={"target_sequence": original.target_sequence + 1})
        if wrong_target
        else original
    )
    certificate = CertifiedCohortBaselineReview(review=review, signatures=signatures(review))
    publish_private_model(
        promotion.directory
        / "model-reward-references"
        / original.target_cohort_sha256
        / (original.candidate.model_sha256 + ".json"),
        certificate,
    )
    artifacts = SimpleNamespace(
        policy=reference.e.r.h.batch["policy"],
        config=SimpleNamespace(reference_preservation_directory=None),
    )
    worker = SettlementReferencePreparation(
        artifacts, tmp_path / "absent-local-archive", promotion, maximum_bytes=64 * 1024**2
    )
    if wrong_target:
        with pytest.raises(ValueError, match="frozen round"):
            worker._source(reference.job.round)
    else:
        resolved = worker._source(reference.job.round)
        assert resolved.bundle == original.model
        assert resolved.selection == reference.value.request
    assert not (promotion.directory / "competition.sqlite3").exists()
