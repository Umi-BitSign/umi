"""Independent reviewer boot retains legacy authority through transport adoption."""

from pathlib import Path
from types import SimpleNamespace

import pytest

from umi import competition_cohort_review_boot as boot
from umi.competition_cohort_model_delivery_candidate import ModelDeliveryAdoptionCandidateConfig
from umi.competition_cohort_review_config import PhaseReviewServiceConfig
from umi.competition_cohort_sandbox import DirectCohortCpuSandbox
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_review_boot import (
    config_for,
    direct_r2_credentials,
    endpoint_credentials,
    qualify_test_scratch,
    with_endpoint,
)
from .test_competition_cohort_review_boot import providers as providers
from .test_competition_cohort_review_budget import profile, select
from .test_competition_effective_model_reward_boot import adopted_case as adopted_case
from .test_competition_effective_model_reward_boot import chain as chain
from .test_competition_effective_model_reward_boot import chain_config as chain_config
from .test_competition_effective_model_reward_boot import config_case as config_case
from .test_competition_effective_model_reward_boot import control as control
from .test_competition_effective_model_reward_boot import inputs as inputs
from .test_competition_effective_model_reward_boot import policy as policy
from .test_competition_effective_model_reward_boot import selected as selected
from .test_competition_effective_model_reward_boot import series_case as series_case

pytestmark = pytest.mark.parametrize("adopted_case", ["writer"], indirect=True)


@pytest.fixture
def review_case(adopted_case, tmp_path):
    h = adopted_case
    original = with_endpoint(config_for(h.before, tmp_path / "phase-review"))
    staged = original.model_copy(
        update={
            "schema_": "umi-cohort-phase-review-service/7",
            "direct_model_review": h.source,
        }
    )
    staged = PhaseReviewServiceConfig.model_validate_json(canonical_json_bytes(staged))
    adopted = staged.model_copy(update={"model_delivery_adoptions": (h.selection,)})
    adopted = PhaseReviewServiceConfig.model_validate_json(canonical_json_bytes(adopted))
    return SimpleNamespace(original=original, staged=staged, adopted=adopted, history=h)


def test_independent_reviewer_preserves_staged_capability_and_legacy_bytes(review_case):
    h = review_case
    for value in (h.original, h.staged):
        raw = canonical_json_bytes(value)
        assert b'"model_delivery_adoptions"' not in raw
        assert canonical_json_bytes(PhaseReviewServiceConfig.model_validate_json(raw)) == raw
    assert canonical_json_bytes(h.adopted.series) == canonical_json_bytes(h.original.series)
    assert canonical_json_bytes(h.adopted.manifest) == canonical_json_bytes(h.original.manifest)
    assert h.adopted.model_signing == h.original.model_signing
    assert h.adopted.benchmark == h.original.benchmark
    assert h.adopted.signing == h.original.signing


@pytest.mark.parametrize("collision", [None, "source", "credential"])
def test_adoption_can_reuse_direct_credentials_without_allowing_mutable_overlap(
    review_case, tmp_path, collision
):
    c = select(review_case.staged, profile(review_case.staged.policy))
    credentials = c.direct_model_review.r2_credentials_file
    candidate = ModelDeliveryAdoptionCandidateConfig.model_validate(
        {
            "schema": "umi-model-delivery-adoption-candidate/1",
            "source": {
                "schema": "umi-legacy-model-storage-source/1",
                "cohort_sha256": digest(review_case.history.selection.history.plan),
                "directory": str(tmp_path / "candidate-originals"),
                "baseline_model_sha256": "ab" * 32,
            },
            "delivery": {
                "schema": "umi-model-delivery-profile/1",
                "mechanism": "direct_r2_multipart_v1",
                "part_size_bytes": 64 * 1024**2,
                "maximum_concurrent_parts": 4,
                "capability_ttl_seconds": 3600,
            },
            "r2_credentials_file": credentials,
            "r2_bucket": c.direct_model_review.r2_bucket,
            "verification_directory": str(tmp_path / "candidate-verification"),
            "model_only": True,
        }
    )
    if collision == "source":
        candidate = candidate.model_copy(
            update={
                "source": candidate.source.model_copy(update={"directory": c.signing.directory}),
            }
        )
    elif collision == "credential":
        candidate = candidate.model_copy(update={"r2_credentials_file": c.signing.directory})
    staged = c.model_copy(update={"model_delivery_adoption_candidates": (candidate,)})
    if collision:
        with pytest.raises(ValueError, match="disjoint"):
            PhaseReviewServiceConfig.model_validate_json(canonical_json_bytes(staged))
    else:
        restored = PhaseReviewServiceConfig.model_validate_json(canonical_json_bytes(staged))
        assert canonical_json_bytes(restored) == canonical_json_bytes(staged)
        assert Path(credentials) not in restored.stores()


def test_committed_adoption_requires_independent_reader(review_case):
    changed = review_case.original.model_copy(
        update={"model_delivery_adoptions": review_case.adopted.model_delivery_adoptions}
    )
    with pytest.raises(ValueError, match="independent R2 review source"):
        PhaseReviewServiceConfig.model_validate_json(canonical_json_bytes(changed))


@pytest.mark.parametrize("fault", ["unadopted", "tip", "future", "signature", "duplicate"])
async def test_bad_selection_fails_before_keys_or_service_state(review_case, monkeypatch, fault):
    h = review_case
    selection = h.history.selection
    if fault == "unadopted":
        selection = selection.model_copy(update={"history": h.history.history})
    elif fault == "tip":
        selection = selection.model_copy(update={"committed_tip_sha256": "ff" * 32})
    elif fault == "future":
        selection = selection.model_copy(update={"observed_at_block": 219})
    elif fault == "signature":
        transition = selection.history.transitions[0].model_copy(
            update={"signatures": selection.history.genesis_signatures}
        )
        selection = selection.model_copy(
            update={"history": selection.history.model_copy(update={"transitions": (transition,)})}
        )
    selections = (selection, selection) if fault == "duplicate" else (selection,)
    changed = h.adopted.model_copy(update={"model_delivery_adoptions": selections})

    def forbidden(*args, **kwargs):
        pytest.fail("invalid transport reached credentialed startup")

    monkeypatch.setattr(boot, "HistoricalRegistrationProvider", forbidden)
    monkeypatch.setattr(boot, "load_named_hotkey", forbidden)
    assert not Path(changed.signing.directory).exists()
    with pytest.raises(ValueError):
        async with boot.phase_review_app(changed):
            pytest.fail("invalid transport booted")
    assert not Path(changed.signing.directory).exists()


async def test_real_reviewer_constructor_restarts_with_same_original_journals(
    review_case, providers, monkeypatch
):
    c = review_case.adopted
    Path(c.owner_token_file).parent.mkdir(parents=True)
    for path, token in (
        (c.owner_token_file, "owner-token" * 4),
        (c.vote_token_file, "vote-token" * 4),
    ):
        Path(path).write_text(token + "\n")
        Path(path).chmod(0o440)
    endpoint_credentials(c)
    direct_r2_credentials(c)
    qualify_test_scratch(monkeypatch)
    monkeypatch.setattr(boot, "CohortEndpointFinalityProvider", providers.provider)
    journal_inodes = None
    for _ in range(2):
        async with boot.phase_review_app(c) as app:
            sandbox = app.state.benchmark.sandbox
            assert isinstance(sandbox, DirectCohortCpuSandbox)
            assert sandbox.artifacts.config == c.direct_model_review
            assert sandbox.artifacts.verification_root == (
                Path(c.signing.directory) / "direct-model-byte-verification"
            )
            current = {
                str(path): path.stat().st_ino
                for root in (c.signing.directory, c.model_signing.directory)
                for path in Path(root).rglob("*.sqlite3")
            }
            assert current
            if journal_inodes is None:
                journal_inodes = current
            else:
                assert current == journal_inodes
    assert providers.events.count("started") == providers.events.count("closed")
