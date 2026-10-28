"""Signed native boot selection and retained metadata-only adoption publication."""

from pathlib import Path
from types import SimpleNamespace

import pytest

from umi import competition_cohort_model_score_adoption as module
from umi import competition_cohort_model_scores as scores
from umi.competition_cohort_reward_allocation import derive_effective_reward_allocation
from umi.competition_geometric_rewards import cohort_reward_parameters
from umi.competition_public_results_directory import atomic_write, owned_directory
from umi.competition_reward_adoption import (
    RewardAdoptionSelection,
    RewardModelAdoption,
    SignedRewardModelAdoption,
)
from umi.competition_reward_adoption_handoff import prepare_reward_adoption_boot_candidates
from umi.competition_reward_coordinator_boot import RewardCoordinatorConfig
from umi.open_competition import digest, identity, sign_object
from umi.protocol import canonical_json_bytes

from .test_competition_geometric_rewards import package_boundary
from .test_competition_reward_boot import inputs as inputs
from .test_competition_reward_coordinator_boot import config_case as config_case
from .test_competition_reward_decisions import chain as chain
from .test_competition_reward_decisions import chain_config as chain_config
from .test_competition_reward_decisions import control as control
from .test_competition_reward_decisions import policy as policy
from .test_competition_reward_decisions import series_case as series_case
from .test_competition_reward_decisions import signatures
from .test_open_competition import wallet


@pytest.fixture
def selection(config_case, tmp_path):
    """Synthetic compact award, real signed selection and root-control reader.

    Native source certification is covered by the existing score publisher tests;
    this fixture does not claim model/proof replay or live chain activation.
    """
    boot = config_case.config
    cohort = next(p for p in boot.series.cohorts if p.sequence == 7)
    package = package_boundary(["0.595", "0.594"], baseline="0.6")
    effective = derive_effective_reward_allocation(package, cohort_reward_parameters(7))
    originals = []
    for allocation in (package.allocation, effective):
        award = allocation.model_award
        certificates = []
        for old in award.acceptances:
            body = old.acceptance.model_copy(
                update={
                    "policy_sha256": digest(boot.policy),
                    "authority_sha256": digest(boot.series.recovery.authority),
                    "cohort_sha256": digest(cohort),
                }
            )
            certificates.append(
                old.model_copy(
                    update={"acceptance": body, "signatures": (sign_object(body, wallet("Alice")),)}
                )
            )
        by_submission = {c.acceptance.submission_sha256: c for c in certificates}
        award = award.model_copy(
            update={
                "policy_sha256": digest(boot.policy),
                "authority_sha256": digest(boot.series.recovery.authority),
                "acceptances": tuple(certificates),
                "candidates": tuple(
                    c.model_copy(
                        update={"acceptance_sha256": digest(by_submission[c.submission_sha256])}
                    )
                    for c in award.candidates
                ),
            }
        )
        originals.append(
            type(allocation).model_validate_json(
                canonical_json_bytes(
                    allocation.model_copy(
                        update={"policy_sha256": digest(boot.policy), "model_award": award}
                    )
                )
            )
        )
    original_allocation, effective = originals
    weight = {identity(r.hotkey): r.raw_weight for r in original_allocation.recipients}
    candidates = sorted(
        original_allocation.model_award.candidates,
        key=lambda c: -float(c.aggregate.numerator) / int(c.aggregate.denominator),
    )
    original = scores.PublicModelScores(
        schema="umi-public-cohort-model-results/1",
        cohort_sha256=digest(cohort),
        round_sha256=original_allocation.round_sha256,
        policy_sha256=digest(boot.policy),
        allocation_sha256=digest(original_allocation),
        certified_history_tip_sha256="ab" * 32,
        source_metadata_sha256="cd" * 32,
        certification="quorum_certified_native_allocation",
        items=tuple(
            scores.PublicModelScore(
                submission_sha256=c.submission_sha256,
                model_sha256=c.model_sha256,
                uid=i,
                hotkey=c.recipient_hotkey,
                status="scored",
                aggregate=scores.ModelScore.make(c.aggregate),
                baseline_aggregate=scores.ModelScore.make(c.baseline_aggregate),
                score_rank=i + 1,
                baseline_eligible=False,
                model_reward_status="below_baseline",
                certified_raw_weight_for_hotkey=weight.get(identity(c.recipient_hotkey), 0),
            )
            for i, c in enumerate(candidates)
        ),
    )
    body = RewardModelAdoption(
        schema="umi-standing-model-reward-adoption/1",
        series_sha256=digest(boot.series),
        policy_sha256=digest(boot.policy),
        cohort_sha256=digest(cohort),
        authority_sha256=digest(boot.series.recovery.authority),
        package_sha256="12" * 32,
        allocation_sha256=digest(original_allocation),
        service_certificate_sha256=effective.service_certificate_sha256,
        quality_manifest_sha256=effective.quality_manifest_sha256,
        effective_allocation_sha256=digest(effective),
        parameters=cohort_reward_parameters(7),
        revision=1,
        predecessor_adoption_sha256=None,
        issued_at_block=boot.series.recovery.authority.issued_at_block,
        lifetime="until_first_verified_live_reward_then_locked",
    )
    signed = SignedRewardModelAdoption(adoption=body, signatures=signatures(body))
    selected = RewardAdoptionSelection(
        schema="umi-standing-reward-adoption-selection/1", adoptions=(signed,)
    )
    selected_boot = RewardCoordinatorConfig.model_validate_json(
        canonical_json_bytes(boot.model_copy(update={"reward_adoptions": selected}))
    )
    config_case.save(config_case.path, canonical_json_bytes(selected_boot))
    root = Path(selected_boot.files_directory)
    owned_directory(root, create=True)
    owned_directory(root / "allocations", create=True)
    allocation_path = root / "allocations" / (digest(effective) + ".json")
    atomic_write(allocation_path, canonical_json_bytes(effective))
    state = tmp_path / "public-state"
    owned_directory(state, create=True)
    return SimpleNamespace(
        boot=selected_boot,
        case=config_case,
        original=original,
        effective=effective,
        signed=signed,
        state=state,
        allocation_path=allocation_path,
    )


def test_selected_signed_adoption_reuses_completed_projection_after_restart_and_eviction(
    selection, monkeypatch
):
    s = selection
    owner = module.SelectedModelScoreAdoptions(s.case.path, policy=s.boot.policy, state=s.state)
    result = owner.project(s.original)
    assert result.reward_adoption_sha256 == digest(s.signed.adoption)
    assert all(r.baseline_eligible for r in result.items)
    assert sum(r.certified_raw_weight_for_hotkey for r in result.items) > 0
    s.allocation_path.unlink()

    def forbidden(*args, **kwargs):
        raise AssertionError("completed effective allocation/projector was reread")

    monkeypatch.setattr(module, "read_input", forbidden)
    monkeypatch.setattr(module, "project_adopted_model_scores", forbidden)
    reopened = module.SelectedModelScoreAdoptions(s.case.path, policy=s.boot.policy, state=s.state)
    assert reopened.project(s.original) == result
    assert reopened.project(s.original) == result


def test_missing_or_changed_allocation_and_damaged_completion_hold(selection):
    s = selection
    owner = module.SelectedModelScoreAdoptions(s.case.path, policy=s.boot.policy, state=s.state)
    original = s.allocation_path.read_bytes()
    s.allocation_path.unlink()
    with pytest.raises(FileNotFoundError):
        owner.project(s.original)
    atomic_write(
        s.allocation_path,
        canonical_json_bytes(s.effective.model_copy(update={"quality_manifest_sha256": "ff" * 32})),
    )
    with pytest.raises(ValueError, match="signed adoption"):
        owner.project(s.original)
    atomic_write(s.allocation_path, original, immutable=False)
    result = owner.project(s.original)
    output = s.state / "published.json"
    atomic_write(output, canonical_json_bytes(result))
    for path in owner.root.glob("*.json"):
        path.unlink()
    reopened = module.SelectedModelScoreAdoptions(s.case.path, policy=s.boot.policy, state=s.state)
    with pytest.raises(ValueError, match="completion missing"):
        reopened.project(s.original, output=output)


def test_boot_signature_change_cannot_be_selected_or_silently_reused(selection):
    s = selection
    owner = module.SelectedModelScoreAdoptions(s.case.path, policy=s.boot.policy, state=s.state)
    altered = s.signed.model_copy(
        update={
            "adoption": s.signed.adoption.model_copy(
                update={"effective_allocation_sha256": "ef" * 32}
            )
        }
    )
    changed = s.boot.model_copy(
        update={
            "reward_adoptions": s.boot.reward_adoptions.model_copy(update={"adoptions": (altered,)})
        }
    )
    s.case.save(s.case.path, canonical_json_bytes(changed))
    with pytest.raises(ValueError, match="selection changed"):
        owner.project(s.original)
    with pytest.raises(ValueError):
        module.SelectedModelScoreAdoptions(s.case.path, policy=s.boot.policy, state=s.state)


@pytest.mark.parametrize("already_selected", [True, False])
def test_score_publisher_handoff_updates_only_boot_pointer_and_rejects_split_lineage(
    selection, inputs, tmp_path, already_selected
):
    s = selection
    original_boot = s.case.config
    config = scores.NativeModelScoresConfig(
        source_directory=str(tmp_path / "source"),
        history_directory=str(tmp_path / "history"),
        output_directory=str(tmp_path / "output"),
        state_directory=str(s.state),
        policy_path=str(tmp_path / "policy.json"),
        policy_sha256=digest(original_boot.policy),
        maximum_package_bytes=64 * 1024**2,
        reward_coordinator_config=str(s.case.path) if already_selected else None,
    )
    # The installed standalone score config is ordinary pretty-printed JSON;
    # only the selected root-controlled coordinator boot requires canonical bytes.
    raw = b"\n" + canonical_json_bytes(config) + b"\n"
    target = str(tmp_path / "new-boot.json")
    result = prepare_reward_adoption_boot_candidates(
        canonical_json_bytes(original_boot),
        canonical_json_bytes(inputs.value),
        s.signed,
        model_score_config_raw=raw,
        model_score_current_boot_raw=canonical_json_bytes(original_boot),
        model_score_current_boot_path=str(s.case.path),
        coordinator_candidate_path=target,
    )
    candidate = scores.NativeModelScoresConfig.model_validate_json(result.model_score_config)
    assert candidate.reward_coordinator_config == target
    assert (
        candidate.model_copy(update={"reward_coordinator_config": config.reward_coordinator_config})
        == config
    )
    with pytest.raises(ValueError, match="lineage"):
        prepare_reward_adoption_boot_candidates(
            canonical_json_bytes(original_boot),
            canonical_json_bytes(inputs.value),
            s.signed,
            model_score_config_raw=raw,
            model_score_current_boot_raw=canonical_json_bytes(s.boot),
            model_score_current_boot_path=str(s.case.path),
            coordinator_candidate_path=target,
        )


@pytest.mark.parametrize("live_feed", [False, True])
def test_native_publisher_automatically_replaces_public_projection_and_preserves_native_receipt(
    selection, tmp_path, monkeypatch, live_feed
):
    s = selection
    source, history, output = [tmp_path / name for name in ("source", "history", "output")]
    for path in (source, history, output):
        owned_directory(path, create=True)
    policy_path = tmp_path / "policy.json"
    policy_path.write_bytes(canonical_json_bytes(s.boot.policy))
    config = scores.NativeModelScoresConfig(
        source_directory=str(source),
        history_directory=str(history),
        output_directory=str(output),
        state_directory=str(s.state),
        policy_path=str(policy_path),
        policy_sha256=digest(s.boot.policy),
        maximum_package_bytes=64 * 1024**2,
    )
    assert b"reward_coordinator_config" not in canonical_json_bytes(config)
    original_owner = scores.NativeModelScoresPublisher(config)
    receipt = scores.ScoreCompletion(
        schema="umi-native-public-model-score-completion/1",
        binding_sha256=original_owner.binding,
        semantics_sha256=scores.SEMANTICS,
        source_stamp=(),
        projection=s.original,
    ).sealed()
    receipt_path = s.state / (s.original.cohort_sha256 + ".json")
    atomic_write(receipt_path, canonical_json_bytes(receipt))
    assert original_owner.poll_once()["published"] == [s.original.cohort_sha256]
    native_receipt = receipt_path.read_bytes()

    def forbidden(*args, **kwargs):
        raise AssertionError("unchanged native metadata must not be replayed")

    monkeypatch.setattr(scores, "native_header", forbidden)
    if live_feed:
        from umi.competition_reward_adoption_feed import (
            RewardAdoptionFeed,
            RewardAdoptionFeedConfig,
        )

        feed_source = RewardAdoptionFeedConfig(path=str(tmp_path / "adoption-selection.json"))
        boot = s.boot.model_copy(update={"reward_adoption_feed": feed_source})
        s.case.save(s.case.path, canonical_json_bytes(boot))
        producer = RewardAdoptionFeed(
            tmp_path / "producer-feed",
            source=feed_source,
            series=s.boot.series,
            policy=s.boot.policy,
            initial=s.boot.reward_adoptions,
        )
    config = config.model_copy(update={"reward_coordinator_config": str(s.case.path)})
    adopted_owner = scores.NativeModelScoresPublisher(config)
    result = adopted_owner.poll_once()
    assert not result["held"], result
    public_path = output / (s.original.cohort_sha256 + ".json")
    public = scores.PublicModelScores.model_validate_json(public_path.read_bytes())
    assert public.reward_adoption_sha256 == digest(s.signed.adoption)
    assert receipt_path.read_bytes() == native_receipt
    assert all(item.baseline_eligible for item in public.items)
    if live_feed:
        body = s.signed.adoption.model_copy(
            update={
                "revision": 2,
                "predecessor_adoption_sha256": digest(s.signed.adoption),
                "issued_at_block": s.signed.adoption.issued_at_block + 1,
            }
        )
        signed = SignedRewardModelAdoption(adoption=body, signatures=signatures(body))
        producer.publish(signed)
        assert not adopted_owner.poll_once()["held"]
        changed = scores.PublicModelScores.model_validate_json(public_path.read_bytes())
        assert changed.reward_adoption_sha256 == digest(body)
        assert changed.items == public.items
        assert receipt_path.read_bytes() == native_receipt
        stamp = public_path.stat().st_mtime_ns
        assert not adopted_owner.poll_once()["held"]
        assert public_path.stat().st_mtime_ns == stamp
    s.allocation_path.unlink()
    assert not scores.NativeModelScoresPublisher(config).poll_once()["held"]
    c6 = next(p for p in s.boot.series.cohorts if p.sequence == 6)
    old = s.original.model_copy(update={"cohort_sha256": digest(c6)})
    assert adopted_owner.adoptions.project(old) == old


def test_missing_c7_adoption_holds_first_publication_and_older_series_reuses_archive(
    selection, monkeypatch
):
    s = selection
    owner = module.SelectedModelScoreAdoptions(s.case.path, policy=s.boot.policy, state=s.state)
    cohort, _ = owner.cohorts[s.original.cohort_sha256]
    owner.cohorts[s.original.cohort_sha256] = (cohort, None)
    with pytest.raises(ValueError, match="await the announced signed reward adoption"):
        owner.project(s.original)
    owner.cohorts[s.original.cohort_sha256] = (cohort, s.boot.reward_adoptions)
    result = owner.project(s.original)
    s.allocation_path.unlink()
    reopened = module.SelectedModelScoreAdoptions(s.case.path, policy=s.boot.policy, state=s.state)
    # A successor root-controlled boot selects other cohorts; the retained
    # previous signed result remains archival authority for this public record.
    reopened.cohorts = {}

    def forbidden(*args, **kwargs):
        raise AssertionError("archived adoption must not reload effective allocation")

    monkeypatch.setattr(module, "read_input", forbidden)
    assert reopened.project(s.original) == result
    assert reopened.project(s.original) == result
