from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from umi.competition_artifacts import preserve_bundle
from umi.competition_evaluator import _publish, _read
from umi.competition_launch import PublicRoundSchedule
from umi.competition_publication import PublicationReplayLimits
from umi.competition_round_assets import (
    ArchivedRoundWorkAssets,
    RoundWorkAssetFile,
    resolve_incumbent,
)
from umi.competition_rounds import RoundCoordinator, RoundJournal, RoundPlan, RoundProposal
from umi.competition_store import CompetitionStore
from umi.competition_work_plans import RoundWorkAssets
from umi.open_competition import EvaluationRound, digest
from umi.protocol import Video, canonical_json_bytes

from .test_competition_work_plans import policy as policy
from .test_competition_work_plans import runtime as runtime
from .test_competition_work_plans import setup as work_fixture
from .test_open_competition import scenario as scenario
from .test_open_competition import snapshot
from .test_promotion_agreement import agreed_review, promote

work = work_fixture


def assets_for(round_, runtime):
    return ArchivedRoundWorkAssets(
        schema="umi-round-work-assets/2",
        suite_sha256=round_.suite_sha256,
        runtime=runtime,
        videos=tuple(
            Video(
                url=f"https://videos.example/{i}.mp4",
                sha256=f"{i:064x}",
                size_bytes=10,
                media_type="video/mp4",
            )
            for i in range(3)
        ),
    )


@pytest.fixture
def setup(work, tmp_path):
    archive = tmp_path / "archive"
    preserve_bundle(work.plan.incumbent, tmp_path / "incumbent", archive, work.policy)
    round_ = work.plan.cutoff.publication.round
    assets = assets_for(round_, work.plan.runtime).model_copy(
        update={"videos": work.options["videos"]}
    )
    return SimpleNamespace(
        work=work, archive=archive, assets=assets, round=round_, policy=work.policy
    )


def resolve(s, assets=None, archive=None):
    return resolve_incumbent(
        assets or s.assets,
        s.round,
        policy=s.policy,
        archive=s.archive if archive is None else archive,
    )


def test_both_asset_versions_roundtrip_without_changing_v1_bytes(setup, tmp_path):
    s = setup
    v1 = RoundWorkAssets(
        **{
            **s.assets.model_dump(by_alias=True),
            "schema": "umi-round-work-assets/1",
            "incumbent": s.work.plan.incumbent,
        }
    )
    for value in (v1, s.assets):
        path = tmp_path / digest(value) / "assets.json"
        _publish(path, value)
        loaded = _read(path, RoundWorkAssetFile).root
        assert canonical_json_bytes(loaded) == canonical_json_bytes(value)
        assert resolve(s, loaded) == s.work.plan.incumbent
    assert resolve_incumbent(v1, s.round, policy=s.policy) == s.work.plan.incumbent


def test_v2_requires_explicit_archive_and_forbids_an_incumbent_override(setup):
    s = setup
    with pytest.raises(ValueError, match="requires reviewed promotion delivery"):
        resolve_incumbent(s.assets, s.round, policy=s.policy)
    with pytest.raises(ValueError):
        RoundWorkAssetFile.model_validate(
            {**s.assets.model_dump(by_alias=True), "incumbent": s.work.plan.incumbent}
        )


@pytest.mark.parametrize("damage", ["missing", "wrong", "noncanonical", "symlink", "hardlink"])
def test_invalid_archive_manifest_holds_without_substitution(setup, tmp_path, damage):
    s = setup
    manifest = s.archive / s.round.incumbent_model_sha256 / "manifest.json"
    original = manifest.read_bytes()
    if damage in {"missing", "symlink", "hardlink"}:
        manifest.unlink()
        alternate = tmp_path / "alternate.json"
        alternate.write_bytes(original)
        alternate.chmod(0o600)
        if damage == "symlink":
            manifest.symlink_to(alternate)
        elif damage == "hardlink":
            os.link(alternate, manifest)
    else:
        manifest.chmod(0o600)
        manifest.write_bytes(
            original + b"\n"
            if damage == "noncanonical"
            else canonical_json_bytes(
                s.work.plan.incumbent.model_copy(update={"parent_baseline_sha256": "ef" * 32})
            )
        )
    with pytest.raises((OSError, ValueError)):
        resolve(s)


def test_wrong_suite_or_policy_is_rejected_before_archive_access(setup, monkeypatch):
    def unexpected(*_):
        pytest.fail("read archive before checking round identity")

    monkeypatch.setattr("umi.competition_round_assets._read", unexpected)
    with pytest.raises(ValueError, match="frozen suite or policy"):
        resolve(setup, setup.assets.model_copy(update={"suite_sha256": "ff" * 32}))
    with pytest.raises(ValueError, match="frozen suite or policy"):
        resolve_incumbent(
            setup.assets,
            setup.round.model_copy(update={"policy_sha256": "ff" * 32}),
            policy=setup.policy,
            archive=setup.archive,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("version", [1, 2])
async def test_coordinator_resolves_assets_before_deriving_work(setup, tmp_path, version):
    s = setup
    coordinator = object.__new__(RoundCoordinator)
    coordinator.policy = s.policy
    coordinator.config = SimpleNamespace(
        work=SimpleNamespace(asset_directory=str(tmp_path / "assets")),
        promotion_delivery=SimpleNamespace(archive_directory=str(s.archive)),
    )
    coordinator.journal = RoundJournal(tmp_path / "rounds", {"test": "asset-resolution"})
    coordinator.publish_certificate = lambda _: s.work.plan.cutoff
    calls = []

    async def prepared(plan, *, videos):
        calls.append((plan, videos))

    coordinator.work_queue = SimpleNamespace(maintain=prepared)
    plan = RoundPlan(
        schema="umi-round-plan/2",
        suite=s.work.item.suite,
        public_schedule=s.round.public_schedule,
        eligible_tracks=s.round.eligible_tracks,
        intake_opened_block=s.round.public_schedule.intake_opened_block,
        not_before_block=s.round.public_schedule.roster_close_earliest_block,
        admission_close_by_block=s.round.public_schedule.roster_close_latest_block,
        signing_close_block=s.round.public_schedule.work_signing_close_block,
        evaluation_close_block=s.round.public_schedule.evaluation_close_block,
        reveal_block=s.round.public_schedule.protected_reference_reveal_block,
        evidence_cutoff_block=s.round.public_schedule.evidence_cutoff_block,
        valid_through_block=s.round.public_schedule.round_valid_through_block,
    )
    coordinator.journal.put("plan", s.round.suite_sha256, plan)
    value = s.assets
    if version == 1:
        value = RoundWorkAssets(
            **{
                **s.assets.model_dump(by_alias=True),
                "schema": "umi-round-work-assets/1",
                "incumbent": s.work.plan.incumbent,
            }
        )
    _publish(
        Path(coordinator.config.work.asset_directory) / (s.round.suite_sha256 + ".json"), value
    )
    proposal = RoundProposal(
        schema="umi-round-proposal/1",
        cutoff=s.work.plan.cutoff.publication,
        submissions=s.work.plan.submissions,
        signing_close_block=plan.signing_close_block,
    )
    await coordinator.prepare_work(proposal)
    assert calls == [(s.work.plan, s.work.options["videos"])]


def test_new_round_uses_promoted_incumbent_and_old_round_stays_frozen(scenario, runtime):
    s = scenario
    previous = canonical_json_bytes(s.round)
    original_assets = assets_for(s.round, runtime)
    assert (
        resolve_incumbent(original_assets, s.round, policy=s.policy, archive=s.archive)
        == s.baseline
    )
    # Real promotion/store preparation, with a new committed suite and no model
    # field in the preplanned assets. No SQL promotion/head shortcut is used.
    suite = s.suite.model_copy(
        update={
            "cases": tuple(
                case.model_copy(update={"case_id": f"{index + 1000:064x}"})
                for index, case in enumerate(s.suite.cases)
            )
        }
    )
    next_assets = original_assets.model_copy(update={"suite_sha256": digest(suite)})
    planned_bytes = canonical_json_bytes(next_assets)
    promote(s, s.store, agreed_review(s), 150)
    prepared = s.store.prepare_round(
        snapshot=snapshot(151),
        suite=suite,
        public_schedule=PublicRoundSchedule(
            schema="umi-public-round-schedule/1",
            intake_opened_block=s.policy.valid_from_block,
            roster_close_earliest_block=151,
            roster_close_latest_block=151,
            work_signing_close_block=160,
            evaluation_close_block=170,
            protected_reference_reveal_block=180,
            evidence_cutoff_block=185,
            round_valid_through_block=190,
        ),
        eligible_tracks=("endpoint", "model"),
        intake_opened_block=s.policy.valid_from_block,
        evaluation_close_block=170,
        reveal_block=180,
        evidence_cutoff_block=185,
        valid_through_block=190,
        limits=PublicationReplayLimits(
            maximum_roster_bytes=1_000_000,
            maximum_certificate_bytes=4_000_000,
            maximum_evidence_bytes=5_000_000,
        ),
    )
    next_round = EvaluationRound.model_validate_json(
        canonical_json_bytes(prepared["cutoff_publication"]["round"])
    )
    assert next_round.incumbent_model_sha256 == digest(s.model.submission.model_bundle)
    assert (
        resolve_incumbent(next_assets, next_round, policy=s.policy, archive=s.archive)
        == s.model.submission.model_bundle
    )
    s.store = CompetitionStore(s.store.directory, s.policy)
    assert canonical_json_bytes(next_assets) == planned_bytes
    assert canonical_json_bytes(s.round) == previous
    assert (
        resolve_incumbent(original_assets, s.round, policy=s.policy, archive=s.archive)
        == s.baseline
    )
