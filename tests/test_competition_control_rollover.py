"""Recurring control identities using bounded native journals and synthetic keys."""

from pathlib import Path
from types import SimpleNamespace

import pytest

from umi.competition_launch import PublicLaunchIdentity
from umi.competition_rounds import RoundCoordinator, RoundCoordinatorConfig, RoundPlan
from umi.open_competition import digest
from umi.private_files import publish_private_model
from umi.protocol import canonical_json_bytes

from .competition_checkpoint import bind_submission_checkpoint
from .test_competition_chain import chain_config as chain_config
from .test_competition_rounds import OwnedProvider, deployment_for, plan_at
from .test_competition_rounds import preparation as preparation
from .test_open_competition import policy as policy


@pytest.fixture
def recurring(preparation, chain_config, tmp_path):
    p = preparation
    schedule = p.options["public_schedule"]
    launch = PublicLaunchIdentity.model_validate(
        {
            **deployment_for(schedule, p.options["eligible_tracks"])
            .launch_identity()
            .model_dump(by_alias=True),
            "schema": "umi-competition-public-launch/2",
            "round_stride_blocks": 100,
        }
    )
    checkpoint = tmp_path / "checkpoint"
    store = bind_submission_checkpoint(p.store, launch, checkpoint)
    config = RoundCoordinatorConfig(
        schema="umi-round-coordinator-config/2",
        policy_sha256=digest(p.policy),
        public_launch=launch,
        chain=chain_config.model_copy(update={"state_directory": str(tmp_path / "chain")}),
        state_directory=str(tmp_path / "round-state"),
        intake_directory=str(store.directory),
        submission_head_checkpoint_directory=str(checkpoint),
        plan_directory=str(tmp_path / "plans"),
        certificate_directory=str(tmp_path / "certificates"),
        replay_limits=p.options["limits"],
    )
    base = RoundPlan(
        schema="umi-round-plan/2",
        suite=p.options["suite"],
        public_schedule=schedule,
        eligible_tracks=launch.eligible_tracks,
        intake_opened_block=schedule.intake_opened_block,
        not_before_block=schedule.roster_close_earliest_block,
        admission_close_by_block=schedule.roster_close_latest_block,
        signing_close_block=schedule.work_signing_close_block,
        evaluation_close_block=schedule.evaluation_close_block,
        reveal_block=schedule.protected_reference_reveal_block,
        evidence_cutoff_block=schedule.evidence_cutoff_block,
        valid_through_block=schedule.round_valid_through_block,
    )
    plans = tuple(plan_at(SimpleNamespace(plan=base), i + 1, 120 + 100 * i) for i in range(7))
    for i, plan in enumerate(plans):
        assert plan.public_schedule == launch.schedule_for_cycle(i)
        publish_private_model(Path(config.plan_directory) / (digest(plan.suite) + ".json"), plan)
    provider = OwnedProvider(110)
    coordinator = RoundCoordinator(config, p.policy, provider)
    return SimpleNamespace(
        coordinator=coordinator, provider=provider, config=config, policy=p.policy, plans=plans
    )


@pytest.mark.asyncio
async def test_seven_cycles_keep_exact_suite_schedule_and_prior_round_bytes(recurring):
    c = recurring
    # Polling all future plans must not close a round or retime any plan.
    for _ in range(4):
        result = await c.coordinator.cycle()
        assert result["held"] == result["prepared"] == 0
    assert len(c.coordinator.journal.keys("plan")) == 7
    assert not c.coordinator.journal.keys("prepared")
    frozen = {}
    for cycle, plan in enumerate(c.plans):
        if cycle == 3:
            c.coordinator = RoundCoordinator(c.config, c.policy, c.provider)
        c.provider.block = plan.not_before_block
        assert (await c.coordinator.cycle())["held"] == 0
        key = digest(plan.suite)
        raw = c.coordinator.journal.get("prepared", key)
        round_ = raw["cutoff"]["round"]
        assert round_["sequence"] == cycle + 1
        assert round_["suite_sha256"] == key
        assert round_["public_schedule"] == plan.public_schedule.model_dump(by_alias=True)
        assert round_["submission_close_block"] == plan.not_before_block
        frozen[key] = canonical_json_bytes(raw)
        for prior, expected in frozen.items():
            assert canonical_json_bytes(c.coordinator.journal.get("prepared", prior)) == expected
    assert len(c.coordinator.journal.keys("prepared")) == 7


@pytest.mark.asyncio
async def test_future_suite_cannot_be_retimed_after_reservation(recurring):
    c = recurring
    for _ in range(4):
        await c.coordinator.cycle()
    original = c.plans[1]
    changed = c.plans[2].model_copy(update={"suite": original.suite})
    path = Path(c.config.plan_directory) / (digest(original.suite) + ".json")
    # Simulate an operator replacing a staged file, not a supported publication.
    path.write_bytes(canonical_json_bytes(changed))
    c.provider.block = original.not_before_block
    assert (await c.coordinator.cycle())["held"] >= 1
    assert not c.coordinator.journal.keys("prepared")
    restarted = RoundCoordinator(c.config, c.policy, c.provider)
    path.write_bytes(canonical_json_bytes(original))
    assert (await restarted.cycle())["held"] >= 1
    assert not restarted.journal.keys("prepared")
