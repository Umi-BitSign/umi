from __future__ import annotations

import sqlite3
from pathlib import Path
from types import SimpleNamespace

import pytest

from umi import competition_rounds as rounds
from umi.competition_evaluator import _publish, _read
from umi.competition_publication import build_cutoff_publication
from umi.competition_settlement_preparation import SettlementPreparation
from umi.open_competition import digest, identity
from umi.protocol import canonical_json_bytes

from .test_competition_chain import chain_config as chain_config
from .test_competition_publication import _certificate, _scenario
from .test_competition_publication import replay_limits as replay_limits
from .test_competition_rounds import OwnedProvider
from .test_open_competition import policy as policy
from .test_open_competition import snapshot


@pytest.fixture
def setup(policy, replay_limits, chain_config, tmp_path):
    limits = replay_limits.model_copy(update={"maximum_certificate_bytes": 2_000_000})
    s = _scenario(policy, tmp_path, limits, settle=False)
    cutoff = _certificate(
        build_cutoff_publication(
            round_=s.round,
            cutoff_schedule=s.schedule,
            registration_snapshot=snapshot(120),
            submissions=s.submissions,
            policy=policy,
            limits=limits,
        )
    )
    config = rounds.RoundCoordinatorConfig(
        schema="umi-round-coordinator-config/1",
        policy_sha256=digest(policy),
        chain=chain_config.model_copy(
            update={
                "policy_sha256": digest(policy),
                "state_directory": str(tmp_path / "chain"),
                "collection_timeout_seconds": 10,
            }
        ),
        state_directory=str(tmp_path / "rounds"),
        intake_directory=str(s.store.directory),
        plan_directory=str(tmp_path / "plans"),
        certificate_directory=str(tmp_path / "cutoffs"),
        settlement_directory=str(tmp_path / "settlements"),
        replay_limits=limits,
    )
    provider = OwnedProvider(160)
    coordinator = rounds.RoundCoordinator(config, policy, provider)
    proposal = rounds.RoundProposal(
        schema="umi-round-proposal/1",
        cutoff=cutoff.publication,
        submissions=s.submissions,
        signing_close_block=130,
    )
    plan = rounds.RoundPlan(
        schema="umi-round-plan/1",
        suite=s.suite,
        not_before_block=120,
        admission_close_by_block=125,
        signing_close_block=130,
        evaluation_close_block=140,
        reveal_block=150,
        evidence_cutoff_block=160,
        valid_through_block=200,
    )
    _publish(Path(config.plan_directory) / (digest(s.suite) + ".json"), plan)
    coordinator.journal.put("plan", digest(s.suite), plan)
    coordinator.journal.put("prepared", digest(s.suite), proposal)
    for signature in cutoff.signatures:
        vote = rounds.CutoffEndorsement(proposal_sha256=digest(proposal), signature=signature)
        coordinator.journal.put("vote", digest(proposal) + ":" + identity(signature.hotkey), vote)
    return SimpleNamespace(
        scenario=s,
        policy=policy,
        config=config,
        coordinator=coordinator,
        provider=provider,
        proposal=proposal,
        plan=plan,
    )


@pytest.mark.asyncio
async def test_coordinator_poll_reaches_retained_settlement_without_manual_assembly(setup):
    s = setup
    result = await s.coordinator.cycle()
    assert result["settlement_prepared"] == 1
    assert result["settlement_held"] == result["settlement_incomplete"] == 0
    path = Path(s.config.settlement_directory) / (
        digest(s.scenario.round) + ".settlement-proposal.json"
    )
    prepared = _read(path, SettlementPreparation)
    assert b'"references"' in canonical_json_bytes(prepared)
    assert not prepared.chain_submission_authorized
    assert s.coordinator.proposals(block=160) == []
    assert s.coordinator.journal.settlement_entries(160) == [s.proposal]
    s.provider.block = 170
    s.coordinator = rounds.RoundCoordinator(s.config, s.policy, s.provider)
    assert (await s.coordinator.cycle())["settlement_prepared"] == 1
    assert _read(path, SettlementPreparation) == prepared


@pytest.mark.asyncio
async def test_missing_evidence_does_not_stop_coordinator_or_shrink_roster(setup):
    s = setup
    with sqlite3.connect(s.scenario.store.path) as db:
        db.execute(
            "DELETE FROM independent_evaluation_evidence WHERE submission=?",
            (s.scenario.round.roster[0],),
        )
    result = await s.coordinator.cycle()
    assert result["settlement_incomplete"] == 1 and result["settlement_prepared"] == 0
    assert s.scenario.store.settlement_status(digest(s.scenario.round)) is None
    assert not Path(s.config.settlement_directory).exists()


def test_settlement_output_cannot_overlap_intake_or_other_private_directories(setup):
    s = setup
    for path in (s.config.intake_directory, s.config.plan_directory + "/nested"):
        values = s.config.model_dump(mode="json", by_alias=True)
        values["settlement_directory"] = path
        with pytest.raises(ValueError, match="overlap"):
            rounds.RoundCoordinatorConfig.model_validate_json(canonical_json_bytes(values))


def test_settlement_index_reconstructed_from_retained_original_windows(setup):
    s = setup
    with sqlite3.connect(s.coordinator.journal.path) as db:
        db.execute("DROP TABLE round_settlement_index")
    driver = rounds.RoundCoordinator(s.config, s.policy, s.provider)
    assert driver.journal.settlement_entries(159) == []
    assert driver.journal.settlement_entries(160) == [s.proposal]
    assert driver.journal.settlement_entries(200) == [s.proposal]
    assert driver.journal.settlement_entries(201) == []


@pytest.mark.parametrize("field", ["cutoff", "valid_through"])
def test_changed_settlement_window_is_not_silently_repaired(setup, field):
    s = setup
    with sqlite3.connect(s.coordinator.journal.path) as db:
        db.execute(f"UPDATE round_settlement_index SET {field}={field}+1")
    with pytest.raises(ValueError, match="windows changed"):
        rounds.RoundCoordinator(s.config, s.policy, s.provider)


def test_settlement_page_has_bounded_cursor_and_original_deadlines(setup):
    s = setup
    assert len(s.coordinator.journal.settlement_entries(160)) == 1
    assert s.coordinator.journal.settlement_entries(160, after_sequence=1) == []
    assert s.coordinator.journal.settlement_entries(201) == []


def test_expired_history_does_not_starve_current_settlement_pages(setup):
    s = setup
    for sequence in range(2, 25):
        expired = sequence < 20
        round_ = s.proposal.cutoff.round.model_copy(
            update={
                "sequence": sequence,
                "suite_sha256": f"{sequence:064x}",
                "valid_through_block": 159 if expired else 200,
            }
        )
        schedule = s.proposal.cutoff.cutoff_schedule.model_copy(
            update={
                "round_sha256": digest(round_),
                "evidence_cutoff_block": 150 if expired else 160,
            }
        )
        cutoff = s.proposal.cutoff.model_copy(
            update={
                "round": round_,
                "round_sha256": digest(round_),
                "cutoff_schedule": schedule,
            }
        )
        proposal = s.proposal.model_copy(update={"cutoff": cutoff})
        s.coordinator.journal.put("prepared", round_.suite_sha256, proposal)
    first = s.coordinator.journal.settlement_entries(160)
    assert [p.cutoff.round.sequence for p in first] == [1, 20, 21, 22]
    second = s.coordinator.journal.settlement_entries(160, after_sequence=22)
    assert [p.cutoff.round.sequence for p in second] == [23, 24]
    assert s.coordinator.journal.settlement_entries(160, after_sequence=24) == []


def test_disabled_settlement_preserves_the_previous_configuration_binding(setup, tmp_path):
    s = setup
    config = s.config.model_copy(
        update={
            "state_directory": str(tmp_path / "old-round-state"),
            "settlement_directory": None,
        }
    )
    old_binding = config.model_dump(
        mode="json",
        by_alias=True,
        exclude={
            "maximum_rounds",
            "maximum_journal_bytes",
            "poll_seconds",
            "host",
            "port",
            "work",
            "settlement_directory",
            "settlement_delivery",
        },
    )
    rounds.RoundJournal(Path(config.state_directory), old_binding)
    driver = rounds.RoundCoordinator(config, s.policy, s.provider)
    assert driver.config.settlement_directory is None
