"""Adopted original plan through native request close, publication and reopen."""

import pytest

from umi.competition_cohort_coordinator import replay_cohort_decisions
from umi.competition_cohort_order_signer import CohortOrderHistory
from umi.competition_cohort_request_publication import CohortRequestSettlementPublisher
from umi.competition_cohort_request_rule import authenticated_request_tail_rule
from umi.open_competition import digest
from umi.private_files import read_private_model
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_request_phase import base_policy as base_policy
from .test_competition_cohort_request_phase import chain as chain
from .test_competition_cohort_request_phase import chain_config as chain_config
from .test_competition_cohort_request_phase import endpoint as endpoint
from .test_competition_cohort_request_phase import execution as execution
from .test_competition_cohort_request_phase import granted as granted
from .test_competition_cohort_request_phase import harness as harness
from .test_competition_cohort_request_phase import known_video_bytes as known_video_bytes
from .test_competition_cohort_request_phase import legacy_scenario as legacy_scenario
from .test_competition_cohort_request_phase import miner_policy as miner_policy
from .test_competition_cohort_request_phase import original_harness as original_harness
from .test_competition_cohort_request_phase import policy as policy
from .test_competition_cohort_request_phase import receipt_scenario as receipt_scenario
from .test_competition_cohort_request_phase import recovery as recovery
from .test_competition_cohort_request_phase import recovery_case as recovery_case
from .test_competition_cohort_request_phase import relay as relay
from .test_competition_cohort_request_phase import request_controller
from .test_competition_cohort_request_phase import request_owner as request_owner
from .test_competition_cohort_request_phase import runtime as runtime
from .test_competition_cohort_request_phase import scenario as scenario
from .test_competition_cohort_request_phase import service as service
from .test_competition_cohort_request_phase import service_catalog_inputs as service_catalog_inputs
from .test_competition_cohort_request_phase import service_closed as service_closed
from .test_competition_cohort_request_phase import service_owner as service_owner
from .test_competition_cohort_request_phase import shared_control_group as shared_control_group
from .test_competition_cohort_service_grants import service_quality_inputs as service_quality_inputs


@pytest.mark.asyncio
@pytest.mark.parametrize("recovery", ["legacy6"], indirect=True)
@pytest.mark.parametrize("receipt_scenario", ["adopted"], indirect=True)
async def test_original_adopted_history_closes_and_retries_publication(request_owner, tmp_path):
    h = request_owner
    original_history = h.intake.history(h.cohort)
    original_plan = canonical_json_bytes(original_history.plan)
    adoption = next(
        t
        for t in original_history.transitions
        if t.transition.operation == "adopt_request_tail_rule"
    )
    opening = h.source.request_opening(h.state)
    assert (
        authenticated_request_tail_rule(original_history, h.b["policy"])
        == "original_request_12h_with_completed_miner/1"
    )
    h.window()
    handoff = tmp_path / "adopted-handoff" / (h.cohort + ".json")
    proofs = []
    failed = False

    async def proof(observation):
        nonlocal failed
        if not failed:
            failed = True
            raise OSError("publication interrupted after original certification")
        proofs.append(observation)

    def publication(decisions):
        return CohortRequestSettlementPublisher(
            h.source,
            h.provider.collect,
            decisions,
            proof,
            sources=h.sources,
            history_directory=handoff.parent,
        )

    with request_controller(h, tmp_path, publication) as control:
        with pytest.raises(OSError, match="publication interrupted"):
            await control.reopen().tick()
        assert control.store.status(h.cohort)[0].phase == "reference_reveal"
        assert not handoff.exists()
        h.source = h.reopen()
        control.publisher.source = h.source
        closed = h.intake.history(h.cohort)
        await control.publisher(closed)
        raw = handoff.read_bytes()
        await control.publisher(closed)
        assert handoff.read_bytes() == raw
        exported = read_private_model(handoff, CohortOrderHistory, maximum_bytes=8 * 1024**2)
        assert exported.history == closed
        assert canonical_json_bytes(exported.history.plan) == original_plan
        assert adoption in exported.history.transitions
        assert adoption.transition.evidence_sha256 not in exported.inputs()
        state, _, _ = replay_cohort_decisions(
            exported.history, h.b["policy"], exported.inputs().__getitem__
        )
        assert state.phase == "reference_reveal"
        assert state.request_tail_rule == "original_request_12h_with_completed_miner/1"
        assert opening in proofs
        assert set(map(digest, proofs)) == {digest(d.observation) for d in exported.decisions}


@pytest.mark.asyncio
@pytest.mark.parametrize("recovery", ["legacy6"], indirect=True)
@pytest.mark.parametrize("receipt_scenario", ["adopted"], indirect=True)
@pytest.mark.parametrize("service_catalog_inputs", [True], indirect=True)
async def test_adopted_legacy_history_survives_native_reward_package(
    service_quality_inputs, tmp_path
):
    from umi.competition_cohort_reward_package import replay_reward_package

    from .test_competition_cohort_consumers import tip
    from .test_competition_reward_preparation import native_package

    b = service_quality_inputs
    original_plan = canonical_json_bytes(b["history"].plan)
    adoption = next(
        t for t in b["history"].transitions if t.transition.operation == "adopt_request_tail_rule"
    )
    prepared = await native_package.__wrapped__(b, tmp_path / "adopted-package")
    package = prepared.package
    assert canonical_json_bytes(package.inputs.history.plan) == original_plan
    assert adoption in package.inputs.history.transitions
    assert adoption.transition.evidence_sha256 not in {obj.sha256 for obj in package.objects}
    assert (
        authenticated_request_tail_rule(package.inputs.history, b["policy"])
        == "original_request_12h_with_completed_miner/1"
    )
    replayed = replay_reward_package(
        package,
        b["policy"],
        prepared.store,
        package.inputs.history,
        expected_package_sha256=digest(package),
        expected_cohort_sha256=digest(package.inputs.history.plan),
        expected_tip_sha256=tip(package.inputs.history),
        current_block=2**53 - 1,
        expected_terms_sha256=prepared.requirement.terms_sha256,
        expected_catalog_sha256s=prepared.requirement.catalog_sha256s,
        maximum_promotion_bytes=1_000_000,
    )
    assert replayed == prepared.allocation
