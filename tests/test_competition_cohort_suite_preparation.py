"""The native preparation owner freezes adopted suite and original incumbent together."""

import pytest

from umi.competition_cohort_history import CohortRecoveryHistory
from umi.competition_cohort_suite_adoption import prepare_evaluation_suite_adoption
from umi.open_competition import digest, sign_object
from umi.protocol import canonical_json_bytes

from . import test_competition_cohort_consumers as consumers
from .test_competition_cohort_intake import intake as intake
from .test_competition_cohort_preparation import preparation as preparation
from .test_competition_cohort_preparation import run
from .test_competition_cohort_recovery import recovery as recovery
from .test_competition_cohort_recovery import signatures, signed_transition
from .test_competition_cohort_standing_phases import standing
from .test_open_competition import policy as policy
from .test_open_competition import wallet

legacy_scenario = consumers.scenario


@pytest.fixture
def scenario(legacy_scenario, policy):
    original = legacy_scenario["intake_history"]
    authority, genesis, _ = standing(original.plan, policy, model_rewards=True)
    history = CohortRecoveryHistory(
        schema="umi-cohort-recovery-history/1",
        plan=original.plan,
        authority=authority,
        genesis=genesis,
        genesis_signatures=signatures(genesis),
        transitions=(),
    )
    amendment = prepare_evaluation_suite_adoption(
        history,
        policy,
        expected_tip_sha256=digest(genesis),
        current_block=200,
        suite_sha256="91" * 32,
        selection_manifest_sha256="92" * 32,
    )
    history = history.model_copy(update={"transitions": (signed_transition(amendment),)})
    consent = legacy_scenario["consent"].consent.model_copy(
        update={"authority_sha256": digest(authority.authority)}
    )
    consent = legacy_scenario["consent"].__class__(
        consent=consent,
        signature=sign_object(consent, wallet("Alice")),
    )
    return legacy_scenario | dict(intake_history=history, consent=consent)


def test_native_preparation_and_restart_keep_effective_suite_and_original_floor_model(preparation):
    h = preparation
    h.certify()
    original_history = canonical_json_bytes(h.history)
    result = run(h)
    assert result.roster.round.suite_sha256 == "91" * 32
    assert result.roster.round.suite_sha256 != h.history.plan.suite_sha256
    assert result.roster.round.cohort_sha256 == digest(h.history.plan)
    assert result.roster.round.incumbent_model_sha256 == result.promotion_head.model_sha256
    assert canonical_json_bytes(h.history) == original_history
    repeated = run(h, block=100_330)
    assert canonical_json_bytes(repeated) == canonical_json_bytes(result)
