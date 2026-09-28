"""Original registration archives through native intake progress review."""

from __future__ import annotations

import pytest

from umi.competition_cohort_admission_queue import CohortAdmissionQueue
from umi.competition_cohort_intake import CohortIntake, history_tip
from umi.competition_cohort_intake_phase import CohortIntakePhaseObserver
from umi.competition_cohort_intake_review import IntakeProgressReviewer, NativeIntakeProgressSource
from umi.open_competition import digest

from .test_competition_chain import chain as chain
from .test_competition_chain import chain_config as chain_config
from .test_competition_cohort_admission_review import accepted as accepted
from .test_competition_cohort_consumers import scenario as scenario
from .test_competition_cohort_intake import capture_at
from .test_competition_cohort_recovery import recovery as recovery
from .test_competition_historical_registration import archive as archive
from .test_open_competition import policy as policy


@pytest.mark.parametrize("changed", [False, True])
async def test_review_uses_original_proofs_and_owned_headers(archive, accepted, changed):
    a = archive
    config, history, _, receipt = accepted
    intake = CohortIntake(config, a.chain.policy)
    phase = CohortIntakePhaseObserver(intake)
    cohort = digest(history.plan)
    # Readiness samples are synthetic, as is the fixture's finality/codec port.
    # Seal and consent use the actual archived capture and native proof replay.
    for block in range(a.old.height - 100, a.old.height, 5):
        phase.observe(
            cohort, capture_at(block), serving=True, expected_tip_sha256=history_tip(history)
        )
    result = phase.observe(
        cohort, a.capture, serving=True, expected_tip_sha256=history_tip(history)
    )
    assert result.seal is not None
    CohortAdmissionQueue(intake).attach_evidence(
        cohort, receipt.proposed_admission.consent_sha256, a.raw, a.metadata
    )

    async def original(expected):
        assert expected == a.expected
        return (a.raw, b"changed" if changed else a.metadata)

    reviewer = IntakeProgressReviewer(NativeIntakeProgressSource(intake), a.reviewer, original)
    before = len(a.chain.verifier.checked)
    if changed:
        with pytest.raises(ValueError):
            await reviewer.review(result.progress)
    else:
        reviewed = await reviewer.review(result.progress)
        assert reviewed.seal_sha256 == digest(result.seal)
        assert reviewed.service.observation.block == a.old.height
        assert len(a.chain.verifier.checked) > before
