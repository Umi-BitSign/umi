"""Quorum-bound tail decisions preserve clocks and legacy recovery semantics."""

import asyncio

import pytest

from umi.competition_cohort_coordinator import CohortPhaseProgress
from umi.competition_cohort_recovery import propose_recovery_transition
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_coordinator import harness as harness
from .test_competition_cohort_recovery import recovery as recovery
from .test_open_competition import policy as policy


@pytest.mark.parametrize("before_original_target", [False, True])
def test_certified_tail_closes_requests_without_resetting_outage_clock(
    harness, before_original_target
):
    h = harness
    h.advance_to("requests")
    original = h.state
    h.block = (
        original.observed_at_block + 1
        if before_original_target
        else original.targets[2].target_block + 1
    )
    h.unavailable = 100_000
    h.complete = True
    h.progress_changes = {
        "schema_": "umi-cohort-phase-progress/2",
        "request_tail_sha256": "ab" * 32,
    }
    h.tick()
    assert h.state.phase == "reference_reveal"
    signed = h.publications[-1].transitions[-1]
    assert signed.transition.schema_ == "umi-cohort-recovery-transition/2"
    assert signed.transition.request_tail_sha256 == "ab" * 32
    assert h.state.targets[:3] == original.targets[:3]
    assert h.state.observed_at_block == h.block
    # A new coordinator must replay the same additive decision, not synthesize
    # another opening, reset the measured outage, or reject the retained tail.
    h.restart()._history()
    assert h.state.phase == "reference_reveal"


def test_tail_progress_requires_the_independent_quorum(harness):
    h = harness
    h.advance_to("requests")
    h.block = h.state.observed_at_block + 1
    h.complete = True
    h.unavailable = 100_000
    h.names = ("Charlie",)
    h.progress_changes = {
        "schema_": "umi-cohort-phase-progress/2",
        "request_tail_sha256": "ab" * 32,
    }
    with pytest.raises(ValueError):
        h.tick()
    assert h.state.phase == "requests"


@pytest.mark.parametrize("phase", ["intake", "preparation", "reference_reveal", "evidence"])
def test_tail_cannot_shorten_other_phases(harness, phase):
    h = harness
    h.advance_to(phase)
    with pytest.raises(ValueError, match="only authorizes request closure"):
        propose_recovery_transition(
            h.state,
            h.authority.authority,
            operation="close_phase",
            observed_at_block=max(h.state.observed_at_block + 1, h.state.not_before_block),
            evidence_sha256="cd" * 32,
            request_tail_sha256="ab" * 32,
        )


def test_legacy_progress_and_transitions_keep_exact_wire_shape(harness):
    h = harness
    capture = asyncio.run(h.collect())
    progress = asyncio.run(h.observe(h.state, capture)).progress
    raw = canonical_json_bytes(progress)
    assert b"request_tail" not in raw
    assert CohortPhaseProgress.model_validate_json(raw) == progress
    h.complete = True
    h.block = h.state.targets[0].target_block
    h.tick()
    assert b"request_tail" not in canonical_json_bytes(h.publications[-1].transitions[-1])


@pytest.mark.parametrize(
    "changes",
    [
        {"request_tail_sha256": "ab" * 32},
        {"schema_": "umi-cohort-phase-progress/2"},
        {"schema_": "umi-cohort-phase-progress/2", "request_tail_sha256": "00" * 32},
        {"schema_": "umi-cohort-phase-progress/2", "request_tail_sha256": "ab" * 32},
    ],
)
def test_pending_progress_cannot_claim_tail_authority(harness, changes):
    h = harness
    h.advance_to("requests")
    progress = asyncio.run(h.observe(h.state, asyncio.run(h.collect()))).progress
    altered = progress.model_copy(update=changes)
    with pytest.raises(ValueError):
        CohortPhaseProgress.model_validate_json(canonical_json_bytes(altered))
