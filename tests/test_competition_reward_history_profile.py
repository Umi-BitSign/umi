"""Local parallel selection preserves original signed/installed defaults."""

import pytest

from umi.competition_reward_history_workers import MAX_FRAME_BYTES, HistoryVerificationProfile
from umi.competition_reward_service import StandingRewardServiceLimits
from umi.protocol import canonical_json_bytes


def test_existing_serial_service_config_preserves_canonical_bytes():
    body = {
        "maximum_journal_bytes": 1024**2,
        "mortality_period": 128,
        "maximum_history_blocks": 64,
        "submission_timeout_seconds": 120,
        "poll_seconds": 12,
    }
    old = StandingRewardServiceLimits.model_validate(body)
    assert old.history_verification is None
    assert canonical_json_bytes(old) == canonical_json_bytes(body)
    selected = old.model_copy(
        update={
            "history_verification": HistoryVerificationProfile(
                schema="umi-history-verification-profile/1"
            )
        }
    )
    assert (
        StandingRewardServiceLimits.model_validate_json(canonical_json_bytes(selected)) == selected
    )
    assert old.mortality_period == selected.mortality_period
    assert canonical_json_bytes(old) == canonical_json_bytes(body)


@pytest.mark.parametrize(
    "change",
    [
        dict(workers=True),
        dict(workers=0),
        dict(workers=3),
        dict(maximum_in_flight_bytes=MAX_FRAME_BYTES - 1),
    ],
)
def test_unsupported_worker_profiles_refuse_before_native_work(change):
    with pytest.raises(ValueError):
        HistoryVerificationProfile(schema="umi-history-verification-profile/1", **change)


def test_maximum_supported_frame_is_admitted_by_explicit_local_profile():
    selected = HistoryVerificationProfile(
        schema="umi-history-verification-profile/1",
        workers=1,
        maximum_in_flight=1,
        maximum_in_flight_bytes=MAX_FRAME_BYTES,
    )
    assert selected.required_memory_bytes > 16 * MAX_FRAME_BYTES
