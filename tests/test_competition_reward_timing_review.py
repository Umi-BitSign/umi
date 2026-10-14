"""Actual native archive proof and persistent timestamp reuse."""

import hashlib

import pytest

from umi.competition_reward_timing_review import review_activation_age

from .test_competition_reward_control_archive import historical as historical
from .test_competition_reward_decisions import chain as chain
from .test_competition_reward_decisions import chain_config as chain_config
from .test_competition_reward_decisions import control as control
from .test_competition_reward_decisions import policy as policy
from .test_competition_reward_decisions import series_case as series_case


@pytest.mark.parametrize("damage", ["missing", "damaged_without_marker", "legacy_damaged"])
async def test_native_timestamp_proof_is_retained_across_provider_restart(
    historical, tmp_path, monkeypatch, damage
):
    h = historical
    # The historical fixture's original block is independently native-authenticated.
    plan = h.c.series.cohorts[0].model_copy(update={"not_before_block": h.old.height})
    series = h.c.series.model_copy(update={"cohorts": (plan,)})
    for _ in range(7):
        h.advance()
    observation = await h.item.provider.collect_control(h.item.hotkey)
    args = dict(
        series=series,
        plan=plan,
        observation=observation,
        start_evidence=h.raw,
        start_metadata=h.metadata,
        receipt_directory=tmp_path / "age-receipts",
    )
    value = await review_activation_age(h.item.provider, **args)
    assert value.skips_activation_delay
    assert value.cohort_start_timestamp_ms == h.old.timestamp_ms
    assert value.observed_timestamp_ms == observation.timestamp_ms
    assert value.start_evidence_sha256 == hashlib.sha256(h.raw).hexdigest()
    await h.item.provider.aclose()
    h.item.provider = h.reopen()
    import umi.competition_reward_timing_review as review

    async def cannot_repeat(*args, **kwargs):
        raise AssertionError("completed native timestamp proof must be reused")

    monkeypatch.setattr(review, "verify_slot_archive", cannot_repeat)
    observation = await h.item.provider.collect_control(h.item.hotkey)
    repeated = await review_activation_age(h.item.provider, **{**args, "observation": observation})
    assert repeated.cohort_start_timestamp_ms == value.cohort_start_timestamp_ms
    assert repeated.start_evidence_sha256 == value.start_evidence_sha256
    receipts = list((tmp_path / "age-receipts").glob("*.json"))
    assert len(receipts) == 1
    if damage == "missing":
        receipts[0].unlink()
    else:
        receipts[0].write_text("damaged")
        receipts[0].with_suffix(".complete").unlink()
        if damage == "legacy_damaged":
            monkeypatch.setenv(
                "UMI_NATIVE_VERIFICATION_DIRECTORY", str(tmp_path / "shared-receipts")
            )
    with pytest.raises(ValueError, match="explicit receipt repair"):
        await review_activation_age(h.item.provider, **{**args, "observation": observation})
    await h.item.provider.aclose()


async def test_wrong_cohort_start_refused_before_native_work(historical, tmp_path):
    h = historical
    plan = h.c.series.cohorts[0].model_copy(update={"not_before_block": h.old.height + 1})
    series = h.c.series.model_copy(update={"cohorts": (plan,)})
    observation = await h.item.provider.collect_control(h.item.hotkey)
    with pytest.raises(ValueError, match="signed cohort start"):
        await review_activation_age(
            h.item.provider,
            series=series,
            plan=plan,
            observation=observation,
            start_evidence=h.raw,
            start_metadata=h.metadata,
            receipt_directory=tmp_path / "age-receipts",
        )
    await h.item.provider.aclose()


async def test_legacy_raw_history_needs_no_per_block_checkpoint_migration(
    historical, tmp_path, monkeypatch
):
    from umi.competition_reward_history import RewardControlHistoryReader
    from umi.open_competition import digest

    h = historical
    plan = h.c.series.cohorts[0].model_copy(update={"not_before_block": h.old.height})
    series = h.c.series.model_copy(update={"cohorts": (plan,)})
    history = RewardControlHistoryReader(
        tmp_path / "legacy-history",
        control_hotkey=h.item.hotkey,
        chain_config_sha256=digest(h.item.config),
        first_block=h.old.height,
        maximum_bytes=32 * 1024**2,
    )
    history._save_fields(
        h.old.height,
        {
            "slot_evidence": h.raw,
            "slot_metadata": h.metadata,
            "evidence": b"retained write archive not consumed by the timestamp proof",
        },
    )
    assert history.checkpoints.load(h.old.height) is None
    observation = await h.item.provider.collect_control(h.item.hotkey)
    args = dict(
        series=series,
        plan=plan,
        observation=observation,
        history=history,
        receipt_directory=tmp_path / "legacy-age",
    )
    value = await review_activation_age(h.item.provider, **args)
    assert value.cohort_start_timestamp_ms == h.old.timestamp_ms
    assert history.checkpoints.load(h.old.height) is None

    def forbid_payload(*args, **kwargs):
        raise AssertionError("cached timestamp must not reread legacy history payloads")

    monkeypatch.setattr(history, "_load", forbid_payload)
    again = await review_activation_age(h.item.provider, **args)
    assert again == value
    await h.item.provider.aclose()
