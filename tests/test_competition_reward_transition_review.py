"""Native endpoint reuse and fresh control binding at the signing boundary.

The retained-endpoint issuer is a fixture for completed native verification;
these tests do not claim that serialized coverage hints establish a proof.
"""

from dataclasses import replace
from types import SimpleNamespace

import pytest

from umi.competition_reward_coverage_intervals import _issue_retained_coverage
from umi.competition_reward_opportunity import opportunity_rule
from umi.competition_reward_transition_review import predecessor_live_age_from_owned_control
from umi.competition_reward_transition_timing import REWARD_TRANSITION_WAIT_MS
from umi.open_competition import digest, identity

from .test_competition_reward_control import commitment
from .test_competition_reward_coverage_intervals import point
from .test_competition_reward_opportunity import chain as chain
from .test_competition_reward_opportunity import chain_config as chain_config
from .test_competition_reward_opportunity import control as control
from .test_competition_reward_opportunity import manifest_case as manifest_case
from .test_competition_reward_opportunity import opportunity_case as opportunity_case
from .test_competition_reward_opportunity import policy as policy
from .test_competition_reward_opportunity import series_case as series_case
from .test_competition_reward_transition_timing import predecessor
from .test_open_competition import wallet


@pytest.fixture
async def live_case(opportunity_case, control):
    c = opportunity_case
    prior = predecessor(c)
    control.rpc.values[control.spec] = commitment(digest(prior), 200)
    observation = await control.provider.collect_control(control.hotkey)
    native = point(
        series_sha256=digest(c.series),
        runtime_profile_sha256=c.manifest.opportunity.runtime_profile_sha256,
        chain_config_sha256=digest(control.config),
        activation_sha256=digest(c.activation),
        allocation_sha256=c.activation.allocation_sha256,
        validator_account_id=identity(c.series.validators[0]),
        block=201,
        timestamp_ms=observation.timestamp_ms - REWARD_TRANSITION_WAIT_MS,
    )

    def endpoint(*, changes=None, row=None):
        selected = native.model_copy(update=changes or {})
        return _issue_retained_coverage(
            selected,
            c.activation.package_sha256,
            "22" * 32,
            row_state=row
            if row is not None
            else {
                "row_matches": True,
                "validator_last_update": selected.block,
            },
        )

    args = dict(
        series=c.series,
        predecessor=prior,
        live_endpoint=endpoint(),
        observation=observation,
        chain_config_sha256=digest(control.config),
        rule=opportunity_rule(c.manifest, c.series, c.policy),
    )
    return SimpleNamespace(c=c, control=control, args=args, native=native, endpoint=endpoint)


async def test_owned_live_anchor_reuses_native_verdict_without_rpc_or_proof_replay(live_case):
    c = live_case
    checked_before = len(c.control.verifier.checked)
    calls_before = len(c.control.rpc.calls)
    actual = predecessor_live_age_from_owned_control(**c.args)
    observation = c.args["observation"]
    assert actual.ready and actual.remaining_ms == 0
    assert actual.live_endpoint_sha256 == c.native.key()
    assert actual.live_block_hash == c.native.block_hash.removeprefix("0x")
    assert actual.live_timestamp_ms == c.native.timestamp_ms
    assert actual.observation_evidence_sha256 == observation.evidence_sha256
    assert actual.observed_block_hash == observation.snapshot.block_hash.removeprefix("0x")
    assert actual.observed_at_block == observation.snapshot.block_number
    assert actual.observed_timestamp_ms == observation.timestamp_ms
    assert predecessor_live_age_from_owned_control(**c.args) == actual
    assert len(c.control.verifier.checked) == checked_before
    assert len(c.control.rpc.calls) == calls_before


@pytest.mark.parametrize("mutation", ["unissued", "row_write_changed", "serialized_hint"])
async def test_unowned_or_altered_live_anchor_is_not_signable(live_case, mutation):
    endpoint = live_case.args["live_endpoint"]
    forged = {
        "unissued": replace(endpoint, _issuer=None),
        "row_write_changed": replace(endpoint, validator_last_update=200),
        "serialized_hint": live_case.native,
    }[mutation]
    with pytest.raises(ValueError, match="native provenance"):
        predecessor_live_age_from_owned_control(**(live_case.args | {"live_endpoint": forged}))


@pytest.mark.parametrize(
    "change",
    [
        {"series_sha256": "fa" * 32},
        {"chain_config_sha256": "fa" * 32},
        {"activation_sha256": "fa" * 32},
        {"validator_account_id": "fa" * 32},
        {"runtime_profile_sha256": "fa" * 32},
        {"covered": False},
        {"block": 199},
    ],
)
async def test_other_owned_domain_or_nonlive_row_cannot_start_the_clock(live_case, change):
    endpoint = live_case.endpoint(changes=change)
    with pytest.raises(ValueError):
        predecessor_live_age_from_owned_control(**(live_case.args | {"live_endpoint": endpoint}))


@pytest.mark.parametrize(
    "row",
    [
        {"row_matches": False, "validator_last_update": 201},
        {"row_matches": None, "validator_last_update": 201},
        {"row_matches": True, "validator_last_update": None},
        {"row_matches": True, "validator_last_update": 200},
        {"row_matches": True, "validator_last_update": True},
    ],
)
async def test_covered_endpoint_requires_its_proved_matching_row_write(live_case, row):
    with pytest.raises(ValueError, match="row-write endpoint"):
        predecessor_live_age_from_owned_control(
            **(live_case.args | {"live_endpoint": live_case.endpoint(row=row)})
        )


@pytest.mark.parametrize("mutation", ["timestamp", "evidence", "unissued"])
async def test_current_control_cannot_be_recreated_or_edited(live_case, mutation):
    observation = live_case.args["observation"]
    changes = {
        "timestamp": {"timestamp_ms": observation.timestamp_ms + 1},
        "evidence": {"evidence": b"{}"},
        "unissued": {"_issuer": None},
    }[mutation]
    with pytest.raises(ValueError, match="current proof adapter"):
        predecessor_live_age_from_owned_control(
            **(live_case.args | {"observation": replace(observation, **changes)})
        )


@pytest.mark.parametrize("when", ["before_capture", "expired"])
async def test_observation_is_fresh_when_consumed_not_only_when_captured(
    live_case, monkeypatch, when
):
    observation = live_case.args["observation"]
    now = (
        observation.captured_monotonic_ns - 1
        if when == "before_capture"
        else observation.expires_monotonic_ns + 1
    )
    monkeypatch.setattr("umi.competition_reward_control.time.monotonic_ns", lambda: now)
    with pytest.raises(ValueError, match="current proof adapter"):
        predecessor_live_age_from_owned_control(**live_case.args)


async def test_fresh_observation_of_a_new_control_cannot_time_the_old_predecessor(live_case):
    c = live_case
    c.control.rpc.values[c.control.spec] = commitment("fa" * 32, 201)
    changed = await c.control.provider.collect_control(c.control.hotkey)
    with pytest.raises(ValueError, match="row-write endpoint"):
        predecessor_live_age_from_owned_control(**(c.args | {"observation": changed}))


@pytest.mark.parametrize("change", ["chain", "control_authority"])
async def test_native_observation_must_belong_to_selected_chain_and_authority(live_case, change):
    args = live_case.args
    if change == "chain":
        args = args | {"chain_config_sha256": "fa" * 32}
    else:
        args = args | {
            "series": args["series"].model_copy(
                update={"control_hotkey": wallet("Alice").hotkey.ss58_address}
            )
        }
    with pytest.raises(ValueError, match="current proof adapter"):
        predecessor_live_age_from_owned_control(**args)


@pytest.mark.parametrize("change", ["future_block", "future_timestamp"])
async def test_live_anchor_cannot_follow_current_finalized_observation(live_case, change):
    observation = live_case.args["observation"]
    mutation = (
        {"block": observation.snapshot.block_number + 1}
        if change == "future_block"
        else {"timestamp_ms": observation.timestamp_ms + 1}
    )
    with pytest.raises(ValueError, match="finalized observation order"):
        predecessor_live_age_from_owned_control(
            **(live_case.args | {"live_endpoint": live_case.endpoint(changes=mutation)})
        )
