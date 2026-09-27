"""Static minimum and predecessor bindings; native replay is tested separately."""

from dataclasses import replace
from types import SimpleNamespace

import pytest

from umi.competition_reward_decisions import (
    RewardActivation,
    RewardControlDecision,
    StandingRewardControlReader,
    StandingRewardSelection,
)
from umi.competition_reward_handoff_models import (
    LegacyRewardHandoffIntent,
    LegacyRewardHandoffPlan,
    VerifiedLegacyRewardHandoff,
    _issue_legacy_handoff,
)
from umi.competition_reward_manifest import (
    RewardOpportunityTerms,
    StandingRewardOpportunityManifest,
    verify_reward_manifest,
)
from umi.competition_reward_opportunity import (
    RewardOpportunityCertificate,
    RewardOpportunityContribution,
    RewardOpportunityWitness,
    VerifiedRewardOpportunity,
    _issue_opportunity,
    check_opportunity_claim,
    opportunity_rule,
    require_previous_opportunity,
)
from umi.open_competition import digest, identity
from umi.protocol import canonical_json_bytes

from .test_competition_reward_decisions import signed
from .test_competition_reward_manifest import chain as chain
from .test_competition_reward_manifest import chain_config as chain_config
from .test_competition_reward_manifest import control as control
from .test_competition_reward_manifest import manifest_case as manifest_case
from .test_competition_reward_manifest import policy as policy
from .test_competition_reward_manifest import series_case as series_case


@pytest.fixture
def opportunity_case(manifest_case, tmp_path):
    c = manifest_case
    manifest = StandingRewardOpportunityManifest(
        **(
            c.manifest.model_dump(by_alias=True)
            | {
                "schema": "umi-standing-reward-manifest/2",
                "opportunity": RewardOpportunityTerms(
                    runtime_profile_sha256="99" * 32,
                    maximum_interval_ms=12000,
                    minimum_validator_ms=24000,
                ),
            }
        )
    )
    series = c.series.model_copy(update={"manifest_sha256": digest(manifest)})
    reader = StandingRewardControlReader(
        tmp_path / "opportunity-reader",
        series,
        c.policy,
        expected_series_sha256=digest(series),
        expected_chain_config_sha256=c.reader.chain_config_sha256,
        maximum_bytes=8 * 1024**2,
    )
    activation = RewardActivation(
        cohort_sha256=digest(series.cohorts[0]),
        allocation_sha256="01" * 32,
        package_sha256="02" * 32,
        recovery_tip_sha256="03" * 32,
        prior_opportunity_sha256="04" * 32,
    )
    rule = opportunity_rule(manifest, series, c.policy)
    certificate = RewardOpportunityCertificate(
        schema="umi-reward-opportunity-certificate/1",
        series_sha256=digest(series),
        manifest_sha256=digest(manifest),
        rule_sha256=digest(rule),
        activation_sha256=digest(activation),
        contributions=tuple(
            RewardOpportunityContribution(
                validator_account_id=identity(k),
                witness_sha256=f"{i + 20:02x}" * 32,
                credited_ms=24000,
                through_block=10000,
            )
            for i, k in enumerate(series.validators)
        ),
    )
    return SimpleNamespace(
        manifest=manifest,
        series=series,
        reader=reader,
        policy=c.policy,
        activation=activation,
        certificate=certificate,
        terms=dict(manifest=manifest, series=series, policy=c.policy, activation=activation),
    )


def test_terms_are_explicit_and_bound_before_admission(opportunity_case, manifest_case):
    c = opportunity_case
    assert (
        verify_reward_manifest(canonical_json_bytes(c.manifest), c.series, c.policy) == c.manifest
    )
    with pytest.raises(ValueError, match="no approved opportunity terms"):
        opportunity_rule(manifest_case.manifest, manifest_case.series, manifest_case.policy)
    for field, value in [("minimum_validator_ms", 0), ("maximum_interval_ms", True)]:
        changed = c.manifest.model_copy(
            update={"opportunity": c.manifest.opportunity.model_copy(update={field: value})}
        )
        with pytest.raises(ValueError):
            verify_reward_manifest(canonical_json_bytes(changed), c.series, c.policy)
    changed = c.manifest.model_copy(
        update={
            "opportunity": c.manifest.opportunity.model_copy(update={"minimum_validator_ms": 12000})
        }
    )
    with pytest.raises(ValueError, match="differs from the selected series"):
        verify_reward_manifest(canonical_json_bytes(changed), c.series, c.policy)


@pytest.mark.parametrize(
    "change",
    [
        "missing_validator",
        "duplicate_validator",
        "short",
        "wrong_series",
        "wrong_manifest",
        "wrong_rule",
        "wrong_activation",
    ],
)
def test_claim_cannot_skip_a_validator_or_borrow_other_coverage(opportunity_case, change):
    c = opportunity_case
    cert = c.certificate
    if change == "missing_validator":
        cert = cert.model_copy(update={"contributions": cert.contributions[:1]})
    elif change == "duplicate_validator":
        cert = cert.model_copy(update={"contributions": cert.contributions[:1] * 2})
    elif change == "short":
        cert = cert.model_copy(
            update={
                "contributions": (
                    cert.contributions[0].model_copy(update={"credited_ms": 23999}),
                    *cert.contributions[1:],
                )
            }
        )
    else:
        field = change.removeprefix("wrong_") + "_sha256"
        cert = cert.model_copy(update={field: "ff" * 32})
    with pytest.raises(ValueError):
        check_opportunity_claim(cert, **c.terms)
    assert check_opportunity_claim(c.certificate, **c.terms)


def test_witness_rejects_duplicate_interval_ids():
    with pytest.raises(ValueError, match="repeats an interval"):
        RewardOpportunityWitness(
            schema="umi-reward-opportunity-witness/1",
            rule_sha256="01" * 32,
            activation_sha256="02" * 32,
            validator_account_id="03" * 32,
            interval_keys=("04" * 32,) * 2,
        )


def handoff(c, *, through=10000, prior_sha=None):
    previous = RewardControlDecision(
        schema="umi-reward-control-decision/1",
        series_sha256=digest(c.series),
        sequence=1,
        predecessor_sha256="ee" * 32,
        kind="activate",
        observed_at_block=200,
        activation=c.activation,
    )
    current = RewardControlDecision(
        schema="umi-reward-control-decision/1",
        series_sha256=digest(c.series),
        sequence=2,
        predecessor_sha256=digest(previous),
        kind="activate",
        observed_at_block=through,
        activation=c.activation.model_copy(
            update={
                "cohort_sha256": digest(c.series.cohorts[1]),
                "prior_opportunity_sha256": prior_sha or digest(c.certificate),
            }
        ),
    )
    c.reader.journal.put("reward_control_decision", "0001", signed(previous))
    c.reader.journal.put("reward_control_decision", "0002", signed(current))
    # This fixture supplies a static prefix, not a native chain history. It
    # tests only binding after the caller's separately required native review.
    return StandingRewardSelection(
        digest(c.series), digest(current), 2, "selected", through, through + 160, current.activation
    )


def test_handoff_requires_process_native_result_and_immutable_exact_predecessor(opportunity_case):
    c = opportunity_case
    selection = handoff(c)
    args = dict(reader=c.reader, manifest=c.manifest, selection=selection)
    for value in (None, VerifiedRewardOpportunity(c.certificate)):
        with pytest.raises(ValueError, match="native replay provenance"):
            require_previous_opportunity(value, **args)
    # Test-only native provenance: full producer/reviewer proof replay is in
    # the complete preparation integration case, not asserted by this fixture.
    checked = _issue_opportunity(c.certificate)
    require_previous_opportunity(checked, **args)
    changed = replace(
        checked, certificate=c.certificate.model_copy(update={"activation_sha256": "ff" * 32})
    )
    with pytest.raises(ValueError, match="native replay provenance"):
        require_previous_opportunity(changed, **args)
    late = replace(selection, committed_at_block=99999999, effective_at_block=100000159)
    require_previous_opportunity(checked, **(args | {"selection": late}))


@pytest.mark.parametrize("change", ["future", "other_certificate"])
def test_handoff_cannot_backdate_evidence_or_change_selected_certificate(opportunity_case, change):
    c = opportunity_case
    selection = handoff(
        c,
        through=9999 if change == "future" else 10000,
        prior_sha="ff" * 32 if change == "other_certificate" else None,
    )
    with pytest.raises(ValueError, match="predecessor, certificate or evidence cutoff"):
        require_previous_opportunity(
            _issue_opportunity(c.certificate),
            reader=c.reader,
            manifest=c.manifest,
            selection=selection,
        )


def test_minimum_certificate_cannot_replace_legacy_first_handoff(opportunity_case):
    c = opportunity_case
    selection = replace(handoff(c), activation=c.activation)
    with pytest.raises(ValueError, match="qualified legacy handoff"):
        require_previous_opportunity(
            _issue_opportunity(c.certificate),
            reader=c.reader,
            manifest=c.manifest,
            selection=selection,
        )


@pytest.mark.parametrize(
    "change", [None, "copy", "other_validator", "old_block", "ended_lease", "other_decision"]
)
def test_first_activation_rechecks_exact_local_handoff(opportunity_case, change):
    c = opportunity_case
    plan = LegacyRewardHandoffPlan(
        schema="umi-legacy-reward-handoff-plan/1",
        series_sha256=digest(c.series),
        cohort_sha256=digest(c.series.cohorts[0]),
        legacy_policy_sha256="11" * 32,
        legacy_round_sha256="12" * 32,
        legacy_package_sha256="13" * 32,
    )
    activation = c.activation.model_copy(update={"prior_opportunity_sha256": digest(plan)})
    first = RewardControlDecision(
        schema="umi-reward-control-decision/1",
        series_sha256=digest(c.series),
        sequence=1,
        predecessor_sha256="ee" * 32,
        kind="activate",
        observed_at_block=200,
        activation=activation,
    )
    c.reader.journal.put("reward_control_decision", "0001", signed(first))
    intent = LegacyRewardHandoffIntent(
        schema="umi-legacy-reward-handoff-intent/1",
        plan=plan,
        activation_sha256=digest(activation),
        installation_receipt_sha256="14" * 32,
        validator_hotkey=c.series.validators[0],
    )
    active = True
    calls = []

    def fence():
        calls.append(True)
        if not active:
            raise ValueError("writer lease ended")

    # Test-only native issuance. Full inventory/lock handling has its own suite.
    value = _issue_legacy_handoff(intent, "15" * 32, 10000, fence)
    selection = StandingRewardSelection(
        digest(c.series), digest(first), 1, "selected", 200, 360, activation
    )
    args = dict(
        reader=c.reader,
        manifest=c.manifest,
        selection=selection,
        validator_hotkey=c.series.validators[0],
        current_block=10001,
    )
    if change == "copy":
        value = VerifiedLegacyRewardHandoff(intent, value.inventory_sha256, 10000)
    elif change == "other_validator":
        args["validator_hotkey"] = c.series.validators[1]
    elif change == "old_block":
        args["current_block"] = 9999
    elif change == "ended_lease":
        active = False
    elif change == "other_decision":
        args["selection"] = replace(selection, decision_sha256="ff" * 32)
    if change:
        with pytest.raises(ValueError):
            require_previous_opportunity(value, **args)
    else:
        require_previous_opportunity(value, **args)
        require_previous_opportunity(value, **(args | {"current_block": 10_000_000}))
        assert len(calls) == 3  # Rechecked on every projection, with no age expiry.


async def test_coverage_scheduler_retries_each_validator_without_expiry(opportunity_case, tmp_path):
    from umi.competition_reward_coverage_collector import RewardCoverageCollector
    from umi.competition_reward_coverage_journal import RewardCoverageJournal
    from umi.competition_reward_coverage_source import CoverageHistoryPending

    c = opportunity_case
    rule = opportunity_rule(c.manifest, c.series, c.policy)
    journal = RewardCoverageJournal(tmp_path / "collector", rule, expected_rule_sha256=digest(rule))
    calls = []
    head = 100

    class Source:
        async def finalized_height(self):
            return head

        async def capture(self, hotkey, height):
            calls.append((hotkey, height))
            if hotkey == c.series.validators[0]:
                raise TimeoutError("sensitive endpoint detail")
            raise CoverageHistoryPending

        async def replay(self, key):
            pytest.fail("empty journal has no replay obligations")

    assert len(c.series.validators) >= 2
    collector = RewardCoverageCollector(
        journal, Source(), **c.terms, first_block=99, capture_window_blocks=2
    )
    for _ in range(4):
        result = await collector.step()
        assert all(total == 0 for _, total in result.credited_ms)
        assert result.certificate is None
    for hotkey in c.series.validators:
        assert calls.count((hotkey, 99)) == 4
    head += 3000  # A ten-hour gap supplies no coverage and does not expire work.
    result = await collector.step()
    assert result.certificate is None
    assert calls[-len(c.series.validators) :] == [(k, head - 1) for k in c.series.validators]
    assert not await journal.interval_keys()


async def test_coverage_service_retries_head_and_stops_without_leaking_errors(
    opportunity_case, tmp_path, caplog
):
    import asyncio

    from umi.competition_reward_coverage_collector import RewardCoverageCollector
    from umi.competition_reward_coverage_journal import RewardCoverageJournal

    c = opportunity_case
    rule = opportunity_rule(c.manifest, c.series, c.policy)
    journal = RewardCoverageJournal(tmp_path / "collector", rule, expected_rule_sha256=digest(rule))
    stop = asyncio.Event()
    calls = 0

    class Source:
        async def finalized_height(self):
            nonlocal calls
            calls += 1
            if calls == 3:
                stop.set()
            raise TimeoutError("https://private-provider/token")

        async def capture(self, *_):
            pytest.fail("unavailable head cannot schedule capture")

        async def replay(self, *_):
            pytest.fail("empty journal cannot schedule replay")

    collector = RewardCoverageCollector(journal, Source(), **c.terms, first_block=99)
    with caplog.at_level("INFO"):
        assert await collector.run(stop, poll_seconds=0.001) is None
    assert calls == 3
    assert "coverage_pending" in caplog.text
    assert "TimeoutError" in caplog.text
    assert "private-provider" not in caplog.text
    for invalid in (0, float("nan"), float("inf"), 3601):
        with pytest.raises(ValueError, match="poll interval"):
            await collector.run(stop, poll_seconds=invalid)
