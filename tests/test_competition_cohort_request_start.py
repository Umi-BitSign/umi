"""Native series/history verification with synthetic finalized-clock captures."""

import asyncio
import json
import shutil
import sqlite3
from types import SimpleNamespace

import pytest

from umi.competition_chain import RegistrationCapture
from umi.competition_cohort_coordinator import (
    AttestedCohortPhaseProgress,
    CohortDecisionInput,
    CohortPhaseProgress,
)
from umi.competition_cohort_history import CohortRecoveryHistory
from umi.competition_cohort_order_signer import CohortOrderHistory
from umi.competition_cohort_recovery import (
    SignedCohortRecoveryAuthority,
    StandingCohortRecoveryAuthority,
    admit_recoverable_cohort,
    apply_recovery_transition,
    propose_recovery_transition,
)
from umi.competition_cohort_request_start import REST_MS, RequestStartConfig, SeriesRequestStart
from umi.competition_execution import execution_boundary
from umi.competition_reward_decisions import (
    StandingRewardSeries,
    StandingRewardSeriesPredecessor,
)
from umi.grandpa_finality import FINNEY_GENESIS_HASH
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_recovery import recovery as recovery
from .test_competition_cohort_recovery import signatures, signed_transition
from .test_open_competition import policy as policy
from .test_open_competition import snapshot, wallet


@pytest.fixture
def rest(recovery, policy, tmp_path):
    plan = recovery[0]
    plans = tuple(plan.model_copy(update={"sequence": n}) for n in range(5, 11))
    body = StandingCohortRecoveryAuthority(
        schema="umi-cohort-recovery-authority/2",
        policy_sha256=digest(policy),
        cohort_sha256s=tuple(sorted(digest(p) for p in plans)),
        issued_at_block=150,
        lifetime="until_completed_or_revoked",
        closure_rule="quorum_certified_phase_completion",
        timing_rule="targets_without_extension_signatures",
    )
    authority = SignedCohortRecoveryAuthority(authority=body, signatures=signatures(body))
    series = StandingRewardSeries(
        schema="umi-standing-reward-series/1",
        genesis_hash=FINNEY_GENESIS_HASH,
        netuid=78,
        policy_sha256=digest(policy),
        policy_epoch=1,
        manifest_sha256="ab" * 32,
        control_hotkey=wallet("Charlie").hotkey.ss58_address,
        recovery=authority,
        cohorts=plans,
        validators=(wallet("Charlie").hotkey.ss58_address,),
        maximum_proof_lag_blocks=32,
        maximum_transaction_lifetime_blocks=128,
        lifetime="until_superseded_or_revoked",
    )
    h = SimpleNamespace(
        series=series,
        policy=policy,
        block=1000,
        timestamp=1_000_000,
        offline=False,
        histories={},
        captures=0,
    )

    def capture(block):
        s = snapshot(block)
        return RegistrationCapture(
            s,
            {
                "schema": "umi-competition-registration-provenance/1",
                "evidence_class": "verifier_attested_finality",
                "offline_finality_proof": False,
                "chain_submission_authorized": False,
                "block": block,
                "block_hash": s.block_hash,
                "state_root": "0x" + "aa" * 32,
                "snapshot_sha256": digest(s),
                "evidence_sha256": "bb" * 32,
                "timestamp_ms": h.timestamp,
            },
        )

    class Provider:
        config = SimpleNamespace(maximum_head_age_ms=120_000, maximum_future_skew_ms=30_000)

        async def collect(self):
            h.captures += 1
            if h.offline:
                raise OSError("synthetic finality unavailable")
            return capture(h.block)

    provider = Provider()
    provider.policy = policy

    async def history(cohort):
        if cohort not in h.histories:
            raise FileNotFoundError("predecessor delivery pending")
        return h.histories[cohort]

    def closed(index=0, phases=("intake", "preparation", "requests")):
        p = plans[index]
        genesis, state = admit_recoverable_cohort(p, authority, policy, admitted_at_block=160)
        transitions = []
        decisions = []
        for n, phase in enumerate(phases):
            assert state.phase == phase
            block = 300 + 90 * n
            progress = CohortPhaseProgress(
                schema="umi-cohort-phase-progress/1",
                cohort_sha256=digest(p),
                recovery_tip_sha256=state.tip_sha256,
                phase=phase,
                observed_at_block=block,
                unavailable_blocks=0,
                completion="complete",
                phase_result_sha256="c1" * 32,
                evidence_sha256="c2" * 32,
            )
            evidence = CohortDecisionInput(
                schema="umi-cohort-decision-input/1",
                progress=AttestedCohortPhaseProgress(
                    progress=progress, signatures=signatures(progress)
                ),
                observation=execution_boundary(capture(block)),
            )
            proposal = propose_recovery_transition(
                state,
                body,
                operation="close_phase",
                observed_at_block=block,
                evidence_sha256=digest(evidence),
            )
            signed = signed_transition(proposal)
            state = apply_recovery_transition(state, signed, authority, policy)
            transitions.append(signed)
            decisions.append(evidence)
        value = CohortOrderHistory(
            history=CohortRecoveryHistory(
                schema="umi-cohort-recovery-history/1",
                plan=p,
                authority=authority,
                genesis=genesis,
                genesis_signatures=signatures(genesis),
                transitions=tuple(transitions),
            ),
            decisions=tuple(decisions),
        )
        h.histories[digest(p)] = value
        return value

    def reopen(root=tmp_path / "rest", **changes):
        selection = changes.pop("operator_selection", None)
        cfg = RequestStartConfig(
            schema="umi-cohort-request-start-config/1",
            directory=str(root),
            first_cohort_not_before_unix_ms=1_000_000,
            **changes,
        )
        return SeriesRequestStart(cfg, series, provider, history, operator_selection=selection)

    h.closed, h.reopen, h.capture, h.provider = closed, reopen, capture, provider
    h.gate = reopen()
    return h


async def test_first_cohort_respects_approved_start_floor_and_freshness(rest):
    h = rest
    key = digest(h.series.cohorts[0])
    assert not (await h.gate.check(key))["ready"]
    h.timestamp += h.gate.future_skew
    assert (await h.gate.check(key))["ready"]
    h.offline = True
    with pytest.raises(OSError, match="finality"):
        await h.gate.check(key)


def operator_start(rest):
    current = rest.closed(index=1, phases=("intake",))
    key = digest(current.history.plan)
    selected = {
        "baseline_model_sha256": "ad" * 32,
        "evaluation_runtime_sha256": rest.policy.evaluation_runtime_sha256,
        "runtime_adoption_sha256": None,
    }

    async def selection(cohort, block):
        assert cohort == key and block == rest.block
        return dict(selected)

    override = dict(
        schema="umi-cohort-operator-request-start/1",
        cohort_sha256=key,
        authorized_history_tip_sha256=digest(current.history.genesis),
        suite_sha256=current.history.plan.suite_sha256,
        **selected,
        not_before_unix_ms=rest.timestamp + 60_000,
        source_sha256="ca" * 32,
    )
    return key, override, selected, selection


async def test_operator_start_uses_exact_deadline_and_preserves_rest_across_restart(rest):
    h = rest
    key, override, _, selection = operator_start(h)
    # An operator clock never supplies the preceding cohort's closure.
    gate = h.reopen(operator_start_overrides=(override,), operator_selection=selection)
    assert (await gate.check(key))["status"] == "waiting_predecessor_requests"
    h.closed()
    legacy = await h.gate.check(key)
    saved = canonical_json_bytes(h.gate.journal.get("request_rest", key))
    result = await gate.check(key)
    assert not result["ready"] and result["eta_seconds"] == 90
    assert result["not_before_unix_ms"] == override["not_before_unix_ms"]
    h.timestamp = override["not_before_unix_ms"] + gate.future_skew - 1
    h.block += 1
    gate = h.reopen(operator_start_overrides=(override,), operator_selection=selection)
    assert not (await gate.check(key))["ready"]
    h.timestamp += 1
    ready = await gate.check(key)
    assert ready["ready"] and ready["percent"] == 100
    assert ready["operator_start_source_sha256"] == override["source_sha256"]
    assert ready["cutover_unix_ms"] is None
    assert legacy["not_before_unix_ms"] > ready["not_before_unix_ms"]
    assert canonical_json_bytes(gate.journal.get("request_rest", key)) == saved
    changed = dict(override, not_before_unix_ms=override["not_before_unix_ms"] + 1)
    with pytest.raises(ValueError, match="operator request start changed"):
        await h.reopen(operator_start_overrides=(changed,), operator_selection=selection).check(key)


@pytest.mark.parametrize(
    "changed",
    [
        "baseline_model_sha256",
        "evaluation_runtime_sha256",
        "runtime_adoption_sha256",
        "suite_sha256",
        "authorized_history_tip_sha256",
    ],
)
async def test_operator_start_refuses_changed_native_selection(rest, changed):
    h = rest
    h.closed()
    key, override, selection, reader = operator_start(h)
    if changed in selection:
        selection[changed] = "ef" * 32
    else:
        override[changed] = "ef" * 32
    gate = h.reopen(operator_start_overrides=(override,), operator_selection=reader)
    with pytest.raises(ValueError, match="operator request start"):
        await gate.check(key)
    assert gate.journal.get("operator_request_start", key) is None


def test_operator_start_optional_configuration_preserves_legacy_bytes(rest):
    before = canonical_json_bytes(rest.gate.config)
    assert b"operator_start_overrides" not in before
    assert canonical_json_bytes(RequestStartConfig.model_validate_json(before)) == before
    _, override, _, selection = operator_start(rest)
    with pytest.raises(ValueError, match="unique cohort ordering"):
        rest.reopen(operator_start_overrides=(override, override), operator_selection=selection)


async def test_target_or_partial_history_cannot_start_rest(rest):
    h = rest
    key = digest(h.series.cohorts[1])
    assert (await h.gate.check(key))["status"] == "waiting_predecessor_requests"
    h.closed(phases=("intake", "preparation"))
    h.timestamp += 10 * 60 * 60 * 1000
    assert not (await h.gate.check(key))["ready"]
    assert h.gate.journal.get("request_rest", key) is None
    assert h.captures == 0


async def test_late_certification_restart_and_migration_keep_exact_rest(rest, tmp_path):
    h = rest
    h.closed()
    key = digest(h.series.cohorts[1])
    # The certified progress's observation is old. Start from actual discovery.
    h.timestamp += 10 * 60 * 60 * 1000
    result = await h.gate.check(key)
    expected = h.timestamp + h.gate.head_age + REST_MS
    assert result["not_before_unix_ms"] == expected and not result["ready"]
    saved = canonical_json_bytes(h.gate.journal.get("request_rest", key))
    h.gate = h.reopen()
    h.timestamp = expected + h.gate.future_skew - 1
    h.block += 1
    assert not (await h.gate.check(key))["ready"]
    h.timestamp += 1
    assert (await h.gate.check(key))["ready"]
    target = tmp_path / "migrated"
    shutil.copytree(h.gate.journal.root, target)
    h.gate = h.reopen(target)
    h.timestamp += 10 * 60 * 60 * 1000
    h.block += 1
    assert (await h.gate.check(key))["ready"]
    assert canonical_json_bytes(h.gate.journal.get("request_rest", key)) == saved


async def test_reviewed_head_age_growth_and_rollback_preserve_rest(rest):
    h = rest
    h.closed()
    key = digest(h.series.cohorts[1])
    await h.gate.check(key)
    saved = canonical_json_bytes(h.gate.journal.get("request_rest", key))

    def binding_head_age():
        with sqlite3.connect(h.gate.journal.path) as db:
            raw = db.execute("SELECT body FROM binding").fetchone()[0]
        return json.loads(raw)["maximum_head_age_ms"]

    assert binding_head_age() == 120_000
    h.provider.config.maximum_head_age_ms = 300_000
    h.gate = h.reopen()
    assert binding_head_age() == 300_000
    h.timestamp += REST_MS + 300_000 + h.gate.future_skew
    h.block += 1
    assert (await h.gate.check(key))["ready"]
    assert canonical_json_bytes(h.gate.journal.get("request_rest", key)) == saved

    h.provider.config.maximum_head_age_ms = 120_000
    h.gate = h.reopen()
    assert binding_head_age() == 120_000
    assert (await h.gate.check(key))["ready"]
    assert canonical_json_bytes(h.gate.journal.get("request_rest", key)) == saved


def test_unreviewed_head_age_change_remains_rejected(rest):
    rest.provider.config.maximum_head_age_ms = 60_000
    with pytest.raises(ValueError, match="round journal configuration changed"):
        rest.reopen()


def test_head_age_migration_does_not_admit_another_binding_change(rest):
    rest.provider.config.maximum_head_age_ms = 300_000
    rest.provider.config.maximum_future_skew_ms = 60_000
    with pytest.raises(ValueError, match="round journal configuration changed"):
        rest.reopen()


async def test_lost_ack_and_concurrent_checks_never_restart_the_rest(rest, monkeypatch):
    h = rest
    h.closed()
    key = digest(h.series.cohorts[1])
    original = h.gate.journal.put

    def lost(*args):
        original(*args)
        raise OSError("lost persistence acknowledgement")

    monkeypatch.setattr(h.gate.journal, "put", lost)
    with pytest.raises(OSError, match="acknowledgement"):
        await h.gate.check(key)
    saved = h.gate.journal.get("request_rest", key)
    h.gate = h.reopen()
    h.timestamp += REST_MS + h.gate.head_age + h.gate.future_skew
    h.block += 1
    results = await asyncio.gather(*(h.gate.check(key) for _ in range(3)))
    assert all(r["ready"] for r in results)
    assert h.gate.journal.get("request_rest", key) == saved


@pytest.mark.parametrize("fault", ["signature", "decision", "revoked", "regressed", "timestamp"])
async def test_unverified_or_regressed_inputs_cannot_open_requests(rest, fault):
    h = rest
    source = h.closed()
    key = digest(h.series.cohorts[1])
    await h.gate.check(key)
    if fault == "signature":
        t = source.history.transitions[-1]
        t = t.model_copy(update={"signatures": signatures(t.transition, ("Alice",))})
        h.histories[digest(source.history.plan)] = source.model_copy(
            update={
                "history": source.history.model_copy(
                    update={"transitions": (*source.history.transitions[:-1], t)}
                )
            }
        )
    elif fault == "decision":
        h.histories[digest(source.history.plan)] = source.model_copy(
            update={"decisions": source.decisions[:-1]}
        )
    elif fault == "revoked":
        from umi.competition_cohort_coordinator import replay_cohort_decisions

        state, _, _ = replay_cohort_decisions(source.history, h.policy, source.inputs().__getitem__)
        t = propose_recovery_transition(
            state,
            h.series.recovery.authority,
            operation="revoke",
            observed_at_block=500,
            evidence_sha256="ab" * 32,
        )
        h.histories[digest(source.history.plan)] = source.model_copy(
            update={
                "history": source.history.model_copy(
                    update={"transitions": (*source.history.transitions, signed_transition(t))}
                )
            }
        )
    elif fault == "regressed":
        h.block -= 1
    else:
        h.timestamp = None
    with pytest.raises((ValueError, KeyError)):
        await h.gate.check(key)


async def test_six_cohorts_keep_separate_rest_after_repeated_long_outages(rest):
    h = rest
    h.timestamp += h.gate.future_skew
    assert (await h.gate.check(digest(h.series.cohorts[0])))["ready"]
    starts = []
    for index in range(1, len(h.series.cohorts)):
        key = digest(h.series.cohorts[index])
        h.closed(index - 1)
        h.offline = True
        h.timestamp += 10 * 60 * 60 * 1000
        h.block += 3000
        with pytest.raises(OSError):
            await h.gate.check(key)
        assert h.gate.journal.get("request_rest", key) is None
        h.offline = False
        wait = await h.gate.check(key)
        assert not wait["ready"]
        starts.append(wait["not_before_unix_ms"])
        h.timestamp = starts[-1] + h.gate.future_skew
        h.block += 1600
        h.gate = h.reopen()
        assert (await h.gate.check(key))["ready"]
    assert len(set(starts)) == 5
    assert starts == sorted(starts)


def successor_gate(rest, root):
    previous = rest.series
    plans = tuple(
        previous.cohorts[-1].model_copy(
            update={"sequence": sequence, "suite_sha256": f"{sequence:02x}" * 32}
        )
        for sequence in (11, 12)
    )
    authority = StandingCohortRecoveryAuthority(
        schema="umi-cohort-recovery-authority/2",
        policy_sha256=digest(rest.policy),
        cohort_sha256s=tuple(sorted(digest(plan) for plan in plans)),
        issued_at_block=950,
        lifetime="until_completed_or_revoked",
        closure_rule="quorum_certified_phase_completion",
        timing_rule="targets_without_extension_signatures",
    )
    recovery = SignedCohortRecoveryAuthority(authority=authority, signatures=signatures(authority))
    predecessor = StandingRewardSeriesPredecessor(
        schema="umi-standing-reward-series-predecessor/1",
        series_sha256=digest(previous),
        policy_sha256=previous.policy_sha256,
        manifest_sha256=previous.manifest_sha256,
        recovery_sha256=digest(previous.recovery),
        cohort_sha256=digest(previous.cohorts[-1]),
        cohort_sequence=previous.cohorts[-1].sequence,
        control_hotkey=previous.control_hotkey,
        decision_sha256="d1" * 32,
        activation_sha256="d2" * 32,
        decision_committed_at_block=900,
    )
    series = StandingRewardSeries.model_validate_json(
        canonical_json_bytes(
            previous.model_copy(
                update={
                    "schema_": "umi-standing-reward-series/2",
                    "recovery": recovery,
                    "cohorts": plans,
                    "predecessor": predecessor,
                }
            )
        )
    )
    config = RequestStartConfig(
        schema="umi-cohort-request-start-config/2",
        directory=str(root),
        first_cohort_not_before_unix_ms=1,
        predecessor_plan=previous.cohorts[-1],
        predecessor_recovery=previous.recovery,
    )
    return SeriesRequestStart(config, series, rest.provider, rest.gate.history), series


async def test_successor_first_cohort_replays_prior_series_close_and_full_rest(rest, tmp_path):
    gate, series = successor_gate(rest, tmp_path / "successor-rest")
    key = digest(series.cohorts[0])
    rest.timestamp += 20 * 60 * 60 * 1000
    waiting = await gate.check(key)
    assert waiting["status"] == "waiting_predecessor_requests"
    assert gate.journal.get("request_rest", key) is None

    rest.closed(index=len(rest.series.cohorts) - 1)
    started = await gate.check(key)
    expected = rest.timestamp + gate.head_age + REST_MS
    assert not started["ready"] and started["not_before_unix_ms"] == expected
    gate = SeriesRequestStart(gate.config, series, rest.provider, gate.history)
    rest.timestamp = expected + gate.future_skew
    rest.block += 1
    assert (await gate.check(key))["ready"]


def test_successor_request_start_rejects_changed_predecessor_inputs(rest, tmp_path):
    gate, series = successor_gate(rest, tmp_path / "successor-rest-bad")
    changed = gate.config.predecessor_plan.model_copy(update={"suite_sha256": "ff" * 32})
    config = gate.config.model_copy(update={"predecessor_plan": changed})
    with pytest.raises(ValueError, match="predecessor differs"):
        SeriesRequestStart(config, series, rest.provider, gate.history)


async def test_cutover_clock_credits_elapsed_intake_without_rewriting_legacy_timer(rest):
    h = rest
    h.timestamp = 100_000_000
    h.closed()
    cohort = h.gate.cohorts[1]
    assert not (await h.gate.check(cohort))["ready"]
    original = h.gate.journal.get("request_rest", cohort)
    override = dict(
        schema="umi-cohort-cutover-observation/1",
        cohort_sha256=cohort,
        cutover_unix_ms=h.timestamp - 10 * 60 * 60 * 1000,
        source_sha256="ab" * 32,
    )
    gate = h.reopen(rest_clock="cohort_cutover", cutover_overrides=(override,))
    ready = await gate.check(cohort)
    assert ready["ready"] and ready["rest_clock"] == "cohort_cutover"
    assert (
        ready["not_before_unix_ms"]
        == override["cutover_unix_ms"] + REST_MS + h.provider.config.maximum_head_age_ms
    )
    assert gate.journal.get("request_rest", cohort) == original
    again = h.reopen(rest_clock="cohort_cutover", cutover_overrides=(override,))
    assert (await again.check(cohort))["not_before_unix_ms"] == ready["not_before_unix_ms"]
    changed = dict(override, cutover_unix_ms=override["cutover_unix_ms"] + 1)
    with pytest.raises(ValueError, match="conflicts"):
        await h.reopen(rest_clock="cohort_cutover", cutover_overrides=(changed,)).check(cohort)


@pytest.mark.parametrize("cohort_index", range(1, 6))
async def test_automatic_cutover_observation_survives_intake_and_restart(rest, cohort_index):
    h = rest
    cohort = h.gate.cohorts[cohort_index]
    gate = h.reopen(rest_clock="cohort_cutover")
    saved = await gate.observe_cutover(cohort)
    h.timestamp += (
        REST_MS
        + h.provider.config.maximum_head_age_ms
        + h.provider.config.maximum_future_skew_ms
        + 1
    )
    h.block += 100
    h.closed(index=cohort_index - 1)
    again = h.reopen(rest_clock="cohort_cutover")
    result = await again.check(cohort)
    assert result["ready"] and result["cutover_unix_ms"] == saved.cutover_unix_ms
    assert (await again.observe_cutover(cohort)) == saved


async def test_preparation_never_starts_a_late_cutover_timer(rest):
    h = rest
    h.closed()
    gate = h.reopen(rest_clock="cohort_cutover")
    result = await gate.check(gate.cohorts[1])
    assert not result["ready"] and result["status"] == "waiting_cutover_observation"
