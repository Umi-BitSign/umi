"""Native series/history verification with synthetic finalized-clock captures."""

import asyncio
import shutil
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
from umi.competition_reward_decisions import StandingRewardSeries
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
        cfg = RequestStartConfig(
            schema="umi-cohort-request-start-config/1",
            directory=str(root),
            first_cohort_not_before_unix_ms=1_000_000,
            **changes,
        )
        return SeriesRequestStart(cfg, series, provider, history)

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
