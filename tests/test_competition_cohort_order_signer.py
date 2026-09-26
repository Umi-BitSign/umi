"""Native selection/signing recovery with real journals and synthetic finality."""

import asyncio
from types import SimpleNamespace

import pytest

from umi.competition_chain import RegistrationCapture
from umi.competition_cohort_intake import CohortIntakeBinding, history_tip
from umi.competition_cohort_order_signer import (
    CohortOrderHistory,
    CohortOrderJournal,
    CohortOrderParticipant,
    CohortOrderSigner,
    CohortOrderSignerConfig,
    certify_order_votes,
    order_slot,
)
from umi.competition_cohort_orders import verify_recoverable_order
from umi.open_competition import digest, sign_object
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_consumers import transition
from .test_competition_cohort_disposition import order as signed_order
from .test_competition_cohort_execution import setup_scenario
from .test_competition_cohort_roster import base_policy as base_policy
from .test_competition_cohort_roster import legacy_scenario as legacy_scenario
from .test_competition_cohort_roster import make_round
from .test_competition_cohort_roster import policy as policy
from .test_competition_cohort_roster import receipt_scenario as receipt_scenario
from .test_competition_cohort_roster import recovery as recovery
from .test_competition_cohort_roster import runtime as runtime
from .test_open_competition import snapshot, wallet


@pytest.fixture(params=["paired_model", "endpoint_incumbent"])
def scenario(receipt_scenario, tmp_path, runtime, request):
    return setup_scenario(receipt_scenario, tmp_path, runtime, mode=request.param)


def source_for(b, history):
    keys = sorted(
        {
            t.transition.evidence_sha256
            for t in history.transitions
            if t.transition.operation != "revoke"
        }
    )
    return CohortOrderHistory(history=history, decisions=tuple(b["decisions"][k] for k in keys))


@pytest.fixture
def harness(scenario, tmp_path):
    # Selection precedes responses, so no completed model/endpoint result is built.
    b = make_round(scenario, include_outcomes=False)
    full = b["history"]
    index = next(i for i, t in enumerate(full.transitions) if t.transition.phase == "requests")
    h = SimpleNamespace(
        batch=b,
        source=source_for(b, full.model_copy(update={"transitions": full.transitions[:index]})),
        block=400,
        fail=False,
        fail_collect=False,
        calls=[],
        reads=0,
    )
    selected = signed_order(b["scenarios"][0]).order
    p = b["roster"].participants[0]
    h.order = selected
    h.participant = CohortOrderParticipant(
        consent=p.record.request.consent,
        admission=p.admission,
        admission_snapshot=p.record.snapshot,
    )

    async def current(cohort):
        assert cohort == selected.round.cohort_sha256
        h.reads += 1
        return h.source

    async def collect():
        if h.fail_collect:
            raise OSError("provider unavailable")
        snap = snapshot(h.block)
        return RegistrationCapture(
            snap,
            {
                "schema": "umi-competition-registration-provenance/1",
                "evidence_class": "verifier_attested_finality",
                "offline_finality_proof": False,
                "chain_submission_authorized": False,
                "snapshot_sha256": digest(snap),
                "block": snap.block,
                "block_hash": snap.block_hash,
                "state_root": "0x" + "aa" * 32,
                "evidence_sha256": "bb" * 32,
            },
        )

    def worker(name="Charlie", **overrides):
        cfg = CohortOrderSignerConfig(
            schema="umi-cohort-order-signer-config/1",
            directory=str(tmp_path / name),
            policy_sha256=digest(b["policy"]),
            signer=wallet(name).hotkey.ss58_address,
            cohorts=(
                CohortIntakeBinding(
                    cohort_sha256=digest(full.plan),
                    authority_sha256=digest(full.authority.authority),
                ),
            ),
            **overrides,
        )
        journal = CohortOrderJournal(cfg, b["policy"])

        async def sign(body):
            intent, vote = journal.load(order_slot(body))
            assert intent.order == body and vote is None
            assert journal.journal.reservation(order_slot(body)) is not None
            h.calls.append((name, canonical_json_bytes(body)))
            if h.fail:
                raise OSError("signature acknowledgement lost")
            return sign_object(body, wallet(name))

        return CohortOrderSigner(
            journal, SimpleNamespace(collect=collect, policy=b["policy"]), current, sign
        )

    h.worker = worker
    return h


async def test_native_quorum_uses_retained_selections(harness):
    h = harness
    votes = [await h.worker(n).attest(h.order, h.participant) for n in ("Charlie", "Dave")]
    certificate = certify_order_votes(h.order, votes, h.batch["policy"])
    assert (
        verify_recoverable_order(
            certificate,
            h.batch["policy"],
            h.participant.consent,
            h.participant.admission,
            h.participant.admission_snapshot,
            h.source.history,
            expected_tip_sha256=history_tip(h.source.history),
            current_block=h.block,
        )
        == certificate
    )
    for bad in (votes[:1], [votes[0], votes[0]]):
        with pytest.raises(ValueError):
            certify_order_votes(h.order, bad, h.batch["policy"])


async def test_repeated_long_outages_recover_identical_selection_without_renewals(harness):
    h = harness
    slot = order_slot(h.order)
    h.fail = True
    for block in (400, 400 + 3000, 400 + 6000, 10**6):
        h.block = block
        with pytest.raises(OSError):
            await h.worker().attest(h.order, h.participant)
        saved = h.worker().journal.load(slot)[0]
        assert saved.observation.block == 400
    assert len({body for _, body in h.calls}) == 1
    h.fail = False
    vote = await h.worker().recover(slot)
    h.fail_collect = True
    h.source = source_for(h.batch, h.batch["history"])
    assert await h.worker().recover(slot) == vote
    assert len(h.calls) == 5


@pytest.mark.parametrize("damage", ["evaluators", "case", "participant"])
async def test_restart_cannot_replace_reserved_inputs(harness, damage):
    h = harness
    h.fail = True
    with pytest.raises(OSError):
        await h.worker().attest(h.order, h.participant)
    order, participant = h.order, h.participant
    if damage == "evaluators":
        order = order.model_copy(update={"evaluators": tuple(reversed(order.evaluators))})
    elif damage == "case":
        cases = (order.cases[0].model_copy(update={"video_sha256": "ff" * 32}), *order.cases[1:])
        order = order.model_copy(update={"cases": cases})
    else:
        participant = participant.model_copy(update={"admission_snapshot": snapshot(211)})
    h.fail = False
    with pytest.raises(ValueError, match="reserved"):
        await h.worker().attest(order, participant)
    assert len(h.calls) == 1
    await h.worker().recover(order_slot(h.order))


@pytest.mark.parametrize("phase", ["closed", "revealed", "revoked"])
async def test_new_signatures_stop_at_closed_or_revoked_history(harness, phase):
    h = harness
    h.fail = True
    with pytest.raises(OSError):
        await h.worker().attest(h.order, h.participant)
    full = h.batch["history"]
    h.block = 5000
    if phase == "closed":
        history = full.model_copy(update={"transitions": full.transitions[:-1]})
    elif phase == "revealed":
        history = full
    else:
        history = transition(h.source.history, h.batch["policy"], "revoke", 500)
    h.source = source_for(h.batch, history)
    h.fail = False
    with pytest.raises(ValueError, match="open request"):
        await h.worker().recover(order_slot(h.order))
    assert len(h.calls) == 1 and h.worker().journal.load(order_slot(h.order))[1] is None
    # Even a separately valid old prefix is rejected after restart.
    h.source = source_for(h.batch, full.model_copy(update={"transitions": full.transitions[:2]}))
    with pytest.raises(ValueError, match="rolled back"):
        await h.worker().recover(order_slot(h.order))


async def test_history_change_during_review_keeps_original_intent_and_fences_old_source(harness):
    h = harness
    worker = h.worker()
    original = worker.history
    calls = 0

    async def changing(cohort):
        nonlocal calls
        calls += 1
        if calls == 2:
            h.block = 5000
            return source_for(h.batch, h.batch["history"])
        return await original(cohort)

    worker.history = changing
    with pytest.raises(OSError, match="history changed"):
        await worker.attest(h.order, h.participant)
    assert not h.calls
    assert worker.journal.load(order_slot(h.order))[0].order == h.order
    with pytest.raises(ValueError, match="rolled back"):
        await h.worker().recover(order_slot(h.order))


@pytest.mark.parametrize(
    "damage", ["missing_decision", "wrong_decision", "preparation", "signature"]
)
async def test_unauthenticated_or_wrong_preparation_never_reserves_or_signs(harness, damage):
    h = harness
    if damage == "missing_decision":
        h.source = h.source.model_copy(update={"decisions": h.source.decisions[1:]})
    elif damage == "wrong_decision":
        d = h.source.decisions[0]
        p = d.progress.progress.model_copy(update={"phase_result_sha256": "ff" * 32})
        h.source = h.source.model_copy(
            update={
                "decisions": (
                    d.model_copy(
                        update={"progress": d.progress.model_copy(update={"progress": p})}
                    ),
                    *h.source.decisions[1:],
                )
            }
        )
    elif damage == "preparation":
        h.order = h.order.model_copy(
            update={"round": h.order.round.model_copy(update={"suite_sha256": "ff" * 32})}
        )
    else:
        a = h.participant.admission
        h.participant = h.participant.model_copy(
            update={
                "admission": a.model_copy(update={"signatures": (a.signatures[0], a.signatures[0])})
            }
        )
    worker = h.worker()
    with pytest.raises(ValueError):
        await worker.attest(h.order, h.participant)
    assert not h.calls and worker.journal.load(order_slot(h.order)) is None


async def test_capacity_failure_is_retryable_after_configuration_increase(harness):
    h = harness
    with pytest.raises(ValueError, match="capacity"):
        await h.worker(maximum_bytes=1024).attest(h.order, h.participant)
    assert not h.calls
    assert await h.worker(maximum_bytes=1024**3).attest(h.order, h.participant)


async def test_lost_commit_acknowledgement_returns_exact_original_vote(harness, monkeypatch):
    h = harness
    worker = h.worker()
    original = worker.journal.commit

    def lost(slot, vote):
        original(slot, vote)
        raise OSError("commit reply lost")

    monkeypatch.setattr(worker.journal, "commit", lost)
    with pytest.raises(OSError):
        await worker.attest(h.order, h.participant)
    saved = worker.journal.load(order_slot(h.order))[1]
    h.fail_collect = True
    assert await h.worker().recover(order_slot(h.order)) == saved
    assert len(h.calls) == 1


async def test_cancellation_drains_signing_before_unlocking(harness):
    h = harness
    worker = h.worker()
    entered = asyncio.Event()
    release = asyncio.Event()

    async def sign(body):
        entered.set()
        try:
            await asyncio.Future()
        except asyncio.CancelledError:
            await release.wait()
        return sign_object(body, wallet("Charlie"))

    worker.sign = sign
    task = asyncio.create_task(worker.attest(h.order, h.participant))
    await asyncio.wait_for(entered.wait(), 5)
    task.cancel()
    await asyncio.sleep(0)
    with pytest.raises(BlockingIOError), h.worker().journal.journal.locked():
        pass
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    # The completed signature is committed while the task still owns its lock.
    saved = worker.journal.load(order_slot(h.order))[1]
    assert saved is not None
    assert await h.worker().recover(order_slot(h.order)) == saved


async def test_separate_instances_serialize_one_selection(harness):
    h = harness
    first = h.worker()
    second = h.worker()
    entered = asyncio.Event()
    release = asyncio.Event()
    original = first.sign

    async def delayed(body):
        entered.set()
        await release.wait()
        return await original(body)

    first.sign = delayed
    task = asyncio.create_task(first.attest(h.order, h.participant))
    await asyncio.wait_for(entered.wait(), 5)
    try:
        with pytest.raises(BlockingIOError):
            await second.attest(h.order, h.participant)
    finally:
        release.set()
    vote = await task
    assert await second.attest(h.order, h.participant) == vote
    assert len(h.calls) == 1


async def test_owned_finality_cannot_roll_back_between_retries(harness):
    h = harness
    h.fail = True
    h.block = 5000
    with pytest.raises(OSError):
        await h.worker().attest(h.order, h.participant)
    h.block = 400
    h.fail = False
    with pytest.raises(ValueError, match="finalized head regressed"):
        await h.worker().recover(order_slot(h.order))
    assert len(h.calls) == 1


async def test_partial_quorum_retains_each_signers_original_vote(harness):
    h = harness
    first = await h.worker("Charlie").attest(h.order, h.participant)
    h.fail = True
    with pytest.raises(OSError):
        await h.worker("Dave").attest(h.order, h.participant)
    h.block = 10**6
    h.fail = False
    recovered = [await h.worker(n).recover(order_slot(h.order)) for n in ("Charlie", "Dave")]
    assert recovered[0] == first
    certified = certify_order_votes(h.order, recovered, h.batch["policy"])
    assert certified.order == h.order
    assert [name for name, _ in h.calls] == ["Charlie", "Dave", "Dave"]


async def test_attempt_timeout_keeps_selection_for_a_late_retry(harness):
    h = harness
    worker = h.worker(signing_timeout_seconds=1)

    async def slow(body):
        await asyncio.Future()

    worker.sign = slow
    with pytest.raises(TimeoutError):
        await worker.attest(h.order, h.participant)
    saved = worker.journal.load(order_slot(h.order))[0]
    h.block = 10**6
    vote = await h.worker().recover(order_slot(h.order))
    assert worker.journal.load(order_slot(h.order))[0] == saved
    assert vote.order_sha256 == digest(h.order)


async def test_result_allowance_recovers_after_intent_write_interruption(harness, monkeypatch):
    h = harness
    worker = h.worker()
    original = worker.journal.journal.put

    def fail(kind, key, value):
        if kind == "intent":
            raise OSError("disk write interrupted")
        return original(kind, key, value)

    monkeypatch.setattr(worker.journal.journal, "put", fail)
    with pytest.raises(OSError):
        await worker.attest(h.order, h.participant)
    assert not h.calls and worker.journal.load(order_slot(h.order)) is None
    assert worker.journal.journal.reservation(order_slot(h.order)) is not None
    h.block = 5000
    assert await h.worker().attest(h.order, h.participant)


async def test_wrong_policy_provider_cannot_be_used(harness):
    worker = harness.worker()
    provider = SimpleNamespace(policy=worker.provider.policy.model_copy(update={"netuid": 1}))
    with pytest.raises(ValueError, match="finality belongs"):
        CohortOrderSigner(worker.journal, provider, worker.history, worker.sign)
