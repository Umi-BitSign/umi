"""Owner inventory joins before native closure; no finality or scoring claims."""

from types import SimpleNamespace as NS

import pytest

from umi.competition_chain import RegistrationCapture
from umi.competition_cohort_recovery import PHASES, PhaseTarget, RecoverableCohortPlan
from umi.competition_cohort_request_tail import MINIMUM_REQUEST_OPEN_MS
from umi.competition_cohort_request_tail_owner import select_request_tail
from umi.competition_historical_registration import HistoricalRegistration
from umi.open_competition import Hotkey, digest, identity
from umi.protocol import StrictProtocolModel

from .test_competition_execution import boundary
from .test_open_competition import wallet


class Submission(StrictProtocolModel):
    hotkey: Hotkey
    entry: int


def inventory(
    monkeypatch, *, miners=11, duplicate_entry=False, benchmark_missing=(), paid_missing=()
):
    identities = tuple(wallet(f"tail-owner-{i}").hotkey.ss58_address for i in range(miners))
    submissions = [Submission(hotkey=who, entry=i) for i, who in enumerate(identities)]
    if duplicate_entry:
        submissions.append(Submission(hotkey=identities[0], entry=miners))
    signed = [NS(submission=s) for s in submissions]
    roster = NS(
        participants=tuple(NS(record=NS(request=NS(signed_submission=s))) for s in signed),
        round=object(),
    )
    orders = tuple(NS(order=NS(submission=s, evaluators=("first", "second"))) for s in signed)
    paid = tuple(NS(admission=NS(submission=s, work_sha256=digest(s.submission))) for s in signed)
    monkeypatch.setattr(
        "umi.competition_cohort_request_tail_owner.sealed_service_assignments", lambda *a, **k: paid
    )
    capture = RegistrationCapture(None, {"timestamp_ms": 1000 + MINIMUM_REQUEST_OPEN_MS})
    monkeypatch.setattr(
        "umi.competition_cohort_request_tail_owner.execution_boundary", lambda c: boundary(2000)
    )
    return dict(
        plan=RecoverableCohortPlan(
            schema="umi-recoverable-cohort-plan/1",
            policy_sha256="a1" * 32,
            launch_sha256="a2" * 32,
            sequence=5,
            suite_sha256="a3" * 32,
            not_before_block=200,
            initial_targets=tuple(
                PhaseTarget(phase=p, target_block=300 + 90 * i) for i, p in enumerate(PHASES)
            ),
        ),
        roster=roster,
        orders=orders,
        terminals=lambda order, evaluator: (
            None if order.order.submission.submission.entry in benchmark_missing else object()
        ),
        catalogs=(object(),),
        seals=(object(),),
        service_terminals=lambda assignment: (
            None if assignment.admission.submission.submission.entry in paid_missing else object()
        ),
        objects=None,
        policy=None,
        opened=HistoricalRegistration(None, boundary(1000), NS(block_number=2000), 1000),
        capture=capture,
    )


def test_pending_union_counts_a_miner_once_and_keeps_complete_work(monkeypatch):
    args = inventory(monkeypatch, benchmark_missing=(0,), paid_missing=(0,))
    result = select_request_tail(**args)
    assert len(result.original_hotkeys) == 11
    assert result.unfinished_hotkeys == (identity(wallet("tail-owner-0").hotkey.ss58_address),)
    assert len(args["orders"]) == 11


def test_paid_and_benchmark_together_may_exceed_threshold(monkeypatch):
    args = inventory(monkeypatch, benchmark_missing=(0,), paid_missing=(1,))
    assert select_request_tail(**args) is None


def test_duplicate_entry_cannot_inflate_distinct_miner_denominator(monkeypatch):
    args = inventory(monkeypatch, miners=9, duplicate_entry=True, benchmark_missing=(0,))
    assert select_request_tail(**args) is None


def test_exact_tenth_is_selected_after_original_twelve_hours(monkeypatch):
    args = inventory(monkeypatch, miners=10, benchmark_missing=(0,), paid_missing=(0,))
    result = select_request_tail(**args)
    assert len(result.original_hotkeys) == 10
    assert len(result.unfinished_hotkeys) == 1


def test_retained_corruption_is_not_absence(monkeypatch):
    args = inventory(monkeypatch, benchmark_missing=(0,))

    def broken(order, evaluator):
        if evaluator == "first":
            return None
        raise ValueError("retained signed object is corrupt")

    args["terminals"] = broken
    with pytest.raises(ValueError, match="corrupt"):
        select_request_tail(**args)


def test_clock_uses_original_opening_and_current_completions(monkeypatch):
    args = inventory(monkeypatch, benchmark_missing=(0,))
    args["capture"].provenance["timestamp_ms"] += 7 * 24 * 60 * 60 * 1000
    assert select_request_tail(**args) is not None
    args["terminals"] = lambda *_: object()
    assert select_request_tail(**args).unfinished_hotkeys == ()
    args = inventory(monkeypatch, benchmark_missing=(0,))
    args["capture"].provenance["timestamp_ms"] -= 1
    assert select_request_tail(**args) is None


def test_unselected_paid_miner_cannot_expand_threshold(monkeypatch):
    args = inventory(monkeypatch, benchmark_missing=(0,))
    foreign = NS(
        admission=NS(
            submission=NS(
                submission=Submission(
                    hotkey=wallet("foreign-tail-owner").hotkey.ss58_address, entry=100
                )
            )
        )
    )
    monkeypatch.setattr(
        "umi.competition_cohort_request_tail_owner.sealed_service_assignments",
        lambda *a, **k: (foreign,),
    )
    with pytest.raises(ValueError, match="outside"):
        select_request_tail(**args)


def hard_tail(args, *, sequence=6):
    args["plan"] = RecoverableCohortPlan.model_validate(
        args["plan"].model_dump(by_alias=True)
        | {
            "schema": "umi-recoverable-cohort-plan/4",
            "sequence": sequence,
            "eligible_tracks": ("endpoint",),
            "service_pool_bps": 10000,
            "request_tail_rule": "original_request_12h_with_completed_miner/1",
        }
    )
    return args


@pytest.mark.parametrize("sequence", [6, 7, 11, 2**32 - 1])
def test_hard_tail_waits_for_one_original_miner_without_restarting_clock(monkeypatch, sequence):
    args = hard_tail(
        inventory(monkeypatch, miners=10, benchmark_missing=tuple(range(10))), sequence=sequence
    )
    args["capture"].provenance["timestamp_ms"] += 36_000_000
    assert select_request_tail(**args) is None
    args["terminals"] = lambda order, evaluator: (
        object() if order.order.submission.submission.entry == 0 else None
    )
    result = select_request_tail(**args)
    assert len(result.unfinished_hotkeys) == 9
    assert result.opened_timestamp_ms == 1000
    assert result.observed_timestamp_ms == 1000 + MINIMUM_REQUEST_OPEN_MS + 36_000_000
    assert result.rule == "original_request_12h_with_completed_miner/1"


def test_one_complete_entry_cannot_hide_the_same_miners_other_obligations(monkeypatch):
    args = hard_tail(
        inventory(
            monkeypatch, miners=10, duplicate_entry=True, benchmark_missing=tuple(range(1, 11))
        )
    )
    assert select_request_tail(**args) is None
    args["terminals"] = lambda order, evaluator: (
        object() if order.order.submission.submission.entry in (0, 10) else None
    )
    assert len(select_request_tail(**args).unfinished_hotkeys) == 9


def test_paid_and_benchmark_union_must_leave_one_original_miner_complete(monkeypatch):
    args = hard_tail(inventory(monkeypatch, miners=10, paid_missing=tuple(range(10))))
    assert select_request_tail(**args) is None
    args["service_terminals"] = lambda assignment: (
        object() if assignment.admission.submission.submission.entry == 0 else None
    )
    assert len(select_request_tail(**args).unfinished_hotkeys) == 9


def test_new_rule_uses_exact_original_twelve_hour_boundary(monkeypatch):
    args = hard_tail(inventory(monkeypatch, miners=10, benchmark_missing=tuple(range(9))))
    args["capture"].provenance["timestamp_ms"] -= 1
    assert select_request_tail(**args) is None
    args["capture"].provenance["timestamp_ms"] += 1
    assert len(select_request_tail(**args).unfinished_hotkeys) == 9


def test_single_miner_waits_until_its_complete_result(monkeypatch):
    args = hard_tail(inventory(monkeypatch, miners=1, benchmark_missing=(0,)))
    assert select_request_tail(**args) is None
    args["terminals"] = lambda *_: object()
    assert select_request_tail(**args).unfinished_hotkeys == ()


@pytest.mark.asyncio
async def test_live_observer_forwards_native_opening_without_changing_readiness(monkeypatch):
    from umi.competition_cohort_request_readiness import LiveRequestPhaseObserver

    seen = []
    opening = object()
    state = NS(cohort_sha256="ab" * 32, phase="requests")
    observed = object()
    source = NS(
        seal_fenced=lambda s, c: seen.append(("fence", s, c)),
        observe=lambda s, c, **kw: seen.append((s, c, kw)) or "progress",
    )

    async def clock(s):
        assert s is state
        return opening

    live = LiveRequestPhaseObserver(
        source, "https://owner.example", client=None, opening_clock=clock
    )

    async def ready(*_):
        return False

    monkeypatch.setattr(live, "_ready", ready)
    assert await live(state, observed) == "progress"
    assert seen == [
        ("fence", state, observed),
        (state, observed, {"serving": False, "opened": opening}),
    ]


@pytest.mark.asyncio
async def test_opening_clock_reuses_verified_original_and_retries_failed_publication():
    from umi.competition_cohort_lifecycle_host import LifecycleHost

    observation = boundary(1000)
    counts = {"read": 0, "review": 0, "publish": 0}
    verified = HistoricalRegistration(None, observation, NS(block_number=2000), 1000)

    async def archive(o):
        assert o == observation
        counts["read"] += 1
        return b"original-proof", b"metadata"

    async def review(o, raw, metadata):
        assert (o, raw, metadata) == (observation, b"original-proof", b"metadata")
        counts["review"] += 1
        return verified

    async def publish(o):
        assert o == observation
        counts["publish"] += 1
        if counts["publish"] == 1:
            raise OSError("proof publication interrupted")

    host = NS(
        provider=NS(retained_archive=archive, review_archive=review),
        proofs=NS(publish=publish),
        request_opening_clocks={},
    )
    source = NS(request_opening=lambda state: observation)
    with pytest.raises(OSError, match="interrupted"):
        await LifecycleHost._request_opening_clock(host, source, object())
    assert not host.request_opening_clocks
    assert await LifecycleHost._request_opening_clock(host, source, object()) is verified
    assert await LifecycleHost._request_opening_clock(host, source, object()) is verified
    assert counts == {"read": 2, "review": 2, "publish": 2}
    host.request_opening_clocks.clear()
    assert await LifecycleHost._request_opening_clock(host, source, object()) is verified
    assert counts == {"read": 3, "review": 3, "publish": 3}
