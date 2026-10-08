"""Native durable scheduling reservations; grant authentication is a caller boundary."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from threading import Barrier

import pytest

from umi.competition_cohort_window_store import (
    CohortMinerWindowStore,
    WindowAdmissionHeld,
    WindowRequest,
)
from umi.config import Limits
from umi.endpoint_retirement import EndpointRetirementReceipt, SignedEndpointRetirementReceipt
from umi.open_competition import sign_object
from umi.protocol import request_digest

from .factories import POLICY_HASH, challenge_request, dev_wallet

COHORTS = ("51" * 32, "61" * 32)
SOURCES = ("endpoint-primary", "endpoint-peer", "paid-owner")
PINS = {source: f"{index:064x}" for index, source in enumerate(SOURCES, 1)}


def store(path, *, windows=1):
    return CohortMinerWindowStore(
        path,
        cohorts=COHORTS,
        evaluators=tuple(dev_wallet(name).hotkey.ss58_address for name in ("//Alice", "//Charlie")),
        transports={POLICY_HASH: replace(Limits(), maximum_active_windows=windows)},
        bootstrap_sources=SOURCES,
    )


def selected(index=1, *, window="11" * 32, cohort=COHORTS[0], miner="//Bob", evaluator="//Alice"):
    return WindowRequest(
        schema="umi-cohort-window-request/1",
        cohort_sha256=cohort,
        miner_hotkey=dev_wallet(miner).hotkey.ss58_address,
        evaluator_hotkey=dev_wallet(evaluator).hotkey.ss58_address,
        grant_sha256="aa" * 32,
        request=challenge_request(index).model_copy(update={"window_id": window}),
    )


def retired(value, *, signer="//Bob"):
    body = EndpointRetirementReceipt(
        schema="umi-endpoint-retirement/1",
        grant_sha256=value.grant_sha256,
        request_digest=request_digest(value.request),
        miner_hotkey=value.miner_hotkey,
        evaluator_hotkey=value.evaluator_hotkey,
        result="response_retained",
        response_sha256="ef" * 32,
    )
    return SignedEndpointRetirementReceipt(
        receipt=body, signature=sign_object(body, dev_wallet(signer))
    )


def test_unseeded_owner_holds_new_dispatch_but_accepts_retirement(tmp_path):
    owner = store(tmp_path / "owner")
    value = selected()
    with pytest.raises(WindowAdmissionHeld, match="bootstrap_pending"):
        owner.reserve(value)
    with owner.journal.read_transaction() as db:
        assert db.execute("SELECT COUNT(*) FROM miner_windows").fetchone() == (0,)
        assert db.execute(
            "SELECT COUNT(*) FROM records WHERE kind='window_request'"
        ).fetchone() == (0,)
    assert owner.retire(value, retired(value)) == "retired"
    with pytest.raises(ValueError, match="missing a configured"):
        owner.seal_bootstrap({SOURCES[0]: PINS[SOURCES[0]]})
    owner.seal_bootstrap(PINS)
    assert owner.reserve(value) == "retired"


def test_all_cases_in_window_must_retire_before_another_cohort_or_evaluator(tmp_path):
    owner = store(tmp_path / "owner")
    owner.seal_bootstrap(PINS)
    first, second = selected(1), selected(2)
    later = selected(3, window="22" * 32, cohort=COHORTS[1], evaluator="//Charlie")
    assert owner.reserve(first) == owner.reserve(second) == "reserved"
    assert owner.retire(first, retired(first)) == "retired"
    with pytest.raises(WindowAdmissionHeld, match="retirement_pending"):
        owner.reserve(later)
    # An unrelated miner progresses while this miner's second case remains held.
    assert owner.reserve(selected(4, miner="//Dave", window="22" * 32)) == "reserved"
    owner.retire(second, retired(second))
    assert owner.reserve(later) == "reserved"


def test_unknown_send_survives_restart_and_retry_is_idempotent(tmp_path):
    path = tmp_path / "owner"
    owner = store(path)
    owner.seal_bootstrap(PINS)
    original = selected()
    owner.reserve(original)  # Process can exit before HTTP intent or acknowledgement.
    reopened = store(path)
    assert reopened.reserve(original) == "reserved"
    with pytest.raises(WindowAdmissionHeld):
        reopened.reserve(selected(2, window="22" * 32))
    reopened.retire(original, retired(original))
    assert reopened.reserve(selected(2, window="22" * 32)) == "reserved"


def test_concurrent_owners_cannot_allocate_different_windows_to_one_miner(tmp_path):
    path = tmp_path / "owner"
    left, right = store(path), store(path)
    left.seal_bootstrap(PINS)
    ready = Barrier(2)

    def attempt(owner, request):
        ready.wait()
        try:
            return owner.reserve(request)
        except WindowAdmissionHeld:
            return "held"

    with ThreadPoolExecutor(2) as pool:
        futures = (
            pool.submit(attempt, left, selected()),
            pool.submit(attempt, right, selected(2, window="22" * 32)),
        )
        assert sorted(f.result(timeout=30) for f in futures) == ["held", "reserved"]


def test_bootstrap_preserves_overlapping_old_sends_until_each_is_retired(tmp_path):
    owner = store(tmp_path / "owner")
    first, second = selected(), selected(2, window="22" * 32)
    owner.import_request(first)
    owner.import_request(second)
    owner.seal_bootstrap(PINS)
    owner.seal_bootstrap(PINS)
    third = selected(3, window="33" * 32)
    with pytest.raises(WindowAdmissionHeld):
        owner.reserve(third)
    owner.retire(first, retired(first))
    with pytest.raises(WindowAdmissionHeld):
        owner.reserve(third)
    owner.retire(second, retired(second))
    assert owner.reserve(third) == "reserved"
    with pytest.raises(ValueError, match="already sealed"):
        owner.import_request(selected(4))


@pytest.mark.parametrize("change", ["signer", "request", "grant"])
def test_unbound_retirement_cannot_release_window(tmp_path, change):
    owner = store(tmp_path / "owner")
    owner.seal_bootstrap(PINS)
    value = selected()
    owner.reserve(value)
    altered = value
    if change == "request":
        altered = selected(2)
    elif change == "grant":
        altered = value.model_copy(update={"grant_sha256": "bb" * 32})
    proof = retired(altered, signer="//Charlie" if change == "signer" else "//Bob")
    with pytest.raises(ValueError):
        owner.retire(value, proof)
    with pytest.raises(WindowAdmissionHeld):
        owner.reserve(selected(3, window="22" * 32))


def test_window_capacity_is_bound_to_selected_transport(tmp_path):
    path = tmp_path / "owner"
    owner = store(path, windows=2)
    owner.seal_bootstrap(PINS)
    assert owner.reserve(selected()) == "reserved"
    assert owner.reserve(selected(2, window="22" * 32)) == "reserved"
    with pytest.raises(WindowAdmissionHeld):
        owner.reserve(selected(3, window="33" * 32))
    with pytest.raises(ValueError):
        store(path, windows=3)
