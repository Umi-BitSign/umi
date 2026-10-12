"""Native signatures, restart receipts and exact source coverage for closure reuse."""

import json
import time

import pytest

from umi.competition_cohort_reward_package import ReplayObjectCollector
from umi.competition_verification_reuse import VerificationReuse
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_service_grants import base_policy as base_policy
from .test_competition_cohort_service_grants import chain as chain
from .test_competition_cohort_service_grants import chain_config as chain_config
from .test_competition_cohort_service_grants import endpoint as endpoint
from .test_competition_cohort_service_grants import execution as execution
from .test_competition_cohort_service_grants import granted as granted
from .test_competition_cohort_service_grants import harness as harness
from .test_competition_cohort_service_grants import known_video_bytes as known_video_bytes
from .test_competition_cohort_service_grants import legacy_scenario as legacy_scenario
from .test_competition_cohort_service_grants import miner_policy as miner_policy
from .test_competition_cohort_service_grants import original_harness as original_harness
from .test_competition_cohort_service_grants import policy as policy
from .test_competition_cohort_service_grants import receipt_scenario as receipt_scenario
from .test_competition_cohort_service_grants import recovery as recovery
from .test_competition_cohort_service_grants import recovery_case as recovery_case
from .test_competition_cohort_service_grants import relay as relay
from .test_competition_cohort_service_grants import review_service_closed
from .test_competition_cohort_service_grants import runtime as runtime
from .test_competition_cohort_service_grants import scenario as scenario
from .test_competition_cohort_service_grants import service as service
from .test_competition_cohort_service_grants import service_catalog_inputs as service_catalog_inputs
from .test_competition_cohort_service_grants import service_closed as service_closed
from .test_competition_cohort_service_grants import service_owner as service_owner
from .test_competition_cohort_service_grants import shared_control_group as shared_control_group


def test_native_complete_warm_restart_coverage_and_tamper(
    service_closed, tmp_path, monkeypatch, caplog
):
    from umi import competition_cohort_request_closure as request

    from .test_competition_cohort_consumers import tip
    from .test_competition_cohort_request_closure import certified_history

    b = service_closed
    root = tmp_path / "verified"
    counts = []
    native = request.read_request_terminal

    def counted(*args, **kwargs):
        counts.append(1)
        return native(*args, **kwargs)

    monkeypatch.setattr(request, "read_request_terminal", counted)
    caplog.set_level("INFO", logger="umi.competition.progress")
    before = {k: v for k, v in b["objects"].items()}
    source = ReplayObjectCollector(b["objects"].__getitem__, 64 * 1024**2)
    cold_started = time.monotonic()
    with VerificationReuse(root, owner={"signer": "a"}).selected():
        assert review_service_closed(b, objects=source) == b["closure"]
    cold = time.monotonic() - cold_started
    count = len(counts)
    assert count > 0
    assert tuple(root.glob("*.json"))
    warm_source = ReplayObjectCollector(b["objects"].__getitem__, 64 * 1024**2)
    warm_started = time.monotonic()
    # Fresh owner instance simulates service restart; no in-memory verdict survives.
    with VerificationReuse(root, owner={"signer": "a"}).selected():
        assert review_service_closed(b, objects=warm_source) == b["closure"]
    warm = time.monotonic() - warm_started
    assert len(counts) == count
    assert warm_source.values == source.values
    assert warm < cold
    assert b["objects"] == before
    # New current certified history is checked independently while replay uses
    # the same original request-prefix receipt.
    h = certified_history(b)
    with VerificationReuse(root, owner={"signer": "a"}).selected():
        assert (
            review_service_closed(
                b, certified=True, history=h, expected_tip_sha256=tip(h), current_block=2**53 - 1
            )
            == b["closure"]
        )
    assert len(counts) == count
    key = b["service_terminal"].terminal.response_sha256
    original = b["objects"].pop(key)
    with VerificationReuse(root, owner={"signer": "a"}).selected(), pytest.raises(KeyError):
        review_service_closed(b)
    b["objects"][key] = b"{}"
    with VerificationReuse(root, owner={"signer": "a"}).selected(), pytest.raises(ValueError):
        review_service_closed(b)
    b["objects"][key] = original
    with VerificationReuse(root, owner={"signer": "a"}).selected():
        assert review_service_closed(b) == b["closure"]
    messages = [json.loads(r.message) for r in caplog.records if r.message.startswith("{")]
    assert any(
        m.get("stage") == "service_request_closure" and m.get("state") == "hit" for m in messages
    )
    print(
        {
            "cold_seconds": cold,
            "restart_seconds": warm,
            "terminals": count,
            "dependencies": len(source.values),
        }
    )


def test_interrupted_closure_resumes_completed_participants(service_closed, tmp_path, monkeypatch):
    from umi import competition_cohort_request_closure as request

    b = service_closed
    root = tmp_path / "resume"
    native = request.verify_recoverable_order
    verified = []
    interrupted = False

    def stop_after_one(order, *args, **kwargs):
        nonlocal interrupted
        if len(verified) == 1 and not interrupted:
            interrupted = True
            raise InterruptedError("process interrupted between completed participants")
        verified.append(digest(order))
        return native(order, *args, **kwargs)

    monkeypatch.setattr(request, "verify_recoverable_order", stop_after_one)
    with VerificationReuse(root, owner="one").selected(), pytest.raises(InterruptedError):
        review_service_closed(b)
    assert len(verified) == 1
    with VerificationReuse(root, owner="one").selected():
        assert review_service_closed(b) == b["closure"]
    assert len(verified) == len(set(verified))
    assert len(verified) == len(b["roster"].participants)


def test_context_changes_and_receipt_repair_never_borrow_verification(
    service_closed, tmp_path, monkeypatch
):
    from umi import competition_cohort_request_closure as request

    b = service_closed
    root = tmp_path / "context"
    verified = []
    native = request.verify_recoverable_order

    def count(order, *args, **kwargs):
        verified.append(digest(order))
        return native(order, *args, **kwargs)

    monkeypatch.setattr(request, "verify_recoverable_order", count)
    owner = VerificationReuse(root, owner="one")
    with owner.selected():
        review_service_closed(b)
    count_one = len(verified)
    owner_one_receipts = tuple(root.glob("*.json"))
    with VerificationReuse(root, owner="two").selected():
        review_service_closed(b)
    assert len(verified) == 2 * count_one
    # Changing the exact certified interval cannot borrow the original verdict.
    with owner.selected(), pytest.raises(ValueError):
        review_service_closed(b, current_block=b["closure"].observation.block - 1)
    # Invalid bytes cannot become a hit by merely retaining the same model type.
    with owner.selected(), pytest.raises(ValueError):
        review_service_closed(b, expected_tip_sha256="ff" * 32)
    # A corrupt optional receipt is repaired from native input, while completed
    # per-item receipts remain independently available to the repair pass.
    for path in owner_one_receipts:
        item = json.loads(path.read_bytes())
        if item["result_json"] == canonical_json_bytes(b["closure"]).decode():
            path.write_bytes(b"corrupt receipt")
    with owner.selected():
        assert review_service_closed(b) == b["closure"]
    assert all(
        json.loads(p.read_bytes())["schema"] == "umi-private-native-verification/1"
        for p in root.glob("*.json")
    )
    # Selecting a different runtime invalidates both top-level and per-item receipts.
    another = VerificationReuse(root, owner="one")
    another.runtime = "ff" * 32
    with another.selected():
        review_service_closed(b)
    assert len(verified) == 3 * count_one
