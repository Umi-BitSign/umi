"""Actual miner/evaluator retirement HTTP and durable response reconciliation.

RPC, owned finality, DNS and inference use fixtures. Replacement certification
and host fencing are not simulated by these tests.
"""

import hashlib
from dataclasses import replace

import bittensor as bt
import httpx
import pytest

from umi import miner as miner_module
from umi.competition_cohort_endpoint import endpoint_obligation_sha256
from umi.competition_cohort_endpoint_recovery import CohortEndpointResponseRecovery
from umi.competition_cohort_endpoint_retirement import CohortEndpointRetirement
from umi.endpoint_protocol import COHORT_RETIRE_PATH, RESPONSE_RECOVERY_PATH
from umi.endpoint_retirement import SignedEndpointRetirementReceipt
from umi.open_competition import sign_object
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_order_signer import source_for
from .test_endpoint_retirement import base_policy as base_policy
from .test_endpoint_retirement import chain as chain
from .test_endpoint_retirement import chain_config as chain_config
from .test_endpoint_retirement import delivery as delivery
from .test_endpoint_retirement import endpoint as endpoint
from .test_endpoint_retirement import execution as execution
from .test_endpoint_retirement import expire, translate
from .test_endpoint_retirement import granted as granted
from .test_endpoint_retirement import harness as harness
from .test_endpoint_retirement import known_video_bytes as known_video_bytes
from .test_endpoint_retirement import legacy_scenario as legacy_scenario
from .test_endpoint_retirement import policy as policy
from .test_endpoint_retirement import receipt_scenario as receipt_scenario
from .test_endpoint_retirement import recovery as recovery
from .test_endpoint_retirement import recovery_case as recovery_case
from .test_endpoint_retirement import relay as relay
from .test_endpoint_retirement import runtime as runtime
from .test_endpoint_retirement import scenario as scenario
from .test_open_competition import wallet


@pytest.fixture
async def retiring(delivery):
    p = delivery
    assert (await p.deliver()).status == "retained"
    p.retirement = CohortEndpointRetirement(p.delivery_recovery)
    p.retire_slot = p.delivery_selection.assignment_slot
    p.retire = lambda: p.retirement.retire(p.retire_slot, p.case_id)
    return p


def expire_both(p, monkeypatch):
    expire(p, monkeypatch)
    p.c.finality.ref = replace(
        p.c.finality.ref,
        block_number=p.requests[0].deadline_block + 1,
        block_hash="0x" + "ab" * 32,
    )


def reopen_evaluator(p):
    recovery = CohortEndpointResponseRecovery(
        p.service(), p.validator, transport=p.delivery_recovery.transport
    )
    p.delivery_recovery = recovery
    p.retirement = CohortEndpointRetirement(recovery)


@pytest.mark.parametrize("failure", [False, True])
async def test_original_response_and_retirement_commit_then_replay_offline(
    retiring, monkeypatch, failure
):
    p = retiring
    p.model.fail = failure
    original = await translate(p)
    assert original.status_code == 200, original.text
    result = await p.retire()
    assert result.status == "retained", result
    assert (
        result.value.retirement.receipt.response_sha256
        == hashlib.sha256(original.content).hexdigest()
    )
    recovered = p.delivery_recovery.retained(p.retire_slot, p.case_id)
    assert bytes.fromhex(recovered.response.envelope_hex) == original.content
    assert p.transmissions[-2:] == [
        (COHORT_RETIRE_PATH, "example.com", "example.com"),
        (RESPONSE_RECOVERY_PATH, "example.com", "example.com"),
    ]
    count = len(p.transmissions)
    reopen_evaluator(p)
    p.c.finality.fail = True
    p.e.r.h.source = source_for(p.e.r.h.batch, p.e.r.h.batch["history"])
    assert (await p.retire()).value == result.value
    assert len(p.transmissions) == count
    assert p.model.calls == 1
    assert not result.value.replacement_authorized
    assert not result.value.original_receipt_timing_proven


async def test_expired_unstarted_request_retirement_is_durable(retiring, monkeypatch):
    p = retiring
    expire_both(p, monkeypatch)
    result = await p.retire()
    assert result.status == "retained", result
    assert result.value.retirement.receipt.result == "no_response_retained"
    assert p.model.calls == p.fetcher.calls == 0
    reopen_evaluator(p)
    p.c.finality.fail = True
    assert (await p.retire()).value == result.value
    assert p.model.calls == 0


async def test_unexpired_request_stays_pending(retiring):
    p = retiring
    assert (await p.retire()).reason == "retirement_not_acknowledged"
    assert p.retirement.retained(p.retire_slot, p.case_id) is None
    assert p.model.calls == p.fetcher.calls == 0


async def test_lost_http_ack_recovers_same_signed_retirement(retiring, monkeypatch):
    p = retiring
    expire_both(p, monkeypatch)
    real = p.delivery_recovery.transport

    class Lost(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            response = await real.handle_async_request(request)
            await response.aread()
            await response.aclose()
            raise httpx.ReadError("lost acknowledgement")

    p.delivery_recovery.transport = Lost()
    assert (await p.retire()).status == "pending"
    p.delivery_recovery.transport = real

    def forbidden(*args):
        raise AssertionError("retained retirement must not be signed again")

    monkeypatch.setattr(miner_module, "sign_object", forbidden)
    assert (await p.retire()).status == "retained"
    assert p.model.calls == 0


@pytest.mark.parametrize("after_commit", [False, True])
async def test_interrupted_evaluator_commit_preserves_atomic_selection(
    retiring, monkeypatch, after_commit
):
    p = retiring
    original = await translate(p)
    assert original.status_code == 200
    db = p.delivery_recovery.journal.journal
    real = db.put_many

    def interrupt(records, **kwargs):
        if any(kind == "endpoint_retired_case" for kind, _, _ in records):
            if after_commit:
                real(records, **kwargs)
            raise OSError("interrupted receipt commit")
        return real(records, **kwargs)

    with monkeypatch.context() as m:
        m.setattr(db, "put_many", interrupt)
        with pytest.raises(OSError, match="interrupted"):
            await p.retire()
    key = endpoint_obligation_sha256(p.e.job, p.case_id)
    assert (db.get("endpoint_retired_case", key) is not None) == after_commit
    assert (db.get("endpoint_recovered_case", key) is not None) == after_commit
    reopen_evaluator(p)
    if after_commit:
        p.c.finality.fail = True
    result = await p.retire()
    assert result.status == "retained", result
    assert (
        bytes.fromhex(p.delivery_recovery.retained(p.retire_slot, p.case_id).response.envelope_hex)
        == original.content
    )
    assert p.model.calls == 1


async def test_sealed_response_must_be_retrieved_before_retirement_ack(retiring):
    p = retiring
    assert (await translate(p)).status_code == 200
    real = p.delivery_recovery.transport

    class Missing(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            if request.url.path == RESPONSE_RECOVERY_PATH:
                return httpx.Response(503)
            return await real.handle_async_request(request)

    p.delivery_recovery.transport = Missing()
    result = await p.retire()
    assert result.reason == "retirement_response_pending"
    assert p.retirement.retained(p.retire_slot, p.case_id) is None
    p.delivery_recovery.transport = real
    assert (await p.retire()).status == "retained"
    assert p.model.calls == 1


@pytest.mark.parametrize(
    "damage", ["signature", "request", "grant", "miner", "evaluator", "noncanonical", "oversize"]
)
async def test_invalid_remote_receipt_cannot_complete(retiring, monkeypatch, damage):
    p = retiring
    expire_both(p, monkeypatch)
    real = p.delivery_recovery.transport

    class Damaged(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            response = await real.handle_async_request(request)
            raw = await response.aread()
            await response.aclose()
            assert response.status_code == 200
            value = SignedEndpointRetirementReceipt.model_validate_json(raw)
            if damage == "noncanonical":
                raw = b" " + raw
            elif damage == "oversize":
                raw = b"x" * (16 * 1024 + 1)
            elif damage == "signature":
                raw = canonical_json_bytes(
                    value.model_copy(
                        update={"signature": sign_object(value.receipt, wallet("Alice"))}
                    )
                )
            else:
                field = {
                    "request": "request_digest",
                    "grant": "grant_sha256",
                    "miner": "miner_hotkey",
                    "evaluator": "evaluator_hotkey",
                }[damage]
                body = value.receipt.model_copy(
                    update={
                        field: wallet("Alice").hotkey.ss58_address
                        if "hotkey" in field
                        else "ab" * 32
                    }
                )
                raw = canonical_json_bytes(
                    value.model_copy(
                        update={"receipt": body, "signature": sign_object(body, wallet("Bob"))}
                    )
                )
            return httpx.Response(200, stream=httpx.ByteStream(raw))

    p.delivery_recovery.transport = Damaged()
    assert (await p.retire()).status == "pending"
    assert p.retirement.retained(p.retire_slot, p.case_id) is None
    assert p.model.calls == 0


@pytest.mark.parametrize("expired", ["neither", "block", "round"])
async def test_client_rejects_premature_signed_absence(retiring, monkeypatch, expired):
    p = retiring
    # Obtain an authentic miner receipt after expiry, then present it to an
    # evaluator whose own observations do not establish expiry.
    old_ref = p.c.finality.ref
    expire_both(p, monkeypatch)
    from .test_endpoint_retirement import retire

    response = await retire(p)
    assert response.status_code == 200
    if expired in {"neither", "round"}:
        p.c.finality.ref = old_ref
    if expired in {"neither", "block"}:
        monkeypatch.setattr(
            bt.timelock, "current_round", lambda: p.requests[0].response_close_round - 1
        )
    p.delivery_recovery.transport = httpx.MockTransport(
        lambda request: httpx.Response(200, stream=httpx.ByteStream(response.content))
    )
    assert (await p.retire()).reason == "retirement_receipt_invalid"
    assert p.retirement.retained(p.retire_slot, p.case_id) is None


@pytest.mark.parametrize("claim", ["wrong_hash", "absent"])
async def test_signed_conflict_does_not_discard_original_response(retiring, monkeypatch, claim):
    p = retiring
    assert (await translate(p)).status_code == 200
    assert (await p.delivery_recovery.recover(p.retire_slot, p.case_id)).status == "recovered"
    saved = p.delivery_recovery.retained(p.retire_slot, p.case_id)
    expire_both(p, monkeypatch)
    real = p.delivery_recovery.transport

    class Conflict(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            reply = await real.handle_async_request(request)
            value = SignedEndpointRetirementReceipt.model_validate_json(await reply.aread())
            await reply.aclose()
            body = value.receipt.model_copy(
                update={
                    "response_sha256": None if claim == "absent" else "ab" * 32,
                    "result": "no_response_retained" if claim == "absent" else "response_retained",
                }
            )
            return httpx.Response(
                200,
                stream=httpx.ByteStream(
                    canonical_json_bytes(
                        value.model_copy(
                            update={"receipt": body, "signature": sign_object(body, wallet("Bob"))}
                        )
                    )
                ),
            )

    p.delivery_recovery.transport = Conflict()
    assert (await p.retire()).reason == "retirement_response_conflict"
    assert p.delivery_recovery.retained(p.retire_slot, p.case_id) == saved
    assert p.retirement.retained(p.retire_slot, p.case_id) is None
    assert p.model.calls == 1
