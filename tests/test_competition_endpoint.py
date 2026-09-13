from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from types import SimpleNamespace

import bittensor as bt
import pytest

from umi.competition_endpoint import prepare_endpoint_case, replay_endpoint_outcome
from umi.config import Limits
from umi.crypto import sign_response_digest
from umi.drand import DrandPulse, DrandVerificationError
from umi.miner import _signed_envelope
from umi.open_competition import digest
from umi.protocol import ResponseEnvelope, base64url_decode, base64url_encode, canonical_json_bytes
from umi.validator import QueryOutcome, prepare_request_attempt
from umi.window import QUICKNET_GENESIS_MS, QUICKNET_PERIOD_MS

from .factories import challenge_request
from .test_component_run import response_plaintext
from .test_drand import ROUND, pulse_record
from .test_open_competition import policy as policy
from .test_open_competition import round_for, submission, suite_for, wallet

_CLOSE_NS = (QUICKNET_GENESIS_MS + (ROUND - 3) * QUICKNET_PERIOD_MS) * 1_000_000
_START_NS = _CLOSE_NS - 1_000_000_000
_FINISH_NS = _START_NS + 5_000_000


@pytest.fixture
def endpoint(policy, monkeypatch):
    # Only the local seal helper's clock is shifted. All signatures, portable
    # ciphertext parsing, pulse verification and offline decryption are real.
    monkeypatch.setattr(bt.timelock, "current_round", lambda: ROUND - 10)
    suite = suite_for(policy)
    signed = submission(policy)
    round_ = round_for(policy, suite, [signed])
    request = challenge_request(stratum="fingerspelling", reveal_round=ROUND)
    request = request.model_copy(
        update={
            "issued_block": 125,
            "deadline_block": 130,
            "video": request.video.model_copy(update={"sha256": suite.cases[0].video_sha256}),
        }
    )
    prepared = prepare_request_attempt(
        request,
        wallet=wallet("Charlie"),
        miner_hotkey=wallet("Alice").hotkey.ss58_address,
        nonce_ns=_START_NS,
    )
    kwargs = {
        "policy": policy,
        "round_": round_,
        "signed": signed,
        "case_id": suite.cases[0].case_id,
        "expected_transport_policy_sha256": request.scoring_policy_hash,
        "limits": Limits(),
    }
    item = prepare_endpoint_case(prepared, **kwargs)
    plain = response_plaintext(
        request,
        validator_hotkey=prepared.validator_hotkey,
        miner_hotkey=prepared.miner_hotkey,
    ).model_copy(update={"model_revision": signed.submission.model_revision})
    return SimpleNamespace(
        item=item, prepared=prepared, kwargs=kwargs, suite=suite, plaintext=plain
    )


def _outcome(endpoint, *, plaintext=None, raw_plaintext=None):
    if plaintext is None:
        plaintext = endpoint.plaintext
    runtime = SimpleNamespace(
        wallet=wallet("Alice"),
        hotkey_ss58=wallet("Alice").hotkey.ss58_address,
        signature_scheme="sr25519",
        limits=Limits(),
    )
    raw, signature = _signed_envelope(runtime, endpoint.prepared.request, plaintext)
    return QueryOutcome(
        request=endpoint.prepared.request,
        auth_headers=dict(endpoint.prepared.auth_headers),
        received_at_unix_ns=str(_FINISH_NS),
        envelope_bytes=raw,
        envelope=None,
        response_signature=signature,
        sealed_response=None,
        plaintext_bytes=raw_plaintext,
        received_bytes_sha256=hashlib.sha256(raw).hexdigest(),
        received_body_prefix=raw,
    )


def _replay(endpoint, outcome, **overrides):
    args = {
        "suite": endpoint.suite,
        "reveal_pulse": DrandPulse(**pulse_record()),
        "started_at_unix_ns": str(_START_NS),
        "finished_at_unix_ns": str(_FINISH_NS),
        **overrides,
    }
    return replay_endpoint_outcome(endpoint.item, outcome, **args)


def test_real_crypto_replay_retains_exact_transcript_and_rehearsal_class(endpoint, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("offline replay must not fetch a beacon or send a request")

    monkeypatch.setattr(bt.timelock, "decrypt", forbidden)
    monkeypatch.setattr("httpx.Client.send", forbidden)
    monkeypatch.setattr("httpx.AsyncClient.send", forbidden)
    outcome = _outcome(endpoint)
    replay = _replay(endpoint, outcome)
    assert (replay.output.status, replay.output.hypothesis, replay.output.elapsed_ms) == (
        "ok",
        "hello",
        5,
    )
    evidence = json.loads(replay.evidence_bytes)
    assert replay.evidence_bytes == canonical_json_bytes(evidence)
    assert replay.evidence_sha256 == hashlib.sha256(replay.evidence_bytes).hexdigest()
    assert evidence["no_weight"] is True
    assert evidence["miner_authorization_verified"] is False
    assert evidence["pre_reveal_delivery_proven"] is False
    assert evidence["profile"] == "legacy-transport-rehearsal/1"
    assert evidence["timing_class"] == "evaluator_reported_round_trip"
    assert evidence["policy_sha256"] != evidence["transport_policy_sha256"]
    assert base64url_decode(evidence["request_bytes"]) == endpoint.prepared.request_bytes
    assert base64url_decode(evidence["envelope_bytes"]) == outcome.envelope_bytes
    assert base64url_decode(evidence["plaintext_bytes"]) == canonical_json_bytes(endpoint.plaintext)
    assert evidence["auth_headers"] == dict(endpoint.prepared.auth_headers)
    assert evidence["reveal_pulse"] == pulse_record()
    assert b'"references"' not in replay.evidence_bytes
    assert not hasattr(endpoint.item, "suite")


@pytest.mark.parametrize("field", ["case_id", "expected_transport_policy_sha256"])
def test_preparation_rejects_invalid_digest_fields(endpoint, field):
    with pytest.raises(ValueError, match=r"digest|transport policy"):
        prepare_endpoint_case(endpoint.prepared, **{**endpoint.kwargs, field: "invalid"})


def test_cannot_relabel_competition_policy_as_transport_policy(endpoint):
    req = endpoint.prepared.request.model_copy(
        update={"scoring_policy_hash": digest(endpoint.item.policy)}
    )
    prepared = prepare_request_attempt(
        req,
        wallet=wallet("Charlie"),
        miner_hotkey=endpoint.prepared.miner_hotkey,
        nonce_ns=_START_NS,
    )
    with pytest.raises(ValueError, match="distinct legacy"):
        prepare_endpoint_case(
            prepared,
            **{**endpoint.kwargs, "expected_transport_policy_sha256": digest(endpoint.item.policy)},
        )


@pytest.mark.parametrize(
    "changes",
    [
        {"issued_block": 120},
        {"deadline_block": 141},
        {"scoring_policy_hash": "ff" * 32},
    ],
)
def test_authenticated_wrong_request_interval_or_transport_policy_is_rejected(endpoint, changes):
    request = endpoint.prepared.request.model_copy(update=changes)
    prepared = prepare_request_attempt(
        request,
        wallet=wallet("Charlie"),
        miner_hotkey=endpoint.prepared.miner_hotkey,
        nonce_ns=_START_NS,
    )
    with pytest.raises(ValueError):
        prepare_endpoint_case(prepared, **endpoint.kwargs)


@pytest.mark.parametrize("name", ["Alice", "Bob"])
def test_evaluator_must_be_policy_member_and_not_submitter(endpoint, name):
    prepared = prepare_request_attempt(
        endpoint.prepared.request,
        wallet=wallet(name),
        miner_hotkey=endpoint.prepared.miner_hotkey,
        nonce_ns=_START_NS,
    )
    with pytest.raises(ValueError, match="unauthorized evaluator"):
        prepare_endpoint_case(prepared, **endpoint.kwargs)


def test_replay_rechecks_model_copy_signature_bypass(endpoint):
    forged = endpoint.item.signed.model_copy(
        update={
            "submission": endpoint.item.signed.submission.model_copy(
                update={"model_revision": "ff" * 32}
            )
        }
    )
    endpoint.item = replace(endpoint.item, signed=forged)
    with pytest.raises(ValueError, match="signature"):
        _replay(endpoint, _outcome(endpoint))


@pytest.mark.parametrize("mutation", ["suite", "video", "stratum", "missing_case"])
def test_post_reveal_case_membership_is_required(endpoint, mutation):
    if mutation == "suite":
        suite = endpoint.suite.model_copy(update={"policy_sha256": "ff" * 32})
        args = {"suite": suite}
    else:
        args = {}
        if mutation == "missing_case":
            endpoint.item = replace(endpoint.item, case_id="ff" * 32)
        else:
            request = endpoint.prepared.request
            request = request.model_copy(
                update={"video": request.video.model_copy(update={"sha256": "ff" * 32})}
                if mutation == "video"
                else {"task": request.task.model_copy(update={"stratum": "continuous"})}
            )
            prepared = prepare_request_attempt(
                request,
                wallet=wallet("Charlie"),
                miner_hotkey=endpoint.prepared.miner_hotkey,
                nonce_ns=_START_NS,
            )
            endpoint.item = replace(endpoint.item, prepared=prepared)
    with pytest.raises(ValueError, match="suite"):
        _replay(endpoint, _outcome(endpoint), **args)


@pytest.mark.parametrize("mutation", ["request", "auth", "digest", "prefix", "plaintext"])
def test_raw_transcript_tampering_fails_closed(endpoint, mutation):
    outcome = _outcome(endpoint)
    updates = {
        "request": {"request": outcome.request.model_copy(update={"window_id": "ff" * 32})},
        "auth": {"auth_headers": {**outcome.auth_headers, "x-bittensor-nonce": "1"}},
        "digest": {"received_bytes_sha256": "ff" * 32},
        "prefix": {"received_body_prefix": b"unrelated"},
        "plaintext": {"plaintext_bytes": b"invented answer"},
    }[mutation]
    with pytest.raises(ValueError):
        _replay(endpoint, replace(outcome, **updates))


def test_cached_parsed_models_and_reported_failure_do_not_override_raw_bytes(endpoint):
    outcome = _outcome(endpoint)
    cached_envelope = ResponseEnvelope.model_validate_json(outcome.envelope_bytes)
    outcome = replace(
        outcome,
        envelope=cached_envelope.model_copy(update={"serving_hotkey": "forged"}),
        plaintext=endpoint.plaintext.model_copy(update={"hypothesis": "invented"}),
        failure_code="transport_timeout",
    )
    replay = _replay(endpoint, outcome)
    assert replay.output.status == "ok"
    assert replay.output.hypothesis == "hello"


@pytest.mark.parametrize("mutation", ["wrong_round", "bad_signature", "missing"])
def test_verified_matching_quicknet_pulse_is_required(endpoint, mutation):
    pulse = DrandPulse(**pulse_record())
    if mutation == "wrong_round":
        pulse = replace(pulse, round=pulse.round + 1)
    elif mutation == "bad_signature":
        pulse = replace(pulse, signature="00" * 48)
    else:
        pulse = None
    with pytest.raises((ValueError, DrandVerificationError)):
        _replay(endpoint, _outcome(endpoint), reveal_pulse=pulse)


@pytest.mark.parametrize(
    "changes,reason",
    [
        ({"model_revision": None}, "model_revision_mismatch"),
        ({"model_revision": "ff" * 32}, "model_revision_mismatch"),
        ({"hypothesis": "a" * 101}, "output_limit"),
        (
            {
                "status": "error",
                "hypothesis": None,
                "model_revision": None,
                "error_code": "backend_failed",
            },
            "signed_miner_error",
        ),
    ],
)
def test_authenticated_miner_faults_have_no_hypothesis(endpoint, changes, reason):
    outcome = _outcome(endpoint, plaintext=endpoint.plaintext.model_copy(update=changes))
    replay = _replay(endpoint, outcome)
    assert replay.output.status == "miner_failure"
    assert replay.output.hypothesis == ""
    assert replay.reason_code == reason


def test_unauthenticated_transport_failure_voids_instead_of_penalizing_miner(endpoint):
    outcome = QueryOutcome(
        request=endpoint.prepared.request,
        auth_headers=dict(endpoint.prepared.auth_headers),
        received_at_unix_ns=None,
        envelope_bytes=None,
        envelope=None,
        response_signature=None,
        sealed_response=None,
        failure_code="transport_timeout",
    )
    replay = _replay(endpoint, outcome, reveal_pulse=None)
    assert replay.output.status == "infrastructure_failure"
    assert replay.reason_code == "unauthenticated_transport"


def test_invalid_miner_signature_cannot_manufacture_miner_fault(endpoint):
    outcome = replace(_outcome(endpoint), response_signature="0x" + "00" * 64)
    replay = _replay(endpoint, outcome)
    assert replay.output.status == "infrastructure_failure"
    assert replay.reason_code == "bad_signature"


@pytest.mark.parametrize(
    "args",
    [
        {"started_at_unix_ns": "01"},
        {"finished_at_unix_ns": str(_START_NS - 1)},
        {"started_at_unix_ns": str(_START_NS - 3_000_000_000)},
        {"finished_at_unix_ns": str(_START_NS + 1)},
    ],
)
def test_timing_claims_are_bounded_canonical_and_consistent(endpoint, args):
    with pytest.raises(ValueError):
        _replay(endpoint, _outcome(endpoint), **args)


def test_delivery_at_response_close_is_not_proven_timely(endpoint):
    outcome = replace(_outcome(endpoint), received_at_unix_ns=str(_CLOSE_NS))
    replay = _replay(endpoint, outcome, finished_at_unix_ns=str(_CLOSE_NS))
    assert replay.output.status == "infrastructure_failure"
    assert replay.reason_code == "reported_late_delivery"


def test_oversized_response_rejected_before_crypto_or_decryption(endpoint, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("oversize input must be rejected before pulse crypto")

    monkeypatch.setattr(DrandPulse, "verify", forbidden)
    outcome = replace(_outcome(endpoint), envelope_bytes=b"x" * (64 * 1024 + 1))
    with pytest.raises(ValueError, match="byte limit"):
        _replay(endpoint, outcome)


def test_unbounded_limits_cannot_be_injected(endpoint):
    with pytest.raises(ValueError, match="bounded transport"):
        prepare_endpoint_case(
            endpoint.prepared,
            **{**endpoint.kwargs, "limits": Limits(maximum_response_body_bytes=2**30)},
        )


def test_stricter_transport_output_limit_is_preserved(endpoint):
    endpoint.item = replace(
        endpoint.item, limits=replace(endpoint.item.limits, maximum_hypothesis_utf8_bytes=4)
    )
    replay = _replay(endpoint, _outcome(endpoint))
    assert replay.output.status == "miner_failure"
    assert replay.reason_code == "output_limit"


def test_prepared_auth_headers_are_bounded_before_signature_replay(endpoint, monkeypatch):
    # Simulate an untrusted reconstructed dataclass, bypassing its constructor.
    prepared = endpoint.prepared
    object.__setattr__(prepared, "auth_headers", (("x", "a" * (16 * 1024)),))

    def forbidden(*args, **kwargs):
        raise AssertionError("headers must be bounded before signature verification")

    monkeypatch.setattr("umi.competition_endpoint.VerifiedAuthEvidence.from_headers", forbidden)
    with pytest.raises(ValueError, match="authentication headers exceed"):
        prepare_endpoint_case(prepared, **endpoint.kwargs)


def test_signed_but_undecryptable_ciphertext_is_reproduced_as_miner_failure(endpoint):
    outcome = _outcome(endpoint)
    envelope = ResponseEnvelope.model_validate_json(outcome.envelope_bytes)
    portable = bytearray(base64url_decode(envelope.encrypted_response))
    # Change an authenticated ciphertext byte, preserving the canonical SCALE
    # framing, curve element, lengths, marker and embedded reveal round.
    portable[200] ^= 1
    envelope = envelope.model_copy(
        update={
            "encrypted_response": base64url_encode(bytes(portable)),
            "encrypted_response_sha256": hashlib.sha256(portable).hexdigest(),
        }
    )
    raw = canonical_json_bytes(envelope)
    _, signature = sign_response_digest(wallet("Alice"), envelope)
    outcome = replace(
        outcome,
        envelope_bytes=raw,
        received_body_prefix=raw,
        received_bytes_sha256=hashlib.sha256(raw).hexdigest(),
        response_signature=signature,
    )
    replay = _replay(endpoint, outcome)
    assert replay.output.status == "miner_failure"
    assert replay.reason_code == "undecryptable"


def test_signed_plaintext_cannot_substitute_another_video(endpoint):
    outcome = _outcome(
        endpoint,
        plaintext=endpoint.plaintext.model_copy(update={"received_video_sha256": "ff" * 32}),
    )
    replay = _replay(endpoint, outcome)
    assert replay.output.status == "miner_failure"
    assert replay.reason_code == "plaintext_binding_mismatch"
