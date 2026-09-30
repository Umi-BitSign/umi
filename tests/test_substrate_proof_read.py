from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

from umi.substrate_proof import (
    READ_RESPONSE_SCHEMA,
    SubprocessStorageProofVerifier,
    SubstrateProofLimits,
    SubstrateProofVerifierError,
    _communicate_bounded,
)

FAKE = Path(__file__).parent / "fixtures" / "proof_sidecar_fake.sh"


@pytest.fixture
def exchange(monkeypatch):
    requests = []
    response = {
        "schema": READ_RESPONSE_SCHEMA,
        "ok": True,
        "state_version": 1,
        "state_root": "0x" + "11" * 32,
        "items": [
            {"key": "0x61", "value": None},
            {"key": "0x62", "value": "0x"},
            {"key": "0x63", "value": "0x1122"},
        ],
    }

    def run(_self, _binary, raw, **_kwargs):
        request = json.loads(raw)
        requests.append(request)
        result = copy.deepcopy(response)
        result.setdefault("request_id", request["request_id"])
        return result

    monkeypatch.setattr(SubprocessStorageProofVerifier, "_exchange_staged", run)
    return requests, response


def verifier(**kwargs):
    return SubprocessStorageProofVerifier(
        binary_path=FAKE.resolve(),
        expected_sha256=hashlib.sha256(FAKE.read_bytes()).hexdigest(),
        **kwargs,
    )


def read(selected, **kwargs):
    request = {
        "state_root": b"\x11" * 32,
        "storage_keys": (b"c", b"a", b"b"),
        "proof": (b"fixture",),
    }
    request.update(kwargs)
    return selected.read_many(**request)


def test_read_preserves_absence_empty_and_values_and_binds_request(exchange):
    requests, _ = exchange
    assert read(verifier()) == ((b"a", None), (b"b", b""), (b"c", b"\x11\x22"))
    read(verifier(), maximum_total_value_bytes=10)
    read(verifier(), proof=(b"different-proof",))
    read(verifier(), storage_keys=(b"b", b"c", b"a"))
    assert requests[0]["keys"] == ["0x61", "0x62", "0x63"]
    assert len({r["request_id"] for r in requests[:3]}) == 3
    assert requests[0] == requests[3]
    for request in requests:
        request = dict(request)
        identity = request.pop("request_id")
        raw = json.dumps(request, sort_keys=True, separators=(",", ":")).encode("ascii")
        assert identity == hashlib.sha256(b"umi-substrate-proof-read-v1\0" + raw).hexdigest()


@pytest.mark.parametrize("local_limits", [False, True])
def test_read_uses_strictest_caller_local_and_native_limits(exchange, local_limits):
    requests, _ = exchange
    limits = SubstrateProofLimits(
        maximum_value_bytes=3 if local_limits else 32 * 1024**2,
        maximum_read_values_bytes=4 if local_limits else 64 * 1024**2,
    )
    read(
        verifier(limits=limits),
        maximum_value_bytes=64 * 1024**2,
        maximum_total_value_bytes=128 * 1024**2,
    )
    assert requests[-1]["maximum_value_bytes"] == (3 if local_limits else 16 * 1024**2)
    assert requests[-1]["maximum_total_value_bytes"] == (4 if local_limits else 32 * 1024**2)


@pytest.mark.parametrize("field", ["maximum_value_bytes", "maximum_total_value_bytes"])
@pytest.mark.parametrize("limit", [False, 0, -1, 1.5, "5"])
def test_invalid_caller_limits_do_not_launch(exchange, field, limit):
    requests, _ = exchange
    with pytest.raises(ValueError):
        read(verifier(), **{field: limit})
    assert requests == []


@pytest.mark.parametrize(
    "fault",
    [
        "schema",
        "id",
        "root",
        "version",
        "bool-version",
        "numeric-ok",
        "extra",
        "missing",
        "reordered",
        "duplicate",
        "wrong-key",
        "extra-item-field",
        "odd-hex",
        "upper-hex",
        "non-hex",
        "non-string",
        "per-value",
        "total",
        "partial-error",
        "unknown-error",
    ],
)
def test_read_rejects_malformed_or_partially_successful_results(exchange, fault):
    _, response = exchange
    limits = {}
    if fault == "schema":
        response["schema"] = "umi-substrate-proof-result/1"
    elif fault == "id":
        response["request_id"] = "00" * 32
    elif fault == "root":
        response["state_root"] = "0x" + "22" * 32
    elif fault in {"version", "bool-version"}:
        response["state_version"] = 2 if fault == "version" else True
    elif fault == "numeric-ok":
        response["ok"] = 1
    elif fault == "extra":
        response["unexpected"] = True
    elif fault == "missing":
        response["items"].pop()
    elif fault == "reordered":
        response["items"].reverse()
    elif fault == "duplicate":
        response["items"][1] = response["items"][0]
    elif fault == "wrong-key":
        response["items"][0]["key"] = "0x64"
    elif fault == "extra-item-field":
        response["items"][0]["untrusted"] = True
    elif fault in {"odd-hex", "upper-hex", "non-hex", "non-string"}:
        response["items"][2]["value"] = {
            "odd-hex": "0x1",
            "upper-hex": "0xAB",
            "non-hex": "0xzz",
            "non-string": 12,
        }[fault]
    elif fault == "per-value":
        limits["maximum_value_bytes"] = 1
    elif fault == "total":
        response["items"][1]["value"] = "0x1122"
        limits["maximum_total_value_bytes"] = 3
    elif fault == "partial-error":
        response["ok"] = False
        response["error_code"] = "invalid_proof"
    elif fault == "unknown-error":
        response.clear()
        response.update(schema=READ_RESPONSE_SCHEMA, ok=False, error_code="untrusted detail")
    with pytest.raises(SubstrateProofVerifierError) as error:
        read(verifier(), **limits)
    assert error.value.reason_code == "invalid_sidecar_response"


@pytest.mark.parametrize("code", ["invalid_proof", "duplicate_node", "value_limit"])
def test_read_propagates_bounded_native_rejections(exchange, code):
    _, response = exchange
    response.clear()
    response.update(schema=READ_RESPONSE_SCHEMA, ok=False, error_code=code)
    with pytest.raises(SubstrateProofVerifierError) as error:
        read(verifier())
    assert error.value.reason_code == code


def child(source):
    return subprocess.Popen(
        [sys.executable, "-I", "-B", "-c", source],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )


def test_bounded_exchange_drains_both_pipes_without_deadlock():
    # The child writes more than a pipe before reading the large request.
    process = child(
        "import sys; sys.stdout.buffer.write(b'x' * 262144); sys.stdout.buffer.flush(); "
        "data = sys.stdin.buffer.read(); sys.stdout.buffer.write(str(len(data)).encode())"
    )
    result = _communicate_bounded(
        process,
        b"p" * 262144,
        maximum_response_bytes=300000,
        timeout_seconds=5,
    )
    assert result == b"x" * 262144 + b"262144"
    assert process.returncode == 0


def test_oversized_response_stops_a_child_without_waiting_for_eof():
    process = child(
        "import sys,time; sys.stdout.buffer.write(b'x' * 262144); "
        "sys.stdout.buffer.flush(); time.sleep(30)"
    )
    with pytest.raises(SubstrateProofVerifierError) as error:
        _communicate_bounded(
            process,
            b"p" * 262144,
            maximum_response_bytes=1024,
            timeout_seconds=5,
        )
    assert error.value.reason_code == "invalid_sidecar_response"
    assert process.poll() is not None
    assert process.stdin.closed and process.stdout.closed


def test_closed_stdout_does_not_bypass_process_timeout():
    process = child("import os,time; os.close(0); os.close(1); time.sleep(30)")
    with pytest.raises(subprocess.TimeoutExpired):
        _communicate_bounded(
            process,
            b"p" * 262144,
            maximum_response_bytes=1024,
            timeout_seconds=0.1,
        )
    assert process.poll() is not None
    assert process.stdin.closed and process.stdout.closed
