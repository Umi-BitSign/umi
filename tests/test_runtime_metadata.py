from __future__ import annotations

import hashlib
import json
import os
import sys
from dataclasses import replace
from types import SimpleNamespace

import pytest

from umi.chain_evidence import FinalizedSnapshotRef, StorageEvidence
from umi.runtime_metadata import RuntimeMetadataError, RuntimeMetadataExecutor


@pytest.fixture
def snapshot():
    return FinalizedSnapshotRef(123, "0x" + "11" * 32, "0x" + "22" * 32, "0x" + "33" * 32)


def evidence(snapshot, key=b":code", value=b"verified wasm"):
    return StorageEvidence(
        snapshot=snapshot,
        storage_key=key,
        value=value,
        proof=(b"proof",),
        verifier=lambda **kwargs: True,
    )


def response(code=b"verified wasm"):
    metadata = b"meta\x0e-test-codec"
    return {
        "schema": "umi-runtime-metadata-execution/1",
        "runtime_code_sha256": hashlib.sha256(code).hexdigest(),
        "metadata_sha256": hashlib.sha256(metadata).hexdigest(),
        "metadata_hex": metadata.hex(),
        "spec_version": 459,
        "transaction_version": 1,
        "state_version": 1,
        "chain_submission_authorized": False,
    }


@pytest.fixture
def executor(monkeypatch, tmp_path):
    executor = RuntimeMetadataExecutor(
        binary_path=tmp_path / "not-executed", expected_sha256="a" * 64
    )
    monkeypatch.setattr(
        executor, "_invoke", lambda code: json.dumps(response(code)).encode() + b"\n"
    )
    monkeypatch.setattr(
        "umi.runtime_metadata.bittensor_core.Runtime",
        lambda metadata, spec, transaction, **kwargs: SimpleNamespace(
            spec_version=spec, transaction_version=transaction, constant=lambda *args: 42
        ),
    )
    return executor


def test_proven_runtime_has_distinct_non_signing_mode(snapshot, executor):
    proof = evidence(snapshot)
    result = executor.execute(snapshot, proof)
    assert result.storage_codec_mode == "executed_runtime/1"
    assert result.snapshot == snapshot and result.code_evidence is proof
    assert result.pin.spec_version == 459
    assert result.executor_sha256 == executor.expected_sha256
    assert json.loads(result.runtime_version_bytes)["specVersion"] == 459


@pytest.mark.parametrize("key,value", [(b"other", b"code"), (b":code", None), (b":code", b"")])
def test_only_code_membership_is_accepted(snapshot, executor, key, value):
    with pytest.raises(RuntimeMetadataError, match="runtime_code_evidence_invalid"):
        executor.execute(snapshot, evidence(snapshot, key, value))


def test_other_snapshot_rejected_before_execution(snapshot, executor, monkeypatch):
    monkeypatch.setattr(executor, "_invoke", lambda code: pytest.fail("executed mismatched proof"))
    with pytest.raises(RuntimeMetadataError, match="runtime_code_evidence_invalid"):
        executor.execute(replace(snapshot, block_number=124), evidence(snapshot))


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema", "other"),
        ("runtime_code_sha256", "0" * 64),
        ("metadata_sha256", "0" * 64),
        ("metadata_hex", "00"),
        ("metadata_hex", "6d 65 74 61 0e"),
        ("spec_version", True),
        ("spec_version", 0),
        ("spec_version", 2**32),
        ("transaction_version", 0),
        ("state_version", 0),
        ("state_version", True),
        ("chain_submission_authorized", True),
        ("chain_submission_authorized", 0),
        ("unknown", 1),
    ],
)
def test_execution_output_binding(snapshot, executor, monkeypatch, field, value):
    output = response()
    output[field] = value
    monkeypatch.setattr(executor, "_invoke", lambda code: json.dumps(output).encode() + b"\n")
    with pytest.raises(RuntimeMetadataError, match="runtime_execution_response_invalid"):
        executor.execute(snapshot, evidence(snapshot))


@pytest.mark.parametrize("raw", [b"", b"{}", b"{}\n{}\n", b"null\n", b"[]\n", b"bad\n"])
def test_output_framing(snapshot, executor, monkeypatch, raw):
    monkeypatch.setattr(executor, "_invoke", lambda code: raw)
    with pytest.raises(RuntimeMetadataError, match="runtime_execution_response_invalid"):
        executor.execute(snapshot, evidence(snapshot))


def test_wrong_ss58_rejected(snapshot, executor, monkeypatch):
    monkeypatch.setattr(
        "umi.runtime_metadata.bittensor_core.Runtime",
        lambda *args, **kwargs: SimpleNamespace(
            spec_version=459, transaction_version=1, constant=lambda *args: 0
        ),
    )
    with pytest.raises(RuntimeMetadataError, match="runtime_execution_response_invalid"):
        executor.execute(snapshot, evidence(snapshot))


@pytest.mark.parametrize("timeout", [0, -1, True, float("inf"), float("nan"), 46])
def test_timeout_bounds(tmp_path, timeout):
    with pytest.raises(ValueError):
        RuntimeMetadataExecutor(
            binary_path=tmp_path / "tool", expected_sha256="a" * 64, timeout_seconds=timeout
        )


def executable(tmp_path, body):
    script = tmp_path / "executor"
    script.write_text(f"#!{sys.executable}\n" + body)
    script.chmod(0o500)
    return script, hashlib.sha256(script.read_bytes()).hexdigest()


@pytest.mark.skipif(os.name != "posix", reason="Unix executor")
def test_pinned_subprocess_roundtrip(tmp_path, snapshot, monkeypatch):
    script, digest = executable(
        tmp_path,
        "import sys\nsys.stdin.buffer.read()\nprint(" + repr(json.dumps(response())) + ")\n",
    )
    executor = RuntimeMetadataExecutor(binary_path=script, expected_sha256=digest)
    assert json.loads(executor._invoke(b"verified wasm")) == response()
    with pytest.raises(RuntimeMetadataError):
        RuntimeMetadataExecutor(binary_path=script, expected_sha256="0" * 64)._invoke(b"code")
    link = tmp_path / "link"
    link.symlink_to(script)
    with pytest.raises(RuntimeMetadataError):
        RuntimeMetadataExecutor(binary_path=link, expected_sha256=digest)._invoke(b"code")


@pytest.mark.skipif(os.name != "posix", reason="Unix executor")
def test_subprocess_timeout_and_failure(tmp_path):
    script, digest = executable(tmp_path, "import time\ntime.sleep(10)\n")
    with pytest.raises(RuntimeMetadataError, match="runtime_execution_timeout"):
        RuntimeMetadataExecutor(
            binary_path=script, expected_sha256=digest, timeout_seconds=0.05
        )._invoke(b"code")
    script.chmod(0o700)
    script.write_text(f"#!{sys.executable}\nraise SystemExit(7)\n")
    script.chmod(0o500)
    with pytest.raises(RuntimeMetadataError, match="runtime_execution_failed"):
        RuntimeMetadataExecutor(
            binary_path=script, expected_sha256=hashlib.sha256(script.read_bytes()).hexdigest()
        )._invoke(b"code")
