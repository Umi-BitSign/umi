from __future__ import annotations

import errno
import hashlib
import os
import shutil
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from umi import pinned_artifact, substrate_proof
from umi.substrate_proof import (
    SubprocessStorageProofVerifier,
    SubstrateProofLimits,
    SubstrateProofVerifierError,
)

FAKE_SIDECAR = Path(__file__).parent / "fixtures" / "proof_sidecar_fake.sh"


def executable(tmp_path: Path, mode: str, *, copy: bool = False) -> tuple[Path, str]:
    if copy:
        path = tmp_path / f"proof-sidecar-{mode}"
        shutil.copyfile(FAKE_SIDECAR, path)
        path.chmod(0o700)
    else:
        # Executing the one fixed path avoids flaky macOS launch-services work
        # for a newly generated executable in every parameterized case.
        path = FAKE_SIDECAR.resolve()
    return path, hashlib.sha256(path.read_bytes()).hexdigest()


def test_verify_many_uses_content_pinned_one_shot_protocol(tmp_path: Path) -> None:
    path, digest = executable(tmp_path, "success-many")
    verifier = SubprocessStorageProofVerifier(
        binary_path=path,
        expected_sha256=digest,
        timeout_seconds=1,
    )

    assert (
        verifier.verify_many(
            state_root=b"\x11" * 32,
            items=((b"b", b""), (b"a", None)),
            proof=(b"node-1", b"node-2"),
        )
        is True
    )
    assert verifier.binary_path == path
    assert verifier.expected_sha256 == digest


def test_single_item_callback_wraps_verify_many(tmp_path: Path) -> None:
    path, digest = executable(tmp_path, "success-single")
    verifier = SubprocessStorageProofVerifier(binary_path=path, expected_sha256=digest)
    assert (
        verifier(
            state_root=b"r" * 32,
            storage_key=b"key",
            expected_value=b"value",
            proof=(b"proof",),
        )
        is True
    )


def test_exact_success_reuse_binds_root_claims_nodes_and_instance(tmp_path, monkeypatch):
    path, digest = executable(tmp_path, "success-single")
    verifier = SubprocessStorageProofVerifier(binary_path=path, expected_sha256=digest)
    invoke = verifier._invoke
    calls = []

    def counted(raw, *, request_id):
        calls.append(request_id)
        return invoke(raw, request_id=request_id)

    monkeypatch.setattr(verifier, "_invoke", counted)
    request = dict(state_root=b"r" * 32, items=((b"key", b"value"),), proof=(b"proof",))
    assert verifier.verify_many(**request)
    assert verifier.verify_many(**request)
    assert len(calls) == 1
    assert verifier.verify_many(**(request | {"state_root": b"s" * 32}))
    assert len(calls) == 2
    for changed in (
        {"items": ((b"different-key", b"value"),)},
        {"items": ((b"key", None),)},
        {"items": ((b"key", b""),)},
        {"proof": (b"error-invalid_proof",)},
    ):
        before = len(calls)
        with pytest.raises(SubstrateProofVerifierError):
            verifier.verify_many(**(request | changed))
        assert len(calls) == before + 1
    assert verifier.verify_many(**request)
    assert len(calls) == 6
    restarted = SubprocessStorageProofVerifier(binary_path=path, expected_sha256=digest)
    monkeypatch.setattr(restarted, "_invoke", counted)
    assert restarted.verify_many(**request)
    assert len(calls) == 7


def test_failed_proofs_never_enter_success_reuse(tmp_path, monkeypatch):
    path, digest = executable(tmp_path, "success-single")
    verifier = SubprocessStorageProofVerifier(binary_path=path, expected_sha256=digest)
    invoke = verifier._invoke
    calls = []

    def counted(raw, *, request_id):
        calls.append(request_id)
        return invoke(raw, request_id=request_id)

    monkeypatch.setattr(verifier, "_invoke", counted)
    for _ in range(2):
        with pytest.raises(SubstrateProofVerifierError, match="invalid_proof"):
            verifier.verify_many(
                state_root=b"r" * 32,
                items=((b"key", None),),
                proof=(b"error-invalid_proof",),
            )
    assert len(calls) == 2 and not verifier._successful_proofs


def test_inherited_verifier_does_not_acquire_parent_lock_or_reuse_success(tmp_path, monkeypatch):
    path, digest = executable(tmp_path, "success-single")
    verifier = SubprocessStorageProofVerifier(binary_path=path, expected_sha256=digest)
    request = dict(state_root=b"r" * 32, items=((b"key", b"value"),), proof=(b"proof",))
    assert verifier.verify_many(**request)
    parent_cache = dict(verifier._successful_proofs)
    monkeypatch.setattr(os, "getpid", lambda: verifier._pid + 1)

    class ParentLock:
        def __enter__(self):
            pytest.fail("inherited lock must not be acquired")

        def __exit__(self, *_args):
            pass

    monkeypatch.setattr(verifier, "_success_lock", ParentLock())
    calls = []
    invoke = verifier._invoke

    def counted(raw, *, request_id):
        calls.append(request_id)
        return invoke(raw, request_id=request_id)

    monkeypatch.setattr(verifier, "_invoke", counted)
    assert verifier.verify_many(**request)
    assert verifier.verify_many(**request)
    assert len(calls) == 2
    assert verifier._successful_proofs == parent_cache


def test_cached_success_still_checks_binary_and_current_bounds(tmp_path):
    path, digest = executable(tmp_path, "success-single", copy=True)
    verifier = SubprocessStorageProofVerifier(binary_path=path, expected_sha256=digest)
    request = dict(state_root=b"r" * 32, items=((b"key", b"value"),), proof=(b"proof",))
    assert verifier.verify_many(**request)
    original_limits = verifier._limits
    verifier._limits = replace(original_limits, maximum_request_bytes=4)
    with pytest.raises(ValueError, match="encoded proof request"):
        verifier.verify_many(**request)
    verifier._limits = original_limits
    path.write_bytes(path.read_bytes() + b"\n")
    with pytest.raises(SubstrateProofVerifierError, match="binary_hash_mismatch"):
        verifier.verify_many(**request)


def test_success_reuse_is_bounded_and_evicted_proofs_are_checked_again(tmp_path, monkeypatch):
    path, digest = executable(tmp_path, "success-single")
    verifier = SubprocessStorageProofVerifier(binary_path=path, expected_sha256=digest)
    calls = []

    def affirm(raw, *, request_id):
        calls.append(request_id)
        return True

    monkeypatch.setattr(verifier, "_invoke", affirm)
    for height in range(65):
        assert verifier.verify_many(
            state_root=height.to_bytes(32, "big"),
            items=((b"key", b"value"),),
            proof=(b"proof",),
        )
    assert len(verifier._successful_proofs) == 64 and len(calls) == 65
    assert verifier.verify_many(
        state_root=bytes(32),
        items=((b"key", b"value"),),
        proof=(b"proof",),
    )
    assert len(calls) == 66 and len(verifier._successful_proofs) == 64


@pytest.mark.parametrize("state_version", [0, 1])
def test_extrinsics_root_callback_uses_the_same_pinned_sidecar(
    tmp_path: Path, state_version: int
) -> None:
    path, digest = executable(tmp_path, "extrinsics-root")
    verifier = SubprocessStorageProofVerifier(binary_path=path, expected_sha256=digest)
    assert (
        verifier.verify_extrinsics_root(
            expected_root=b"\x22" * 32,
            extrinsics=(b"first", b"second"),
            state_version=state_version,
        )
        is True
    )

    with pytest.raises(SubstrateProofVerifierError) as mismatch:
        verifier.verify_extrinsics_root(
            expected_root=b"\x22" * 32,
            extrinsics=(b"invalid-root",),
            state_version=state_version,
        )
    assert mismatch.value.reason_code == "invalid_extrinsics_root"


@pytest.mark.parametrize(
    ("error_code",),
    [("invalid_input",), ("unsupported_state_version",), ("duplicate_node",), ("invalid_proof",)],
)
def test_sidecar_rejections_are_stable_fail_closed_errors(tmp_path: Path, error_code: str) -> None:
    path, digest = executable(tmp_path, f"error-{error_code}")
    verifier = SubprocessStorageProofVerifier(binary_path=path, expected_sha256=digest)
    with pytest.raises(SubstrateProofVerifierError) as error:
        verifier(
            state_root=b"r" * 32,
            storage_key=b"key",
            expected_value=None,
            proof=(f"error-{error_code}".encode(),),
        )
    assert error.value.reason_code == error_code


@pytest.mark.parametrize(
    "mode",
    [
        "malformed-not-json",
        "malformed-empty-object",
        "malformed-wrong-id",
        "malformed-extra",
    ],
)
def test_malformed_or_extra_sidecar_output_is_rejected(tmp_path: Path, mode: str) -> None:
    path, digest = executable(tmp_path, mode)
    verifier = SubprocessStorageProofVerifier(binary_path=path, expected_sha256=digest)
    with pytest.raises(SubstrateProofVerifierError) as error:
        verifier(
            state_root=b"r" * 32,
            storage_key=b"key",
            expected_value=None,
            proof=(mode.encode(),),
        )
    assert error.value.reason_code == "invalid_sidecar_response"


def test_timeout_kills_the_sidecar_process_group(tmp_path: Path) -> None:
    path, digest = executable(tmp_path, "timeout")
    verifier = SubprocessStorageProofVerifier(
        binary_path=path,
        expected_sha256=digest,
        timeout_seconds=0.05,
    )
    with pytest.raises(SubstrateProofVerifierError) as error:
        verifier(
            state_root=b"r" * 32,
            storage_key=b"key",
            expected_value=None,
            proof=(b"timeout",),
        )
    assert error.value.reason_code == "sidecar_timeout"


def test_nonzero_sidecar_exit_is_rejected_without_exposing_stderr(tmp_path: Path) -> None:
    path, digest = executable(tmp_path, "nonzero")
    verifier = SubprocessStorageProofVerifier(binary_path=path, expected_sha256=digest)
    with pytest.raises(SubstrateProofVerifierError) as error:
        verifier(
            state_root=b"r" * 32,
            storage_key=b"key",
            expected_value=None,
            proof=(b"nonzero",),
        )
    assert error.value.reason_code == "sidecar_failed"
    assert "sensitive" not in str(error.value)


def test_binary_must_be_absolute_executable_immutable_and_hash_matched(tmp_path: Path) -> None:
    path, digest = executable(tmp_path, "unused", copy=True)
    with pytest.raises(ValueError, match="absolute"):
        SubprocessStorageProofVerifier(binary_path="relative", expected_sha256=digest)
    with pytest.raises(SubstrateProofVerifierError) as error:
        SubprocessStorageProofVerifier(binary_path=path, expected_sha256="00" * 32)
    assert error.value.reason_code == "binary_hash_mismatch"

    path.chmod(0o722)
    with pytest.raises(SubstrateProofVerifierError) as error:
        SubprocessStorageProofVerifier(binary_path=path, expected_sha256=digest)
    assert error.value.reason_code == "unsafe_binary"


def test_binary_is_rehashed_immediately_before_each_execution(tmp_path: Path) -> None:
    path, digest = executable(tmp_path, "success-many", copy=True)
    verifier = SubprocessStorageProofVerifier(binary_path=path, expected_sha256=digest)
    path.write_text(path.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    with pytest.raises(SubstrateProofVerifierError) as error:
        verifier.verify_many(
            state_root=b"\x11" * 32,
            items=((b"a", None), (b"b", b"")),
            proof=(b"node-1", b"node-2"),
        )
    assert error.value.reason_code == "binary_hash_mismatch"


def test_execution_uses_private_copy_of_the_descriptor_that_was_hashed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path, digest = executable(tmp_path, "success-many", copy=True)
    verifier = SubprocessStorageProofVerifier(binary_path=path, expected_sha256=digest)
    real_popen = subprocess.Popen
    invoked: list[Path] = []

    def swapping_popen(command, *args, **kwargs):
        invoked.append(Path(command[0]))
        path.write_text("#!/bin/sh\nexit 97\n", encoding="utf-8")
        path.chmod(0o700)
        return real_popen(command, *args, **kwargs)

    monkeypatch.setattr("umi.substrate_proof.subprocess.Popen", swapping_popen)
    assert verifier.verify_many(
        state_root=b"\x11" * 32,
        items=((b"a", None), (b"b", b"")),
        proof=(b"node-1", b"node-2"),
    )
    assert len(invoked) == 1
    assert invoked[0] != path
    assert invoked[0].parent != path.parent


@pytest.mark.skipif(sys.platform != "linux", reason="Linux executable write-descriptor exclusion")
@pytest.mark.parametrize("reject_proof", [False, True])
def test_busy_staged_executable_retries_same_verified_copy(tmp_path, monkeypatch, reject_proof):
    path, digest = executable(tmp_path, "busy-copy")
    verifier = SubprocessStorageProofVerifier(binary_path=path, expected_sha256=digest)
    original_write = pinned_artifact._write_all
    original_popen = subprocess.Popen
    held = []
    attempts = []
    errors = []

    def retain_write_descriptor(fd, data):
        original_write(fd, data)
        if not held:
            held.append(os.dup(fd))

    def launch(command, **kwargs):
        staged = Path(command[0])
        attempts.append(
            (staged, staged.stat().st_ino, hashlib.sha256(staged.read_bytes()).hexdigest())
        )
        try:
            return original_popen(command, **kwargs)
        except OSError as error:
            errors.append(error.errno)
            assert error.errno == errno.ETXTBSY
            os.close(held.pop())
            raise

    monkeypatch.setattr(pinned_artifact, "_write_all", retain_write_descriptor)
    monkeypatch.setattr(substrate_proof.subprocess, "Popen", launch)
    try:

        def verify():
            return verifier(
                state_root=b"r" * 32,
                storage_key=b"key",
                expected_value=b"value",
                proof=(b"error-invalid_proof" if reject_proof else b"proof",),
            )

        if reject_proof:
            with pytest.raises(SubstrateProofVerifierError, match="invalid_proof"):
                verify()
        else:
            assert verify()
        assert errors == [errno.ETXTBSY]
        assert len(attempts) == 2 and attempts[0] == attempts[1]
        assert attempts[0][2] == digest
        assert not attempts[0][0].exists()
    finally:
        for fd in held:
            os.close(fd)


@pytest.mark.parametrize("code", [errno.EACCES, errno.ENOENT, errno.EAGAIN, errno.ENOMEM])
def test_other_sidecar_start_errors_are_not_retried(tmp_path, monkeypatch, code):
    path, digest = executable(tmp_path, "launch-error")
    verifier = SubprocessStorageProofVerifier(binary_path=path, expected_sha256=digest)
    attempts = []

    def launch(*args, **kwargs):
        attempts.append(args)
        raise OSError(code, "private-path")

    monkeypatch.setattr(substrate_proof.subprocess, "Popen", launch)
    with pytest.raises(SubstrateProofVerifierError, match="sidecar_start_failed") as error:
        verifier(state_root=b"r" * 32, storage_key=b"key", expected_value=None, proof=(b"proof",))
    assert len(attempts) == 1
    assert error.value.__cause__.errno == code
    assert "private-path" not in str(error.value)


def test_busy_sidecar_start_obeys_original_total_budget(tmp_path, monkeypatch):
    path, digest = executable(tmp_path, "busy-budget")
    verifier = SubprocessStorageProofVerifier(
        binary_path=path, expected_sha256=digest, timeout_seconds=0.05
    )
    clock = [0.0]
    sleeps = []

    def launch(*args, **kwargs):
        raise OSError(errno.ETXTBSY, "busy")

    def sleep(seconds):
        sleeps.append(seconds)
        clock[0] += seconds

    monkeypatch.setattr(substrate_proof.subprocess, "Popen", launch)
    monkeypatch.setattr(substrate_proof.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(substrate_proof.time, "sleep", sleep)
    with pytest.raises(SubstrateProofVerifierError, match="sidecar_start_failed") as error:
        verifier(state_root=b"r" * 32, storage_key=b"key", expected_value=None, proof=(b"proof",))
    assert error.value.__cause__.errno == errno.ETXTBSY
    assert sum(sleeps) == pytest.approx(0.05)


def test_python_preflight_enforces_shape_uniqueness_and_limits(tmp_path: Path) -> None:
    path, digest = executable(tmp_path, "unused")
    verifier = SubprocessStorageProofVerifier(
        binary_path=path,
        expected_sha256=digest,
        limits=SubstrateProofLimits(
            maximum_items=2,
            maximum_key_bytes=2,
            maximum_value_bytes=2,
            maximum_proof_nodes=2,
            maximum_proof_node_bytes=2,
            maximum_proof_bytes=3,
            maximum_request_bytes=1_024,
            maximum_response_bytes=1_024,
        ),
    )
    common = {"state_root": b"r" * 32, "proof": (b"p",)}
    with pytest.raises(ValueError, match="unique"):
        verifier.verify_many(items=((b"a", None), (b"a", b"")), **common)
    with pytest.raises(ValueError, match="byte limit"):
        verifier.verify_many(items=((b"key", None),), **common)
    with pytest.raises(ValueError, match="duplicate node"):
        verifier.verify_many(
            state_root=b"r" * 32,
            items=((b"a", None),),
            proof=(b"p", b"p"),
        )
    with pytest.raises(ValueError, match="total byte limit"):
        verifier.verify_many(
            state_root=b"r" * 32,
            items=((b"a", None),),
            proof=(b"aa", b"bb"),
        )


@pytest.mark.parametrize("size", [3 * 1024 * 1024, 16 * 1024 * 1024])
def test_preflight_accepts_external_values_up_to_the_value_limit(tmp_path: Path, size: int) -> None:
    path, digest = executable(tmp_path, "unused")
    verifier = SubprocessStorageProofVerifier(binary_path=path, expected_sha256=digest)
    value = b"v" * size
    items = ((b":code", value),)
    # This tests Python admission only. Actual trie membership is checked in Rust.
    assert verifier._preflight(state_root=b"r" * 32, items=items, proof=(value,)) == items


def test_default_external_value_proof_limits_remain_bounded(tmp_path: Path) -> None:
    path, digest = executable(tmp_path, "unused")
    verifier = SubprocessStorageProofVerifier(binary_path=path, expected_sha256=digest)
    limits = SubstrateProofLimits()
    assert limits.maximum_proof_node_bytes == limits.maximum_value_bytes == 16 * 1024 * 1024
    assert limits.maximum_proof_bytes == 32 * 1024 * 1024
    common = {"state_root": b"r" * 32, "items": ((b":code", None),)}
    with pytest.raises(ValueError, match="node byte limit"):
        verifier._preflight(proof=(b"v" * (limits.maximum_proof_node_bytes + 1),), **common)
    with pytest.raises(ValueError, match="total byte limit"):
        verifier._preflight(
            proof=(
                b"a" * limits.maximum_proof_node_bytes,
                b"b" * limits.maximum_proof_node_bytes,
                b"c",
            ),
            **common,
        )


def test_extrinsics_root_preflight_enforces_body_shape_and_limits(tmp_path: Path) -> None:
    path, digest = executable(tmp_path, "unused")
    verifier = SubprocessStorageProofVerifier(
        binary_path=path,
        expected_sha256=digest,
        limits=SubstrateProofLimits(
            maximum_extrinsics=1,
            maximum_extrinsic_bytes=3,
            maximum_block_body_bytes=3,
            maximum_request_bytes=1_024,
        ),
    )
    with pytest.raises(ValueError, match="count limit"):
        verifier.verify_extrinsics_root(
            expected_root=b"r" * 32,
            extrinsics=(b"a", b"b"),
            state_version=1,
        )
    with pytest.raises(ValueError, match="byte limit"):
        verifier.verify_extrinsics_root(
            expected_root=b"r" * 32,
            extrinsics=(b"four",),
            state_version=1,
        )
    with pytest.raises(ValueError, match="state_version"):
        verifier.verify_extrinsics_root(
            expected_root=b"r" * 32,
            extrinsics=(),
            state_version=2,
        )


def test_limit_configuration_and_constructor_inputs_are_strict(tmp_path: Path) -> None:
    path, digest = executable(tmp_path, "unused")
    with pytest.raises(ValueError, match="positive integer"):
        SubstrateProofLimits(maximum_items=True)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="lowercase hexadecimal"):
        SubprocessStorageProofVerifier(binary_path=path, expected_sha256=digest.upper())
    with pytest.raises(ValueError, match="positive finite"):
        SubprocessStorageProofVerifier(
            binary_path=path,
            expected_sha256=digest,
            timeout_seconds=float("inf"),
        )
