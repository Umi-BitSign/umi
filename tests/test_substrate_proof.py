from __future__ import annotations

import hashlib
import shutil
import subprocess
from pathlib import Path

import pytest

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


def test_extrinsics_root_callback_uses_the_same_pinned_sidecar(tmp_path: Path) -> None:
    path, digest = executable(tmp_path, "extrinsics-root")
    verifier = SubprocessStorageProofVerifier(binary_path=path, expected_sha256=digest)
    assert (
        verifier.verify_extrinsics_root(
            expected_root=b"\x22" * 32,
            extrinsics=(b"first", b"second"),
            state_version=1,
        )
        is True
    )

    with pytest.raises(SubstrateProofVerifierError) as mismatch:
        verifier.verify_extrinsics_root(
            expected_root=b"\x22" * 32,
            extrinsics=(b"invalid-root",),
            state_version=1,
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
            state_version=0,
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
