"""Native signing tools shipped inside the signed, read-only bridge image.

The fixed manifest is covered by the supervisor's authenticated image digest.
It is not an operator-supplied configuration or a network download. The native
adapters separately hash the executable bytes before running them.
"""

from __future__ import annotations

import os
import platform
import stat
from pathlib import Path
from typing import Literal

from pydantic import Field

from ..protocol import Hex32, StrictProtocolModel, canonical_json_bytes
from ..runtime_metadata import RuntimeMetadataExecutor
from ..substrate_proof import SubprocessStorageProofVerifier
from ..validator_chain import BittensorRawJsonRpc
from .policy import _require
from .receipts import BridgeReceiptReader
from .signing import BridgeFinality, BridgeSigningStateReader

IMAGE_MANIFEST = Path("/opt/umi/bridge-native-artifacts.json")
_IMAGE_OWNER_UID = 0
_TARGETS = {"x86_64": "linux/amd64", "aarch64": "linux/arm64"}


class BridgeNativeArtifacts(StrictProtocolModel):
    schema_: Literal["umi-bridge-native-artifacts/1"] = Field(alias="schema")
    target: Literal["linux/amd64", "linux/arm64"]
    proof_sha256: Hex32
    runtime_sha256: Hex32


def read_image_artifacts() -> BridgeNativeArtifacts:
    _require(
        platform.system() == "Linux" and platform.machine() in _TARGETS,
        "native_signing_platform_unsupported",
    )
    path = IMAGE_MANIFEST
    _require(path.is_absolute() and path.resolve() == path, "native_signing_manifest_path_unsafe")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        _require(
            stat.S_ISREG(before.st_mode)
            and before.st_uid == _IMAGE_OWNER_UID
            and before.st_nlink == 1
            and stat.S_IMODE(before.st_mode) == 0o444
            and 0 < before.st_size <= 4096,
            "native_signing_manifest_unsafe",
        )
        raw = stream.read(4097)
        after = os.fstat(stream.fileno())
        stable_fields = (
            "st_dev",
            "st_ino",
            "st_uid",
            "st_gid",
            "st_mode",
            "st_nlink",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
        _require(
            all(getattr(before, name) == getattr(after, name) for name in stable_fields)
            and len(raw) == before.st_size,
            "native_signing_manifest_changed",
        )
    artifacts = BridgeNativeArtifacts.model_validate_json(raw)
    _require(canonical_json_bytes(artifacts) == raw, "native_signing_manifest_noncanonical")
    _require(
        artifacts.target == _TARGETS[platform.machine()], "native_signing_manifest_target_mismatch"
    )
    return artifacts


def _tools():
    artifacts = read_image_artifacts()
    return dict(
        verifier=SubprocessStorageProofVerifier(
            binary_path="/opt/umi/bin/umi-substrate-proof-verifier",
            expected_sha256=artifacts.proof_sha256,
        ),
        runtime_executor=RuntimeMetadataExecutor(
            binary_path=Path("/opt/umi/bin/umi-runtime-metadata"),
            expected_sha256=artifacts.runtime_sha256,
        ),
    )


def signing_reader(*, client, finality: BridgeFinality, clock) -> BridgeSigningStateReader:
    return BridgeSigningStateReader(
        finality=finality, rpc=BittensorRawJsonRpc(client), clock=clock, **_tools()
    )


def receipt_reader(*, client, finality: BridgeFinality) -> BridgeReceiptReader:
    return BridgeReceiptReader(finality=finality, rpc=BittensorRawJsonRpc(client), **_tools())
