"""Create the bridge image's fixed native manifest during its root-owned build."""

import hashlib
import os
from pathlib import Path

from umi.bridge.native import IMAGE_MANIFEST, BridgeNativeArtifacts, read_image_artifacts
from umi.protocol import canonical_json_bytes

artifacts = BridgeNativeArtifacts(
    schema="umi-bridge-native-artifacts/1",
    target=os.environ["TARGETPLATFORM"],
    proof_sha256=hashlib.sha256(
        Path("/opt/umi/bin/umi-substrate-proof-verifier").read_bytes()
    ).hexdigest(),
    runtime_sha256=hashlib.sha256(
        Path("/opt/umi/bin/umi-runtime-metadata").read_bytes()
    ).hexdigest(),
)
with IMAGE_MANIFEST.open("xb") as stream:
    stream.write(canonical_json_bytes(artifacts))
IMAGE_MANIFEST.chmod(0o444)
assert read_image_artifacts() == artifacts
