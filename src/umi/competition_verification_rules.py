"""Release guard for compatible durable native-verification semantics.

The checked source manifest is deliberately separate from the receipt ABI.
A tested compatible verifier release updates its manifest and keeps its ABI;
a change to accepted semantics must advance the ABI. Unrelated modules do not
participate. This guard runs before any native verdict can be borrowed.
"""

from __future__ import annotations

import hashlib
import json
from functools import lru_cache
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as distribution_version
from pathlib import Path

VERIFICATION_SEMANTICS = "umi-native-request-verification/1"
# Additive wire formats use distinct native namespaces. A qualified /1 verdict
# remains true for unchanged /1 bytes; never invalidate all completed work just
# because a new, previously unaccepted evidence format becomes readable.
VERIFICATION_EXTENSIONS = {
    "archived_execution_shared_incumbent_v2": "umi-native-shared-incumbent/2",
    "shared_incumbent_source_terminal_v2": "umi-native-shared-incumbent/2",
    "shared_incumbent_source_participant_v2": "umi-native-shared-incumbent/2",
}


def verify_dependency_manifest(directory: Path, manifest: dict) -> str:
    if (
        manifest.get("schema") != "umi-native-verification-dependencies/1"
        or manifest.get("abi") != VERIFICATION_SEMANTICS
        or manifest.get("extensions") != VERIFICATION_EXTENSIONS
        or not manifest.get("sources")
        or not manifest.get("compatibility_basis")
        or not manifest.get("external_distributions")
    ):
        raise RuntimeError("native verification rules require a qualified dependency manifest")
    for name, expected in manifest["sources"].items():
        path = Path(name)
        if path.name != name or path.suffix != ".py":
            raise RuntimeError("native verification dependency has an invalid source path")
        actual = hashlib.sha256((directory / name).read_bytes()).hexdigest()
        if actual != expected:
            raise RuntimeError(
                "native verification dependency changed without qualified ABI compatibility: "
                + name
            )
    for name, qualified in manifest["external_distributions"].items():
        if (
            not isinstance(qualified, list)
            or not qualified
            or any(not isinstance(value, str) or not value for value in qualified)
        ):
            raise RuntimeError("native verification has invalid qualified external versions")
        try:
            actual = distribution_version(name)
        except PackageNotFoundError as error:
            raise RuntimeError("native verification dependency is unavailable: " + name) from error
        if actual not in qualified:
            raise RuntimeError(
                "native verification external dependency changed without qualified ABI "
                f"compatibility: {name}=={actual}"
            )
    return hashlib.sha256(VERIFICATION_SEMANTICS.encode()).hexdigest()


@lru_cache(maxsize=1)
def runtime_identity():
    directory = Path(__file__).parent
    manifest = json.loads((directory / "competition_verification_rules.json").read_bytes())
    return verify_dependency_manifest(directory, manifest)
