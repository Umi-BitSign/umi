"""A rebuild must bind actual bytes, immutable source and the native version."""

import copy
import hashlib
import runpy
from pathlib import Path

import pytest

VALIDATE = runpy.run_path(str(Path(__file__).parents[1] / "tools/qualify_runtime_source.py"))[
    "validate_build"
]
REVISION = "ab" * 20
RAW = bytes.fromhex("52bc537646db8e05") + b"synthetic test bytes; no native proof claim"
CODE = hashlib.sha256(RAW).hexdigest()


@pytest.fixture
def build():
    return {
        "commit": REVISION,
        "info": {"git": {"commit": REVISION}, "profile": "production"},
        "pkg": "node-subtensor-runtime",
        "gen": "srtool v0.18.3",
        "rustc": "rustc 1.89.0 (29483883e 2025-08-04)",
        "sha256": "0x" + CODE,
        "runtimes": {"compressed": {"subwasm": {"core_version": {"specVersion": 483}}}},
    }


def check(raw, build):
    return VALIDATE(raw, build, revision=REVISION, code_sha256=CODE, spec_version=483)


def test_exact_build_match_confers_no_native_or_reward_authority(build):
    result = check(RAW, build)
    assert result["source_build_correspondence_established"]
    assert result["runtime_bytes"] == len(RAW)
    assert not result["native_input_identity_authenticated_by_this_tool"]
    assert not result["reward_semantics_qualified"]
    assert not result["profile_authorized"]
    assert not result["transaction_submitted"]


def test_same_source_and_spec_cannot_qualify_different_code(build):
    raw = RAW + b"changed code"
    build["sha256"] = "0x" + hashlib.sha256(raw).hexdigest()
    with pytest.raises(ValueError, match="differ from the native code"):
        check(raw, build)


def test_claimed_digest_cannot_replace_actual_built_bytes(build):
    with pytest.raises(ValueError, match="actual built bytes"):
        check(RAW + b"changed code", build)


@pytest.mark.parametrize(
    "path,value",
    [
        (("commit",), "cd" * 20),
        (("info", "git", "commit"), "cd" * 20),
        (("info", "profile"), "release"),
        (("pkg",), "different-runtime"),
        (("gen",), "srtool v0.18.4"),
        (("rustc",), "rustc 1.90.0"),
        (("runtimes", "compressed", "subwasm", "core_version", "specVersion"), 482),
    ],
)
def test_build_provenance_and_native_version_must_all_match(build, path, value):
    build = copy.deepcopy(build)
    parent = build
    for key in path[:-1]:
        parent = parent[key]
    parent[path[-1]] = value
    with pytest.raises(ValueError):
        check(RAW, build)


def test_an_uncompressed_or_empty_artifact_refuses(build):
    with pytest.raises(ValueError, match="expected compressed Wasm"):
        check(b"\x00asm", build)
