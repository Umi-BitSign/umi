from __future__ import annotations

import json
from fractions import Fraction
from types import SimpleNamespace

import bittensor as bt
import pytest

import umi.tools as tools_module
from umi.artifacts import PublisherCapacityStatement, publisher_capacity_digest
from umi.media import FrameDigestResult, MediaInspectionResult, MediaProfile
from umi.protocol import canonical_json_bytes
from umi.tools import (
    _inspect_media,
    _parser,
    _policy_hash,
    _run_shadow_rehearsal,
    _verify_capacity,
    _verify_public_batch,
)

from .test_artifacts import capacity_data, ground_truth_data, manifest_data
from .test_policy import make_policy


def test_policy_hash_tool_reads_only_canonical_policy(tmp_path) -> None:
    policy = make_policy()
    path = tmp_path / "policy.json"
    path.write_bytes(canonical_json_bytes(policy))
    args = _parser().parse_args(["policy-hash", "--policy", str(path)])

    record = _policy_hash(args)
    assert record["policy_sha256"]
    assert record["translation_weights_active"] is False
    assert record["protocol_conformance"] is False
    assert record["activation_evidence"] is False

    path.write_bytes(json.dumps(policy.model_dump(mode="json", by_alias=True), indent=2).encode())
    with pytest.raises(ValueError, match="canonical JSON"):
        _policy_hash(args)


def test_tool_parser_requires_verification_inputs() -> None:
    parsed = _parser().parse_args(
        [
            "verify-capacity",
            "--policy",
            "policy.json",
            "--statement",
            "capacity.json",
            "--scheme",
            "sr25519",
            "--signature",
            "0x" + "00" * 64,
        ]
    )
    assert parsed.command == "verify-capacity"

    with pytest.raises(SystemExit):
        _parser().parse_args(["verify-capacity", "--policy", "policy.json"])

    shadow = _parser().parse_args(
        ["run-shadow-rehearsal", "--input", "window.json", "--output", "bundle"]
    )
    assert shadow.command == "run-shadow-rehearsal"


def test_public_batch_tool_verifies_ciphertext_and_revealed_shape(tmp_path) -> None:
    ciphertext = b"sealed-ground-truth"
    policy = make_policy()
    manifest_record = manifest_data()
    import hashlib

    manifest_record["ciphertext_sha256"] = hashlib.sha256(ciphertext).hexdigest()
    policy_path = tmp_path / "policy.json"
    manifest_path = tmp_path / "manifest.json"
    ciphertext_path = tmp_path / "ground-truth.tle"
    ground_truth_path = tmp_path / "ground-truth.json"
    policy_path.write_bytes(canonical_json_bytes(policy))
    manifest_path.write_bytes(canonical_json_bytes(manifest_record))
    ciphertext_path.write_bytes(ciphertext)
    ground_truth_path.write_bytes(canonical_json_bytes(ground_truth_data()))

    args = _parser().parse_args(
        [
            "verify-public-batch",
            "--policy",
            str(policy_path),
            "--manifest",
            str(manifest_path),
            "--ciphertext",
            str(ciphertext_path),
            "--ground-truth",
            str(ground_truth_path),
        ]
    )
    result = _verify_public_batch(args)
    assert result["ciphertext_hash_verified"] is True
    assert result["revealed_shape_validated"] is True
    assert result["protocol_conformance"] is False


def test_capacity_tool_requires_the_administrator_signature(tmp_path) -> None:
    policy = make_policy()
    statement = PublisherCapacityStatement.model_validate(capacity_data())
    administrator = bt.sp_core.Keypair.create_from_uri("//Group1")
    signature = "0x" + administrator.sign(publisher_capacity_digest(statement)).hex()
    policy_path = tmp_path / "policy.json"
    statement_path = tmp_path / "capacity.json"
    policy_path.write_bytes(canonical_json_bytes(policy))
    statement_path.write_bytes(canonical_json_bytes(statement))
    args = SimpleNamespace(
        policy=policy_path,
        statement=statement_path,
        scheme="sr25519",
        signature=signature,
    )

    assert _verify_capacity(args)["administrator_signature_verified"] is True
    args.signature = "0x" + "00" * 64
    with pytest.raises(ValueError, match="does not verify"):
        _verify_capacity(args)


def test_media_tool_uses_the_single_snapshot_inspection_result(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    video = tmp_path / "clip.mp4"
    video.write_bytes(b"caller path must not be reread")
    profile = MediaProfile(
        size_bytes=123,
        duration=Fraction(2, 1),
        width=64,
        height=48,
        frame_rate=Fraction(2, 1),
        codec_name="h264",
        format_names=("mp4",),
    )
    decoded = FrameDigestResult(
        frame_digest="12" * 32,
        frame_count=4,
        width=64,
        height=48,
        decoder_sha256="34" * 32,
    )
    inspection = MediaInspectionResult(
        video_sha256="56" * 32,
        profile=profile,
        frames=decoded,
    )
    calls = []

    def fake_inspect(path):
        calls.append(path)
        video.write_bytes(b"swapped after snapshot")
        return inspection

    def forbidden_reread(*_args, **_kwargs):
        raise AssertionError("media tool reread the mutable caller path")

    monkeypatch.setattr(tools_module, "inspect_media", fake_inspect)
    monkeypatch.setattr(tools_module, "_read_regular_file", forbidden_reread)

    record = _inspect_media(SimpleNamespace(video=video))

    assert calls == [video]
    assert record["video_sha256"] == inspection.video_sha256
    assert record["frame_digest"] == decoded.frame_digest


def test_shadow_runner_tool_preserves_the_offline_safety_labels(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence = tmp_path / "window.json"
    evidence.write_bytes(b"{}")
    report = SimpleNamespace(
        model_dump=lambda **_kwargs: {
            "terminal_classification": "shadow_rehearsal_no_weight",
            "translation_weights_active": False,
            "protocol_conformance": False,
            "activation_evidence": False,
        }
    )
    manifest = {
        "schema": "umi-shadow-rehearsal-bundle/2",
        "translation_weights_active": False,
    }
    monkeypatch.setattr(
        tools_module,
        "run_shadow_rehearsal",
        lambda raw, output: SimpleNamespace(
            report=report,
            audit_manifest=manifest,
            manifest_path=output / "manifest.json",
        ),
    )
    args = SimpleNamespace(input=evidence, output=tmp_path / "bundle")
    record = _run_shadow_rehearsal(args)
    assert record["report"]["terminal_classification"] == "shadow_rehearsal_no_weight"
    assert record["translation_weights_active"] is False
    assert record["protocol_conformance"] is False
    assert record["activation_evidence"] is False
