from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import bittensor as bt
import pytest

import umi.external_miner_pilot as pilot
from umi.protocol import canonical_json_bytes

from .factories import dev_wallet


def _model_manifest(*, umi_revision: str, inference_revision: str) -> dict[str, Any]:
    return {
        "inference_revision": inference_revision,
        "release_id": pilot.MODEL_RELEASE_ID,
        "status": "baseline_no_weight",
        "umi_git_revision": umi_revision,
    }


def _source_runner(
    *,
    umi_repository: Path,
    expected_umi_revision: str,
    model_repository: Path,
    signer: str = pilot.MODEL_RELEASE_SIGNER_FINGERPRINT,
):
    calls: list[tuple[tuple[str, ...], Path, str]] = []

    def run(command, cwd: Path, label: str) -> tuple[bytes, bytes]:
        command = tuple(command)
        calls.append((command, cwd, label))
        if command == ("git", "rev-parse", "HEAD"):
            revision = (
                expected_umi_revision if cwd == umi_repository else pilot.MODEL_RELEASE_COMMIT
            )
            return revision.encode("ascii") + b"\n", b""
        if command[:2] == ("git", "status"):
            return b"", b""
        if command == ("git", "verify-tag", "--raw", pilot.MODEL_RELEASE_TAG):
            return b"", f"[GNUPG:] VALIDSIG {signer} 2026 0 4 0 1 10 00\n".encode()
        if command == (
            "git",
            "rev-parse",
            f"{pilot.MODEL_RELEASE_TAG}^{{commit}}",
        ):
            return pilot.MODEL_RELEASE_COMMIT.encode("ascii") + b"\n", b""
        if command[:3] == ("git", "merge-base", "--is-ancestor"):
            return b"", b""
        if command[0] == pilot.sys.executable:
            return b'{"status":"verified"}\n', b""
        raise AssertionError(f"unexpected command: {command!r}")

    return run, calls


def test_reference_inputs_pin_asset_and_derive_future_rounds() -> None:
    chunks = iter((b"B" * 16, b"C" * 16, b"N" * 32))
    request, truth = pilot._reference_inputs(
        current_round=100,
        backend_lifecycle_timeout_seconds=60,
        inference_timeout_seconds=180,
        response_buffer_seconds=60,
        reveal_margin_seconds=30,
        entropy=lambda size: next(chunks),
    )

    assert request.response_close_round == 200
    assert request.reveal_round == 210
    assert str(request.video.url) == pilot.ASSET_URL
    assert request.video.sha256 == pilot.ASSET_SHA256
    assert request.video.size_bytes == pilot.ASSET_SIZE_BYTES
    assert request.task.stratum == "continuous"
    assert truth.reveal_round == request.reveal_round
    assert truth.response_close_round == request.response_close_round
    assert truth.items[0].references == list(pilot.ASSET_REFERENCES)
    assert truth.items[0].canary is False


def test_verify_sources_pins_tag_signer_release_and_umi_ancestry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    umi_repository = Path(pilot.__file__).resolve().parents[2]
    model_repository = tmp_path / "reference-model"
    (model_repository / "release").mkdir(parents=True)
    (model_repository / "src" / "bitsign_motion").mkdir(parents=True)
    (model_repository / "tools").mkdir()
    expected_umi_revision = "ab" * 20
    model_umi_revision = "cd" * 20
    base_inference_revision = "ef" * 32
    manifest = _model_manifest(
        umi_revision=model_umi_revision,
        inference_revision=base_inference_revision,
    )
    manifest_bytes = canonical_json_bytes(manifest) + b"\n"
    (model_repository / "release" / "release-manifest.json").write_bytes(manifest_bytes)
    runner, calls = _source_runner(
        umi_repository=umi_repository,
        expected_umi_revision=expected_umi_revision,
        model_repository=model_repository,
    )
    monkeypatch.setattr(pilot, "_require_loaded_source_checkout", lambda *args: None)

    verified = pilot.verify_pilot_sources(
        umi_repository=umi_repository,
        expected_umi_revision=expected_umi_revision,
        model_repository=model_repository,
        runner=runner,
    )

    assert verified.umi_revision == expected_umi_revision
    assert verified.model_revision == pilot.MODEL_RELEASE_COMMIT
    assert verified.model_manifest_umi_revision == model_umi_revision
    assert verified.base_inference_revision == base_inference_revision
    assert any(command[:3] == ("git", "merge-base", "--is-ancestor") for command, _, _ in calls)
    verifier_calls = [command for command, _, _ in calls if command[0] == pilot.sys.executable]
    assert len(verifier_calls) == 1
    assert verifier_calls[0][-1] == pilot.MODEL_RELEASE_COMMIT


def test_verify_sources_rejects_unpinned_tag_signer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    umi_repository = Path(pilot.__file__).resolve().parents[2]
    model_repository = tmp_path / "reference-model"
    (model_repository / "release").mkdir(parents=True)
    expected_umi_revision = "ab" * 20
    (model_repository / "release" / "release-manifest.json").write_bytes(
        canonical_json_bytes(_model_manifest(umi_revision="cd" * 20, inference_revision="ef" * 32))
    )
    runner, _calls = _source_runner(
        umi_repository=umi_repository,
        expected_umi_revision=expected_umi_revision,
        model_repository=model_repository,
        signer="12" * 20,
    )
    monkeypatch.setattr(pilot, "_require_loaded_source_checkout", lambda *args: None)

    with pytest.raises(RuntimeError, match="pinned signer fingerprint"):
        pilot.verify_pilot_sources(
            umi_repository=umi_repository,
            expected_umi_revision=expected_umi_revision,
            model_repository=model_repository,
            runner=runner,
        )


@pytest.mark.asyncio
async def test_external_pilot_emits_honest_receipt_and_removes_private_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    umi_repository = tmp_path / "umi"
    model_repository = tmp_path / "model"
    umi_repository.mkdir()
    model_repository.mkdir()
    output = tmp_path / "published-pilot"
    expected_umi_revision = "ab" * 20
    base_inference_revision = "cd" * 32
    local_inference_revision = "ef" * 32
    sources = pilot.VerifiedPilotSources(
        umi_revision=expected_umi_revision,
        model_tag=pilot.MODEL_RELEASE_TAG,
        model_revision=pilot.MODEL_RELEASE_COMMIT,
        model_tag_signer_fingerprint=pilot.MODEL_RELEASE_SIGNER_FINGERPRINT,
        model_manifest_sha256="12" * 32,
        model_manifest_umi_revision="34" * 20,
        base_inference_revision=base_inference_revision,
    )
    validator_wallet = dev_wallet("//ExternalPilotValidator")
    miner_wallet = dev_wallet("//ExternalPilotMiner")
    miner_hotkey = miner_wallet.hotkey.ss58_address
    translator = object()
    observed: dict[str, Any] = {}

    monkeypatch.setattr(pilot, "verify_pilot_sources", lambda **kwargs: sources)
    monkeypatch.setattr(pilot, "load_translator", lambda *args, **kwargs: translator)
    monkeypatch.setattr(bt.timelock, "current_round", lambda: 1_000)

    async def fake_run_local_component_pilot(**kwargs):
        observed.update(kwargs)
        requests = json.loads(kwargs["requests_path"].read_bytes())
        truth = json.loads(kwargs["ground_truth_path"].read_bytes())
        assert requests[0]["reveal_round"] > requests[0]["response_close_round"] > 1_000
        assert truth["reveal_round"] == requests[0]["reveal_round"]
        bundle = kwargs["output"]
        bundle.mkdir()
        manifest = bundle / "manifest.json"
        manifest.write_bytes(canonical_json_bytes({"schema": "fixture-component-bundle"}))
        return manifest, {
            "assigned_clip_count": 1,
            "per_clip": [{"failure_code": None}],
        }

    monkeypatch.setattr(pilot, "run_local_component_pilot", fake_run_local_component_pilot)
    monkeypatch.setattr(
        pilot,
        "replay_bundle_detailed",
        lambda _root: SimpleNamespace(
            outcomes=(
                SimpleNamespace(
                    failure_code=None,
                    response=SimpleNamespace(
                        hypothesis="book",
                        model_revision=local_inference_revision,
                        received_video_sha256=pilot.ASSET_SHA256,
                        status="ok",
                    ),
                ),
            ),
            scoring={
                "assigned_clip_count": 1,
                "per_clip": [{"failure_code": None}],
            },
        ),
    )

    manifest_path, receipt_path = await pilot.run_external_reference_pilot(
        output=output,
        umi_repository=umi_repository,
        expected_umi_revision=expected_umi_revision,
        model_repository=model_repository,
        validator_wallet=validator_wallet,
        miner_wallet=miner_wallet,
        model_revision=local_inference_revision,
        expected_miner_hotkey=miner_hotkey,
        declared_miner_uid=236,
    )

    receipt = json.loads(receipt_path.read_bytes())
    assert manifest_path == output / "bundle" / "manifest.json"
    assert receipt["evidence_class"] == "component_test_no_weight"
    assert receipt["translation_weights_active"] is False
    assert receipt["protocol_conformance"] is False
    assert receipt["activation_evidence"] is False
    assert receipt["validator_input_eligible"] is False
    assert receipt["public_miner_transport_used"] is False
    assert receipt["public_axon_service_proven"] is False
    assert receipt["uid_chain_binding_verified"] is False
    assert receipt["receipt_authenticated_by_miner"] is False
    assert receipt["source_verification_is_operator_asserted"] is True
    assert receipt["model_execution_is_operator_asserted"] is True
    assert "network_request_used" not in receipt
    assert receipt["declared_miner_uid"] == 236
    assert receipt["miner_hotkey"] == miner_hotkey
    assert receipt["model"]["local_inference_revision"] == local_inference_revision
    assert receipt["asset"]["sha256"] == pilot.ASSET_SHA256
    assert not (output / ".private-inputs").exists()
    assert observed["translator"] is translator


def test_external_pilot_requires_a_successful_model_response(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        pilot,
        "replay_bundle_detailed",
        lambda _root: SimpleNamespace(
            outcomes=(SimpleNamespace(failure_code="inference_failed", response=None),),
            scoring={
                "assigned_clip_count": 1,
                "per_clip": [{"failure_code": "inference_failed"}],
            },
        ),
    )
    with pytest.raises(RuntimeError, match="successful model response"):
        pilot._require_successful_model_outcome(
            tmp_path,
            expected_model_revision="ab" * 32,
            expected_scoring={
                "assigned_clip_count": 1,
                "per_clip": [{"failure_code": "inference_failed"}],
            },
        )


def test_external_pilot_cli_requires_explicit_uid_and_hotkey() -> None:
    required = {
        action.dest for action in pilot._parser()._actions if getattr(action, "required", False)
    }
    assert {"expected_miner_uid", "expected_miner_hotkey"} <= required
