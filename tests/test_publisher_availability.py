from __future__ import annotations

import hashlib
import inspect
import os
from dataclasses import replace
from fractions import Fraction
from pathlib import Path

import bittensor as bt
import pytest
from pydantic import ValidationError

from tests.factories import dev_wallet
from tests.test_artifacts import manifest_data
from tests.test_policy import make_policy
from umi.artifacts import PublicBatchManifest
from umi.canary import wer_canary_stratum
from umi.crypto import seal_response
from umi.encoding import account_id32
from umi.media import FrameDigestResult, MediaInspectionResult, MediaProfile
from umi.policy import ScoringPolicy, scoring_policy_hash
from umi.pool import (
    POOL_MANIFEST_SCHEMA,
    PoolBody,
    batch_commitment,
    parse_pool_manifest_bytes,
)
from umi.protocol import base64url_encode, canonical_json_bytes
from umi.publisher_availability import (
    ANCHOR_INTENTS_FILENAME,
    CERTIFIED_RELEASE_FILENAME,
    QUALIFICATION_CONTEXT_SCHEMA,
    QUALIFICATION_RECEIPTS_DIRECTORY,
    AvailabilityCandidateSet,
    AvailabilityQualificationContext,
    AvailabilityQualificationStore,
    AvailabilityStateConflict,
    AvailabilityStateCorruption,
    AvailabilityWorkflowError,
    build_candidate_set,
    build_certified_release,
    load_candidate_bundle,
    qualify_candidate_set_component,
    validate_candidate_bundle,
    write_candidate_bundle,
    write_certified_release,
)
from umi.registries import spent_video_leaf
from umi.validator_live_ports import MirrorWindowIndex
from umi.validator_state import WindowPlan
from umi.window import QUICKNET_GENESIS_MS, QUICKNET_PERIOD_MS, WindowClock, ceil_div


def _window(policy: ScoringPolicy, *, reveal_round: int) -> WindowPlan:
    selection_round = reveal_round - sum(
        ceil_div(seconds, 3)
        for seconds in (
            policy.clock.issue_allowance_seconds,
            policy.clock.response_window_seconds,
            policy.clock.reveal_margin_seconds,
        )
    )
    selection_timestamp_ms = QUICKNET_GENESIS_MS + (selection_round - 1) * QUICKNET_PERIOD_MS
    announcement_timestamp_ms = selection_timestamp_ms - 1000 * (
        policy.clock.anchor_blocks * policy.clock.target_block_interval_seconds
        + policy.clock.selection_finality_buffer_seconds
    )
    clock = WindowClock(
        activation_block=policy.activation_block,
        window_stride_blocks=policy.clock.window_stride_blocks,
        proposal_blocks=policy.clock.proposal_blocks,
        anchor_blocks=policy.clock.anchor_blocks,
        target_block_interval_seconds=policy.clock.target_block_interval_seconds,
        selection_finality_buffer_seconds=policy.clock.selection_finality_buffer_seconds,
        issue_allowance_seconds=policy.clock.issue_allowance_seconds,
        response_window_seconds=policy.clock.response_window_seconds,
        delivery_grace_seconds=policy.clock.delivery_grace_seconds,
        reveal_margin_seconds=policy.clock.reveal_margin_seconds,
    )
    schedule = clock.derive(
        0,
        netuid=policy.netuid,
        announcement_block_hash="0x" + "ab" * 32,
        announcement_timestamp_ms=announcement_timestamp_ms,
        scoring_policy_hash=scoring_policy_hash(policy),
    )
    assert schedule.reveal_round == reveal_round
    return WindowPlan.from_schedule(
        schedule,
        scoring_policy_hash=scoring_policy_hash(policy),
    )


def _candidate_material(
    policy: ScoringPolicy,
    window: WindowPlan,
    *,
    publisher_count: int = 1,
    video_suffix: bytes = b"",
) -> tuple[list[bytes], dict[str, bytes], dict[str, bytes], dict[tuple[str, str], bytes]]:
    body_bytes: list[bytes] = []
    public_bytes: dict[str, bytes] = {}
    envelopes: dict[str, bytes] = {}
    videos: dict[tuple[str, str], bytes] = {}
    for publisher_index, publisher in enumerate(policy.publisher_registry[:publisher_count]):
        batch_id = base64url_encode(bytes([65 + publisher_index]) * 16)
        document = manifest_data()
        document.update(
            window_id=window.window_id,
            batch_id=batch_id,
            publisher_hotkey=publisher.publisher_hotkey,
            scoring_policy_hash=scoring_policy_hash(policy),
            response_close_round=window.response_close_round,
            reveal_round=window.reveal_round,
        )
        strata = [
            "fingerspelling",
            "fingerspelling",
            "short_utterance",
            "short_utterance",
            "short_utterance",
            "short_utterance",
            "continuous",
            "continuous",
            "continuous",
            "continuous",
            "continuous",
            "continuous",
            "fingerspelling",
            wer_canary_stratum(window.window_id, batch_id),
        ]
        for item_index, item in enumerate(document["items"]):
            item["stratum"] = strata[item_index]
            item["metric"] = "cer" if strata[item_index] == "fingerspelling" else "wer"
            challenge_id = base64url_encode(bytes([publisher_index * 20 + item_index]) * 16)
            raw_video = b"fake-mp4-" + bytes([publisher_index, item_index]) + video_suffix
            video_sha256 = hashlib.sha256(raw_video).hexdigest()
            frame_digest = hashlib.sha256(b"frame-" + raw_video).hexdigest()
            item["challenge_id"] = challenge_id
            item["media"].update(
                sha256=video_sha256,
                frame_digest=frame_digest,
                size_bytes=len(raw_video),
            )
            item["signer_id_sha256"] = f"{10_000 + publisher_index * 10 + item_index // 2:064x}"
            item["consent_manifest_sha256"] = f"{20_000 + publisher_index * 20 + item_index:064x}"
            item["provenance_manifest_sha256"] = (
                f"{30_000 + publisher_index * 20 + item_index:064x}"
            )
            videos[(batch_id, challenge_id)] = raw_video
        sealed = seal_response(
            f"ground-truth-{publisher_index}".encode(),
            reveal_round=window.reveal_round,
        )
        document["ciphertext_sha256"] = sealed.sha256_hex
        manifest = PublicBatchManifest.model_validate(document)
        public = canonical_json_bytes(manifest)
        entry = {
            "batch_id": batch_id,
            "batch_commitment": batch_commitment(
                manifest,
                sealed.portable_bytes,
                window.reveal_round,
            ),
            "public_manifest_sha256": hashlib.sha256(public).hexdigest(),
            "ciphertext_sha256": sealed.sha256_hex,
            "reveal_round": window.reveal_round,
        }
        body = PoolBody.model_validate(
            {
                "schema": POOL_MANIFEST_SCHEMA,
                "window_id": window.window_id,
                "publisher_hotkey": publisher.publisher_hotkey,
                "scoring_policy_hash": scoring_policy_hash(policy),
                "batches": [entry],
            }
        )
        body_bytes.append(canonical_json_bytes(body))
        public_bytes[batch_id] = public
        envelopes[batch_id] = sealed.portable_bytes
    return body_bytes, public_bytes, envelopes, videos


def _write_bundle(
    root: Path,
    policy: ScoringPolicy,
    window: WindowPlan,
    *,
    publisher_count: int = 1,
    video_suffix: bytes = b"",
):
    bodies, public, envelopes, videos = _candidate_material(
        policy,
        window,
        publisher_count=publisher_count,
        video_suffix=video_suffix,
    )
    manifest, objects = build_candidate_set(
        policy=policy,
        window=window,
        pool_body_bytes=bodies,
        public_manifest_bytes=public,
        ground_truth_envelopes=envelopes,
        videos=videos,
    )
    write_candidate_bundle(root, manifest, objects)
    return load_candidate_bundle(root)


def _fake_inspect_factory(policy: ScoringPolicy):
    def fake_inspect(path, **_kwargs):
        assert _kwargs["expected_ffmpeg_sha256"] == (
            policy.implementation_pins.media.ffmpeg_binary_sha256
        )
        assert _kwargs["expected_ffprobe_sha256"] == (
            policy.implementation_pins.media.ffprobe_binary_sha256
        )
        raw = Path(path).read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        return MediaInspectionResult(
            video_sha256=digest,
            profile=MediaProfile(
                size_bytes=len(raw),
                duration=Fraction(5, 1),
                width=1280,
                height=720,
                frame_rate=Fraction(30_000, 1_001),
                codec_name="h264",
                format_names=("mp4",),
            ),
            frames=FrameDigestResult(
                frame_digest=hashlib.sha256(b"frame-" + raw).hexdigest(),
                frame_count=150,
                width=1280,
                height=720,
                decoder_sha256=policy.implementation_pins.media.ffmpeg_binary_sha256,
                probe_sha256=policy.implementation_pins.media.ffprobe_binary_sha256,
                executables_content_pinned=True,
            ),
        )

    return fake_inspect


@pytest.mark.parametrize(
    ("frame_override", "reason"),
    [
        ({"probe_sha256": "00" * 32}, "candidate_video_probe_pin_mismatch"),
        (
            {"executables_content_pinned": False},
            "candidate_video_tools_not_content_pinned",
        ),
    ],
)
def test_candidate_validation_rejects_incomplete_media_execution_attestation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    frame_override: dict[str, object],
    reason: str,
) -> None:
    policy = make_policy()
    window = _window(policy, reveal_round=bt.timelock.current_round() + 300)
    loaded = _write_bundle(tmp_path / "candidate", policy, window)
    pinned_inspect = _fake_inspect_factory(policy)

    def incomplete_inspect(path, **kwargs):
        inspection = pinned_inspect(path, **kwargs)
        return replace(
            inspection,
            frames=replace(inspection.frames, **frame_override),
        )

    monkeypatch.setattr(
        "umi.publisher_availability.inspect_media_pinned",
        incomplete_inspect,
    )
    with pytest.raises(AvailabilityWorkflowError, match=reason):
        validate_candidate_bundle(
            loaded,
            policy=policy,
            context=_context(loaded, policy, 0),
        )


def _context(
    loaded,
    policy: ScoringPolicy,
    validator_index: int,
    *,
    spent_leaves: list[str] | None = None,
) -> AvailabilityQualificationContext:
    active = sorted(
        (entry.validator_hotkey for entry in policy.validator_registry),
        key=account_id32,
    )
    validator = dev_wallet(f"//Validator{validator_index}").hotkey.ss58_address
    selection_timestamp_ms = (
        QUICKNET_GENESIS_MS + (loaded.manifest.window.selection_round - 1) * QUICKNET_PERIOD_MS
    )
    lifecycle_offset_ms = 1000 * (
        policy.clock.anchor_blocks * policy.clock.target_block_interval_seconds
        + policy.clock.selection_finality_buffer_seconds
    )
    common = {
        "window_id": loaded.manifest.window.window_id,
        "spent_leaves": spent_leaves or [],
    }
    snapshot_bytes = canonical_json_bytes({"kind": "validator-snapshot", **common})
    proof_bytes = canonical_json_bytes({"kind": "validator-proof", **common})
    state_bytes = canonical_json_bytes({"kind": "protocol-state", **common})
    continuity_bytes = canonical_json_bytes({"kind": "protocol-state-continuity", **common})
    observation_bytes = canonical_json_bytes(
        {
            "kind": "finality-observation",
            "block_number": loaded.manifest.window.announcement_block + 1,
            "block_hash": "0x" + f"{validator_index + 1:064x}",
            **common,
        }
    )
    return AvailabilityQualificationContext(
        schema=QUALIFICATION_CONTEXT_SCHEMA,
        protocol="umi-asl/0.1",
        window_id=loaded.manifest.window.window_id,
        window_index=loaded.manifest.window.window_index,
        scoring_policy_hash=scoring_policy_hash(policy),
        candidate_set_sha256=loaded.sha256,
        announcement_block_hash="0x" + "ab" * 32,
        announcement_timestamp_ms=selection_timestamp_ms - lifecycle_offset_ms,
        announcement_finality_evidence_sha256="a1" * 32,
        active_validator_set_evidence_sha256=hashlib.sha256(snapshot_bytes).hexdigest(),
        announcement_validator_proof_evidence_sha256=hashlib.sha256(proof_bytes).hexdigest(),
        protocol_state_continuity_evidence_sha256=hashlib.sha256(continuity_bytes).hexdigest(),
        observed_finalized_block=loaded.manifest.window.announcement_block + 1,
        observed_finalized_block_hash="0x" + f"{validator_index + 1:064x}",
        observation_finality_evidence_sha256=hashlib.sha256(observation_bytes).hexdigest(),
        validator_hotkey=validator,
        active_validator_hotkeys=active,
        spent_registry_root="00" * 32,
        spent_registry_evidence_sha256=hashlib.sha256(state_bytes).hexdigest(),
        spent_leaves=spent_leaves or [],
    )


def _authority_objects(context: AvailabilityQualificationContext) -> dict[str, bytes]:
    common = {"window_id": context.window_id, "spent_leaves": context.spent_leaves}
    values = (
        canonical_json_bytes({"kind": "validator-snapshot", **common}),
        canonical_json_bytes({"kind": "validator-proof", **common}),
        canonical_json_bytes({"kind": "protocol-state", **common}),
        canonical_json_bytes({"kind": "protocol-state-continuity", **common}),
        canonical_json_bytes(
            {
                "kind": "finality-observation",
                "block_number": context.observed_finalized_block,
                "block_hash": context.observed_finalized_block_hash,
                **common,
            }
        ),
    )
    objects = {hashlib.sha256(value).hexdigest(): value for value in values}
    assert set(objects) == {
        context.active_validator_set_evidence_sha256,
        context.announcement_validator_proof_evidence_sha256,
        context.protocol_state_continuity_evidence_sha256,
        context.spent_registry_evidence_sha256,
        context.observation_finality_evidence_sha256,
    }
    return objects


def _qualify(
    root: Path,
    validated,
    policy: ScoringPolicy,
    validator_index: int,
):
    context = _context(validated.loaded, policy, validator_index)
    validated = validate_candidate_bundle(
        validated.loaded,
        policy=policy,
        context=context,
    )
    store = AvailabilityQualificationStore(
        root,
        policy_hash=scoring_policy_hash(policy),
        validator_hotkey=context.validator_hotkey,
    )
    receipt = qualify_candidate_set_component(
        validated,
        policy=policy,
        context=context,
        authority_objects=_authority_objects(context),
        state=store,
        wallet=dev_wallet(f"//Validator{validator_index}"),
    )
    return receipt, store, context


def test_quorum_builds_exact_final_manifests_anchor_intents_and_hostable_index(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = make_policy()
    reveal = bt.timelock.current_round() + 300
    window = _window(policy, reveal_round=reveal)
    loaded = _write_bundle(tmp_path / "candidate", policy, window, publisher_count=2)
    monkeypatch.setattr(
        "umi.publisher_availability.inspect_media_pinned",
        _fake_inspect_factory(policy),
    )
    validated = validate_candidate_bundle(
        loaded,
        policy=policy,
        context=_context(loaded, policy, 0),
    )
    receipts = [
        _qualify(tmp_path / f"validator-{index}", validated, policy, index)[0] for index in range(3)
    ]

    material = build_certified_release(validated, list(reversed(receipts)), policy=policy)
    assert len(material.certificate.signatures) == 3
    assert [
        account_id32(item.validator_hotkey) for item in material.certificate.signatures
    ] == sorted(account_id32(item.validator_hotkey) for item in receipts)
    assert all(not item.broadcast_authorized for item in material.anchor_intents)
    assert all(not item.weight_submission_capability for item in material.anchor_intents)
    assert all(
        item.fields[0].sha256 == item.pool_manifest_sha256 for item in material.anchor_intents
    )
    for raw in material.pool_manifest_bytes.values():
        manifest = parse_pool_manifest_bytes(raw, policy=policy)
        assert canonical_json_bytes(manifest) == raw
        assert manifest.availability_certificate == material.certificate

    release_root = write_certified_release(tmp_path / "release", material)
    index_path = release_root / "v1" / "umi" / "windows" / window.window_id / "pool-source.json"
    parsed_index = MirrorWindowIndex.model_validate_json(index_path.read_bytes())
    assert parsed_index == material.mirror_index
    assert (release_root / CERTIFIED_RELEASE_FILENAME).read_bytes() == material.release_bytes
    assert (release_root / ANCHOR_INTENTS_FILENAME).read_bytes() == (material.anchor_intents_bytes)
    for descriptor in parsed_index.objects:
        data = (release_root / descriptor.path.removeprefix("/")).read_bytes()
        assert hashlib.sha256(data).hexdigest() == descriptor.sha256
    for digest in material.release.signer_receipt_sha256s:
        receipt_bytes = (
            release_root / QUALIFICATION_RECEIPTS_DIRECTORY / f"{digest}.json"
        ).read_bytes()
        assert hashlib.sha256(receipt_bytes).hexdigest() == digest


def test_durable_reservation_prevents_a_second_root_and_restart_is_idempotent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = make_policy()
    window = _window(policy, reveal_round=bt.timelock.current_round() + 300)
    monkeypatch.setattr(
        "umi.publisher_availability.inspect_media_pinned",
        _fake_inspect_factory(policy),
    )
    loaded = _write_bundle(tmp_path / "candidate-one", policy, window)
    validated = validate_candidate_bundle(
        loaded,
        policy=policy,
        context=_context(loaded, policy, 0),
    )
    receipt, _store, context = _qualify(tmp_path / "state", validated, policy, 0)

    restarted = AvailabilityQualificationStore(
        tmp_path / "state",
        policy_hash=scoring_policy_hash(policy),
        validator_hotkey=context.validator_hotkey,
    )
    replayed = qualify_candidate_set_component(
        validated,
        policy=policy,
        context=context,
        authority_objects=_authority_objects(context),
        state=restarted,
        wallet=dev_wallet("//Validator0"),
    )
    assert canonical_json_bytes(replayed) == canonical_json_bytes(receipt)

    other_loaded = _write_bundle(
        tmp_path / "candidate-two",
        policy,
        window,
        video_suffix=b"-different",
    )
    other_validated = validate_candidate_bundle(
        other_loaded,
        policy=policy,
        context=_context(other_loaded, policy, 0),
    )
    with pytest.raises(AvailabilityStateConflict, match="availability_equivocation_prevented"):
        other_context = _context(other_loaded, policy, 0)
        qualify_candidate_set_component(
            other_validated,
            policy=policy,
            context=other_context,
            authority_objects=_authority_objects(other_context),
            state=restarted,
            wallet=dev_wallet("//Validator0"),
        )


def test_restart_completes_a_reservation_left_by_signer_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import umi.publisher_availability as availability

    policy = make_policy()
    window = _window(policy, reveal_round=bt.timelock.current_round() + 300)
    loaded = _write_bundle(tmp_path / "candidate", policy, window)
    monkeypatch.setattr(
        availability,
        "inspect_media_pinned",
        _fake_inspect_factory(policy),
    )
    context = _context(loaded, policy, 0)
    validated = validate_candidate_bundle(loaded, policy=policy, context=context)
    state = AvailabilityQualificationStore(
        tmp_path / "state",
        policy_hash=scoring_policy_hash(policy),
        validator_hotkey=context.validator_hotkey,
    )
    real_sign = availability.sign_response_digest

    def fail_signing(*_args, **_kwargs):
        raise RuntimeError("simulated signer outage")

    monkeypatch.setattr(availability, "sign_response_digest", fail_signing)
    with pytest.raises(AvailabilityWorkflowError, match="availability_signer_failed"):
        qualify_candidate_set_component(
            validated,
            policy=policy,
            context=context,
            authority_objects=_authority_objects(context),
            state=state,
            wallet=dev_wallet("//Validator0"),
        )

    monkeypatch.setattr(availability, "sign_response_digest", real_sign)
    refreshed_context = context.model_copy(
        update={
            "observed_finalized_block": context.observed_finalized_block + 1,
            "observed_finalized_block_hash": "0x" + "f0" * 32,
        }
    )
    refreshed_observation = canonical_json_bytes(
        {
            "kind": "finality-observation",
            "block_number": refreshed_context.observed_finalized_block,
            "block_hash": refreshed_context.observed_finalized_block_hash,
            "window_id": refreshed_context.window_id,
            "spent_leaves": refreshed_context.spent_leaves,
        }
    )
    refreshed_context = refreshed_context.model_copy(
        update={
            "observation_finality_evidence_sha256": hashlib.sha256(
                refreshed_observation
            ).hexdigest()
        }
    )
    refreshed_validated = validate_candidate_bundle(
        loaded,
        policy=policy,
        context=refreshed_context,
    )
    restarted = AvailabilityQualificationStore(
        tmp_path / "state",
        policy_hash=scoring_policy_hash(policy),
        validator_hotkey=context.validator_hotkey,
    )
    receipt = qualify_candidate_set_component(
        refreshed_validated,
        policy=policy,
        context=refreshed_context,
        authority_objects=_authority_objects(refreshed_context),
        state=restarted,
        wallet=dev_wallet("//Validator0"),
    )
    assert receipt.qualified_at_finalized_block == refreshed_context.observed_finalized_block
    assert restarted.load(window.window_id) == receipt


def test_missing_and_tampered_candidate_artifacts_fail_closed(
    tmp_path: Path,
) -> None:
    policy = make_policy()
    window = _window(policy, reveal_round=bt.timelock.current_round() + 300)
    loaded = _write_bundle(tmp_path / "candidate", policy, window)
    first_digest = loaded.manifest.objects[0].sha256
    (loaded.root / "objects" / first_digest).unlink()
    with pytest.raises(AvailabilityWorkflowError, match="candidate_object_set_mismatch"):
        load_candidate_bundle(loaded.root)

    loaded = _write_bundle(tmp_path / "candidate-two", policy, window)
    video = next(item for item in loaded.manifest.objects if item.kind == "video")
    (loaded.root / "objects" / video.sha256).write_bytes(b"tampered")
    with pytest.raises(
        AvailabilityWorkflowError,
        match=r"candidate_object_(size|digest)_mismatch",
    ):
        load_candidate_bundle(loaded.root)


def test_spent_public_media_is_rejected_before_signing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = make_policy()
    window = _window(policy, reveal_round=bt.timelock.current_round() + 300)
    loaded = _write_bundle(tmp_path / "candidate", policy, window)
    monkeypatch.setattr(
        "umi.publisher_availability.inspect_media_pinned",
        _fake_inspect_factory(policy),
    )
    manifest_descriptor = next(
        item for item in loaded.manifest.objects if item.kind == "public_manifest"
    )
    public = PublicBatchManifest.model_validate_json(loaded.objects[manifest_descriptor.sha256])
    spent = spent_video_leaf(public.items[0].media.sha256).hex()
    with pytest.raises(AvailabilityWorkflowError, match="candidate_public_content_spent"):
        validate_candidate_bundle(
            loaded,
            policy=policy,
            context=_context(loaded, policy, 0, spent_leaves=[spent]),
        )


def test_retained_object_tamper_is_detected_on_restart(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = make_policy()
    window = _window(policy, reveal_round=bt.timelock.current_round() + 300)
    loaded = _write_bundle(tmp_path / "candidate", policy, window)
    monkeypatch.setattr(
        "umi.publisher_availability.inspect_media_pinned",
        _fake_inspect_factory(policy),
    )
    validated = validate_candidate_bundle(
        loaded,
        policy=policy,
        context=_context(loaded, policy, 0),
    )
    receipt, _store, context = _qualify(tmp_path / "state", validated, policy, 0)
    retained = tmp_path / "state" / "objects" / receipt.retained_objects[0].sha256
    os.chmod(retained, 0o600)
    retained.write_bytes(b"corrupt")
    with pytest.raises((AvailabilityStateCorruption, AvailabilityWorkflowError)):
        AvailabilityQualificationStore(
            tmp_path / "state",
            policy_hash=scoring_policy_hash(policy),
            validator_hotkey=context.validator_hotkey,
        )


def test_noncanonical_order_and_forged_receipt_never_reach_release(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = make_policy()
    window = _window(policy, reveal_round=bt.timelock.current_round() + 300)
    loaded = _write_bundle(tmp_path / "candidate", policy, window)
    document = loaded.manifest.model_dump(mode="json", by_alias=True)
    document["objects"] = list(reversed(document["objects"]))
    with pytest.raises(ValidationError, match="canonically ordered"):
        AvailabilityCandidateSet.model_validate(document)

    monkeypatch.setattr(
        "umi.publisher_availability.inspect_media_pinned",
        _fake_inspect_factory(policy),
    )
    validated = validate_candidate_bundle(
        loaded,
        policy=policy,
        context=_context(loaded, policy, 0),
    )
    receipts = [
        _qualify(tmp_path / f"state-{index}", validated, policy, index)[0] for index in range(3)
    ]
    forged = receipts[0].model_copy(update={"signature": "0x" + "00" * 64})
    with pytest.raises(
        AvailabilityWorkflowError,
        match="availability_receipt_signature_invalid",
    ):
        build_certified_release(validated, [forged, *receipts[1:]], policy=policy)

    with pytest.raises(ValueError, match="does not meet quorum"):
        build_certified_release(validated, receipts[:2], policy=policy)

    source = inspect.getsource(build_certified_release)
    assert "wallet" not in inspect.signature(build_certified_release).parameters
    assert ".submit" not in source
    assert "compose" not in source


@pytest.mark.parametrize("kind", ["public_manifest", "ground_truth_envelope"])
def test_candidate_graph_rejects_duplicate_batch_artifact_identity(
    tmp_path: Path,
    kind: str,
) -> None:
    policy = make_policy()
    window = _window(policy, reveal_round=bt.timelock.current_round() + 300)
    loaded = _write_bundle(tmp_path / "candidate", policy, window)
    objects = list(loaded.manifest.objects)
    original = next(item for item in objects if item.kind == kind)
    replacement_digest = "ff" * 32 if original.sha256 != "ff" * 32 else "fe" * 32
    objects.append(original.model_copy(update={"sha256": replacement_digest}))
    objects.sort(key=lambda item: item.identity)
    document = loaded.manifest.model_dump(mode="json", by_alias=True)
    document["objects"] = [item.model_dump(mode="json", by_alias=True) for item in objects]
    with pytest.raises(ValidationError, match=r"repeats a .* batch identity"):
        AvailabilityCandidateSet.model_validate(document)


def test_qualification_binds_candidate_to_window_rounds_and_exact_context(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = make_policy()
    window = _window(policy, reveal_round=bt.timelock.current_round() + 300)
    loaded = _write_bundle(tmp_path / "candidate", policy, window)
    monkeypatch.setattr(
        "umi.publisher_availability.inspect_media_pinned",
        _fake_inspect_factory(policy),
    )

    changed_window = loaded.manifest.window.model_copy(
        update={"response_close_round": loaded.manifest.window.response_close_round + 1}
    )
    changed_manifest = loaded.manifest.model_copy(update={"window": changed_window})
    changed_loaded = replace(
        loaded,
        manifest=changed_manifest,
        manifest_bytes=canonical_json_bytes(changed_manifest),
    )
    with pytest.raises(
        AvailabilityWorkflowError,
        match="public_manifest_window_round_mismatch",
    ):
        validate_candidate_bundle(changed_loaded, policy=policy)

    context = _context(loaded, policy, 0)
    validated = validate_candidate_bundle(loaded, policy=policy, context=context)
    changed_context = context.model_copy(update={"spent_registry_evidence_sha256": "bc" * 32})
    state = AvailabilityQualificationStore(
        tmp_path / "state",
        policy_hash=scoring_policy_hash(policy),
        validator_hotkey=context.validator_hotkey,
    )
    with pytest.raises(
        AvailabilityWorkflowError,
        match="qualification_context_not_validated",
    ):
        qualify_candidate_set_component(
            validated,
            policy=policy,
            context=changed_context,
            authority_objects=_authority_objects(context),
            state=state,
            wallet=dev_wallet("//Validator0"),
        )

    late_context = context.model_copy(
        update={
            "observed_finalized_block": loaded.manifest.window.proposal_close_block,
            "observed_finalized_block_hash": "0x" + "ce" * 32,
            "observation_finality_evidence_sha256": "cf" * 32,
        }
    )
    with pytest.raises(
        AvailabilityWorkflowError,
        match="qualification_outside_proposal_interval",
    ):
        validate_candidate_bundle(loaded, policy=policy, context=late_context)


def test_release_rejects_signed_receipts_from_different_chain_contexts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = make_policy()
    window = _window(policy, reveal_round=bt.timelock.current_round() + 300)
    loaded = _write_bundle(tmp_path / "candidate", policy, window)
    monkeypatch.setattr(
        "umi.publisher_availability.inspect_media_pinned",
        _fake_inspect_factory(policy),
    )
    base_context = _context(loaded, policy, 0)
    base_validated = validate_candidate_bundle(
        loaded,
        policy=policy,
        context=base_context,
    )
    receipts = [
        _qualify(tmp_path / f"state-{index}", base_validated, policy, index)[0]
        for index in range(2)
    ]
    context = _context(loaded, policy, 2).model_copy(
        update={"announcement_finality_evidence_sha256": "bd" * 32}
    )
    validated = validate_candidate_bundle(loaded, policy=policy, context=context)
    state = AvailabilityQualificationStore(
        tmp_path / "state-2",
        policy_hash=scoring_policy_hash(policy),
        validator_hotkey=context.validator_hotkey,
    )
    receipts.append(
        qualify_candidate_set_component(
            validated,
            policy=policy,
            context=context,
            authority_objects=_authority_objects(context),
            state=state,
            wallet=dev_wallet("//Validator2"),
        )
    )
    release_validated = validate_candidate_bundle(loaded, policy=policy)
    with pytest.raises(
        AvailabilityWorkflowError,
        match="availability_receipt_context_disagreement",
    ):
        build_certified_release(release_validated, receipts, policy=policy)


def test_retained_context_tamper_is_detected_on_restart(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = make_policy()
    window = _window(policy, reveal_round=bt.timelock.current_round() + 300)
    loaded = _write_bundle(tmp_path / "candidate", policy, window)
    monkeypatch.setattr(
        "umi.publisher_availability.inspect_media_pinned",
        _fake_inspect_factory(policy),
    )
    validated = validate_candidate_bundle(
        loaded,
        policy=policy,
        context=_context(loaded, policy, 0),
    )
    receipt, _store, context = _qualify(tmp_path / "state", validated, policy, 0)
    retained = tmp_path / "state" / "objects" / receipt.qualification_context_sha256
    retained.write_bytes(b"{}")
    with pytest.raises(AvailabilityStateCorruption):
        AvailabilityQualificationStore(
            tmp_path / "state",
            policy_hash=scoring_policy_hash(policy),
            validator_hotkey=context.validator_hotkey,
        )


def test_weight_active_policy_is_rejected_before_candidate_assembly() -> None:
    policy = make_policy()
    window = _window(policy, reveal_round=bt.timelock.current_round() + 300)
    bodies, public, envelopes, videos = _candidate_material(policy, window)
    active_policy = policy.model_copy(update={"translation_weights_active": True})
    with pytest.raises(
        AvailabilityWorkflowError,
        match="availability_requires_shadow_policy",
    ):
        build_candidate_set(
            policy=active_policy,
            window=window,
            pool_body_bytes=bodies,
            public_manifest_bytes=public,
            ground_truth_envelopes=envelopes,
            videos=videos,
        )
