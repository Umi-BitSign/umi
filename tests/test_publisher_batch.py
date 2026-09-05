from __future__ import annotations

import hashlib
import json
import stat
import time
from fractions import Fraction
from pathlib import Path

import pytest

import umi.publisher_batch as publisher_batch_module
import umi.publisher_batch_cli as publisher_batch_cli_module
from tests.test_policy import make_policy
from umi.crypto import SealedResponse
from umi.media import (
    FrameDigestResult,
    MediaConformanceError,
    MediaInspectionResult,
    MediaProfile,
)
from umi.policy import ScoringPolicy, scoring_policy_hash
from umi.protocol import canonical_json_bytes
from umi.publisher_availability_cli import AvailabilityAssemblyConfig
from umi.publisher_batch import (
    CANARY_CER_ROLE,
    CANARY_WER_ROLE,
    MAXIMUM_OPAQUE_ID_DRAWS,
    PUBLISHER_BATCH_ROLES,
    PUBLISHER_BATCH_SOURCE_SCHEMA,
    PublisherBatchError,
    PublisherBatchIdentity,
    PublisherBatchSource,
    PublisherBatchWindow,
    PublisherReserveVideoInspection,
    create_publisher_batch_identity,
    derive_publisher_batch_window,
    inspect_publisher_reserve_video,
    load_publisher_batch_release,
    prepare_publisher_batch,
    prepare_publisher_batch_from_paths,
    read_canonical_private_publisher_input,
    read_canonical_public_publisher_input,
    write_publisher_batch,
    write_publisher_batch_identity,
)
from umi.validator_state import WindowPlan
from umi.window import WindowClock


def _private_file(path: Path, payload: bytes) -> Path:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_bytes(payload)
    path.chmod(0o400)
    return path


def _private_directory(path: Path) -> Path:
    path.mkdir(mode=0o700, parents=True)
    path.chmod(0o700)
    return path


def _window(policy: ScoringPolicy, *, now_ms: int | None = None) -> PublisherBatchWindow:
    observed = time.time_ns() // 1_000_000 if now_ms is None else now_ms
    clock = policy.clock
    schedule = WindowClock(
        activation_block=policy.activation_block,
        window_stride_blocks=clock.window_stride_blocks,
        proposal_blocks=clock.proposal_blocks,
        anchor_blocks=clock.anchor_blocks,
        target_block_interval_seconds=clock.target_block_interval_seconds,
        selection_finality_buffer_seconds=clock.selection_finality_buffer_seconds,
        issue_allowance_seconds=clock.issue_allowance_seconds,
        response_window_seconds=clock.response_window_seconds,
        delivery_grace_seconds=clock.delivery_grace_seconds,
        reveal_margin_seconds=clock.reveal_margin_seconds,
    ).derive(
        0,
        netuid=policy.netuid,
        announcement_block_hash="0x" + "71" * 32,
        announcement_timestamp_ms=observed,
        scoring_policy_hash=scoring_policy_hash(policy),
    )
    return PublisherBatchWindow.from_plan(
        WindowPlan.from_schedule(schedule, scoring_policy_hash=scoring_policy_hash(policy)),
        announcement_block_hash="0x" + "71" * 32,
        announcement_timestamp_ms=observed,
    )


def _identity(policy: ScoringPolicy, window: PublisherBatchWindow) -> PublisherBatchIdentity:
    values = iter(bytes([value]) * 16 for value in range(1, 16))
    return create_publisher_batch_identity(
        policy=policy,
        window=window,
        publisher_hotkey=policy.publisher_registry[0].publisher_hotkey,
        random_bytes=lambda size: next(values) if size == 16 else b"",
        now_ms=window.announcement_timestamp_ms,
    )


def _source(
    tmp_path: Path,
    identity: PublisherBatchIdentity,
) -> tuple[PublisherBatchSource, dict[str, bytes]]:
    evidence = _private_directory(tmp_path / "private-evidence")
    consent = _private_file(evidence / "consent.json", b'{"consent":"external-record"}')
    provenance = _private_file(evidence / "provenance.json", b'{"provenance":"external-record"}')
    review = _private_file(evidence / "review.json", b'{"review":"external-record"}')
    common = {
        "consent_manifest_sha256": hashlib.sha256(consent.read_bytes()).hexdigest(),
        "consent_manifest_path": str(consent),
        "provenance_manifest_sha256": hashlib.sha256(provenance.read_bytes()).hexdigest(),
        "provenance_manifest_path": str(provenance),
        "review_manifest_sha256": hashlib.sha256(review.read_bytes()).hexdigest(),
        "review_manifest_path": str(review),
    }
    videos: dict[str, bytes] = {}
    rows = []
    video_root = _private_directory(tmp_path / "private-videos")
    for index, role in enumerate(PUBLISHER_BATCH_ROLES):
        payload = f"opaque-mp4-fixture-{index}".encode()
        video = _private_file(video_root / f"{index:02d}.mp4", payload)
        videos[role] = payload
        row = {
            "role": role,
            "video_path": str(video),
            "video_sha256": hashlib.sha256(payload).hexdigest(),
            "signer_id_sha256": f"{index // 2 + 1:064x}",
            **common,
            "script": f"private script {index}",
            "references": [
                f"reference {index} alpha",
                f"reference {index} beta",
                f"reference {index} gamma",
            ],
            "actual_references": None,
            "reserved_script": None,
            "mismatched_references": None,
        }
        if role == CANARY_CER_ROLE:
            row.update(
                references=None,
                actual_references=["aaaaaaaaaa", "bbbbbbbbbb", "cccccccccc"],
                reserved_script="private reserved cer script",
                mismatched_references=["xxxxxxxxxx", "yyyyyyyyyy", "zzzzzzzzzz"],
            )
        elif role == CANARY_WER_ROLE:
            row.update(
                references=None,
                actual_references=["apple amber", "berry bronze", "citrus copper"],
                reserved_script="private reserved wer script",
                mismatched_references=["xray xenon", "yellow yarrow", "zebra zinc"],
            )
        rows.append(row)
    source = PublisherBatchSource.model_validate(
        {
            "schema": PUBLISHER_BATCH_SOURCE_SCHEMA,
            "protocol": "umi-asl/0.1",
            "identity_sha256": hashlib.sha256(canonical_json_bytes(identity)).hexdigest(),
            "items": rows,
        }
    )
    return source, videos


def _inspection(policy: ScoringPolicy, payload: bytes, index: int) -> MediaInspectionResult:
    return MediaInspectionResult(
        video_sha256=hashlib.sha256(payload).hexdigest(),
        profile=MediaProfile(
            size_bytes=len(payload),
            duration=Fraction(2, 1),
            width=1,
            height=1,
            frame_rate=Fraction(1, 1),
            codec_name="h264",
            format_names=("mp4",),
        ),
        frames=FrameDigestResult(
            frame_digest=f"{1000 + index:064x}",
            frame_count=2,
            width=1,
            height=1,
            decoder_sha256=policy.implementation_pins.media.ffmpeg_binary_sha256,
            probe_sha256=policy.implementation_pins.media.ffprobe_binary_sha256,
            executables_content_pinned=True,
        ),
    )


def _prepared(tmp_path: Path):
    policy = make_policy()
    window = _window(policy)
    identity = _identity(policy, window)
    source, videos = _source(tmp_path, identity)
    inspections = {
        role: _inspection(policy, videos[role], index)
        for index, role in enumerate(PUBLISHER_BATCH_ROLES)
    }
    prepared = prepare_publisher_batch(
        policy=policy,
        identity=identity,
        source=source,
        video_bytes_by_role=videos,
        inspection_by_role=inspections,
        now_ms=window.announcement_timestamp_ms,
    )
    return policy, window, identity, source, prepared


def test_builder_constructs_exact_sealed_launch_shape_without_public_plaintext(
    tmp_path: Path,
) -> None:
    _policy, window, identity, source, prepared = _prepared(tmp_path)

    assert len(prepared.public_manifest.items) == 14
    assert len([item for item in prepared.ground_truth.items if item.canary]) == 2
    assert len([item for item in prepared.ground_truth.items if not item.canary]) == 12
    assert prepared.ground_truth.reveal_round == window.reveal_round
    assert prepared.pool_body.batches[0].batch_id == identity.batch_id
    assert prepared.release.objects[-1].kind == "video"

    public_bytes = b"".join(
        (
            canonical_json_bytes(prepared.public_manifest),
            canonical_json_bytes(prepared.pool_body),
            canonical_json_bytes(prepared.release),
        )
    )
    for item in source.items:
        assert item.script.encode() not in public_bytes
        for reference_set in (
            item.references,
            item.actual_references,
            item.mismatched_references,
        ):
            for reference in reference_set or []:
                assert reference.encode() not in public_bytes
    assert b"ground_truth_plaintext" not in public_bytes
    assert b"identity_sha256" not in canonical_json_bytes(prepared.release)
    assert prepared.ground_truth_envelope not in canonical_json_bytes(prepared.release)


def test_window_derivation_cli_check_is_read_only_and_real_write_is_canonical(
    tmp_path: Path,
    capsysbinary: pytest.CaptureFixture[bytes],
) -> None:
    policy = make_policy()
    announcement_timestamp_ms = time.time_ns() // 1_000_000
    announcement_block_hash = "0x" + "72" * 32
    expected = derive_publisher_batch_window(
        policy=policy,
        window_index=0,
        announcement_block_hash=announcement_block_hash,
        announcement_timestamp_ms=announcement_timestamp_ms,
        now_ms=announcement_timestamp_ms,
    )
    parent = _private_directory(tmp_path / "derive-window")
    policy_path = parent / "policy.json"
    policy_path.write_bytes(canonical_json_bytes(policy))
    policy_path.chmod(0o444)
    output = parent / "window.json"
    arguments = [
        "derive-window",
        "--policy",
        str(policy_path),
        "--window-index",
        "0",
        "--announcement-block-hash",
        announcement_block_hash,
        "--announcement-timestamp-ms",
        str(announcement_timestamp_ms),
    ]

    assert publisher_batch_cli_module.run_cli([*arguments, "--output", str(output), "--check"]) == 0
    stdout, stderr = capsysbinary.readouterr()
    assert stderr == b""
    result = json.loads(stdout)
    assert result["state_mutated"] is False
    assert result["announcement_finality_verified"] is False
    assert not output.exists()

    assert publisher_batch_cli_module.run_cli([*arguments, "--output", str(output)]) == 0
    stdout, stderr = capsysbinary.readouterr()
    assert stderr == b""
    assert json.loads(stdout)["state_mutated"] is True
    assert output.read_bytes() == canonical_json_bytes(expected)
    assert stat.S_IMODE(output.stat().st_mode) == 0o400


def test_window_reproduction_and_future_round_are_fail_closed() -> None:
    policy = make_policy()
    window = _window(policy)
    bad = window.model_copy(update={"closing_block": window.closing_block + 1})
    with pytest.raises(PublisherBatchError, match="publisher_window_schedule_mismatch"):
        create_publisher_batch_identity(
            policy=policy,
            window=bad,
            publisher_hotkey=policy.publisher_registry[0].publisher_hotkey,
        )

    stale_ms = window.announcement_timestamp_ms + 10_000_000
    with pytest.raises(PublisherBatchError, match="publisher_window_response_close_not_future"):
        create_publisher_batch_identity(
            policy=policy,
            window=window,
            publisher_hotkey=policy.publisher_registry[0].publisher_hotkey,
            now_ms=stale_ms,
        )


def test_publisher_cli_rejects_a_runtime_mismatch_before_reading_private_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsysbinary: pytest.CaptureFixture[bytes],
) -> None:
    policy = make_policy()
    changed_pins = policy.implementation_pins.model_copy(
        update={"umi_source_tree_sha256": "00" * 32}
    )
    changed_policy = policy.model_copy(update={"implementation_pins": changed_pins})

    with pytest.raises(RuntimeError, match="umi_source_tree_sha256"):
        derive_publisher_batch_window(
            policy=changed_policy,
            window_index=0,
            announcement_block_hash="0x" + "73" * 32,
            announcement_timestamp_ms=time.time_ns() // 1_000_000,
        )

    parent = _private_directory(tmp_path / "bad-runtime")
    policy_path = parent / "policy.json"
    policy_path.write_bytes(canonical_json_bytes(changed_policy))
    policy_path.chmod(0o444)

    def unexpected_private_read(*_args, **_kwargs):
        raise AssertionError("private input was read before runtime validation")

    monkeypatch.setattr(
        publisher_batch_cli_module,
        "read_canonical_private_publisher_input",
        unexpected_private_read,
    )
    assert (
        publisher_batch_cli_module.run_cli(
            [
                "build",
                "--policy",
                str(policy_path),
                "--identity",
                str(parent / "identity.json"),
                "--source",
                str(parent / "source.json"),
                "--check",
            ]
        )
        == 2
    )
    stdout, stderr = capsysbinary.readouterr()
    assert stdout == b""
    assert json.loads(stderr)["reason_code"] == "publisher_batch_failed"


def test_publisher_cli_requires_output_before_reading_private_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsysbinary: pytest.CaptureFixture[bytes],
) -> None:
    policy = make_policy()
    policy_path = tmp_path / "policy.json"
    policy_path.write_bytes(canonical_json_bytes(policy))
    policy_path.chmod(0o444)

    def unexpected_private_read(*_args, **_kwargs):
        raise AssertionError("private input was read before output preflight")

    monkeypatch.setattr(
        publisher_batch_cli_module,
        "read_canonical_private_publisher_input",
        unexpected_private_read,
    )
    assert (
        publisher_batch_cli_module.run_cli(
            [
                "build",
                "--policy",
                str(policy_path),
                "--identity",
                str(tmp_path / "identity.json"),
                "--source",
                str(tmp_path / "source.json"),
            ]
        )
        == 2
    )
    stdout, stderr = capsysbinary.readouterr()
    assert stdout == b""
    assert json.loads(stderr)["reason_code"] == "publisher_batch_output_required"


def test_build_rejects_bad_private_identity_before_reading_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsysbinary: pytest.CaptureFixture[bytes],
) -> None:
    policy = make_policy()
    window = _window(policy)
    identity = _identity(policy, window).model_copy(
        update={"window": window.model_copy(update={"closing_block": window.closing_block + 1})}
    )
    policy_path = tmp_path / "policy.json"
    policy_path.write_bytes(canonical_json_bytes(policy))
    policy_path.chmod(0o444)
    reads = 0

    def private_read(_path, _model_type):
        nonlocal reads
        reads += 1
        if reads == 1:
            return identity
        raise AssertionError("source was read before identity validation")

    monkeypatch.setattr(
        publisher_batch_cli_module,
        "read_canonical_private_publisher_input",
        private_read,
    )
    assert (
        publisher_batch_cli_module.run_cli(
            [
                "build",
                "--policy",
                str(policy_path),
                "--identity",
                str(tmp_path / "identity.json"),
                "--source",
                str(tmp_path / "source.json"),
                "--check",
            ]
        )
        == 2
    )
    stdout, stderr = capsysbinary.readouterr()
    assert stdout == b""
    assert json.loads(stderr)["reason_code"] == "publisher_window_schedule_mismatch"
    assert reads == 1


def test_identifier_generation_has_a_bounded_collision_failure() -> None:
    policy = make_policy()
    window = _window(policy)
    calls = 0

    def repeated(size: int) -> bytes:
        nonlocal calls
        calls += 1
        return b"x" * size

    with pytest.raises(PublisherBatchError, match="opaque_id_randomness_collision_limit"):
        create_publisher_batch_identity(
            policy=policy,
            window=window,
            publisher_hotkey=policy.publisher_registry[0].publisher_hotkey,
            random_bytes=repeated,
            now_ms=window.announcement_timestamp_ms,
        )
    assert calls == MAXIMUM_OPAQUE_ID_DRAWS


def test_builder_rejects_unparseable_timelock_from_sealer(
    tmp_path: Path,
) -> None:
    policy = make_policy()
    window = _window(policy)
    identity = _identity(policy, window)
    source, videos = _source(tmp_path, identity)
    inspections = {
        role: _inspection(policy, videos[role], index)
        for index, role in enumerate(PUBLISHER_BATCH_ROLES)
    }
    portable = b"not-a-portable-timelock"

    def bad_seal(_plaintext: bytes, *, reveal_round: int) -> SealedResponse:
        return SealedResponse(
            portable_bytes=portable,
            portable_b64=publisher_batch_module.base64url_encode(portable),
            reveal_round=reveal_round,
            sha256_hex=hashlib.sha256(portable).hexdigest(),
        )

    with pytest.raises(PublisherBatchError, match="generated_artifact_replay_failed"):
        prepare_publisher_batch(
            policy=policy,
            identity=identity,
            source=source,
            video_bytes_by_role=videos,
            inspection_by_role=inspections,
            seal=bad_seal,
            now_ms=window.announcement_timestamp_ms,
        )


def test_reference_count_cannot_be_inflated_with_normalized_duplicates(
    tmp_path: Path,
) -> None:
    policy = make_policy()
    window = _window(policy)
    identity = _identity(policy, window)
    source, videos = _source(tmp_path, identity)
    first = source.items[0].model_copy(
        update={"references": ["same words", "same, words", "SAME WORDS"]}
    )
    changed_source = source.model_copy(update={"items": [first, *source.items[1:]]})
    inspections = {
        role: _inspection(policy, videos[role], index)
        for index, role in enumerate(PUBLISHER_BATCH_ROLES)
    }

    with pytest.raises(PublisherBatchError, match="ordinary_references_duplicate"):
        prepare_publisher_batch(
            policy=policy,
            identity=identity,
            source=changed_source,
            video_bytes_by_role=videos,
            inspection_by_role=inspections,
            now_ms=window.announcement_timestamp_ms,
        )


def test_private_and_public_input_permissions_are_separate(tmp_path: Path) -> None:
    policy = make_policy()
    public = tmp_path / "policy.json"
    public.write_bytes(canonical_json_bytes(policy))
    public.chmod(0o444)
    assert read_canonical_public_publisher_input(public, ScoringPolicy) == policy
    with pytest.raises(PublisherBatchError, match="publisher_private_input_unsafe"):
        read_canonical_private_publisher_input(public, ScoringPolicy)

    public.chmod(0o400)
    assert read_canonical_private_publisher_input(public, ScoringPolicy) == policy
    tmp_path.chmod(0o750)
    with pytest.raises(PublisherBatchError, match="publisher_private_input_parent_unsafe"):
        read_canonical_private_publisher_input(public, ScoringPolicy)
    tmp_path.chmod(0o700)

    hardlink = tmp_path / "policy-hardlink.json"
    hardlink.hardlink_to(public)
    with pytest.raises(PublisherBatchError, match="publisher_private_input_unsafe"):
        read_canonical_private_publisher_input(public, ScoringPolicy)
    hardlink.unlink()
    symlink = tmp_path / "policy-symlink.json"
    symlink.symlink_to(public)
    with pytest.raises(PublisherBatchError, match="publisher_private_input_unavailable"):
        read_canonical_private_publisher_input(symlink, ScoringPolicy)

    public.chmod(0o622)
    with pytest.raises(PublisherBatchError, match="publisher_input_unsafe"):
        read_canonical_public_publisher_input(public, ScoringPolicy)


def test_source_evidence_digests_and_exact_millisecond_duration_are_checked(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = make_policy()
    window = _window(policy)
    identity = _identity(policy, window)
    source, videos = _source(tmp_path, identity)
    first = source.items[0]
    Path(first.review_manifest_path).chmod(0o600)
    with pytest.raises(PublisherBatchError, match="publisher_review_manifest_unsafe"):
        prepare_publisher_batch_from_paths(
            policy=policy,
            identity=identity,
            source=source,
            now_ms=window.announcement_timestamp_ms,
        )
    Path(first.review_manifest_path).chmod(0o400)
    changed_item = first.model_copy(update={"review_manifest_sha256": "ab" * 32})
    changed_source = source.model_copy(update={"items": [changed_item, *source.items[1:]]})
    with pytest.raises(PublisherBatchError, match="review_manifest_digest_mismatch"):
        prepare_publisher_batch_from_paths(
            policy=policy,
            identity=identity,
            source=changed_source,
            now_ms=window.announcement_timestamp_ms,
        )

    inspections = {
        role: _inspection(policy, videos[role], index)
        for index, role in enumerate(PUBLISHER_BATCH_ROLES)
    }
    inspections[PUBLISHER_BATCH_ROLES[0]] = MediaInspectionResult(
        video_sha256=inspections[PUBLISHER_BATCH_ROLES[0]].video_sha256,
        profile=MediaProfile(
            size_bytes=len(videos[PUBLISHER_BATCH_ROLES[0]]),
            duration=Fraction(2_000_001, 1_000_000),
            width=1,
            height=1,
            frame_rate=Fraction(1, 1),
            codec_name="h264",
            format_names=("mp4",),
        ),
        frames=inspections[PUBLISHER_BATCH_ROLES[0]].frames,
    )
    with pytest.raises(PublisherBatchError, match="duration_not_integer_milliseconds"):
        prepare_publisher_batch(
            policy=policy,
            identity=identity,
            source=source,
            video_bytes_by_role=videos,
            inspection_by_role=inspections,
            now_ms=window.announcement_timestamp_ms,
        )


def test_path_builder_rejects_video_mutation_before_media_inspection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = make_policy()
    window = _window(policy)
    identity = _identity(policy, window)
    source, _videos = _source(tmp_path, identity)
    video_path = Path(source.items[0].video_path)
    video_path.chmod(0o600)
    video_path.write_bytes(b"mutated-after-source-record")
    video_path.chmod(0o400)
    inspection_calls = 0

    def inspect(*_args, **_kwargs):
        nonlocal inspection_calls
        inspection_calls += 1
        raise AssertionError("media inspection ran before the source digest check")

    monkeypatch.setattr(publisher_batch_module, "inspect_media_pinned", inspect)
    with pytest.raises(PublisherBatchError, match="publisher_video_digest_mismatch"):
        prepare_publisher_batch_from_paths(
            policy=policy,
            identity=identity,
            source=source,
            now_ms=window.announcement_timestamp_ms,
        )
    assert inspection_calls == 0


def test_builder_rejects_supplied_video_digest_mismatch_before_inspection_validation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = make_policy()
    window = _window(policy)
    identity = _identity(policy, window)
    source, videos = _source(tmp_path, identity)
    changed_videos = dict(videos)
    changed_videos[PUBLISHER_BATCH_ROLES[0]] = b"different-supplied-video-bytes"
    inspections = {
        role: _inspection(policy, payload, index)
        for index, (role, payload) in enumerate(videos.items())
    }
    inspection_validation_calls = 0

    def validate_inspection(*_args, **_kwargs):
        nonlocal inspection_validation_calls
        inspection_validation_calls += 1
        raise AssertionError("inspection validation ran before the source digest check")

    monkeypatch.setattr(
        publisher_batch_module,
        "_validate_inspection",
        validate_inspection,
    )
    with pytest.raises(PublisherBatchError, match="publisher_video_digest_mismatch"):
        prepare_publisher_batch(
            policy=policy,
            identity=identity,
            source=source,
            video_bytes_by_role=changed_videos,
            inspection_by_role=inspections,
            now_ms=window.announcement_timestamp_ms,
        )
    assert inspection_validation_calls == 0


def test_path_builder_snapshots_all_clips_and_uses_both_policy_pins(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = make_policy()
    window = _window(policy)
    identity = _identity(policy, window)
    source, videos = _source(tmp_path, identity)
    calls: list[tuple[bytes, str, str]] = []

    def inspect(path: Path, **kwargs) -> MediaInspectionResult:
        payload = Path(path).read_bytes()
        role = next(role for role, value in videos.items() if value == payload)
        calls.append(
            (
                payload,
                kwargs["expected_ffmpeg_sha256"],
                kwargs["expected_ffprobe_sha256"],
            )
        )
        return _inspection(policy, payload, PUBLISHER_BATCH_ROLES.index(role))

    monkeypatch.setattr(publisher_batch_module, "inspect_media_pinned", inspect)
    prepared = prepare_publisher_batch_from_paths(
        policy=policy,
        identity=identity,
        source=source,
        ffmpeg="/not/executed/ffmpeg",
        ffprobe="/not/executed/ffprobe",
        now_ms=window.announcement_timestamp_ms,
    )

    assert len(calls) == 14
    assert {payload for payload, _ffmpeg, _ffprobe in calls} == set(videos.values())
    assert {(ffmpeg, ffprobe) for _payload, ffmpeg, ffprobe in calls} == {
        (
            policy.implementation_pins.media.ffmpeg_binary_sha256,
            policy.implementation_pins.media.ffprobe_binary_sha256,
        )
    }
    assert (
        prepared.public_manifest.ciphertext_sha256
        == hashlib.sha256(prepared.ground_truth_envelope).hexdigest()
    )


def test_reserve_video_inspection_binds_one_snapshot_policy_pins_and_full_profile(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = make_policy()
    root = _private_directory(tmp_path / "reserve-inspection")
    payload = b"private reserve video fixture"
    video = _private_file(root / "opaque.mp4", payload)
    expected_digest = hashlib.sha256(payload).hexdigest()
    observed: dict[str, object] = {}

    def inspect(path: Path, **kwargs) -> MediaInspectionResult:
        snapshot = Path(path)
        observed.update(path=snapshot, payload=snapshot.read_bytes(), kwargs=kwargs)
        return _inspection(policy, payload, 9)

    monkeypatch.setattr(publisher_batch_module, "inspect_media_pinned", inspect)
    receipt = inspect_publisher_reserve_video(
        policy=policy,
        video_path=video,
        expected_video_sha256=expected_digest,
        ffmpeg="/not/executed/ffmpeg",
        ffprobe="/not/executed/ffprobe",
    )

    assert isinstance(receipt, PublisherReserveVideoInspection)
    assert receipt.status == "passed"
    assert receipt.state_mutated is False
    assert receipt.translation_weights_active is False
    assert observed["payload"] == payload
    assert observed["path"] != video
    assert not Path(observed["path"]).exists()
    assert observed["kwargs"] == {
        "expected_ffmpeg_sha256": policy.implementation_pins.media.ffmpeg_binary_sha256,
        "expected_ffprobe_sha256": policy.implementation_pins.media.ffprobe_binary_sha256,
        "ffmpeg": "/not/executed/ffmpeg",
        "ffprobe": "/not/executed/ffprobe",
        "maximum_clip_size": policy.limits.maximum_clip_size_bytes,
    }
    assert receipt.scoring_policy_hash == scoring_policy_hash(policy)
    assert receipt.ffmpeg_binary_sha256 == policy.implementation_pins.media.ffmpeg_binary_sha256
    assert receipt.ffprobe_binary_sha256 == policy.implementation_pins.media.ffprobe_binary_sha256
    assert receipt.frame_count == 2
    assert receipt.media.sha256 == expected_digest
    assert receipt.media.frame_digest == f"{1009:064x}"
    assert receipt.media.duration_ms == 2_000
    assert receipt.media.video_codec == "h264"
    assert receipt.media.audio_track_count == 0
    assert str(video).encode() not in canonical_json_bytes(receipt)

    non_integral = _inspection(policy, payload, 9)
    non_integral = MediaInspectionResult(
        video_sha256=non_integral.video_sha256,
        profile=MediaProfile(
            size_bytes=len(payload),
            duration=Fraction(2_000_001, 1_000_000),
            width=1,
            height=1,
            frame_rate=Fraction(1, 1),
            codec_name="h264",
            format_names=("mp4",),
        ),
        frames=non_integral.frames,
    )
    monkeypatch.setattr(
        publisher_batch_module,
        "inspect_media_pinned",
        lambda *_args, **_kwargs: non_integral,
    )
    with pytest.raises(PublisherBatchError, match="duration_not_integer_milliseconds"):
        inspect_publisher_reserve_video(
            policy=policy,
            video_path=video,
            expected_video_sha256=expected_digest,
        )


def test_reserve_video_inspection_rejects_mutation_before_media_tools(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = make_policy()
    root = _private_directory(tmp_path / "reserve-mutation")
    video = _private_file(root / "opaque.mp4", b"original reserve video")
    expected_digest = hashlib.sha256(video.read_bytes()).hexdigest()
    video.chmod(0o600)
    video.write_bytes(b"mutated reserve video")
    video.chmod(0o400)
    inspection_calls = 0

    def inspect(*_args, **_kwargs):
        nonlocal inspection_calls
        inspection_calls += 1
        raise AssertionError("media tools ran before the expected video digest check")

    monkeypatch.setattr(publisher_batch_module, "inspect_media_pinned", inspect)
    with pytest.raises(PublisherBatchError, match="publisher_video_digest_mismatch"):
        inspect_publisher_reserve_video(
            policy=policy,
            video_path=video,
            expected_video_sha256=expected_digest,
        )
    assert inspection_calls == 0


def test_reserve_video_cli_writes_private_receipt_and_hides_media_details(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsysbinary: pytest.CaptureFixture[bytes],
) -> None:
    policy = make_policy()
    root = _private_directory(tmp_path / "reserve-cli")
    policy_path = root / "policy.json"
    policy_path.write_bytes(canonical_json_bytes(policy))
    policy_path.chmod(0o444)
    payload = b"private reserve CLI fixture"
    video = _private_file(root / "opaque-private-name.mp4", payload)
    expected_digest = hashlib.sha256(payload).hexdigest()
    frame_digest = f"{1011:064x}"

    monkeypatch.setattr(
        publisher_batch_module,
        "inspect_media_pinned",
        lambda *_args, **_kwargs: _inspection(policy, payload, 11),
    )
    output = root / "reserve-receipt.json"
    arguments = [
        "inspect-reserve-video",
        "--policy",
        str(policy_path),
        "--video",
        str(video),
        "--expected-video-sha256",
        expected_digest,
        "--ffmpeg",
        "/not/executed/ffmpeg",
        "--ffprobe",
        "/not/executed/ffprobe",
        "--output",
        str(output),
    ]
    assert publisher_batch_cli_module.run_cli(arguments) == 0
    stdout, stderr = capsysbinary.readouterr()
    assert stderr == b""
    summary = json.loads(stdout)
    receipt = PublisherReserveVideoInspection.model_validate_json(output.read_bytes())
    assert output.read_bytes() == canonical_json_bytes(receipt)
    assert stat.S_IMODE(output.stat().st_mode) == 0o400
    assert summary == {
        "schema": "umi-publisher-reserve-video-inspection-result/1",
        "protocol": "umi-asl/0.1",
        "status": "created",
        "receipt_sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
        "state_mutated": True,
        "translation_weights_active": False,
    }
    for private_value in (str(video), expected_digest, frame_digest):
        assert private_value.encode() not in stdout + stderr

    def failed_tool(*_args, **_kwargs):
        raise MediaConformanceError(f"private path must stay hidden: {video}")

    monkeypatch.setattr(publisher_batch_module, "inspect_media_pinned", failed_tool)
    failed_output = root / "failed-tool-receipt.json"
    failed_arguments = [*arguments[:-1], str(failed_output)]
    assert publisher_batch_cli_module.run_cli(failed_arguments) == 2
    stdout, stderr = capsysbinary.readouterr()
    assert stdout == b""
    assert json.loads(stderr)["reason_code"] == "publisher_reserve_media_inspection_failed"
    assert str(video).encode() not in stderr
    assert not failed_output.exists()

    changed_pins = policy.implementation_pins.model_copy(
        update={"umi_source_tree_sha256": "00" * 32}
    )
    changed_policy = policy.model_copy(update={"implementation_pins": changed_pins})
    changed_policy_path = root / "invalid-policy.json"
    changed_policy_path.write_bytes(canonical_json_bytes(changed_policy))
    changed_policy_path.chmod(0o444)

    def unexpected_inspection(**_kwargs):
        raise AssertionError("reserve video was read before policy validation")

    monkeypatch.setattr(
        publisher_batch_cli_module,
        "inspect_publisher_reserve_video",
        unexpected_inspection,
    )
    policy_failed_output = root / "policy-failed-receipt.json"
    policy_arguments = list(arguments)
    policy_arguments[2] = str(changed_policy_path)
    policy_arguments[-1] = str(policy_failed_output)
    assert publisher_batch_cli_module.run_cli(policy_arguments) == 2
    stdout, stderr = capsysbinary.readouterr()
    assert stdout == b""
    assert json.loads(stderr)["reason_code"] == "publisher_batch_failed"
    assert not policy_failed_output.exists()


def test_atomic_tree_is_read_only_complete_and_replays_into_availability(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy, window, identity, _source_record, prepared = _prepared(tmp_path)
    output_parent = _private_directory(tmp_path / "output")
    output = output_parent / "publisher-a"
    original_write = publisher_batch_module._write_file_bytes
    written_paths: list[str] = []

    def record_write(path: Path, payload: bytes, *, mode: int) -> None:
        staging_root = path.parent.parent if path.parent.name == "videos" else path.parent
        written_paths.append(path.relative_to(staging_root).as_posix())
        original_write(path, payload, mode=mode)

    monkeypatch.setattr(publisher_batch_module, "_write_file_bytes", record_write)
    write_publisher_batch(prepared, output)

    assert written_paths[:-1] == sorted(item.relative_path for item in prepared.release.objects)
    assert written_paths[-1] == "publisher-batch-release.json"
    assert stat.S_IMODE(output.stat().st_mode) == 0o500
    assert stat.S_IMODE((output / "videos").stat().st_mode) == 0o500
    files = [path for path in output.rglob("*") if path.is_file()]
    assert len(files) == 18
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o400 for path in files)
    assert not any(
        token in path.read_bytes()
        for path in files
        for token in (b"private script", b"reference 0 alpha")
    )

    loaded = load_publisher_batch_release(output, policy=policy, window=window)
    assert loaded.release.batch_id == identity.batch_id
    with pytest.raises(FileExistsError):
        write_publisher_batch(prepared, output)


def test_failed_tree_write_does_not_publish_a_partial_destination(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _policy, _window_record, _identity_record, _source_record, prepared = _prepared(tmp_path)
    output_parent = _private_directory(tmp_path / "failed-output")
    output = output_parent / "publisher-a"
    original = publisher_batch_module._write_file_bytes
    calls = 0

    def fail_once(path: Path, payload: bytes, *, mode: int) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("simulated crash before publication")
        original(path, payload, mode=mode)

    monkeypatch.setattr(publisher_batch_module, "_write_file_bytes", fail_once)
    with pytest.raises(OSError, match="simulated crash"):
        write_publisher_batch(prepared, output)
    assert not output.exists()
    assert list(output_parent.glob(".publisher-a.*")) == [output_parent / ".publisher-a.lock"]

    monkeypatch.setattr(publisher_batch_module, "_write_file_bytes", original)
    write_publisher_batch(prepared, output)
    assert (output / "publisher-batch-release.json").is_file()


def test_private_identity_write_is_atomic_and_immutable(tmp_path: Path) -> None:
    policy = make_policy()
    window = _window(policy)
    identity = _identity(policy, window)
    parent = _private_directory(tmp_path / "identity")
    output = parent / "identity.json"

    write_publisher_batch_identity(identity, output)
    assert output.read_bytes() == canonical_json_bytes(identity)
    assert stat.S_IMODE(output.stat().st_mode) == 0o400
    with pytest.raises(FileExistsError):
        write_publisher_batch_identity(identity, output)


def test_initialize_check_allocates_nothing_and_real_run_writes_one_private_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsysbinary: pytest.CaptureFixture[bytes],
) -> None:
    policy = make_policy()
    window = _window(policy)
    parent = _private_directory(tmp_path / "initialize")
    policy_path = parent / "policy.json"
    window_path = parent / "window.json"
    policy_path.write_bytes(canonical_json_bytes(policy))
    window_path.write_bytes(canonical_json_bytes(window))
    policy_path.chmod(0o444)
    window_path.chmod(0o444)
    output = parent / "identity.json"
    arguments = [
        "initialize",
        "--policy",
        str(policy_path),
        "--window",
        str(window_path),
        "--publisher-hotkey",
        policy.publisher_registry[0].publisher_hotkey,
        "--output",
        str(output),
    ]
    original_create = publisher_batch_cli_module.create_publisher_batch_identity

    def unexpected_create(**_kwargs):
        raise AssertionError("check mode must not allocate identifiers")

    monkeypatch.setattr(
        publisher_batch_cli_module,
        "create_publisher_batch_identity",
        unexpected_create,
    )
    assert publisher_batch_cli_module.run_cli([*arguments, "--check"]) == 0
    stdout, stderr = capsysbinary.readouterr()
    assert stderr == b""
    result = json.loads(stdout)
    assert result["state_mutated"] is False
    assert "identity_sha256" not in result
    assert not output.exists()

    monkeypatch.setattr(
        publisher_batch_cli_module,
        "create_publisher_batch_identity",
        original_create,
    )
    assert publisher_batch_cli_module.run_cli(arguments) == 0
    stdout, stderr = capsysbinary.readouterr()
    assert stderr == b""
    result = json.loads(stdout)
    assert result["state_mutated"] is True
    assert "identity_sha256" not in result
    parsed = read_canonical_private_publisher_input(output, PublisherBatchIdentity)
    assert parsed.window == window
    assert stat.S_IMODE(output.stat().st_mode) == 0o400


def test_build_check_and_error_output_never_emit_private_text_or_write_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsysbinary: pytest.CaptureFixture[bytes],
) -> None:
    policy, window, identity, source, prepared = _prepared(tmp_path)
    input_root = _private_directory(tmp_path / "cli-input")
    policy_path = input_root / "policy.json"
    window_path = input_root / "window.json"
    identity_path = input_root / "identity.json"
    source_path = input_root / "source.json"
    for path, value, mode in (
        (policy_path, policy, 0o400),
        (window_path, window, 0o400),
        (identity_path, identity, 0o400),
        (source_path, source, 0o400),
    ):
        path.write_bytes(canonical_json_bytes(value))
        path.chmod(mode)
    output = input_root / "must-not-exist"
    monkeypatch.setattr(
        publisher_batch_cli_module,
        "prepare_publisher_batch_from_paths",
        lambda **_kwargs: prepared,
    )

    assert (
        publisher_batch_cli_module.run_cli(
            [
                "build",
                "--policy",
                str(policy_path),
                "--identity",
                str(identity_path),
                "--source",
                str(source_path),
                "--output",
                str(output),
                "--check",
            ]
        )
        == 0
    )
    stdout, stderr = capsysbinary.readouterr()
    assert not output.exists()
    assert b"private script" not in stdout + stderr
    assert b"reference 0 alpha" not in stdout + stderr
    assert json.loads(stdout)["state_mutated"] is False

    assert (
        publisher_batch_cli_module.run_cli(
            [
                "build",
                "--policy",
                str(policy_path),
                "--identity",
                str(identity_path),
                "--source",
                str(source_path),
                "--output",
                str(output),
            ]
        )
        == 0
    )
    stdout, stderr = capsysbinary.readouterr()
    assert stderr == b""
    result = json.loads(stdout)
    assert result["state_mutated"] is True
    assert result["status"] == "created"
    assert b"private script" not in stdout
    assert b"reference 0 alpha" not in stdout
    installed = load_publisher_batch_release(output, policy=policy, window=window)
    assert installed.release == prepared.release

    def secret_failure(**_kwargs):
        raise RuntimeError("private script and reference 0 alpha")

    monkeypatch.setattr(
        publisher_batch_cli_module,
        "prepare_publisher_batch_from_paths",
        secret_failure,
    )
    assert (
        publisher_batch_cli_module.run_cli(
            [
                "build",
                "--policy",
                str(policy_path),
                "--identity",
                str(identity_path),
                "--source",
                str(source_path),
                "--check",
            ]
        )
        == 2
    )
    stdout, stderr = capsysbinary.readouterr()
    assert stdout == b""
    assert json.loads(stderr)["reason_code"] == "publisher_batch_failed"
    assert b"private script" not in stderr


def test_availability_config_is_directly_accepted_by_availability_schema(
    tmp_path: Path,
    capsysbinary: pytest.CaptureFixture[bytes],
) -> None:
    policy, window, _identity_record, _source_record, prepared = _prepared(tmp_path)
    parent = _private_directory(tmp_path / "availability")
    release_root = parent / "publisher-a"
    write_publisher_batch(prepared, release_root)
    policy_path = parent / "policy.json"
    window_path = parent / "window.json"
    policy_path.write_bytes(canonical_json_bytes(policy))
    window_path.write_bytes(canonical_json_bytes(window))
    policy_path.chmod(0o400)
    window_path.chmod(0o400)
    config_path = parent / "assembly.json"
    arguments = [
        "availability-config",
        "--policy",
        str(policy_path),
        "--window",
        str(window_path),
        "--release-root",
        str(release_root),
        "--output",
        str(config_path),
    ]

    assert publisher_batch_cli_module.run_cli([*arguments, "--check"]) == 0
    stdout, stderr = capsysbinary.readouterr()
    assert stderr == b""
    assert json.loads(stdout)["state_mutated"] is False
    assert not config_path.exists()

    assert publisher_batch_cli_module.run_cli(arguments) == 0
    stdout, stderr = capsysbinary.readouterr()
    assert stderr == b""
    assert json.loads(stdout)["batch_count"] == 1
    config = AvailabilityAssemblyConfig.model_validate_json(config_path.read_bytes())
    assert canonical_json_bytes(config) == config_path.read_bytes()
    assert config.pool_body_paths == [str(release_root / "pool-body.json")]
    assert len(config.videos) == 14
    assert stat.S_IMODE(config_path.stat().st_mode) == 0o400


def test_release_loader_rejects_tampering(tmp_path: Path) -> None:
    policy, window, _identity_record, _source_record, prepared = _prepared(tmp_path)
    parent = _private_directory(tmp_path / "tamper")
    release_root = parent / "publisher-a"
    write_publisher_batch(prepared, release_root)
    target = release_root / "pool-body.json"
    target.chmod(0o600)
    target.write_bytes(target.read_bytes() + b" ")
    target.chmod(0o400)

    with pytest.raises(PublisherBatchError, match="release_object_mismatch"):
        load_publisher_batch_release(release_root, policy=policy, window=window)
