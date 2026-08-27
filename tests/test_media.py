from __future__ import annotations

import copy
import hashlib
import shutil
import subprocess

import pytest

import umi.media as media_module
from umi.media import (
    FrameDigestResult,
    MediaConformanceError,
    decode_frame_digest,
    frame_digest,
    inspect_media,
    probe_media,
    profile_from_probe,
)


def _probe_document() -> dict:
    return {
        "streams": [
            {
                "codec_type": "video",
                "codec_name": "h264",
                "width": 640,
                "height": 360,
                "avg_frame_rate": "30/1",
                "duration": "2.000000",
                "tags": {"language": "und", "handler_name": "VideoHandler"},
            }
        ],
        "format": {
            "format_name": "mov,mp4,m4a,3gp,3g2,mj2",
            "duration": "2.000000",
            "tags": {
                "major_brand": "isom",
                "minor_version": "512",
                "compatible_brands": "isomiso2avc1mp41",
            },
        },
    }


def test_media_profile_accepts_exact_boundaries_and_preserves_exact_rationals() -> None:
    document = _probe_document()
    document["streams"][0]["width"] = 1280
    document["streams"][0]["height"] = 720
    document["streams"][0]["duration"] = "15"
    document["format"]["duration"] = "15"
    profile = profile_from_probe(document, size_bytes=16 * 1024 * 1024)

    assert profile.width == 1280
    assert profile.height == 720
    assert profile.duration.numerator == 15
    assert profile.duration.denominator == 1
    assert profile.frame_rate.numerator == 30
    assert profile.format_names == ("3g2", "3gp", "m4a", "mj2", "mov", "mp4")


@pytest.mark.parametrize(
    ("case", "message"),
    [
        ("audio", "one video stream and no audio"),
        ("auxiliary", "unsupported auxiliary stream"),
        ("codec", "H.264"),
        ("dimensions", "dimensions"),
        ("frame_rate", "frame rate"),
        ("short_duration", "2 through 15"),
        ("long_duration", "2 through 15"),
        ("container", "MP4"),
        ("metadata", "non-structural metadata"),
    ],
)
def test_media_profile_rejects_each_nonconforming_dimension(case: str, message: str) -> None:
    document = copy.deepcopy(_probe_document())
    stream = document["streams"][0]
    if case == "audio":
        document["streams"].append({"codec_type": "audio"})
    elif case == "auxiliary":
        document["streams"].append({"codec_type": "subtitle"})
    elif case == "codec":
        stream["codec_name"] = "hevc"
    elif case == "dimensions":
        stream["width"] = 1281
    elif case == "frame_rate":
        stream["avg_frame_rate"] = "30001/1000"
    elif case == "short_duration":
        stream["duration"] = "1.999"
    elif case == "long_duration":
        stream["duration"] = "15.001"
    elif case == "container":
        document["format"]["format_name"] = "matroska,webm"
    elif case == "metadata":
        document["format"]["tags"]["title"] = "answer-bearing label"

    with pytest.raises(MediaConformanceError, match=message):
        profile_from_probe(document, size_bytes=1_000)


def test_frame_digest_reproduces_the_rgb24_formula_and_is_order_sensitive() -> None:
    frames = (b"\x00\x01\x02", b"\x03\x04\x05")
    expected = hashlib.sha256(
        b"umi-frames-v1\0"
        + (2).to_bytes(4, "big")
        + b"".join(
            hashlib.sha256((1).to_bytes(4, "big") + (1).to_bytes(4, "big") + frame).digest()
            for frame in frames
        )
    ).hexdigest()
    assert frame_digest(1, 1, frames) == (expected, 2)
    assert frame_digest(1, 1, tuple(reversed(frames)))[0] != expected

    with pytest.raises(ValueError, match="wrong byte length"):
        frame_digest(1, 1, (b"too long",))
    with pytest.raises(ValueError, match="at least one"):
        frame_digest(1, 1, ())


@pytest.mark.parametrize(
    ("tag", "value"),
    [
        ("handler_name", "the answer is hello"),
        ("encoder", "Lavc libx264 answer=hello"),
        ("language", "answer"),
    ],
)
def test_media_profile_rejects_answer_bearing_values_in_structural_tag_names(
    tag: str,
    value: str,
) -> None:
    document = _probe_document()
    document["streams"][0]["tags"][tag] = value
    with pytest.raises(MediaConformanceError, match="answer-bearing"):
        profile_from_probe(document, size_bytes=1_000)


def test_ffprobe_output_is_streamed_through_a_hard_evidence_ceiling(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clip = tmp_path / "clip.mp4"
    clip.write_bytes(b"not-empty")
    fake_probe = tmp_path / "ffprobe"
    fake_probe.write_text("#!/bin/sh\nprintf '%s' '" + "a" * 4_096 + "'\n")
    fake_probe.chmod(0o755)
    monkeypatch.setattr(media_module, "MAX_PROBE_OUTPUT_BYTES", 64)

    with pytest.raises(MediaConformanceError, match="evidence ceiling"):
        probe_media(clip, ffprobe=str(fake_probe))


def test_probe_rejects_empty_oversized_and_symlink_inputs_before_invoking_ffprobe(tmp_path) -> None:
    empty = tmp_path / "empty.mp4"
    empty.write_bytes(b"")
    with pytest.raises(MediaConformanceError, match="byte length"):
        probe_media(empty)

    oversized = tmp_path / "oversized.mp4"
    oversized.write_bytes(b"xx")
    with pytest.raises(MediaConformanceError, match="byte length"):
        probe_media(oversized, maximum_clip_size=1)

    link = tmp_path / "linked.mp4"
    link.symlink_to(oversized)
    with pytest.raises(MediaConformanceError, match="non-symlink"):
        probe_media(link)


def test_inspection_keeps_probe_decode_and_hash_on_one_snapshot(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clip = tmp_path / "clip.mp4"
    original = b"original immutable clip bytes"
    replacement = b"replacement caller path bytes"
    clip.write_bytes(original)
    snapshot_paths = []
    profile = profile_from_probe(_probe_document(), size_bytes=len(original))
    decoded = FrameDigestResult(
        frame_digest="12" * 32,
        frame_count=60,
        width=profile.width,
        height=profile.height,
        decoder_sha256="34" * 32,
    )

    def fake_probe(snapshot, **_kwargs):
        snapshot_paths.append(snapshot.path)
        assert snapshot.path.read_bytes() == original
        clip.write_bytes(replacement)
        return profile

    def fake_decode(snapshot, actual_profile, **_kwargs):
        snapshot_paths.append(snapshot.path)
        assert actual_profile == profile
        assert snapshot.path.read_bytes() == original
        return decoded

    monkeypatch.setattr(media_module, "_probe_snapshot", fake_probe)
    monkeypatch.setattr(media_module, "_decode_snapshot", fake_decode)

    result = inspect_media(clip)

    assert result.video_sha256 == hashlib.sha256(original).hexdigest()
    assert result.profile == profile
    assert result.frames == decoded
    assert clip.read_bytes() == replacement
    assert snapshot_paths[0] == snapshot_paths[1]
    assert not snapshot_paths[0].exists()


def test_snapshot_rejects_in_place_mutation_during_bounded_copy(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clip = tmp_path / "clip.mp4"
    clip.write_bytes(b"a" * (128 * 1024))
    real_read = media_module.os.read
    mutated = False

    def mutating_read(descriptor: int, maximum_bytes: int) -> bytes:
        nonlocal mutated
        chunk = real_read(descriptor, maximum_bytes)
        if chunk and not mutated:
            mutated = True
            with clip.open("r+b") as handle:
                handle.seek(0)
                handle.write(b"b")
                handle.flush()
        return chunk

    monkeypatch.setattr(media_module.os, "read", mutating_read)

    with pytest.raises(MediaConformanceError, match="changed while its snapshot was copied"):
        probe_media(clip)


@pytest.mark.skipif(
    shutil.which("ffmpeg") is None or shutil.which("ffprobe") is None,
    reason="real media fixture requires ffmpeg and ffprobe",
)
def test_real_ffmpeg_fixture_probes_and_decodes_to_the_independent_frame_digest(tmp_path) -> None:
    clip = tmp_path / "black.mp4"
    generated = subprocess.run(
        [
            "ffmpeg",
            "-v",
            "error",
            "-y",
            "-f",
            "lavfi",
            "-i",
            "color=c=black:s=64x48:r=2:d=2",
            "-an",
            "-map_metadata",
            "-1",
            "-metadata",
            "encoder=",
            "-fflags",
            "+bitexact",
            "-flags:v",
            "+bitexact",
            "-c:v",
            "libx264",
            "-pix_fmt",
            "yuv420p",
            str(clip),
        ],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=False,
        timeout=20,
    )
    if generated.returncode != 0:
        pytest.skip("installed ffmpeg cannot create the H.264 fixture")

    profile = probe_media(clip)
    decoded = decode_frame_digest(clip)
    raw = subprocess.run(
        [
            "ffmpeg",
            "-v",
            "error",
            "-i",
            str(clip),
            "-map",
            "0:v:0",
            "-fps_mode",
            "passthrough",
            "-pix_fmt",
            "rgb24",
            "-f",
            "rawvideo",
            "pipe:1",
        ],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=True,
        timeout=20,
    ).stdout
    frame_size = profile.width * profile.height * 3
    assert len(raw) % frame_size == 0
    frames = tuple(raw[offset : offset + frame_size] for offset in range(0, len(raw), frame_size))
    independent_digest, independent_count = frame_digest(profile.width, profile.height, frames)

    assert decoded.frame_digest == independent_digest
    assert decoded.frame_count == independent_count == 4
    assert decoded.width == profile.width == 64
    assert decoded.height == profile.height == 48
    assert len(decoded.decoder_sha256) == 64
