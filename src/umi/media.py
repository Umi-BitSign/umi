"""Fail-closed MP4/H.264 conformance checks and protocol frame digests."""

from __future__ import annotations

import hashlib
import json
import os
import re
import selectors
import shutil
import stat
import subprocess
import tempfile
import time
from collections.abc import Iterable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from fractions import Fraction
from pathlib import Path
from typing import Any

from .encoding import sha256_domain, u32be

MAX_PROBE_OUTPUT_BYTES = 1024 * 1024
MAX_DECODER_ERROR_BYTES = 64 * 1024


class MediaConformanceError(RuntimeError):
    """A clip or decoder does not match the policy-pinned media profile."""


@dataclass(frozen=True)
class MediaProfile:
    size_bytes: int
    duration: Fraction
    width: int
    height: int
    frame_rate: Fraction
    codec_name: str
    format_names: tuple[str, ...]


@dataclass(frozen=True)
class FrameDigestResult:
    frame_digest: str
    frame_count: int
    width: int
    height: int
    decoder_sha256: str


@dataclass(frozen=True)
class MediaInspectionResult:
    video_sha256: str
    profile: MediaProfile
    frames: FrameDigestResult


@dataclass(frozen=True)
class _ClipSnapshot:
    path: Path
    size_bytes: int
    sha256: str


def frame_digest(width: int, height: int, frames: Iterable[bytes]) -> tuple[str, int]:
    if width <= 0 or height <= 0:
        raise ValueError("frame dimensions must be positive")
    expected_size = width * height * 3
    per_frame: list[bytes] = []
    for frame in frames:
        if not isinstance(frame, bytes) or len(frame) != expected_size:
            raise ValueError("RGB24 frame has the wrong byte length")
        per_frame.append(hashlib.sha256(u32be(width) + u32be(height) + frame).digest())
    if not per_frame:
        raise ValueError("frame digest requires at least one decoded frame")
    return (
        sha256_domain(
            b"umi-frames-v1\0",
            u32be(len(per_frame)),
            b"".join(per_frame),
        ).hex(),
        len(per_frame),
    )


def probe_media(
    path: str | Path,
    *,
    ffprobe: str = "ffprobe",
    maximum_clip_size: int = 16 * 1024 * 1024,
    timeout_seconds: float = 15.0,
) -> MediaProfile:
    with _snapshot_clip(path, maximum_clip_size) as snapshot:
        return _probe_snapshot(
            snapshot,
            ffprobe=ffprobe,
            timeout_seconds=timeout_seconds,
        )


def _probe_snapshot(
    snapshot: _ClipSnapshot,
    *,
    ffprobe: str,
    timeout_seconds: float,
) -> MediaProfile:
    _verify_snapshot(snapshot)
    executable = _executable(ffprobe)
    command = [
        executable,
        "-v",
        "error",
        "-show_streams",
        "-show_format",
        "-of",
        "json",
        str(snapshot.path),
    ]
    return_code, stdout, _stderr = _run_bounded_command(
        command,
        timeout_seconds=timeout_seconds,
        maximum_stdout_bytes=MAX_PROBE_OUTPUT_BYTES,
        maximum_stderr_bytes=MAX_PROBE_OUTPUT_BYTES,
        label="ffprobe",
    )
    if return_code != 0:
        raise MediaConformanceError("ffprobe could not parse the clip")
    try:
        document = json.loads(stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise MediaConformanceError("ffprobe did not return valid JSON") from error
    _verify_snapshot(snapshot)
    return profile_from_probe(document, size_bytes=snapshot.size_bytes)


def profile_from_probe(document: Mapping[str, Any], *, size_bytes: int) -> MediaProfile:
    streams = document.get("streams")
    format_record = document.get("format")
    if not isinstance(streams, list) or not isinstance(format_record, Mapping):
        raise MediaConformanceError("ffprobe document is missing streams or format")
    video_streams = [item for item in streams if item.get("codec_type") == "video"]
    audio_streams = [item for item in streams if item.get("codec_type") == "audio"]
    if len(video_streams) != 1 or audio_streams:
        raise MediaConformanceError("clip must contain one video stream and no audio")
    if len(streams) != 1:
        raise MediaConformanceError("clip contains an unsupported auxiliary stream")
    video = video_streams[0]
    if video.get("codec_name") != "h264":
        raise MediaConformanceError("video codec must be H.264")
    try:
        width = int(video["width"])
        height = int(video["height"])
    except (KeyError, TypeError, ValueError) as error:
        raise MediaConformanceError("video dimensions are missing or invalid") from error
    if width <= 0 or height <= 0 or width > 1280 or height > 720:
        raise MediaConformanceError("video dimensions exceed the 1280x720 profile")
    frame_rate = _fraction(video.get("avg_frame_rate") or video.get("r_frame_rate"))
    if frame_rate <= 0 or frame_rate > 30:
        raise MediaConformanceError("video frame rate must be in (0, 30]")
    duration = _fraction(video.get("duration") or format_record.get("duration"))
    if duration < 2 or duration > 15:
        raise MediaConformanceError("video duration must be from 2 through 15 seconds")
    format_names = tuple(sorted(set(str(format_record.get("format_name", "")).split(","))))
    if "mp4" not in format_names:
        raise MediaConformanceError("video container must be MP4")
    _validate_metadata(format_record.get("tags"), video.get("tags"))
    return MediaProfile(
        size_bytes=size_bytes,
        duration=duration,
        width=width,
        height=height,
        frame_rate=frame_rate,
        codec_name="h264",
        format_names=format_names,
    )


def decode_frame_digest(
    path: str | Path,
    *,
    ffmpeg: str = "ffmpeg",
    ffprobe: str = "ffprobe",
    maximum_clip_size: int = 16 * 1024 * 1024,
    timeout_seconds: float = 30.0,
) -> FrameDigestResult:
    with _snapshot_clip(path, maximum_clip_size) as snapshot:
        profile = _probe_snapshot(
            snapshot,
            ffprobe=ffprobe,
            timeout_seconds=min(timeout_seconds, 15.0),
        )
        return _decode_snapshot(
            snapshot,
            profile,
            ffmpeg=ffmpeg,
            timeout_seconds=timeout_seconds,
        )


def inspect_media(
    path: str | Path,
    *,
    ffmpeg: str = "ffmpeg",
    ffprobe: str = "ffprobe",
    maximum_clip_size: int = 16 * 1024 * 1024,
    probe_timeout_seconds: float = 15.0,
    decode_timeout_seconds: float = 30.0,
) -> MediaInspectionResult:
    """Probe, hash, and decode one bounded immutable snapshot of caller bytes."""

    with _snapshot_clip(path, maximum_clip_size) as snapshot:
        profile = _probe_snapshot(
            snapshot,
            ffprobe=ffprobe,
            timeout_seconds=probe_timeout_seconds,
        )
        decoded = _decode_snapshot(
            snapshot,
            profile,
            ffmpeg=ffmpeg,
            timeout_seconds=decode_timeout_seconds,
        )
        _verify_snapshot(snapshot)
        return MediaInspectionResult(
            video_sha256=snapshot.sha256,
            profile=profile,
            frames=decoded,
        )


def _decode_snapshot(
    snapshot: _ClipSnapshot,
    profile: MediaProfile,
    *,
    ffmpeg: str,
    timeout_seconds: float,
) -> FrameDigestResult:
    _verify_snapshot(snapshot)
    executable = _executable(ffmpeg)
    decoder_sha256 = _file_sha256(Path(executable))
    command = [
        executable,
        "-v",
        "error",
        "-i",
        str(snapshot.path),
        "-map",
        "0:v:0",
        "-fps_mode",
        "passthrough",
        "-pix_fmt",
        "rgb24",
        "-f",
        "rawvideo",
        "pipe:1",
    ]
    process = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if process.stdout is None or process.stderr is None:
        process.kill()
        raise MediaConformanceError("decoder pipes were not created")
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    deadline = time.monotonic() + timeout_seconds
    frame_size = profile.width * profile.height * 3
    maximum_frames = 15 * 30
    buffer = bytearray()
    frame_hashes: list[bytes] = []
    error_bytes = bytearray()
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise MediaConformanceError("frame decoder exceeded its deadline")
            events = selector.select(timeout=remaining)
            if not events:
                raise MediaConformanceError("frame decoder exceeded its deadline")
            for key, _ in events:
                chunk = os.read(key.fileobj.fileno(), 64 * 1024)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                if key.data == "stderr":
                    if len(error_bytes) < MAX_DECODER_ERROR_BYTES:
                        error_bytes.extend(chunk[: MAX_DECODER_ERROR_BYTES - len(error_bytes)])
                    continue
                buffer.extend(chunk)
                while len(buffer) >= frame_size:
                    frame = bytes(buffer[:frame_size])
                    del buffer[:frame_size]
                    frame_hashes.append(
                        hashlib.sha256(
                            u32be(profile.width) + u32be(profile.height) + frame
                        ).digest()
                    )
                    if len(frame_hashes) > maximum_frames:
                        raise MediaConformanceError("decoded frame count exceeds the profile")
        return_code = process.wait(timeout=max(0.1, deadline - time.monotonic()))
    except Exception:
        process.kill()
        process.wait()
        raise
    finally:
        selector.close()
    if return_code != 0:
        raise MediaConformanceError("ffmpeg could not decode the clip")
    if buffer or not frame_hashes:
        raise MediaConformanceError("decoder output is empty or not whole RGB24 frames")
    _verify_snapshot(snapshot)
    digest = sha256_domain(
        b"umi-frames-v1\0",
        u32be(len(frame_hashes)),
        b"".join(frame_hashes),
    ).hex()
    return FrameDigestResult(
        frame_digest=digest,
        frame_count=len(frame_hashes),
        width=profile.width,
        height=profile.height,
        decoder_sha256=decoder_sha256,
    )


@contextmanager
def _snapshot_clip(path: str | Path, maximum_clip_size: int) -> Iterator[_ClipSnapshot]:
    """Copy one regular file descriptor into a bounded content-addressed snapshot."""

    if maximum_clip_size <= 0:
        raise ValueError("maximum clip size must be positive")
    source = Path(path).expanduser().absolute()
    try:
        path_metadata = source.lstat()
    except OSError as error:
        raise MediaConformanceError("clip cannot be opened") from error
    if not stat.S_ISREG(path_metadata.st_mode):
        raise MediaConformanceError("clip must be a regular non-symlink file")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        source_descriptor = os.open(source, flags)
    except OSError as error:
        raise MediaConformanceError("clip cannot be opened safely") from error

    temporary_directory: Path | None = None
    temporary_descriptor: int | None = None
    try:
        metadata_before = os.fstat(source_descriptor)
        if not stat.S_ISREG(metadata_before.st_mode):
            raise MediaConformanceError("clip must be a regular non-symlink file")
        if (path_metadata.st_dev, path_metadata.st_ino) != (
            metadata_before.st_dev,
            metadata_before.st_ino,
        ):
            raise MediaConformanceError("clip changed while it was opened")
        if metadata_before.st_size <= 0 or metadata_before.st_size > maximum_clip_size:
            raise MediaConformanceError("clip byte length is outside the media profile")

        temporary_directory = Path(tempfile.mkdtemp(prefix="umi-media-snapshot-"))
        partial_path = temporary_directory / "snapshot.partial"
        temporary_descriptor = os.open(
            partial_path,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            0o400,
        )
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(
                source_descriptor,
                min(64 * 1024, maximum_clip_size - total + 1),
            )
            if not chunk:
                break
            total += len(chunk)
            if total > maximum_clip_size:
                raise MediaConformanceError("clip byte length is outside the media profile")
            digest.update(chunk)
            _write_all(temporary_descriptor, chunk)

        metadata_after = os.fstat(source_descriptor)
        if total != metadata_before.st_size or _file_identity(metadata_before) != _file_identity(
            metadata_after
        ):
            raise MediaConformanceError("clip changed while its snapshot was copied")
        os.fsync(temporary_descriptor)
        os.close(temporary_descriptor)
        temporary_descriptor = None

        digest_hex = digest.hexdigest()
        snapshot_path = temporary_directory / f"{digest_hex}.mp4"
        os.replace(partial_path, snapshot_path)
        os.chmod(snapshot_path, 0o400)
        snapshot = _ClipSnapshot(
            path=snapshot_path,
            size_bytes=total,
            sha256=digest_hex,
        )
        _verify_snapshot(snapshot)
        yield snapshot
    finally:
        if temporary_descriptor is not None:
            os.close(temporary_descriptor)
        os.close(source_descriptor)
        if temporary_directory is not None:
            shutil.rmtree(temporary_directory, ignore_errors=True)


def _file_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _write_all(descriptor: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise MediaConformanceError("media snapshot could not be written")
        view = view[written:]


def _verify_snapshot(snapshot: _ClipSnapshot) -> None:
    try:
        path_metadata = snapshot.path.lstat()
    except OSError as error:
        raise MediaConformanceError("media snapshot is unavailable") from error
    if not stat.S_ISREG(path_metadata.st_mode):
        raise MediaConformanceError("media snapshot is not a regular file")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(snapshot.path, flags)
    except OSError as error:
        raise MediaConformanceError("media snapshot cannot be opened safely") from error
    try:
        metadata_before = os.fstat(descriptor)
        if not stat.S_ISREG(metadata_before.st_mode) or (
            path_metadata.st_dev,
            path_metadata.st_ino,
        ) != (metadata_before.st_dev, metadata_before.st_ino):
            raise MediaConformanceError("media snapshot changed while it was opened")
        digest = hashlib.sha256()
        total = 0
        while chunk := os.read(descriptor, 64 * 1024):
            total += len(chunk)
            digest.update(chunk)
        metadata_after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if _file_identity(metadata_before) != _file_identity(metadata_after):
        raise MediaConformanceError("media snapshot changed while it was verified")
    if total != snapshot.size_bytes:
        raise MediaConformanceError("media snapshot byte length changed")
    if digest.hexdigest() != snapshot.sha256:
        raise MediaConformanceError("media snapshot content changed")


def _executable(name: str) -> str:
    resolved = shutil.which(name)
    if resolved is None:
        raise MediaConformanceError(f"required media tool is unavailable: {name}")
    return str(Path(resolved).resolve())


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _fraction(value: Any) -> Fraction:
    try:
        fraction = Fraction(str(value))
    except (ValueError, ZeroDivisionError) as error:
        raise MediaConformanceError("media rational value is invalid") from error
    return fraction


def _validate_metadata(format_tags: Any, stream_tags: Any) -> None:
    allowed_format = {"major_brand", "minor_version", "compatible_brands"}
    allowed_stream = {"language", "handler_name", "vendor_id", "encoder"}
    for tags, allowed in ((format_tags, allowed_format), (stream_tags, allowed_stream)):
        if tags is None:
            continue
        if not isinstance(tags, Mapping):
            raise MediaConformanceError("media metadata tags are malformed")
        unexpected = {str(key).lower() for key in tags}.difference(allowed)
        if unexpected:
            raise MediaConformanceError("clip contains non-structural metadata")
    if format_tags is not None:
        _validate_format_tag_values(format_tags)
    if stream_tags is not None:
        _validate_stream_tag_values(stream_tags)


def _validate_format_tag_values(tags: Mapping[str, Any]) -> None:
    normalized = {str(key).lower(): value for key, value in tags.items()}
    structural_brands = {
        "avc1",
        "iso2",
        "iso3",
        "iso4",
        "iso5",
        "iso6",
        "isom",
        "mp41",
        "mp42",
    }
    major_brand = normalized.get("major_brand")
    if major_brand is not None and major_brand not in structural_brands:
        raise MediaConformanceError("clip contains answer-bearing or unknown brand metadata")
    minor_version = normalized.get("minor_version")
    if minor_version is not None and (
        not isinstance(minor_version, str)
        or not minor_version.isdecimal()
        or minor_version != str(int(minor_version))
    ):
        raise MediaConformanceError("clip contains malformed minor-version metadata")
    compatible = normalized.get("compatible_brands")
    if compatible is not None:
        if not isinstance(compatible, str) or not compatible or len(compatible) % 4:
            raise MediaConformanceError("clip contains malformed compatible-brand metadata")
        brands = {compatible[index : index + 4] for index in range(0, len(compatible), 4)}
        if not brands.issubset(structural_brands):
            raise MediaConformanceError("clip contains answer-bearing or unknown brand metadata")


def _validate_stream_tag_values(tags: Mapping[str, Any]) -> None:
    normalized = {str(key).lower(): value for key, value in tags.items()}
    allowed_exact = {
        "language": "und",
        "handler_name": "VideoHandler",
        "vendor_id": "[0][0][0][0]",
    }
    for key, expected in allowed_exact.items():
        value = normalized.get(key)
        if value is not None and value != expected:
            raise MediaConformanceError("clip contains answer-bearing stream metadata")
    encoder = normalized.get("encoder")
    if encoder is not None and (
        not isinstance(encoder, str)
        or re.fullmatch(r"Lavc(?:\d+\.\d+\.\d+)? libx264", encoder) is None
    ):
        raise MediaConformanceError("clip contains answer-bearing stream metadata")


def _run_bounded_command(
    command: list[str],
    *,
    timeout_seconds: float,
    maximum_stdout_bytes: int,
    maximum_stderr_bytes: int,
    label: str,
) -> tuple[int, bytes, bytes]:
    """Drain a child process without ever buffering past either evidence ceiling."""

    process = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if process.stdout is None or process.stderr is None:
        process.kill()
        process.wait()
        raise MediaConformanceError(f"{label} pipes were not created")
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    deadline = time.monotonic() + timeout_seconds
    stdout = bytearray()
    stderr = bytearray()
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise MediaConformanceError(f"{label} exceeded its deadline")
            events = selector.select(timeout=remaining)
            if not events:
                raise MediaConformanceError(f"{label} exceeded its deadline")
            for key, _ in events:
                chunk = os.read(key.fileobj.fileno(), 64 * 1024)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                target = stdout if key.data == "stdout" else stderr
                limit = maximum_stdout_bytes if key.data == "stdout" else maximum_stderr_bytes
                if len(target) + len(chunk) > limit:
                    raise MediaConformanceError(f"{label} output exceeds its evidence ceiling")
                target.extend(chunk)
        return_code = process.wait(timeout=max(0.1, deadline - time.monotonic()))
    except Exception:
        process.kill()
        process.wait()
        raise
    finally:
        selector.close()
    return return_code, bytes(stdout), bytes(stderr)


__all__ = [
    "FrameDigestResult",
    "MediaConformanceError",
    "MediaInspectionResult",
    "MediaProfile",
    "decode_frame_digest",
    "frame_digest",
    "inspect_media",
    "probe_media",
    "profile_from_probe",
]
