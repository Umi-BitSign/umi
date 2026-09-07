"""Single-writer installation of completed public-pilot bundles."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import shutil
import stat
import tarfile
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from .audit import EvidenceStore, _read_bounded_regular_file
from .encoding import account_id32
from .observer_pilot_feed import (
    MAX_PILOT_CONFIG_BYTES,
    PILOT_EVIDENCE_CLASS,
    PILOT_FEED_CONFIG_SCHEMA,
    build_observer_pilot_feed,
)
from .protocol import PROTOCOL_VERSION, canonical_json_bytes
from .public_pilot_archive import MAX_PUBLIC_PILOT_ARCHIVE_BYTES, extract_evidence_archive
from .public_pilot_coordinator import replay_public_endpoint_pilot


@dataclass(frozen=True, slots=True)
class PilotPublicationResult:
    pilot_id: str
    installed_root: str
    configured_pilot_ids: tuple[str, ...]
    already_installed: bool

    def as_dict(self) -> dict[str, object]:
        return {
            "status": "public_pilot_installed",
            "pilot_id": self.pilot_id,
            "installed_root": self.installed_root,
            "configured_pilot_ids": list(self.configured_pilot_ids),
            "already_installed": self.already_installed,
        }


class InvalidPublicPilotArchive(ValueError):
    """An incoming archive failed bounded extraction or public-pilot replay."""


def _require_private_directory(path: Path) -> Path:
    expanded = path.expanduser()
    if not expanded.is_absolute():
        raise ValueError("pilot publication directory path must be absolute")
    metadata = expanded.lstat()
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_mode & 0o077
    ):
        raise ValueError("pilot publication directory is unsafe")
    return expanded.resolve(strict=True)


@contextmanager
def _publication_lock(path: Path) -> Iterator[None]:
    if not path.is_absolute():
        raise ValueError("pilot publication lock path must be absolute")
    parent = _require_private_directory(path.parent)
    lock = parent / path.name
    descriptor = os.open(
        lock,
        os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != os.geteuid()
        ):
            raise ValueError("pilot publication lock is unsafe")
        os.fchmod(descriptor, 0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _write_new(path: Path, data: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        offset = 0
        while offset < len(data):
            written = os.write(descriptor, data[offset:])
            if written <= 0:
                raise OSError("pilot publication write made no progress")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _replay_for_coordinator(root: Path, expected_coordinator_hotkey: str) -> dict[str, object]:
    replay = replay_public_endpoint_pilot(root)
    actual = replay.get("coordinator_hotkey")
    if not isinstance(actual, str) or account_id32(actual) != account_id32(
        expected_coordinator_hotkey
    ):
        raise ValueError("pilot bundle was not signed by the configured coordinator")
    return replay


def _copy_verified_tree(
    source: Path,
    destination: Path,
    *,
    expected_coordinator_hotkey: str,
) -> None:
    staging = Path(tempfile.mkdtemp(prefix=f".{destination.name}.", dir=destination.parent))
    os.chmod(staging, 0o700)
    try:
        (staging / "objects").mkdir(mode=0o700)
        manifest = _read_bounded_regular_file(
            source / "manifest.json", EvidenceStore(source).maximum_manifest_bytes
        )
        _write_new(staging / "manifest.json", manifest)
        for object_path in sorted((source / "objects").iterdir(), key=lambda item: item.name):
            data = _read_bounded_regular_file(
                object_path, EvidenceStore(source).maximum_object_bytes
            )
            _write_new(staging / "objects" / object_path.name, data)
        _fsync_directory(staging / "objects")
        _fsync_directory(staging)
        _replay_for_coordinator(staging, expected_coordinator_hotkey)
        os.rename(staging, destination)
        _fsync_directory(destination.parent)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def _base_config(public_origin: str) -> dict[str, object]:
    return {
        "schema": PILOT_FEED_CONFIG_SCHEMA,
        "protocol": PROTOCOL_VERSION,
        "mode": PILOT_EVIDENCE_CLASS,
        "translation_weights_active": False,
        "protocol_conformance": False,
        "activation_evidence": False,
        "public_origin": public_origin,
        "bundle_roots": [],
    }


def install_public_pilot(
    source_root: Path,
    *,
    publication_root: Path,
    config_path: Path,
    lock_path: Path,
    public_origin: str,
    expected_coordinator_hotkey: str,
) -> PilotPublicationResult:
    """Replay, install, and append one bundle under an exclusive publication lock."""

    source = _require_private_directory(source_root)
    destination_parent = _require_private_directory(publication_root)
    config_input = config_path.expanduser()
    if not config_input.is_absolute():
        raise ValueError("pilot publication config path must be absolute")
    config_parent = _require_private_directory(config_input.parent)
    config = config_parent / config_input.name
    if config.exists() and stat.S_ISLNK(config.lstat().st_mode):
        raise ValueError("pilot publication config path is unsafe")
    account_id32(expected_coordinator_hotkey)
    replay = _replay_for_coordinator(source, expected_coordinator_hotkey)
    pilot_id = str(replay["bundle_manifest_sha256"])
    destination = destination_parent / pilot_id

    with _publication_lock(lock_path.expanduser()):
        original: bytes | None = None
        old_ids: set[str] = set()
        if config.exists():
            old_feed = build_observer_pilot_feed(config)
            old_ids = {pilot.pilot_id for pilot in old_feed.pilots}
            original = _read_bounded_regular_file(config, MAX_PILOT_CONFIG_BYTES)
            decoded = json.loads(original)
        else:
            decoded = _base_config(public_origin)
        if decoded.get("public_origin") != public_origin:
            raise ValueError("pilot publication origin differs from the installed feed")

        already_installed = destination.exists()
        if already_installed:
            installed = _replay_for_coordinator(destination, expected_coordinator_hotkey)
            if installed["bundle_manifest_sha256"] != pilot_id:
                raise ValueError("installed pilot path contains another bundle")
        else:
            _copy_verified_tree(
                source,
                destination,
                expected_coordinator_hotkey=expected_coordinator_hotkey,
            )

        roots = decoded.get("bundle_roots")
        if not isinstance(roots, list) or any(not isinstance(item, str) for item in roots):
            raise ValueError("installed pilot config has an invalid bundle list")
        destination_text = str(destination)
        if destination_text not in roots:
            decoded["bundle_roots"] = [*roots, destination_text]
            candidate_bytes = canonical_json_bytes(decoded)
            candidate = config.with_name(f".{config.name}.candidate-{pilot_id}")
            if candidate.exists():
                raise ValueError("stale pilot config candidate requires operator review")
            try:
                _write_new(candidate, candidate_bytes)
                candidate_feed = build_observer_pilot_feed(candidate)
                new_ids = {pilot.pilot_id for pilot in candidate_feed.pilots}
                if not old_ids.issubset(new_ids) or pilot_id not in new_ids:
                    raise ValueError("candidate pilot config is not an append-only feed")
                if original is not None:
                    active = _read_bounded_regular_file(config, MAX_PILOT_CONFIG_BYTES)
                    if active != original:
                        raise ValueError("pilot config changed during locked publication")
                    backup = config.with_name(f"{config.name}.before-{pilot_id}")
                    if backup.exists():
                        if _read_bounded_regular_file(backup, MAX_PILOT_CONFIG_BYTES) != original:
                            raise ValueError(
                                "pilot config backup conflicts with current publication"
                            )
                    else:
                        _write_new(backup, original)
                if (
                    not config.exists()
                    or _read_bounded_regular_file(config, MAX_PILOT_CONFIG_BYTES) != candidate_bytes
                ):
                    os.replace(candidate, config)
                    _fsync_directory(config.parent)
                else:
                    candidate.unlink()
            finally:
                candidate.unlink(missing_ok=True)

        installed_feed = build_observer_pilot_feed(config)
        installed_ids = tuple(pilot.pilot_id for pilot in installed_feed.pilots)
        if pilot_id not in installed_ids or not old_ids.issubset(installed_ids):
            raise ValueError("installed pilot feed failed its final replay")
        return PilotPublicationResult(
            pilot_id=pilot_id,
            installed_root=str(destination),
            configured_pilot_ids=installed_ids,
            already_installed=already_installed,
        )


def import_public_pilot_archive(
    archive_path: Path,
    *,
    work_root: Path,
    publication_root: Path,
    config_path: Path,
    lock_path: Path,
    public_origin: str,
    expected_coordinator_hotkey: str,
) -> PilotPublicationResult:
    """Safely extract an incoming bundle archive and install it through the sole writer."""

    workspace = _require_private_directory(work_root)
    # A malformed deployment value is an operator error, not evidence that the
    # producer supplied a bad archive. Validate it before the quarantine boundary.
    account_id32(expected_coordinator_hotkey)
    archive_digest = hashlib.sha256(
        _read_bounded_regular_file(archive_path, MAX_PUBLIC_PILOT_ARCHIVE_BYTES)
    ).hexdigest()
    extracted = workspace / f"incoming-{archive_digest}"
    if extracted.exists():
        shutil.rmtree(extracted)
    try:
        try:
            extract_evidence_archive(archive_path, extracted, archive_root="bundle")
            _replay_for_coordinator(extracted, expected_coordinator_hotkey)
        except (EOFError, RuntimeError, ValueError, tarfile.TarError) as error:
            raise InvalidPublicPilotArchive(
                "incoming public-pilot archive failed verification"
            ) from error
        return install_public_pilot(
            extracted,
            publication_root=publication_root,
            config_path=config_path,
            lock_path=lock_path,
            public_origin=public_origin,
            expected_coordinator_hotkey=expected_coordinator_hotkey,
        )
    finally:
        shutil.rmtree(extracted, ignore_errors=True)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Install one completed UMI public pilot bundle")
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--work-root", type=Path, required=True)
    parser.add_argument("--publication-root", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--public-origin", required=True)
    parser.add_argument("--expected-coordinator-hotkey", required=True)
    return parser


def main() -> None:
    args = _parser().parse_args()
    result = import_public_pilot_archive(
        args.archive,
        work_root=args.work_root,
        publication_root=args.publication_root,
        config_path=args.config,
        lock_path=args.lock,
        public_origin=args.public_origin,
        expected_coordinator_hotkey=args.expected_coordinator_hotkey,
    )
    print(canonical_json_bytes(result.as_dict()).decode())


__all__ = [
    "InvalidPublicPilotArchive",
    "PilotPublicationResult",
    "import_public_pilot_archive",
    "install_public_pilot",
]


if __name__ == "__main__":
    main()
