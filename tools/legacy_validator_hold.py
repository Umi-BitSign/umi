#!/usr/bin/env python3
"""Wallet-free local hold process for an explicitly retired SN78 validator writer.

This file is intentionally standalone and standard-library only. It contains no
chain, wallet, HTTP, socket, subprocess, or process-control operation. A running
hold is a narrow host assertion; finalized chain observations remain the cutover
authority.
"""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import json
import os
import re
import signal
import stat
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

HOLD_SCHEMA = "umi-legacy-validator-hold/1"
RECEIPT_SCHEMA = "umi-legacy-validator-hold-receipt/1"
MAX_STATE_BYTES = 16 * 1024

_HEX40_RE = re.compile(r"^[0-9a-f]{40}$")
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_SAFE_PATH_RE = re.compile(r"^/[A-Za-z0-9._/+:-]+$")
_SAFE_GIT_REF_RE = re.compile(r"^refs/[A-Za-z0-9._/-]+$")
_UNIT_RE = re.compile(r"^[A-Za-z0-9_.@-]+\.service$")
_TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_BASE58_INDEX = {character: index for index, character in enumerate(_BASE58_ALPHABET)}
_SS58_PREFIX = b"SS58PRE"


class HoldError(RuntimeError):
    """A stable failure that is safe to show in operator output."""


class SafeArgumentParser(argparse.ArgumentParser):
    """Argument parser whose failures never echo possibly sensitive input."""

    def error(self, _message: str) -> None:
        raise HoldError("invalid_arguments")


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _source_sha256() -> str:
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def _decode_base58(value: str) -> bytes:
    number = 0
    try:
        for character in value:
            number = number * 58 + _BASE58_INDEX[character]
    except KeyError as exc:
        raise HoldError("invalid_hotkey") from exc
    decoded = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    return b"\x00" * (len(value) - len(value.lstrip("1"))) + decoded


def _validate_hotkey(value: str) -> str:
    if not 46 <= len(value) <= 50 or any(character.isspace() for character in value):
        raise HoldError("invalid_hotkey")
    decoded = _decode_base58(value)
    if len(decoded) != 35 or decoded[0] != 42:
        raise HoldError("invalid_hotkey")
    payload, checksum = decoded[:-2], decoded[-2:]
    expected = hashlib.blake2b(_SS58_PREFIX + payload, digest_size=64).digest()[:2]
    if checksum != expected:
        raise HoldError("invalid_hotkey")
    return value


def _validate_revision(value: str) -> str:
    if _HEX40_RE.fullmatch(value) is None:
        raise HoldError("invalid_umi_revision")
    return value


def _validate_sha256(value: str) -> str:
    if _HEX64_RE.fullmatch(value) is None:
        raise HoldError("invalid_source_sha256")
    return value


def _validate_timestamp(value: Any) -> str:
    if not isinstance(value, str) or _TIMESTAMP_RE.fullmatch(value) is None:
        raise HoldError("invalid_hold_timestamp")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise HoldError("invalid_hold_timestamp") from exc
    now = datetime.now(timezone.utc)
    if parsed.year < 2020 or parsed > now + timedelta(minutes=5):
        raise HoldError("invalid_hold_timestamp")
    return value


def _validate_absolute_path(value: str, reason: str) -> Path:
    if len(value) > 1024 or _SAFE_PATH_RE.fullmatch(value) is None or "%" in value:
        raise HoldError(reason)
    path = Path(value)
    if "." in path.parts or ".." in path.parts or str(path) != value:
        raise HoldError(reason)
    return path


def _check_source(expected_source_sha256: str) -> str:
    expected = _validate_sha256(expected_source_sha256)
    actual = _source_sha256()
    if actual != expected:
        raise HoldError("source_sha256_mismatch")
    return actual


def _read_small_file(path: Path, reason: str, maximum_bytes: int = 4096) -> str:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as handle:
            metadata = os.fstat(handle.fileno())
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or metadata.st_nlink != 1
            ):
                raise HoldError(reason)
            body = handle.read(maximum_bytes + 1)
    except OSError as exc:
        raise HoldError(reason) from exc
    if not body or len(body) > maximum_bytes:
        raise HoldError(reason)
    try:
        return body.decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise HoldError(reason) from exc


def _verify_repository(repository_root: Path, revision: str, source_sha256: str) -> None:
    git_dir = repository_root / ".git"
    try:
        git_metadata = git_dir.lstat()
    except OSError as exc:
        raise HoldError("repository_git_dir_missing") from exc
    if stat.S_ISLNK(git_metadata.st_mode) or not stat.S_ISDIR(git_metadata.st_mode):
        raise HoldError("repository_git_dir_invalid")

    head = _read_small_file(git_dir / "HEAD", "repository_head_read_failed")
    if _HEX40_RE.fullmatch(head):
        actual_revision = head
    elif head.startswith("ref: "):
        reference = head.removeprefix("ref: ")
        if _SAFE_GIT_REF_RE.fullmatch(reference) is None or ".." in reference or "//" in reference:
            raise HoldError("repository_head_invalid")
        actual_revision = _read_small_file(
            git_dir / reference, "repository_head_reference_read_failed"
        )
    else:
        raise HoldError("repository_head_invalid")
    if actual_revision != revision:
        raise HoldError("repository_revision_mismatch")

    repository_script = repository_root / "tools" / "legacy_validator_hold.py"
    try:
        if not repository_script.samefile(Path(__file__)):
            raise HoldError("repository_script_mismatch")
        repository_source_sha256 = hashlib.sha256(repository_script.read_bytes()).hexdigest()
    except OSError as exc:
        raise HoldError("repository_script_read_failed") from exc
    if repository_source_sha256 != source_sha256:
        raise HoldError("repository_script_hash_mismatch")


def _reject_symlink_components(path: Path, reason: str) -> None:
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            return
        except OSError as exc:
            raise HoldError(reason) from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise HoldError(reason)


def _check_state_dir(path: Path) -> None:
    _reject_symlink_components(path, "unsafe_state_dir")
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise HoldError("state_dir_missing") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise HoldError("unsafe_state_dir")
    if metadata.st_uid != os.geteuid():
        raise HoldError("unsafe_state_dir_owner")
    if stat.S_IMODE(metadata.st_mode) != 0o700:
        raise HoldError("unsafe_state_dir_permissions")


def _prepare_state_dir(path: Path) -> None:
    _reject_symlink_components(path.parent, "unsafe_state_dir")
    previous_umask = os.umask(0o077)
    try:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
    except OSError as exc:
        raise HoldError("state_dir_create_failed") from exc
    finally:
        os.umask(previous_umask)
    _check_state_dir(path)


def _open_lock(path: Path, *, create: bool) -> Any:
    flags = os.O_RDWR | os.O_CLOEXEC | os.O_NONBLOCK
    if create:
        flags |= os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise HoldError("hold_lock_open_failed") from exc
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        os.close(descriptor)
        raise HoldError("unsafe_hold_lock")
    return os.fdopen(descriptor, "r+")


def _write_private_json(path: Path, value: dict[str, Any]) -> bytes:
    body = _canonical_json(value) + b"\n"
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor: int | None = None
    try:
        descriptor = os.open(temporary, flags, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = None
            handle.write(body)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except OSError as exc:
        if descriptor is not None:
            os.close(descriptor)
        with contextlib.suppress(FileNotFoundError):
            temporary.unlink()
        raise HoldError("hold_state_write_failed") from exc
    return body


def _read_marker(path: Path) -> tuple[dict[str, Any], bytes]:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as handle:
            metadata = os.fstat(handle.fileno())
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or metadata.st_nlink != 1
                or stat.S_IMODE(metadata.st_mode) != 0o600
            ):
                raise HoldError("unsafe_hold_marker")
            body = handle.read(MAX_STATE_BYTES + 1)
    except OSError as exc:
        raise HoldError("hold_marker_read_failed") from exc
    if not body or len(body) > MAX_STATE_BYTES:
        raise HoldError("invalid_hold_marker")
    try:
        value = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HoldError("invalid_hold_marker") from exc
    if not isinstance(value, dict) or _canonical_json(value) + b"\n" != body:
        raise HoldError("noncanonical_hold_marker")
    return value, body


def _identity(args: argparse.Namespace, source_sha256: str) -> dict[str, Any]:
    if not 0 <= args.uid <= 65535:
        raise HoldError("invalid_uid")
    revision = _validate_revision(args.umi_revision)
    repository_root = _validate_absolute_path(args.repository_root, "invalid_repository_root")
    _verify_repository(repository_root, revision, source_sha256)
    return {
        "hotkey": _validate_hotkey(args.hotkey),
        "source_sha256": source_sha256,
        "uid": args.uid,
        "umi_revision": revision,
    }


def _paths(args: argparse.Namespace) -> tuple[Path, Path, Path]:
    state_dir = _validate_absolute_path(args.state_dir, "invalid_state_dir")
    return state_dir, state_dir / "hold.lock", state_dir / "hold-state.json"


def _lock_is_held(lock_handle: Any) -> bool:
    try:
        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return True
    fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)
    return False


def _run(args: argparse.Namespace) -> int:
    source_sha256 = _check_source(args.expected_source_sha256)
    identity = _identity(args, source_sha256)
    state_dir, lock_path, marker_path = _paths(args)
    _prepare_state_dir(state_dir)
    with _open_lock(lock_path, create=True) as lock_handle:
        try:
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise HoldError("hold_already_running") from exc

        marker = {
            "schema": HOLD_SCHEMA,
            **identity,
            "started_at": _utc_now(),
            "status": "hold_process_running",
        }
        _write_private_json(marker_path, marker)
        sys.stdout.buffer.write(_canonical_json(marker) + b"\n")
        sys.stdout.buffer.flush()

        stopping = False

        def request_stop(_signum: int, _frame: Any) -> None:
            nonlocal stopping
            stopping = True

        signal.signal(signal.SIGINT, request_stop)
        signal.signal(signal.SIGTERM, request_stop)
        while not stopping:
            time.sleep(1)

        stopped_marker = {
            **marker,
            "status": "hold_process_stopped",
            "stopped_at": _utc_now(),
        }
        _write_private_json(marker_path, stopped_marker)
    return 0


def _receipt(args: argparse.Namespace) -> int:
    source_sha256 = _check_source(args.expected_source_sha256)
    identity = _identity(args, source_sha256)
    state_dir, lock_path, marker_path = _paths(args)
    _check_state_dir(state_dir)
    with _open_lock(lock_path, create=False) as lock_handle:
        if not _lock_is_held(lock_handle):
            raise HoldError("hold_not_running")
        marker, marker_body = _read_marker(marker_path)

    started_at = _validate_timestamp(marker.get("started_at"))
    expected_marker = {
        "schema": HOLD_SCHEMA,
        **identity,
        "started_at": started_at,
        "status": "hold_process_running",
    }
    if marker != expected_marker:
        raise HoldError("hold_marker_identity_mismatch")

    receipt = {
        "schema": RECEIPT_SCHEMA,
        **identity,
        "hold_started_at": started_at,
        "marker_sha256": hashlib.sha256(marker_body).hexdigest(),
        "observed_at": _utc_now(),
        "status": "hold_lock_observed",
        "scope": "local_process_observation_only",
    }
    sys.stdout.buffer.write(_canonical_json(receipt) + b"\n")
    return 0


def _render_systemd_user(args: argparse.Namespace) -> int:
    source_sha256 = _check_source(args.expected_source_sha256)
    identity = _identity(args, source_sha256)
    state_dir, _, _ = _paths(args)
    repository_root = _validate_absolute_path(args.repository_root, "invalid_repository_root")
    python_path = _validate_absolute_path(args.python, "invalid_python_path")
    script_path = _validate_absolute_path(args.script, "invalid_script_path")
    output_path = _validate_absolute_path(args.output, "invalid_unit_output_path")
    if _UNIT_RE.fullmatch(output_path.name) is None:
        raise HoldError("invalid_unit_name")
    if not python_path.is_file() or not os.access(python_path, os.X_OK):
        raise HoldError("python_not_executable")
    try:
        target_script = script_path.read_bytes()
    except OSError as exc:
        raise HoldError("unit_script_read_failed") from exc
    if target_script != Path(__file__).read_bytes():
        raise HoldError("unit_script_source_mismatch")
    if output_path.exists() or output_path.is_symlink():
        raise HoldError("unit_output_exists")
    output_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    command = " ".join(
        (
            "/usr/bin/env",
            "-i",
            str(python_path),
            "-I",
            "-S",
            str(script_path),
            "run",
            "--uid",
            str(identity["uid"]),
            "--hotkey",
            str(identity["hotkey"]),
            "--umi-revision",
            str(identity["umi_revision"]),
            "--expected-source-sha256",
            str(identity["source_sha256"]),
            "--repository-root",
            str(repository_root),
            "--state-dir",
            str(state_dir),
        )
    )
    body = (
        "[Unit]\n"
        "Description=UMI SN78 legacy-validator hold\n"
        "Documentation=https://github.com/Umi-BitSign/umi\n\n"
        "[Service]\n"
        "Type=simple\n"
        f"ExecStart={command}\n"
        "Restart=always\n"
        "RestartSec=5\n"
        "NoNewPrivileges=true\n"
        "PrivateTmp=true\n"
        "RestrictAddressFamilies=AF_UNIX\n"
        "UMask=0077\n\n"
        "[Install]\n"
        "WantedBy=default.target\n"
    ).encode()
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(output_path, flags, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(body)
            handle.flush()
            os.fsync(handle.fileno())
    except OSError as exc:
        raise HoldError("unit_output_write_failed") from exc
    return 0


def _add_identity_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--uid", type=int, required=True)
    parser.add_argument("--hotkey", required=True)
    parser.add_argument("--umi-revision", required=True)
    parser.add_argument("--expected-source-sha256", required=True)
    parser.add_argument("--repository-root", required=True)
    parser.add_argument("--state-dir", required=True)


def _parser() -> argparse.ArgumentParser:
    parser = SafeArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    run = commands.add_parser("run", help="run the wallet-free local hold")
    _add_identity_arguments(run)
    run.set_defaults(function=_run)

    receipt = commands.add_parser("receipt", help="emit a public-safe local receipt")
    _add_identity_arguments(receipt)
    receipt.set_defaults(function=_receipt)

    render = commands.add_parser(
        "render-systemd-user", help="write a systemd user unit without starting it"
    )
    _add_identity_arguments(render)
    render.add_argument("--python", required=True)
    render.add_argument("--script", required=True)
    render.add_argument("--output", required=True)
    render.set_defaults(function=_render_systemd_user)
    return parser


def main() -> None:
    try:
        args = _parser().parse_args()
        code = args.function(args)
    except HoldError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1) from None
    except Exception:
        print("error: internal_failure", file=sys.stderr)
        raise SystemExit(1) from None
    raise SystemExit(code)


if __name__ == "__main__":
    main()
