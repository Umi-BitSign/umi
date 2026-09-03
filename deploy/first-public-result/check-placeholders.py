#!/usr/bin/env python3
"""Reject unresolved deployment examples before a service can be started."""

from __future__ import annotations

import argparse
import json
import stat
import sys
from pathlib import Path

_MAX_FILE_BYTES = 1024 * 1024
_FORBIDDEN_MARKERS = (
    "REPLACE_WITH",
    "https://audits.example.org",
    "5DXDWSgAioftJk5CBhnE1WM7hJVAiCsXALSLxzcV5ouKLo5p",
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="fail if installed UMI deployment files retain example values"
    )
    parser.add_argument(
        "--observer-feed",
        type=Path,
        help="also inspect every publication_config_path named by this observer feed",
    )
    parser.add_argument("files", nargs="+", type=Path)
    return parser


def _read_regular_utf8(path: Path) -> str:
    if not path.is_absolute():
        raise ValueError("path_is_not_absolute")
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ValueError("path_is_not_one_regular_file")
    if info.st_size == 0 or info.st_size > _MAX_FILE_BYTES:
        raise ValueError("file_size_is_invalid")
    return path.read_bytes().decode("utf-8", errors="strict")


def _observer_publication_paths(path: Path, encoded: str) -> tuple[Path, ...]:
    try:
        document = json.loads(encoded)
        targets = document["targets"]
        if not isinstance(targets, list) or not targets:
            raise ValueError
        values = tuple(Path(item["publication_config_path"]) for item in targets)
        if any(not value.is_absolute() for value in values):
            raise ValueError
        if len(values) != len(set(values)):
            raise ValueError
        return values
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise ValueError("observer_feed_targets_are_invalid") from error


def main() -> int:
    args = _parser().parse_args()
    paths = list(args.files)
    errors: list[str] = []

    if args.observer_feed is not None:
        paths.append(args.observer_feed)
        try:
            feed = _read_regular_utf8(args.observer_feed)
            paths.extend(_observer_publication_paths(args.observer_feed, feed))
        except (OSError, UnicodeError, ValueError) as error:
            errors.append(f"{args.observer_feed}: {error}")

    unique_paths = tuple(dict.fromkeys(paths))
    for path in unique_paths:
        try:
            encoded = _read_regular_utf8(path)
        except (OSError, UnicodeError, ValueError) as error:
            errors.append(f"{path}: {error}")
            continue
        for marker in _FORBIDDEN_MARKERS:
            if marker in encoded:
                errors.append(f"{path}: unresolved marker {marker!r}")

    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    print(f"deployment_files_resolved={len(unique_paths)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
