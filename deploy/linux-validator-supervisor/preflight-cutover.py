"""Refuse unsupported legacy retirement before the installer changes services.

This stdlib-only helper belongs to the invoked installer, so it also works with
the older pinned host release. A normal installed supervisor retains its own
state and does not use the installer's foreign-unit retirement path.
"""

import argparse
import json
import os
import stat
import sys
from pathlib import Path

BOOTSTRAP_ONLY_RELEASES = {"5f9d189f819f5fca7572dd830ab080730edefe7e"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--preflight", type=Path, required=True)
    parser.add_argument("--release-revision", required=True)
    parser.add_argument("--legacy-unit", required=True)
    args = parser.parse_args()
    try:
        if len(args.release_revision) != 40 or any(
            c not in "0123456789abcdef" for c in args.release_revision
        ):
            raise ValueError
        st = args.preflight.lstat()
        if (
            not stat.S_ISREG(st.st_mode)
            or st.st_uid != os.geteuid()
            or st.st_nlink != 1
            or st.st_mode & 0o077
            or not 0 < st.st_size <= 1024 * 1024
        ):
            raise ValueError
        value = json.loads(args.preflight.read_bytes())
        if (
            value.get("status") != "common_switch_preflight_ok"
            or value.get("initial_hold_verified") is not True
            or type(value.get("sequence")) is not int
            or not 1 <= value["sequence"] <= 2**53 - 1
        ):
            raise ValueError
        mode = value.get("mode")
        if mode is None and args.release_revision in BOOTSTRAP_ONLY_RELEASES:
            mode = "bootstrap_service_weights"
        if mode not in {"bootstrap_service_weights", "translation_weights"}:
            raise ValueError
    except (OSError, ValueError, TypeError, AttributeError):
        print("installer_preflight_profile_invalid", file=sys.stderr)
        return 2
    if args.legacy_unit and mode == "translation_weights":
        print("translation_legacy_retirement_requires_preserving_migration", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
