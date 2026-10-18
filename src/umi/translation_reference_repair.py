"""Explicit local repair of follower indexes under the original stopped lock.

Missing signed bytes or native verification results require restoration of the
original records. This command cannot recreate authority, sign or submit.
"""

import argparse
from pathlib import Path

from .protocol import canonical_json_bytes
from .translation_reference_legacy_state import ReferenceLegacyState
from .translation_reference_transactions import ReferenceWeightJournal
from .translation_reference_worker import REFERENCE_JOURNAL_MAXIMUM_BYTES


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-root", type=Path, required=True)
    parser.add_argument("--validator-hotkey", required=True)
    args = parser.parse_args()

    def progress(value):
        print(canonical_json_bytes(value).decode(), flush=True)

    with ReferenceLegacyState(args.state_root, progress=progress) as legacy:
        ReferenceWeightJournal(
            legacy.follower_root,
            validator_hotkey=args.validator_hotkey,
            maximum_bytes=REFERENCE_JOURNAL_MAXIMUM_BYTES,
            repair_head_index=True,
            progress=progress,
        )
        legacy.require_owner()


if __name__ == "__main__":
    main()
