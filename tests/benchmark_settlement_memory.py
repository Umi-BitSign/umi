"""Isolated storage benchmark, not real evidence replay or host qualification.

Run with PYTHONPATH=src and an explicit disposable directory under the caller's
task root. Payloads are synthetic strings. Retain the JSON results and remove
the directory after checking its dependencies. Never point this at live state.
"""

import argparse
import gc
import hashlib
import json
import os
import resource
import subprocess
import sys
import time
from pathlib import Path

from pydantic import BaseModel, ValidationError

from umi.competition_publication import PublicationReplayLimits
from umi.competition_round_journal import RoundJournal
from umi.competition_settlement_preparation import validate_preparation
from umi.private_files import publish_private_model, read_private_model


class Envelope(BaseModel):
    evidence: str


def memory():
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    if sys.platform == "linux":
        peak *= 1024
        status = Path("/proc/self/status").read_text().splitlines()
        current = int(next(line for line in status if line.startswith("VmRSS:")).split()[1]) * 1024
    elif sys.platform == "darwin":
        current = (
            int(subprocess.check_output(["ps", "-o", "rss=", "-p", str(os.getpid())], text=True))
            * 1024
        )
    else:
        raise ValueError("benchmark memory units are defined for Linux and macOS only")
    return {"peak_rss_bytes": peak, "current_rss_bytes": current}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mib", type=int, default=16)
    parser.add_argument("--directory", type=Path, required=True)
    args = parser.parse_args()
    if not 1 <= args.mib <= 256:
        parser.error("payload must be between 1 and 256 MiB")
    root = args.directory.absolute()
    # Existing paths, including symlinks, must never be reused.
    root.mkdir(mode=0o700)
    rows = []

    def step(name, operation):
        started = time.perf_counter()
        operation()
        gc.collect()
        row = {"operation": name, "seconds": time.perf_counter() - started, **memory()}
        rows.append(row)
        print(json.dumps(row, sort_keys=True), flush=True)

    step("baseline_imports", lambda: None)
    value = Envelope(evidence="v" * (args.mib * 1024**2))
    limits = PublicationReplayLimits(
        maximum_roster_bytes=4 * 1024**2,
        maximum_certificate_bytes=4 * 1024**2,
        maximum_evidence_bytes=256 * 1024**2,
    )
    path = root / "out" / "evidence.json"
    bound = 320 * 1024**2
    step("private_publish", lambda: publish_private_model(path, value, maximum_bytes=bound))
    step("private_retry", lambda: publish_private_model(path, value, maximum_bytes=bound))
    step("private_read", lambda: read_private_model(path, Envelope, maximum_bytes=bound))

    def reject():
        try:
            validate_preparation(value, None, limits)
        except ValidationError:
            return
        raise AssertionError("expected malformed envelope rejection")

    step("invalid_preparation_rejection", reject)
    journal = RoundJournal(root / "journal", {}, maximum_record_bytes=bound)
    step("journal_put", lambda: journal.put("intent", "one", value))
    step("journal_get", lambda: journal.get("intent", "one"))
    step("journal_retry", lambda: journal.put("intent", "one", value))
    value = None
    step("release_input", lambda: None)
    with path.open("rb") as source:
        file_sha256 = hashlib.file_digest(source, "sha256").hexdigest()
    result = {
        "payload_bytes": args.mib * 1024**2,
        "platform": sys.platform,
        "python": sys.version,
        "file_sha256": file_sha256,
        "steps": rows,
    }
    (root / "benchmark-result.json").write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
