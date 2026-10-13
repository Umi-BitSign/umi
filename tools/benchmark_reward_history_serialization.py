"""Bounded synthetic proof serialization measurement; no retained evidence reads."""

import argparse
import json
import statistics
import time

import rfc8785

from umi.canonical_proof import canonical_proof_matches
from umi.competition_evidence_codec import encode_evidence, encode_evidence_for_reuse


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--samples", type=int, default=7)
    parser.add_argument("--hex-bytes", type=int, default=2 * 1024**2)
    args = parser.parse_args()
    if not 1 <= args.samples <= 100 or not 1 <= args.hex_bytes <= 32 * 1024**2:
        parser.error("samples must be 1..100 and synthetic hex bytes 1..32 MiB")
    value = {
        "schema": "synthetic-control-proof/1",
        "block": 9178000,
        "runtime_execution": {"block": 9177999, "value": "0x" + "ac" * args.hex_bytes},
        "extrinsics": ["0x" + "01" * 1024 for _ in range(32)],
        "proof": ["0x" + "ab" * 1024 for _ in range(16)],
        "chain_submission_authorized": False,
    }
    raw = rfc8785.dumps(value)
    prepared = encode_evidence_for_reuse(raw, kind="proof")
    rows = {}
    for name, operation in (
        ("reference", lambda: rfc8785.dumps(value) == raw),
        ("ascii_integer_fast_path", lambda: canonical_proof_matches(value, raw)),
        ("repeat_evidence_encoding", lambda: encode_evidence(raw, kind="proof")),
        ("reuse_completed_encoding", lambda: prepared.for_bytes(raw, kind="proof")),
    ):
        samples = []
        for _ in range(args.samples):
            started = time.perf_counter()
            assert operation()
            samples.append(time.perf_counter() - started)
        rows[name] = {"seconds": samples, "median_seconds": statistics.median(samples)}
    print(
        json.dumps(
            {
                "schema": "umi-history-serialization-benchmark/1",
                "fixture": "synthetic ASCII hex proof; no live or retained payload",
                "bytes": len(raw),
                "samples": args.samples,
                "timings": rows,
                "speedup": rows["reference"]["median_seconds"]
                / rows["ascii_integer_fast_path"]["median_seconds"],
                "encoding_speedup": rows["repeat_evidence_encoding"]["median_seconds"]
                / rows["reuse_completed_encoding"]["median_seconds"],
                "scope": (
                    "canonical comparison and redundant encoding only; excludes first codec pass "
                    "and archive IO; not an overall history ETA"
                ),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
