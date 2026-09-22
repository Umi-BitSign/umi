"""Replay one explicitly synthetic fixture; print only bounded measurements.

Run in separate baseline/candidate processes with their respective PYTHONPATHs.
No wallet, service, store, network, native model execution or receipt is opened.
"""

from __future__ import annotations

import argparse
import gc
import hashlib
import json
import platform
import resource
import statistics
import sys
import time
from pathlib import Path

from umi.competition_void import VoidEvaluationEvidence, replay_void_evidence
from umi.open_competition import CompetitionPolicy, EvaluationSuite
from umi.protocol import canonical_json_bytes


def measure(path: Path, *, sample_count: int = 3, warmup: bool = True) -> dict:
    if sample_count < 1:
        raise ValueError("at least one sample is required")
    fixture = json.loads(path.read_bytes())
    if fixture.get("schema") != "umi-synthetic-void-replay-benchmark/1":
        raise ValueError("expected an explicitly synthetic benchmark fixture")
    evidence = VoidEvaluationEvidence.model_validate_json(json.dumps(fixture["evidence"]))
    policy = CompetitionPolicy.model_validate_json(json.dumps(fixture["policy"]))
    suite = EvaluationSuite.model_validate_json(json.dumps(fixture["suite"]))
    raw = canonical_json_bytes(evidence)
    context = dict(policy=policy, suite=suite, current_block=fixture["current_block"])
    if warmup:
        assert replay_void_evidence(evidence, **context) == evidence
    gc.collect()
    samples = []
    for _ in range(sample_count):
        wall_start, cpu_start = time.perf_counter(), time.process_time()
        replayed = replay_void_evidence(evidence, **context)
        cpu_elapsed = time.process_time() - cpu_start
        wall_elapsed = time.perf_counter() - wall_start
        assert replayed == evidence
        samples.append({"cpu_seconds": cpu_elapsed, "wall_seconds": wall_elapsed})
        del replayed
    maximum_rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return {
        "python": platform.python_version(),
        "platform": platform.system(),
        "machine": platform.machine(),
        "cases": len(suite.cases),
        "evaluators": len(evidence.certificate.void.observations),
        "warmup": warmup,
        "evidence_bytes": len(raw),
        "evidence_sha256": hashlib.sha256(raw).hexdigest(),
        "median_cpu_seconds": statistics.median(s["cpu_seconds"] for s in samples),
        "median_wall_seconds": statistics.median(s["wall_seconds"] for s in samples),
        "samples": samples,
        "process_maximum_rss_bytes": maximum_rss * (1024 if sys.platform != "darwin" else 1),
        "rss_scope": "fresh process high-water mark, including imports and fixture parsing",
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", required=True, type=Path)
    parser.add_argument("--samples", type=int, default=3)
    parser.add_argument("--no-warmup", action="store_true")
    args = parser.parse_args()
    try:
        print(
            json.dumps(
                measure(args.fixture, sample_count=args.samples, warmup=not args.no_warmup),
                sort_keys=True,
            )
        )
    except Exception as error:
        # Do not expose fixture values through validation errors or tracebacks.
        print(json.dumps({"error_type": type(error).__name__}))
        raise SystemExit(1) from None
