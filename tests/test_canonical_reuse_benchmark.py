"""Small synthetic native void benchmark; never consumes a production ledger."""

from __future__ import annotations

import json
import os
import statistics
import time
from pathlib import Path

from umi.competition_void import (
    VoidEvaluationEvidence,
    replay_void_evidence,
    void_decision_digest,
    void_evidence_digest,
)
from umi.protocol import canonical_json_bytes

from .test_competition_execution import policy as policy
from .test_competition_execution import runtime as runtime
from .test_competition_execution import setup as setup
from .test_competition_void import attempts as attempts
from .test_competition_void import certify


async def test_small_native_void_benchmark(attempts):
    context, observations, signers = attempts
    evidence = VoidEvaluationEvidence(
        schema="umi-competition-void-evidence/1",
        order=context["signed_order"],
        certificate=certify(context, observations, signers),
        legacy_policy=None,
    )
    raw = canonical_json_bytes(evidence)
    replay_context = {k: context[k] for k in ("suite", "policy", "current_block")}
    operations = {
        "schema_validation": lambda: VoidEvaluationEvidence.model_validate_json(raw),
        "evidence_digest": lambda: void_evidence_digest(evidence),
        "decision_digest": lambda: void_decision_digest(evidence.certificate.void),
        "full_void_replay": lambda: replay_void_evidence(evidence, **replay_context),
    }
    results = {}
    for name, operation in operations.items():
        expected = operation()
        samples = []
        for _ in range(5):
            start = time.perf_counter()
            for _ in range(4):
                actual = operation()
            samples.append((time.perf_counter() - start) / 4)
            assert actual == expected
        results[name] = {"median_seconds": statistics.median(samples), "samples": samples}
    output = {
        "schema": context["policy"].schema_,
        "fixture_bytes": len(raw),
        "cases": len(context["suite"].cases),
        "evaluators": len(observations),
        "results": results,
    }
    destination = os.environ.get("UMI_CANONICAL_BENCH_RESULT")
    if destination:
        path = Path(destination)
        path.parent.mkdir(parents=True, exist_ok=True)
        prior = json.loads(path.read_text()) if path.exists() else []
        path.write_text(json.dumps([*prior, output], indent=2) + "\n")
