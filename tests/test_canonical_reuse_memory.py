"""Bounded local replay measurements, with synthetic signed native evidence."""

from __future__ import annotations

import gc
import hashlib
import json
import os
import statistics
import time
import tracemalloc
from pathlib import Path

import pytest

from umi import canonical_reuse as reuse
from umi.competition_execution import ExecutionCase
from umi.competition_void import replay_void_evidence
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from .test_competition_execution import policy as policy
from .test_competition_execution import runtime as runtime
from .test_competition_execution import setup as execution_setup
from .test_competition_void import attempts as attempts
from .test_competition_void_reuse import native_void as native_void
from .test_open_competition import round_for

base_setup = execution_setup


@pytest.fixture(params=[3, 36])
def setup(base_setup, request):
    policy, job, suite, archive, videos, calls = base_setup
    cases = []
    for i in range(request.param):
        video = f"scaled-inert-video-{i}".encode()
        video_sha = hashlib.sha256(video).hexdigest()
        (videos / (video_sha + ".mp4")).write_bytes(video)
        cases.append(
            suite.cases[i % 3].model_copy(
                update={"case_id": f"{i:064x}", "video_sha256": video_sha}
            )
        )
    suite = suite.model_copy(update={"cases": tuple(cases)})
    round_ = round_for(policy, suite, (job.submission,), incumbent=digest(job.incumbent))
    job = job.model_copy(
        update={
            "round": round_,
            "cases": tuple(
                ExecutionCase(case_id=c.case_id, video_sha256=c.video_sha256, stratum=c.stratum)
                for c in cases
            ),
        }
    )
    return policy, job, suite, archive, videos, calls


async def test_replay_memory_and_small_scaled_fixture(native_void):
    evidence, context = native_void
    measurements = {}
    for name, budget in (("uncached", 0), ("cached", 8 * 1024**2)):
        samples = []
        for _ in range(3):
            start = time.perf_counter()
            with reuse.canonical_json_reuse(maximum_bytes=budget):
                assert replay_void_evidence(evidence, **context) == evidence
            samples.append(time.perf_counter() - start)
        gc.collect()
        tracemalloc.start()
        try:
            with reuse.canonical_json_reuse(maximum_bytes=budget):
                assert replay_void_evidence(evidence, **context) == evidence
                cache = reuse._ACTIVE.get()
                retained = cache.size
                entries = len(cache.entries)
                peak = tracemalloc.get_traced_memory()[1]
            assert cache.closed and not cache.entries and cache.size == 0
        finally:
            tracemalloc.stop()
        measurements[name] = {
            "median_seconds": statistics.median(samples),
            "samples": samples,
            "python_traced_peak_bytes": peak,
            "cache_key_output_bytes_at_exit": retained,
            "cache_entries_at_exit": entries,
        }
    output = {
        "schema": context["policy"].schema_,
        "cases": len(context["suite"].cases),
        "fixture_bytes": len(canonical_json_bytes(evidence)),
        "measurements": measurements,
        "memory_scope": "tracemalloc during one replay, not process RSS or preparation peak",
    }
    destination = os.environ.get("UMI_CANONICAL_MEMORY_RESULT")
    if destination:
        path = Path(destination)
        path.parent.mkdir(parents=True, exist_ok=True)
        prior = json.loads(path.read_text()) if path.exists() else []
        path.write_text(json.dumps([*prior, output], indent=2) + "\n")
