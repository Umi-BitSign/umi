"""Synthetic aggregate byte/storage qualification; no cohort or signing authority.

Use an explicitly new directory under the task's temporary root. This performs
real canonical hashing, unique collector accounting and private publication,
retry and reopen beyond 512 MiB. It does not replace native semantic fixtures.
"""

import argparse
import gc
import hashlib
import json
import resource
import sys
import time
from pathlib import Path

from umi.competition_cohort_aggregate_files import publish_aggregate_model, read_aggregate_model
from umi.competition_cohort_reward_package import ReplayObjectCollector, RewardPackageObject
from umi.open_competition import digest
from umi.protocol import StrictProtocolModel, canonical_json_bytes


class Aggregate(StrictProtocolModel):
    objects: tuple[RewardPackageObject, ...]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    args = parser.parse_args()
    root = args.directory.absolute()
    root.mkdir(mode=0o700)
    started = time.monotonic()
    object_bytes, count, maximum = 14 * 1024**2, 40, 1024**3
    indices = {}
    for index in range(count):
        indices[digest({"slot": index, "value": "v" * object_bytes})] = index

    def source(key):
        return canonical_json_bytes({"slot": indices[key], "value": "v" * object_bytes})

    rows = []

    def record(operation, **values):
        rows.append(
            {
                "operation": operation,
                "elapsed_seconds": time.monotonic() - started,
                "peak_rss_bytes": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
                * (1024 if sys.platform == "linux" else 1),
                **values,
            }
        )

    for prior_bound in (256 * 1024**2, 512 * 1024**2):
        collector = ReplayObjectCollector(source, prior_bound)
        try:
            for key in indices:
                collector(key)
        except ValueError as error:
            assert str(error) == "reward package evidence exceeds its bound"
            record("prior_bound_refused", maximum_bytes=prior_bound, used=collector.used)
        else:
            raise AssertionError("synthetic set must exceed each prior aggregate bound")
        del collector
        gc.collect()

    collector = ReplayObjectCollector(source, maximum)
    for key in indices:
        collector(key)
        collector(key)
    assert len(collector.values) == count and collector.used > 512 * 1024**2
    record("aggregate_replay", used=collector.used, objects=len(collector.values))
    value = Aggregate(
        objects=tuple(
            RewardPackageObject(sha256=key, value=json.loads(raw))
            for key, raw in sorted(collector.values.items())
        )
    )
    del collector
    gc.collect()
    path = root / "private" / "aggregate.json"
    publish_aggregate_model(path, value, maximum_bytes=maximum)
    inode, size = path.stat().st_ino, path.stat().st_size
    assert size > 512 * 1024**2
    record("aggregate_publish", canonical_bytes=size)
    publish_aggregate_model(path, value, maximum_bytes=maximum)
    assert path.stat().st_ino == inode
    record("aggregate_retry")
    expected = digest(value)
    del value
    gc.collect()
    reopened = read_aggregate_model(path, Aggregate, maximum_bytes=maximum)
    assert digest(reopened) == expected
    record("aggregate_reopen")
    del reopened
    gc.collect()
    checksum = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024**2), b""):
            checksum.update(chunk)
    file_sha = checksum.hexdigest()
    report = {
        "schema": "umi-cohort-aggregate-memory-qualification/1",
        "status": "passed",
        "synthetic_evidence_only": True,
        "semantic_cohort_replay": False,
        "maximum_bytes": maximum,
        "objects": count,
        "canonical_bytes": size,
        "file_sha256": file_sha,
        "steps": rows,
    }
    (root / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"status": "passed", "canonical_bytes": size}), flush=True)


if __name__ == "__main__":
    main()
