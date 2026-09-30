"""Switch isolated native fixtures to a candidate backend without host authorization shortcuts."""

import hashlib
import os
import sqlite3
from types import SimpleNamespace

from umi.competition_evidence_copy import copy_legacy_weight_journal
from umi.competition_evidence_store import EvidenceBudget
from umi.competition_evidence_worker import (
    ContentAddressedWeightWorker,
    EvidenceWorkerProfile,
    bind_worker_profile,
)
from umi.protocol import canonical_json_bytes


def use_candidate(item, *, copy=False, profile=None):
    previous = item.worker
    profile = profile or EvidenceWorkerProfile(
        EvidenceBudget(2 * 1024**3, 4 * 1024**3, 10000, 2000000), 16
    )
    root = previous.state_root.parent / "candidate-weights"
    if copy:
        root.mkdir(mode=0o700)
        path = root / previous.path.name
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(descriptor)
        source = sqlite3.connect(previous.path.as_uri() + "?mode=ro", uri=True)
        source.execute("PRAGMA query_only=ON")
        source.execute("BEGIN")
        binding = source.execute("SELECT * FROM binding").fetchall()
        with sqlite3.connect(path) as destination:
            destination.execute("BEGIN")
            copy_legacy_weight_journal(
                source,
                destination,
                expected_binding_sha256=hashlib.sha256(canonical_json_bytes(binding)).hexdigest(),
                limits=profile.limits,
            )
            bind_worker_profile(destination, profile, create=True)
        source.close()
    item.worker = ContentAddressedWeightWorker(
        root,
        evidence_profile=profile,
        package_limits=previous.package_limits,
        replay_worker=previous.replay_worker,
        maximum_attempts=previous.maximum_attempts,
        maximum_evidence_bytes=previous.maximum_evidence_bytes,
        submission_timeout_seconds=previous.submission_timeout_seconds,
    )

    async def submit(encoded, signer):
        from .test_competition_weights import _advance

        with sqlite3.connect(item.worker.path) as db:
            import json

            attempt = json.loads(db.execute("SELECT body FROM attempts").fetchone()[0])
            assert attempt["phase"] == "signed"
            assert bytes.fromhex(attempt["signed_extrinsic"][2:]) == encoded
        item.encoded.append(encoded)
        if item.behavior == "disconnect":
            raise ConnectionError("fixture connection lost after send")
        if item.behavior == "apply":
            _advance(item, 171, applied=True)
        return SimpleNamespace(success=True)

    item.transport.submit = submit
    return previous
