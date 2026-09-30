from __future__ import annotations

import hashlib
from dataclasses import replace

import pytest

from .test_competition_scheduling import _publish
from .test_competition_scheduling_reservations import (
    claim,
    reserve,
    state,
)
from .test_competition_scheduling_reservations import (
    reserved_schedule as reserved_schedule,
)
from .test_competition_scheduling_reservations import (
    schedule as schedule,
)
from .test_open_competition import policy as policy


def independent_proof(block):
    evidence = block.finality_evidence + b"-independent-owned-observer"
    return replace(
        block,
        finality_evidence=evidence,
        finality_evidence_sha256=hashlib.sha256(evidence).hexdigest(),
    )


def test_reserved_block_accepts_independent_verified_proof_and_keeps_first(reserved_schedule):
    fixture = reserved_schedule
    reserve(fixture)
    before = state(fixture.journal)[1]["blocks"]
    fixture.announcement = independent_proof(fixture.announcement)
    fixture.observed = independent_proof(fixture.observed)
    _publish(fixture)
    assert state(fixture.journal)[1]["blocks"] == before
    # Reopening the journal must preserve the same decision and first evidence.
    fixture.journal = type(fixture.journal)(
        fixture.directory, fixture.authorization.policy, fixture.authorization.legacy_policy
    )
    claimed = claim(fixture)
    assert claimed is not None
    assert state(fixture.journal)[1]["blocks"] == before
    with pytest.raises(ValueError, match="already dispatched"):
        claim(fixture)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("block_hash", "0x" + "ab" * 32),
        ("state_root", "0x" + "ab" * 32),
        ("timestamp_ms", 1),
        ("scoring_policy_hash", "ab" * 32),
        ("finality_verifier_sha256", "ab" * 32),
    ],
)
def test_independent_proof_cannot_change_retained_identity(reserved_schedule, field, value):
    fixture = reserved_schedule
    reserve(fixture)
    before = state(fixture.journal)
    original = fixture.observed
    changed = replace(
        independent_proof(original),
        **{field: original.timestamp_ms + value if field == "timestamp_ms" else value},
    )
    with pytest.raises(ValueError):
        _publish(fixture, observed=changed)
    assert state(fixture.journal) == before


def test_independent_proof_does_not_mask_corrupt_retained_evidence(reserved_schedule):
    fixture = reserved_schedule
    reserve(fixture)
    with fixture.journal._transaction() as db:
        # Simulate offline corruption while restoring the exact writer fences.
        sql = db.execute(
            "SELECT sql FROM sqlite_master WHERE name='immutable_blocks_update'"
        ).fetchone()[0]
        db.execute("DROP TRIGGER immutable_blocks_update")
        db.execute("UPDATE blocks SET evidence=?", (b"corrupt",))
        db.execute(sql)
    before = state(fixture.journal)
    with pytest.raises(ValueError):
        _publish(fixture, observed=independent_proof(fixture.observed))
    assert state(fixture.journal) == before
