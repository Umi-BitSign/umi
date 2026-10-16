"""Native evaluation retry ancestry parity for the read-only preflight."""

from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest

from umi.competition_cohort_miner_case import grant_slot
from umi.competition_miner_transition import _grant_fact, _lineage
from umi.competition_miner_transition_io import stopped_snapshots
from umi.endpoint_protocol import COHORT_GRANT_PATH

from .test_competition_cohort_endpoint_decision import (
    base_policy as base_policy,
)
from .test_competition_cohort_endpoint_decision import (
    chain as chain,
)
from .test_competition_cohort_endpoint_decision import (
    chain_config as chain_config,
)
from .test_competition_cohort_endpoint_decision import (
    decisions as decisions,
)
from .test_competition_cohort_endpoint_decision import (
    delivery as delivery,
)
from .test_competition_cohort_endpoint_decision import (
    endpoint as endpoint,
)
from .test_competition_cohort_endpoint_decision import (
    execution as execution,
)
from .test_competition_cohort_endpoint_decision import (
    granted as granted,
)
from .test_competition_cohort_endpoint_decision import (
    harness as harness,
)
from .test_competition_cohort_endpoint_decision import (
    known_video_bytes as known_video_bytes,
)
from .test_competition_cohort_endpoint_decision import (
    legacy_scenario as legacy_scenario,
)
from .test_competition_cohort_endpoint_decision import (
    policy as policy,
)
from .test_competition_cohort_endpoint_decision import (
    receipt_scenario as receipt_scenario,
)
from .test_competition_cohort_endpoint_decision import (
    recovery as recovery,
)
from .test_competition_cohort_endpoint_decision import (
    recovery_case as recovery_case,
)
from .test_competition_cohort_endpoint_decision import (
    relay as relay,
)
from .test_competition_cohort_endpoint_decision import (
    retiring as retiring,
)
from .test_competition_cohort_endpoint_decision import (
    runtime as runtime,
)
from .test_competition_cohort_endpoint_decision import (
    scenario as scenario,
)
from .test_competition_cohort_miner import request
from .test_competition_cohort_miner_case import certify, next_grant, replacement_review


async def test_native_multihop_evaluation_lineage_and_changed_parent_refusals(
    decisions, monkeypatch
):
    d = decisions
    p = d.p
    review = await d.evidence()
    parent = p.grant
    original = parent
    for _ in range(2):
        child = next_grant(d, parent, review, await certify(d, review), monkeypatch)
        ack = await request(p, COHORT_GRANT_PATH, child)
        assert ack.status_code == 200, ack.text
        review = await replacement_review(d, child, monkeypatch)
        parent = child
    config = p.miner.competition_authority.config
    directory = Path(config.directory)
    with stopped_snapshots(
        ((directory / "rounds.sqlite3", directory / "rounds.lock"),),
        maximum_value_bytes=16 * 1024**2,
    ) as (db,):
        facts = {
            row[0]: _grant_fact(
                db, row[0], SimpleNamespace(authority=config), p.c.policy, p.transport_policy
            )
            for row in db.execute("SELECT id FROM records WHERE kind='miner_grant'").fetchall()
        }
    _lineage(facts, p.miner.hotkey_ss58)
    assert len(facts) == 3
    last = grant_slot(parent)
    for name, value in {
        "parent_slot": "ff" * 32,
        "parent_sha256": "ff" * 32,
        "assignment_sha256": "ff" * 32,
        "job_sha256": "ff" * 32,
        "attempt": 99,
        "parent_decision_request_sha256": "ff" * 32,
        "case_ids": ["ff" * 32],
    }.items():
        changed = deepcopy(facts)
        changed[last][name] = value
        with pytest.raises(ValueError):
            _lineage(changed, p.miner.hotkey_ss58)
    missing = deepcopy(facts)
    del missing[grant_slot(original)]
    with pytest.raises(ValueError):
        _lineage(missing, p.miner.hotkey_ss58)
    changed = deepcopy(facts)
    changed[last]["requests"][0]["issued_block"] = 0
    with pytest.raises(ValueError):
        _lineage(changed, p.miner.hotkey_ss58)
    changed = deepcopy(facts)
    changed[last]["parent_retirement"]["receipt"]["request_digest"] = "ff" * 32
    with pytest.raises(ValueError):
        _lineage(changed, p.miner.hotkey_ss58)
