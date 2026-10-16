"""Retained diagnostic facts use actual signed paid-work grants and lineage."""

import copy
import hashlib
from types import SimpleNamespace

import pytest

from umi.competition_cohort_miner_case import grant_slot
from umi.competition_cohort_service_work import verify_service_claim
from umi.competition_miner_transition import _grant_fact, _lineage
from umi.competition_miner_transition_io import TransitionPreflightRefused, stopped_snapshots
from umi.open_competition import digest

from .test_competition_cohort_service_grants import accept, replacement
from .test_competition_cohort_service_grants import base_policy as base_policy
from .test_competition_cohort_service_grants import chain as chain
from .test_competition_cohort_service_grants import chain_config as chain_config
from .test_competition_cohort_service_grants import endpoint as endpoint
from .test_competition_cohort_service_grants import execution as execution
from .test_competition_cohort_service_grants import granted as granted
from .test_competition_cohort_service_grants import harness as harness
from .test_competition_cohort_service_grants import known_video_bytes as known_video_bytes
from .test_competition_cohort_service_grants import legacy_scenario as legacy_scenario
from .test_competition_cohort_service_grants import miner_policy as miner_policy
from .test_competition_cohort_service_grants import original_harness as original_harness
from .test_competition_cohort_service_grants import policy as policy
from .test_competition_cohort_service_grants import receipt_scenario as receipt_scenario
from .test_competition_cohort_service_grants import recovery as recovery
from .test_competition_cohort_service_grants import recovery_case as recovery_case
from .test_competition_cohort_service_grants import relay as relay
from .test_competition_cohort_service_grants import runtime as runtime
from .test_competition_cohort_service_grants import scenario as scenario
from .test_competition_cohort_service_grants import service as service
from .test_competition_cohort_service_grants import service_catalog_inputs as service_catalog_inputs
from .test_competition_cohort_service_grants import service_owner as service_owner
from .test_competition_cohort_service_grants import shared_control_group as shared_control_group


async def test_native_service_parent_and_paid_claim_survive_stopped_inspection(
    service, monkeypatch
):
    c, p = service, service.p
    child, _, _ = await replacement(c, monkeypatch)
    accepted = await accept(c, child)
    assert accepted.status_code == 200, accepted.text
    journal = p.miner.competition_authority.journal
    before = hashlib.sha256(journal.path.read_bytes()).hexdigest()
    startup = SimpleNamespace(authority=p.miner_cfg)
    with stopped_snapshots(
        ((journal.path, journal.lock_path),), maximum_value_bytes=16 * 1024**2
    ) as (snapshot,):
        facts = {
            grant_slot(grant): _grant_fact(
                snapshot, grant_slot(grant), startup, p.c.policy, p.transport_policy
            )
            for grant in (c.grant, child)
        }
    assert hashlib.sha256(journal.path.read_bytes()).hexdigest() == before
    _lineage(facts, p.miner.hotkey_ss58)
    claim = verify_service_claim(c.claim)
    for fact in facts.values():
        assert fact["kind"] == "service"
        assert fact["claim_sha256"] == digest(claim.claim)
        assert fact["submission_sha256"] == claim.claim.submission_sha256
        assert fact["cohort_sha256"] == c.assignment.round.cohort_sha256
        assert fact["assignment_sha256"] == digest(c.assignment)
        assert fact["receipt_pending"] is False
    parent_slot, child_slot = grant_slot(c.grant), grant_slot(child)
    assert facts[child_slot]["parent_slot"] == parent_slot
    with pytest.raises(TransitionPreflightRefused, match="replacement_parent_binding_changed"):
        _lineage({child_slot: facts[child_slot]}, p.miner.hotkey_ss58)
    for field, value in (
        ("parent_sha256", "01" * 32),
        ("assignment_sha256", "02" * 32),
        ("parent_decision_request_sha256", "03" * 32),
        ("attempt", facts[child_slot]["attempt"] + 1),
        ("case_ids", ["04" * 32]),
    ):
        changed = copy.deepcopy(facts)
        changed[child_slot][field] = value
        with pytest.raises(TransitionPreflightRefused, match="replacement_parent"):
            _lineage(changed, p.miner.hotkey_ss58)
    assert hashlib.sha256(journal.path.read_bytes()).hexdigest() == before
