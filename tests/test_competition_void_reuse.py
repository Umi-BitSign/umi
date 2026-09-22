"""Canonicalization reuse must never become a replay/authority cache."""

from __future__ import annotations

import pytest

from umi.canonical_reuse import canonical_json_reuse
from umi.competition_store import SettlementNotReadyError
from umi.competition_void import VoidEvaluationEvidence, replay_void_evidence, void_evidence_digest
from umi.open_competition import digest

from .test_competition_execution import policy as policy
from .test_competition_execution import runtime as runtime
from .test_competition_execution import setup as setup
from .test_competition_publication import replay_limits as replay_limits
from .test_competition_void import attempts as attempts
from .test_competition_void import certify
from .test_competition_void_settlement import mixed as mixed


@pytest.fixture
async def native_void(attempts):
    context, observations, signers = attempts
    evidence = VoidEvaluationEvidence(
        schema="umi-competition-void-evidence/1",
        order=context["signed_order"],
        certificate=certify(context, observations, signers),
        legacy_policy=None,
    )
    return evidence, {k: context[k] for k in ("suite", "policy", "current_block")}


async def test_replay_rechecks_time_policy_suite_and_signatures_after_warmup(native_void):
    evidence, context = native_void
    with canonical_json_reuse():
        assert replay_void_evidence(evidence, **context) == evidence
        for block in (evidence.order.order.round.valid_through_block + 1, 0):
            with pytest.raises(ValueError):
                replay_void_evidence(evidence, **{**context, "current_block": block})
        for key, changed in (
            ("policy", context["policy"].model_copy(update={"maximum_inference_ms": 1})),
            ("suite", context["suite"].model_copy(update={"policy_sha256": "00" * 32})),
        ):
            with pytest.raises(ValueError):
                replay_void_evidence(evidence, **{**context, key: changed})
        forged = evidence.model_dump(mode="json", by_alias=True)
        forged["certificate"]["signatures"][0]["signature"] = "0x" + "00" * 64
        # Structural validity and digestability do not authorize a signature.
        void_evidence_digest(forged)
        with pytest.raises(ValueError):
            replay_void_evidence(forged, **context)
        assert replay_void_evidence(evidence, **context) == evidence


async def test_nested_mutation_cannot_reuse_schema_success(native_void):
    evidence, _ = native_void
    body = evidence.model_dump(mode="json", by_alias=True)
    with canonical_json_reuse():
        original = void_evidence_digest(body)
        body["certificate"]["void"]["chain_submission_authorized"] = True
        with pytest.raises(ValueError):
            void_evidence_digest(body)
        body["certificate"]["void"]["chain_submission_authorized"] = False
        assert void_evidence_digest(body) == original


async def test_retained_conflict_is_rechecked_after_warmed_material(mixed, replay_limits):
    store, round_, suite, _, _, evidence, _ = mixed
    with canonical_json_reuse():
        store.record_void_evaluation(evidence=evidence, suite=suite, observed_block=150)
        store.settlement_material(round_, limits=replay_limits)
        with store._transaction() as db:
            db.execute("INSERT INTO round_conflicts VALUES (?,?)", (digest(round_), 160))
        with pytest.raises((ValueError, SettlementNotReadyError)):
            store.settlement_material(round_, limits=replay_limits)
