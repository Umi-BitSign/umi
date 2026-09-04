from __future__ import annotations

import asyncio
import hashlib
import json
from collections.abc import Sequence
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from decimal import Decimal, localcontext
from typing import Any

import pytest
from fastapi.testclient import TestClient

from umi.observer import (
    _STATIC_PROTOCOL_FACTS,
    ObserverUnavailable,
    SnapshotCache,
    create_observer_app,
)
from umi.observer_bundle_feed import (
    BundleFeedSnapshot,
    FeedHealth,
    ValidatorLocalScore,
    VerifiedEvidenceObject,
    VerifiedFeedWindow,
    VerifiedMinerSolution,
    VerifiedSolutionEvidence,
)
from umi.observer_models import (
    ChainNetworkSnapshot,
    ChainParticipant,
    ChainParticipantMetrics,
    EpochState,
    ExactExchangeRate,
    ExactNormalizedMetric,
    ExactRational,
    ExactTokenAmount,
    FinalizedBlock,
    LeaderboardResponse,
    NetworkCounts,
    NetworkHyperparameters,
    ObserverSnapshot,
    ProtocolState,
    SourceProvenance,
    UmiTranslationMetrics,
    WindowResponse,
    WindowsResponse,
)

UTC_NOW = datetime(2026, 9, 1, 16, 0, tzinfo=timezone.utc)


def _metric(raw: int) -> ExactNormalizedMetric:
    with localcontext() as context:
        context.prec = 50
        display = format(Decimal(raw) / Decimal(65_535), "f").rstrip("0").rstrip(".")
    return ExactNormalizedMetric(
        raw_numerator=str(raw),
        display_decimal=display or "0",
    )


def _participant(uid: int, *, validator: bool = False) -> ChainParticipant:
    return ChainParticipant(
        uid=uid,
        hotkey=f"5ParticipantHotkey{uid}",
        role="validator" if validator else "miner",
        chain_active=True,
        validator_permit=validator,
        registration_block="10",
        last_update_block="90",
        last_update_age_blocks="9",
        serving_announced=True,
        chain_metrics=ChainParticipantMetrics(
            rank=None,
            trust=None,
            consensus=_metric(32_767),
            incentive=_metric(32_767),
            dividends=_metric(0),
            pruning_score=None,
            emission=ExactTokenAmount(raw=str(2**64 - 1), asset="subnet_alpha"),
            alpha_stake=ExactTokenAmount(raw=str(2**53), asset="subnet_alpha"),
            tao_stake=ExactTokenAmount(raw=str(2**53 - 1), asset="tao"),
            total_stake=ExactTokenAmount(raw="0", asset="subnet_alpha"),
        ),
        umi_translation=UmiTranslationMetrics(
            availability="unavailable",
            reason_code="released_umi_score_evidence_unavailable",
            miner_root=None,
            accuracy=None,
            utility=None,
            rank=None,
            audit_bundle_sha256=None,
            audit_release_block=None,
        ),
    )


def _snapshot(
    *,
    block_number: int = 99,
    block_hash_byte: str = "11",
    parent_hash_byte: str = "22",
    participants: Sequence[ChainParticipant] | None = None,
) -> ObserverSnapshot:
    rows = tuple(participants or (_participant(0), _participant(1, validator=True)))
    block = FinalizedBlock(
        number=str(block_number),
        hash="0x" + block_hash_byte * 32,
        parent_hash="0x" + parent_hash_byte * 32,
        state_root="0x" + "33" * 32,
        timestamp=UTC_NOW,
    )
    source = SourceProvenance(
        source_id="bittensor-finalized-sn78",
        source_kind="chain_finalized",
        verification_status="finalized_read",
        block=block,
    )
    network = ChainNetworkSnapshot(
        name="Vocence",
        symbol="V",
        identity=None,
        runtime_spec_version="452",
        mechanism_count=1,
        maximum_mechanism_count=2,
        mechanism_emission_split=None,
        commit_reveal_enabled=True,
        commit_reveal_version="4",
        reveal_period_epochs="1",
        pending_weight_commit_count=0,
        subnet_exists=True,
        subnet_started=True,
        subnet_emission_enabled=False,
        price=None,
        epoch=EpochState(
            epoch_index="123",
            tempo_blocks="360",
            last_epoch_block="50",
            next_epoch_start_block="410",
            pending_epoch_at=None,
            blocks_since_last_step="49",
            blocks_remaining="311",
            seconds_remaining=None,
        ),
        counts=NetworkCounts(
            registered=len(rows),
            chain_active=len(rows),
            miners=sum(not row.validator_permit for row in rows),
            validators=sum(row.validator_permit for row in rows),
            serving_announced=len(rows),
            maximum_uids=256,
        ),
        hyperparameters=NetworkHyperparameters(
            min_allowed_weights=1,
            weights_version_key="0",
            weights_rate_limit_blocks="100",
            immunity_period_blocks="5000",
            activity_cutoff_blocks="360",
            maximum_weight=_metric(32_767),
        ),
        unavailable_fields=("mechanism_emission_split",),
    )
    return ObserverSnapshot(
        collected_at=UTC_NOW,
        sources=(source,),
        network=network,
        participants=rows,
    )


class SequenceCollector:
    def __init__(self, values: Sequence[ObserverSnapshot | Exception]) -> None:
        self.values = list(values)
        self.calls = 0

    async def collect(self) -> ObserverSnapshot:
        self.calls += 1
        if not self.values:
            raise RuntimeError("collector exhausted with secret https://rpc.invalid/key")
        value = self.values.pop(0)
        if isinstance(value, Exception):
            raise value
        return value


def _cache(collector: SequenceCollector, **overrides: Any) -> SnapshotCache:
    return SnapshotCache(
        collector,
        fresh_for_seconds=overrides.pop("fresh_for_seconds", 30),
        maximum_stale_seconds=overrides.pop("maximum_stale_seconds", 120),
        refresh_interval_seconds=overrides.pop("refresh_interval_seconds", 60),
        refresh_timeout_seconds=overrides.pop("refresh_timeout_seconds", 2),
        maximum_finalized_head_age_seconds=overrides.pop("maximum_finalized_head_age_seconds", 120),
        maximum_future_block_skew_seconds=overrides.pop("maximum_future_block_skew_seconds", 30),
        clock=overrides.pop("clock", lambda: UTC_NOW),
        **overrides,
    )


def test_status_is_finalized_chain_observation_not_umi_evidence() -> None:
    collector = SequenceCollector([_snapshot()])
    app = create_observer_app(_cache(collector))

    with TestClient(app) as client:
        response = client.get("/api/v1/status")
        network = client.get("/api/v1/network")

    assert response.status_code == 200
    body = response.json()
    assert body["schema"] == "umi-observer-status/1"
    assert body["generated_at"] == "2026-09-01T16:00:00Z"
    assert body["freshness"] == "fresh"
    assert body["finalized_head_age_seconds"] == 0
    assert body["protocol_state"]["phase"] == "pre_public_calibration"
    assert body["protocol_state"]["economic_era"] == "unverified"
    assert body["protocol_state"]["chain_result_classification"] == "unverified"
    assert body["protocol_state"]["translation_weights_active"] is False
    assert body["protocol_state"]["scoring_policy_hash"] is None
    assert body["protocol_state"]["validator_input_eligible"] is False
    assert body["finalized_block"]["number"] == "99"
    assert body["finalized_block"]["storage_proofs_verified"] is False
    assert "public_calibration_not_started" in body["outstanding_gap_codes"]
    assert response.headers["x-umi-finalized-block"] == "99"
    assert (
        response.headers["x-umi-contract-revision"]
        == "bfd20ab3df0a7737361248f6c79fb14794a1fcc4b1cbc5d97854705e0b3df1ab"
    )
    assert set(_STATIC_PROTOCOL_FACTS) == (
        set(ProtocolState.model_fields) - {"chain_identity_matches_expected"}
    ) | {"api_version"}
    static_source = next(
        source for source in body["sources"] if source["source_kind"] == "dashboard_static"
    )
    assert static_source["artifact_sha256"] == response.headers["x-umi-contract-revision"]
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["strict-transport-security"] == "max-age=2592000"
    assert network.status_code == 200
    assert collector.calls == 1, "request handlers must not trigger chain refreshes"


def test_participants_use_exact_numbers_and_omit_sensitive_chain_fields() -> None:
    app = create_observer_app(_cache(SequenceCollector([_snapshot()])))

    with TestClient(app) as client:
        response = client.get("/api/v1/participants?role=miner&limit=1")

    assert response.status_code == 200
    body = response.json()
    assert body["page"] == {
        "role": "miner",
        "limit": 1,
        "total": 1,
        "returned": 1,
        "next_cursor": None,
    }
    row = body["participants"][0]
    assert row["chain_metrics"]["incentive"] == {
        "raw_numerator": "32767",
        "raw_denominator": "65535",
        "display_decimal": "0.49999237048905165178912031738765545128557259479667",
        "unit": "per_u16",
    }
    assert row["chain_metrics"]["emission"]["raw"] == str(2**64 - 1)
    assert row["chain_metrics"]["alpha_stake"]["raw"] == str(2**53)
    assert row["chain_metrics"]["tao_stake"]["asset"] == "tao"
    assert row["umi_translation"]["availability"] == "unavailable"
    serialized = response.text.casefold()
    for forbidden in ("coldkey", "axon", "127.0.0.1", "video_url", "hypothesis"):
        assert forbidden not in serialized


def test_participant_cursor_is_bound_to_role_and_finalized_block() -> None:
    rows = (_participant(0), _participant(1), _participant(2, validator=True))
    first = _snapshot(participants=rows)
    app = create_observer_app(_cache(SequenceCollector([first])))

    with TestClient(app) as client:
        page_one = client.get("/api/v1/participants?role=miner&limit=1")
        cursor = page_one.json()["page"]["next_cursor"]
        page_two = client.get(f"/api/v1/participants?role=miner&limit=1&cursor={cursor}")
        wrong_role = client.get(f"/api/v1/participants?role=all&limit=1&cursor={cursor}")

    assert page_two.status_code == 200
    assert page_two.json()["participants"][0]["uid"] == 1
    assert wrong_role.status_code == 422
    assert wrong_role.json()["error"]["reason_code"] == "cursor_role_mismatch"


def test_unreleased_protocol_feeds_are_explicit_empty_states() -> None:
    app = create_observer_app(_cache(SequenceCollector([_snapshot()])))

    with TestClient(app) as client:
        leaderboard = client.get("/api/v1/leaderboard").json()
        windows = client.get("/api/v1/windows").json()
        gates = client.get("/api/v1/activation-gates").json()
        benchmarks = client.get("/api/v1/benchmarks").json()
        incidents = client.get("/api/v1/incidents").json()

    assert leaderboard["chain_economics"]["classification"] == "unverified"
    assert leaderboard["chain_economics"]["derivation_status"] == "dashboard_derived"
    assert leaderboard["chain_economics"]["ranking_status"] == "no_economic_separation"
    assert leaderboard["chain_economics"]["reason_code"] == "all_observed_incentives_equal"
    assert leaderboard["chain_economics"]["entries"][0]["chain_rank"] is None
    assert leaderboard["chain_economics"]["entries"][0]["incentive_tie_size"] == 1
    assert leaderboard["umi_translation"]["availability"] == "not_started"
    assert leaderboard["umi_translation"]["entries"] == []
    assert windows["availability"] == "not_started"
    assert windows["windows"] == []
    assert gates["readiness"] == "not_ready"
    assert {gate["status"] for gate in gates["gates"]} == {"pending"}
    assert benchmarks["benchmarks"] == []
    assert incidents["incidents"] == []


class StaticBundleFeed:
    def __init__(self, windows: tuple[VerifiedFeedWindow, ...]) -> None:
        self.value = BundleFeedSnapshot(
            windows,
            tuple(
                FeedHealth(item.validator_account_id32, "current", None, 1, 1) for item in windows
            ),
        )

    async def start(self, _height, _poll) -> None:
        return None

    async def close(self) -> None:
        return None

    def snapshot(self) -> BundleFeedSnapshot:
        return self.value


def _released_local_window(validator: str, *, classification: str = "calibration_no_weight"):
    return VerifiedFeedWindow(
        validator_account_id32=validator,
        window_id="cd" * 32,
        window_index=7,
        terminal_classification=classification,
        reason_codes=()
        if classification == "calibration_no_weight"
        else ("response_anchor_failed",),
        scoring_policy_hash="ef" * 32,
        audit_release_block=99,
        audit_release_block_hash="0x" + "44" * 32,
        manifest_sha256=hashlib.sha256(validator.encode()).hexdigest(),
        tree_sha256="43" * 32,
        public_origin="https://audits.example",
        bundle_relative_path=(f"validators/{validator}/windows/{'cd' * 32}/{classification}"),
        reveal_stage_manifest=None,
        reveal_result=None,
        solutions=(),
        scores=(
            ValidatorLocalScore(
                miner_root_account_id32="aa" * 32,
                assigned_clips=24,
                accuracy_numerator=1,
                accuracy_denominator=2,
                eligible=True,
                utility_numerator=4,
                utility_denominator=25,
            ),
        ),
    )


def _solution(ordinal: int, *, missing: bool = False) -> VerifiedMinerSolution:
    def evidence(byte: int) -> VerifiedEvidenceObject:
        return VerifiedEvidenceObject(f"{byte:02x}" * 32, "application/json", 100)

    return VerifiedMinerSolution(
        assignment_id=f"{ordinal:02x}" * 32,
        request_leaf=f"{ordinal + 16:02x}" * 32,
        batch_id="AQEBAQEBAQEBAQEBAQEBAQ",
        challenge_id="AgICAgICAgICAgICAgICAg",
        miner_hotkey=f"5MinerHotkey{ordinal}",
        miner_root_account_id32=f"{ordinal + 32:02x}" * 32,
        stratum="short_utterance",
        metric="wer",
        canary=False,
        outer_disposition="missing" if missing else "sealed",
        zero_score_reason="missing" if missing else None,
        response_plaintext_valid=not missing,
        response_status=None if missing else "ok",
        hypothesis=None if missing else "hello world",
        response_error_code=None,
        model_revision=None,
        references=("hello world", "hi world", "hello there"),
        canary_actual_references=(),
        score_numerator=0 if missing else 1,
        score_denominator=1,
        score_trace=None if missing else {"distance": 0, "metric": "wer"},
        canary_result=None,
        evidence=VerifiedSolutionEvidence(
            prepared_attempt=evidence(ordinal + 40),
            request=evidence(ordinal + 50),
            attempt_outcome=evidence(ordinal + 60),
            retained_response=None if missing else evidence(ordinal + 70),
            response_plaintext=None if missing else evidence(ordinal + 80),
            response_decryption=evidence(ordinal + 90),
            ground_truth_plaintext=evidence(ordinal + 100),
            ground_truth_decryption=evidence(ordinal + 110),
        ),
    )


def test_released_windows_expose_validator_local_scores_without_consensus_ranking() -> None:
    first = _released_local_window("11" * 32)
    second = _released_local_window("22" * 32)
    second = second.__class__(
        **{
            **{field: getattr(second, field) for field in second.__dataclass_fields__},
            "scores": (ValidatorLocalScore("aa" * 32, 24, 3, 4, True, 9, 25),),
        }
    )
    app = create_observer_app(
        _cache(SequenceCollector([_snapshot()])),
        bundle_feed=StaticBundleFeed((first, second)),  # type: ignore[arg-type]
    )

    with TestClient(app) as client:
        listed = client.get("/api/v1/windows")
        ambiguous = client.get(f"/api/v1/windows/{first.window_id}")
        selected = client.get(
            f"/api/v1/windows/{first.window_id}?validator={first.validator_account_id32}"
        )

    assert listed.status_code == 200
    records = listed.json()["windows"]
    assert len(records) == 2
    assert {item["validator_account_id32"] for item in records} == {"11" * 32, "22" * 32}
    assert records[0]["score_scope"] == "validator_local"
    assert "rank" not in records[0]["validator_local_scores"][0]
    assert ambiguous.status_code == 409
    assert ambiguous.json()["error"]["reason_code"] == "released_window_validator_required"
    assert selected.status_code == 200
    assert selected.json()["window"]["validator_account_id32"] == "11" * 32


def test_replayed_incidents_are_validator_bound_and_chain_economics_remain_separate() -> None:
    incident = _released_local_window("11" * 32, classification="skipped")
    app = create_observer_app(
        _cache(SequenceCollector([_snapshot()])),
        bundle_feed=StaticBundleFeed((incident,)),  # type: ignore[arg-type]
    )

    with TestClient(app) as client:
        incidents = client.get("/api/v1/incidents").json()
        leaderboard = client.get("/api/v1/leaderboard").json()
        status = client.get("/api/v1/status").json()

    assert incidents["availability"] == "available"
    assert incidents["incidents"][0]["validator_account_id32"] == "11" * 32
    assert incidents["incidents"][0]["audit_release_block"] == "99"
    assert leaderboard["umi_translation"]["availability"] == "not_started"
    assert leaderboard["umi_translation"]["reason_code"] == "public_calibration_not_started"
    assert leaderboard["chain_economics"]["classification"] == "unverified"
    assert status["protocol_state"]["phase"] == "pre_public_calibration"
    assert status["protocol_state"]["scoring_policy_hash"] is None
    assert status["protocol_state"]["conformance_evidence_available"] is False
    assert "public_calibration_not_started" in status["outstanding_gap_codes"]
    assert "released_audit_bundle_feed_unavailable" not in status["outstanding_gap_codes"]
    assert "active_scoring_policy_unavailable" in status["outstanding_gap_codes"]
    assert any(
        source["artifact_sha256"] == incident.manifest_sha256
        for source in status["sources"]
        if source["source_kind"] == "released_audit_bundle"
    )


def test_released_solutions_are_paginated_validator_local_and_evidence_bound() -> None:
    base = _released_local_window("11" * 32)
    reveal_manifest = VerifiedEvidenceObject("91" * 32, "application/json", 200)
    reveal_result = VerifiedEvidenceObject("92" * 32, "application/json", 300)
    window = replace(
        base,
        reveal_stage_manifest=reveal_manifest,
        reveal_result=reveal_result,
        solutions=(_solution(1), _solution(2, missing=True)),
    )
    app = create_observer_app(
        _cache(SequenceCollector([_snapshot()])),
        bundle_feed=StaticBundleFeed((window,)),  # type: ignore[arg-type]
    )

    with TestClient(app) as client:
        status_response = client.get("/api/v1/status")
        status = status_response.json()
        first = client.get(
            f"/api/v1/windows/{window.window_id}/solutions"
            f"?validator={window.validator_account_id32}&limit=1"
        )
        cursor = first.json()["page"]["next_cursor"]
        second = client.get(
            f"/api/v1/windows/{window.window_id}/solutions"
            f"?validator={window.validator_account_id32}&limit=1&cursor={cursor}"
        )

    assert status["protocol_state"]["phase"] == "shadow_calibration"
    assert status["protocol_state"]["scoring_policy_hash"] == window.scoring_policy_hash
    assert status["protocol_state"]["conformance_evidence_available"] is True
    assert status["protocol_state"]["translation_weights_active"] is False
    assert status["protocol_state"]["activation_evidence_available"] is False
    assert "public_calibration_not_started" not in status["outstanding_gap_codes"]
    assert "active_scoring_policy_unavailable" not in status["outstanding_gap_codes"]
    assert status["sources"][-1]["artifact_sha256"] == window.manifest_sha256
    assert status_response.headers["x-umi-dataset-revision"] != status["finalized_block"]["hash"]
    static_source = next(
        source for source in status["sources"] if source["source_kind"] == "dashboard_static"
    )
    assert static_source["artifact_sha256"] == status_response.headers["x-umi-contract-revision"]
    assert first.status_code == 200
    first_body = first.json()
    assert first_body["schema"] == "umi-observer-window-solutions/1"
    assert first_body["score_scope"] == "validator_local"
    assert first_body["window"]["validator_account_id32"] == window.validator_account_id32
    assert first_body["window"]["audit_release_block_hash"] == window.audit_release_block_hash
    assert first_body["window"]["evidence"]["manifest_sha256"] == window.manifest_sha256
    assert first_body["window"]["evidence"]["reveal_result"]["sha256"] == "92" * 32
    assert first_body["page"]["total"] == 2
    solution = first_body["solutions"][0]
    assert solution["hypothesis"] == "hello world"
    assert solution["references"] == ["hello world", "hi world", "hello there"]
    assert solution["score"] == {"numerator": "1", "denominator": "1"}
    assert solution["evidence"]["request"]["url"].endswith(
        "/objects/" + solution["evidence"]["request"]["sha256"]
    )
    assert second.status_code == 200
    failed = second.json()["solutions"][0]
    assert failed["outer_disposition"] == "missing"
    assert failed["zero_score_reason"] == "missing"
    assert failed["response_status"] is None
    assert failed["score"] == {"numerator": "0", "denominator": "1"}
    serialized = first.text + second.text
    assert "video_url" not in serialized
    assert "consent_manifest" not in serialized


def test_unreleased_solution_window_is_not_visible_or_status_advancing() -> None:
    window = replace(
        _released_local_window("11" * 32),
        audit_release_block=100,
        solutions=(_solution(1),),
    )
    app = create_observer_app(
        _cache(SequenceCollector([_snapshot(block_number=99)])),
        bundle_feed=StaticBundleFeed((window,)),  # type: ignore[arg-type]
    )

    with TestClient(app) as client:
        status = client.get("/api/v1/status").json()
        response = client.get(
            f"/api/v1/windows/{window.window_id}/solutions"
            f"?validator={window.validator_account_id32}"
        )

    assert status["protocol_state"]["phase"] == "pre_public_calibration"
    assert "public_calibration_not_started" in status["outstanding_gap_codes"]
    assert response.status_code == 404
    assert response.json()["error"]["reason_code"] == "released_window_not_found"


def test_released_incident_has_no_solutions_endpoint() -> None:
    incident = _released_local_window("11" * 32, classification="skipped")
    app = create_observer_app(
        _cache(SequenceCollector([_snapshot()])),
        bundle_feed=StaticBundleFeed((incident,)),  # type: ignore[arg-type]
    )

    with TestClient(app) as client:
        response = client.get(
            f"/api/v1/windows/{incident.window_id}/solutions"
            f"?validator={incident.validator_account_id32}"
        )

    assert response.status_code == 404
    assert response.json()["error"]["reason_code"] == "released_solution_evidence_not_found"


def test_window_cursor_is_bounded_and_invalidated_by_new_verified_entry() -> None:
    first = _released_local_window("11" * 32)
    second = replace(
        _released_local_window("22" * 32),
        window_id="ce" * 32,
        window_index=8,
        bundle_relative_path=(f"validators/{'22' * 32}/windows/{'ce' * 32}/calibration_no_weight"),
    )
    feed = StaticBundleFeed((first, second))
    app = create_observer_app(
        _cache(SequenceCollector([_snapshot()])),
        bundle_feed=feed,  # type: ignore[arg-type]
    )

    with TestClient(app) as client:
        page_one = client.get("/api/v1/windows?limit=1")
        cursor = page_one.json()["page"]["next_cursor"]
        page_two = client.get(f"/api/v1/windows?limit=1&cursor={cursor}")
        feed.value = BundleFeedSnapshot(
            (
                *feed.value.windows,
                replace(
                    second,
                    window_id="cf" * 32,
                    window_index=9,
                    bundle_relative_path=(
                        f"validators/{'22' * 32}/windows/{'cf' * 32}/calibration_no_weight"
                    ),
                ),
            ),
            feed.value.health,
        )
        changed = client.get(f"/api/v1/windows?limit=1&cursor={cursor}")
        cross_feed = client.get(f"/api/v1/incidents?limit=1&cursor={cursor}")

    assert page_one.status_code == 200
    assert page_one.json()["page"]["returned"] == 1
    assert page_one.json()["page"]["total"] == 2
    assert page_two.json()["windows"][0]["window_id"] == second.window_id
    assert changed.status_code == 409
    assert changed.json()["error"]["reason_code"] == "cursor_snapshot_changed"
    assert cross_feed.status_code == 422
    assert cross_feed.json()["error"]["reason_code"] == "cursor_feed_mismatch"


def test_chain_economics_uses_competition_ranks_for_exact_ties() -> None:
    incentives = (50, 40, 40)
    rows = tuple(
        _participant(uid).model_copy(
            update={
                "chain_metrics": _participant(uid).chain_metrics.model_copy(
                    update={"incentive": _metric(raw)}
                )
            }
        )
        for uid, raw in enumerate(incentives)
    )
    app = create_observer_app(_cache(SequenceCollector([_snapshot(participants=rows)])))

    with TestClient(app) as client:
        leaderboard = client.get("/api/v1/leaderboard").json()["chain_economics"]

    assert leaderboard["ranking_status"] == "ranked"
    assert leaderboard["reason_code"] is None
    assert [entry["chain_rank"] for entry in leaderboard["entries"]] == [1, 2, 2]
    assert [entry["incentive_tie_size"] for entry in leaderboard["entries"]] == [1, 2, 2]


def test_window_lookup_has_bounded_structured_errors() -> None:
    app = create_observer_app(_cache(SequenceCollector([_snapshot()])))

    with TestClient(app) as client:
        malformed = client.get("/api/v1/windows/not-a-window")
        absent = client.get("/api/v1/windows/" + "ab" * 32)

    assert malformed.status_code == 422
    assert malformed.headers["cache-control"] == "no-store"
    assert malformed.json()["freshness"] == "unavailable"
    assert malformed.json()["error"]["reason_code"] == "invalid_window_id"
    assert absent.status_code == 404
    assert absent.headers["cache-control"] == "no-store"
    assert absent.json()["error"]["reason_code"] == "released_window_not_found"


def test_etag_head_and_mutating_methods() -> None:
    app = create_observer_app(_cache(SequenceCollector([_snapshot()])))

    with TestClient(app) as client:
        initial = client.get("/api/v1/status")
        unchanged = client.get(
            "/api/v1/status",
            headers={"If-None-Match": initial.headers["etag"]},
        )
        weak = client.get(
            "/api/v1/status",
            headers={"If-None-Match": f"W/{initial.headers['etag']}"},
        )
        wildcard = client.get(
            "/api/v1/status",
            headers={"If-None-Match": "*"},
        )
        listed = client.get(
            "/api/v1/status",
            headers={"If-None-Match": f'"unrelated", {initial.headers["etag"]}'},
        )
        head = client.head("/api/v1/status")
        post = client.post("/api/v1/status")

    assert unchanged.status_code == 304
    assert unchanged.content == b""
    assert weak.status_code == 304
    assert wildcard.status_code == 304
    assert listed.status_code == 304
    assert head.status_code == 200
    assert head.content == b""
    assert head.headers["content-length"] == initial.headers["content-length"]
    assert head.headers["etag"] == initial.headers["etag"]
    assert post.status_code == 405


def test_unknown_query_fields_and_untrusted_hosts_fail() -> None:
    app = create_observer_app(_cache(SequenceCollector([_snapshot()])))

    with TestClient(app) as client:
        unknown = client.get("/api/v1/participants?url=http://127.0.0.1")
        untrusted = client.get("/api/v1/status", headers={"Host": "attacker.invalid"})

    assert unknown.status_code == 422
    assert unknown.json()["error"]["reason_code"] == "invalid_request"
    assert untrusted.status_code == 400


def test_cors_is_absent_by_default_and_exact_when_configured() -> None:
    default_app = create_observer_app(_cache(SequenceCollector([_snapshot()])))
    allowed_app = create_observer_app(
        _cache(SequenceCollector([_snapshot()])),
        cors_origins=("https://umi.vision",),
    )

    with TestClient(default_app) as client:
        default = client.get("/api/v1/status", headers={"Origin": "https://umi.vision"})
    with TestClient(allowed_app) as client:
        allowed = client.get("/api/v1/status", headers={"Origin": "https://umi.vision"})
        spoofed = client.get(
            "/api/v1/status",
            headers={"Origin": "https://umi.vision.attacker.invalid"},
        )

    assert "access-control-allow-origin" not in default.headers
    assert allowed.headers["access-control-allow-origin"] == "https://umi.vision"
    exposed = {
        value.strip().casefold()
        for value in allowed.headers["access-control-expose-headers"].split(",")
    }
    assert exposed == {
        "etag",
        "x-umi-contract-revision",
        "x-umi-dataset-revision",
        "x-umi-finalized-block",
        "x-umi-pilot-bundle",
    }
    assert "access-control-allow-origin" not in spoofed.headers
    with pytest.raises(ValueError, match="exact HTTPS origins"):
        create_observer_app(
            _cache(SequenceCollector([_snapshot()])),
            cors_origins=("*",),
        )
    with pytest.raises(ValueError, match="exact HTTPS origins"):
        create_observer_app(
            _cache(SequenceCollector([_snapshot()])),
            cors_origins=("https://um" + chr(0x131) + ".vision",),
        )


def test_openapi_exposes_no_mutating_operation() -> None:
    app = create_observer_app(_cache(SequenceCollector([_snapshot()])))
    document = app.openapi()
    methods = {method for path in document["paths"].values() for method in path}
    assert methods <= {"get", "head"}
    window_get = document["paths"]["/api/v1/windows/{window_id}"]["get"]
    assert window_get["parameters"][0]["schema"]["pattern"] == "^[0-9a-f]{64}$"
    assert window_get["responses"]["200"]["content"]["application/json"]["schema"]["$ref"].endswith(
        "/WindowResponse"
    )
    for status in ("404", "422", "503"):
        assert window_get["responses"][status]["content"]["application/json"]["schema"][
            "$ref"
        ].endswith("/ErrorResponse")
    solutions_get = document["paths"]["/api/v1/windows/{window_id}/solutions"]["get"]
    parameters = {item["name"]: item for item in solutions_get["parameters"]}
    assert parameters["window_id"]["schema"]["pattern"] == "^[0-9a-f]{64}$"
    assert parameters["validator"]["schema"]["anyOf"][0]["pattern"] == "^[0-9a-f]{64}$"
    assert parameters["limit"]["schema"]["minimum"] == 1
    assert parameters["limit"]["schema"]["maximum"] == 50
    assert solutions_get["responses"]["200"]["content"]["application/json"]["schema"][
        "$ref"
    ].endswith("/WindowSolutionsResponse")


@pytest.mark.asyncio
async def test_cache_retains_last_good_snapshot_as_stale_without_error_leak() -> None:
    now = [100.0]
    collector = SequenceCollector(
        [_snapshot(), RuntimeError("secret https://rpc.invalid/token=credential")]
    )
    cache = _cache(collector, monotonic=lambda: now[0])

    assert await cache.refresh() is True
    now[0] += 1
    assert await cache.refresh() is False
    view = cache.current()
    assert view.freshness == "stale"
    assert view.snapshot.network.name == "Vocence"


@pytest.mark.asyncio
async def test_cache_fails_closed_without_snapshot_and_after_stale_limit() -> None:
    now = [100.0]
    missing = _cache(
        SequenceCollector([RuntimeError("down")]),
        fresh_for_seconds=1,
        maximum_stale_seconds=2,
        monotonic=lambda: now[0],
    )
    assert await missing.refresh() is False
    with pytest.raises(ObserverUnavailable):
        missing.current()

    existing = _cache(
        SequenceCollector([_snapshot()]),
        fresh_for_seconds=1,
        maximum_stale_seconds=2,
        monotonic=lambda: now[0],
    )
    assert await existing.refresh() is True
    now[0] += 3
    with pytest.raises(ObserverUnavailable):
        existing.current()


@pytest.mark.asyncio
async def test_same_finalized_head_does_not_reset_stale_deadline() -> None:
    now = [100.0]
    snapshot = _snapshot()
    cache = _cache(
        SequenceCollector([snapshot, snapshot]),
        fresh_for_seconds=1,
        maximum_stale_seconds=2,
        monotonic=lambda: now[0],
    )

    assert await cache.refresh() is True
    now[0] += 3
    assert await cache.refresh() is True
    with pytest.raises(ObserverUnavailable):
        cache.current()


@pytest.mark.asyncio
async def test_old_finalized_head_is_rejected_on_initial_collection() -> None:
    cache = _cache(
        SequenceCollector([_snapshot()]),
        maximum_finalized_head_age_seconds=120,
        clock=lambda: UTC_NOW + timedelta(seconds=121),
    )

    assert await cache.refresh() is False
    with pytest.raises(ObserverUnavailable):
        cache.current()


@pytest.mark.asyncio
async def test_refresh_log_is_bounded_and_never_contains_raw_exception(
    caplog: pytest.LogCaptureFixture,
) -> None:
    cache = _cache(SequenceCollector([RuntimeError("secret https://rpc.invalid/token=credential")]))

    with caplog.at_level("WARNING", logger="umi.observer"):
        assert await cache.refresh() is False

    assert "reason_code=snapshot_refresh_failed" in caplog.text
    assert "credential" not in caplog.text


def test_cache_headers_never_outlive_origin_stale_budget() -> None:
    now = [100.0]
    cache = _cache(
        SequenceCollector([_snapshot()]),
        fresh_for_seconds=1,
        maximum_stale_seconds=1,
        monotonic=lambda: now[0],
    )
    app = create_observer_app(cache)

    with TestClient(app) as client:
        response = client.get("/api/v1/status")

    directives = {
        part.strip().split("=", 1)[0]: part.strip().split("=", 1)[1] if "=" in part else None
        for part in response.headers["cache-control"].split(",")
    }
    assert int(directives["max-age"]) <= 1
    assert "stale-if-error" not in directives


def test_snapshot_v1_rejects_premature_umi_translation_scores() -> None:
    participant = _participant(0).model_copy(
        update={
            "umi_translation": UmiTranslationMetrics(
                availability="available",
                reason_code=None,
                miner_root="5MinerRoot",
                accuracy=ExactRational(numerator="1", denominator="2"),
                utility=ExactRational(numerator="4", denominator="25"),
                rank=1,
                audit_bundle_sha256="ab" * 32,
                audit_release_block="999999999",
            )
        }
    )

    with pytest.raises(ValueError, match="cannot publish released UMI translation scores"):
        _snapshot(participants=(participant,))


def test_snapshot_rejects_duplicate_identifiers_and_inconsistent_counts() -> None:
    duplicate_uid = _participant(1).model_copy(update={"uid": 0})
    with pytest.raises(ValueError, match="participant UIDs must be unique"):
        _snapshot(participants=(_participant(0), duplicate_uid))

    duplicate_hotkey = _participant(1).model_copy(update={"hotkey": _participant(0).hotkey})
    with pytest.raises(ValueError, match="participant hotkeys must be unique"):
        _snapshot(participants=(_participant(0), duplicate_hotkey))

    snapshot = _snapshot()
    inconsistent_network = snapshot.network.model_copy(
        update={"counts": snapshot.network.counts.model_copy(update={"chain_active": 0})}
    )
    with pytest.raises(ValueError, match=r"counts\.chain_active"):
        ObserverSnapshot(
            collected_at=snapshot.collected_at,
            sources=snapshot.sources,
            network=inconsistent_network,
            participants=snapshot.participants,
        )


def test_released_score_and_window_feeds_require_finalized_bundle_evidence() -> None:
    app = create_observer_app(_cache(SequenceCollector([_snapshot()])))
    with TestClient(app) as client:
        leaderboard = client.get("/api/v1/leaderboard").json()
        windows = client.get("/api/v1/windows").json()

    bundle_hash = "ab" * 32
    released_source = {
        "source_id": "released-bundle-ab",
        "source_kind": "released_audit_bundle",
        "verification_status": "bundle_verified",
        "block": None,
        "policy_hash": None,
        "artifact_sha256": bundle_hash,
        "validator_input_eligible": False,
    }
    score_entry = {
        "rank": 1,
        "miner_root": "5MinerRoot",
        "serving_hotkey": "5MinerServingHotkey",
        "accuracy": {"numerator": "1", "denominator": "2"},
        "utility": {"numerator": "1", "denominator": "4"},
        "audit_bundle_sha256": bundle_hash,
        "audit_release_block": "99",
    }
    leaderboard["umi_translation"] = {
        "availability": "available",
        "reason_code": None,
        "entries": [score_entry],
    }
    with pytest.raises(ValueError, match="verified audit-bundle source"):
        LeaderboardResponse.model_validate_json(json.dumps(leaderboard))

    leaderboard["sources"].append(released_source)
    valid_leaderboard = LeaderboardResponse.model_validate_json(json.dumps(leaderboard))
    assert valid_leaderboard.umi_translation.entries[0].rank == 1
    leaderboard["umi_translation"]["entries"][0]["audit_release_block"] = "100"
    with pytest.raises(ValueError, match="cannot exceed the finalized source block"):
        LeaderboardResponse.model_validate_json(json.dumps(leaderboard))

    released_window = {
        "window_id": "cd" * 32,
        "window_index": "7",
        "terminal_classification": "calibration_no_weight",
        "audit_release_block": "99",
        "audit_release_block_hash": "0x" + "44" * 32,
        "audit_bundle_sha256": bundle_hash,
        "evidence": {
            "public_origin": "https://audits.example",
            "index_url": "https://audits.example/validators/" + "11" * 32 + "/index.json",
            "relative_path": (
                "validators/" + "11" * 32 + "/windows/" + "cd" * 32 + "/calibration_no_weight"
            ),
            "manifest_url": (
                "https://audits.example/validators/"
                + "11" * 32
                + "/windows/"
                + "cd" * 32
                + "/calibration_no_weight/manifest.json"
            ),
            "manifest_sha256": bundle_hash,
            "tree_sha256": "43" * 32,
            "reveal_stage_manifest": None,
            "reveal_result": None,
        },
    }
    windows["availability"] = "available"
    windows["reason_code"] = None
    windows["windows"] = [released_window]
    with pytest.raises(ValueError, match="verified audit-bundle source"):
        WindowsResponse.model_validate_json(json.dumps(windows))

    windows["sources"].append(released_source)
    assert WindowsResponse.model_validate_json(json.dumps(windows)).windows[0].window_index == "7"

    window = {
        "schema": "umi-observer-window/1",
        "generated_at": windows["generated_at"],
        "freshness": windows["freshness"],
        "snapshot_age_seconds": windows["snapshot_age_seconds"],
        "finalized_head_age_seconds": windows["finalized_head_age_seconds"],
        "sources": windows["sources"],
        "protocol_state": windows["protocol_state"],
        "window": released_window,
    }
    assert WindowResponse.model_validate_json(json.dumps(window)).window.window_index == "7"
    window["window"]["audit_release_block"] = "100"
    with pytest.raises(ValueError, match="cannot exceed the finalized source block"):
        WindowResponse.model_validate_json(json.dumps(window))


def test_exact_observer_score_must_be_in_unit_interval() -> None:
    with pytest.raises(ValueError, match="cannot exceed one"):
        ExactRational(numerator="2", denominator="1")


def test_health_and_readiness_responses_are_not_cacheable() -> None:
    app = create_observer_app(_cache(SequenceCollector([_snapshot()])))

    with TestClient(app) as client:
        health = client.get("/healthz")
        ready = client.get("/readyz")

    assert health.status_code == 200
    assert health.headers["cache-control"] == "no-store"
    assert ready.status_code == 200
    assert ready.headers["cache-control"] == "no-store"


def test_normalized_display_must_match_authoritative_raw_fraction() -> None:
    with pytest.raises(ValueError, match="must match the raw PerU16 fraction"):
        ExactNormalizedMetric(raw_numerator="32767", display_decimal="0.5")


def test_exchange_display_must_match_authoritative_raw_reserves() -> None:
    with pytest.raises(ValueError, match="must match the observed pool reserves"):
        ExactExchangeRate(
            tao_reserve_rao="2000000000",
            subnet_alpha_reserve_rao="1000000000",
            display_decimal="1.999",
        )


@pytest.mark.asyncio
async def test_cache_rejects_finalized_regression_atomically() -> None:
    first = _snapshot(block_number=99, block_hash_byte="11")
    regression = _snapshot(block_number=98, block_hash_byte="44")
    collector = SequenceCollector([first, regression])
    cache = _cache(collector)

    assert await cache.refresh() is True
    assert await cache.refresh() is False
    view = cache.current()
    assert view.freshness == "stale"
    assert _snapshot(block_number=99).sources[0].block is not None
    assert view.snapshot.sources[0].block == first.sources[0].block


@pytest.mark.asyncio
async def test_refresh_is_single_flight() -> None:
    class BlockingCollector:
        def __init__(self) -> None:
            self.calls = 0

        async def collect(self) -> ObserverSnapshot:
            self.calls += 1
            await asyncio.sleep(0)
            return _snapshot()

    collector = BlockingCollector()
    cache = SnapshotCache(
        collector,
        refresh_interval_seconds=60,
        clock=lambda: UTC_NOW,
    )
    results = await asyncio.gather(cache.refresh(), cache.refresh())

    assert results == [True, True]
    assert collector.calls == 1
