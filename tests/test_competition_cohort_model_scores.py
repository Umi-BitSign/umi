"""Certified allocation projection, retained publication and cache-only serving."""

import json
import sqlite3

import httpx
import pytest

from umi import competition_cohort_model_scores as module
from umi.competition_cohort_intake import history_tip
from umi.competition_cohort_order_signer import CohortOrderHistory
from umi.competition_cohort_public_api import CohortPublicApiConfig, create_cohort_public_app
from umi.competition_cohort_reward_allocation import CohortRewardAllocation
from umi.competition_public_results_directory import atomic_write, owned_directory
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_model_award import (
    award,
)
from .test_competition_cohort_model_award import (
    base_policy as base_policy,
)
from .test_competition_cohort_model_award import (
    legacy_scenario as legacy_scenario,
)
from .test_competition_cohort_model_award import (
    model_case as model_case,
)
from .test_competition_cohort_model_award import (
    policy as policy,
)
from .test_competition_cohort_model_award import (
    receipt_scenario as receipt_scenario,
)
from .test_competition_cohort_model_award import (
    recovery as recovery,
)
from .test_competition_cohort_model_award import (
    runtime as runtime,
)
from .test_competition_cohort_roster import close
from .test_open_competition import wallet

C = "c" * 64


@pytest.fixture
def certified(model_case):
    b, _, manifest, _, _ = model_case
    completed = {p.submission_sha256 for p in b["closure"].participants}
    selected = award(
        model_case,
        acceptances=tuple(a for a in model_case[3] if a.acceptance.submission_sha256 in completed),
    )
    version = {
        "umi-cohort-model-award/1": 2,
        "umi-cohort-model-award/2": 3,
        "umi-cohort-model-award/3": 4,
        "umi-cohort-model-award/4": 5,
    }[selected.schema_]
    allocation = CohortRewardAllocation(
        schema="umi-cohort-reward-allocation/" + str(version),
        policy_sha256=digest(b["policy"]),
        round_sha256=digest(b["roster"].round),
        service_certificate_sha256="a" * 64,
        quality_manifest_sha256=digest(manifest),
        model_award=selected,
        recipients=(),
        burn_weight=65535,
    )
    history, decisions = b["history"], dict(b["decisions"])
    start = history.transitions[-1].transition.observed_at_block + 100
    for index, result in enumerate(
        (digest(b["closure"]), "c" * 64, digest(manifest), "b" * 64, digest(allocation))
    ):
        history = close(history, b["policy"], decisions, start + index * 10, result)
    wanted = {
        t.transition.evidence_sha256
        for t in history.transitions
        if t.transition.requires_progress_evidence
    }
    packet = CohortOrderHistory(
        history=history, decisions=tuple(decisions[k] for k in sorted(wanted))
    )
    header = dict(
        allocation=allocation.model_dump(mode="json", by_alias=True),
        inputs=dict(
            roster=b["roster"].model_dump(mode="json", by_alias=True),
            history=history.model_dump(mode="json", by_alias=True),
        ),
    )
    return header, packet, b["policy"], digest(history.plan)


@pytest.mark.parametrize(
    "model_case",
    [("equal", 2), ("below", 1), ("candidate-failure", 1), ("tail", 11)],
    indirect=True,
)
@pytest.mark.parametrize("receipt_scenario", ["model-awards"], indirect=True)
def test_actual_native_model_metadata_keeps_quality_rank_and_reward_dispositions(certified):
    header, packet, policy, cohort = certified
    result = module.project_model_scores(header, packet, policy, cohort=cohort)
    assert len(result.items) == len(header["inputs"]["roster"]["participants"])
    assert result.reward_activation == "not_assessed_by_this_endpoint"
    assert result.certification == "quorum_certified_native_allocation"
    assert result.raw_weight_scope == "certified_cohort_all_tracks_per_hotkey"
    assert not result.chain_submission_authorized
    assert all(i.certified_raw_weight_for_hotkey == 0 for i in result.items)
    scored = [i for i in result.items if i.status == "scored"]
    assert scored and all(i.score_rank >= 1 for i in scored)
    if len(scored) == 2:
        assert scored[0].aggregate == scored[1].aggregate and {i.score_rank for i in scored} == {1}
    if len(scored) < len(result.items):
        unscored = [i for i in result.items if i.status == "not_scored"]
        assert all(
            i.score_rank is None and i.aggregate is None and i.baseline_eligible is None
            for i in unscored
        )
    raw = canonical_json_bytes(result)
    for private in (b'"references"', b'"hypothesis"', b'"video"', b'"signatures"', b'"objects"'):
        assert private not in raw
    for row in scored:
        assert row.baseline_eligible == (row.aggregate.decimal >= row.baseline_aggregate.decimal)
        if not row.baseline_eligible:
            assert row.model_reward_status == "below_baseline"


@pytest.mark.parametrize("receipt_scenario", ["model-awards"], indirect=True)
def test_changed_allocation_or_history_cannot_supply_public_scores(certified):
    from copy import deepcopy

    header, packet, policy, cohort = certified
    changed = deepcopy(header)
    changed["allocation"]["burn_weight"] -= 1
    with pytest.raises(ValueError):
        module.project_model_scores(changed, packet, policy, cohort=cohort)
    changed = deepcopy(header)
    changed["allocation"]["service_certificate_sha256"] = "e" * 64
    with pytest.raises(ValueError, match="certified result"):
        module.project_model_scores(changed, packet, policy, cohort=cohort)
    with pytest.raises(ValueError, match="selected native package"):
        module.project_model_scores(header, packet, policy, cohort="f" * 64)
    transition = packet.history.transitions[-1]
    invalid = packet.model_copy(
        update={
            "history": packet.history.model_copy(
                update={
                    "transitions": (
                        *packet.history.transitions[:-1],
                        transition.model_copy(update={"signatures": transition.signatures[:-1]}),
                    )
                }
            )
        }
    )
    changed = deepcopy(header)
    changed["inputs"]["history"] = invalid.history.model_dump(mode="json", by_alias=True)
    with pytest.raises(ValueError):
        module.project_model_scores(changed, invalid, policy, cohort=cohort)


def sample_scores():
    return module.PublicModelScores(
        schema="umi-public-cohort-model-results/1",
        cohort_sha256=C,
        round_sha256="d" * 64,
        policy_sha256="e" * 64,
        allocation_sha256="f" * 64,
        certified_history_tip_sha256="a" * 64,
        source_metadata_sha256="b" * 64,
        certification="quorum_certified_native_allocation",
        items=(
            module.PublicModelScore(
                submission_sha256="1" * 64,
                model_sha256="2" * 64,
                uid=7,
                hotkey=wallet("Alice").hotkey.ss58_address,
                status="scored",
                aggregate=module.ModelScore(numerator="1", denominator="2", decimal=0.5),
                baseline_aggregate=module.ModelScore(numerator="1", denominator="4", decimal=0.25),
                score_rank=1,
                baseline_eligible=True,
                model_reward_status="selected_by_certified_rule",
                certified_raw_weight_for_hotkey=123,
            ),
        ),
    )


async def test_score_get_is_cached_and_never_reads_files_sqlite_or_chain(tmp_path, monkeypatch):
    owned_directory(tmp_path / "model-results", create=True)
    atomic_write(tmp_path / "model-results" / (C + ".json"), canonical_json_bytes(sample_scores()))
    app = create_cohort_public_app(CohortPublicApiConfig(results=dict(directory=str(tmp_path))))
    app.state.model_scores.sample()

    def forbidden(*args, **kwargs):
        raise AssertionError("score GET performed native work or file I/O")

    monkeypatch.setattr(module, "read_owned_file", forbidden)
    monkeypatch.setattr(module, "_stamp", forbidden)
    monkeypatch.setattr(module, "native_header", forbidden)
    monkeypatch.setattr(sqlite3, "connect", forbidden)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        result = await client.get(f"/v1/competition/cohorts/{C}/model-results?limit=1")
        assert result.status_code == 200
        body = result.json()
        assert body["total"] == 1 and body["items"][0]["uid"] == 7
        assert body["reward_activation"] == "not_assessed_by_this_endpoint"
        assert (
            await client.get(f"/v1/competition/cohorts/{'0' * 64}/model-results")
        ).status_code == 404


def test_cache_restart_and_damage_remain_explicit(tmp_path, monkeypatch):
    root = tmp_path / "model-results"
    owned_directory(root, create=True)
    path = root / (C + ".json")
    atomic_write(path, canonical_json_bytes(sample_scores()))
    first = module.PublicModelScoreCache(tmp_path)
    first.sample()
    restarted = module.PublicModelScoreCache(tmp_path)
    restarted.sample()
    assert first.read(C) == restarted.read(C)
    path.write_bytes(b'{"broken":true}')
    restarted.sample()
    with pytest.raises(ValueError, match="metadata needs repair"):
        restarted.read(C)
    monkeypatch.setattr(
        module, "read_owned_file", lambda *a: pytest.fail("unchanged damage was retried")
    )
    restarted.sample()
    with pytest.raises(ValueError):
        restarted.read(C)


def test_signed_correction_overlay_is_selected_and_missing_artifact_fails_closed(tmp_path):
    original_dir = tmp_path / "model-results"
    corrected_dir = tmp_path / "model-results-corrections"
    owned_directory(original_dir, create=True)
    owned_directory(corrected_dir, create=True)
    original = sample_scores()
    selected = original.model_copy(
        update={
            "schema_": "umi-public-cohort-model-results/2",
            "certification": "quorum_certified_score_correction",
            "allocation_sha256": "e" * 64,
            "original_allocation_sha256": original.allocation_sha256,
            "score_correction_statement_sha256": "d" * 64,
            "reward_adoption_sha256": "f" * 64,
        }
    )
    atomic_write(original_dir / (C + ".json"), canonical_json_bytes(original))
    overlay = corrected_dir / (C + ".json")
    atomic_write(overlay, canonical_json_bytes(selected))
    cache = module.PublicModelScoreCache(tmp_path, corrections={C: "d" * 64})
    cache.sample()
    assert cache.read(C)["schema"] == "umi-public-cohort-model-results/2"
    assert cache.read(C)["allocation_sha256"] == "e" * 64
    (original_dir / (C + ".json")).write_bytes(canonical_json_bytes(original))
    cache.sample()
    assert cache.read(C)["schema"] == "umi-public-cohort-model-results/2"
    overlay.unlink()
    cache.sample()
    with pytest.raises(ValueError, match="metadata needs repair"):
        cache.read(C)


def test_header_never_traverses_native_objects_and_refuses_link_or_partial(tmp_path, monkeypatch):
    path = tmp_path / "native.json"
    header = dict(
        allocation={},
        inputs={"roster": {}, "history": {}},
        objects=[{"private": "NO_OBJECT_READ"}],
        schema="umi-cohort-reward-package/1",
    )
    raw = canonical_json_bytes(header)
    path.write_bytes(raw)
    path.chmod(0o600)
    boundary = raw.index(b'"objects":')
    value_end = module.value_end

    def bounded(raw, start, depth):
        assert start < boundary, "private native object inventory was scanned"
        return value_end(raw, start, depth)

    monkeypatch.setattr(module, "value_end", bounded)
    result, stamp = module.native_header(
        path, maximum_bytes=len(raw), maximum_metadata_bytes=len(raw)
    )
    assert set(result) == {"allocation", "inputs"} and stamp[6] == len(raw)
    linked = tmp_path / "linked.json"
    linked.symlink_to(path)
    with pytest.raises(ValueError):
        module.native_header(linked, maximum_bytes=len(raw), maximum_metadata_bytes=len(raw))
    path.write_bytes(raw[: boundary - 2])
    with pytest.raises(ValueError):
        module.native_header(path, maximum_bytes=len(raw), maximum_metadata_bytes=len(raw))


@pytest.mark.parametrize("receipt_scenario", ["model-awards"], indirect=True)
def test_publisher_retains_once_then_restores_without_header_or_certificate_replay(
    certified, tmp_path, monkeypatch
):
    header, packet, policy, cohort = certified
    source, history, output, state = [
        tmp_path / name for name in ("source", "history", "output", "state")
    ]
    for p in (source, history, history / cohort):
        owned_directory(p, create=True)
    policy_path = tmp_path / "policy.json"
    policy_path.write_bytes(canonical_json_bytes(policy))
    native = source / (cohort + ".json")
    atomic_write(
        native,
        canonical_json_bytes(
            {
                **header,
                "objects": [{"private": "NEVER_EXPOSE"}],
                "schema": "umi-cohort-reward-package/1",
            }
        ),
    )
    atomic_write(
        history / cohort / (history_tip(packet.history) + ".json"), canonical_json_bytes(packet)
    )
    config = module.NativeModelScoresConfig(
        source_directory=str(source),
        history_directory=str(history),
        output_directory=str(output),
        state_directory=str(state),
        policy_path=str(policy_path),
        policy_sha256=digest(policy),
        maximum_package_bytes=64 * 1024**2,
    )
    first = module.NativeModelScoresPublisher(config)
    report = first.poll_once()
    assert report["published"] == [cohort], report
    original = (output / (cohort + ".json")).read_bytes()
    reopened = module.NativeModelScoresPublisher(config)

    def forbidden(*args, **kw):
        raise AssertionError("completed native scoring was checked twice")

    monkeypatch.setattr(module, "native_header", forbidden)
    monkeypatch.setattr(module, "project_model_scores", forbidden)
    (output / (cohort + ".json")).unlink()
    native.unlink()  # Durable checked completion outlives evicted native bytes.
    assert reopened.poll_once()["published"] == [cohort]
    assert (output / (cohort + ".json")).read_bytes() == original
    assert reopened.poll_once()["retained"] == [cohort]
    receipt = state / (cohort + ".json")
    value = json.loads(receipt.read_bytes())
    value["projection"]["items"][0]["certified_raw_weight_for_hotkey"] += 1
    receipt.write_bytes(canonical_json_bytes(value))
    assert reopened.poll_once()["held"]
