"""Exact owner-local outcome checkpoints across phase changes and process restart."""

import hashlib
import json
import time

import pytest

from umi import competition_cohort_quality as quality
from umi import competition_cohort_request_terminal as terminals
from umi.competition_cohort_quality_signing import review_quality_manifest
from umi.competition_verification_reuse import VerificationReuse, VerificationSourceChanged
from umi.competition_verification_snapshot import VerifiedPackageSnapshot
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_consumers import tip
from .test_competition_cohort_quality import reviewer
from .test_competition_cohort_roster import close
from .test_competition_cpu_efficiency_pipeline import base_policy as base_policy
from .test_competition_cpu_efficiency_pipeline import legacy_scenario as legacy_scenario
from .test_competition_cpu_efficiency_pipeline import pipeline_case as pipeline_case
from .test_competition_cpu_efficiency_pipeline import policy as policy
from .test_competition_cpu_efficiency_pipeline import receipt_scenario as receipt_scenario
from .test_competition_cpu_efficiency_pipeline import recovery as recovery
from .test_competition_cpu_efficiency_pipeline import runtime as runtime
from .test_competition_verification_collectors import snapshot_at

pytestmark = pytest.mark.parametrize(
    "receipt_scenario", ["geometric-model-awards-c7"], indirect=True
)
MAXIMUM = 8 * 1024**2


def outcome_receipts(root):
    found = {}
    for path in root.glob("*.json"):
        receipt = json.loads(path.read_bytes())
        result = json.loads(receipt["result_json"])
        if isinstance(result, dict) and result.get("schema", "").startswith(
            "umi-cohort-closed-quality/"
        ):
            found[result["submission_sha256"]] = path
    return found


def fail_repeat(*args, **kwargs):
    pytest.fail("unchanged completed outcome repeated payload or native calculation")


@pytest.mark.parametrize("recovery", [7, 8], indirect=True)
async def test_upgrade_reuses_existing_proofs_then_restart_skips_outcome_payloads(
    pipeline_case, tmp_path, monkeypatch, caplog
):
    b, _, benchmark, *_ = pipeline_case
    reopen = snapshot_at(tmp_path / "input", b["objects"])
    root = tmp_path / "verdicts"
    caplog.set_level("INFO", logger="umi.competition.progress")
    native = quality._closed_participant_quality
    # Simulate a supported older installation: same exact pure calculation and
    # native proof receipts, but no participant-outcome checkpoint yet.
    with monkeypatch.context() as legacy:
        legacy.setattr(quality, "_closed_participant_quality", native.__wrapped__)
        with VerificationReuse(root, owner="validator-a").selected():
            expected = review_quality_manifest(
                benchmark, reviewer(b, objects=reopen().collector(MAXIMUM))
            )
    old_receipts = {path: path.read_bytes() for path in root.glob("*.json")}
    assert old_receipts and not outcome_receipts(root)
    monkeypatch.setattr(terminals, "replay_execution_steps", fail_repeat)
    monkeypatch.setattr(terminals, "replay_shared_incumbent_steps", fail_repeat)
    source = reopen().collector(MAXIMUM)
    started = time.monotonic()
    with VerificationReuse(root, owner="validator-a").selected():
        assert review_quality_manifest(benchmark, reviewer(b, objects=source)) == expected
    first_seconds = time.monotonic() - started
    assert len(outcome_receipts(root)) == len(expected) == 2
    assert all(path.read_bytes() == raw for path, raw in old_receipts.items())

    # Advance signed history without changing any quality inputs. This is the
    # evidence -> review boundary that previously reconstructed every outcome.
    history = close(b["quality_history"], b["policy"], b["decisions"], 2200, digest(benchmark))
    restarted = reopen().collector(MAXIMUM)
    with VerificationReuse(root, owner="validator-a").selected():
        fresh = reviewer(
            b,
            objects=restarted,
            history=history,
            expected_tip_sha256=tip(history),
            current_block=2**53 - 1,
        )
        before = set(restarted.values)
        # Reject both rereading and rehashing exact original payloads. Metadata
        # hashing remains legitimate and collector coverage must still advance.
        original_hash = hashlib.sha256
        payloads = set(b["objects"].values())

        def no_payload_hash(raw=b"", *args, **kwargs):
            assert raw not in payloads, "unchanged payload was rehashed"
            return original_hash(raw, *args, **kwargs)

        monkeypatch.setattr(VerifiedPackageSnapshot, "read", fail_repeat)
        monkeypatch.setattr(quality, "quality_totals", fail_repeat)
        monkeypatch.setattr(quality, "replay_archived_execution", fail_repeat)
        monkeypatch.setattr(hashlib, "sha256", no_payload_hash)
        started = time.monotonic()
        actual = tuple(fresh.outcome(item.submission_sha256) for item in expected)
        restart_seconds = time.monotonic() - started
    assert tuple(canonical_json_bytes(item) for item in actual) == tuple(
        canonical_json_bytes(item) for item in expected
    )
    assert set(restarted.values) >= before
    for path in outcome_receipts(root).values():
        dependencies = json.loads(path.read_bytes())["dependencies"]
        assert {d["key"] for d in dependencies if d["kind"] == "objects"} <= set(restarted.values)
    assert restarted.used == sum(restarted.snapshot.records[key].size for key in restarted.values)
    timed = b["history"].plan.sequence >= 8
    assert all((item.cpu_efficiency is not None) == timed for item in actual)
    events = [
        json.loads(record.message) for record in caplog.records if record.message.startswith("{")
    ]
    assert (
        sum(
            e.get("stage") == "closed_participant_quality_v1" and e.get("state") == "hit"
            for e in events
        )
        == 2
    )
    print(
        {
            "participants": len(actual),
            "first_outcome_seconds": first_seconds,
            "restart_outcome_seconds": restart_seconds,
            "native_proofs_replayed": 0,
        }
    )


async def test_interruption_retains_completed_participant_and_independent_owners_do_work(
    pipeline_case, tmp_path, monkeypatch
):
    b, _, benchmark, *_ = pipeline_case
    reopen = snapshot_at(tmp_path / "input", b["objects"])
    root = tmp_path / "verdicts"
    native = quality.replay_archived_execution
    calls = []

    def counted(job, *args, **kwargs):
        calls.append(digest(job.submission.submission))
        return native(job, *args, **kwargs)

    monkeypatch.setattr(quality, "replay_archived_execution", counted)
    with VerificationReuse(root, owner="validator-a").selected():
        first = reviewer(b, objects=reopen().collector(MAXIMUM))
        keys = [member.submission_sha256 for member in first.closure.participants]
        expected_first = first.outcome(keys[0])
        # Model a controller exit between participant checkpoints.
    count_first = calls.count(keys[0])
    assert count_first > 0 and set(outcome_receipts(root)) == {keys[0]}
    with VerificationReuse(root, owner="validator-a").selected():
        resumed = reviewer(b, objects=reopen().collector(MAXIMUM))
        outcomes = review_quality_manifest(benchmark, resumed)
    assert expected_first in outcomes and calls.count(keys[0]) == count_first
    assert calls.count(keys[1]) == count_first
    # The same directory cannot grant another independent validator a verdict.
    with VerificationReuse(root, owner="validator-b").selected():
        assert (
            review_quality_manifest(benchmark, reviewer(b, objects=reopen().collector(MAXIMUM)))
            == outcomes
        )
    assert calls.count(keys[0]) == calls.count(keys[1]) == 2 * count_first


@pytest.mark.parametrize("damage", ["missing", "malformed"])
async def test_damaged_completed_outcome_reports_repair_and_preserves_other_items(
    pipeline_case, tmp_path, monkeypatch, caplog, damage
):
    b, _, benchmark, *_ = pipeline_case
    reopen = snapshot_at(tmp_path / "input", b["objects"])
    root = tmp_path / "verdicts"
    with VerificationReuse(root, owner="validator").selected():
        expected = review_quality_manifest(
            benchmark, reviewer(b, objects=reopen().collector(MAXIMUM))
        )
    paths = outcome_receipts(root)
    lost, intact = sorted(paths)
    intact_bytes = paths[intact].read_bytes()
    if damage == "missing":
        paths[lost].unlink()
    else:
        paths[lost].write_bytes(b"damaged")
    caplog.set_level("INFO", logger="umi.competition.progress")
    native = quality.replay_archived_execution
    repaired = []

    def counted(job, *args, **kwargs):
        repaired.append(digest(job.submission.submission))
        return native(job, *args, **kwargs)

    monkeypatch.setattr(quality, "replay_archived_execution", counted)
    monkeypatch.setattr(terminals, "replay_execution_steps", fail_repeat)
    monkeypatch.setattr(terminals, "replay_shared_incumbent_steps", fail_repeat)
    with VerificationReuse(root, owner="validator").selected():
        assert (
            review_quality_manifest(benchmark, reviewer(b, objects=reopen().collector(MAXIMUM)))
            == expected
        )
    assert set(repaired) == {lost} and paths[intact].read_bytes() == intact_bytes
    events = [
        json.loads(record.message) for record in caplog.records if record.message.startswith("{")
    ]
    assert any(
        e.get("stage") == "verification_receipt" and e.get("state") == "repair_required"
        for e in events
    )


async def test_fresh_authority_and_changed_original_still_refuse_reuse(pipeline_case, tmp_path):
    b, _, benchmark, *_ = pipeline_case
    reopen = snapshot_at(tmp_path / "input", b["objects"])
    root = tmp_path / "verdicts"
    with VerificationReuse(root, owner="validator").selected():
        review_quality_manifest(benchmark, reviewer(b, objects=reopen().collector(MAXIMUM)))
    with VerificationReuse(root, owner="validator").selected(), pytest.raises(ValueError):
        reviewer(b, objects=reopen().collector(MAXIMUM), expected_tip_sha256="ff" * 32)
    with VerificationReuse(root, owner="validator").selected(), pytest.raises(ValueError):
        reviewer(b, objects=reopen().collector(MAXIMUM), current_block=100)
    source = reopen().collector(MAXIMUM)
    with VerificationReuse(root, owner="validator").selected():
        fresh = reviewer(b, objects=source)
        item = fresh.closure.participants[0]
        path = source.snapshot.store.object_path(item.evaluators[0].terminal_sha256)
        # Corrupt the immutable fixture deliberately, including when CI runs
        # unprivileged; the production source-change fence must still refuse it.
        path.chmod(0o600)
        path.write_bytes(b"{}")
        with pytest.raises(VerificationSourceChanged):
            fresh.outcome(item.submission_sha256)
