"""Successful owned quality migrates without scoring or proof re-execution."""

import json
from types import SimpleNamespace

import pytest

from umi import competition_cohort_quality as quality
from umi import competition_cohort_request_terminal as terminals
from umi.competition_cohort_quality_migration import retained_quality_migration
from umi.competition_cohort_quality_signing import (
    CertifiedClosedQuality,
    SignedClosedQualityVote,
    collect_quality_certificate,
)
from umi.competition_round_journal import RoundJournal
from umi.competition_verification_reuse import VerificationReceiptUnavailable, VerificationReuse
from umi.competition_verification_snapshot import VerifiedPackageSnapshot
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_quality import reviewer
from .test_competition_cohort_quality_reuse import outcome_receipts
from .test_competition_cpu_efficiency_pipeline import base_policy as base_policy
from .test_competition_cpu_efficiency_pipeline import legacy_scenario as legacy_scenario
from .test_competition_cpu_efficiency_pipeline import pipeline_case as pipeline_case
from .test_competition_cpu_efficiency_pipeline import policy as policy
from .test_competition_cpu_efficiency_pipeline import receipt_scenario as receipt_scenario
from .test_competition_cpu_efficiency_pipeline import recovery as recovery
from .test_competition_cpu_efficiency_pipeline import runtime as runtime
from .test_competition_verification_collectors import snapshot_at

pytestmark = [
    pytest.mark.parametrize("receipt_scenario", ["geometric-model-awards-c7"], indirect=True),
    pytest.mark.parametrize("recovery", [7], indirect=True),
]
MAXIMUM = 8 * 1024**2


def forbidden(*args, **kwargs):
    pytest.fail("migration repeated quality scoring or native proof work")


@pytest.fixture
async def completed(pipeline_case, tmp_path, monkeypatch):
    b, _, manifest, *_ = pipeline_case
    binding = {"scope": "native-owned-quality-collection", "owner": "validator-a"}
    journal = RoundJournal(tmp_path / "successful-owner", binding)
    reopen = snapshot_at(tmp_path / "inputs", b["objects"])
    native = VerificationReuse(tmp_path / "receipts", owner="validator-a")
    original = quality._closed_participant_quality
    results = []
    # Produce authentic old successful native rows through the real collecting
    # API; only the later outcome checkpoint decorator is absent in this source.
    with monkeypatch.context() as legacy:
        legacy.setattr(quality, "_closed_participant_quality", original.__wrapped__)
        with native.selected():
            prior = reviewer(b, objects=reopen().collector(MAXIMUM))
            for entry in manifest.participants:
                certificate = CertifiedClosedQuality.model_validate_json(
                    b["objects"][entry.certificate_sha256]
                )
                votes = tuple(
                    SignedClosedQualityVote(result=certificate.result, signature=s)
                    for s in certificate.signatures
                )
                retained = collect_quality_certificate(
                    journal, prior, entry.submission_sha256, votes
                )
                assert retained == certificate
                results.append(certificate.result)
    assert not outcome_receipts(native.directory)
    old_receipts = {path: path.read_bytes() for path in native.directory.glob("*.json")}
    assert old_receipts
    monkeypatch.setattr(quality, "quality_totals", forbidden)
    monkeypatch.setattr(terminals, "replay_execution_steps", forbidden)
    monkeypatch.setattr(terminals, "replay_shared_incumbent_steps", forbidden)
    return SimpleNamespace(
        b=b,
        binding=binding,
        journal=journal,
        native=native,
        reopen=reopen,
        results=tuple(results),
        old_receipts=old_receipts,
    )


async def test_owned_success_migrates_per_participant_then_restart_uses_exact_receipts(
    completed, monkeypatch
):
    h = completed
    originals = {
        digest(result): tuple(
            h.journal.get_raw(kind, digest(result))
            for kind in ("closed_quality_collect_intent", "closed_quality_certificate")
        )
        for result in h.results
    }
    with (
        h.native.selected(),
        retained_quality_migration(h.journal, h.binding, verification_reuse=h.native),
    ):
        first = reviewer(h.b, objects=h.reopen().collector(MAXIMUM))
        assert first.outcome(h.results[0].submission_sha256) == h.results[0]
    paths = outcome_receipts(h.native.directory)
    assert set(paths) == {h.results[0].submission_sha256}
    first_bytes = paths[h.results[0].submission_sha256].read_bytes()
    restarted = VerificationReuse(h.native.directory, owner="validator-a")
    with (
        restarted.selected(),
        retained_quality_migration(h.journal, h.binding, verification_reuse=restarted),
    ):
        second = reviewer(h.b, objects=h.reopen().collector(MAXIMUM))
        assert tuple(second.outcome(result.submission_sha256) for result in h.results) == h.results
    paths = outcome_receipts(h.native.directory)
    assert len(paths) == len(h.results)
    assert paths[h.results[0].submission_sha256].read_bytes() == first_bytes
    assert all(path.read_bytes() == raw for path, raw in h.old_receipts.items())
    for result in h.results:
        assert (
            tuple(
                h.journal.get_raw(kind, digest(result))
                for kind in ("closed_quality_collect_intent", "closed_quality_certificate")
            )
            == originals[digest(result)]
        )
        receipt = json.loads(paths[result.submission_sha256].read_bytes())
        keys = {d["key"] for d in receipt["dependencies"]}
        assert all(run.terminal_sha256 in keys for run in result.runs)
        assert len(keys) < len(h.b["objects"])

    # Once migrated, original object identity/dependency checks are sufficient;
    # no migration index, payload reads, or outcome calculation repeats.
    with restarted.selected():
        fresh = reviewer(h.b, objects=h.reopen().collector(MAXIMUM))
        monkeypatch.setattr(VerifiedPackageSnapshot, "read", forbidden)
        monkeypatch.setattr(h.journal, "read_transaction", forbidden)
        assert tuple(fresh.outcome(result.submission_sha256) for result in h.results) == h.results


@pytest.mark.parametrize(
    "damage",
    ["missing_intent", "missing_certificate", "conflict", "binding", "changed_certificate"],
)
async def test_changed_local_completion_cannot_seed_a_receipt(completed, damage):
    h = completed
    result = h.results[0]
    key = digest(result)
    with h.journal.transaction() as db:
        if damage == "missing_intent":
            db.execute(
                "DELETE FROM records WHERE kind='closed_quality_collect_intent' AND id=?", (key,)
            )
        elif damage == "missing_certificate":
            db.execute(
                "DELETE FROM records WHERE kind='closed_quality_certificate' AND id=?", (key,)
            )
        elif damage == "conflict":
            db.execute("INSERT INTO holds VALUES (?)", (key,))
        elif damage == "binding":
            db.execute("UPDATE binding SET body=?", (canonical_json_bytes({"other": "owner"}),))
        else:
            raw = db.execute(
                "SELECT body FROM records WHERE kind='closed_quality_certificate' AND id=?", (key,)
            ).fetchone()[0]
            certificate = json.loads(raw)
            certificate["result"]["hotkey"] = "0" * 64
            db.execute(
                "UPDATE records SET body=? WHERE kind='closed_quality_certificate' AND id=?",
                (canonical_json_bytes(certificate), key),
            )
    with (
        h.native.selected(),
        retained_quality_migration(h.journal, h.binding, verification_reuse=h.native),
    ):
        fresh = reviewer(h.b, objects=h.reopen().collector(MAXIMUM))
        with pytest.raises((ValueError, VerificationReceiptUnavailable)):
            fresh.outcome(result.submission_sha256)
    assert not outcome_receipts(h.native.directory)


async def test_remote_certificate_without_local_success_is_not_migration_authority(
    completed, monkeypatch
):
    h = completed
    result = h.results[0]
    with h.journal.transaction() as db:
        db.execute(
            "DELETE FROM records WHERE kind IN "
            "('closed_quality_collect_intent','closed_quality_certificate') AND id=?",
            (digest(result),),
        )

    # Ordinary first native work may still score; it may not borrow the remote
    # certificate as an independently completed local calculation.
    def first_work(*args, **kwargs):
        raise RuntimeError("genuine first local scoring")

    monkeypatch.setattr(quality, "quality_totals", first_work)
    with (
        h.native.selected(),
        retained_quality_migration(h.journal, h.binding, verification_reuse=h.native),
    ):
        fresh = reviewer(h.b, objects=h.reopen().collector(MAXIMUM))
        with pytest.raises(RuntimeError, match="genuine first local scoring"):
            fresh.outcome(result.submission_sha256)
    with (
        h.native.selected(),
        retained_quality_migration(
            h.journal, h.binding, verification_reuse=h.native, require_completed=True
        ),
    ):
        fresh = reviewer(h.b, objects=h.reopen().collector(MAXIMUM))
        with pytest.raises(
            VerificationReceiptUnavailable, match="successful local outcome unavailable"
        ):
            fresh.outcome(result.submission_sha256)
    assert not outcome_receipts(h.native.directory)


async def test_missing_existing_execution_receipt_never_replays_proofs(completed):
    h = completed
    removed = []
    for path, raw in h.old_receipts.items():
        value = json.loads(json.loads(raw)["result_json"])
        if isinstance(value, dict) and set(value) == {"candidate", "incumbent"}:
            path.unlink()
            removed.append(path)
    assert removed
    with (
        h.native.selected(),
        retained_quality_migration(h.journal, h.binding, verification_reuse=h.native),
    ):
        fresh = reviewer(h.b, objects=h.reopen().collector(MAXIMUM))
        with pytest.raises(VerificationReceiptUnavailable):
            fresh.outcome(h.results[0].submission_sha256)
    assert not outcome_receipts(h.native.directory)


async def test_conflict_added_during_dependency_checks_refuses_before_receipt_publication(
    completed, monkeypatch
):
    h = completed
    result = h.results[0]
    source = h.reopen().collector(MAXIMUM)
    native_replay = source.verification_replay
    changed = False
    with (
        h.native.selected(),
        retained_quality_migration(h.journal, h.binding, verification_reuse=h.native),
    ):
        fresh = reviewer(h.b, objects=source)

        def conflict(key):
            nonlocal changed
            native_replay(key)
            if not changed:
                changed = True
                with h.journal.transaction() as db:
                    db.execute("INSERT INTO holds VALUES (?)", (digest(result),))

        monkeypatch.setattr(source, "verification_replay", conflict)
        with pytest.raises(ValueError, match="conflict"):
            fresh.outcome(result.submission_sha256)
    assert changed and not outcome_receipts(h.native.directory)
