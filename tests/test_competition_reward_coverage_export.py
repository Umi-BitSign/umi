"""Transport tests use isolated completion fixtures, never production authority."""

from types import SimpleNamespace

import pytest

from umi import competition_reward_coverage_checkpoint as checkpoint_module
from umi import competition_reward_proof_archive as archive_module
from umi.competition_evidence_codec import encode_evidence
from umi.competition_reward_coverage_checkpoint import CoverageCheckpointRepairRequired
from umi.competition_reward_coverage_export import export_completed_endpoint
from umi.competition_reward_coverage_journal import _FIELDS, RewardCoverageJournal
from umi.competition_reward_proof_archive import RewardProofArchive
from umi.open_competition import digest, identity

from .test_competition_reward_coverage_intervals import point, rule

HOTKEY = "5FLKx6h7DwWRuqq1dcfQafsBw5i9cbchNEFAEHrqSRthGnDZ"


@pytest.fixture
def completed(tmp_path, monkeypatch):
    return completed_case(tmp_path, monkeypatch)


def completed_case(tmp_path, monkeypatch, *, proof_repeats=4096):
    monkeypatch.setattr(checkpoint_module, "runtime_identity", lambda: "aa" * 32)
    monkeypatch.setattr(checkpoint_module, "coverage_point", lambda endpoint, _: endpoint.point)
    monkeypatch.setattr(archive_module, "_publication_clock_ns", lambda: 2**63 - 1)
    selected = rule()
    journal = RewardCoverageJournal(
        tmp_path / "source", selected, expected_rule_sha256=digest(selected)
    )
    p = point(validator_account_id=identity(HOTKEY))
    endpoint = SimpleNamespace(
        point=p,
        prepared=SimpleNamespace(
            activation=SimpleNamespace(package_sha256="11" * 32, cohort_sha256="22" * 32),
            requirement_sha256="33" * 32,
        ),
        eligibility=SimpleNamespace(policy_sha256="44" * 32),
    )
    fields = {
        "control": b'{"proof":"' + b"ab" * proof_repeats + b'"}',
        "metadata": b'{"abi":"' + b"ab" * 4096 + b'"}',
        "chain": b"chain-original",
        "eligibility": b"eligibility-original",
    }
    refs, records = {}, []
    for name, raw in fields.items():
        encoded = encode_evidence(raw, kind=_FIELDS[name])
        records.extend(
            ("coverage_object", sha, {"hex": data.hex()}) for sha, data in encoded.objects.items()
        )
        records.append(
            (
                "coverage_blob_" + _FIELDS[name],
                encoded.sha256,
                {"length": len(raw), "recipe_hex": encoded.recipe.hex()},
            )
        )
        refs[name] = encoded.sha256
    frame = {
        "point": p.model_dump(mode="json"),
        "package": "11" * 32,
        "validator_hotkey": HOTKEY,
        "blobs": refs,
    }
    records.append(("coverage_endpoint", p.key(), frame))
    journal.journal.put_many(records)
    journal.checkpoints.remember(endpoint, [(kind, sha) for kind, sha, _ in records])
    archive = RewardProofArchive(tmp_path / "destination")
    journal.export_archive = archive
    return SimpleNamespace(
        journal=journal, archive=archive, fields=fields, key=p.key(), rule=selected
    )


def forbidden(*args, **kwargs):
    pytest.fail("compact export must not expand/re-encode completed endpoint evidence")


def test_first_repeat_and_journal_restart_use_existing_native_completion(completed, monkeypatch):
    c = completed
    monkeypatch.setattr(c.journal, "_load", forbidden)
    c.journal._export(c.key, c.archive)
    context, fields = c.archive.read(
        "endpoint", c.key, bounds={name: len(raw) for name, raw in c.fields.items()}
    )
    assert fields == c.fields and context["validator_hotkey"] == HOTKEY
    original = c.journal.externalized.get

    def metadata_only(kind, key, *, db):
        if kind == "coverage_object":
            forbidden()
        return original(kind, key, db=db)

    monkeypatch.setattr(c.journal.externalized, "get", metadata_only)
    c.journal._export(c.key, c.archive)
    fresh = RewardCoverageJournal(
        c.journal.journal.root, c.rule, expected_rule_sha256=digest(c.rule)
    )
    monkeypatch.setattr(fresh, "_load", forbidden)
    original = fresh.externalized.get
    monkeypatch.setattr(fresh.externalized, "get", metadata_only)
    fresh._export(c.key, c.archive)
    assert fresh.checkpoints.load(c.key) == c.journal.checkpoints.load(c.key)


def test_existing_other_encoding_preserves_original_fallback_and_bytes(completed, monkeypatch):
    c = completed
    p = point(validator_account_id=identity(HOTKEY))
    c.archive.write(
        "endpoint",
        c.key,
        context={
            "point": p.model_dump(mode="json"),
            "package": "11" * 32,
            "validator_hotkey": HOTKEY,
        },
        fields=c.fields,
    )
    before = {p.relative_to(c.archive.root): p.read_bytes() for p in c.archive.root.rglob("*.json")}
    assert not export_completed_endpoint(c.journal, c.key, c.archive, field_kinds=_FIELDS)
    c.journal._export(c.key, c.archive)
    assert before == {
        p.relative_to(c.archive.root): p.read_bytes() for p in c.archive.root.rglob("*.json")
    }


@pytest.mark.parametrize("change", ["source", "ledger", "held"])
def test_lost_changed_or_held_native_completion_refuses_before_transfer(
    completed, monkeypatch, change
):
    c = completed
    with c.journal.journal.transaction() as db:
        if change == "source":
            db.execute("UPDATE records SET body='{}' WHERE kind='coverage_endpoint'")
        elif change == "ledger":
            db.execute("DELETE FROM coverage_checkpoint_index")
        else:
            db.execute("INSERT INTO holds VALUES (?)", (c.key,))
    monkeypatch.setattr(c.archive, "copy_encoded_transport", forbidden)
    with pytest.raises((CoverageCheckpointRepairRequired, ValueError)):
        c.journal._export(c.key, c.archive)


def test_source_change_after_transfer_cannot_borrow_old_native_completion(completed, monkeypatch):
    c = completed
    load, calls = c.journal.checkpoints.load, []

    def changed(key):
        calls.append(key)
        if len(calls) == 2:
            assert c.archive._path("endpoint", c.key).exists()
            with c.journal.journal.transaction() as db:
                db.execute("UPDATE records SET body='{}' WHERE kind='coverage_endpoint'")
        return load(key)

    monkeypatch.setattr(c.journal.checkpoints, "load", changed)
    with pytest.raises(CoverageCheckpointRepairRequired):
        c.journal._export(c.key, c.archive)


def test_interrupted_transfer_has_no_frame_and_resumes_without_native_replay(
    completed, monkeypatch
):
    c = completed
    publish = c.archive._publish_bytes
    attempts = []

    def interrupted(path, raw):
        attempts.append(path)
        if len(attempts) == 2:
            raise OSError("interrupted transfer")
        return publish(path, raw)

    monkeypatch.setattr(c.archive, "_publish_bytes", interrupted)
    with pytest.raises(OSError, match="interrupted"):
        c.journal._export(c.key, c.archive)
    assert not c.archive._path("endpoint", c.key).exists()
    monkeypatch.setattr(c.archive, "_publish_bytes", publish)
    monkeypatch.setattr(c.journal, "_load", forbidden)
    c.journal._export(c.key, c.archive)
    assert (
        c.archive.read(
            "endpoint", c.key, bounds={name: len(raw) for name, raw in c.fields.items()}
        )[1]
        == c.fields
    )
