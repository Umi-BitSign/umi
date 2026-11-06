"""An operator timeout must retain its authority and fence incompatible journal writers."""

import pytest

from umi.competition_cohort_admission_deadline import OperatorAdmissionDeadline
from umi.competition_cohort_direct_model_attempts import (
    DirectModelAttemptJournal,
    DirectModelAttemptRepairRequired,
    DirectModelMetadataCapacityPending,
)
from umi.competition_cohort_upload_completion_policy import OperatorUploadCompletionPolicy
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_direct_model_attempts import BINDING, native_legacy, records


def policy():
    return OperatorUploadCompletionPolicy(
        schema="umi-operator-upload-completion-policy/1",
        admission_deadline=OperatorAdmissionDeadline(
            schema="umi-cohort-operator-admission-deadline/1",
            cohort_sha256=BINDING["cohort_sha256"],
            authority_sha256="11" * 32,
            authorized_history_tip_sha256="12" * 32,
            close_new_admissions_at_unix_ms=1_800_000_000_000,
            source_sha256="13" * 32,
            operator_plan_sha256="14" * 32,
            reason="Operator selected intake cutoff",
        ),
        grace_seconds=1800,
        source_sha256="15" * 32,
        operator_plan_sha256="16" * 32,
        reason="Operator selected upload completion grace",
    )


def open_owner(root, selected=None, **kwargs):
    return DirectModelAttemptJournal(
        root,
        BINDING,
        maximum_uploads=1,
        maximum_bytes=1024**2,
        completion_policy=selected,
        **kwargs,
    )


def test_policy_selection_is_disabled_by_default_and_preserves_original_records(tmp_path):
    root = native_legacy(tmp_path / "journal").root
    old = open_owner(root)
    original = records(old)
    assert old._journal_version() == 6
    selected = policy()
    new = open_owner(root, selected)
    assert records(new) == original and new._journal_version() == 6
    new.activate_completion_policy()
    assert new._journal_version() == 7
    after = records(new)
    assert [row for row in after if row[0] != "direct-completion-policy"] == original
    assert [row[2] for row in after if row[0] == "direct-completion-policy"] == [
        canonical_json_bytes(selected)
    ]
    with pytest.raises(DirectModelAttemptRepairRequired, match="must be selected"):
        old.get("direct-request", original[0][1])
    with pytest.raises(DirectModelAttemptRepairRequired, match="must be selected"):
        open_owner(root)
    reopened = open_owner(root, selected)
    reopened.activate_completion_policy()
    assert records(reopened) == after
    repaired = open_owner(root, selected, repair_attempt_index=True)
    assert repaired._journal_version() == 7 and records(repaired) == after


def test_selected_policy_cannot_be_replaced_on_restart(tmp_path):
    root = native_legacy(tmp_path / "journal").root
    selected = policy()
    owner = open_owner(root, selected)
    owner.activate_completion_policy()
    original = records(owner)
    changed = selected.model_copy(update={"grace_seconds": 3600})
    with pytest.raises(DirectModelAttemptRepairRequired, match="marker needs repair"):
        open_owner(root, changed)
    assert records(owner) == original


@pytest.mark.parametrize("damage", ["missing_policy", "missing_marker", "downgraded"])
def test_damaged_policy_cannot_be_silently_recreated(tmp_path, damage):
    root = native_legacy(tmp_path / "journal").root
    selected = policy()
    owner = open_owner(root, selected)
    owner.activate_completion_policy()
    with owner.transaction() as db:
        if damage == "missing_policy":
            db.execute("DELETE FROM records WHERE kind='direct-completion-policy'")
        elif damage == "missing_marker":
            db.execute("DROP TABLE round_generation_direct_completion_deadline")
        else:
            db.execute("PRAGMA user_version=6")
    with pytest.raises(DirectModelAttemptRepairRequired):
        open_owner(root, selected)


def test_policy_capacity_failure_does_not_fence_existing_owner(tmp_path, monkeypatch):
    root = native_legacy(tmp_path / "journal").root
    old = open_owner(root)
    owner = open_owner(root, policy())
    before = records(owner)
    monkeypatch.setattr(owner, "maximum_bytes", owner.metadata_snapshot()["metadata_bytes"])
    with pytest.raises(DirectModelMetadataCapacityPending):
        owner.activate_completion_policy()
    assert old._journal_version() == 6 and records(old) == before


def test_policy_keeps_original_deadline_and_requires_nonzero_decision():
    selected = policy()
    assert selected.close_completion_at_unix_ms == 1_800_001_800_000
    original = canonical_json_bytes(selected.admission_deadline)
    assert (
        canonical_json_bytes(
            OperatorUploadCompletionPolicy.model_validate_json(
                canonical_json_bytes(selected)
            ).admission_deadline
        )
        == original
    )
    for field in ("source_sha256", "operator_plan_sha256"):
        raw = selected.model_dump(mode="json", by_alias=True)
        raw[field] = "0" * 64
        with pytest.raises(ValueError, match="operator decision"):
            OperatorUploadCompletionPolicy.model_validate(raw)


def test_host_config_preserves_old_bytes_and_rejects_duplicate_policy(tmp_path):
    from umi.competition_cohort_model_static_review import StandingModelReviewPolicy
    from umi.competition_cohort_service_host import DirectModelUploadHostConfig

    from .test_open_competition import wallet

    review = StandingModelReviewPolicy(
        schema="umi-standing-model-artifact-review-policy/1",
        competition_policy_sha256="ab" * 32,
        contribution_terms_sha256="ac" * 32,
        standing_approval_record_sha256="ad" * 32,
        approved_by="operator@example.test",
        approved_at_utc="2026-10-01T00:00:00Z",
        complete_declared_bundle_rights_approved=True,
        licenses_and_notices_reviewed=True,
        public_redistribution_and_evaluation_approved=True,
    )
    config = DirectModelUploadHostConfig(
        schema="umi-direct-model-upload-host/1",
        directory=str(tmp_path / "uploads"),
        owner_hotkey=wallet("Charlie").hotkey.ss58_address,
        owner_key_file=str(tmp_path / "owner-key"),
        r2_credentials_file=str(tmp_path / "credentials"),
        r2_bucket="umi-model-artifacts",
        standing_review_policy=review,
    )
    raw = canonical_json_bytes(config)
    assert b"completion_policies" not in raw
    assert canonical_json_bytes(DirectModelUploadHostConfig.model_validate_json(raw)) == raw
    values = config.model_dump(mode="json", by_alias=True)
    values["completion_policies"] = [policy().model_dump(mode="json", by_alias=True)]
    selected = DirectModelUploadHostConfig.model_validate_json(canonical_json_bytes(values))
    assert selected.completion_policies == (policy(),)
    values["completion_policies"] *= 2
    with pytest.raises(ValueError, match="unique cohorts"):
        DirectModelUploadHostConfig.model_validate_json(canonical_json_bytes(values))
