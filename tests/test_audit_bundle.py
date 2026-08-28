from __future__ import annotations

import json
from pathlib import Path

import pytest

from umi.audit_bundle import (
    SHADOW_INCIDENT_TERMINAL,
    STAGE_IDS,
    BundleObjectInput,
    StageInput,
    verify_audit_bundle,
    write_audit_bundle,
)
from umi.protocol import canonical_json_bytes


def stages_through(highest: int) -> tuple[StageInput, ...]:
    records = []
    for index, stage_id in enumerate(STAGE_IDS):
        if index <= highest:
            records.append(
                StageInput(
                    stage_id,
                    (BundleObjectInput(f"stage-{index}".encode(), "application/octet-stream"),),
                )
            )
        else:
            records.append(StageInput(stage_id, not_reached_reason="shadow_policy"))
    return tuple(records)


def test_bundle_round_trip_has_exact_size_and_stage_prefix(tmp_path: Path) -> None:
    root = tmp_path / "bundle"
    path = write_audit_bundle(
        root,
        scoring_policy_hash="11" * 32,
        software_revisions={"umi": "abc", "python": "3.14"},
        window_id="22" * 32,
        terminal_classification="shadow_rehearsal_no_weight",
        audit_release_block=0,
        reason_codes=["shadow_policy", "shadow_policy"],
        stages=stages_through(5),
    )

    manifest = verify_audit_bundle(root)
    assert path == root / "manifest.json"
    assert manifest.highest_stage == "weight_build"
    assert manifest.stages[-1].reason_code == "shadow_policy"
    assert manifest.reason_codes == ["shadow_policy"]
    assert manifest.audit_bundle_bytes == path.stat().st_size + sum(
        item.size_bytes for item in manifest.objects
    )


def test_bundle_rejects_noncontiguous_stages_duplicate_objects_and_cap(tmp_path: Path) -> None:
    noncontiguous = list(stages_through(2))
    noncontiguous[1] = StageInput(STAGE_IDS[1], not_reached_reason="failed")
    with pytest.raises(ValueError, match="after a skipped"):
        write_audit_bundle(
            tmp_path / "noncontiguous",
            scoring_policy_hash="11" * 32,
            software_revisions={"umi": "abc"},
            window_id="22" * 32,
            terminal_classification="shadow_rehearsal_no_weight",
            audit_release_block=0,
            reason_codes=["failed", "shadow_policy"],
            stages=noncontiguous,
        )

    duplicate = list(stages_through(1))
    shared = BundleObjectInput(b"same", "application/octet-stream")
    duplicate[0] = StageInput(STAGE_IDS[0], (shared,))
    duplicate[1] = StageInput(STAGE_IDS[1], (shared,))
    with pytest.raises(ValueError, match="more than one stage"):
        write_audit_bundle(
            tmp_path / "duplicate",
            scoring_policy_hash="11" * 32,
            software_revisions={"umi": "abc"},
            window_id="22" * 32,
            terminal_classification="shadow_rehearsal_no_weight",
            audit_release_block=0,
            reason_codes=["shadow_policy"],
            stages=duplicate,
        )

    with pytest.raises(ValueError, match="byte ceiling"):
        write_audit_bundle(
            tmp_path / "small",
            scoring_policy_hash="11" * 32,
            software_revisions={"umi": "abc"},
            window_id="22" * 32,
            terminal_classification="shadow_rehearsal_no_weight",
            audit_release_block=0,
            reason_codes=["shadow_policy"],
            stages=stages_through(0),
            maximum_bundle_bytes=8,
        )


def test_bundle_verifier_detects_object_and_accounting_tampering(tmp_path: Path) -> None:
    root = tmp_path / "bundle"
    path = write_audit_bundle(
        root,
        scoring_policy_hash="11" * 32,
        software_revisions={"umi": "abc"},
        window_id="22" * 32,
        terminal_classification="shadow_rehearsal_no_weight",
        audit_release_block=0,
        reason_codes=["shadow_policy"],
        stages=stages_through(0),
    )
    manifest = json.loads(path.read_bytes())
    object_path = root / "objects" / manifest["objects"][0]["sha256"]
    object_path.write_bytes(b"tampered")
    with pytest.raises(ValueError, match=r"wrong byte length|SHA-256"):
        verify_audit_bundle(root)


def test_offline_bundle_cannot_claim_protocol_terminal_state(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="cannot claim"):
        write_audit_bundle(
            tmp_path / "claim",
            scoring_policy_hash="11" * 32,
            software_revisions={"umi": "abc"},
            window_id="22" * 32,
            terminal_classification="calibration_no_weight",
            audit_release_block=0,
            reason_codes=["shadow_policy"],
            stages=stages_through(5),
        )
    assert not (tmp_path / "claim").exists()

    all_reached = tuple(
        StageInput(
            stage_id,
            (BundleObjectInput(stage_id.encode(), "application/octet-stream"),),
        )
        for stage_id in STAGE_IDS
    )
    with pytest.raises(ValueError, match="cannot reach chain terminal"):
        write_audit_bundle(
            tmp_path / "terminal",
            scoring_policy_hash="11" * 32,
            software_revisions={"umi": "abc"},
            window_id="22" * 32,
            terminal_classification="shadow_rehearsal_no_weight",
            audit_release_block=0,
            reason_codes=[],
            stages=all_reached,
        )


def test_bundle_reason_table_must_match_not_reached_stages(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="equal the not-reached"):
        write_audit_bundle(
            tmp_path / "missing-reason",
            scoring_policy_hash="11" * 32,
            software_revisions={"umi": "abc"},
            window_id="22" * 32,
            terminal_classification="shadow_rehearsal_no_weight",
            audit_release_block=0,
            reason_codes=[],
            stages=stages_through(5),
        )

    root = tmp_path / "tampered-reason"
    path = write_audit_bundle(
        root,
        scoring_policy_hash="11" * 32,
        software_revisions={"umi": "abc"},
        window_id="22" * 32,
        terminal_classification="shadow_rehearsal_no_weight",
        audit_release_block=0,
        reason_codes=["shadow_policy"],
        stages=stages_through(5),
    )
    manifest = json.loads(path.read_bytes())
    manifest["reason_codes"] = ["extra", "shadow_policy"]
    path.write_bytes(canonical_json_bytes(manifest))
    with pytest.raises(ValueError, match="equal the not-reached"):
        verify_audit_bundle(root)


def test_void_rehearsal_cannot_reach_weight_build(tmp_path: Path) -> None:
    stages = list(stages_through(5))
    stages[-1] = StageInput(STAGE_IDS[-1], not_reached_reason="canary_hit")
    with pytest.raises(ValueError, match="void rehearsal cannot reach weight build"):
        write_audit_bundle(
            tmp_path / "invalid-void",
            scoring_policy_hash="11" * 32,
            software_revisions={"umi": "abc"},
            window_id="22" * 32,
            terminal_classification=SHADOW_INCIDENT_TERMINAL,
            audit_release_block=0,
            reason_codes=["canary_hit"],
            stages=stages,
        )


def test_bundle_verifier_rejects_a_symlinked_manifest(tmp_path: Path) -> None:
    root = tmp_path / "bundle-symlink"
    path = write_audit_bundle(
        root,
        scoring_policy_hash="11" * 32,
        software_revisions={"umi": "abc"},
        window_id="22" * 32,
        terminal_classification="shadow_rehearsal_no_weight",
        audit_release_block=0,
        reason_codes=["shadow_policy"],
        stages=stages_through(5),
    )
    target = tmp_path / "manifest-target.json"
    path.replace(target)
    path.symlink_to(target)
    with pytest.raises(ValueError, match="opened safely"):
        verify_audit_bundle(root)
