"""Source compatibility must be explicit while unrelated releases preserve work."""

import hashlib
import json
from pathlib import Path

import pytest

from umi import competition_verification_rules as rules


def test_selected_dependency_manifest_is_complete_and_qualified():
    source = Path(rules.__file__).parent
    manifest = json.loads((source / "competition_verification_rules.json").read_bytes())
    assert (
        rules.verify_dependency_manifest(source, manifest)
        == hashlib.sha256(rules.VERIFICATION_SEMANTICS.encode()).hexdigest()
    )
    for module in (
        "competition_verification_reuse.py",
        "competition_reward_cutover.py",
        "competition_reward_history_preparation.py",
        "competition_reward_history_preparation_capacity.py",
        "competition_reward_history_preparation_service.py",
        "competition_reward_writer_broker.py",
        "competition_reward_writer_broker_worker.py",
        "competition_reward_writer_exchange.py",
        "competition_reward_writer_prefix.py",
        "competition_reward_writer_selection.py",
        "competition_reward_writer_review.py",
        "competition_reward_runtime_adoption.py",
        "competition_reward_runtime_review.py",
        "competition_reward_history_transfer.py",
        "competition_reward_history_transfer_owner.py",
        "competition_reward_history_transfer_runtime.py",
        "competition_reward_history_transfer_cli.py",
        "competition_reward_writer_resources.py",
        "competition_chain_resource_preflight.py",
        "historical_header_hint_import.py",
        "competition_cohort_request_closure.py",
        "competition_cohort_request_publication.py",
        "competition_cohort_publication_objects.py",
        "competition_cohort_lifecycle_host.py",
        "competition_cohort_execution_work.py",
        "competition_cohort_model_delivery_candidate.py",
        "competition_cohort_suite_adoption_candidate.py",
        "competition_suite_reference_qa.py",
        "competition_suite_selection.py",
        "competition_cohort_review_config.py",
        "competition_cohort_service_host.py",
        "competition_cohort_readiness_wake.py",
        "competition_cohort_model_batch_adoption_cli.py",
        "competition_cohort_model_batch_adoption_operator.py",
        "competition_cohort_model_batch_adoption_series.py",
        "competition_shared_file_bytes.py",
        "competition_model_byte_store.py",
        "competition_model_batch_progress.py",
        "competition_model_byte_store_cli.py",
        "competition_cohort_endpoint_archive.py",
        "competition_cohort_service_closure.py",
        "competition_cohort_endpoint_decision.py",
        "competition_cohort_service_terminal.py",
        "competition_cohort_model_upload_delivery.py",
        "competition_cohort_model_upload_replay.py",
        "competition_cohort_direct_model_owner.py",
        "competition_cohort_direct_model_attempts.py",
        "competition_cohort_direct_model_selection.py",
        "competition_cohort_participation_delivery.py",
        "competition_cohort_reserved_participation.py",
        "competition_remote_model_verification.py",
        "r2_connection_pool.py",
        "r2_multipart.py",
        "endpoint_response_recovery.py",
        "open_competition.py",
        "protocol.py",
    ):
        assert module in manifest["sources"]


def test_unrelated_change_preserves_receipts_but_verifier_change_requires_qualification(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(rules, "distribution_version", lambda _: "1.0")
    native = tmp_path / "native.py"
    native.write_bytes(b"original native rule")
    manifest = {
        "schema": "umi-native-verification-dependencies/1",
        "abi": rules.VERIFICATION_SEMANTICS,
        "extensions": rules.VERIFICATION_EXTENSIONS,
        "compatibility_basis": "qualified native fixture parity",
        "sources": {native.name: hashlib.sha256(native.read_bytes()).hexdigest()},
        "external_distributions": {"native-library": ["1.0"]},
    }
    original = rules.verify_dependency_manifest(tmp_path, manifest)
    (tmp_path / "unrelated.py").write_bytes(b"unrelated release")
    assert rules.verify_dependency_manifest(tmp_path, manifest) == original
    native.write_bytes(b"unreviewed native rule")
    with pytest.raises(RuntimeError, match="without qualified ABI compatibility"):
        rules.verify_dependency_manifest(tmp_path, manifest)
    # A reviewed compatible change may retain its ABI; changed accepted semantics
    # require changing the ABI in code and this manifest together.
    manifest["sources"][native.name] = hashlib.sha256(native.read_bytes()).hexdigest()
    assert rules.verify_dependency_manifest(tmp_path, manifest) == original
    manifest["abi"] = "incompatible"
    with pytest.raises(RuntimeError, match="qualified dependency manifest"):
        rules.verify_dependency_manifest(tmp_path, manifest)


def test_external_version_drift_requires_qualification_without_discarding_completed_abi(
    tmp_path, monkeypatch
):
    native = tmp_path / "native.py"
    native.write_bytes(b"same native semantics")
    manifest = {
        "schema": "umi-native-verification-dependencies/1",
        "abi": rules.VERIFICATION_SEMANTICS,
        "extensions": rules.VERIFICATION_EXTENSIONS,
        "compatibility_basis": "qualified native fixture parity",
        "sources": {native.name: hashlib.sha256(native.read_bytes()).hexdigest()},
        "external_distributions": {"native-library": ["1.0"]},
    }
    monkeypatch.setattr(rules, "distribution_version", lambda _: "1.0")
    original = rules.verify_dependency_manifest(tmp_path, manifest)
    monkeypatch.setattr(rules, "distribution_version", lambda _: "2.0")
    with pytest.raises(RuntimeError, match="external dependency changed without qualified"):
        rules.verify_dependency_manifest(tmp_path, manifest)
    # A separately reviewed compatible library version retains completed work.
    manifest["external_distributions"]["native-library"].append("2.0")
    assert rules.verify_dependency_manifest(tmp_path, manifest) == original

    def unavailable(name):
        raise rules.PackageNotFoundError(name)

    monkeypatch.setattr(rules, "distribution_version", unavailable)
    with pytest.raises(RuntimeError, match="dependency is unavailable"):
        rules.verify_dependency_manifest(tmp_path, manifest)


def test_additive_shared_incumbent_semantics_are_guarded_without_invalidating_legacy_receipts():
    source = Path(rules.__file__).parent
    manifest = json.loads((source / "competition_verification_rules.json").read_bytes())
    assert (
        rules.verify_dependency_manifest(source, manifest)
        == hashlib.sha256(b"umi-native-request-verification/1").hexdigest()
    )
    manifest["extensions"] = {}
    with pytest.raises(RuntimeError, match="qualified dependency manifest"):
        rules.verify_dependency_manifest(source, manifest)
