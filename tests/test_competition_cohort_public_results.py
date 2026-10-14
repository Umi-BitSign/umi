"""Public output uses native retained identities without opening source payloads."""

import hashlib
import os
from fractions import Fraction
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from umi.competition_cohort_direct_model_upload import DirectModelPayload
from umi.competition_cohort_public_api import (
    CohortPublicApiConfig,
    create_cohort_public_app,
    publish_cohort,
)
from umi.competition_cohort_public_downloads import PublicModelDownload, legacy_download
from umi.competition_cohort_public_publisher import PinnedPublicMetadata
from umi.competition_cohort_public_results import (
    PublicModelCatalog,
    PublicModelEntry,
    PublicModelInventory,
    project_models,
    project_paid_results,
)
from umi.competition_cohort_service_allocation import allocate_service_quality
from umi.competition_cohort_service_certification import (
    CertifiedServiceAllocation,
    ServiceAllocationStatement,
)
from umi.competition_cohort_service_quality import ClosedServiceQuality
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes
from umi.r2_sigv4 import R2Credentials, R2SigV4

from .test_competition_cohort_model_award import base_policy as base_policy
from .test_competition_cohort_model_award import legacy_scenario as legacy_scenario
from .test_competition_cohort_model_award import model_case as model_case
from .test_competition_cohort_model_award import policy as policy
from .test_competition_cohort_model_award import receipt_scenario as receipt_scenario
from .test_competition_cohort_model_award import recovery as recovery
from .test_competition_cohort_model_award import runtime as runtime
from .test_competition_cohort_recovery import signatures
from .test_competition_cohort_service_allocation import terms, work
from .test_open_competition import bundle_at, wallet


@pytest.mark.parametrize("receipt_scenario", ["model-awards"], indirect=True)
@pytest.mark.parametrize("model_case", [("equal", 2)], indirect=True)
def test_certified_paid_projection_preserves_zero_rows_and_original_uid(model_case):
    b, _, _, _, _ = model_case
    roster, policy = b["roster"], b["policy"]
    hotkey = roster.participants[0].record.request.signed_submission.submission.hotkey
    selected_terms = terms(policy_sha256=digest(policy))
    quality = ClosedServiceQuality(
        schema="umi-cohort-service-quality/2",
        terms_sha256=digest(selected_terms),
        request_closure_sha256="ab" * 32,
        reference_reveal_sha256="cd" * 32,
        work=(work(1, hotkey, Fraction(1, 2)),),
        skipped_work=("ff" * 32,),
    )
    statement = ServiceAllocationStatement(
        schema="umi-cohort-service-allocation-statement/1",
        policy_sha256=digest(policy),
        round_sha256=digest(roster.round),
        allocation=allocate_service_quality(quality, selected_terms),
    )
    certificate = CertifiedServiceAllocation(
        schema="umi-cohort-certified-service-allocation/1",
        statement=statement,
        signatures=signatures(statement),
    )
    result = project_paid_results(quality, selected_terms, certificate, roster, policy)
    assert len(result.items) == 2
    assert sum(r.paid_completed for r in result.items) == 1
    assert result.skipped_unassigned_work == 1
    assert result.reward_activation == "not_verified_live"
    assert "reference_sha256" not in canonical_json_bytes(result).decode()
    for row in result.items:
        retained = next(
            p
            for p in roster.participants
            if p.record.request.signed_submission.submission.hotkey == row.hotkey
        )
        assert row.uid == retained.admission.admission.uid
    with pytest.raises(ValueError, match="certified allocation"):
        project_paid_results(
            quality.model_copy(update={"work": ()}), selected_terms, certificate, roster, policy
        )


@pytest.mark.parametrize("receipt_scenario", ["model-awards"], indirect=True)
def test_model_projection_requires_original_terms_and_artifact_acceptance(model_case, monkeypatch):
    b, _, _, accepted, _ = model_case
    inventory = PublicModelInventory(
        schema="umi-native-public-model-inventory/1",
        scope="all_admitted_model_submissions",
        policy=b["policy"],
        history=b["history"],
        participants=b["roster"].participants,
        acceptances=accepted,
    )
    catalog, bundles = project_models(inventory)
    assert catalog.items[0].release == "terms_review_required" and not bundles
    monkeypatch.setattr(
        "umi.competition_cohort_public_results.PUBLIC_RELEASE_TERMS",
        {b["policy"].contribution_terms_sha256},
    )
    catalog, bundles = project_models(inventory)
    assert catalog.items[0].release == "public_release_authorized" and bundles
    pending, bundles = project_models(inventory.model_copy(update={"acceptances": ()}))
    assert pending.items[0].release == "artifact_acceptance_pending" and not bundles
    assert "rights_evidence" not in canonical_json_bytes(catalog).decode()
    with pytest.raises(ValueError, match="repeats"):
        project_models(inventory.model_copy(update={"participants": inventory.participants * 2}))


@pytest.fixture
def public_case(tmp_path):
    bundle = bundle_at(tmp_path / "files")
    model, cohort = digest(bundle), "12" * 32
    entry = PublicModelEntry(
        submission_sha256="34" * 32,
        model_sha256=model,
        uid=7,
        hotkey=wallet("Alice").hotkey.ss58_address,
        accepted_terms_sha256="56" * 32,
        license_id=bundle.license_id,
        file_count=len(bundle.files),
        total_bytes=sum(f.size_bytes for f in bundle.files),
        release="public_release_authorized",
        acceptance_sha256="78" * 32,
    )
    catalog = PublicModelCatalog(
        schema="umi-public-cohort-models/1",
        cohort_sha256=cohort,
        policy_sha256="90" * 32,
        inventory_sha256="ab" * 32,
        inventory_scope="all_admitted_model_submissions",
        items=(entry,),
    )
    payload = DirectModelPayload(
        schema="umi-direct-model-payload/1",
        upload_sha256="cd" * 32,
        model_sha256=model,
        payload_sha256="ef" * 32,
        total_bytes=entry.total_bytes,
        file_count=entry.file_count,
        part_size_bytes=5 * 1024**2,
        total_parts=1,
    )
    download = PublicModelDownload(
        schema="umi-public-model-download/1",
        cohort_sha256=cohort,
        model_sha256=model,
        bundle=bundle,
        format="concatenated_payload",
        payload=payload,
    )
    config = CohortPublicApiConfig(results={"directory": str(tmp_path / "published")})
    signer = R2SigV4(
        "https://" + "a" * 32 + ".r2.cloudflarestorage.com",
        "umi-model-artifacts",
        R2Credentials("b" * 32, "c" * 32),
    )
    return config, catalog, download, signer


def test_routes_restart_ranges_renewable_get_and_no_arbitrary_key(public_case):
    config, catalog, download, signer = public_case
    publish_cohort(config, catalog, None, (download,))
    prefix = f"/v1/competition/cohorts/{catalog.cohort_sha256}"
    for _ in range(2):
        with TestClient(create_cohort_public_app(config, signer=signer)) as client:
            listed = client.get(prefix + "/models").json()
            assert listed["total"] == 1 and listed["items"][0]["download_available"]
            response = client.get(listed["items"][0]["download_url"])
            assert response.status_code == 200, response.text
            d = response.json()
            assert d["method"] == "GET" and "preservation/v1/" in d["payload"]["url"]
            assert "incoming/" not in response.text and "secret" not in response.text
            files = client.get(d["files_url"], params={"file_index": 1}).json()
            assert (
                files["segments"]["items"][0]["range_start"] == download.bundle.files[0].size_bytes
            )
            assert client.post(listed["items"][0]["download_url"]).status_code == 405
            assert client.get(prefix + "/models/" + "f" * 64 + "/download").status_code == 404
            assert client.get(prefix + "/service-results").status_code == 404
            assert client.get(prefix + "/models", params={"limit": 101}).status_code == 422
    # Renewable requests generate a fresh capability rather than persisting URLs.
    assert b"X-Amz" not in b"".join(
        p.read_bytes() for p in Path(config.results.directory).glob("artifacts/*")
    )


def test_publication_failure_keeps_previous_descriptor_and_repairs_identical_missing_artifact(
    public_case,
):
    config, catalog, download, signer = public_case
    first = publish_cohort(config, catalog, None, (download,))

    path = (
        Path(config.results.directory)
        / "artifacts"
        / (first.downloads[download.model_sha256] + ".json")
    )
    path.unlink()
    with TestClient(create_cohort_public_app(config, signer=signer)) as client:
        url = (
            f"/v1/competition/cohorts/{catalog.cohort_sha256}/models/"
            f"{download.model_sha256}/download"
        )
        assert client.get(url).status_code == 503
    assert publish_cohort(config, catalog, None, (download,)) == first
    descriptor_path = Path(config.results.directory) / "cohorts" / (catalog.cohort_sha256 + ".json")
    descriptor_path.unlink()
    with TestClient(create_cohort_public_app(config, signer=signer)) as client:
        assert (
            client.get(f"/v1/competition/cohorts/{catalog.cohort_sha256}/models").status_code == 503
        )
    with pytest.raises(ValueError, match="discard admitted history"):
        publish_cohort(config, catalog.model_copy(update={"items": ()}), None, ())
    with pytest.raises(ValueError, match="completed public model transport missing"):
        publish_cohort(config, catalog, None, ())
    assert publish_cohort(config, catalog, None, (download,)) == first
    catalog_path = Path(config.results.directory) / "artifacts" / (first.catalog_sha256 + ".json")
    catalog_path.unlink()
    assert publish_cohort(config, catalog, None, (download,)) == first
    with pytest.raises(ValueError, match="discard admitted history"):
        publish_cohort(config, catalog.model_copy(update={"items": ()}), None, (download,))
    assert path.exists()
    path.write_bytes(b"{}")
    path.chmod(0o600)
    with pytest.raises(ValueError, match="conflicts"):
        publish_cohort(config, catalog, None, (download,))


def test_publication_checkpoint_interruption_and_corruption_are_explicit(public_case):
    config, catalog, download, signer = public_case
    first = publish_cohort(config, catalog, None, (download,))
    root = Path(config.results.directory)
    descriptor_path = root / "cohorts" / (catalog.cohort_sha256 + ".json")
    # Interrupted publication may leave the mutable descriptor from an older
    # publication. The immutable checkpoint owns the monotonic inventory.
    descriptor_path.write_bytes(b"{}")
    with TestClient(create_cohort_public_app(config, signer=signer)) as client:
        assert (
            client.get(f"/v1/competition/cohorts/{catalog.cohort_sha256}/models").status_code == 503
        )
    assert publish_cohort(config, catalog, None, (download,)) == first
    checkpoint_path = root / "cohorts" / (catalog.cohort_sha256 + ".published")
    checkpoint_sha256 = checkpoint_path.read_text()
    retained_descriptor = root / "artifacts" / (checkpoint_sha256 + ".json")
    descriptor_backup = retained_descriptor.read_bytes()
    retained_descriptor.unlink()
    with pytest.raises(ValueError, match="checkpoint descriptor missing"):
        publish_cohort(config, catalog.model_copy(update={"items": ()}), None, ())
    with TestClient(create_cohort_public_app(config, signer=signer)) as client:
        assert (
            client.get(f"/v1/competition/cohorts/{catalog.cohort_sha256}/models").status_code == 503
        )
    assert hashlib.sha256(descriptor_backup).hexdigest() == checkpoint_sha256
    retained_descriptor.write_bytes(descriptor_backup)
    retained_descriptor.chmod(0o600)
    assert publish_cohort(config, catalog, None, (download,)) == first
    with TestClient(create_cohort_public_app(config, signer=signer)) as client:
        assert (
            client.get(f"/v1/competition/cohorts/{catalog.cohort_sha256}/models").status_code == 200
        )
    checkpoint_path.write_bytes(b"invalid")
    with pytest.raises(ValueError, match="invalid descriptor digest"):
        publish_cohort(config, catalog, None, (download,))


def test_legacy_chunk_metadata_binds_complete_native_files(public_case):
    _, catalog, download, _ = public_case
    bundle = download.bundle
    files = [
        {
            "path": f.path,
            "chunks": []
            if not f.size_bytes
            else [{"sha256": f.sha256, "size_bytes": f.size_bytes}],
        }
        for f in bundle.files
    ]
    package = {
        "schema": "umi-cohort-model-preserved-package/1",
        "model_sha256": digest(bundle),
        "native_bundle": bundle.model_dump(mode="json", by_alias=True),
        "files": files,
        "chunk_bytes": 8 * 1024**2,
    }
    raw = canonical_json_bytes(package)
    sha = hashlib.sha256(raw).hexdigest()
    association = {
        "schema": "umi-cohort-model-backup-association/1",
        "model_sha256": digest(bundle),
        "package_sha256": sha,
        "package_key": f"packages/{digest(bundle)}/{sha}.json",
        "verification": "all_declared_bytes_uploaded_and_read_back",
        "artifact_acceptance_certified": False,
    }
    checked = legacy_download(catalog.cohort_sha256, bundle, association, raw)
    assert checked.chunk_key(0, 0).startswith("preservation/v1/chunks/sha256/")
    with pytest.raises(ValueError, match="association"):
        legacy_download(
            catalog.cohort_sha256, bundle, {**association, "package_key": "private/secret"}, raw
        )
    with pytest.raises(ValueError):
        checked.model_validate_json(
            canonical_json_bytes(checked.model_copy(update={"files": checked.files[:-1]}))
        )


def test_pinned_metadata_rejects_replacement_links_and_changes(tmp_path):
    path = tmp_path / "metadata.json"
    path.write_bytes(b"{}")
    path.chmod(0o600)
    pin = PinnedPublicMetadata(
        path=str(path),
        sha256=hashlib.sha256(b"{}").hexdigest(),
        size_bytes=2,
        owner_uid=os.getuid(),
    )
    assert pin.read() == b"{}"
    path.write_bytes(b"[]")
    with pytest.raises(ValueError, match="changed"):
        pin.read()
    target = tmp_path / "target"
    path.rename(target)
    path.symlink_to(target)
    with pytest.raises(ValueError, match="symlinks"):
        pin.read()
