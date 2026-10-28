"""Optional license discovery publishes during intake and reuses checked metadata."""

import hashlib
import json
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from umi import competition_cohort_public_licenses as module
from umi.competition_cohort_public_api import create_cohort_public_app
from umi.competition_cohort_public_catalog_watch import (
    NativePublicCatalogWatchConfig,
    NativePublicCatalogWatcher,
)
from umi.competition_cohort_recovery import (
    SignedCohortRecoveryAuthority,
    admit_recoverable_cohort,
)
from umi.competition_model_license_client import fetch_model_license_adoptions
from umi.competition_model_training_rights import (
    CONDITIONAL_TRAINING_RIGHTS_SHA256,
    NC_CONTRIBUTION_TERMS_SHA256,
)
from umi.open_competition import SignedModelLicenseTermsAdoption, digest
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_recovery import signatures
from .test_competition_model_license import nc_case as nc_case
from .test_competition_model_license import resign_submission
from .test_conditional_model_client import base_recovery as base_recovery
from .test_conditional_model_client import recovery as recovery
from .test_open_competition import policy as policy


@pytest.fixture
def approved_case(nc_case):
    body = nc_case["adoption"].adoption.model_copy(
        update={
            "noncommercial_terms_sha256": NC_CONTRIBUTION_TERMS_SHA256,
            "training_rights_policy_sha256": CONDITIONAL_TRAINING_RIGHTS_SHA256,
        }
    )
    adoption = SignedModelLicenseTermsAdoption(adoption=body, signatures=signatures(body))
    bundle = nc_case["bundle"].model_copy(update={"license_adoption": adoption})
    case = resign_submission(
        nc_case,
        model_bundle=bundle,
        model_revision=digest(bundle),
        accepted_terms_sha256=body.noncommercial_terms_sha256,
    )
    return dict(case, adoption=adoption, bundle=bundle)


@pytest.fixture
def watched(tmp_path, approved_case, policy, monkeypatch):
    cohort = digest(approved_case["history"].plan)
    policy_path = tmp_path / "policy.json"
    raw = canonical_json_bytes(policy)
    policy_path.write_bytes(raw)
    policy_path.chmod(0o600)
    score = tmp_path / "scores"
    score.mkdir(mode=0o700)
    config = NativePublicCatalogWatchConfig.model_validate_json(
        canonical_json_bytes(
            {
                "schema": "umi-native-public-catalog-watch/1",
                "cohorts": [cohort],
                "score_directory": str(score),
                "state_directory": str(tmp_path / "state"),
                "model_license_adoptions": [
                    approved_case["adoption"].model_dump(mode="json", by_alias=True)
                ],
                "template": {
                    "api": {"results": {"directory": str(tmp_path / "public")}},
                    "policy": {
                        "path": str(policy_path),
                        "sha256": hashlib.sha256(raw).hexdigest(),
                        "size_bytes": len(raw),
                        "owner_uid": policy_path.stat().st_uid,
                    },
                    "native_intake": {
                        "cohort_sha256": cohort,
                        "eligible_tracks": ["model"],
                        "config": {
                            "directory": str(tmp_path / "native"),
                            "cohorts": [
                                {
                                    "cohort_sha256": cohort,
                                    "authority_sha256": digest(
                                        approved_case["history"].authority.authority
                                    ),
                                }
                            ],
                        },
                    },
                },
            }
        )
    )
    reads = []

    class Intake:
        def __init__(self, config, selected_policy, *, eligible_tracks, read_only):
            assert selected_policy == policy and read_only is True

        def history(self, requested):
            assert requested == cohort
            reads.append(requested)
            return approved_case["history"]

    monkeypatch.setattr(module, "CohortIntake", Intake)
    return config, reads


def forbid_native(*args, **kwargs):
    pytest.fail("completed optional license selection repeated native work")


def test_intake_publishes_without_scores_then_restarts_without_native_reads(watched, monkeypatch):
    config, reads = watched
    cohort = config.cohorts[0]
    first = NativePublicCatalogWatcher(config).poll_once()
    assert first["total"] == 0 and first["model_license_adoptions"]["published"] == [cohort]
    assert first["model_license_adoptions"]["completed"] == 1
    assert first["model_license_adoptions"]["percent"] == 100
    assert first["model_license_adoptions"]["eta_seconds"] == 0
    assert reads == [cohort]
    result = module.read_model_license_adoptions(
        Path(config.template.api.results.directory), cohort
    )
    assert (
        result.status == "available"
        and result.items[0].terms_sha256 == NC_CONTRIBUTION_TERMS_SHA256
    )
    monkeypatch.setattr(module, "CohortIntake", forbid_native)
    monkeypatch.setattr(module, "project_model_license_adoptions", forbid_native)
    restarted = NativePublicCatalogWatcher(config)
    assert restarted.poll_once()["model_license_adoptions"]["retained"] == [cohort]
    output, checkpoint = module._paths(Path(config.template.api.results.directory), cohort)
    output.unlink()
    restored = restarted.poll_once()["model_license_adoptions"]
    assert restored["published"] == [cohort]
    assert restored["repaired"][0]["cohort_sha256"] == cohort
    assert output.exists() and checkpoint.exists()


@pytest.mark.parametrize("damage", ["delete", "corrupt"])
def test_damaged_completion_requires_repair_without_source_rescan(watched, monkeypatch, damage):
    config, _ = watched
    NativePublicCatalogWatcher(config).poll_once()
    path = next((Path(config.state_directory) / "model-license-adoptions").glob("*.json"))
    if damage == "delete":
        path.unlink()
    else:
        path.write_bytes(b"{}")
    monkeypatch.setattr(module, "CohortIntake", forbid_native)
    report = NativePublicCatalogWatcher(config).poll_once()
    assert len(report["model_license_adoptions"]["held"]) == 1
    assert report["model_license_adoptions"]["completed"] == 0
    assert report["model_license_adoptions"]["eta_seconds"] is None
    assert report["stalled_or_retrying"] is True


def test_public_polling_uses_only_projection_and_refuses_output_corruption(watched, monkeypatch):
    config, _ = watched
    NativePublicCatalogWatcher(config).poll_once()
    monkeypatch.setattr(module, "CohortIntake", forbid_native)
    monkeypatch.setattr(module, "verify_model_license_selection", forbid_native)
    cohort = config.cohorts[0]
    url = f"/v1/competition/cohorts/{cohort}/model-license-adoptions"
    with TestClient(create_cohort_public_app(config.template.api)) as client:
        first = client.get(url)
        assert first.status_code == 200 and first.json()["status"] == "available"
        assert client.get(url).json() == first.json()
        missing = client.get(url.replace(cohort, "ff" * 32))
        assert missing.status_code == 200 and missing.json()["status"] == "not_selected"
        path, _ = module._paths(Path(config.template.api.results.directory), cohort)
        path.write_bytes(b"{}")
        assert client.get(url).status_code == 503


def test_cli_discovery_authenticates_scope_before_any_wallet(approved_case, policy):
    history = approved_case["history"]
    response = module.project_model_license_adoptions(history, policy, (approved_case["adoption"],))
    wire = json.loads(canonical_json_bytes(response))
    args = dict(
        origin="https://intake.example",
        history=history,
        policy=policy,
        expected_tip_sha256=digest(history.genesis),
        current_block=210,
    )
    result = fetch_model_license_adoptions(
        **args, transport=httpx.MockTransport(lambda _: httpx.Response(200, json=wire))
    )
    assert result == response
    wire["cohort_sha256"] = "ff" * 32
    with pytest.raises(ValueError):
        fetch_model_license_adoptions(
            **args, transport=httpx.MockTransport(lambda _: httpx.Response(200, json=wire))
        )


def test_absent_license_selection_preserves_original_config_bytes(watched):
    config, _ = watched
    old = config.model_copy(update={"model_license_adoptions": ()})
    assert b"model_license_adoptions" not in canonical_json_bytes(old)
    assert NativePublicCatalogWatchConfig.model_validate_json(canonical_json_bytes(old)) == old


def test_one_signed_selection_publishes_every_selected_future_cohort(
    watched, approved_case, policy, monkeypatch
):
    config, _ = watched
    original = approved_case["history"]
    plans = (original.plan, original.plan.model_copy(update={"sequence": 8}))
    cohorts = tuple(sorted(digest(plan) for plan in plans))
    authority_body = original.authority.authority.model_copy(update={"cohort_sha256s": cohorts})
    authority = SignedCohortRecoveryAuthority(
        authority=authority_body, signatures=signatures(authority_body)
    )
    histories = {}
    for plan in plans:
        genesis, _ = admit_recoverable_cohort(plan, authority, policy, admitted_at_block=160)
        histories[digest(plan)] = original.model_copy(
            update={
                "plan": plan,
                "authority": authority,
                "genesis": genesis,
                "genesis_signatures": signatures(genesis),
            }
        )
    body = approved_case["adoption"].adoption.model_copy(
        update={"authority_sha256": digest(authority_body), "cohort_sha256s": cohorts}
    )
    adoption = SignedModelLicenseTermsAdoption(adoption=body, signatures=signatures(body))
    wire = config.model_dump(mode="json", by_alias=True)
    wire["cohorts"] = list(cohorts)
    wire["model_license_adoptions"] = [adoption.model_dump(mode="json", by_alias=True)]
    wire["template"]["native_intake"]["config"]["cohorts"] = [
        {"cohort_sha256": cohort, "authority_sha256": digest(authority_body)} for cohort in cohorts
    ]
    configured = NativePublicCatalogWatchConfig.model_validate_json(canonical_json_bytes(wire))
    reads = []

    class Intake:
        def __init__(self, *args, **kwargs):
            assert kwargs["read_only"] is True

        def history(self, cohort):
            reads.append(cohort)
            return histories[cohort]

    monkeypatch.setattr(module, "CohortIntake", Intake)
    report = NativePublicCatalogWatcher(configured).poll_once()["model_license_adoptions"]
    assert report["published"] == list(cohorts)
    assert report["completed"] == report["total"] == 2 and report["percent"] == 100
    assert reads == list(cohorts)
    for cohort in cohorts:
        result = module.read_model_license_adoptions(
            Path(config.template.api.results.directory), cohort
        )
        assert result.items[0].signed_adoption == adoption
    monkeypatch.setattr(module, "CohortIntake", forbid_native)
    report = NativePublicCatalogWatcher(configured).poll_once()["model_license_adoptions"]
    assert report["retained"] == list(cohorts)
