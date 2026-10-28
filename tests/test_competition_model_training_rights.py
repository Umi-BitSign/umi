"""Conditional source declarations preserve legacy review and exact NC consent."""

import copy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from umi.competition_model_training_rights import (
    CONDITIONAL_TRAINING_RIGHTS_SHA256,
    NC_CONTRIBUTION_TERMS_SHA256,
    NC_MODEL_LICENSE,
    PROVENANCE_SCHEMA,
    ResearchRightsWarranty,
    declared_nc_training,
    validate_model_training_provenance,
)
from umi.open_competition import BundleFile


def source(**changes):
    value = {
        "name": "How2Sign",
        "version": "declared-release",
        "canonical_url": "https://how2sign.github.io/",
        "license_id": "CC-BY-NC-4.0",
        "download_route": "Publisher public-license download",
        "acquired_on": "2026-10-01",
        "archives": [{"name": "training-archive", "sha256": "11" * 32}],
        "uses": ["training"],
        "accepted_access_terms": [],
        "additional_dataset_contract": False,
        "permission_record_sha256": None,
        "split": "train",
        "responsible_use_requests": [],
        "destruction_required": False,
        "destroyed_on": None,
    }
    return value | changes


def documents(sources=None):
    provenance = {
        "schema": PROVENANCE_SCHEMA,
        "model_license_id": NC_MODEL_LICENSE,
        "sources": sources or [source()],
        "rights_warranty": dict.fromkeys(ResearchRightsWarranty.model_fields, True),
    }
    return {
        "PROVENANCE.json": json.dumps(provenance).encode(),
        "NOTICE": b"How2Sign consortium, CVPR 2021. ChicagoFSWild+. Example source. ASL STEM Wiki.",
        "LICENSE-WEIGHTS": NC_MODEL_LICENSE.encode(),
        "MODEL_CARD.md": b"Research model. Weights: CC BY-NC-SA 4.0; card: CC BY 4.0.",
    }


def bundle(raw, license_id=NC_MODEL_LICENSE):
    return SimpleNamespace(
        license_id=license_id,
        files=tuple(
            BundleFile(
                path=name,
                role="license" if name in ("NOTICE", "LICENSE-WEIGHTS") else "provenance",
                sha256=hashlib.sha256(body).hexdigest(),
                size_bytes=len(body),
            )
            for name, body in raw.items()
        ),
    )


def review(raw, **kwargs):
    return validate_model_training_provenance(
        bundle(raw), raw, rights_policy_sha256=CONDITIONAL_TRAINING_RIGHTS_SHA256, **kwargs
    )


def test_how2_research_declaration_is_bound_and_scope_is_honest(monkeypatch):
    raw = documents()
    selected_bundle = bundle(raw)
    with monkeypatch.context() as patch:
        patch.setattr(hashlib, "sha256", lambda *_: pytest.fail("payload rehashed"))
        result = validate_model_training_provenance(
            selected_bundle, raw, rights_policy_sha256=CONDITIONAL_TRAINING_RIGHTS_SHA256
        )
        assert result == validate_model_training_provenance(
            selected_bundle, raw, rights_policy_sha256=CONDITIONAL_TRAINING_RIGHTS_SHA256
        )
    assert result["provenance_sha256"] == selected_bundle.files[0].sha256
    assert result["source_decisions"][0]["decision"] == "noncommercial_research_source"
    assert result["supplemental_terms_sha256"] == NC_CONTRIBUTION_TERMS_SHA256
    assert result["actual_training_independently_audited"] is False
    assert result["memorisation_probe_executed"] is False
    assert result["memorisation_probe_threshold"] is None


def test_terms_digest_matches_exact_published_bytes():
    root = Path(__file__).resolve().parents[1]
    terms = root / "docs/MODEL_CONTRIBUTION_TERMS_NC_V1.md"
    assert hashlib.sha256(terms.read_bytes()).hexdigest() == NC_CONTRIBUTION_TERMS_SHA256
    assert NC_CONTRIBUTION_TERMS_SHA256 in terms.with_suffix(".sha256").read_text()


@pytest.mark.parametrize("raw", [b"Legacy prose", b"{}", b"[]", b"not JSON", b"\xff"])
def test_old_provenance_keeps_original_reader(raw):
    assert declared_nc_training({"PROVENANCE.json": raw}) is False


def test_inherited_nc_checkpoint_requires_conditional_route():
    raw = documents([source(uses=["inherited_checkpoint"])])
    assert declared_nc_training(raw)
    assert review(raw)["declared_model_license"] == NC_MODEL_LICENSE
    with pytest.raises(ValueError, match="nc_training_requires_nc_model_license"):
        validate_model_training_provenance(
            bundle(raw, "MIT"), raw, rights_policy_sha256=CONDITIONAL_TRAINING_RIGHTS_SHA256
        )


def test_how2_cannot_be_relabelled_permissive():
    raw = documents([source(license_id="MIT")])
    assert declared_nc_training(raw)
    with pytest.raises(ValueError, match="how2sign_requires_noncommercial_source_declaration"):
        review(raw)


def test_validation_only_nc_source_does_not_select_nc_model_route():
    raw = documents([source(uses=["validation", "testing"])])
    assert not declared_nc_training(raw)
    with pytest.raises(ValueError, match="nc_route_requires_declared_nc_training_or_checkpoint"):
        review(raw)


def test_evaluation_source_declaration_is_not_training_permission():
    raw = documents([source(), source(name="ASL STEM Wiki", uses=["testing"])])
    assert review(raw)["source_decisions"][1]["decision"] == (
        "declared_evaluation_source_not_training_permission"
    )


@pytest.mark.parametrize(
    "changes,error",
    [
        ({"additional_dataset_contract": True}, "written_permission_not_selected"),
        ({"permission_record_sha256": "ab" * 32}, "permission_record_not_selected"),
        ({"name": "ASL STEM Wiki"}, "written_permission_not_selected"),
        ({"name": "Example source", "license_id": "CC-BY-ND-4.0"}, "license_not_permitted"),
        ({"name": "Example source", "license_id": "unspecified"}, "license_not_permitted"),
        ({"name": "ChicagoFSWild+", "split": "dev"}, "chicago_training_requires_train_split"),
        ({"name": "ChicagoFSWild+", "split": "test"}, "chicago_training_requires_train_split"),
    ],
)
def test_disallowed_training_sources_fail_with_specific_reason(changes, error):
    raw = documents([source(), source(version="second-source", **changes)])
    with pytest.raises(ValueError, match=error):
        review(raw)


def test_chicago_operator_permission_preserves_publisher_license_truth():
    raw = documents([source(), source(name="ChicagoFSWild+", license_id="not-stated")])
    result = review(raw)["source_decisions"][1]
    assert result["license_id"] == "not-stated"
    assert result["decision"] == "operator_approved_train_split"


@pytest.mark.parametrize("path", ["PROVENANCE.json", "NOTICE", "LICENSE-WEIGHTS", "MODEL_CARD.md"])
def test_required_documents_are_not_satisfied_by_empty_files(path):
    raw = documents()
    raw[path] = b" "
    with pytest.raises(ValueError, match="nc_required_document_missing"):
        review(raw)


def test_notice_includes_attribution_and_responsible_requests():
    raw = documents([source(responsible_use_requests=["Do not reidentify signers."])])
    with pytest.raises(ValueError, match="nc_source_notice_or_responsible_use_missing"):
        review(raw)
    raw["NOTICE"] += b" Do not reidentify signers."
    review(raw)
    raw["NOTICE"] = b"How2Sign. Do not reidentify signers."
    with pytest.raises(ValueError, match="how2sign_attribution_or_citation_missing"):
        review(raw)


@pytest.mark.parametrize(
    "change",
    [
        {"destruction_required": True},
        {"destruction_required": True, "destroyed_on": "2026-09-30"},
        {"canonical_url": "https://name:secret@example.test/file"},
        {"uses": ["training", "training"]},
        {"acquired_on": "unknown"},
    ],
)
def test_invalid_explicit_provenance_fails_in_both_new_readers(change):
    raw = documents([source(**change)])
    for reader in (declared_nc_training, review):
        with pytest.raises(ValueError, match="nc_provenance_schema_invalid"):
            reader(raw)


def test_valid_destruction_and_warranty_required():
    raw = documents([source(destruction_required=True, destroyed_on="2026-10-02")])
    review(raw)
    provenance = json.loads(raw["PROVENANCE.json"])
    provenance["rights_warranty"]["complete_source_inventory"] = False
    raw["PROVENANCE.json"] = json.dumps(provenance).encode()
    with pytest.raises(ValueError, match="nc_provenance_schema_invalid"):
        review(raw)


def test_wrong_rights_contract_refused_without_reviewing_payloads():
    with pytest.raises(ValueError, match="conditional_training_rights_policy_not_supported"):
        validate_model_training_provenance(None, {}, rights_policy_sha256="ff" * 32)


def test_duplicate_sources_and_wrong_weights_notice_fail():
    raw = documents([source(), copy.deepcopy(source())])
    with pytest.raises(ValueError, match="nc_provenance_source_duplicated"):
        review(raw)
    raw = documents()
    raw["LICENSE-WEIGHTS"] = b"MIT"
    with pytest.raises(ValueError, match="nc_weights_license_notice_missing"):
        review(raw)
