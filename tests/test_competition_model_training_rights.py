"""Conditional source declarations preserve legacy review and exact NC consent."""

import copy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from umi.competition_model_training_rights import (
    CONDITIONAL_TRAINING_RIGHTS_SHA256,
    LEGACY_CONDITIONAL_TRAINING_RIGHTS_SHA256,
    LEGACY_NC_CONTRIBUTION_TERMS_SHA256,
    NC_CONTRIBUTION_TERMS_SHA256,
    NC_MODEL_LICENSE,
    PROVENANCE_SCHEMA,
    ResearchRightsWarranty,
    TrainingSource,
    declared_nc_training,
    validate_model_training_provenance,
    validate_model_training_terms,
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


@pytest.mark.parametrize(
    "version,expected",
    [(1, LEGACY_NC_CONTRIBUTION_TERMS_SHA256), (2, NC_CONTRIBUTION_TERMS_SHA256)],
)
def test_terms_digest_matches_exact_published_bytes(version, expected):
    root = Path(__file__).resolve().parents[1]
    terms = root / f"docs/MODEL_CONTRIBUTION_TERMS_NC_V{version}.md"
    assert hashlib.sha256(terms.read_bytes()).hexdigest() == expected
    assert expected in terms.with_suffix(".sha256").read_text()


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
        ({"name": "ASL STEM Wiki"}, "microsoft_research_source_declaration"),
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


def stem_source(**changes):
    return source(
        **{
            "name": "ASL STEM Wiki",
            "canonical_url": "https://www.microsoft.com/en-us/research/project/asl-stem-wiki/",
            "license_id": "LicenseRef-Microsoft-Research",
            "additional_dataset_contract": True,
            "accepted_access_terms": [
                "https://www.microsoft.com/en-us/research/project/asl-stem-wiki/dataset-license/"
            ],
            "destruction_required": True,
            "research_complete": False,
        }
        | changes
    )


@pytest.mark.parametrize("use", ["training", "inherited_checkpoint"])
def test_stem_requires_new_signed_revision_and_nc_consent_route(use):
    raw = documents([stem_source(uses=[use])])
    assert declared_nc_training(raw, rights_policy_sha256=CONDITIONAL_TRAINING_RIGHTS_SHA256)
    current = review(raw)
    assert current["source_decisions"][0]["decision"] == (
        "operator_approved_noncommercial_research_source"
    )
    assert current["supplemental_terms_sha256"] == NC_CONTRIBUTION_TERMS_SHA256
    # V1 retains its rejection; a new reader does not rewrite old signed terms.
    with pytest.raises(ValueError, match="nc_provenance_schema_invalid"):
        validate_model_training_provenance(
            bundle(raw), raw, rights_policy_sha256=LEGACY_CONDITIONAL_TRAINING_RIGHTS_SHA256
        )
    old_source = stem_source(uses=[use], destruction_required=False)
    old_source.pop("research_complete")
    old_raw = documents([source(), old_source])
    with pytest.raises(ValueError, match="written_permission_not_selected"):
        validate_model_training_provenance(
            bundle(old_raw),
            old_raw,
            rights_policy_sha256=LEGACY_CONDITIONAL_TRAINING_RIGHTS_SHA256,
        )


@pytest.mark.parametrize(
    "changes",
    [
        {"license_id": "MIT"},
        {"license_id": "CC-BY-NC-4.0"},
        {"canonical_url": "https://example.test/asl-stem-wiki/"},
        {"additional_dataset_contract": False},
        {"accepted_access_terms": []},
    ],
)
def test_stem_approval_does_not_relabel_microsoft_source_or_clear_other_contracts(changes):
    raw = documents([stem_source(**changes)])
    assert declared_nc_training(raw, rights_policy_sha256=CONDITIONAL_TRAINING_RIGHTS_SHA256)
    with pytest.raises(ValueError, match="asl_stem_requires_microsoft_research_source_declaration"):
        review(raw)


def test_stem_source_cannot_supply_its_own_unselected_permission():
    with pytest.raises(ValueError, match="nc_source_permission_record_not_selected"):
        review(documents([stem_source(permission_record_sha256="ab" * 32)]))
    with pytest.raises(ValueError, match="written_permission_not_selected"):
        review(
            documents(
                [
                    stem_source(),
                    source(name="Other Microsoft Dataset", additional_dataset_contract=True),
                ]
            )
        )


def test_stem_approval_cannot_cover_different_additional_access_terms():
    selected = stem_source()
    selected["accepted_access_terms"].append("https://example.test/other-contract")
    with pytest.raises(ValueError, match="asl_stem_access_terms_not_selected"):
        review(documents([selected]))


def test_stem_publisher_identity_forces_nc_even_with_a_different_display_name():
    raw = documents([stem_source(name="Example source", license_id="MIT")])
    assert declared_nc_training(raw, rights_policy_sha256=CONDITIONAL_TRAINING_RIGHTS_SHA256)
    with pytest.raises(ValueError, match="asl_stem_requires_microsoft_research_source_declaration"):
        review(raw)


def test_legacy_how2_rights_evidence_and_exact_supplement_pair_are_preserved():
    raw = documents()
    legacy = validate_model_training_provenance(
        bundle(raw), raw, rights_policy_sha256=LEGACY_CONDITIONAL_TRAINING_RIGHTS_SHA256
    )
    current = review(raw)
    assert (
        legacy
        | {
            "training_rights_policy_sha256": CONDITIONAL_TRAINING_RIGHTS_SHA256,
            "supplemental_terms_sha256": NC_CONTRIBUTION_TERMS_SHA256,
        }
        == current
    )
    for policy, terms in (
        (LEGACY_CONDITIONAL_TRAINING_RIGHTS_SHA256, LEGACY_NC_CONTRIBUTION_TERMS_SHA256),
        (CONDITIONAL_TRAINING_RIGHTS_SHA256, NC_CONTRIBUTION_TERMS_SHA256),
    ):
        validate_model_training_terms(rights_policy_sha256=policy, supplemental_terms_sha256=terms)
        other = (
            NC_CONTRIBUTION_TERMS_SHA256
            if terms == LEGACY_NC_CONTRIBUTION_TERMS_SHA256
            else LEGACY_NC_CONTRIBUTION_TERMS_SHA256
        )
        with pytest.raises(ValueError, match="conditional_model_terms_not_supported"):
            validate_model_training_terms(
                rights_policy_sha256=policy, supplemental_terms_sha256=other
            )


def test_stem_destruction_trigger_is_research_completion_not_submission():
    review(documents([stem_source()]))  # Ongoing research; deletion is not due yet.
    review(documents([stem_source(research_complete=True, destroyed_on="2026-10-02")]))
    with pytest.raises(ValueError, match="nc_provenance_schema_invalid"):
        review(documents([stem_source(research_complete=True)]))
    with pytest.raises(ValueError, match="research_completion_and_destruction_declaration"):
        review(documents([stem_source(destruction_required=False)]))
    missing = stem_source(destruction_required=False)
    missing.pop("research_complete")
    with pytest.raises(ValueError, match="research_completion_and_destruction_declaration"):
        review(documents([missing]))
    with pytest.raises(ValueError, match="nc_provenance_schema_invalid"):
        review(documents([source(destruction_required=True, research_complete=False)]))


def test_legacy_stem_permissive_signal_is_unchanged_without_prospective_selection():
    legacy_source = source(name="ASL STEM Wiki", license_id="MIT")
    raw = documents([legacy_source])
    assert not declared_nc_training(raw)
    assert declared_nc_training(raw, rights_policy_sha256=CONDITIONAL_TRAINING_RIGHTS_SHA256)


def test_original_training_source_serialization_has_no_new_default_field():
    original = source()
    restored = TrainingSource.model_validate_json(json.dumps(original))
    assert restored.model_dump(mode="json", by_alias=True) == original
    assert "research_complete" not in restored.model_dump()
