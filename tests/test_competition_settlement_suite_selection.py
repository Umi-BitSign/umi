"""Prospective suite selection retains the ordinary path's signed authority checks."""

import pytest

from umi.competition_settlement_release_selection import ForwardSuitePackageSelection
from umi.competition_successor_publication import SuccessorRoundPublicationBuilder
from umi.private_files import publish_private_model

pytest_plugins = ("tests.test_competition_settlement_release_selection",)


def select_suite(case, **updates):
    case.selection_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    selection = ForwardSuitePackageSelection(
        schema="umi-forward-suite-package-selection/1",
        suite_sha256=case.prepared.publication.round.suite_sha256,
        **case.selection.model_dump(
            exclude={"schema_", "round_sha256"}, mode="json", by_alias=True
        ),
    ).model_copy(update=updates)
    path = (
        case.selection_path.parent
        / "suites"
        / (case.prepared.publication.round.suite_sha256 + ".json")
    )
    publish_private_model(path, selection)
    return path


def test_prepared_suite_selects_native_package_without_round_sidecar(case, tmp_path):
    select_suite(case)
    assert not case.selection_path.exists()
    prepared = case.queue._package(case.prepared, case.package.settlement_certificate, 160)
    loaded = SuccessorRoundPublicationBuilder(tmp_path / "forward", case.config.plan)._load(
        prepared
    )
    assert loaded.release_identity == case.package.release_identity
    assert loaded.settlement_certificate == case.package.settlement_certificate
    assert loaded.evidence == case.package.evidence
    case.queue = case.reopen()
    assert case.queue._package(case.prepared, case.package.settlement_certificate, 160) == prepared


def test_removed_suite_selection_cannot_change_reserved_verifier(case):
    path = select_suite(case)
    assert case.queue._release_identity(case.prepared, 160) == case.package.release_identity
    path.unlink()
    case.queue = case.reopen()
    with pytest.raises(ValueError, match="missing"):
        case.queue._release_identity(case.prepared, 160)


@pytest.mark.parametrize(
    "field", ["suite_sha256", "predecessor_release_identity_sha256", "publisher_config_sha256"]
)
def test_suite_pin_mismatch_refused_before_certificate(case, field):
    select_suite(case, **{field: "00" * 32})
    with pytest.raises(ValueError):
        case.queue._release_identity(case.prepared, 160)
    assert case.queue.journal.get("release-selection", "1") is None
    assert case.queue.journal.get("certificate", "1") is None


def test_exact_and_suite_choices_must_agree(case):
    select_suite(case)
    publish_private_model(
        case.selection_path,
        case.selection.model_copy(update={"publisher_config_sha256": "00" * 32}),
    )
    with pytest.raises(ValueError, match="conflict"):
        case.queue._release_identity(case.prepared, 160)


@pytest.mark.parametrize("head", [124, 301])
def test_suite_selection_does_not_extend_authorized_time(case, head):
    select_suite(case)
    with pytest.raises(ValueError, match="scope"):
        case.queue._release_identity(case.prepared, head)


def test_late_suite_selection_cannot_rebind_prior_package(case):
    case.queue._package(case.prepared, case.package.settlement_certificate, 160)
    select_suite(case)
    with pytest.raises(ValueError, match="too late"):
        case.queue._release_identity(case.prepared, 160)


def test_unselected_suite_preserves_legacy_behavior(case):
    path = select_suite(case)
    path.rename(path.with_name("00" * 32 + ".json"))
    assert case.queue._release_identity(case.prepared, 160) == case.old
