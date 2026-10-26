"""Metadata-only prospective selection; no video, model, RPC or signing ports."""

from types import SimpleNamespace

import pytest

from umi import competition_suite_selection_cli as cli
from umi.competition_suite_selection import (
    SuiteCandidate,
    SuiteCandidateInventory,
    SuiteExclusions,
    SuiteSelectionCounts,
    reference_identities,
    select_future_suite,
)
from umi.open_competition import SingleReferenceEvaluationCase
from umi.private_files import publish_private_model
from umi.protocol import canonical_json_bytes

from .test_competition_two_task_profile import launch_policy
from .test_open_competition import policy as policy


def candidate(i, text, *, task="continuous", dataset="ASL-STEM", signer=None, topic=None):
    return SuiteCandidate(
        case=SingleReferenceEvaluationCase(
            case_id=f"{i:064x}",
            video_sha256=f"{1000 + i:064x}",
            stratum=task,
            references=(text,),
        ),
        dataset=dataset,
        dataset_version="pinned-metadata",
        source_group_sha256=f"{2000 + i:064x}",
        provenance_sha256=f"{3000 + i:064x}",
        license_id="research-only-or-other-declared-license",
        attribution="Original publisher; retained privately for evaluation",
        training_exposure="known_public",
        signer_group_sha256=None if signer is None else f"{signer:064x}",
        topic=topic,
        reference_qa_sha256=f"{4000 + i:064x}",
    )


@pytest.fixture
def case(policy):
    values = (
        candidate(1, "Mariam", task="fingerspelling", dataset="FSboard", signer=1),
        candidate(2, "Maple Street", task="fingerspelling", dataset="ChicagoFSWild", signer=2),
        candidate(3, "Z981R", task="fingerspelling", dataset="ChicagoFSWild", signer=3),
        candidate(4, "Place the saucepan beside the oven", dataset="How2Sign", signer=4),
        candidate(5, "A magnetic field changes particle motion", signer=5, topic="Physics"),
        candidate(6, "Volcanic eruptions release pressure under rock", signer=6, topic="Geology"),
    )
    return SimpleNamespace(
        policy=launch_policy(policy),
        inventory=SuiteCandidateInventory(schema="umi-private-suite-candidates/1", cases=values),
        exclusions=SuiteExclusions(
            schema="umi-private-suite-exclusions/1", source_metadata_sha256s=("f" * 64,)
        ),
        counts=SuiteSelectionCounts(fingerspelling=3, continuous=3),
        key=bytes(range(32)),
    )


def select(c, **updates):
    return select_future_suite(
        updates.get("inventory", c.inventory),
        updates.get("exclusions", c.exclusions),
        updates.get("counts", c.counts),
        c.policy,
        selection_key=c.key,
    )


def test_diverse_selection_preserves_publisher_references_and_is_order_independent(case):
    c = case
    suite, report = select(c)
    shuffled = c.inventory.model_copy(update={"cases": tuple(reversed(c.inventory.cases))})
    assert select(c, inventory=shuffled)[0] == suite
    assert {v.references for v in suite.cases} == {v.case.references for v in c.inventory.cases}
    assert report["selected_by_task_and_dataset"]["continuous"] == {"ASL-STEM": 2, "How2Sign": 1}
    assert report["selected_diversity"]["continuous"]["known_signers"] == 3
    assert report["selected_diversity"]["continuous"]["unknown_signer_cases"] == 0
    assert report["selected_diversity"]["continuous"]["known_topics"] == 2
    assert report["unknown_or_public_exposure_is_not_verified_holdout"]
    assert report["media_payload_reads"] == 0 and not report["signed_inputs_changed"]
    assert all(value.case.references[0] not in str(report) for value in c.inventory.cases)
    assert all(
        x["license_id"] == "research-only-or-other-declared-license"
        for x in report["selected_provenance"]
    )


@pytest.mark.parametrize("damage", ["sentence", "source", "signer", "near_sentence"])
def test_known_training_or_exposed_text_and_group_overlap_is_excluded(case, damage):
    c = case
    original = c.inventory.cases[4]
    if damage == "near_sentence":
        original = candidate(
            5, "magnetic fields alter charged particle motion", signer=5, topic="Physics"
        )
    replacement = candidate(
        7, "Mitochondria supply energy inside living cells", signer=7, topic="Biology"
    )
    inventory = c.inventory.model_copy(
        update={"cases": (*c.inventory.cases[:4], original, c.inventory.cases[5], replacement)}
    )
    changes = {
        "sentence": dict(references=("\uff21 magnetic FIELD changes particle motion!",)),
        "source": dict(source_group_sha256s=(original.source_group_sha256,)),
        "signer": dict(signer_group_sha256s=(original.signer_group_sha256,)),
        "near_sentence": dict(
            references=("magnetic fields alter charged particle motion significantly",)
        ),
    }
    exclusions = c.exclusions.model_copy(update=changes[damage])
    suite, report = select(c, inventory=inventory, exclusions=exclusions)
    assert original.case.case_id not in {x.case_id for x in suite.cases}
    assert replacement.case.case_id in {x.case_id for x in suite.cases}
    assert sum(report["excluded_cases"].values()) == 1


def test_normalization_catches_nfkc_punctuation_and_fs_whitespace_without_rewriting():
    assert reference_identities("\uff2d\uff21\uff32\uff29\uff21\uff2d!") & reference_identities(
        "mariam"
    )
    assert reference_identities("Maple Street") & reference_identities("MAPLESTREET")


@pytest.mark.parametrize("constraint", ["dataset", "signer", "topic"])
def test_selection_refuses_missing_diversity_instead_of_relaxing(case, constraint):
    c = case
    values = tuple(
        x.model_copy(
            update={
                "dataset": "only-one" if constraint == "dataset" else x.dataset,
                "signer_group_sha256": None if constraint == "signer" else x.signer_group_sha256,
                "topic": None if constraint == "topic" else x.topic,
            }
        )
        for x in c.inventory.cases
    )
    with pytest.raises(ValueError, match="diversity"):
        select(c, inventory=c.inventory.model_copy(update={"cases": values}))


def test_unknown_exposure_cannot_be_promoted_to_documented_holdout(case):
    c = case
    value = c.inventory.cases[0].model_dump(mode="json")
    value["training_exposure"] = "documented_training_excluded"
    with pytest.raises(ValueError, match="documented evidence"):
        SuiteCandidate.model_validate_json(canonical_json_bytes(value))
    values = tuple(x.model_copy(update={"training_exposure": "unknown"}) for x in c.inventory.cases)
    _, report = select(c, inventory=c.inventory.model_copy(update={"cases": values}))
    assert report["selected_training_exposure"] == {"unknown": 6}
    assert report["unknown_or_public_exposure_is_not_verified_holdout"]


def test_cli_reuses_completed_preparation_and_restores_interrupted_output(
    case, tmp_path, monkeypatch
):
    c = case
    tmp_path.chmod(0o700)
    args = SimpleNamespace(destination=tmp_path / "prepared")
    for name in ("inventory", "exclusions", "counts", "policy"):
        path = tmp_path / (name + ".json")
        publish_private_model(path, getattr(c, name))
        setattr(args, name, path)
    args.selection_key = tmp_path / "key"
    args.selection_key.write_bytes(c.key)
    args.selection_key.chmod(0o600)
    first = cli.prepare(args)
    assert not first["reused_preparation"]
    args.policy.chmod(0o444)
    (args.destination / "selection-report.json").unlink()

    def forbidden(*args, **kwargs):
        pytest.fail("same completed selection must not review candidates twice")

    monkeypatch.setattr(cli, "select_future_suite", forbidden)
    second = cli.prepare(args)
    assert second["reused_preparation"] and second["suite_sha256"] == first["suite_sha256"]
    assert (args.destination / "selection-report.json").is_file()
    args.selection_key.write_bytes(bytes(reversed(c.key)))
    with pytest.raises(ValueError, match="different original inputs"):
        cli.prepare(args)
    assert args.policy.read_bytes() == canonical_json_bytes(c.policy)
    assert not first["production_state_changed"]


@pytest.mark.parametrize("field", ["signer_group_sha256", "reference_qa_sha256"])
def test_strict_selection_excludes_unqualified_cases_before_preparation(case, field):
    c = case
    original = c.inventory.cases[4]
    damaged = original.model_copy(update={field: None})
    alternate = candidate(
        7, "Mitochondria supply energy inside living cells", signer=7, topic="Biology"
    )
    inventory = c.inventory.model_copy(
        update={"cases": (*c.inventory.cases[:4], damaged, c.inventory.cases[5], alternate)}
    )
    suite, report = select(c, inventory=inventory)
    assert original.case.case_id not in {x.case_id for x in suite.cases}
    assert report["excluded_cases"]["missing_reference_qa_or_signer_identity"] == 1


def test_strict_selection_keeps_signers_separate_across_selected_cases(case):
    c = case
    repeated = c.inventory.cases[-1].model_copy(
        update={"signer_group_sha256": c.inventory.cases[-2].signer_group_sha256}
    )
    inventory = c.inventory.model_copy(update={"cases": (*c.inventory.cases[:-1], repeated)})
    with pytest.raises(ValueError, match="disjoint diversity"):
        select(c, inventory=inventory)
