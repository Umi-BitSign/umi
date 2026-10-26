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


def test_declared_dataset_share_cap_refuses_concentrated_public_source(case):
    counts = case.counts.model_copy(update={"maximum_continuous_dataset_share_bps": 5000})
    with pytest.raises(ValueError, match="diversity"):
        select(case, counts=counts)
    third = candidate(
        7,
        "A new sentence about the weather in town",
        dataset="IndependentContinuous",
        signer=7,
        topic="Weather",
    )
    inventory = case.inventory.model_copy(update={"cases": (*case.inventory.cases, third)})
    suite, report = select(case, inventory=inventory, counts=counts)
    assert len(suite.cases) == 6
    assert report["selected_by_task_and_dataset"]["continuous"] == {
        "ASL-STEM": 1,
        "How2Sign": 1,
        "IndependentContinuous": 1,
    }


def test_declared_fingerspelling_share_cap_requires_another_source(case):
    counts = case.counts.model_copy(update={"maximum_fingerspelling_dataset_share_bps": 5000})
    with pytest.raises(ValueError, match="diversity"):
        select(case, counts=counts)
    third = candidate(
        8,
        "Oak Lane",
        task="fingerspelling",
        dataset="IndependentFingerspelling",
        signer=8,
    )
    inventory = case.inventory.model_copy(update={"cases": (*case.inventory.cases, third)})
    _, report = select(case, inventory=inventory, counts=counts)
    assert max(report["selected_by_task_and_dataset"]["fingerspelling"].values()) == 1


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


def categorized(c, *, fingerspelling=4):
    from umi.competition_suite_selection import FingerspellingCategoryMinimums

    values = tuple(
        entry.model_copy(update={"fingerspelling_category": category})
        for entry, category in zip(
            c.inventory.cases[:3], ("name", "address", "number"), strict=True
        )
    )
    sentence = candidate(
        100, "want to join us for lunch", task="fingerspelling", dataset="FSboard", signer=100
    ).model_copy(update={"fingerspelling_category": "sentence"})
    inventory = c.inventory.model_copy(
        update={"cases": (*values, *c.inventory.cases[3:], sentence)}
    )
    counts = c.counts.model_copy(
        update={
            "fingerspelling": fingerspelling,
            "fingerspelling_category_minimums": FingerspellingCategoryMinimums(
                sentence=1, name=1, address=1, number=1
            ),
        }
    )
    return inventory, counts


def test_explicit_fingerspelling_quotas_preserve_all_four_categories_in_a_larger_pool(case):
    c = case
    inventory, counts = categorized(c, fingerspelling=6)
    extras = tuple(
        candidate(
            i, "DifferentName" + str(i), task="fingerspelling", dataset="FSboard", signer=i
        ).model_copy(update={"fingerspelling_category": "name"})
        for i in range(101, 109)
    )
    inventory = inventory.model_copy(update={"cases": (*inventory.cases, *extras)})
    for seed in (0, 1, 7, 31):
        suite, report = select_future_suite(
            inventory, c.exclusions, counts, c.policy, selection_key=bytes([seed]) * 32
        )
        assert len(suite.cases) == 9
        assert report["selected_fingerspelling_categories"] == {
            "sentence": 1,
            "name": 3,
            "address": 1,
            "number": 1,
        }
        assert all(
            case.references in {entry.case.references for entry in inventory.cases}
            for case in suite.cases
        )


def test_four_fingerspelling_categories_respect_two_source_75_percent_cap(case):
    inventory, counts = categorized(case)
    categories = ("sentence", "name", "address", "number")
    primary = tuple(
        candidate(
            200 + index,
            f"Distinct finger spelling example {index}",
            task="fingerspelling",
            dataset="PrimaryFS",
            signer=200 + index,
        ).model_copy(update={"fingerspelling_category": category})
        for index, category in enumerate(categories)
    )
    secondary = candidate(
        210,
        "An independent signed sentence",
        task="fingerspelling",
        dataset="SecondaryFS",
        signer=210,
    ).model_copy(update={"fingerspelling_category": "sentence"})
    inventory = inventory.model_copy(
        update={"cases": (*primary, secondary, *case.inventory.cases[3:])}
    )
    counts = counts.model_copy(
        update={
            "minimum_fingerspelling_datasets": 2,
            "maximum_fingerspelling_dataset_share_bps": 7500,
        }
    )
    for seed in (0, 1, 7, 31):
        _, report = select_future_suite(
            inventory,
            case.exclusions,
            counts,
            case.policy,
            selection_key=bytes([seed]) * 32,
        )
        assert report["selected_fingerspelling_categories"] == dict.fromkeys(categories, 1)
        assert report["selected_by_task_and_dataset"]["fingerspelling"] == {
            "PrimaryFS": 3,
            "SecondaryFS": 1,
        }

    primary_only = inventory.model_copy(update={"cases": (*primary, *case.inventory.cases[3:])})
    with pytest.raises(ValueError, match="diversity"):
        select_future_suite(
            primary_only, case.exclusions, counts, case.policy, selection_key=case.key
        )


@pytest.mark.parametrize("category", ["sentence", "name", "address", "number"])
def test_category_shortage_refuses_instead_of_reclassifying_or_reducing_quotas(case, category):
    inventory, counts = categorized(case)
    inventory = inventory.model_copy(
        update={
            "cases": tuple(
                entry for entry in inventory.cases if entry.fingerspelling_category != category
            )
        }
    )
    with pytest.raises(ValueError, match="diversity"):
        select(case, inventory=inventory, counts=counts)


def test_legacy_standalone_selection_keeps_exact_uncategorized_bytes(case):
    entry = case.inventory.cases[0]
    assert b"fingerspelling_category" not in canonical_json_bytes(entry)
    assert b"fingerspelling_category_minimums" not in canonical_json_bytes(case.counts)
    raw = canonical_json_bytes(case.counts)
    assert canonical_json_bytes(SuiteSelectionCounts.model_validate_json(raw)) == raw
    _, report = select(case)
    assert "selected_fingerspelling_categories" not in report
    assert all("fingerspelling_category" not in row for row in report["selected_provenance"])


def test_four_category_quota_minimums_must_fit_and_cannot_be_zero_or_missing(case):
    from umi.competition_suite_selection import FingerspellingCategoryMinimums

    for changes in ({"sentence": 0}, {"number": False}):
        with pytest.raises(ValueError):
            FingerspellingCategoryMinimums.model_validate(
                {"sentence": 1, "name": 1, "address": 1, "number": 1} | changes
            )
    with pytest.raises(ValueError):
        FingerspellingCategoryMinimums.model_validate({"name": 1, "address": 1, "number": 1})
    _, counts = categorized(case)
    with pytest.raises(ValueError, match="fit"):
        SuiteSelectionCounts.model_validate(counts.model_dump() | {"fingerspelling": 3})
    with pytest.raises(ValueError, match="only a fingerspelling"):
        SuiteCandidate.model_validate(
            case.inventory.cases[-1].model_dump() | {"fingerspelling_category": "sentence"}
        )
