"""Certified public metadata survives producer restart without repeating native work."""

import hashlib
import shutil
from pathlib import Path

import pytest

from umi import competition_cohort_public_catalog_watch as module
from umi.competition_cohort_public_publisher import NativePublicProjection
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_model_scores import sample_scores
from .test_competition_cohort_public_results import public_case as public_case


@pytest.fixture
def watched(tmp_path, public_case, monkeypatch):
    api, catalog, download, _ = public_case
    policy = tmp_path / "policy.json"
    policy.write_bytes(b"{}")
    score = tmp_path / "scores"
    score.mkdir(mode=0o700)
    base = sample_scores()
    entry = base.items[0].model_copy(
        update={
            "submission_sha256": catalog.items[0].submission_sha256,
            "model_sha256": download.model_sha256,
        }
    )
    scores = base.model_copy(
        update={
            "cohort_sha256": catalog.cohort_sha256,
            "policy_sha256": catalog.policy_sha256,
            "items": (entry,),
        }
    )
    trigger = score / (catalog.cohort_sha256 + ".json")
    trigger.write_bytes(canonical_json_bytes(scores))
    trigger.chmod(0o600)
    config = module.NativePublicCatalogWatchConfig.model_validate_json(
        canonical_json_bytes(
            dict(
                schema="umi-native-public-catalog-watch/1",
                score_directory=str(score),
                state_directory=str(tmp_path / "state"),
                cohorts=[catalog.cohort_sha256],
                template=dict(
                    api=api.model_dump(mode="json"),
                    policy=dict(
                        path=str(policy),
                        sha256=hashlib.sha256(b"{}").hexdigest(),
                        owner_uid=policy.stat().st_uid,
                        size_bytes=2,
                    ),
                    native_intake=dict(
                        config=dict(
                            directory=str(tmp_path / "native"),
                            cohorts=[
                                dict(cohort_sha256=catalog.cohort_sha256, authority_sha256="f" * 64)
                            ],
                        ),
                        cohort_sha256=catalog.cohort_sha256,
                        eligible_tracks=["model"],
                    ),
                ),
            )
        )
    )
    projection = NativePublicProjection(catalog=catalog, paid=None, downloads=(download,))
    calls = []

    def prepare(config, *, submission_sha256s):
        calls.append(submission_sha256s)
        return projection

    monkeypatch.setattr(module, "prepare_native_cohort", prepare)
    return config, projection, calls, trigger


def forbid_native(*args, **kwargs):
    raise AssertionError("completed public projection repeated native work")


def test_first_publication_and_unchanged_poll_check_native_once(watched, monkeypatch):
    config, projection, calls, _ = watched
    owner = module.NativePublicCatalogWatcher(config)
    assert owner.poll_once()["held"] == []
    assert calls == [(projection.catalog.items[0].submission_sha256,)]
    monkeypatch.setattr(module, "prepare_native_cohort", forbid_native)
    monkeypatch.setattr(module, "read_owned_file", forbid_native)
    result = owner.poll_once()
    assert result["retained"] == [projection.catalog.cohort_sha256]
    assert result["percent"] == 100


def test_restart_and_evicted_output_restore_without_source_or_native_work(watched, monkeypatch):
    config, projection, _, trigger = watched
    assert module.NativePublicCatalogWatcher(config).poll_once()["held"] == []
    shutil.rmtree(config.template.api.results.directory)
    trigger.unlink()
    monkeypatch.setattr(module, "prepare_native_cohort", forbid_native)
    result = module.NativePublicCatalogWatcher(config).poll_once()
    assert result["published"] == [projection.catalog.cohort_sha256]
    assert result["held"] == []


def adopted_trigger(scores, revision="1"):
    return module.PublicModelScores.model_validate_json(
        canonical_json_bytes(
            scores.model_copy(
                update={
                    "schema_": "umi-public-cohort-model-results/3",
                    "certification": "quorum_certified_reward_adoption",
                    "original_allocation_sha256": scores.original_allocation_sha256
                    or scores.allocation_sha256,
                    "original_source_metadata_sha256": scores.original_source_metadata_sha256
                    or scores.source_metadata_sha256,
                    "reward_adoption_sha256": revision * 64,
                    "source_metadata_sha256": revision * 64,
                    "allocation_sha256": "9" * 64,
                }
            )
        )
    )


@pytest.mark.parametrize("initially_adopted", [False, True])
def test_selected_adoption_rebinds_catalog_trigger_without_native_work(
    watched, monkeypatch, initially_adopted
):
    config, projection, calls, trigger = watched
    original = module.PublicModelScores.model_validate_json(trigger.read_bytes())
    if initially_adopted:
        trigger.write_bytes(canonical_json_bytes(adopted_trigger(original)))
    owner = module.NativePublicCatalogWatcher(config)
    assert owner.poll_once()["held"] == []
    receipt_path = Path(config.state_directory) / (projection.catalog.cohort_sha256 + ".json")
    before = module.CatalogCompletion.model_validate_json(receipt_path.read_bytes()).checked()
    monkeypatch.setattr(module, "prepare_native_cohort", forbid_native)
    trigger.write_bytes(canonical_json_bytes(adopted_trigger(original, "2")))
    assert owner.poll_once()["held"] == []
    after = module.CatalogCompletion.model_validate_json(receipt_path.read_bytes()).checked()
    assert after.source_stamp != before.source_stamp
    assert after.score_metadata_sha256 == original.source_metadata_sha256
    assert canonical_json_bytes(after.projection) == canonical_json_bytes(before.projection)
    assert len(calls) == 1
    # A later adopted revision still names the original native metadata, and
    # a cold watcher restores the same catalog without admission/model reads.
    trigger.write_bytes(canonical_json_bytes(adopted_trigger(original, "3")))
    restarted = module.NativePublicCatalogWatcher(config)
    assert restarted.poll_once()["held"] == []
    monkeypatch.setattr(module, "read_owned_file", forbid_native)
    assert restarted.poll_once()["held"] == []
    assert len(calls) == 1


@pytest.mark.parametrize("change", ["source", "uid", "model", "policy"])
def test_adopted_trigger_cannot_rebind_another_catalog_source_or_roster(
    watched, monkeypatch, change
):
    config, projection, _, trigger = watched
    owner = module.NativePublicCatalogWatcher(config)
    assert owner.poll_once()["held"] == []
    receipt_path = Path(config.state_directory) / (projection.catalog.cohort_sha256 + ".json")
    retained = receipt_path.read_bytes()
    adopted = adopted_trigger(module.PublicModelScores.model_validate_json(trigger.read_bytes()))
    if change == "source":
        adopted = adopted.model_copy(update={"original_source_metadata_sha256": "7" * 64})
    elif change == "policy":
        adopted = adopted.model_copy(update={"policy_sha256": "7" * 64})
    else:
        item = adopted.items[0].model_copy(
            update={
                "uid": adopted.items[0].uid + 1,
            }
            if change == "uid"
            else {"model_sha256": "7" * 64}
        )
        adopted = adopted.model_copy(update={"items": (item,)})
    trigger.write_bytes(canonical_json_bytes(adopted))
    monkeypatch.setattr(module, "prepare_native_cohort", forbid_native)
    report = owner.poll_once()
    assert report["completed"] == 0 and report["held"][0]["stage"] == "adopted_score_catalog_rebind"
    assert receipt_path.read_bytes() == retained


def test_interrupted_output_publication_reuses_checkpoint(watched, monkeypatch):
    config, _, calls, _ = watched
    original = module.publish_native_cohort

    def interrupted(*args, **kwargs):
        raise OSError("interrupted public metadata publication")

    monkeypatch.setattr(module, "publish_native_cohort", interrupted)
    result = module.NativePublicCatalogWatcher(config).poll_once()
    assert result["held"][0]["stage"] == "public_catalog_output"
    monkeypatch.setattr(module, "publish_native_cohort", original)
    monkeypatch.setattr(module, "prepare_native_cohort", forbid_native)
    assert module.NativePublicCatalogWatcher(config).poll_once()["held"] == []
    assert len(calls) == 1


@pytest.mark.parametrize(
    "damage", ["receipt_missing", "receipt_damaged", "source_changed", "binding_changed"]
)
def test_completed_metadata_damage_is_explicit_repair_not_new_native_work(
    watched, monkeypatch, damage
):
    config, projection, _, trigger = watched
    assert module.NativePublicCatalogWatcher(config).poll_once()["held"] == []
    receipt = config.state_directory + "/" + projection.catalog.cohort_sha256 + ".json"
    from pathlib import Path

    if damage == "receipt_missing":
        Path(receipt).unlink()
    elif damage == "receipt_damaged":
        Path(receipt).write_bytes(b"{}")
    elif damage == "source_changed":
        trigger.write_bytes(trigger.read_bytes() + b" ")
    else:
        config = config.model_copy(
            update={
                "template": config.template.model_copy(
                    update={
                        "policy": config.template.policy.model_copy(update={"sha256": "a" * 64})
                    }
                )
            }
        )
    monkeypatch.setattr(module, "prepare_native_cohort", forbid_native)
    result = module.NativePublicCatalogWatcher(config).poll_once()
    assert result["completed"] == 0 and len(result["held"]) == 1
    assert result["stalled_or_retrying"] and result["eta_seconds"] is None


def test_unknown_cohort_is_refused_before_publication(watched):
    config, _, _, _ = watched
    changed = config.model_dump(mode="json", by_alias=True)
    changed["cohorts"] = ["e" * 64]
    with pytest.raises(ValueError, match="unknown native cohort"):
        module.NativePublicCatalogWatchConfig.model_validate_json(canonical_json_bytes(changed))


def legacy_case(watched, tmp_path, monkeypatch):
    import os

    from umi.competition_cohort_public_publisher import (
        LegacyPublicModelSource,
        PinnedPublicMetadata,
    )

    config, projection, _, _ = watched
    download = projection.downloads[0]
    model = download.model_sha256
    package = dict(
        schema="umi-cohort-model-preserved-package/1",
        model_sha256=model,
        native_bundle=download.bundle.model_dump(mode="json", by_alias=True),
        chunk_bytes=8 * 1024**2,
        files=[
            dict(
                path=f.path,
                chunks=[]
                if f.size_bytes == 0
                else [dict(sha256=f.sha256, size_bytes=f.size_bytes)],
            )
            for f in download.bundle.files
        ],
    )
    raw = canonical_json_bytes(package)
    sha = hashlib.sha256(raw).hexdigest()
    association = dict(
        schema="umi-cohort-model-backup-association/1",
        model_sha256=model,
        package_key=f"packages/{model}/{sha}.json",
        package_sha256=sha,
        verification="all_declared_bytes_uploaded_and_read_back",
        artifact_acceptance_certified=False,
    )
    pins = {}
    for name, body in [("package", raw), ("association", canonical_json_bytes(association))]:
        path = tmp_path / (name + ".json")
        path.write_bytes(body)
        path.chmod(0o600)
        pins[name] = PinnedPublicMetadata(
            path=str(path),
            sha256=hashlib.sha256(body).hexdigest(),
            owner_uid=os.getuid(),
            size_bytes=len(body),
        )
    source = LegacyPublicModelSource(model_sha256=model, **pins)
    config = config.model_copy(update={"legacy_sources": {download.cohort_sha256: (source,)}})
    projection = projection.model_copy(update={"downloads": ()})
    monkeypatch.setattr(module, "prepare_native_cohort", lambda *a, **k: projection)
    return config, source, PinnedPublicMetadata


def test_legacy_transport_checkpoint_survives_interruption_before_catalog_commit(
    watched, tmp_path, monkeypatch
):
    config, _, pin = legacy_case(watched, tmp_path, monkeypatch)
    original = module.atomic_write

    def interrupted(path, raw, **kwargs):
        if str(path).startswith(config.state_directory + "/") and kwargs.get("immutable") is False:
            raise OSError("interrupted catalog enrichment")
        return original(path, raw, **kwargs)

    monkeypatch.setattr(module, "atomic_write", interrupted)
    result = module.NativePublicCatalogWatcher(config).poll_once()
    assert result["held"][0]["stage"] == "legacy_public_transport_metadata"
    monkeypatch.setattr(module, "atomic_write", original)
    monkeypatch.setattr(module, "prepare_native_cohort", forbid_native)
    monkeypatch.setattr(pin, "read", forbid_native)
    result = module.NativePublicCatalogWatcher(config).poll_once()
    assert result["held"] == [] and result["completed"] == 1


@pytest.mark.parametrize("damage", ["missing", "damaged"])
def test_legacy_completed_transport_damage_is_explicit_repair(
    watched, tmp_path, monkeypatch, damage
):
    from pathlib import Path

    config, source, pin = legacy_case(watched, tmp_path, monkeypatch)
    original = module.atomic_write

    def interrupted(path, raw, **kwargs):
        if str(path).startswith(config.state_directory + "/") and kwargs.get("immutable") is False:
            raise OSError("interrupted catalog enrichment")
        return original(path, raw, **kwargs)

    monkeypatch.setattr(module, "atomic_write", interrupted)
    assert module.NativePublicCatalogWatcher(config).poll_once()["held"]
    path = Path(
        config.state_directory, "transports", config.cohorts[0], source.model_sha256 + ".json"
    )
    if damage == "missing":
        path.unlink()
    else:
        path.write_bytes(b"{}")
    monkeypatch.setattr(module, "atomic_write", original)
    monkeypatch.setattr(module, "prepare_native_cohort", forbid_native)
    monkeypatch.setattr(pin, "read", forbid_native)
    result = module.NativePublicCatalogWatcher(config).poll_once()
    assert result["held"] and result["stalled_or_retrying"]
    assert result["completed"] == 0
