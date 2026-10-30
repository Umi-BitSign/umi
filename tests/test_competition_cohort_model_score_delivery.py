"""Bounded public metadata delivery; no private award/proof replay."""

import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from umi import competition_cohort_model_score_delivery as module
from umi import competition_host_activation as activation
from umi.competition_cohort_model_scores import ModelScore, PublicModelScore, PublicModelScores
from umi.competition_geometric_rewards import cohort_reward_parameters
from umi.competition_public_results_directory import atomic_write, owned_directory
from umi.protocol import canonical_json_bytes

from .test_competition_cpu_efficiency_public import timed_public
from .test_open_competition import wallet


@pytest.fixture
def delivery(tmp_path, request):
    source, target, state = (tmp_path / name for name in ("source", "target", "state"))
    for path in (source, target):
        owned_directory(path, create=True)
    score = PublicModelScores(
        schema="umi-public-cohort-model-results/1",
        cohort_sha256="11" * 32,
        round_sha256="22" * 32,
        policy_sha256="33" * 32,
        allocation_sha256="44" * 32,
        certified_history_tip_sha256="55" * 32,
        source_metadata_sha256="66" * 32,
        certification="quorum_certified_native_allocation",
        items=(
            PublicModelScore(
                submission_sha256="77" * 32,
                model_sha256="88" * 32,
                uid=1,
                hotkey=wallet("Alice").hotkey.ss58_address,
                status="scored",
                aggregate=ModelScore(numerator="4", denominator="5", decimal=0.8),
                baseline_aggregate=ModelScore(numerator="1", denominator="2", decimal=0.5),
                score_rank=1,
                baseline_eligible=True,
                model_reward_status="selected_by_certified_rule",
                certified_raw_weight_for_hotkey=65535,
            ),
        ),
    )
    if getattr(request, "param", None) == "cpu":
        score = timed_public(score)
    name = score.cohort_sha256 + ".json"

    def reopen():
        return module.ModelScoreDelivery(
            source,
            target,
            state,
            source_uid=os.getuid(),
            destination_uid=os.getuid(),
            destination_gid=os.getgid(),
        )

    atomic_write(source / name, canonical_json_bytes(score))
    return SimpleNamespace(
        source=source, target=target, state=state, score=score, name=name, reopen=reopen
    )


def adopted(original, *, adoption="99" * 32, allocation="aa" * 32):
    timed = original.cpu_efficiency_adoption_sha256 is not None
    value = original.model_copy(
        update={
            "schema_": "umi-public-cohort-model-results/4"
            if timed
            else "umi-public-cohort-model-results/3",
            "certification": "quorum_certified_reward_adoption",
            "original_allocation_sha256": original.allocation_sha256,
            "original_source_metadata_sha256": original.source_metadata_sha256,
            "allocation_sha256": allocation,
            "reward_adoption_sha256": adoption,
            "reward_parameters": cohort_reward_parameters(8 if timed else 7),
            "efficiency_weight_applied": True if timed else None,
            "source_metadata_sha256": "ab" * 32,
            "items": tuple(
                r.model_copy(
                    update={
                        "baseline_threshold": ModelScore(
                            numerator="99", denominator="200", decimal=0.495
                        )
                    }
                )
                for r in original.items
            ),
        }
    )
    return PublicModelScores.model_validate_json(canonical_json_bytes(value))


@pytest.mark.parametrize("delivery", ["quality", "cpu"], indirect=True)
def test_delivery_restarts_without_reading_unchanged_payloads(delivery, monkeypatch):
    d = delivery
    owner = d.reopen()
    assert owner.deliver(d.name) is True
    owner.close()
    owner = d.reopen()

    def forbidden(*args, **kw):
        raise AssertionError("unchanged public snapshot was reread")

    monkeypatch.setattr(module, "_read", forbidden)
    try:
        assert owner.deliver(d.name) is False
    finally:
        owner.close()


@pytest.mark.parametrize("delivery", ["quality", "cpu"], indirect=True)
def test_atomic_adoption_and_later_revision_keep_same_source(delivery):
    d = delivery
    owner = d.reopen()
    try:
        owner.deliver(d.name)
        for sha in ("99" * 32, "cc" * 32):
            newer = adopted(d.score, adoption=sha)
            atomic_write(d.source / d.name, canonical_json_bytes(newer), immutable=False)
            assert owner.deliver(d.name)
            assert (d.target / d.name).read_bytes() == canonical_json_bytes(newer)
            assert not list(owner.scratch.glob("copy-*"))
        (d.target / d.name).unlink()
        assert owner.deliver(d.name)
    finally:
        owner.close()


@pytest.mark.parametrize("delivery", ["cpu"], indirect=True)
@pytest.mark.parametrize("change", ["contract", "slowdown", "factor"])
def test_timed_delivery_refuses_rewritten_measurements(delivery, change):
    d = delivery
    owner = d.reopen()
    try:
        owner.deliver(d.name)
        before = (d.target / d.name).read_bytes()
        newer = adopted(d.score)
        if change == "contract":
            newer = newer.model_copy(update={"cpu_efficiency_adoption_sha256": "fe" * 32})
        else:
            from umi.competition_cohort_model_scores import PublicCpuSlowdown

            update = (
                {"efficiency_multiplier_ppm": 1_150_000}
                if change == "factor"
                else {"normalized_cpu_slowdown": PublicCpuSlowdown.make(2)}
            )
            newer = newer.model_copy(update={"items": (newer.items[0].model_copy(update=update),)})
        atomic_write(d.source / d.name, canonical_json_bytes(newer), immutable=False)
        with pytest.raises(ValueError, match="replacement"):
            owner.deliver(d.name)
        assert (d.target / d.name).read_bytes() == before
    finally:
        owner.close()


@pytest.mark.parametrize(
    "mutation", ["policy", "roster", "source", "allocation", "old_schema", "same_adoption"]
)
def test_replacement_refuses_unrelated_or_rewritten_snapshots(delivery, mutation):
    d = delivery
    owner = d.reopen()
    try:
        owner.deliver(d.name)
        previous = (d.target / d.name).read_bytes()
        newer = adopted(d.score)
        if mutation == "policy":
            newer = newer.model_copy(update={"policy_sha256": "fe" * 32})
        elif mutation == "roster":
            newer = newer.model_copy(
                update={"items": (newer.items[0].model_copy(update={"uid": 2}),)}
            )
        elif mutation == "source":
            newer = newer.model_copy(update={"original_source_metadata_sha256": "fe" * 32})
        elif mutation == "allocation":
            newer = newer.model_copy(update={"original_allocation_sha256": "fe" * 32})
        elif mutation == "old_schema":
            newer = d.score.model_copy(update={"source_metadata_sha256": "fe" * 32})
        else:
            atomic_write(d.source / d.name, canonical_json_bytes(newer), immutable=False)
            owner.deliver(d.name)
            previous = (d.target / d.name).read_bytes()
            newer = newer.model_copy(update={"source_metadata_sha256": "fe" * 32})
        atomic_write(d.source / d.name, canonical_json_bytes(newer), immutable=False)
        with pytest.raises(ValueError, match="replacement"):
            owner.deliver(d.name)
        assert (d.target / d.name).read_bytes() == previous
    finally:
        owner.close()


@pytest.mark.parametrize("kind", ["source_symlink", "target_symlink", "oversize", "noncanonical"])
def test_unsafe_or_oversized_payloads_never_replace_target(delivery, kind):
    d = delivery
    owner = d.reopen()
    try:
        if kind == "target_symlink":
            (d.target / d.name).symlink_to(d.source / d.name)
        elif kind == "source_symlink":
            actual = d.source / "other"
            (d.source / d.name).rename(actual)
            (d.source / d.name).symlink_to(actual)
        elif kind == "oversize":
            with (d.source / d.name).open("wb") as stream:
                stream.truncate(module.MAXIMUM_BYTES + 1)
        else:
            (d.source / d.name).write_bytes(b" " + canonical_json_bytes(d.score))
        with pytest.raises((ValueError, OSError)):
            owner.deliver(d.name)
    finally:
        owner.close()


@pytest.mark.parametrize("damage", ["shape", "checksum", "missing", "binding", "symlink"])
def test_damaged_receipts_require_repair(delivery, damage):
    d = delivery
    owner = d.reopen()
    owner.deliver(d.name)
    receipt = owner.receipt
    saved = json.loads(receipt.read_bytes())
    owner.close()
    if damage == "missing":
        receipt.unlink()
    elif damage == "symlink":
        original = d.state / "elsewhere"
        receipt.rename(original)
        receipt.symlink_to(original)
    else:
        if damage == "shape":
            saved["items"][d.name]["source"] = ["bad"]
        elif damage == "checksum":
            saved["checksum"] = "ff" * 32
        else:
            valid = module.ScoreDeliveryCheckpoint.model_validate_json(canonical_json_bytes(saved))
            saved = (
                valid.model_copy(update={"binding_sha256": "ff" * 32})
                .sealed()
                .model_dump(mode="json", by_alias=True)
            )
        receipt.write_bytes(canonical_json_bytes(saved))
    with pytest.raises((ValueError, OSError)):
        d.reopen()


def test_interrupted_after_replace_before_receipt_recovers_without_false_fast_path(
    delivery, monkeypatch
):
    d = delivery
    owner = d.reopen()
    real = module.atomic_write

    def interrupted(path, *args, **kwargs):
        if path == owner.receipt:
            raise OSError("injected checkpoint interruption")
        return real(path, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(module, "atomic_write", interrupted)
        with pytest.raises(OSError, match="interruption"):
            owner.deliver(d.name)
    assert d.name not in owner.completed
    assert (d.target / d.name).read_bytes() == canonical_json_bytes(d.score)
    assert owner.deliver(d.name) is False
    owner.close()
    reopened = d.reopen()
    try:
        assert reopened.deliver(d.name) is False
    finally:
        reopened.close()


def test_interrupted_temp_is_cleaned_and_second_owner_is_excluded(delivery, monkeypatch):
    d = delivery
    owner = d.reopen()
    with pytest.raises(BlockingIOError):
        d.reopen()
    real = module.os.replace

    def interrupted(source, target):
        if Path(source).parent == owner.scratch:
            raise OSError("injected pre-publication failure")
        return real(source, target)

    with monkeypatch.context() as patch:
        patch.setattr(module.os, "replace", interrupted)
        with pytest.raises(OSError, match="pre-publication"):
            owner.deliver(d.name)
    assert not (d.target / d.name).exists()
    assert not list(owner.scratch.glob("copy-*"))
    abandoned = owner.scratch / "copy-interrupted-process"
    abandoned.write_bytes(b"partial")
    abandoned.chmod(0o600)
    owner.close()
    reopened = d.reopen()
    try:
        assert not abandoned.exists()
        assert reopened.deliver(d.name)
    finally:
        reopened.close()


def test_config_matches_installed_four_keys_and_unsafe_lease_refuses(
    delivery, tmp_path, monkeypatch
):
    d = delivery
    config = dict(
        schema="umi-native-public-model-score-delivery/1",
        source_directory=str(d.source),
        destination_directory=str(d.target),
        state_directory=str(d.state),
    )
    path = tmp_path / "delivery.json"
    path.write_text(json.dumps(config, indent=2) + "\n")
    path.chmod(0o444)
    monkeypatch.setattr(activation, "_root_owner_uid", os.getuid)
    assert module.load_config(path).model_dump(by_alias=True) == config
    with pytest.raises(ValueError):
        module.ModelScoreDeliveryConfig.model_validate({**config, "unexpected": 1})
    owned_directory(d.state, create=True)
    (d.state / "publisher.lock").symlink_to(path)
    with pytest.raises(OSError):
        d.reopen()


def test_live_checkpoint_change_cannot_hide_behind_memory_fast_path(delivery):
    d = delivery
    owner = d.reopen()
    try:
        owner.deliver(d.name)
        owner.receipt.write_bytes(b"{}")
        with pytest.raises(ValueError, match="checkpoint changed"):
            owner.deliver(d.name)
    finally:
        owner.close()
