"""Static approval bindings and durable retention; no chain authority implied."""

from types import SimpleNamespace

import pytest

from umi.competition_reward_decisions import StandingRewardControlReader
from umi.competition_reward_manifest import (
    MAX_REWARD_MANIFEST_BYTES,
    RewardReplayRequirement,
    StandingRewardManifest,
    retain_reward_manifest,
    verify_reward_manifest,
)
from umi.competition_reward_preparation import StandingRewardPreparation
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from .test_competition_reward_decisions import chain as chain
from .test_competition_reward_decisions import chain_config as chain_config
from .test_competition_reward_decisions import control as control
from .test_competition_reward_decisions import policy as policy
from .test_competition_reward_decisions import series_case as series_case


@pytest.fixture
def manifest_case(series_case, tmp_path):
    c = series_case
    manifest = StandingRewardManifest(
        schema="umi-standing-reward-manifest/1",
        policy_sha256=digest(c.control.policy),
        cohorts=tuple(
            RewardReplayRequirement(
                cohort_sha256=digest(plan),
                terms_sha256=f"{plan.sequence + 20:02x}" * 32,
                catalog_sha256s=(f"{plan.sequence + 30:02x}" * 32,),
            )
            for plan in c.series.cohorts
        ),
    )
    series = c.series.model_copy(update={"manifest_sha256": digest(manifest)})

    def reopen(**overrides):
        options = dict(
            expected_series_sha256=digest(series),
            expected_chain_config_sha256=digest(c.control.config),
            maximum_bytes=8 * 1024**2,
        )
        options.update(overrides)
        return StandingRewardControlReader(
            tmp_path / "manifest-reader", series, c.control.policy, **options
        )

    return SimpleNamespace(
        manifest=manifest, series=series, policy=c.control.policy, reader=reopen(), reopen=reopen
    )


def test_retained_six_cohort_manifest_survives_restart_and_host_capacity_change(manifest_case):
    c = manifest_case
    with pytest.raises(FileNotFoundError):
        retain_reward_manifest(c.reader, None)
    assert c.reader.journal.keys("reward_series_manifest") == []
    first = retain_reward_manifest(c.reader, c.manifest)
    # Changing provider configuration and local capacity does not change the
    # original approved scoring inputs. Current proof checks remain separate.
    c.reader = c.reopen(maximum_bytes=16 * 1024**2, expected_chain_config_sha256="ff" * 32)
    restored = retain_reward_manifest(c.reader, None)
    assert restored == first and restored is not first
    assert tuple(r.cohort_sha256 for r in restored.cohorts) == tuple(
        digest(p) for p in c.series.cohorts
    )
    assert c.reader.journal.keys("reward_series_manifest") == ["approved"]
    for entry in restored.cohorts:
        assert restored.requirement(entry.cohort_sha256) == entry
    with pytest.raises(ValueError, match="absent"):
        restored.requirement("ff" * 32)


@pytest.mark.parametrize("field", ["cohort_sha256", "terms_sha256", "catalog_sha256s"])
def test_changed_inputs_cannot_replace_approved_manifest(manifest_case, field):
    c = manifest_case
    retain_reward_manifest(c.reader, c.manifest)
    value = ("ff" * 32,) if field == "catalog_sha256s" else "ff" * 32
    changed = c.manifest.model_copy(
        update={
            "cohorts": (
                c.manifest.cohorts[0].model_copy(update={field: value}),
                *c.manifest.cohorts[1:],
            )
        }
    )
    with pytest.raises(ValueError, match="manifest differs"):
        retain_reward_manifest(c.reader, changed)
    assert retain_reward_manifest(c.reopen(), None) == c.manifest


@pytest.mark.parametrize("change", ["missing", "extra", "reordered", "duplicate"])
def test_manifest_requires_exact_ordered_series_even_when_digest_matches(manifest_case, change):
    c = manifest_case
    entries = c.manifest.cohorts
    if change == "missing":
        entries = entries[1:]
    elif change == "extra":
        entries += (entries[-1].model_copy(update={"cohort_sha256": "ff" * 32}),)
    elif change == "reordered":
        entries = tuple(reversed(entries))
    else:
        entries += entries[:1]
    manifest = c.manifest.model_copy(update={"cohorts": entries})
    series = c.series.model_copy(update={"manifest_sha256": digest(manifest)})
    with pytest.raises(ValueError, match=r"ordered series|repeats a cohort"):
        verify_reward_manifest(canonical_json_bytes(manifest), series, c.policy)


@pytest.mark.parametrize("change", ["pool", "runtime", "model_threshold", "policy_digest"])
def test_manifest_cannot_rebind_policy_or_runtime(manifest_case, change):
    c = manifest_case
    manifest, policy = c.manifest, c.policy
    if change == "pool":
        policy = policy.model_copy(update={"endpoint_reward_bps": 6000, "model_reward_bps": 4000})
    elif change == "runtime":
        policy = policy.model_copy(update={"evaluation_runtime_sha256": "ff" * 32})
    elif change == "model_threshold":
        policy = policy.model_copy(update={"minimum_score_bps": 1234})
    else:
        manifest = manifest.model_copy(update={"policy_sha256": "ff" * 32})
    series = c.series.model_copy(update={"manifest_sha256": digest(manifest)})
    with pytest.raises(ValueError, match="manifest policy differs"):
        verify_reward_manifest(canonical_json_bytes(manifest), series, policy)


@pytest.mark.parametrize("catalogs", [(), ("bb" * 32, "aa" * 32), ("aa" * 32,) * 2])
def test_catalog_selection_is_nonempty_unique_and_canonical(manifest_case, catalogs):
    c = manifest_case
    entry = c.manifest.cohorts[0].model_copy(update={"catalog_sha256s": catalogs})
    changed = c.manifest.model_copy(update={"cohorts": (entry, *c.manifest.cohorts[1:])})
    with pytest.raises(ValueError):
        verify_reward_manifest(canonical_json_bytes(changed), c.series, c.policy)


@pytest.mark.parametrize(
    "raw",
    [b"", b"{}", b"[", "not bytes", b" " * (MAX_REWARD_MANIFEST_BYTES + 1)],
    ids=["empty", "missing_fields", "malformed_json", "wrong_type", "oversized"],
)
def test_invalid_or_oversized_manifest_is_not_retained(manifest_case, raw):
    c = manifest_case
    with pytest.raises(ValueError):
        verify_reward_manifest(raw, c.series, c.policy)
    assert c.reader.journal.keys("reward_series_manifest") == []


def test_manifest_rejects_unknown_fields_and_invalid_schema(manifest_case):
    c = manifest_case
    for changes in ({"ready": True}, {"schema": "umi-standing-reward-manifest/99"}):
        raw = c.manifest.model_dump(mode="json", by_alias=True) | changes
        with pytest.raises(ValueError):
            verify_reward_manifest(canonical_json_bytes(raw), c.series, c.policy)


@pytest.mark.parametrize("commit", [False, True])
def test_retention_recovers_before_commit_failure_and_lost_reply(
    manifest_case, monkeypatch, commit
):
    c = manifest_case
    put = c.reader.journal.put

    def interrupted(*args):
        if commit:
            put(*args)
        raise OSError("interrupted retention")

    monkeypatch.setattr(c.reader.journal, "put", interrupted)
    with pytest.raises(OSError):
        retain_reward_manifest(c.reader, c.manifest)
    reader = c.reopen()
    if not commit:
        with pytest.raises(FileNotFoundError):
            retain_reward_manifest(reader, None)
    recovered = retain_reward_manifest(reader, None if commit else c.manifest)
    assert recovered == c.manifest


def test_retained_wrong_manifest_is_rejected_without_replacement(manifest_case):
    c = manifest_case
    changed = c.manifest.model_copy(update={"policy_sha256": "ff" * 32})
    c.reader.journal.put("reward_series_manifest", "approved", changed)
    with pytest.raises(ValueError, match="manifest differs"):
        retain_reward_manifest(c.reopen(), None)
    assert c.reader.journal.get("reward_series_manifest", "approved") == changed.model_dump(
        mode="json", by_alias=True
    )


def test_rebound_reader_is_not_an_independent_approval(manifest_case):
    c = manifest_case
    c.reader.series = c.series.model_copy(update={"manifest_sha256": "ff" * 32})
    with pytest.raises(ValueError, match="reader authority changed"):
        retain_reward_manifest(c.reader, c.manifest)
    assert c.reader.journal.keys("reward_series_manifest") == []


def test_preparation_rejects_manifest_change_before_reading_current_control(
    manifest_case, monkeypatch
):
    c = manifest_case
    # Only the store's policy binding participates in this early configuration
    # check; native package/store replay is covered by the integration suite.
    owner = StandingRewardPreparation(
        c.reader, SimpleNamespace(policy=c.policy), c.manifest, maximum_promotion_bytes=1_000_000
    )

    def forbidden(*args):
        pytest.fail("changed approval reached current-control selection")

    monkeypatch.setattr(c.reader, "select_history", forbidden)
    owner.manifest = c.manifest.model_copy(update={"policy_sha256": "ff" * 32})
    with pytest.raises(ValueError, match="authority changed"):
        owner._selected(None, None, None)
