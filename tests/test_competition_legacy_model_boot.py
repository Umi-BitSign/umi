"""Actual selected boot routes adopted legacy cohorts while preserving C5 paths."""

import asyncio
import sqlite3
from pathlib import Path
from types import SimpleNamespace

import pytest

from umi import competition_cohort_settlement_boot as settlement
from umi import competition_reward_boot as writer
from umi import competition_reward_coordinator_boot as coordinator
from umi.competition_cohort_direct_model_review import DirectModelSettlementVerifier
from umi.competition_cohort_legacy_model_selection import (
    AuthenticatedLegacyModelSources,
    LegacyModelStorageSourceConfig,
    authenticate_legacy_model_sources,
    selected_legacy_model_readers,
    validate_legacy_model_selections,
)
from umi.competition_cohort_legacy_model_storage import (
    LegacyModelPreservationInventory,
    LegacyModelStorageInventory,
    LegacyModelStorageRepairRequired,
)
from umi.competition_cohort_model_transport import prepare_model_delivery_adoption
from umi.competition_cohort_model_transport_selection import committed_model_delivery_selection
from umi.competition_cohort_recovery_store import CohortRecoveryStore
from umi.competition_model_cache_space import BootDiskModelCacheConfig
from umi.competition_supervisor_adapters import ProductionSuccessorRuntimeAdapter
from umi.open_competition import digest
from umi.private_files import ensure_private_directory, publish_private_model
from umi.protocol import canonical_json_bytes, sha256_hex

from .test_competition_chunked_model_backup import Remote
from .test_competition_cohort_legacy_model_storage import backup, bundle_at, retain
from .test_competition_cohort_recovery import signed_transition
from .test_competition_effective_model_reward_boot import adopted_case as adopted_case
from .test_competition_effective_model_reward_boot import chain as chain
from .test_competition_effective_model_reward_boot import chain_config as chain_config
from .test_competition_effective_model_reward_boot import config_case as config_case
from .test_competition_effective_model_reward_boot import control as control
from .test_competition_effective_model_reward_boot import inputs as inputs
from .test_competition_effective_model_reward_boot import policy as policy
from .test_competition_effective_model_reward_boot import selected as selected
from .test_competition_effective_model_reward_boot import series_case as series_case
from .test_open_competition import wallet


@pytest.fixture
def legacy_boot(adopted_case, tmp_path):
    h = adopted_case
    bundle = bundle_at(tmp_path / "baseline", "legacy-boot-baseline")
    objects = {}
    common = dict(
        cohort_sha256=digest(h.history.plan),
        policy_sha256=digest(h.candidate.policy),
        authority_sha256=digest(h.history.authority.authority),
        predecessor_sha256=digest(h.history.genesis),
    )
    legacy = LegacyModelStorageInventory(
        schema="umi-cohort-legacy-model-storage-inventory/1",
        **common,
        captured_at_block=220,
        baseline_model_sha256=digest(bundle),
        baseline_manifest_raw_sha256=retain(objects, bundle),
        entries=(),
    )
    preservation = LegacyModelPreservationInventory(
        schema="umi-cohort-legacy-model-preservation-inventory/1",
        **common,
        legacy_inventory_sha256=digest(legacy),
        models=(backup(objects, bundle, h.candidate.policy),),
    )
    proposal = prepare_model_delivery_adoption(
        h.history,
        h.candidate.policy,
        expected_tip_sha256=digest(h.history.genesis),
        current_block=220,
        delivery=h.selection.history.transitions[0].transition.model_delivery_adoption.delivery,
        legacy_inventory_sha256=digest(legacy),
        preservation_inventory_sha256=digest(preservation),
    )
    db = sqlite3.connect(":memory:")
    try:
        store = CohortRecoveryStore(db)
        store.publish_history(h.history, h.candidate.policy, current_block=220)
        store.reserve_exact(proposal)
        store.commit(signed_transition(proposal))
        selection = committed_model_delivery_selection(
            store, common["cohort_sha256"], h.candidate.policy
        )
    finally:
        db.close()
    directory = tmp_path / "legacy-source"
    ensure_private_directory(directory)
    ensure_private_directory(directory / "objects")
    publish_private_model(directory / "legacy-inventory.json", legacy)
    publish_private_model(directory / "preservation-inventory.json", preservation)
    for key, raw in objects.items():
        path = directory / "objects" / (key + ".json")
        path.write_bytes(raw)
        path.chmod(0o600)
    source = LegacyModelStorageSourceConfig(
        schema="umi-legacy-model-storage-source/1",
        cohort_sha256=common["cohort_sha256"],
        directory=str(directory),
        baseline_model_sha256=digest(bundle),
    )
    config = type(h.candidate).model_validate_json(
        canonical_json_bytes(
            h.candidate.model_copy(
                update={"model_delivery_adoptions": (selection,), "legacy_model_storage": (source,)}
            )
        )
    )
    return SimpleNamespace(
        h=h, config=config, source=source, bundle=bundle, objects=objects, selection=selection
    )


def preflight(value):
    return authenticate_legacy_model_sources(
        value.legacy_model_storage,
        series=value.series,
        policy=value.policy,
        model_delivery_adoptions=value.model_delivery_adoptions,
    )


def test_selected_metadata_authenticates_before_binding_remote_namespace(legacy_boot, tmp_path):
    c = legacy_boot
    prepared = preflight(c.config)
    remote = Remote({})
    sources = selected_legacy_model_readers(
        prepared, multipart=remote, verification_root=tmp_path / "durable"
    )
    assert sources.has_cohort(c.source.cohort_sha256)
    assert sources.resolve(c.source.cohort_sha256, baseline=True).selection.bundle == c.bundle
    assert not remote.reads
    remote.signer.bucket = "other-bucket"
    with pytest.raises(ValueError, match="credentialed R2 namespace"):
        selected_legacy_model_readers(
            prepared, multipart=remote, verification_root=tmp_path / "durable"
        )


@pytest.mark.parametrize(
    "fault",
    [
        "cohort",
        "duplicate",
        "baseline",
        "inventory",
        "missing_original",
        "corrupt_original",
        "symlink_original",
    ],
)
def test_unsupported_or_damaged_selections_refuse_preflight(legacy_boot, fault, tmp_path):
    c = legacy_boot
    config, source = c.config, c.source
    if fault in {"cohort", "duplicate", "baseline"}:
        changed = (
            source.model_copy(
                update={
                    "cohort_sha256" if fault == "cohort" else "baseline_model_sha256": "ff" * 32,
                }
            )
            if fault != "duplicate"
            else source
        )
        config = config.model_copy(
            update={
                "legacy_model_storage": (changed, changed) if fault == "duplicate" else (changed,)
            }
        )
    elif fault == "inventory":
        (Path(source.directory) / "legacy-inventory.json").write_bytes(b"{}")
    else:
        key = next(iter(c.objects))
        path = Path(source.directory) / "objects" / (key + ".json")
        if fault == "missing_original":
            path.unlink()
        elif fault == "corrupt_original":
            path.write_bytes(b"{}")
        else:
            original = tmp_path / "moved-original.json"
            path.rename(original)
            path.symlink_to(original)
    with pytest.raises(ValueError):
        preflight(config)


def test_old_config_bytes_and_empty_source_selection_remain_unchanged(legacy_boot):
    c = legacy_boot
    original = canonical_json_bytes(c.h.before)
    assert b'"legacy_model_storage"' not in original
    assert canonical_json_bytes(type(c.h.before).model_validate_json(original)) == original
    assert preflight(c.h.before) is None
    assert (
        validate_legacy_model_selections(
            (), series=c.h.before.series, policy=c.h.before.policy, model_delivery_adoptions=()
        )
        == ()
    )


def operation(c, monkeypatch, *, forbid=False):
    h = c.h
    boot = {"writer": writer, "coordinator": coordinator, "settlement": settlement}[h.kind]

    class Provider:
        def __init__(self, *args, **kwargs):
            assert not forbid, "damaged storage reached provider startup"
            self.policy = c.config.policy

        async def start(self):
            pass

        async def aclose(self):
            pass

    if h.kind == "writer":
        runtime = SimpleNamespace(
            config=h.inputs.anchor.config,
            adapter=object.__new__(ProductionSuccessorRuntimeAdapter),
            _require_lease=lambda: None,
        )
        return boot, lambda: writer.run_installed_standing_rewards(
            runtime, c.config, asyncio.Event()
        )

    def key(*args):
        assert not forbid, "damaged storage reached signing key"
        return wallet("Charlie")

    monkeypatch.setattr(boot, "load_named_hotkey", key)
    monkeypatch.setattr(
        boot,
        "HistoricalRewardControlProvider"
        if h.kind == "coordinator"
        else "HistoricalRegistrationProvider",
        Provider,
    )
    return (
        boot,
        lambda: (
            coordinator.run_reward_coordinator(c.config, asyncio.Event())
            if h.kind == "coordinator"
            else settlement.run_settlement_service(c.config, asyncio.Event())
        ),
    )


async def test_actual_boot_passes_series_sources_and_preserves_c5_fallback(
    legacy_boot, monkeypatch
):
    c = legacy_boot
    boot, run = operation(c, monkeypatch)
    remote, captured = Remote({}), []

    class ReachedVerifier(Exception):
        pass

    def artifacts(config, policy, owner, *, verification_root):
        return SimpleNamespace(
            config=config, policy=policy, multipart=remote, verification_root=verification_root
        )

    def verifier(*args, **kwargs):
        selected = DirectModelSettlementVerifier(*args, **kwargs)
        c5 = next(digest(plan) for plan in c.config.series.cohorts if plan.sequence == 5)
        assert selected.legacy_for(c5) is None
        assert selected.legacy_for(
            c.source.cohort_sha256
        ).authenticated.legacy.baseline_model_sha256 == digest(c.bundle)
        assert selected.legacy_readers.verification_root.name == "legacy-model-byte-verification"
        captured.append(
            (selected.archive, selected.receipts, selected.legacy_readers.verification_root)
        )
        raise ReachedVerifier

    monkeypatch.setattr(boot, "DirectModelArtifactReviewer", artifacts)
    monkeypatch.setattr(boot, "DirectModelSettlementVerifier", verifier)
    for _ in range(2):
        with pytest.raises(ReachedVerifier):
            await run()
    assert captured[0] == captured[1]
    assert not remote.reads


async def test_actual_boot_damaged_original_refuses_before_service_state_or_keys(
    legacy_boot, monkeypatch
):
    c = legacy_boot
    _, run = operation(c, monkeypatch, forbid=True)
    (Path(c.source.directory) / "objects" / (next(iter(c.objects)) + ".json")).unlink()
    with pytest.raises(LegacyModelStorageRepairRequired):
        await run()


def test_original_loader_retains_supported_package_bound_above_legacy_signed_record_bound(tmp_path):
    # Preserved package metadata supports 64 MiB; signed /1 records have a
    # separate 33 MiB bound. The shared loader must not narrow the package reader.
    raw = b'{"document":"' + b"x" * (33 * 1024**2) + b'"}'
    key = sha256_hex(raw)
    path = tmp_path / (key + ".json")
    path.write_bytes(raw)
    path.chmod(0o600)
    sources = AuthenticatedLegacyModelSources(None, {}, {key: (path,)})
    assert sources.load_original(key) == raw
    path.write_bytes(b"{}")
    with pytest.raises(LegacyModelStorageRepairRequired, match="raw identity"):
        sources.load_original(key)


def test_config_keeps_original_metadata_outside_the_entire_disposable_cache(legacy_boot, tmp_path):
    c = legacy_boot
    cache = BootDiskModelCacheConfig(
        schema="umi-boot-disk-model-cache/1",
        directory=str(tmp_path / "disposable"),
        maximum_allocated_bytes=80 * 1024**3,
    )
    direct = c.config.direct_model_review.model_copy(
        update={"materialization_boot_disk_cache": cache}
    )
    candidate = c.config.model_copy(update={"direct_model_review": direct})
    assert type(candidate).model_validate_json(
        canonical_json_bytes(candidate)
    ).legacy_model_storage == (c.source,)
    for path in (Path(cache.directory), Path(cache.directory) / "metadata"):
        damaged = candidate.model_copy(
            update={"legacy_model_storage": (c.source.model_copy(update={"directory": str(path)}),)}
        )
        with pytest.raises(ValueError, match="disjoint"):
            type(damaged).model_validate_json(canonical_json_bytes(damaged))


def shared_selection(c, tmp_path):
    from umi.competition_model_byte_store import ModelByteStoreConfig

    store = ModelByteStoreConfig(
        schema="umi-model-byte-verification-store/1", directory=str(tmp_path / "shared-facts")
    )
    source = c.source.model_copy(update={"shared_byte_store": store})
    return type(c.config).model_validate_json(
        canonical_json_bytes(c.config.model_copy(update={"legacy_model_storage": (source,)}))
    )


def test_explicit_byte_store_is_in_every_consumer_store_inventory(legacy_boot, tmp_path):
    c = legacy_boot
    selected = shared_selection(c, tmp_path)
    roots = selected.mutable_stores() if c.h.kind == "writer" else selected.stores()
    shared = Path(selected.legacy_model_storage[0].shared_byte_store.directory)
    assert roots.count(shared) == 1
    protected = [roots[0], selected.direct_model_review.r2_credentials_file]
    if c.h.kind != "writer":
        protected.append(selected.signer_key_file)
    for path in protected:
        source = selected.legacy_model_storage[0]
        source = source.model_copy(
            update={
                "shared_byte_store": source.shared_byte_store.model_copy(
                    update={"directory": str(path)}
                )
            }
        )
        with pytest.raises(ValueError, match="overlaps"):
            type(selected).model_validate_json(
                canonical_json_bytes(
                    selected.model_copy(update={"legacy_model_storage": (source,)})
                )
            )


async def test_actual_consumer_boot_forwards_selected_shared_store(
    legacy_boot, tmp_path, monkeypatch
):
    c = legacy_boot
    c.config = shared_selection(c, tmp_path)
    boot, run = operation(c, monkeypatch)
    remote = Remote({})
    selected_root = Path(c.config.legacy_model_storage[0].shared_byte_store.directory)

    class ReachedVerifier(Exception):
        pass

    def artifacts(config, policy, owner, *, verification_root):
        return SimpleNamespace(
            config=config, policy=policy, multipart=remote, verification_root=verification_root
        )

    def verifier(*args, **kwargs):
        selected = DirectModelSettlementVerifier(*args, **kwargs)
        resolution = selected.legacy_readers.resolve(c.source.cohort_sha256, baseline=True)
        assert selected.legacy_readers.reader(resolution).root == selected_root
        assert selected_root.stat().st_mode & 0o077 == 0
        raise ReachedVerifier

    monkeypatch.setattr(boot, "DirectModelArtifactReviewer", artifacts)
    monkeypatch.setattr(boot, "DirectModelSettlementVerifier", verifier)
    for _ in range(2):
        with pytest.raises(ReachedVerifier):
            await run()
    assert not remote.reads


@pytest.mark.parametrize("adopted_case", ["writer"], indirect=True)
def test_writer_shared_store_cannot_alias_installed_host_roots(legacy_boot, tmp_path):
    c = legacy_boot
    selected = shared_selection(c, tmp_path)
    host = c.h.inputs.anchor.config
    writer.validate_writer_byte_store_paths(selected, host)
    for path in (
        host.state_root,
        host.worker_state_root,
        host.wallet.path,
        host.release_root,
        host.operator_input_root,
    ):
        source = selected.legacy_model_storage[0]
        for directory in (path, str(Path(path) / "byte-facts")):
            source = source.model_copy(
                update={
                    "shared_byte_store": source.shared_byte_store.model_copy(
                        update={"directory": directory}
                    )
                }
            )
            with pytest.raises(ValueError, match="overlaps"):
                writer.validate_writer_byte_store_paths(
                    selected.model_copy(update={"legacy_model_storage": (source,)}), host
                )


def test_original_verification_reused_by_real_reader_after_restart(
    legacy_boot, tmp_path, monkeypatch
):
    c = legacy_boot
    root = tmp_path / "original-verification"

    def prepare():
        return authenticate_legacy_model_sources(
            c.config.legacy_model_storage,
            series=c.config.series,
            policy=c.config.policy,
            model_delivery_adoptions=c.config.model_delivery_adoptions,
            original_verification_directory=root,
        )

    prepare()

    def no_original(*args, **kwargs):
        raise AssertionError("unchanged originals must not be reread or reverified")

    monkeypatch.setattr(AuthenticatedLegacyModelSources, "load_original", no_original)
    monkeypatch.setattr(
        "umi.competition_cohort_legacy_model_reuse.resolve_legacy_model_storage", no_original
    )
    prepared = prepare()
    remote = Remote({})
    readers = selected_legacy_model_readers(
        prepared, multipart=remote, verification_root=tmp_path / "durable"
    )
    assert readers.resolve(c.source.cohort_sha256, baseline=True).selection.bundle == c.bundle
    assert not remote.reads


@pytest.mark.parametrize("damage", ["missing", "corrupt"])
def test_completed_original_receipt_requires_explicit_repair(legacy_boot, tmp_path, damage):
    c = legacy_boot
    root = tmp_path / "original-verification"

    def prepare(**extra):
        return authenticate_legacy_model_sources(
            c.config.legacy_model_storage,
            series=c.config.series,
            policy=c.config.policy,
            model_delivery_adoptions=c.config.model_delivery_adoptions,
            original_verification_directory=root,
            **extra,
        )

    prepare()
    (receipt,) = root.glob("*/*/*.json")
    if damage == "missing":
        receipt.unlink()
    else:
        receipt.write_bytes(b"{damaged receipt")
    with pytest.raises(LegacyModelStorageRepairRequired, match="explicit repair required"):
        prepare()
    repaired = prepare(original_verification_repair_reason="fixture missing/damaged receipt repair")
    assert repaired.authenticated
    prepare()  # A normal restarted owner reuses the explicitly repaired result.


def test_changed_original_still_refuses_after_completed_reuse(legacy_boot, tmp_path):
    c = legacy_boot
    root = tmp_path / "original-verification"

    def prepare():
        return authenticate_legacy_model_sources(
            c.config.legacy_model_storage,
            series=c.config.series,
            policy=c.config.policy,
            model_delivery_adoptions=c.config.model_delivery_adoptions,
            original_verification_directory=root,
        )

    prepared = prepare()
    selected = next(iter(prepared.authenticated.values()))
    path = (
        Path(c.source.directory)
        / "objects"
        / (selected.legacy.baseline_manifest_raw_sha256 + ".json")
    )
    path.write_bytes(path.read_bytes() + b" ")
    with pytest.raises(LegacyModelStorageRepairRequired):
        prepare()


def test_original_receipt_survives_marker_publication_interruption(
    legacy_boot, tmp_path, monkeypatch
):
    import umi.competition_cohort_legacy_model_reuse as reuse

    c = legacy_boot
    root = tmp_path / "original-verification"

    def prepare():
        return authenticate_legacy_model_sources(
            c.config.legacy_model_storage,
            series=c.config.series,
            policy=c.config.policy,
            model_delivery_adoptions=c.config.model_delivery_adoptions,
            original_verification_directory=root,
        )

    native = reuse.remember_metadata_completion

    def interrupted(path):
        raise RuntimeError("interrupted before completion marker")

    monkeypatch.setattr(reuse, "remember_metadata_completion", interrupted)
    with pytest.raises(RuntimeError, match="completion marker"):
        prepare()

    def no_original(*args, **kwargs):
        raise AssertionError("an intact published receipt must not repeat completed verification")

    monkeypatch.setattr(reuse, "remember_metadata_completion", native)
    monkeypatch.setattr(AuthenticatedLegacyModelSources, "load_original", no_original)
    prepare()
    assert list(root.glob("*/*/*.complete"))


def test_original_receipts_preserve_explicit_disk_reserve(legacy_boot, tmp_path, monkeypatch):
    c = legacy_boot
    monkeypatch.setenv("UMI_LEGACY_ORIGINAL_RECEIPT_MIN_FREE_BYTES", str(2**62))
    root = tmp_path / "original-verification"
    with pytest.raises(OSError, match="physical reserve"):
        authenticate_legacy_model_sources(
            c.config.legacy_model_storage,
            series=c.config.series,
            policy=c.config.policy,
            model_delivery_adoptions=c.config.model_delivery_adoptions,
            original_verification_directory=root,
        )
    assert not list(root.glob("*/*/*.json"))


def test_unchanged_authenticated_context_is_not_serialized_again(
    legacy_boot, tmp_path, monkeypatch
):
    import umi.competition_cohort_legacy_model_reuse as reuse

    c = legacy_boot
    root = tmp_path / "original-verification"
    prepared = authenticate_legacy_model_sources(
        c.config.legacy_model_storage,
        series=c.config.series,
        policy=c.config.policy,
        model_delivery_adoptions=c.config.model_delivery_adoptions,
        original_verification_directory=root,
    )
    authenticated = prepared.authenticated[c.source.cohort_sha256]
    original = reuse.digest
    protected = (
        authenticated.policy,
        authenticated.original_history,
        authenticated.original_history.plan,
        authenticated.legacy,
        authenticated.preservation,
    )

    def no_repeat(value):
        assert all(value is not model for model in protected), (
            "unchanged immutable input was serialized again"
        )
        return original(value)

    monkeypatch.setattr(reuse, "digest", no_repeat)
    remote = Remote({})
    readers = selected_legacy_model_readers(
        prepared, multipart=remote, verification_root=tmp_path / "durable"
    )
    assert readers.resolve(c.source.cohort_sha256, baseline=True).selection.bundle == c.bundle
    assert not remote.reads


def test_original_receipt_context_keeps_existing_wire_bytes(legacy_boot, tmp_path):
    import json

    from umi.competition_verification_rules import runtime_identity

    c = legacy_boot
    root = tmp_path / "original-verification"
    prepared = authenticate_legacy_model_sources(
        c.config.legacy_model_storage,
        series=c.config.series,
        policy=c.config.policy,
        model_delivery_adoptions=c.config.model_delivery_adoptions,
        original_verification_directory=root,
    )
    value = prepared.authenticated[c.source.cohort_sha256]
    (receipt,) = root.glob("*/*/*.json")
    data = json.loads(receipt.read_bytes())
    expected = digest(
        [
            "umi-legacy-original-resolution/1",
            runtime_identity(),
            digest(value.policy),
            digest(value.original_history),
            value.adoption_block,
            digest(value.legacy),
            digest(value.preservation),
            value.preservation.models[0].endpoint,
            value.preservation.models[0].bucket,
            None,
            True,
            None,
        ]
    )
    assert data["context"] == expected
