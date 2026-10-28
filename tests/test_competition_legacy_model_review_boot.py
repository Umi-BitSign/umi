"""Actual phase-review startup preserves /1 approval and runs the R2 sandbox.

Chain finality, owner history transport, R2 and final CPU inference are inert
boundaries. Config, selected metadata, signing, journals, HTTP vote route,
native sandbox/cache and restart are real.
"""

import json
import logging
import os
import sqlite3
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from umi import competition_cohort_direct_model_review as direct
from umi import competition_cohort_review_boot as boot
from umi import competition_host_activation as activation
from umi.competition_cohort_admission_queue import CohortAdmissionQueue
from umi.competition_cohort_intake import history_tip
from umi.competition_cohort_legacy_model_selection import LegacyModelStorageSourceConfig
from umi.competition_cohort_model_acceptance import ModelArtifactVote, check_model_vote
from umi.competition_cohort_model_review_http import VOTE_PATH
from umi.competition_cohort_model_transport_selection import CommittedModelDeliveryHistory
from umi.competition_cohort_review_config import PhaseReviewServiceConfig
from umi.competition_reward_decisions import StandingRewardSeries
from umi.competition_reward_manifest import RewardReplayRequirement, StandingRewardManifest
from umi.grandpa_finality import FINNEY_GENESIS_HASH
from umi.open_competition import digest, identity
from umi.private_files import ensure_private_directory, publish_private_model
from umi.protocol import canonical_json_bytes

from .test_competition_chain import chain_config as chain_config
from .test_competition_cohort_intake import capture_at
from .test_competition_cohort_legacy_model_review import base_policy as base_policy
from .test_competition_cohort_legacy_model_review import case as case
from .test_competition_cohort_legacy_model_review import installed as installed
from .test_competition_cohort_legacy_model_review import legacy_scenario as legacy_scenario
from .test_competition_cohort_legacy_model_review import policy as policy
from .test_competition_cohort_legacy_model_review import prepared as prepared
from .test_competition_cohort_legacy_model_review import receipt_scenario as receipt_scenario
from .test_competition_cohort_legacy_model_review import recovery as recovery
from .test_competition_cohort_legacy_model_review import review as review
from .test_competition_cohort_legacy_model_review import runtime as runtime
from .test_competition_cohort_legacy_model_sandbox import attempt, cpu_readback
from .test_competition_cohort_review_boot import config_for, direct_r2_credentials, with_benchmark
from .test_open_competition import wallet

pytestmark = [
    pytest.mark.parametrize("receipt_scenario", ["model-awards"], indirect=True),
    pytest.mark.parametrize("recovery", ["legacy6"], indirect=True),
]


@pytest.fixture
def selected(review, chain_config, tmp_path, monkeypatch):
    r, i = review, review.installed
    manifest = StandingRewardManifest(
        schema="umi-standing-reward-manifest/1",
        policy_sha256=digest(i.case.policy),
        cohorts=(
            RewardReplayRequirement(
                cohort_sha256=i.case.cohort,
                terms_sha256="12" * 32,
                catalog_sha256s=("13" * 32,),
            ),
        ),
    )
    series = StandingRewardSeries(
        schema="umi-standing-reward-series/1",
        genesis_hash=FINNEY_GENESIS_HASH,
        netuid=78,
        policy_sha256=digest(i.case.policy),
        policy_epoch=1,
        manifest_sha256=digest(manifest),
        control_hotkey=wallet("Ferdie").hotkey.ss58_address,
        recovery=i.case.history.authority,
        cohorts=(i.case.history.plan,),
        validators=tuple(
            sorted(
                (wallet("Charlie").hotkey.ss58_address, wallet("Dave").hotkey.ss58_address),
                key=identity,
            )
        ),
        maximum_proof_lag_blocks=32,
        maximum_transaction_lifetime_blocks=128,
        lifetime="until_superseded_or_revoked",
    )
    chain = chain_config.model_copy(
        update={"proof_rpc_fallback_urls": ("wss://second.example.org", "wss://third.example.org")}
    )
    old = with_benchmark(
        config_for(
            SimpleNamespace(series=series, policy=i.case.policy, manifest=manifest, chain=chain),
            tmp_path / "phase-review",
        )
    )
    signing = old.model_signing.model_copy(update={"archive_directory": str(i.case.owner.archive)})
    benchmark = old.benchmark.model_copy(
        update={
            "archive_directory": signing.archive_directory,
            "workspace_directory": str(
                Path(i.artifacts.config.materialization_boot_disk_cache.directory) / "host-cpu"
            ),
        }
    )
    old = PhaseReviewServiceConfig.model_validate_json(
        canonical_json_bytes(
            old.model_copy(
                update={
                    "model_signing": signing,
                    "benchmark": benchmark,
                    "eligible_tracks": ("model",),
                }
            )
        )
    )
    history = i.case.owner.intake.history(i.case.cohort)
    selection = CommittedModelDeliveryHistory(
        schema="umi-committed-model-delivery-history/1",
        history=history,
        committed_tip_sha256=history_tip(history),
        observed_at_block=221,
    )
    source = LegacyModelStorageSourceConfig(
        schema="umi-legacy-model-storage-source/1",
        cohort_sha256=i.case.cohort,
        directory=str(tmp_path / "legacy-metadata"),
        baseline_model_sha256=digest(i.case.baseline),
        incumbent_model_sha256s=(digest(i.incumbent),),
    )
    c = PhaseReviewServiceConfig.model_validate_json(
        canonical_json_bytes(
            old.model_copy(
                update={
                    "schema_": "umi-cohort-phase-review-service/7",
                    "eligible_tracks": ("model",),
                    "model_signing": signing,
                    "benchmark": benchmark,
                    "direct_model_review": i.artifacts.config,
                    "model_delivery_adoptions": (selection,),
                    "legacy_model_storage": (source,),
                }
            )
        )
    )
    auth = i.sources.authenticated[i.case.cohort]
    root = Path(source.directory)
    publish_private_model(root / "legacy-inventory.json", auth.legacy)
    publish_private_model(root / "preservation-inventory.json", auth.preservation)
    ensure_private_directory(root / "objects")
    for key, raw in i.case.objects.items():
        path = root / "objects" / (key + ".json")
        path.write_bytes(raw)
        path.chmod(0o600)
    publish_private_model(
        Path(c.model_signing.approvals_directory) / (i.request.acceptance.model_sha256 + ".json"),
        r.inputs,
    )
    ensure_private_directory(Path(c.owner_token_file).parent)
    for path, token in (
        (c.owner_token_file, "owner-token" * 4),
        (c.vote_token_file, "vote-token" * 4),
    ):
        Path(path).write_text(token + "\n")
        Path(path).chmod(0o440)
    direct_r2_credentials(c)
    state = SimpleNamespace(events=[], online=True)

    class Provider:
        def __init__(self, _chain, policy):
            self.policy = policy
            state.events.append("provider-created")

        async def start(self):
            state.events.append("provider-started")

        async def collect(self):
            assert state.online, "completed /1 vote should not collect new finality"
            return capture_at(230)

        async def aclose(self):
            state.events.append("provider-closed")

    async def owned_history(cohort):
        assert state.online, "completed /1 vote should not fetch new owner history"
        return CohortAdmissionQueue(i.case.owner.intake).history(cohort)

    monkeypatch.setattr(activation, "_root_owner_uid", os.getuid)
    monkeypatch.setattr(boot, "HistoricalRegistrationProvider", Provider)
    monkeypatch.setattr(boot, "load_named_hotkey", lambda *_: wallet("Dave"))
    monkeypatch.setattr(boot, "AdmissionHistoryReader", lambda *_args, **_kwargs: owned_history)
    monkeypatch.setattr(direct, "R2MultipartClient", lambda *_args, **_kwargs: i.remote)
    return SimpleNamespace(config=c, original=old, source=source, installed=i, state=state)


async def vote(app, request):
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://review.example"
    ) as client:
        response = await client.post(
            VOTE_PATH,
            headers={
                "authorization": "Bearer " + "vote-token" * 4,
                "content-type": "application/json",
            },
            content=canonical_json_bytes(request),
        )
    assert response.status_code == 200, response.text
    return response.content


def test_omitted_storage_selection_keeps_old_canonical_config_bytes(selected):
    raw = canonical_json_bytes(selected.original)
    assert b'"legacy_model_storage"' not in raw
    assert canonical_json_bytes(PhaseReviewServiceConfig.model_validate_json(raw)) == raw
    assert canonical_json_bytes(selected.config.series) == canonical_json_bytes(
        selected.original.series
    )
    assert canonical_json_bytes(selected.config.manifest) == canonical_json_bytes(
        selected.original.manifest
    )
    assert selected.config.model_signing == selected.original.model_signing
    assert selected.config.benchmark == selected.original.benchmark
    assert selected.config.signing == selected.original.signing


@pytest.mark.parametrize("shared", [False, True])
async def test_real_phase_review_boot_signs_original_and_runs_retained_sandbox_after_restart(
    selected, monkeypatch, caplog, tmp_path, shared
):
    s, i, c = selected, selected.installed, selected.config
    if shared:
        from umi.competition_model_byte_store import ModelByteStoreConfig

        source = s.source.model_copy(
            update={
                "shared_byte_store": ModelByteStoreConfig(
                    schema="umi-model-byte-verification-store/1",
                    directory=str(tmp_path / "shared-bytes"),
                )
            }
        )
        c = PhaseReviewServiceConfig.model_validate_json(
            canonical_json_bytes(c.model_copy(update={"legacy_model_storage": (source,)}))
        )
        assert Path(source.shared_byte_store.directory) in c.stores()
    caplog.set_level(logging.INFO, logger="umi.competition.progress")
    first_vote, inodes, reads = None, None, None
    job = i.job.model_copy(update={"evaluator_hotkey": c.signing.signer})
    for restart in (False, True):
        async with boot.phase_review_app(c) as app:
            raw_vote = await vote(app, i.request)
            result = ModelArtifactVote.model_validate_json(raw_vote)
            check_model_vote(result, i.request.acceptance, i.case.policy, signer=c.signing.signer)
            assert result.acceptance.direct_artifact is None
            port = app.state.benchmark.sandbox
            assert port.legacy_artifacts is not None
            assert (
                port.legacy_artifacts.legacy.sources.authenticated[i.case.cohort].legacy
                == i.sources.authenticated[i.case.cohort].legacy
            )
            cpu_readback(port, i, monkeypatch)
            if not restart:
                await port.invoke(job, attempt(job, 1))
            assert await port.invoke(job, attempt(job)) == "inert-cpu-result"
            current = {
                str(path): path.stat().st_ino
                for directory in (
                    c.signing.directory,
                    c.model_signing.directory,
                    c.benchmark.directory,
                )
                for path in Path(directory).rglob("*.sqlite3")
            }
            assert current
            if restart:
                assert raw_vote == first_vote and current == inodes
                assert tuple(i.remote.reads) == reads
            else:
                first_vote, inodes, reads = raw_vote, current, tuple(i.remote.reads)
                s.state.online = False
                (
                    Path(c.model_signing.approvals_directory)
                    / (i.request.acceptance.model_sha256 + ".json")
                ).unlink()
    assert s.state.events.count("provider-started") == s.state.events.count("provider-closed") == 2
    events = [
        json.loads(record.message) for record in caplog.records if record.message.startswith("{")
    ]
    for stage in (
        "legacy_model_storage_selection",
        "legacy_model_storage_originals",
        "chunked_model_materialization",
    ):
        observed = [event for event in events if event.get("stage") == stage]
        assert observed and all(
            "eta_basis" in event and "elapsed_seconds" in event for event in observed
        )


@pytest.mark.parametrize(
    "fault",
    [
        "inventory_missing",
        "original_missing",
        "wrong_baseline",
        "wrong_incumbent",
        "changed_inventory",
    ],
)
async def test_invalid_preservation_fails_before_service_lease_keys_or_provider(
    selected, monkeypatch, fault
):
    s, c, i = selected, selected.config, selected.installed
    root = Path(s.source.directory)
    if fault == "inventory_missing":
        (root / "legacy-inventory.json").unlink()
    elif fault == "original_missing":
        raw_sha = i.sources.authenticated[i.case.cohort].legacy.baseline_manifest_raw_sha256
        (root / "objects" / (raw_sha + ".json")).unlink()
    elif fault == "changed_inventory":
        path = root / "legacy-inventory.json"
        path.chmod(0o600)
        path.write_bytes(path.read_bytes() + b"\n")
    else:
        field = "baseline_model_sha256" if fault == "wrong_baseline" else "incumbent_model_sha256s"
        value = "ff" * 32 if fault == "wrong_baseline" else ()
        c = c.model_copy(
            update={"legacy_model_storage": (s.source.model_copy(update={field: value}),)}
        )

    def forbidden(*_args, **_kwargs):
        pytest.fail("invalid preservation reached service lease, signing keys or provider")

    monkeypatch.setattr(boot, "lock_private_file", forbidden)
    monkeypatch.setattr(boot, "load_named_hotkey", forbidden)
    monkeypatch.setattr(boot, "HistoricalRegistrationProvider", forbidden)
    assert not Path(c.signing.directory).exists()
    with pytest.raises(ValueError):
        async with boot.phase_review_app(c):
            pytest.fail("invalid preservation started reviewer")
    # Preflight may retain original-verification checkpoints before finding a
    # missing original. It must not acquire the service lease or create votes.
    signing = Path(c.signing.directory)
    assert not signing.exists() or {path.name for path in signing.iterdir()} <= {
        "legacy-original-verification"
    }
    assert not i.remote.reads


async def test_execution_refuses_missing_private_intent_even_with_remote_inventory(selected):
    c, i = selected.config, selected.installed
    async with boot.phase_review_app(c) as app:
        await vote(app, i.request)
        path = Path(c.model_signing.directory) / "rounds.sqlite3"
        with sqlite3.connect(path) as db:
            db.execute("DELETE FROM records WHERE kind='model_intent'")
        before = tuple(i.remote.reads)
        with pytest.raises(ValueError, match="private reviewed intent"):
            await app.state.benchmark.sandbox.invoke(i.job, attempt(i.job))
        assert tuple(i.remote.reads) == before


def test_retained_originals_cannot_be_stored_under_disposable_boot_cache(selected):
    c = selected.config
    cached = selected.source.model_copy(
        update={
            "directory": str(
                Path(c.direct_model_review.materialization_boot_disk_cache.directory) / "metadata"
            )
        }
    )
    changed = c.model_copy(update={"legacy_model_storage": (cached,)})
    with pytest.raises(ValueError, match="stores must be disjoint"):
        PhaseReviewServiceConfig.model_validate_json(canonical_json_bytes(changed))


def test_shared_byte_store_rejects_reviewer_cache_signing_and_credentials(selected, tmp_path):
    from umi.competition_model_byte_store import ModelByteStoreConfig

    c = selected.config
    for path in (
        c.signing.directory,
        c.inputs_directory,
        c.signer_key_file,
        c.direct_model_review.r2_credentials_file,
        c.direct_model_review.materialization_boot_disk_cache.directory,
    ):
        source = selected.source.model_copy(
            update={
                "shared_byte_store": ModelByteStoreConfig(
                    schema="umi-model-byte-verification-store/1", directory=str(path)
                )
            }
        )
        with pytest.raises(ValueError, match="overlaps"):
            PhaseReviewServiceConfig.model_validate_json(
                canonical_json_bytes(c.model_copy(update={"legacy_model_storage": (source,)}))
            )


async def test_execution_uses_certified_metadata_without_inventing_local_review(
    selected, monkeypatch
):
    from unittest.mock import AsyncMock

    c, i = selected.config, selected.installed
    async with boot.phase_review_app(c) as app:
        host = app.state.benchmark
        # Independent certification is tested through the actual HTTP reader in
        # test_competition_cohort_model_execution_source. Here retain the actual
        # old installation, empty review journal, sandbox and R2/cache path.
        restored = AsyncMock(return_value=i.request)
        monkeypatch.setattr(host.model_sources, "request", restored)
        cpu_readback(host.sandbox, i, monkeypatch)
        assert await host.sandbox.invoke(i.job, attempt(i.job)) == "inert-cpu-result"
        restored.assert_awaited_once_with(i.job)
        slot = i.case.cohort + ":" + digest(i.job.submission.submission)
        with sqlite3.connect(Path(c.model_signing.directory) / "rounds.sqlite3") as db:
            assert db.execute(
                "SELECT COUNT(*) FROM records WHERE kind IN ('model_request','model_vote') "
                "AND id=?",
                (slot,),
            ).fetchone() == (0,)
