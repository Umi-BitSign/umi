"""Installed selection and private input handling, with explicit service ports.

Config, signatures, journals and files are real. The assembly tests replace
providers/service execution; CLI tests replace the installed seal/container.
These do not establish live chain effects or a deployed production migration.
"""

import asyncio
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from umi import competition_host_activation as activation
from umi import competition_reward_boot as boot
from umi.competition_chain_resources import CompetitionChainResources
from umi.competition_cohort_direct_model_review import DirectModelReviewSourceConfig
from umi.competition_cohort_model_static_review import StandingModelReviewPolicy
from umi.competition_cohort_recovery import (
    ModelDeliveryProfile,
    SignedCohortRecoveryAuthority,
)
from umi.competition_reward_eligibility import RewardEligibilityRuntime
from umi.competition_reward_files import StandingRewardFiles
from umi.competition_reward_handoff_models import LegacyRewardHandoffPlan
from umi.competition_reward_host import StandingRewardHostApproval
from umi.competition_reward_manifest import (
    RewardOpportunityTerms,
    RewardReplayRequirement,
    StandingRewardOpportunityManifest,
)
from umi.competition_reward_service import StandingRewardServiceLimits
from umi.competition_supervisor_adapters import ProductionSuccessorRuntimeAdapter
from umi.grandpa_finality import FINNEY_GENESIS_HASH
from umi.open_competition import digest, identity, sign_object
from umi.protocol import canonical_json_bytes

from .test_competition_reward_decisions import chain as chain
from .test_competition_reward_decisions import chain_config as chain_config
from .test_competition_reward_decisions import control as control
from .test_competition_reward_decisions import policy as policy
from .test_competition_reward_decisions import series_case as series_case
from .test_open_competition import wallet
from .test_validator_supervisor import _config


def direct_reward_config(value, tmp_path, schema):
    plans = list(value.series.cohorts)
    plans[-1] = plans[-1].model_copy(
        update={
            "schema_": "umi-recoverable-cohort-plan/3",
            "eligible_tracks": ("model",),
            "service_pool_bps": 0,
            "model_delivery": ModelDeliveryProfile(
                schema="umi-model-delivery-profile/1",
                mechanism="direct_r2_multipart_v1",
                part_size_bytes=64 * 1024**2,
                maximum_concurrent_parts=4,
                capability_ttl_seconds=3600,
            ),
        }
    )
    plans = tuple(plans)
    authority = value.series.recovery.authority.model_copy(
        update={"cohort_sha256s": tuple(sorted(digest(plan) for plan in plans))}
    )
    recovery = SignedCohortRecoveryAuthority(
        authority=authority,
        signatures=tuple(
            sorted(
                (sign_object(authority, wallet(name)) for name in ("Charlie", "Dave")),
                key=lambda signature: identity(signature.hotkey),
            )
        ),
    )
    manifest = value.manifest.model_copy(
        update={
            "cohorts": tuple(
                requirement.model_copy(update={"cohort_sha256": digest(plan)})
                for requirement, plan in zip(value.manifest.cohorts, plans, strict=True)
            )
        }
    )
    series = value.series.model_copy(
        update={"cohorts": plans, "recovery": recovery, "manifest_sha256": digest(manifest)}
    )
    handoff = value.handoff.model_copy(
        update={"series_sha256": digest(series), "cohort_sha256": digest(plans[0])}
    )
    source = DirectModelReviewSourceConfig(
        schema="umi-direct-model-review-source/1",
        r2_credentials_file=str(tmp_path / "direct-model-reader.env"),
        r2_bucket="umi-model-artifacts",
        standing_review_policy=StandingModelReviewPolicy(
            schema="umi-standing-model-artifact-review-policy/1",
            competition_policy_sha256=digest(value.policy),
            contribution_terms_sha256=value.policy.contribution_terms_sha256,
            standing_approval_record_sha256="ab" * 32,
            approved_by="operator@example.test",
            approved_at_utc="2026-10-02T12:00:00Z",
            complete_declared_bundle_rights_approved=True,
            licenses_and_notices_reviewed=True,
            public_redistribution_and_evaluation_approved=True,
        ),
    )
    return value.model_copy(
        update={
            "schema_": schema,
            "series": series,
            "manifest": manifest,
            "handoff": handoff,
            "direct_model_review": source,
        }
    )


@pytest.fixture
def inputs(series_case, tmp_path, monkeypatch):
    c = series_case
    profile = RewardEligibilityRuntime(
        schema="umi-reward-eligibility-runtime/1",
        genesis_hash=FINNEY_GENESIS_HASH,
        netuid=78,
        runtime_code_sha256="19" * 32,
        epoch_source_revision="c004cebf360f4088187ee49d851dfb1a1eaaf710",
    )
    manifest = StandingRewardOpportunityManifest(
        schema="umi-standing-reward-manifest/2",
        policy_sha256=digest(c.control.policy),
        cohorts=tuple(
            RewardReplayRequirement(
                cohort_sha256=digest(plan),
                terms_sha256="20" * 32,
                catalog_sha256s=("21" * 32,),
            )
            for plan in c.series.cohorts
        ),
        opportunity=RewardOpportunityTerms(
            runtime_profile_sha256=digest(profile),
            maximum_interval_ms=12_000,
            minimum_validator_ms=24_000,
        ),
    )
    series = c.series.model_copy(update={"manifest_sha256": digest(manifest)})
    chain = c.control.config.model_copy(
        update={
            "state_directory": str(tmp_path / "new-chain"),
            "proof_rpc_fallback_urls": (
                "wss://backup-one.example.org",
                "wss://backup-two.example.org",
            ),
        }
    )
    legacy = boot.StandingLegacyChain(
        chain=c.control.config,
        resources=CompetitionChainResources.from_config(c.control.config).model_copy(
            update={"state_directory": str(tmp_path / "old-chain-copy")}
        ),
    )
    plan = LegacyRewardHandoffPlan(
        schema="umi-legacy-reward-handoff-plan/1",
        series_sha256=digest(series),
        cohort_sha256=digest(series.cohorts[0]),
        legacy_policy_sha256=digest(c.control.policy),
        legacy_round_sha256="23" * 32,
        legacy_package_sha256="24" * 32,
    )
    value = boot.StandingRewardBootConfig(
        schema="umi-standing-reward-boot/1",
        approval_path=str(tmp_path / "approval.json"),
        series=series,
        policy=c.control.policy,
        manifest=manifest,
        chain=chain,
        legacy_chains=(legacy,),
        legacy_policy=c.control.policy,
        handoff=plan,
        eligibility=profile,
        delivery_directory=str(tmp_path / "delivery"),
        promotion_directory=str(tmp_path / "promotions"),
        proof_import_directory=str(tmp_path / "proof-import"),
        proof_export_directory=str(tmp_path / "proof-export"),
        service=StandingRewardServiceLimits(
            maximum_journal_bytes=8 * 1024**2, mortality_period=128
        ),
        **{
            k: 8 * 1024**2
            for k in (
                "maximum_history_bytes",
                "maximum_coverage_bytes",
                "maximum_reader_bytes",
                "maximum_package_bytes",
                "maximum_promotion_bytes",
                "maximum_witness_bytes",
                "maximum_header_bytes",
                "maximum_header_database_bytes",
            )
        },
    )
    config = _config(validator_hotkey=series.validators[0]).model_copy(
        update={"state_root": str(tmp_path / "supervisor")}
    )
    anchor = SimpleNamespace(
        config=config,
        receipt_sha256="25" * 32,
        receipt=SimpleNamespace(host_manifest_sha256="26" * 32),
    )
    approval = StandingRewardHostApproval(
        schema="umi-standing-reward-host-approval/1",
        source_config_sha256=digest(config),
        installation_receipt_sha256=anchor.receipt_sha256,
        host_manifest_sha256=anchor.receipt.host_manifest_sha256,
        validator_hotkey=config.validator_hotkey,
        series_sha256=digest(series),
        policy_sha256=digest(value.policy),
        manifest_sha256=digest(manifest),
        chain_config_sha256=digest(chain),
        legacy_handoff_plan_sha256=digest(plan),
    )
    monkeypatch.setattr(activation, "_root_owner_uid", os.getuid)

    def save(path, body):
        if path.exists():
            path.chmod(0o600)
        path.write_bytes(body)
        path.chmod(0o444)

    path = tmp_path / "boot.json"
    save(path, canonical_json_bytes(value))
    save(Path(value.approval_path), canonical_json_bytes(approval))
    return SimpleNamespace(value=value, path=path, anchor=anchor, approval=approval, save=save, c=c)


def test_boot_reads_original_root_approval_and_accepts_capacity_increase(inputs):
    i = inputs
    assert boot.load_standing_boot(i.path, i.anchor) == i.value
    raised = i.value.model_copy(update={"maximum_history_bytes": 16 * 1024**2})
    i.save(i.path, canonical_json_bytes(raised))
    assert boot.load_standing_boot(i.path, i.anchor) == raised


def test_direct_series_requires_read_only_reward_source(inputs, tmp_path):
    direct = direct_reward_config(inputs.value, tmp_path, "umi-standing-reward-boot/2")
    assert boot.StandingRewardBootConfig.model_validate_json(canonical_json_bytes(direct)) == direct
    with pytest.raises(ValueError, match="selected authority"):
        boot.StandingRewardBootConfig.model_validate_json(
            canonical_json_bytes(direct.model_copy(update={"direct_model_review": None}))
        )
    with pytest.raises(ValueError, match="selected authority"):
        boot.StandingRewardBootConfig.model_validate_json(
            canonical_json_bytes(
                inputs.value.model_copy(
                    update={
                        "schema_": "umi-standing-reward-boot/2",
                        "direct_model_review": direct.direct_model_review,
                    }
                )
            )
        )


def test_default_selection_uses_existing_command_and_original_approval(inputs):
    i = inputs
    supervisor = i.path.with_name("validator-supervisor.json")
    assert boot.select_standing_boot(supervisor, i.anchor) is None
    i.path.rename(i.path.with_name(boot.BOOT_FILENAME))
    assert boot.select_standing_boot(supervisor, i.anchor) == i.value


@pytest.mark.parametrize("change", ["missing_approval", "dangling", "writable", "invalid"])
def test_broken_default_selection_cannot_fall_back_to_legacy(inputs, change):
    i = inputs
    selected = i.path.with_name(boot.BOOT_FILENAME)
    i.path.rename(selected)
    if change == "missing_approval":
        Path(i.value.approval_path).unlink()
    elif change == "dangling":
        selected.unlink()
        selected.symlink_to(i.path)
    elif change == "writable":
        selected.chmod(0o644)
    else:
        i.save(selected, b"{}")
    with pytest.raises((ValueError, OSError)):
        boot.select_standing_boot(i.path.with_name("validator-supervisor.json"), i.anchor)


def test_explicit_selection_is_required_and_overrides_default(inputs):
    i = inputs
    i.save(i.path.with_name(boot.BOOT_FILENAME), b"invalid default")
    assert boot.select_standing_boot(i.path, i.anchor, explicit_path=i.path) == i.value
    with pytest.raises(activation.HostActivationError, match="could not open"):
        boot.select_standing_boot(i.path, i.anchor, explicit_path=i.path.with_name("missing"))


@pytest.mark.parametrize(
    "mutation",
    ["policy", "profile", "fallbacks", "handoff", "stores", "legacy", "mortality", "proofs"],
)
def test_boot_rejects_mismatched_inputs_before_resources(inputs, mutation):
    v = inputs.value
    changes = {
        "policy": {"chain": v.chain.model_copy(update={"policy_sha256": "aa" * 32})},
        "profile": {
            "eligibility": v.eligibility.model_copy(update={"runtime_code_sha256": "aa" * 32})
        },
        "fallbacks": {"chain": v.chain.model_copy(update={"proof_rpc_fallback_urls": ()})},
        "handoff": {"handoff": v.handoff.model_copy(update={"legacy_package_sha256": "aa" * 32})},
        "stores": {"delivery_directory": v.promotion_directory + "/nested"},
        "proofs": {"proof_import_directory": v.proof_export_directory + "/nested"},
        "legacy": {"legacy_chains": (v.legacy_chains[0], v.legacy_chains[0])},
        "mortality": {"service": v.service.model_copy(update={"mortality_period": 256})},
    }[mutation]
    inputs.save(inputs.path, canonical_json_bytes(v.model_copy(update=changes)))
    with pytest.raises(ValueError):
        boot.load_standing_boot(inputs.path, inputs.anchor)


@pytest.mark.parametrize(
    "mutation", ["receipt", "validator", "noncanonical", "writable", "symlink", "parent_store"]
)
def test_boot_rejects_wrong_installation_and_unsafe_files(inputs, mutation, tmp_path):
    i = inputs
    if mutation == "receipt":
        i.anchor.receipt_sha256 = "aa" * 32
    elif mutation == "validator":
        i.anchor.config = i.anchor.config.model_copy(
            update={"validator_hotkey": i.value.series.control_hotkey}
        )
    elif mutation == "noncanonical":
        i.save(i.path, i.path.read_bytes() + b"\n")
    elif mutation == "writable":
        i.path.chmod(0o644)
    elif mutation == "symlink":
        target = tmp_path / "moved.json"
        i.path.rename(target)
        i.path.symlink_to(target)
    else:
        changed = i.value.model_copy(update={"delivery_directory": i.anchor.config.state_root})
        i.save(i.path, canonical_json_bytes(changed))
    with pytest.raises((ValueError, OSError)):
        boot.load_standing_boot(i.path, i.anchor)


@pytest.mark.parametrize("failure", [None, "constructor", "service", "cancel"])
async def test_native_assembly_preserves_configuration_and_closes_owned_providers(
    inputs, monkeypatch, failure
):
    i = inputs
    events, providers = [], []

    class Provider:
        def __init__(self, chain, policy, **kwargs):
            if failure == "constructor" and providers:
                raise RuntimeError("fixture constructor failure")
            self.config, self.policy, self.kwargs = chain, policy, kwargs
            providers.append(self)

        async def aclose(self):
            events.append(("closed", digest(self.config)))

    async def run(runtime, **kwargs):
        events.append("service")
        assert "first" not in kwargs  # initial package must be reconstructed natively
        assert kwargs["provider"] is providers[0]
        old = i.value.legacy_chains[0]
        assert kwargs["legacy_providers"] == {digest(old.chain): providers[1]}
        assert providers[1].kwargs["resources"] == old.resources
        assert kwargs["history"].config_sha256 == digest(i.value.chain)
        assert kwargs["preparation"].policy_sha256 == digest(i.value.policy)
        collection = kwargs["coverage"]
        assert collection.provider is kwargs["provider"]
        assert collection.preparation is kwargs["preparation"]
        assert collection.history is kwargs["history"]
        assert collection.history.archive.root == Path(i.value.proof_import_directory)
        assert collection.history.export_archive.root == Path(i.value.proof_export_directory)
        assert collection.journal.archive is collection.history.archive
        assert collection.journal.export_archive is collection.history.export_archive
        assert kwargs["opportunity"] == collection.opportunity
        if failure == "service":
            raise RuntimeError("fixture service failure")
        if failure == "cancel":
            raise asyncio.CancelledError

    runtime = SimpleNamespace(
        config=i.anchor.config,
        adapter=object.__new__(ProductionSuccessorRuntimeAdapter),
        _require_lease=lambda: events.append("lease"),
    )
    monkeypatch.setattr(boot, "HistoricalRewardControlProvider", Provider)
    monkeypatch.setattr(boot, "run_standing_reward_service", run)
    if failure:
        with pytest.raises(asyncio.CancelledError if failure == "cancel" else RuntimeError):
            await boot.run_installed_standing_rewards(runtime, i.value, asyncio.Event())
    else:
        await boot.run_installed_standing_rewards(runtime, i.value, asyncio.Event())
    assert events[0] == "lease"
    assert events[-len(providers) :] == [("closed", digest(p.config)) for p in reversed(providers)]


def test_content_reader_creates_private_root_before_delivery(tmp_path):
    import stat

    root = tmp_path / "new-delivery"
    files = StandingRewardFiles(root, maximum_package_bytes=4096, maximum_witness_bytes=4096)
    assert stat.S_IMODE(root.stat().st_mode) == 0o700
    with pytest.raises(FileNotFoundError):
        files.decision("aa" * 32)
    assert stat.S_IMODE(root.stat().st_mode) == 0o700
    root.chmod(0o755)
    with pytest.raises(ValueError, match="owned and private"):
        StandingRewardFiles(root, maximum_package_bytes=4096, maximum_witness_bytes=4096)


def test_content_reader_does_not_confuse_signed_envelope_with_decision_identity(inputs, tmp_path):
    decision = inputs.c.genesis
    root = tmp_path / "content"
    directory = root / "decisions"
    directory.mkdir(parents=True, mode=0o700)
    root.chmod(0o700)
    path = directory / (digest(decision.decision) + ".json")
    path.write_bytes(canonical_json_bytes(decision))
    path.chmod(0o600)
    files = StandingRewardFiles(root, maximum_package_bytes=4096, maximum_witness_bytes=4096)
    assert files.decision(digest(decision.decision)) == path.read_bytes()
    wrong = directory / (digest(decision) + ".json")
    wrong.write_bytes(path.read_bytes())
    wrong.chmod(0o600)
    with pytest.raises(ValueError, match="identity"):
        files.decision(digest(decision))
    with pytest.raises(ValueError):
        files.decision("../escape")
    path.write_bytes(path.read_bytes() + b"\n")
    with pytest.raises(ValueError, match="canonical"):
        files.decision(digest(decision.decision))
