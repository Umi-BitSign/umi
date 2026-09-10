from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import bittensor as bt
import pytest
from pydantic import ValidationError

from tests.factories import dev_wallet
from umi.bootstrap_direct_weights import DIRECT_MINIMUM_WEIGHTS_VERSION_KEY
from umi.bootstrap_weight_operator import (
    BootstrapChainParticipant,
    BootstrapChainSnapshot,
    BootstrapOperatorError,
)
from umi.bootstrap_weights import U16_MAX, SignedBootstrapEligibilityManifest
from umi.encoding import account_id32
from umi.grandpa_finality import FINNEY_GENESIS_HASH
from umi.protocol import canonical_json_bytes
from umi.simple_bootstrap_validator import (
    SIMPLE_BOOTSTRAP_ACTIVITY_CUTOFF_BLOCKS,
    SIMPLE_BOOTSTRAP_HARD_SUNSET_BLOCK,
    SIMPLE_BOOTSTRAP_JOURNAL_SCHEMA,
    SIMPLE_BOOTSTRAP_LEASE_BODY_SCHEMA,
    SIMPLE_BOOTSTRAP_LEASE_SCHEMA,
    SIMPLE_BOOTSTRAP_MANIFEST_SHA256,
    SIMPLE_BOOTSTRAP_POLICY_SHA256,
    SIMPLE_BOOTSTRAP_PROFILE,
    SIMPLE_BOOTSTRAP_RUNTIME_SPEC_VERSION,
    SIMPLE_BOOTSTRAP_SUBMISSION_ERA_PERIOD,
    SIMPLE_BOOTSTRAP_UNKNOWN_EFFECT_BLOCKS,
    SignedSimpleBootstrapLease,
    SimpleActiveRow,
    SimpleBootstrapError,
    SimpleBootstrapJournal,
    SimpleBootstrapLeaseBody,
    SimpleBootstrapObservation,
    _manifest_anchor_state,
    build_simple_bootstrap_call,
    reconcile_simple_bootstrap_journal,
    run_simple_bootstrap_iteration,
    sign_simple_bootstrap_lease,
    validate_simple_bootstrap_observation,
    verify_simple_bootstrap_checkout,
    verify_simple_bootstrap_lease,
)

NOW = datetime(2026, 9, 10, 16, 0, tzinfo=timezone.utc)
NOW_MS = int(NOW.timestamp() * 1_000)
BLOCK = 9_040_000
BLOCK_HASH = "0x" + "12" * 32
REVISION = "ab" * 20
VALIDATOR_UID = 200
OWNER_UID = 0


def _production_manifest() -> SignedBootstrapEligibilityManifest:
    path = (
        Path(__file__).resolve().parents[1]
        / "deploy"
        / "linux-validator-supervisor"
        / "bootstrap-manifest.json"
    )
    payload = path.read_bytes()
    manifest = SignedBootstrapEligibilityManifest.model_validate_json(payload)
    assert canonical_json_bytes(manifest) == payload
    return manifest


def _lease_body(coordinator_hotkey: str) -> SimpleBootstrapLeaseBody:
    return SimpleBootstrapLeaseBody(
        schema=SIMPLE_BOOTSTRAP_LEASE_BODY_SCHEMA,
        profile=SIMPLE_BOOTSTRAP_PROFILE,
        manifest_sha256=SIMPLE_BOOTSTRAP_MANIFEST_SHA256,
        policy_sha256=SIMPLE_BOOTSTRAP_POLICY_SHA256,
        coordinator_hotkey=coordinator_hotkey,
        umi_git_revision=REVISION,
        valid_from_block=BLOCK - 1_000,
        hard_sunset_block=SIMPLE_BOOTSTRAP_HARD_SUNSET_BLOCK,
        required_runtime_spec_version=SIMPLE_BOOTSTRAP_RUNTIME_SPEC_VERSION,
        weights_version_key=DIRECT_MINIMUM_WEIGHTS_VERSION_KEY,
        required_mechanism_count=1,
        required_commit_reveal_enabled=False,
        required_commit_reveal_version=4,
        required_reveal_period_epochs=1,
        required_tempo=360,
        required_activity_cutoff_blocks=SIMPLE_BOOTSTRAP_ACTIVITY_CUTOFF_BLOCKS,
        required_weights_set_rate_limit=100,
        required_min_allowed_weights=256,
        required_max_allowed_uids=256,
        require_validator_permit=True,
        allow_any_permitted_validator=True,
        require_public_pilot_replay=True,
        require_fresh_endpoint_health=True,
        refresh_margin_blocks=120,
    )


def _unsigned_production_lease(
    manifest: SignedBootstrapEligibilityManifest,
) -> SignedSimpleBootstrapLease:
    return SignedSimpleBootstrapLease(
        schema=SIMPLE_BOOTSTRAP_LEASE_SCHEMA,
        body=_lease_body(manifest.coordinator_hotkey),
        signature_scheme="sr25519",
        signature="0x" + "00" * 64,
    )


def _ss58(label: str) -> str:
    return bt.sp_core.Keypair(public_key=hashlib.sha256(label.encode()).digest()).ss58_address


def _participants(
    manifest: SignedBootstrapEligibilityManifest,
    *,
    validator_last_update: int,
    validator_hotkey: str | None = None,
) -> tuple[list[BootstrapChainParticipant], str, str]:
    owner_hotkey = _ss58("simple-bootstrap-owner")
    validator_hotkey = validator_hotkey or _ss58("simple-bootstrap-validator")
    entries = {entry.uid: entry for entry in manifest.manifest.entries}
    participants = []
    for uid in range(256):
        entry = entries.get(uid)
        if uid == OWNER_UID:
            hotkey = owner_hotkey
            origin = None
            permit = True
        elif uid == VALIDATOR_UID:
            hotkey = validator_hotkey
            origin = None
            permit = True
        elif entry is not None:
            hotkey = entry.miner_hotkey
            origin = entry.origin
            permit = False
        else:
            hotkey = _ss58(f"simple-bootstrap-filler-{uid}")
            origin = None
            permit = False
        participants.append(
            BootstrapChainParticipant(
                hotkey=hotkey,
                uid=uid,
                validator_permit=permit,
                origin=origin,
                last_update=(validator_last_update if uid == VALIDATOR_UID else BLOCK - 500),
            )
        )
    return participants, owner_hotkey, validator_hotkey


def _expected_row(manifest: SignedBootstrapEligibilityManifest) -> list[list[int]]:
    eligible = {entry.uid for entry in manifest.manifest.entries}
    return [[uid, U16_MAX if uid in eligible else 0] for uid in range(256)]


def _observation(
    manifest: SignedBootstrapEligibilityManifest,
    *,
    block: int = BLOCK,
    validator_last_update: int | None = None,
    validator_row: list[list[int]] | None = None,
    active_rows: dict[int, list[list[int]]] | None = None,
    manifest_anchor_block: int | None = BLOCK - 100,
    validator_hotkey: str | None = None,
    runtime_spec_version: int = SIMPLE_BOOTSTRAP_RUNTIME_SPEC_VERSION,
) -> tuple[SimpleBootstrapObservation, str]:
    last_update = block - 500 if validator_last_update is None else validator_last_update
    participants, owner_hotkey, validator_hotkey = _participants(
        manifest,
        validator_last_update=last_update,
        validator_hotkey=validator_hotkey,
    )
    by_uid = {item.uid: item for item in participants}
    rows = active_rows or {}
    ordered_active = sorted(rows, key=lambda uid: account_id32(by_uid[uid].hotkey))
    simple_rows = [
        SimpleActiveRow(
            hotkey=by_uid[uid].hotkey,
            uid=uid,
            last_update=by_uid[uid].last_update,
            row=rows[uid],
        )
        for uid in ordered_active
    ]
    snapshot = BootstrapChainSnapshot(
        network="finney",
        genesis_block_hash=f"0x{FINNEY_GENESIS_HASH}",
        block_number=block,
        block_hash=BLOCK_HASH,
        block_timestamp_ms=NOW_MS,
        manifest_frozen_block_hash=manifest.manifest.frozen_at_block_hash,
        mechanism_count=1,
        commit_reveal_enabled=False,
        commit_reveal_version=4,
        reveal_period_epochs=1,
        weights_version_key=DIRECT_MINIMUM_WEIGHTS_VERSION_KEY,
        min_allowed_weights=256,
        max_weights_limit=32_768,
        max_allowed_uids=256,
        weights_set_rate_limit=100,
        activity_cutoff_blocks=SIMPLE_BOOTSTRAP_ACTIVITY_CUTOFF_BLOCKS,
        validator_mechid0_row=validator_row or [],
        validator_has_pending_commit=False,
        total_pending_commit_count=0,
        active_mechid0_row_hotkeys=[by_uid[uid].hotkey for uid in ordered_active],
        storage_proofs_verified=False,
        tempo=360,
        last_epoch_block=block - 100,
        pending_epoch_at=0,
        subnet_epoch_index=10,
        blocks_since_last_step=100,
        block_time_seconds=12.0,
        participants=participants,
    )
    return (
        SimpleBootstrapObservation(
            snapshot=snapshot,
            runtime_spec_version=runtime_spec_version,
            subnet_owner_hotkey_account_id32="0x" + account_id32(owner_hotkey).hex(),
            manifest_anchor_block=manifest_anchor_block,
            active_rows=simple_rows,
        ),
        validator_hotkey,
    )


def _validated(
    monkeypatch: pytest.MonkeyPatch,
    manifest: SignedBootstrapEligibilityManifest,
    **observation_options: object,
):
    import umi.simple_bootstrap_validator as module

    monkeypatch.setattr(module, "verify_simple_bootstrap_lease", lambda lease, **_kw: lease)
    observation, validator_hotkey = _observation(manifest, **observation_options)
    validated = validate_simple_bootstrap_observation(
        manifest,
        _unsigned_production_lease(manifest),
        observation,
        validator_hotkey=validator_hotkey,
        expected_revision=REVISION,
        now=NOW,
    )
    return validated


def _journal(
    validator_hotkey: str,
    *,
    phase: str = "outcome_unknown",
    preflight_block: int = BLOCK,
    observation_block: int | None = None,
    manifest_anchor_block: int | None = BLOCK - 100,
) -> SimpleBootstrapJournal:
    return SimpleBootstrapJournal(
        schema=SIMPLE_BOOTSTRAP_JOURNAL_SCHEMA,
        phase=phase,
        lease_sha256="11" * 32,
        manifest_sha256=SIMPLE_BOOTSTRAP_MANIFEST_SHA256,
        validator_hotkey=validator_hotkey,
        attempt_id="22" * 32,
        preflight_block=preflight_block,
        prior_last_update=preflight_block - 500,
        manifest_anchor_block=manifest_anchor_block,
        observation_block=observation_block,
        updated_at=NOW,
    )


def test_common_lease_signs_and_verifies_without_validator_specific_state() -> None:
    coordinator = dev_wallet("//SimpleBootstrapLeaseCoordinator")
    body = _lease_body(coordinator.hotkey.ss58_address)

    signed = sign_simple_bootstrap_lease(body, wallet=coordinator)

    assert signed.body == body
    assert (
        verify_simple_bootstrap_lease(
            signed,
            signed_manifest=None,
            expected_revision=REVISION,
            current_block=BLOCK,
        )
        == signed
    )
    with pytest.raises(ValueError, match="targets another UMI revision"):
        verify_simple_bootstrap_lease(
            signed,
            signed_manifest=None,
            expected_revision="cd" * 20,
            current_block=BLOCK,
        )
    with pytest.raises(ValueError, match="signature is invalid"):
        verify_simple_bootstrap_lease(
            signed.model_copy(update={"signature": "0x" + "00" * 64}),
            signed_manifest=None,
            expected_revision=REVISION,
            current_block=BLOCK,
        )
    with pytest.raises(ValueError, match="lease signer is not the manifest coordinator"):
        sign_simple_bootstrap_lease(body, wallet=dev_wallet("//WrongLeaseSigner"))


def test_signed_image_identity_is_an_explicit_alternative_to_git(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    import umi.simple_bootstrap_validator as module

    marker = tmp_path.resolve() / "umi-image-revision"
    marker.write_bytes(REVISION.encode("ascii") + b"\n")
    marker.chmod(0o444)
    real_fstat = module.os.fstat

    def root_owned_fstat(descriptor: int):
        metadata = real_fstat(descriptor)
        return type(
            "RootOwnedStat",
            (),
            {
                "st_mode": metadata.st_mode,
                "st_uid": 0,
                "st_nlink": metadata.st_nlink,
                "st_size": metadata.st_size,
            },
        )()

    monkeypatch.setattr(module.os, "fstat", root_owned_fstat)
    monkeypatch.setattr(module, "umi_source_tree_sha256", lambda: "33" * 32)
    monkeypatch.setenv("UMI_IMAGE_REVISION_PATH", str(marker))
    monkeypatch.setenv("UMI_IMAGE_SOURCE_TREE_SHA256", "33" * 32)
    monkeypatch.setenv("UMI_GIT_REVISION", REVISION)

    assert verify_simple_bootstrap_checkout() == REVISION

    monkeypatch.delenv("UMI_IMAGE_SOURCE_TREE_SHA256")
    with pytest.raises(SimpleBootstrapError, match="image_identity_environment_incomplete"):
        verify_simple_bootstrap_checkout()


@pytest.mark.parametrize("own_row", [False, True])
def test_non_umi_active_rows_warn_without_blocking_submission(
    monkeypatch: pytest.MonkeyPatch,
    own_row: bool,
) -> None:
    manifest = _production_manifest()
    wrong_row = [[46, 1]]
    active_uid = VALIDATOR_UID if own_row else 110

    validated = _validated(
        monkeypatch,
        manifest,
        validator_row=wrong_row if own_row else [],
        active_rows={active_uid: wrong_row},
    )

    expected_warning = (
        "own_active_non_umi_row_detected" if own_row else "other_active_non_umi_row_uid_110"
    )
    assert validated.decision.action == "submit"
    assert validated.warning_codes == [expected_warning]


def test_raw_weight_call_preserves_the_exact_full_row(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = _production_manifest()
    validated = _validated(monkeypatch, manifest)

    call = build_simple_bootstrap_call(validated)

    assert call.module == "SubtensorModule"
    assert call.function == "set_mechanism_weights"
    assert call.params["netuid"] == 78
    assert call.params["mecid"] == 0
    assert call.params["version_key"] == DIRECT_MINIMUM_WEIGHTS_VERSION_KEY
    assert call.params["dests"] == list(range(256))
    assert len(call.params["weights"]) == 256
    assert call.params["weights"].count(0) == 254
    assert {
        uid: weight
        for uid, weight in zip(
            call.params["dests"],
            call.params["weights"],
            strict=True,
        )
        if weight
    } == {6: U16_MAX, 247: U16_MAX}


def test_weight_rate_limit_is_part_of_the_signed_runtime_tuple(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import umi.simple_bootstrap_validator as module

    manifest = _production_manifest()
    observation, validator_hotkey = _observation(manifest)
    observation = observation.model_copy(
        update={"snapshot": observation.snapshot.model_copy(update={"weights_set_rate_limit": 241})}
    )
    monkeypatch.setattr(module, "verify_simple_bootstrap_lease", lambda lease, **_kw: lease)

    with pytest.raises(SimpleBootstrapError, match="weights_rate_limit_changed"):
        validate_simple_bootstrap_observation(
            manifest,
            _unsigned_production_lease(manifest),
            observation,
            validator_hotkey=validator_hotkey,
            expected_revision=REVISION,
            now=NOW,
        )


def test_runtime_spec_version_is_part_of_the_signed_runtime_tuple(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = _production_manifest()

    with pytest.raises(SimpleBootstrapError, match="runtime_spec_version_changed"):
        _validated(
            monkeypatch,
            manifest,
            runtime_spec_version=SIMPLE_BOOTSTRAP_RUNTIME_SPEC_VERSION + 1,
        )


def test_exact_row_waits_without_renewing_once_it_covers_the_hard_sunset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = _production_manifest()
    expected = _expected_row(manifest)
    last_update = SIMPLE_BOOTSTRAP_HARD_SUNSET_BLOCK - SIMPLE_BOOTSTRAP_ACTIVITY_CUTOFF_BLOCKS
    validated = _validated(
        monkeypatch,
        manifest,
        block=last_update + 1,
        validator_last_update=last_update,
        validator_row=expected,
        active_rows={VALIDATOR_UID: expected},
    )

    assert validated.decision.action == "wait"
    assert validated.decision.reason_code == "hard_sunset_covered"
    assert validated.decision.next_action_block == SIMPLE_BOOTSTRAP_HARD_SUNSET_BLOCK


def test_journal_recovers_only_an_exact_row_written_inside_the_mortal_era(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = _production_manifest()
    expected = _expected_row(manifest)
    preflight = BLOCK
    recovered = _validated(
        monkeypatch,
        manifest,
        block=preflight + SIMPLE_BOOTSTRAP_SUBMISSION_ERA_PERIOD,
        validator_last_update=preflight + SIMPLE_BOOTSTRAP_SUBMISSION_ERA_PERIOD,
        validator_row=expected,
        active_rows={VALIDATOR_UID: expected},
    )
    initial = _journal(recovered.validator_hotkey, preflight_block=preflight)

    result = reconcile_simple_bootstrap_journal(
        initial,
        recovered,
        lease_sha256="11" * 32,
        now=NOW,
    )

    assert result is not None
    assert result.phase == "recovered_applied"
    assert result.observation_block == preflight + SIMPLE_BOOTSTRAP_SUBMISSION_ERA_PERIOD
    assert result.weight_call is None


def test_journal_reconciles_across_a_signed_lease_update(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = _production_manifest()
    expected = _expected_row(manifest)
    preflight = BLOCK
    recovered = _validated(
        monkeypatch,
        manifest,
        block=preflight + SIMPLE_BOOTSTRAP_SUBMISSION_ERA_PERIOD,
        validator_last_update=preflight + SIMPLE_BOOTSTRAP_SUBMISSION_ERA_PERIOD,
        validator_row=expected,
        active_rows={VALIDATOR_UID: expected},
    )
    prior_lease_journal = _journal(recovered.validator_hotkey, preflight_block=preflight)

    result = reconcile_simple_bootstrap_journal(
        prior_lease_journal,
        recovered,
        lease_sha256="33" * 32,
        now=NOW,
    )

    assert result is not None
    assert result.phase == "recovered_applied"
    assert result.lease_sha256 == "11" * 32


def test_late_exact_row_is_a_valid_chain_receipt_without_manual_reconciliation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = _production_manifest()
    expected = _expected_row(manifest)
    preflight = BLOCK
    late = _validated(
        monkeypatch,
        manifest,
        block=preflight + SIMPLE_BOOTSTRAP_SUBMISSION_ERA_PERIOD + 2,
        validator_last_update=preflight + SIMPLE_BOOTSTRAP_SUBMISSION_ERA_PERIOD + 1,
        validator_row=expected,
        active_rows={VALIDATOR_UID: expected},
    )

    result = reconcile_simple_bootstrap_journal(
        _journal(late.validator_hotkey, preflight_block=preflight),
        late,
        lease_sha256="11" * 32,
        now=NOW,
    )

    assert result is not None
    assert result.phase == "recovered_applied"
    assert result.weight_call is None


def test_anchor_reconciliation_has_explicit_terminal_observation_fields(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = _production_manifest()
    anchored = _validated(monkeypatch, manifest, manifest_anchor_block=BLOCK - 50)
    applied = reconcile_simple_bootstrap_journal(
        _journal(
            anchored.validator_hotkey,
            phase="anchor_outcome_unknown",
            manifest_anchor_block=None,
        ),
        anchored,
        lease_sha256="11" * 32,
        now=NOW,
    )
    assert applied is not None
    assert applied.phase == "anchor_applied"
    assert applied.manifest_anchor_block == BLOCK - 50
    assert applied.observation_block == BLOCK

    unanchored = _validated(
        monkeypatch,
        manifest,
        block=BLOCK + SIMPLE_BOOTSTRAP_UNKNOWN_EFFECT_BLOCKS + 1,
        manifest_anchor_block=None,
    )
    absent = reconcile_simple_bootstrap_journal(
        _journal(
            unanchored.validator_hotkey,
            phase="anchor_outcome_unknown",
            manifest_anchor_block=None,
        ),
        unanchored,
        lease_sha256="11" * 32,
        now=NOW,
    )
    assert absent is not None
    assert absent.phase == "anchor_not_applied"
    assert absent.manifest_anchor_block is None
    assert absent.observation_block == BLOCK + SIMPLE_BOOTSTRAP_UNKNOWN_EFFECT_BLOCKS + 1

    invalid = absent.model_dump(by_alias=True)
    invalid["observation_block"] = None
    with pytest.raises(ValidationError, match="journal observation"):
        SimpleBootstrapJournal.model_validate(invalid)


def test_old_well_formed_commitment_is_replaceable_but_malformed_storage_is_not() -> None:
    old = {
        "block": BLOCK - 10,
        "info": {"fields": [{"Sha256": "0x" + "99" * 32}]},
    }
    exact = {
        "block": BLOCK - 9,
        "info": {"fields": [{"Sha256": "0x" + SIMPLE_BOOTSTRAP_MANIFEST_SHA256}]},
    }

    assert _manifest_anchor_state(old, SIMPLE_BOOTSTRAP_MANIFEST_SHA256) == (
        None,
        "existing_commitment_will_be_replaced",
    )
    assert _manifest_anchor_state(exact, SIMPLE_BOOTSTRAP_MANIFEST_SHA256) == (
        BLOCK - 9,
        None,
    )
    with pytest.raises(BootstrapOperatorError):
        _manifest_anchor_state(
            {"block": BLOCK - 8, "info": {"fields": []}},
            SIMPLE_BOOTSTRAP_MANIFEST_SHA256,
        )


class _ClientContext:
    def __init__(self, client: object) -> None:
        self.client = client

    async def __aenter__(self) -> object:
        return self.client

    async def __aexit__(self, *_args: object) -> None:
        return None


class _SimpleSubmitClient:
    def __init__(self, *, fail_weight: bool = False) -> None:
        self.calls: list[tuple[object, object, dict[str, object]]] = []
        self.fail_weight = fail_weight

    async def submit_call(self, call: object, wallet: object, **kwargs: object) -> object:
        self.calls.append((call, wallet, kwargs))
        if len(self.calls) == 2 and self.fail_weight:
            raise ConnectionError("ambiguous weight submission")
        block = BLOCK + (1 if len(self.calls) == 1 else 3)
        return SimpleNamespace(
            success=True,
            extrinsic_id=f"{block}-000{len(self.calls)}",
            block_hash="0x" + f"{40 + len(self.calls):02x}" * 32,
        )


class _SimpleIterationChain:
    def __init__(
        self,
        client: _SimpleSubmitClient,
        observations: list[SimpleBootstrapObservation],
        *,
        validator_hotkey: str,
    ) -> None:
        self.client = client
        self.observations = iter(observations)
        self.validator_hotkey = validator_hotkey
        self.client_factory = lambda network: _ClientContext(client)
        self.clock = lambda: NOW

    async def observation_with_client(
        self,
        client: object,
        _manifest: SignedBootstrapEligibilityManifest,
        *,
        validator_hotkey: str,
    ) -> SimpleBootstrapObservation:
        assert client is self.client
        assert validator_hotkey == self.validator_hotkey
        return next(self.observations)


def _iteration_observations(
    manifest: SignedBootstrapEligibilityManifest,
    validator_hotkey: str,
) -> tuple[list[SimpleBootstrapObservation], SimpleBootstrapObservation]:
    expected = _expected_row(manifest)
    before, _ = _observation(
        manifest,
        block=BLOCK,
        manifest_anchor_block=None,
        validator_hotkey=validator_hotkey,
    )
    anchored, _ = _observation(
        manifest,
        block=BLOCK + 1,
        manifest_anchor_block=BLOCK + 1,
        validator_hotkey=validator_hotkey,
    )
    repeated, _ = _observation(
        manifest,
        block=BLOCK + 2,
        manifest_anchor_block=BLOCK + 1,
        validator_hotkey=validator_hotkey,
    )
    applied, _ = _observation(
        manifest,
        block=BLOCK + 3,
        validator_last_update=BLOCK + 3,
        validator_row=expected,
        active_rows={VALIDATOR_UID: expected},
        manifest_anchor_block=BLOCK + 1,
        validator_hotkey=validator_hotkey,
    )
    return [before, anchored, repeated, applied], applied


@pytest.mark.asyncio
async def test_iteration_submits_once_and_verifies_the_finalized_exact_row(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import umi.simple_bootstrap_validator as module

    manifest = _production_manifest()
    wallet = dev_wallet("//SimpleBootstrapIterationValidator")
    validator_hotkey = wallet.hotkey.ss58_address
    observations, applied = _iteration_observations(manifest, validator_hotkey)
    client = _SimpleSubmitClient()
    chain = _SimpleIterationChain(
        client,
        observations,
        validator_hotkey=validator_hotkey,
    )
    replay_calls = 0
    health_calls = 0

    async def replay(_manifest: SignedBootstrapEligibilityManifest) -> None:
        nonlocal replay_calls
        replay_calls += 1

    async def health(
        _manifest: SignedBootstrapEligibilityManifest,
        _validated: object,
        *,
        clock: object,
    ) -> None:
        nonlocal health_calls
        assert clock is chain.clock
        health_calls += 1

    monkeypatch.setattr(module, "verify_simple_bootstrap_lease", lambda lease, **_kw: lease)
    monkeypatch.setattr(module, "replay_bootstrap_pilots", replay)
    monkeypatch.setattr(module, "probe_bootstrap_health", health)
    journal_path = tmp_path / "journal.json"

    status, pilots_verified = await run_simple_bootstrap_iteration(
        manifest,
        _unsigned_production_lease(manifest),
        wallet=wallet,
        chain=chain,
        expected_revision=REVISION,
        journal_path=journal_path,
        pilots_verified=False,
    )

    assert status.status == "submitted"
    assert status.reason_code == "exact_row_applied"
    assert status.finalized_block == BLOCK + 3
    assert status.weight_call is not None
    assert status.weight_call.block_number == BLOCK + 3
    assert pilots_verified
    assert replay_calls == 1
    assert health_calls == 1
    assert [item[0].function for item in client.calls] == [
        "set_commitment",
        "set_mechanism_weights",
    ]
    assert all(item[2]["signer"] == "hotkey" for item in client.calls)
    assert all(item[2]["wait_for_finalization"] is True for item in client.calls)
    journal = SimpleBootstrapJournal.model_validate_json(journal_path.read_bytes())
    assert journal.phase == "applied"
    assert journal.weight_call == status.weight_call

    restart_observation = applied.model_copy(
        update={"snapshot": applied.snapshot.model_copy(update={"block_number": BLOCK + 4})}
    )
    restart_chain = _SimpleIterationChain(
        client,
        [restart_observation],
        validator_hotkey=validator_hotkey,
    )
    restarted, _ = await run_simple_bootstrap_iteration(
        manifest,
        _unsigned_production_lease(manifest),
        wallet=wallet,
        chain=restart_chain,
        expected_revision=REVISION,
        journal_path=journal_path,
        pilots_verified=True,
    )
    assert restarted.status == "waiting"
    assert restarted.reason_code == "exact_row_active"
    assert len(client.calls) == 2


@pytest.mark.asyncio
async def test_unknown_weight_outcome_recovers_from_chain_without_a_duplicate_submit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import umi.simple_bootstrap_validator as module

    manifest = _production_manifest()
    wallet = dev_wallet("//SimpleBootstrapUnknownOutcomeValidator")
    validator_hotkey = wallet.hotkey.ss58_address
    observations, applied = _iteration_observations(manifest, validator_hotkey)
    client = _SimpleSubmitClient(fail_weight=True)
    chain = _SimpleIterationChain(
        client,
        observations[:3],
        validator_hotkey=validator_hotkey,
    )

    async def no_op(*_args: object, **_kwargs: object) -> None:
        return None

    monkeypatch.setattr(module, "verify_simple_bootstrap_lease", lambda lease, **_kw: lease)
    monkeypatch.setattr(module, "replay_bootstrap_pilots", no_op)
    monkeypatch.setattr(module, "probe_bootstrap_health", no_op)
    journal_path = tmp_path / "journal.json"

    with pytest.raises(ConnectionError, match="ambiguous weight submission"):
        await run_simple_bootstrap_iteration(
            manifest,
            _unsigned_production_lease(manifest),
            wallet=wallet,
            chain=chain,
            expected_revision=REVISION,
            journal_path=journal_path,
            pilots_verified=False,
        )
    assert len(client.calls) == 2
    assert SimpleBootstrapJournal.model_validate_json(journal_path.read_bytes()).phase == (
        "outcome_unknown"
    )

    recovered_observation = applied.model_copy(
        update={
            "snapshot": applied.snapshot.model_copy(
                update={"block_number": BLOCK + SIMPLE_BOOTSTRAP_UNKNOWN_EFFECT_BLOCKS + 1}
            )
        }
    )
    recovered_chain = _SimpleIterationChain(
        client,
        [recovered_observation],
        validator_hotkey=validator_hotkey,
    )
    recovered, _ = await run_simple_bootstrap_iteration(
        manifest,
        _unsigned_production_lease(manifest),
        wallet=wallet,
        chain=recovered_chain,
        expected_revision=REVISION,
        journal_path=journal_path,
        pilots_verified=True,
    )

    assert recovered.status == "waiting"
    assert recovered.reason_code == "exact_row_active"
    assert len(client.calls) == 2
    assert SimpleBootstrapJournal.model_validate_json(journal_path.read_bytes()).phase == (
        "recovered_applied"
    )


def test_shared_deployment_has_no_per_validator_control_plane_or_upload_key() -> None:
    root = Path(__file__).resolve().parents[1]
    deploy = root / "deploy" / "linux-validator-supervisor"
    install = (deploy / "install.sh").read_text(encoding="utf-8")
    service = (deploy / "umi-validator-supervisor.service").read_text(encoding="utf-8")
    combined = "\n".join((install, service)).lower()

    assert "result-upload" not in combined
    assert "upload key" not in combined
    assert "--wallet-name" in install
    assert "--hotkey-name" in install
    assert "--wallet-path" in install
    assert "preflight-common-switch" in install
    assert "--validator-hotkey" not in install
    assert "umi-validator-supervisor run" in service
    assert not (root / "deploy" / "simple-bootstrap-validator").exists()
