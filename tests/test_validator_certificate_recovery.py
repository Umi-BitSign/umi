from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from types import SimpleNamespace

import httpx
import pytest

from umi.audit import EvidenceStore
from umi.calibration_bundle import (
    CALIBRATION_RECEIPT_MEDIA_TYPE,
    CalibrationObject,
    CalibrationStageEvidence,
    calibration_stage_replay_hook_id,
)
from umi.encoding import account_id32
from umi.pool import PoolManifest
from umi.protocol import PROTOCOL_VERSION, canonical_json_bytes
from umi.validator_adapters import JournalStageAdapter
from umi.validator_certificate_recovery import (
    reconcile_certificate_breach,
    run_installed_recovery,
)
from umi.validator_incident_bundle import (
    IncidentBundleManifest,
    IncidentSpecObject,
    IncidentTerminalEvidence,
    VerifiedIncidentBundle,
)
from umi.validator_journal import ValidatorStageJournal
from umi.validator_live import LiveValidatorPaths
from umi.validator_live_ports import DurablePoolMirrorSource
from umi.validator_pool_effect import (
    CertifiedPoolArtifactUnavailable,
    PoolAndSelectionEffect,
    PoolEffectPorts,
    PoolSourceRequest,
)
from umi.validator_pool_replay import resolve_pool_stage
from umi.validator_protocol_state import ValidatorProtocolStateStore
from umi.validator_state import (
    IncidentStatus,
    PauseScope,
    TerminalOutcome,
    ValidatorControlPlane,
    WindowPlan,
    WindowStage,
)

from .test_shadow import _fixture as _shadow_fixture
from .test_validator_pool_effect import _Fixture as _PoolFixture

_PUBLIC_ADDRESS = "93.184.216.34"


async def _public_resolver(_hostname: str, _port: int) -> tuple[str, ...]:
    return (_PUBLIC_ADDRESS,)


class _RawAsyncStream(httpx.AsyncByteStream):
    def __init__(self, data: bytes) -> None:
        self.data = data

    async def __aiter__(self):
        yield self.data


class _ReceiptWitness:
    def __init__(self, journal: ValidatorStageJournal) -> None:
        self.journal = journal
        self.calls = 0

    async def after_receipt(self, *, record, work) -> None:
        self.calls += 1
        assert self.journal.load(work.window.plan.window_id, work.stage) == record


class _MustNotPerform:
    async def perform(self, *, operation_id, work):
        raise AssertionError("a durable terminal pool receipt must suppress retries")


def _failed_public_manifest_source(fixture: _PoolFixture):
    manifest_bytes = fixture.final_pool_bytes[0]
    manifest = PoolManifest.model_validate_json(manifest_bytes)
    entry = manifest.batches[0]
    resource_key = f"public:{entry.batch_id}:{entry.public_manifest_sha256}"
    resource_key_sha256 = hashlib.sha256(resource_key.encode("utf-8")).hexdigest()
    retrieval = json.loads(fixture.source.artifact_retrieval_evidence_bytes)
    retrieval["attempts"] = [
        {
            "resource_key_sha256": resource_key_sha256,
            "attempt_index": index,
            "url_sha256": hashlib.sha256(
                (origin + "/v1/umi/objects/" + entry.public_manifest_sha256).encode("utf-8")
            ).hexdigest(),
            "status": "failed",
            "observed_wire_bytes": 0,
            "accounted_wire_bytes": 1,
            "error_code": "mirror_http_status",
            "response_body_sha256": None,
            "response_body_size_bytes": 0,
        }
        for index, origin in enumerate(
            json.loads(fixture.discovery_bytes)["origins"][
                : fixture.policy.limits.maximum_video_fetch_attempts_per_actor
            ]
        )
    ]
    retrieval["artifact_observed_wire_bytes"] = 0
    retrieval["artifact_accounted_wire_bytes"] = len(retrieval["attempts"])
    failure = CertifiedPoolArtifactUnavailable(
        final_pool_manifest_bytes=manifest_bytes,
        artifact_retrieval_evidence_bytes=canonical_json_bytes(retrieval),
        discovery_rule_bytes=fixture.discovery_bytes,
        mirror_readiness_set_bytes=fixture.readiness_bytes,
        artifact_kind="public_manifest",
        batch_id=entry.batch_id,
        expected_sha256=entry.public_manifest_sha256,
        resource_key=resource_key,
    )
    calls = {"source": 0}

    def source(_request):
        calls["source"] += 1
        raise failure

    return source, calls


def _terminal_pool_adapter(
    fixture: _PoolFixture,
    journal: ValidatorStageJournal,
    witness: _ReceiptWitness,
):
    source, calls = _failed_public_manifest_source(fixture)
    effect = PoolAndSelectionEffect(
        policy=fixture.policy,
        validator_hotkey=fixture.validator_wallet.hotkey.ss58_address,
        material_store=fixture.material_store,
        protocol_state=fixture.protocol_state,
        ports=PoolEffectPorts(
            source=source,
            closing_snapshot=lambda _work: fixture.closing,
            selection_pulse=lambda _work: fixture.pulse_bytes,
            delivery_issuance=fixture.delivery_issuance,
            prepared_assignments=fixture.prepared,
            incident_audit_release=lambda _work, _reason: fixture.window.closing_block + 500,
        ),
    )
    return (
        JournalStageAdapter(
            stage=WindowStage.POOL_AND_SELECTION,
            journal=journal,
            effect=effect,
            receipt_observer=witness,
        ),
        calls,
    )


def _verified_incident_fixture(
    *,
    paths: LiveValidatorPaths,
    fixture: _PoolFixture,
    journal: ValidatorStageJournal,
    incident_id: str,
) -> VerifiedIncidentBundle:
    record = journal.load(fixture.window.window_id, WindowStage.POOL_AND_SELECTION)
    store = EvidenceStore(paths.incident_bundles / fixture.window.window_id)
    references = [
        CalibrationObject.from_ref(
            store.add_bytes(record.receipt_bytes, CALIBRATION_RECEIPT_MEDIA_TYPE)
        )
    ]
    for item in record.receipt.objects:
        references.append(
            CalibrationObject.from_ref(store.add_bytes(journal.read_object(item), item.media_type))
        )
    references.sort(key=lambda item: bytes.fromhex(item.sha256))
    receipt_ref = next(
        item for item in references if item.media_type == CALIBRATION_RECEIPT_MEDIA_TYPE
    )
    manifest = IncidentBundleManifest.model_construct(
        terminal_classification="skipped",
        validator_account_id32=account_id32(fixture.validator_wallet.hotkey.ss58_address).hex(),
        window_id=fixture.window.window_id,
        window_index=fixture.window.window_index,
        scoring_policy_hash=fixture.window.scoring_policy_hash,
        terminal_stage=WindowStage.POOL_AND_SELECTION.value,
        reason_codes=["certificate_breach"],
        objects=references,
    )
    store.write_manifest(manifest.model_dump(mode="json", by_alias=True))
    terminal = IncidentTerminalEvidence.model_construct(
        incident=IncidentSpecObject(
            incident_id=incident_id,
            reason_code="certificate_breach",
            metadata={},
        )
    )
    reached = CalibrationStageEvidence.model_construct(receipt_object=receipt_ref)
    return VerifiedIncidentBundle(
        manifest=manifest,
        policy=fixture.policy,
        terminal=terminal,
        no_weight_scan=None,  # type: ignore[arg-type]
        replayed_interval=None,  # type: ignore[arg-type]
        reached_stages=(reached,),
    )


def _write_recovered_objects(root, fixture: _PoolFixture) -> None:
    root.mkdir(mode=0o700)
    values = [
        *fixture.final_pool_bytes,
        *(item.public_manifest_bytes for item in fixture.batch_sources),
        *(item.ground_truth_envelope_bytes for item in fixture.batch_sources),
    ]
    for value in values:
        path = root / hashlib.sha256(value).hexdigest()
        path.write_bytes(value)
        path.chmod(0o600)


@pytest.mark.asyncio
async def test_installed_recovery_reports_a_safe_blocked_result(
    tmp_path,
    capsys,
) -> None:
    result = await run_installed_recovery(
        [
            "--config",
            str(tmp_path / "missing-config.json"),
            "--incident-bundle",
            str(tmp_path / "missing-incident"),
            "--recovered-objects",
            str(tmp_path / "missing-recovery"),
            "--reveal-pulse",
            str(tmp_path / "missing-pulse.json"),
        ]
    )

    assert result == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    document = json.loads(captured.err)
    assert document["status"] == "blocked"
    assert document["scoring_performed"] is False
    assert document["weight_submission_capability"] is False


@pytest.mark.asyncio
@pytest.mark.parametrize("failure_mode", ["http_status", "declared_oversize"])
async def test_live_mirror_restarts_without_retrying_exhausted_certified_child(
    tmp_path,
    failure_mode,
) -> None:
    fixture = _PoolFixture(tmp_path / "fixture")
    state = tmp_path / "mirror.sqlite3"
    manifest = PoolManifest.model_validate_json(fixture.final_pool_bytes[0])
    missing_digest = manifest.batches[0].public_manifest_sha256
    available = {hashlib.sha256(value).hexdigest(): value for value in fixture.final_pool_bytes}
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        digest = request.url.path.rsplit("/", 1)[-1]
        if digest == missing_digest:
            if failure_mode == "http_status":
                return httpx.Response(404, content=b"")
            return httpx.Response(
                200,
                headers={
                    "Content-Length": str(fixture.policy.limits.maximum_manifest_bytes + 1),
                    "Content-Type": "application/json",
                },
                content=b"",
            )
        body = available[digest]
        return httpx.Response(
            200,
            headers={
                "Content-Length": str(len(body)),
                "Content-Type": "application/json",
            },
            stream=_RawAsyncStream(body),
        )

    request = PoolSourceRequest(
        work=fixture.work,
        eligible_anchor_hashes=tuple(
            (item.publisher_hotkey, item.pool_manifest_sha256)
            for item in fixture.closing.snapshot.publishers
        ),
        timely_anchor_hashes=tuple(
            (item.publisher_hotkey, item.pool_manifest_sha256)
            for item in fixture.closing.snapshot.publishers
        ),
        active_validator_hotkeys=tuple(
            item.validator_hotkey
            for item in fixture.closing.snapshot.validators
            if item.validator_permit
        ),
    )
    source = DurablePoolMirrorSource(
        policy=fixture.policy,
        discovery_rule_bytes=fixture.discovery_bytes,
        state_path=state,
        request_headers={
            origin: {"Authorization": f"Bearer test-token-{index}"}
            for index, origin in enumerate(json.loads(fixture.discovery_bytes)["origins"])
        },
        transport=httpx.MockTransport(handler),
        resolver=_public_resolver,
    )
    with pytest.raises(CertifiedPoolArtifactUnavailable) as first:
        await source(request)
    assert first.value.reason_code == "certificate_breach"
    assert first.value.expected_sha256 == missing_digest
    assert len(calls) == (
        len(fixture.final_pool_bytes) + fixture.policy.limits.maximum_video_fetch_attempts_per_actor
    )

    def network_must_not_run(_request: httpx.Request) -> httpx.Response:
        raise AssertionError("restart retried an exhausted certified child")

    restarted = DurablePoolMirrorSource(
        policy=fixture.policy,
        discovery_rule_bytes=fixture.discovery_bytes,
        state_path=state,
        request_headers={
            origin: {"Authorization": f"Bearer test-token-{index}"}
            for index, origin in enumerate(json.loads(fixture.discovery_bytes)["origins"])
        },
        transport=httpx.MockTransport(network_must_not_run),
        resolver=_public_resolver,
    )
    with pytest.raises(CertifiedPoolArtifactUnavailable) as recovered:
        await restarted(request)
    assert recovered.value.expected_sha256 == missing_digest
    assert recovered.value.artifact_retrieval_evidence_bytes == (
        first.value.artifact_retrieval_evidence_bytes
    )


@pytest.mark.asyncio
async def test_pool_effect_does_not_terminalize_unexpected_source_error(tmp_path) -> None:
    fixture = _PoolFixture(tmp_path)
    journal = ValidatorStageJournal(tmp_path / "journal")

    def programming_error(_request):
        raise RuntimeError("simulated invariant bug")

    effect = PoolAndSelectionEffect(
        policy=fixture.policy,
        validator_hotkey=fixture.validator_wallet.hotkey.ss58_address,
        material_store=fixture.material_store,
        protocol_state=fixture.protocol_state,
        ports=PoolEffectPorts(
            source=programming_error,
            closing_snapshot=lambda _work: fixture.closing,
            selection_pulse=lambda _work: fixture.pulse_bytes,
            delivery_issuance=fixture.delivery_issuance,
            prepared_assignments=fixture.prepared,
            incident_audit_release=lambda _work, _reason: fixture.window.closing_block + 500,
        ),
    )
    adapter = JournalStageAdapter(
        stage=WindowStage.POOL_AND_SELECTION,
        journal=journal,
        effect=effect,
    )

    with pytest.raises(RuntimeError, match="simulated invariant bug"):
        await adapter.execute(fixture.work)
    assert journal.load_window(fixture.window.window_id) == ()


@pytest.mark.asyncio
async def test_certificate_breach_restarts_then_reconciles_without_scoring(
    tmp_path,
    monkeypatch,
) -> None:
    fixture = _PoolFixture(tmp_path)
    journal = ValidatorStageJournal(tmp_path / "journal")
    witness = _ReceiptWitness(journal)
    adapter, calls = _terminal_pool_adapter(fixture, journal, witness)

    decision = await adapter.execute(fixture.work)
    assert decision.outcome is TerminalOutcome.SKIPPED
    assert decision.reason_code == "certificate_breach"
    assert decision.pause_scopes == (PauseScope.WINDOW_INTAKE,)
    assert decision.incident is not None
    assert calls == {"source": 1}
    assert witness.calls == 1

    restarted = JournalStageAdapter(
        stage=WindowStage.POOL_AND_SELECTION,
        journal=ValidatorStageJournal(tmp_path / "journal"),
        effect=_MustNotPerform(),
        receipt_observer=_ReceiptWitness(ValidatorStageJournal(tmp_path / "journal")),
    )
    assert await restarted.execute(fixture.work) == decision
    assert calls == {"source": 1}

    record = journal.load(fixture.window.window_id, WindowStage.POOL_AND_SELECTION)
    stage_objects = {item.sha256: journal.read_object(item) for item in record.receipt.objects}
    replay_evidence = CalibrationStageEvidence(
        schema="umi-calibration-stage-evidence/2",
        protocol=PROTOCOL_VERSION,
        window_id=fixture.window.window_id,
        scoring_policy_hash=fixture.window.scoring_policy_hash,
        stage_id=WindowStage.POOL_AND_SELECTION.value,
        replay_hook_id=calibration_stage_replay_hook_id(
            fixture.policy,
            WindowStage.POOL_AND_SELECTION.value,
        ),
        previous_stage_evidence_sha256=None,
        receipt_object=CalibrationObject.from_bytes(
            record.receipt_bytes,
            CALIBRATION_RECEIPT_MEDIA_TYPE,
        ),
        payload_objects=[
            CalibrationObject(
                sha256=item.sha256,
                media_type=item.media_type,
                size_bytes=item.size_bytes,
            )
            for item in record.receipt.objects
        ],
    )
    monkeypatch.setattr(
        "umi.validator_pool_replay.replay_announcement_validator_storage",
        lambda proof, *, verifier: SimpleNamespace(evidence=object()),
    )
    monkeypatch.setattr(
        "umi.validator_pool_replay.validate_replayed_announcement_validator_snapshot",
        lambda snapshot, replayed, *, policy: fixture.closing.announcement_snapshot,
    )
    monkeypatch.setattr(
        "umi.validator_pool_replay.replay_closing_snapshot_storage",
        lambda proof, *, verifier: SimpleNamespace(evidence=object()),
    )
    monkeypatch.setattr(
        "umi.validator_pool_replay.validate_replayed_closing_snapshot",
        lambda snapshot, replayed, *, policy: fixture.closing.snapshot,
    )
    monkeypatch.setattr(
        "umi.validator_pool_replay.verify_snapshot_finality",
        lambda proof, **values: None,
    )
    replay = resolve_pool_stage(
        policy=fixture.policy,
        evidence=replay_evidence,
        receipt=record.receipt,
        objects=stage_objects,
        verifier=lambda **_values: True,
        finality_verifier=lambda **_values: True,
        finality_verifier_sha256="7b" * 32,
    )
    assert replay.selection.reason_code == "certificate_breach"
    assert replay.assignment_ids == ()

    base_paths = LiveValidatorPaths.below(tmp_path / "live-state")
    paths = replace(
        base_paths,
        stage_journal=tmp_path / "journal",
        protocol_state=tmp_path / "protocol.sqlite3",
    )
    control = ValidatorControlPlane(paths.control_plane)
    control.start_window(fixture.window, operation_id="test.start.certificate-breach")
    control.apply_terminal_decision(decision)
    assert control.control_state(PauseScope.WINDOW_INTAKE).paused is True

    verified = _verified_incident_fixture(
        paths=paths,
        fixture=fixture,
        journal=journal,
        incident_id=decision.incident.incident_id,
    )
    recovered = tmp_path / "recovered"
    _write_recovered_objects(recovered, fixture)
    rehearsal, _wallets = _shadow_fixture()
    ground_truth_by_batch = {
        item.batch_id: canonical_json_bytes(item.revealed_ground_truth)
        for item in rehearsal.batch_artifacts
    }
    plaintext_by_ciphertext = {
        hashlib.sha256(item.ground_truth_envelope_bytes).hexdigest(): ground_truth_by_batch[
            item.batch_id
        ]
        for item in fixture.batch_sources
    }
    signature = bytes(range(48))
    reveal_pulse = canonical_json_bytes(
        {
            "round": fixture.window.reveal_round,
            "randomness": hashlib.sha256(signature).hexdigest(),
            "signature": signature.hex(),
        }
    )
    monkeypatch.setattr("umi.drand.verify_quicknet_signature", lambda *_args: True)

    async def decrypt(sealed, pulse):
        assert pulse.round == fixture.window.reveal_round
        return plaintext_by_ciphertext[sealed.sha256_hex]

    fixture.protocol_state.close()
    original_resolve = ValidatorControlPlane.resolve_incident

    def crash_before_resolution(self, *args, **kwargs):
        raise RuntimeError("simulated recovery-process crash")

    monkeypatch.setattr(ValidatorControlPlane, "resolve_incident", crash_before_resolution)
    with pytest.raises(RuntimeError, match="simulated recovery-process crash"):
        await reconcile_certificate_breach(
            policy=fixture.policy,
            paths=paths,
            incident_root=paths.incident_bundles / fixture.window.window_id,
            verified_incident=verified,
            recovered_objects_root=recovered,
            reveal_pulse_bytes=reveal_pulse,
            decrypt=decrypt,
        )
    monkeypatch.setattr(ValidatorControlPlane, "resolve_incident", original_resolve)
    interrupted_control = ValidatorControlPlane(paths.control_plane)
    assert interrupted_control.get_incident(decision.incident.incident_id).status is (
        IncidentStatus.OPEN
    )
    assert interrupted_control.control_state(PauseScope.WINDOW_INTAKE).paused is True
    assert interrupted_control.get_window(fixture.window.window_id).terminal_outcome is (
        TerminalOutcome.SKIPPED
    )
    with ValidatorProtocolStateStore(paths.protocol_state) as interrupted_protocol:
        assert interrupted_protocol.audit().rolling_scores.batches == ()

    report = await reconcile_certificate_breach(
        policy=fixture.policy,
        paths=paths,
        incident_root=paths.incident_bundles / fixture.window.window_id,
        verified_incident=verified,
        recovered_objects_root=recovered,
        reveal_pulse_bytes=reveal_pulse,
        decrypt=decrypt,
    )
    assert report["original_terminal_outcome"] == "skipped"
    assert report["scoring_performed"] is False

    restarted_control = ValidatorControlPlane(paths.control_plane)
    original = restarted_control.get_window(fixture.window.window_id)
    assert original.terminal_outcome is TerminalOutcome.SKIPPED
    assert original.terminal_reason_code == "certificate_breach"
    assert restarted_control.get_incident(decision.incident.incident_id).status is (
        IncidentStatus.RESOLVED
    )
    assert restarted_control.control_state(PauseScope.WINDOW_INTAKE).paused is False
    with ValidatorProtocolStateStore(paths.protocol_state) as protocol:
        state = protocol.audit()
        assert state.last_window_index == fixture.window.window_index
        assert state.last_window_id == bytes.fromhex(fixture.window.window_id)
        assert state.spent_registry.leaves
        assert state.rolling_scores.batches == ()

    repeated = await reconcile_certificate_breach(
        policy=fixture.policy,
        paths=paths,
        incident_root=paths.incident_bundles / fixture.window.window_id,
        verified_incident=verified,
        recovered_objects_root=recovered,
        reveal_pulse_bytes=reveal_pulse,
        decrypt=decrypt,
    )
    assert repeated == report

    stride = fixture.policy.clock.window_stride_blocks
    next_plan = WindowPlan(
        window_id="fe" * 32,
        window_index=fixture.window.window_index + 1,
        scoring_policy_hash=fixture.window.scoring_policy_hash,
        announcement_block=fixture.window.announcement_block + stride,
        proposal_close_block=fixture.window.proposal_close_block + stride,
        closing_block=fixture.window.closing_block + stride,
        selection_round=fixture.window.reveal_round + 1,
        issue_close_round=fixture.window.reveal_round + 2,
        response_close_round=fixture.window.reveal_round + 3,
        reveal_round=fixture.window.reveal_round + 4,
    )
    started = restarted_control.start_window(
        next_plan,
        operation_id="test.start.after-certificate-recovery",
    )
    assert started.plan.window_index == fixture.window.window_index + 1
    assert restarted_control.get_window(fixture.window.window_id).terminal_outcome is (
        TerminalOutcome.SKIPPED
    )
