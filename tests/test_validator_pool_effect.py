from __future__ import annotations

import hashlib
import json
from dataclasses import replace

import pytest

from umi.encoding import account_id32
from umi.mirror_readiness import (
    MIRROR_READINESS_SET_SCHEMA,
    MIRROR_READINESS_STATEMENT_SCHEMA,
    MirrorReadinessSet,
    MirrorReadinessStatement,
    mirror_readiness_statement_digest,
    verify_live_mirror_readiness,
)
from umi.pool import PoolManifest
from umi.protocol import (
    PROTOCOL_VERSION,
    TranslationRequest,
    base64url_decode,
    base64url_encode,
    canonical_json_bytes,
)
from umi.publisher_availability import (
    CERTIFIED_RELEASE_SCHEMA,
    QUALIFICATION_RECEIPTS_DIRECTORY,
    AvailabilityWindow,
    CertifiedPoolRelease,
    PoolAnchorField,
    PoolAnchorIntent,
    ReleasedPoolManifest,
)
from umi.validator import prepare_request_attempt
from umi.validator_adapters import JournalStageAdapter, stage_operation_id
from umi.validator_delivery import (
    DEFAULT_DELIVERY_ISSUANCE_PATH,
    DEFAULT_MIRROR_INDEX_PATH,
    DELIVERY_ISSUANCE_EVIDENCE_SCHEMA,
    DELIVERY_ISSUANCE_RESPONSE_SCHEMA,
    MIRROR_DISCOVERY_SCHEMA,
    IssuedVideoDelivery,
    IssuedVideoDeliverySet,
    MirrorDiscoveryRule,
    VideoDeliveryCommitment,
    VideoDeliveryIssuanceEvidence,
    VideoDeliveryIssuanceResponse,
    build_delivery_request,
    derive_delivery_token,
)
from umi.validator_journal import ValidatorStageJournal
from umi.validator_pool_effect import (
    ANNOUNCEMENT_VALIDATOR_PROOF_PROFILE,
    ANNOUNCEMENT_VALIDATOR_SNAPSHOT_SCHEMA,
    CLOSING_SNAPSHOT_PROOF_PROFILE,
    CLOSING_SNAPSHOT_SCHEMA,
    POOL_SELECTION_EVIDENCE_SCHEMA,
    AnnouncementValidatorSnapshot,
    ClosingNeuron,
    ClosingPublisherState,
    ClosingSnapshot,
    ClosingValidatorState,
    DeliveryIssuanceContext,
    PoolAndSelectionEffect,
    PoolBatchSource,
    PoolEffectBindingError,
    PoolEffectLimitError,
    PoolEffectPorts,
    PoolSelectionContext,
    PoolSourcePackage,
    PreparedAssignmentSet,
    VerifiedClosingSnapshot,
    VideoDeliverySource,
)
from umi.validator_pool_no_score import POOL_NO_SCORE_SCHEMA, PoolNoScoreEvidence
from umi.validator_protocol_state import ValidatorProtocolStateStore
from umi.validator_state import (
    ControlState,
    PauseScope,
    StageEvidence,
    StagePending,
    StageWorkItem,
    WindowPlan,
    WindowRecord,
    WindowStage,
)
from umi.validator_transcript_effects import TranscriptAssignment
from umi.validator_window_material import ValidatorWindowMaterialStore
from umi.window import QUICKNET_GENESIS_MS, QUICKNET_PERIOD_MS

from .test_shadow import RANDOMNESS, ROUND, SIGNATURE, _fixture, _schedule, _wallet


def _controls() -> tuple[ControlState, ...]:
    return tuple(ControlState(scope=scope, active_holds=()) for scope in PauseScope)


def _work(window: WindowPlan) -> StageWorkItem:
    return StageWorkItem(
        window=WindowRecord(
            plan=window,
            stage=WindowStage.POOL_AND_SELECTION,
            terminal_outcome=None,
            terminal_reason_code=None,
            terminal_evidence_sha256=None,
            audit_release_block=None,
            created_at_unix_ns=1,
            updated_at_unix_ns=1,
            revision=0,
        ),
        completed_evidence=(),
        controls=_controls(),
    )


def _pool_no_score(result) -> PoolNoScoreEvidence:
    for item in result.objects:
        if item.media_type != "application/json":
            continue
        value = json.loads(item.data)
        if isinstance(value, dict) and value.get("schema") == POOL_NO_SCORE_SCHEMA:
            return PoolNoScoreEvidence.model_validate(value)
    raise AssertionError("pool no-score evidence is absent")


class _Fixture:
    def __init__(self, tmp_path) -> None:
        rehearsal, _signers = _fixture()
        self.policy = rehearsal.policy
        _announcement_timestamp, schedule = _schedule(self.policy)
        self.window = WindowPlan.from_schedule(
            schedule,
            scoring_policy_hash=rehearsal.pool_bodies[0].scoring_policy_hash,
        )
        self.work = _work(self.window)
        self.validator_wallets = [_wallet(f"//Validator{index}") for index in range(4)]
        self.validator_wallets.sort(key=lambda wallet: account_id32(wallet.hotkey.ss58_address))
        self.validator_wallet = self.validator_wallets[0]
        assert self.validator_wallet.hotkey.ss58_address == rehearsal.validator_hotkey

        final_manifests = [
            PoolManifest.model_validate(
                {
                    **body.model_dump(mode="json", by_alias=True),
                    "availability_certificate": rehearsal.availability_certificate.model_dump(
                        mode="json",
                        by_alias=True,
                    ),
                }
            )
            for body in rehearsal.pool_bodies
        ]
        self.final_pool_bytes = tuple(canonical_json_bytes(item) for item in final_manifests)
        self.batch_sources = tuple(
            PoolBatchSource(
                batch_id=item.batch_id,
                public_manifest_bytes=canonical_json_bytes(item.public_manifest),
                ground_truth_envelope_bytes=item.ciphertext_bytes,
            )
            for item in rehearsal.batch_artifacts
        )
        video_deliveries = []
        for artifact in rehearsal.batch_artifacts:
            for item in artifact.public_manifest.items:
                video_deliveries.append(
                    VideoDeliverySource(
                        batch_id=artifact.batch_id,
                        challenge_id=item.challenge_id,
                        url=f"https://objects.example/{item.media.sha256}",
                        sha256=item.media.sha256,
                        size_bytes=item.media.size_bytes,
                    )
                )
        video_deliveries.sort(
            key=lambda item: (
                base64url_decode(item.batch_id),
                base64url_decode(item.challenge_id),
            )
        )
        self.source = PoolSourcePackage(
            final_pool_manifest_bytes=self.final_pool_bytes,
            batch_artifacts=self.batch_sources,
            video_deliveries=tuple(video_deliveries),
            artifact_retrieval_evidence_bytes=b"bounded-video-retrieval-proof",
        )
        self.discovery_bytes = canonical_json_bytes(
            MirrorDiscoveryRule(
                schema=MIRROR_DISCOVERY_SCHEMA,
                protocol=PROTOCOL_VERSION,
                authentication_profile=(
                    self.policy.implementation_pins.rules.mirror_authentication_profile
                ),
                index_path_template=DEFAULT_MIRROR_INDEX_PATH,
                delivery_issuance_path=DEFAULT_DELIVERY_ISSUANCE_PATH,
                origins=[
                    "https://mirror.example",
                    "https://mirror1.example",
                    "https://mirror2.example",
                ],
                delivery_origins=[
                    "https://delivery.example",
                    "https://delivery1.example",
                    "https://delivery2.example",
                ],
            )
        )
        assert hashlib.sha256(self.discovery_bytes).hexdigest() == (
            self.policy.implementation_pins.rules.mirror_discovery_rule_sha256
        )
        anchor_intents = [
            PoolAnchorIntent(
                schema="umi-pool-anchor-intent/1",
                protocol=PROTOCOL_VERSION,
                netuid=self.policy.netuid,
                window_id=self.window.window_id,
                closing_block=self.window.closing_block,
                publisher_hotkey=manifest.publisher_hotkey,
                pallet="Commitments",
                call="set_commitment",
                fields=[
                    PoolAnchorField(
                        variant="Data::Sha256",
                        sha256=hashlib.sha256(raw).hexdigest(),
                    )
                ],
                pool_manifest_sha256=hashlib.sha256(raw).hexdigest(),
                broadcast_authorized=False,
                translation_weights_active=False,
                weight_submission_capability=False,
            )
            for manifest, raw in zip(final_manifests, self.final_pool_bytes, strict=True)
        ]
        anchor_intents.sort(key=lambda item: account_id32(item.publisher_hotkey))
        anchor_bytes = canonical_json_bytes(
            [item.model_dump(mode="json", by_alias=True) for item in anchor_intents]
        )
        receipt_hash_by_signer = {
            account_id32(item.validator_hotkey): hashlib.sha256(
                b"test-readiness-receipt\0" + account_id32(item.validator_hotkey)
            ).hexdigest()
            for item in rehearsal.availability_certificate.signatures
        }
        release = CertifiedPoolRelease(
            schema=CERTIFIED_RELEASE_SCHEMA,
            protocol=PROTOCOL_VERSION,
            window=AvailabilityWindow.from_plan(self.window),
            candidate_set_sha256="11" * 32,
            availability_certificate_sha256=hashlib.sha256(
                canonical_json_bytes(rehearsal.availability_certificate)
            ).hexdigest(),
            availability_set_root=rehearsal.availability_certificate.availability_set_root,
            qualified_pool_leaves=rehearsal.availability_certificate.qualified_pool_leaves,
            signer_receipt_sha256s=sorted(receipt_hash_by_signer.values(), key=bytes.fromhex),
            qualification_receipts_directory=QUALIFICATION_RECEIPTS_DIRECTORY,
            pool_manifests=[
                ReleasedPoolManifest(
                    publisher_hotkey=manifest.publisher_hotkey,
                    sha256=hashlib.sha256(raw).hexdigest(),
                    size_bytes=len(raw),
                )
                for manifest, raw in zip(final_manifests, self.final_pool_bytes, strict=True)
            ],
            mirror_index_path=DEFAULT_MIRROR_INDEX_PATH,
            mirror_index_sha256="22" * 32,
            mirror_index_size_bytes=1,
            anchor_intents_sha256=hashlib.sha256(anchor_bytes).hexdigest(),
            broadcast_performed=False,
            translation_weights_active=False,
            weight_submission_capability=False,
        )
        release_bytes = canonical_json_bytes(release)
        wallet_by_account = {
            account_id32(wallet.hotkey.ss58_address): wallet for wallet in self.validator_wallets
        }
        readiness_statements = []
        for index, certificate_signer in enumerate(rehearsal.availability_certificate.signatures):
            account = account_id32(certificate_signer.validator_hotkey)
            provisional = MirrorReadinessStatement(
                schema=MIRROR_READINESS_STATEMENT_SCHEMA,
                protocol=PROTOCOL_VERSION,
                window_id=self.window.window_id,
                window_index=self.window.window_index,
                scoring_policy_sha256=self.window.scoring_policy_hash,
                discovery_rule_sha256=hashlib.sha256(self.discovery_bytes).hexdigest(),
                certified_release_sha256=hashlib.sha256(release_bytes).hexdigest(),
                anchor_intents_sha256=hashlib.sha256(anchor_bytes).hexdigest(),
                mirror_index_sha256=release.mirror_index_sha256,
                qualification_receipt_sha256=receipt_hash_by_signer[account],
                validator_hotkey=certificate_signer.validator_hotkey,
                retrieval_origin=json.loads(self.discovery_bytes)["origins"][index],
                delivery_origin=json.loads(self.discovery_bytes)["delivery_origins"][index],
                exact_tree_configuration_checked=True,
                validator_credential_present=True,
                broadcast_performed=False,
                translation_weights_active=False,
                chain_write_capability=False,
                weight_submission_capability=False,
                signature_scheme=certificate_signer.scheme,
                signature="0x" + "00" * 64,
            )
            signature = bytes(
                wallet_by_account[account].hotkey.sign(
                    mirror_readiness_statement_digest(provisional)
                )
            )
            readiness_statements.append(
                provisional.model_copy(update={"signature": "0x" + signature.hex()})
            )
        readiness = MirrorReadinessSet(
            schema=MIRROR_READINESS_SET_SCHEMA,
            protocol=PROTOCOL_VERSION,
            window_id=self.window.window_id,
            window_index=self.window.window_index,
            scoring_policy_sha256=self.window.scoring_policy_hash,
            discovery_rule_sha256=hashlib.sha256(self.discovery_bytes).hexdigest(),
            certified_release_sha256=hashlib.sha256(release_bytes).hexdigest(),
            anchor_intents_sha256=hashlib.sha256(anchor_bytes).hexdigest(),
            mirror_index_sha256=release.mirror_index_sha256,
            certified_release=release,
            anchor_intents=anchor_intents,
            statements=readiness_statements,
            pre_anchor_readiness_gate_passed=True,
            broadcast_performed=False,
            translation_weights_active=False,
            weight_submission_capability=False,
        )
        self.readiness_bytes = canonical_json_bytes(readiness)
        verify_live_mirror_readiness(
            policy=self.policy,
            discovery_rule_bytes=self.discovery_bytes,
            readiness_set_bytes=self.readiness_bytes,
        )

        proof = canonical_json_bytes({"schema": "test-closing-storage-proof/1"})
        publisher_by_account = {
            account_id32(item.publisher_hotkey): item for item in self.policy.publisher_registry
        }
        final_by_account = {
            account_id32(item.publisher_hotkey): raw
            for item, raw in zip(final_manifests, self.final_pool_bytes, strict=True)
        }
        publishers = [
            ClosingPublisherState(
                publisher_hotkey=entry.publisher_hotkey,
                owner_coldkey=entry.owner_coldkey,
                control_group_id=entry.control_group_id,
                registered=True,
                locked_collateral_alpha_rao=(self.policy.minimum_publisher_collateral_alpha_rao),
                minimum_locked_collateral_alpha_rao=(
                    self.policy.minimum_publisher_collateral_alpha_rao
                ),
                pool_manifest_sha256=hashlib.sha256(final_by_account[account]).hexdigest(),
                anchor_inclusion_block=self.window.closing_block,
            )
            for account, entry in sorted(publisher_by_account.items())
        ]
        validators = [
            ClosingValidatorState(
                validator_hotkey=entry.validator_hotkey,
                validator_permit=True,
            )
            for entry in self.policy.validator_registry
        ]
        neurons = [
            ClosingNeuron(
                uid=item.uid,
                hotkey=item.hotkey,
                root=item.root,
                registered=True,
                validator_permit=False,
                serving_url=f"https://miner-{item.uid}.example",
            )
            for item in sorted(rehearsal.miners, key=lambda item: item.uid)
        ]
        closing = ClosingSnapshot(
            schema=CLOSING_SNAPSHOT_SCHEMA,
            protocol=PROTOCOL_VERSION,
            proof_profile=CLOSING_SNAPSHOT_PROOF_PROFILE,
            collector_revision="test-proof-collector@1",
            proof_evidence_sha256=hashlib.sha256(proof).hexdigest(),
            netuid=78,
            window_id=self.window.window_id,
            window_index=self.window.window_index,
            scoring_policy_hash=self.window.scoring_policy_hash,
            closing_block=self.window.closing_block,
            closing_block_hash="0x" + "55" * 32,
            closing_block_timestamp_ms=1_600_000_000_000,
            accepted_at_unix_ms=(
                QUICKNET_GENESIS_MS + (self.window.selection_round - 1) * QUICKNET_PERIOD_MS - 1
            ),
            complete_publisher_registry=True,
            complete_validator_registry=True,
            complete_uid_snapshot=True,
            publishers=publishers,
            validators=validators,
            neurons=neurons,
        )
        announcement_proof = canonical_json_bytes(
            {"schema": "test-announcement-validator-storage-proof/1"}
        )
        announcement = AnnouncementValidatorSnapshot(
            schema=ANNOUNCEMENT_VALIDATOR_SNAPSHOT_SCHEMA,
            protocol=PROTOCOL_VERSION,
            proof_profile=ANNOUNCEMENT_VALIDATOR_PROOF_PROFILE,
            collector_revision="test-announcement-proof-collector@1",
            proof_evidence_sha256=hashlib.sha256(announcement_proof).hexdigest(),
            netuid=78,
            window_id=self.window.window_id,
            window_index=self.window.window_index,
            scoring_policy_hash=self.window.scoring_policy_hash,
            announcement_block=self.window.announcement_block,
            announcement_block_hash="0x" + "44" * 32,
            announcement_block_timestamp_ms=1_599_999_000_000,
            complete_validator_registry=True,
            validators=validators,
        )
        self.closing = VerifiedClosingSnapshot(
            snapshot=closing,
            snapshot_bytes=canonical_json_bytes(closing),
            proof_evidence_bytes=proof,
            announcement_snapshot=announcement,
            announcement_snapshot_bytes=canonical_json_bytes(announcement),
            announcement_proof_evidence_bytes=announcement_proof,
        )
        self.source = replace(
            self.source,
            mirror_discovery_rule_bytes=self.discovery_bytes,
            mirror_readiness_set_bytes=self.readiness_bytes,
            artifact_retrieval_evidence_bytes=canonical_json_bytes(
                {
                    "schema": "umi-pool-anchor-retrieval/1",
                    "protocol": PROTOCOL_VERSION,
                    "window_id": self.window.window_id,
                    "window_index": self.window.window_index,
                    "scoring_policy_hash": self.window.scoring_policy_hash,
                    "discovery_rule_sha256": hashlib.sha256(self.discovery_bytes).hexdigest(),
                    "anchor_outcomes": [
                        {
                            "publisher_hotkey": row.publisher_hotkey,
                            "sha256": row.pool_manifest_sha256,
                            "status": "qualified",
                        }
                        for row in closing.publishers
                    ],
                    "attempts": [],
                    "artifact_observed_wire_bytes": 0,
                    "artifact_accounted_wire_bytes": 0,
                }
            ),
        )
        self.pulse_bytes = canonical_json_bytes(
            {"randomness": RANDOMNESS, "round": ROUND, "signature": SIGNATURE}
        )
        self.material_store = ValidatorWindowMaterialStore(tmp_path / "materials")
        self.protocol_state = ValidatorProtocolStateStore(tmp_path / "protocol.sqlite3")
        self.prepared_calls = 0

    def prepared(self, context: PoolSelectionContext, _work) -> PreparedAssignmentSet:
        self.prepared_calls += 1
        issuance_block = self.window.closing_block + 1
        issuance_hash = "0x" + "66" * 32
        assignments = []
        nonce = 1_800_000_000_000_000_000
        delivery_by_key = {
            (item.batch_id, item.challenge_id): item for item in context.selected_video_deliveries
        }
        for manifest in context.selected_manifests:
            for public_item in manifest.items:
                delivery = delivery_by_key[(manifest.batch_id, public_item.challenge_id)]
                for miner in context.selected_panel:
                    request = TranslationRequest.model_validate(
                        {
                            "protocol": PROTOCOL_VERSION,
                            "window_id": self.window.window_id,
                            "batch_id": manifest.batch_id,
                            "challenge_id": public_item.challenge_id,
                            "issued_block": issuance_block,
                            "issued_block_hash": issuance_hash,
                            "deadline_block": (issuance_block + context.response_deadline_blocks),
                            "response_close_round": self.window.response_close_round,
                            "reveal_round": self.window.reveal_round,
                            "video": {
                                "url": delivery.url,
                                "sha256": public_item.media.sha256,
                                "size_bytes": public_item.media.size_bytes,
                                "media_type": public_item.media.media_type,
                            },
                            "task": {
                                "source_language": "ase",
                                "target_language": "en",
                                "stratum": public_item.stratum,
                            },
                            "scoring_policy_hash": self.window.scoring_policy_hash,
                        }
                    )
                    attempt = prepare_request_attempt(
                        request,
                        wallet=self.validator_wallet,
                        miner_hotkey=miner.hotkey,
                        nonce_ns=nonce,
                    )
                    nonce += 1
                    assignments.append(
                        TranscriptAssignment(
                            initial_attempt=attempt,
                            miner_url=miner.serving_url or "",
                        )
                    )
        assignments.sort(key=lambda item: item.assignment_id)
        return PreparedAssignmentSet(
            assignments=tuple(assignments),
            issuance_block=issuance_block,
            issuance_block_hash=issuance_hash,
            issuance_block_timestamp_ms=(
                QUICKNET_GENESIS_MS + (self.window.selection_round - 1) * QUICKNET_PERIOD_MS + 1_000
            ),
            finality_evidence_bytes=b"issuance-block-finality-proof",
        )

    def delivery_issuance(self, context, _work) -> IssuedVideoDeliverySet:
        request = build_delivery_request(
            context.window,
            context.selected_video_commitments,
            delivery_token_seed=base64url_encode(b"\x99" * 32),
        )
        request_bytes = canonical_json_bytes(request)
        expiry = (
            QUICKNET_GENESIS_MS + (context.window.response_close_round - 1) * QUICKNET_PERIOD_MS
        )
        response = VideoDeliveryIssuanceResponse(
            schema=DELIVERY_ISSUANCE_RESPONSE_SCHEMA,
            protocol=PROTOCOL_VERSION,
            window_id=context.window.window_id,
            window_index=context.window.window_index,
            scoring_policy_hash=context.window.scoring_policy_hash,
            response_close_round=context.window.response_close_round,
            deliveries=[
                IssuedVideoDelivery(
                    batch_id=item.batch_id,
                    challenge_id=item.challenge_id,
                    sha256=item.sha256,
                    size_bytes=item.size_bytes,
                    url=(
                        "https://delivery.example/v1/umi/deliveries/"
                        + derive_delivery_token(request, item)
                    ),
                    expires_at_unix_ms=expiry,
                )
                for item in context.selected_video_commitments
            ],
        )
        response_bytes = canonical_json_bytes(response)
        evidence = VideoDeliveryIssuanceEvidence(
            schema=DELIVERY_ISSUANCE_EVIDENCE_SCHEMA,
            protocol=PROTOCOL_VERSION,
            window_id=context.window.window_id,
            window_index=context.window.window_index,
            scoring_policy_hash=context.window.scoring_policy_hash,
            discovery_rule_sha256=hashlib.sha256(self.discovery_bytes).hexdigest(),
            authentication_profile=(
                self.policy.implementation_pins.rules.mirror_authentication_profile
            ),
            issuance_origin="https://mirror.example",
            issuance_path=DEFAULT_DELIVERY_ISSUANCE_PATH,
            request_sha256=hashlib.sha256(request_bytes).hexdigest(),
            request_size_bytes=len(request_bytes),
            response_sha256=hashlib.sha256(response_bytes).hexdigest(),
            response_size_bytes=len(response_bytes),
            attempts=[
                {
                    "attempt_index": 0,
                    "url_sha256": hashlib.sha256(
                        ("https://mirror.example" + DEFAULT_DELIVERY_ISSUANCE_PATH).encode("utf-8")
                    ).hexdigest(),
                    "status": "success",
                    "observed_wire_bytes": 1,
                    "accounted_wire_bytes": 1,
                    "error_code": None,
                    "response_body_sha256": hashlib.sha256(response_bytes).hexdigest(),
                    "response_body_size_bytes": len(response_bytes),
                }
            ],
            delivery_observed_wire_bytes=1,
            delivery_accounted_wire_bytes=1,
            observed_window_wire_bytes=1,
            accounted_window_wire_bytes=1,
        )
        return IssuedVideoDeliverySet(
            deliveries=tuple(response.deliveries),
            discovery_rule_bytes=self.discovery_bytes,
            request_bytes=request_bytes,
            response_bytes=response_bytes,
            evidence_bytes=canonical_json_bytes(evidence),
        )

    def effect(self, **kwargs) -> PoolAndSelectionEffect:
        return PoolAndSelectionEffect(
            policy=self.policy,
            validator_hotkey=self.validator_wallet.hotkey.ss58_address,
            material_store=self.material_store,
            protocol_state=self.protocol_state,
            ports=PoolEffectPorts(
                source=getattr(self, "source_port", lambda _work: self.source),
                closing_snapshot=lambda _work: self.closing,
                selection_pulse=lambda _work: self.pulse_bytes,
                delivery_issuance=self.delivery_issuance,
                prepared_assignments=self.prepared,
            ),
            **kwargs,
        )


@pytest.mark.asyncio
async def test_pool_effect_persists_exact_plan_and_binds_recovery_receipt(tmp_path) -> None:
    fixture = _Fixture(tmp_path)
    effect = fixture.effect()
    journal = ValidatorStageJournal(tmp_path / "journal")
    adapter = JournalStageAdapter(
        stage=WindowStage.POOL_AND_SELECTION,
        journal=journal,
        effect=effect,
    )

    completion = await adapter.execute(fixture.work)
    assert completion.completed_stage is WindowStage.POOL_AND_SELECTION
    assert fixture.prepared_calls == 1

    record = journal.load(fixture.window.window_id, WindowStage.POOL_AND_SELECTION)
    objects = [journal.read_object(item) for item in record.receipt.objects]
    decoded = [json.loads(item) for item in objects if item.startswith(b"{")]
    selection = next(
        item for item in decoded if item.get("schema") == POOL_SELECTION_EVIDENCE_SCHEMA
    )
    readiness_digest = hashlib.sha256(fixture.readiness_bytes).hexdigest()
    assert selection["mirror_readiness_set"] == {
        "sha256": readiness_digest,
        "size_bytes": len(fixture.readiness_bytes),
        "media_type": "application/json",
    }
    assert (
        objects[
            next(
                index
                for index, item in enumerate(record.receipt.objects)
                if item.sha256 == readiness_digest
            )
        ]
        == fixture.readiness_bytes
    )
    assert len(selection["candidates"]) == 3
    assert (
        len([item for item in selection["candidates"] if item["selection_ordinal"] is not None])
        == 2
    )
    assert len(selection["selected_panel"]) == 2
    assert len(selection["selected_video_deliveries"]) == 28
    assert len(selection["assignment_ids"]) == 56
    assert all(item["ground_truth_envelope"]["sha256"] for item in selection["candidates"])

    assignment_work = replace(
        fixture.work,
        window=replace(
            fixture.work.window,
            stage=WindowStage.ASSIGNMENT,
            updated_at_unix_ns=2,
            revision=1,
        ),
        completed_evidence=(
            StageEvidence(
                window_id=fixture.window.window_id,
                stage=WindowStage.POOL_AND_SELECTION,
                evidence_sha256=completion.evidence_sha256,
                recorded_at_unix_ns=2,
            ),
        ),
    )
    loaded = fixture.material_store.load_for_work(assignment_work)
    assert len(loaded.plan.assignments) == 56
    assert loaded.pool_stage_evidence_sha256 == completion.evidence_sha256
    assert {item.miner_url for item in loaded.plan.assignments} == {
        "https://miner-10.example",
        "https://miner-11.example",
    }
    miner_video_urls = {item.initial_attempt.request.video.url for item in loaded.plan.assignments}
    assert miner_video_urls
    assert all(
        url.startswith("https://delivery.example/v1/umi/deliveries/") for url in miner_video_urls
    )
    assert all("objects.example" not in url for url in miner_video_urls)

    recovered = await adapter.execute(fixture.work)
    assert recovered.evidence_sha256 == completion.evidence_sha256
    assert fixture.prepared_calls == 1


@pytest.mark.asyncio
async def test_pool_effect_rejects_anchor_source_without_mirror_readiness(tmp_path) -> None:
    fixture = _Fixture(tmp_path)
    fixture.source = replace(
        fixture.source,
        mirror_discovery_rule_bytes=None,
        mirror_readiness_set_bytes=None,
    )

    with pytest.raises(PoolEffectBindingError) as captured:
        await fixture.effect().perform(
            operation_id=stage_operation_id(
                fixture.window.window_id,
                WindowStage.POOL_AND_SELECTION,
            ),
            work=fixture.work,
        )

    assert captured.value.reason_code == "mirror_readiness_evidence_missing"


def test_closing_snapshot_rejects_plain_http_miner_serving_origin(tmp_path) -> None:
    fixture = _Fixture(tmp_path)
    neuron = fixture.closing.snapshot.neurons[0]
    values = neuron.model_dump(mode="json")
    values["serving_url"] = "http://miner.example"
    with pytest.raises(ValueError, match="absolute HTTPS origin"):
        ClosingNeuron.model_validate(values)


def test_delivery_context_orders_opaque_ids_by_decoded_bytes(tmp_path) -> None:
    fixture = _Fixture(tmp_path)
    first = VideoDeliveryCommitment(
        batch_id=base64url_encode(b"\x00" * 16),
        challenge_id=base64url_encode(b"\x00" * 16),
        sha256="11" * 32,
        size_bytes=1,
    )
    second = VideoDeliveryCommitment(
        batch_id=base64url_encode(b"\xfb" * 16),
        challenge_id=base64url_encode(b"\x00" * 16),
        sha256="22" * 32,
        size_bytes=1,
    )
    context = DeliveryIssuanceContext(
        window=fixture.window,
        selected_video_commitments=(first, second),
    )
    assert context.selected_video_commitments == (first, second)
    assert second.batch_id < first.batch_id


@pytest.mark.asyncio
async def test_pool_effect_ignores_anchor_source_mismatch(tmp_path) -> None:
    fixture = _Fixture(tmp_path)
    first = fixture.closing.snapshot.publishers[0]
    changed = first.model_copy(update={"pool_manifest_sha256": "ff" * 32})
    snapshot = fixture.closing.snapshot.model_copy(
        update={"publishers": [changed, *fixture.closing.snapshot.publishers[1:]]}
    )
    fixture.closing = replace(
        fixture.closing,
        snapshot=snapshot,
        snapshot_bytes=canonical_json_bytes(snapshot),
    )
    fixture.source = replace(
        fixture.source,
        artifact_retrieval_evidence_bytes=canonical_json_bytes(
            {
                "schema": "umi-pool-anchor-retrieval/1",
                "protocol": "umi-asl/0.1",
                "window_id": fixture.window.window_id,
                "window_index": fixture.window.window_index,
                "scoring_policy_hash": fixture.window.scoring_policy_hash,
                "discovery_rule_sha256": hashlib.sha256(fixture.discovery_bytes).hexdigest(),
                "anchor_outcomes": [
                    {
                        "publisher_hotkey": row.publisher_hotkey,
                        "sha256": row.pool_manifest_sha256,
                        "status": "ignored_digest_mismatch" if index == 0 else "qualified",
                    }
                    for index, row in enumerate(snapshot.publishers)
                ],
                "attempts": [],
                "artifact_observed_wire_bytes": 0,
                "artifact_accounted_wire_bytes": 0,
            }
        ),
    )

    result = await fixture.effect().perform(
        operation_id=stage_operation_id(
            fixture.window.window_id,
            WindowStage.POOL_AND_SELECTION,
        ),
        work=fixture.work,
    )
    objects = [json.loads(item.data) for item in result.objects if item.data.startswith(b"{")]
    selection = next(
        item for item in objects if item.get("schema") == POOL_SELECTION_EVIDENCE_SCHEMA
    )
    assert len(selection["candidates"]) == 2
    assert hashlib.sha256(fixture.final_pool_bytes[0]).hexdigest() not in {
        item["sha256"] for item in selection["source_objects"]
    }


@pytest.mark.asyncio
@pytest.mark.parametrize("bad_kind", ["malformed", "uncertified"])
async def test_pool_effect_ignores_invalid_eligible_anchor_beside_valid_pools(
    tmp_path,
    bad_kind: str,
) -> None:
    fixture = _Fixture(tmp_path)
    if bad_kind == "malformed":
        bad = b'{"schema":"umi-pool-manifest/1","broken":true}'
    else:
        decoded = json.loads(fixture.final_pool_bytes[0])
        decoded["availability_certificate"]["signatures"][0]["signature"] = "0x" + "00" * 64
        bad = canonical_json_bytes(decoded)
    fixture.source = replace(
        fixture.source,
        final_pool_manifest_bytes=(bad, *fixture.final_pool_bytes[1:]),
    )
    first = fixture.closing.snapshot.publishers[0].model_copy(
        update={"pool_manifest_sha256": hashlib.sha256(bad).hexdigest()}
    )
    snapshot = fixture.closing.snapshot.model_copy(
        update={"publishers": [first, *fixture.closing.snapshot.publishers[1:]]}
    )
    fixture.closing = replace(
        fixture.closing,
        snapshot=snapshot,
        snapshot_bytes=canonical_json_bytes(snapshot),
    )
    fixture.source = replace(
        fixture.source,
        artifact_retrieval_evidence_bytes=canonical_json_bytes(
            {
                "schema": "umi-pool-anchor-retrieval/1",
                "protocol": "umi-asl/0.1",
                "window_id": fixture.window.window_id,
                "window_index": fixture.window.window_index,
                "scoring_policy_hash": fixture.window.scoring_policy_hash,
                "discovery_rule_sha256": hashlib.sha256(fixture.discovery_bytes).hexdigest(),
                "anchor_outcomes": [
                    {
                        "publisher_hotkey": row.publisher_hotkey,
                        "sha256": row.pool_manifest_sha256,
                        "status": "ignored_invalid" if index == 0 else "qualified",
                    }
                    for index, row in enumerate(snapshot.publishers)
                ],
                "attempts": [],
                "artifact_observed_wire_bytes": 0,
                "artifact_accounted_wire_bytes": 0,
            }
        ),
    )

    result = await fixture.effect().perform(
        operation_id=stage_operation_id(
            fixture.window.window_id,
            WindowStage.POOL_AND_SELECTION,
        ),
        work=fixture.work,
    )
    objects = [json.loads(item.data) for item in result.objects if item.data.startswith(b"{")]
    selection = next(
        item for item in objects if item.get("schema") == POOL_SELECTION_EVIDENCE_SCHEMA
    )
    assert len(selection["candidates"]) == 2
    assert hashlib.sha256(bad).hexdigest() not in {
        item["sha256"] for item in selection["source_objects"]
    }


@pytest.mark.asyncio
async def test_full_certificate_is_verified_but_ineligible_anchor_is_not_candidate(
    tmp_path,
) -> None:
    fixture = _Fixture(tmp_path)
    first = fixture.closing.snapshot.publishers[0]
    changed = first.model_copy(update={"locked_collateral_alpha_rao": 0})
    snapshot = fixture.closing.snapshot.model_copy(
        update={"publishers": [changed, *fixture.closing.snapshot.publishers[1:]]}
    )
    fixture.closing = replace(
        fixture.closing,
        snapshot=snapshot,
        snapshot_bytes=canonical_json_bytes(snapshot),
    )

    result = await fixture.effect().perform(
        operation_id=stage_operation_id(
            fixture.window.window_id,
            WindowStage.POOL_AND_SELECTION,
        ),
        work=fixture.work,
    )
    objects = [json.loads(item.data) for item in result.objects if item.data.startswith(b"{")]
    selection = next(
        item for item in objects if item.get("schema") == POOL_SELECTION_EVIDENCE_SCHEMA
    )
    assert len(selection["candidates"]) == 2
    source_hashes = {item["sha256"] for item in selection["source_objects"]}
    assert {hashlib.sha256(item).hexdigest() for item in fixture.final_pool_bytes}.issubset(
        source_hashes
    )


@pytest.mark.asyncio
async def test_pool_effect_rejects_duplicate_key_pulse(tmp_path) -> None:
    fixture = _Fixture(tmp_path)
    fixture.pulse_bytes = (
        b'{"randomness":"'
        + RANDOMNESS.encode()
        + b'","round":1000000,"round":1000000,"signature":"'
        + SIGNATURE.encode()
        + b'"}'
    )
    with pytest.raises(PoolEffectBindingError, match="duplicate JSON key"):
        await fixture.effect().perform(
            operation_id=stage_operation_id(
                fixture.window.window_id,
                WindowStage.POOL_AND_SELECTION,
            ),
            work=fixture.work,
        )


@pytest.mark.asyncio
async def test_pool_effect_waits_for_pulse_before_any_other_port(tmp_path) -> None:
    fixture = _Fixture(tmp_path)
    calls = {"source": 0, "closing": 0, "prepared": 0}

    def source(_work):
        calls["source"] += 1
        return fixture.source

    def closing(_work):
        calls["closing"] += 1
        return fixture.closing

    async def pending_pulse(_work):
        raise StagePending("quicknet_selection_pulse_pending")

    def prepared(context, work):
        calls["prepared"] += 1
        return fixture.prepared(context, work)

    effect = PoolAndSelectionEffect(
        policy=fixture.policy,
        validator_hotkey=fixture.validator_wallet.hotkey.ss58_address,
        material_store=fixture.material_store,
        protocol_state=fixture.protocol_state,
        ports=PoolEffectPorts(
            source=source,
            closing_snapshot=closing,
            selection_pulse=pending_pulse,
            delivery_issuance=fixture.delivery_issuance,
            prepared_assignments=prepared,
        ),
    )
    with pytest.raises(StagePending, match="quicknet_selection_pulse_pending") as caught:
        await effect.perform(
            operation_id=stage_operation_id(
                fixture.window.window_id,
                WindowStage.POOL_AND_SELECTION,
            ),
            work=fixture.work,
        )
    assert caught.value.reason_code == "quicknet_selection_pulse_pending"
    assert calls == {"source": 0, "closing": 0, "prepared": 0}


@pytest.mark.asyncio
async def test_availability_uses_announcement_permits_not_closing_permits(tmp_path) -> None:
    fixture = _Fixture(tmp_path)
    closing_rows = list(fixture.closing.snapshot.validators)
    changed_index = next(
        index
        for index, row in enumerate(closing_rows)
        if account_id32(row.validator_hotkey)
        != account_id32(fixture.validator_wallet.hotkey.ss58_address)
    )
    closing_rows[changed_index] = closing_rows[changed_index].model_copy(
        update={"validator_permit": False}
    )
    closing = fixture.closing.snapshot.model_copy(update={"validators": closing_rows})
    fixture.closing = replace(
        fixture.closing,
        snapshot=closing,
        snapshot_bytes=canonical_json_bytes(closing),
    )

    result = await fixture.effect().perform(
        operation_id=stage_operation_id(
            fixture.window.window_id,
            WindowStage.POOL_AND_SELECTION,
        ),
        work=fixture.work,
    )
    assert result.decision is not None


@pytest.mark.asyncio
async def test_inactive_announcement_signer_is_not_rescued_by_closing_permit(tmp_path) -> None:
    fixture = _Fixture(tmp_path)
    rows = list(fixture.closing.announcement_snapshot.validators)
    rows[-1] = rows[-1].model_copy(update={"validator_permit": False})
    announcement = fixture.closing.announcement_snapshot.model_copy(update={"validators": rows})
    fixture.closing = replace(
        fixture.closing,
        announcement_snapshot=announcement,
        announcement_snapshot_bytes=canonical_json_bytes(announcement),
    )

    with pytest.raises(PoolEffectBindingError) as caught:
        await fixture.effect().perform(
            operation_id=stage_operation_id(
                fixture.window.window_id,
                WindowStage.POOL_AND_SELECTION,
            ),
            work=fixture.work,
        )
    assert caught.value.reason_code == "announcement_active_validator_count_below_minimum"


@pytest.mark.asyncio
async def test_issuing_validator_requires_separate_closing_permit(tmp_path) -> None:
    fixture = _Fixture(tmp_path)
    rows = [
        row.model_copy(update={"validator_permit": False})
        if account_id32(row.validator_hotkey)
        == account_id32(fixture.validator_wallet.hotkey.ss58_address)
        else row
        for row in fixture.closing.snapshot.validators
    ]
    closing = fixture.closing.snapshot.model_copy(update={"validators": rows})
    fixture.closing = replace(
        fixture.closing,
        snapshot=closing,
        snapshot_bytes=canonical_json_bytes(closing),
    )
    with pytest.raises(PoolEffectBindingError, match="no closing-block permit") as caught:
        await fixture.effect().perform(
            operation_id=stage_operation_id(
                fixture.window.window_id,
                WindowStage.POOL_AND_SELECTION,
            ),
            work=fixture.work,
        )
    assert caught.value.reason_code == "issuing_validator_closing_permit_missing"


@pytest.mark.asyncio
async def test_closing_acceptance_at_or_after_pulse_is_rejected(tmp_path) -> None:
    fixture = _Fixture(tmp_path)
    publication_ms = QUICKNET_GENESIS_MS + (fixture.window.selection_round - 1) * QUICKNET_PERIOD_MS
    closing = fixture.closing.snapshot.model_copy(update={"accepted_at_unix_ms": publication_ms})
    fixture.closing = replace(
        fixture.closing,
        snapshot=closing,
        snapshot_bytes=canonical_json_bytes(closing),
    )
    with pytest.raises(PoolEffectBindingError, match="accepted after selection pulse") as caught:
        await fixture.effect().perform(
            operation_id=stage_operation_id(
                fixture.window.window_id,
                WindowStage.POOL_AND_SELECTION,
            ),
            work=fixture.work,
        )
    assert caught.value.reason_code == "closing_acceptance_not_before_selection_pulse"


@pytest.mark.asyncio
async def test_empty_eligible_candidate_pool_has_stable_reason_code(tmp_path) -> None:
    fixture = _Fixture(tmp_path)
    publishers = [
        row.model_copy(update={"registered": False}) for row in fixture.closing.snapshot.publishers
    ]
    closing = fixture.closing.snapshot.model_copy(update={"publishers": publishers})
    fixture.closing = replace(
        fixture.closing,
        snapshot=closing,
        snapshot_bytes=canonical_json_bytes(closing),
    )

    result = await fixture.effect().perform(
        operation_id=stage_operation_id(
            fixture.window.window_id,
            WindowStage.POOL_AND_SELECTION,
        ),
        work=fixture.work,
    )
    no_score = _pool_no_score(result)
    assert no_score.schema_ == POOL_NO_SCORE_SCHEMA
    assert no_score.reason_code == "candidate_pool_empty"
    assert no_score.terminal_outcome == "skipped"
    assert no_score.candidates == []
    assert fixture.prepared_calls == 0


@pytest.mark.asyncio
async def test_timely_anchor_never_uses_the_true_empty_source_bypass(tmp_path) -> None:
    fixture = _Fixture(tmp_path)
    source_calls = 0

    async def missing_source(_work):
        nonlocal source_calls
        source_calls += 1
        return None

    fixture.source_port = missing_source
    with pytest.raises(PoolEffectBindingError) as raised:
        await fixture.effect().perform(
            operation_id=stage_operation_id(
                fixture.window.window_id,
                WindowStage.POOL_AND_SELECTION,
            ),
            work=fixture.work,
        )
    assert raised.value.reason_code == "pool_source_type_invalid"
    assert source_calls == 1


@pytest.mark.asyncio
async def test_insufficient_candidate_control_groups_has_stable_reason_code(tmp_path) -> None:
    fixture = _Fixture(tmp_path)
    publishers = [
        row if index == 0 else row.model_copy(update={"registered": False})
        for index, row in enumerate(fixture.closing.snapshot.publishers)
    ]
    closing = fixture.closing.snapshot.model_copy(update={"publishers": publishers})
    fixture.closing = replace(
        fixture.closing,
        snapshot=closing,
        snapshot_bytes=canonical_json_bytes(closing),
    )

    result = await fixture.effect().perform(
        operation_id=stage_operation_id(
            fixture.window.window_id,
            WindowStage.POOL_AND_SELECTION,
        ),
        work=fixture.work,
    )
    no_score = _pool_no_score(result)
    assert no_score.reason_code == "candidate_control_group_count_insufficient"
    assert no_score.terminal_outcome == "void"
    assert len(no_score.candidates) == 1
    assert fixture.prepared_calls == 0


@pytest.mark.asyncio
async def test_empty_eligible_miner_set_has_stable_reason_code(tmp_path) -> None:
    fixture = _Fixture(tmp_path)
    neurons = [
        row.model_copy(update={"validator_permit": True})
        for row in fixture.closing.snapshot.neurons
    ]
    closing = fixture.closing.snapshot.model_copy(update={"neurons": neurons})
    fixture.closing = replace(
        fixture.closing,
        snapshot=closing,
        snapshot_bytes=canonical_json_bytes(closing),
    )

    result = await fixture.effect().perform(
        operation_id=stage_operation_id(
            fixture.window.window_id,
            WindowStage.POOL_AND_SELECTION,
        ),
        work=fixture.work,
    )
    no_score = _pool_no_score(result)
    assert no_score.reason_code == "eligible_miner_set_empty"
    assert no_score.terminal_outcome == "skipped"
    assert len([item for item in no_score.candidates if item.selection_ordinal is not None]) == 2
    assert fixture.prepared_calls == 0


@pytest.mark.asyncio
async def test_pool_effect_rejects_incomplete_prepared_cartesian_set(tmp_path) -> None:
    fixture = _Fixture(tmp_path)

    def incomplete(context, work):
        prepared = fixture.prepared(context, work)
        return replace(prepared, assignments=prepared.assignments[:-1])

    effect = PoolAndSelectionEffect(
        policy=fixture.policy,
        validator_hotkey=fixture.validator_wallet.hotkey.ss58_address,
        material_store=fixture.material_store,
        protocol_state=fixture.protocol_state,
        ports=PoolEffectPorts(
            source=lambda _work: fixture.source,
            closing_snapshot=lambda _work: fixture.closing,
            selection_pulse=lambda _work: fixture.pulse_bytes,
            delivery_issuance=fixture.delivery_issuance,
            prepared_assignments=incomplete,
        ),
    )
    with pytest.raises(PoolEffectBindingError, match="omit selected work"):
        await effect.perform(
            operation_id=stage_operation_id(
                fixture.window.window_id,
                WindowStage.POOL_AND_SELECTION,
            ),
            work=fixture.work,
        )


@pytest.mark.asyncio
async def test_pool_effect_enforces_stage_journal_object_preflight(tmp_path) -> None:
    fixture = _Fixture(tmp_path)
    effect = fixture.effect(maximum_stage_object_bytes=1_024)
    with pytest.raises(PoolEffectLimitError, match="stage-journal object ceiling"):
        await effect.perform(
            operation_id=stage_operation_id(
                fixture.window.window_id,
                WindowStage.POOL_AND_SELECTION,
            ),
            work=fixture.work,
        )
    assert fixture.material_store.load(fixture.window.window_id).pool_stage_evidence_sha256 is None


def test_verified_closing_snapshot_rejects_nonreproducing_proof() -> None:
    proof = b"proof"
    snapshot = ClosingSnapshot(
        schema=CLOSING_SNAPSHOT_SCHEMA,
        protocol=PROTOCOL_VERSION,
        proof_profile=CLOSING_SNAPSHOT_PROOF_PROFILE,
        collector_revision="test",
        proof_evidence_sha256="00" * 32,
        netuid=78,
        window_id="11" * 32,
        window_index=0,
        scoring_policy_hash="22" * 32,
        closing_block=10,
        closing_block_hash="0x" + "33" * 32,
        closing_block_timestamp_ms=1,
        accepted_at_unix_ms=1,
        complete_publisher_registry=True,
        complete_validator_registry=True,
        complete_uid_snapshot=True,
        publishers=[
            ClosingPublisherState(
                publisher_hotkey=_wallet("//PublisherX").hotkey.ss58_address,
                owner_coldkey=_wallet("//OwnerX").hotkey.ss58_address,
                control_group_id="44" * 32,
                registered=False,
                locked_collateral_alpha_rao=0,
                minimum_locked_collateral_alpha_rao=0,
                pool_manifest_sha256=None,
                anchor_inclusion_block=None,
            )
        ],
        validators=[
            ClosingValidatorState(
                validator_hotkey=_wallet("//ValidatorX").hotkey.ss58_address,
                validator_permit=False,
            )
        ],
        neurons=[
            ClosingNeuron(
                uid=0,
                hotkey=_wallet("//MinerX").hotkey.ss58_address,
                root=_wallet("//RootX").hotkey.ss58_address,
                registered=True,
                validator_permit=False,
                serving_url=None,
            )
        ],
    )
    announcement_proof = b"announcement-proof"
    announcement = AnnouncementValidatorSnapshot(
        schema=ANNOUNCEMENT_VALIDATOR_SNAPSHOT_SCHEMA,
        protocol=PROTOCOL_VERSION,
        proof_profile=ANNOUNCEMENT_VALIDATOR_PROOF_PROFILE,
        collector_revision="test",
        proof_evidence_sha256=hashlib.sha256(announcement_proof).hexdigest(),
        netuid=78,
        window_id="11" * 32,
        window_index=0,
        scoring_policy_hash="22" * 32,
        announcement_block=1,
        announcement_block_hash="0x" + "32" * 32,
        announcement_block_timestamp_ms=1,
        complete_validator_registry=True,
        validators=snapshot.validators,
    )
    with pytest.raises(PoolEffectBindingError, match="digest does not reproduce"):
        VerifiedClosingSnapshot(
            snapshot=snapshot,
            snapshot_bytes=canonical_json_bytes(snapshot),
            proof_evidence_bytes=proof,
            announcement_snapshot=announcement,
            announcement_snapshot_bytes=canonical_json_bytes(announcement),
            announcement_proof_evidence_bytes=announcement_proof,
        )


@pytest.mark.asyncio
async def test_source_rejects_artifact_commitment_drift(tmp_path) -> None:
    fixture = _Fixture(tmp_path)
    first = fixture.batch_sources[0]
    public = json.loads(first.public_manifest_bytes)
    public["ciphertext_sha256"] = hashlib.sha256(b"other").hexdigest()
    changed = replace(first, public_manifest_bytes=canonical_json_bytes(public))
    source = replace(fixture.source, batch_artifacts=(changed, *fixture.batch_sources[1:]))
    effect = PoolAndSelectionEffect(
        policy=fixture.policy,
        validator_hotkey=fixture.validator_wallet.hotkey.ss58_address,
        material_store=fixture.material_store,
        protocol_state=fixture.protocol_state,
        ports=PoolEffectPorts(
            source=lambda _work: source,
            closing_snapshot=lambda _work: fixture.closing,
            selection_pulse=lambda _work: fixture.pulse_bytes,
            delivery_issuance=fixture.delivery_issuance,
            prepared_assignments=fixture.prepared,
        ),
    )
    with pytest.raises(PoolEffectBindingError):
        await effect.perform(
            operation_id=stage_operation_id(
                fixture.window.window_id,
                WindowStage.POOL_AND_SELECTION,
            ),
            work=fixture.work,
        )
