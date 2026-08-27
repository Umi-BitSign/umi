from __future__ import annotations

import hashlib
import json
from types import SimpleNamespace

import bittensor as bt
import bittensor_core
import pytest

from umi.artifacts import PUBLIC_BATCH_MANIFEST_SCHEMA, PublicBatchManifest
from umi.canary import wer_canary_stratum
from umi.crypto import sign_response_digest
from umi.encoding import account_id32
from umi.policy import (
    PolicyImplementationPins,
    PublisherControlGroup,
    PublisherRegistryEntry,
    ScoringPolicy,
    ValidatorRegistryEntry,
)
from umi.pool import (
    AVAILABILITY_SCHEMA,
    POOL_MANIFEST_SCHEMA,
    AvailabilityCertificate,
    CandidateBatch,
    PoolBody,
    availability_digest,
    availability_leaf,
    availability_set_root,
    batch_commitment,
    candidate_pool_root,
    select_batches,
    selection_seed,
)
from umi.protocol import (
    GROUND_TRUTH_SCHEMA,
    GroundTruthPayload,
    base64url_encode,
    canonical_json_bytes,
    request_digest,
)
from umi.shadow import (
    NO_CHAIN_REASON,
    SHADOW_REHEARSAL_SCHEMA,
    SHADOW_RESPONSE_SCHEMA,
    RehearsalResponsePayload,
    ShadowRehearsalEvidence,
    parse_shadow_rehearsal_evidence,
    rehearsal_response_digest,
    run_shadow_rehearsal,
)
from umi.window import QUICKNET_GENESIS_MS, WindowClock

ROUND = 1_000_000
SIGNATURE = (
    "83ad29e4c409f9470fc2ef02f90214df49e02b441a1a241a82d622d9f608ef9"
    "8fd8b11a029f1bee9d9e83b45088abe72"
)
RANDOMNESS = "b22aad4794f7451896f7a371aa46106fd84d919f3f569acd5b2fddf1d1440af3"


def _wallet(uri: str) -> SimpleNamespace:
    hotkey = bt.sp_core.Keypair.create_from_uri(uri)
    coldkey = bt.sp_core.Keypair.create_from_uri(uri + "//cold")
    return SimpleNamespace(hotkey=hotkey, coldkey=coldkey, coldkeypub=coldkey)


def _policy(
    publisher_wallets: list[SimpleNamespace],
    validator_wallets: list[SimpleNamespace],
) -> ScoringPolicy:
    groups = [
        PublisherControlGroup(
            control_group_id=f"{index:064x}",
            administrator=_wallet(f"//Group{index}").hotkey.ss58_address,
        )
        for index in range(1, 4)
    ]
    publishers = [
        PublisherRegistryEntry(
            publisher_hotkey=wallet.hotkey.ss58_address,
            owner_coldkey=groups[index - 1].administrator,
            control_group_id=groups[index - 1].control_group_id,
        )
        for index, wallet in enumerate(publisher_wallets, 1)
    ]
    publishers.sort(key=lambda item: account_id32(item.publisher_hotkey))
    validators = [
        ValidatorRegistryEntry(
            validator_hotkey=wallet.hotkey.ss58_address,
            administrator_id=f"{100 + index:064x}",
        )
        for index, wallet in enumerate(validator_wallets)
    ]
    validators.sort(key=lambda item: account_id32(item.validator_hotkey))
    return ScoringPolicy.launch(
        translation_weights_active=False,
        activation_block=1_000,
        minimum_publisher_collateral_alpha_rao=1_000_000_000,
        soak_start_window_index=0,
        validator_capacity_set_root="aa" * 32,
        validator_cost_schedule_hash="bb" * 32,
        implementation_pins=PolicyImplementationPins.local_rehearsal(),
        validator_registry=validators,
        control_group_registry=groups,
        publisher_registry=publishers,
    )


def _schedule(policy: ScoringPolicy):
    selection_timestamp = QUICKNET_GENESIS_MS + (ROUND - 1) * 3_000
    announcement_timestamp = selection_timestamp - 1_000 * (
        policy.clock.anchor_blocks * policy.clock.target_block_interval_seconds
        + policy.clock.selection_finality_buffer_seconds
    )
    clock = WindowClock(
        activation_block=policy.activation_block,
        window_stride_blocks=policy.clock.window_stride_blocks,
        proposal_blocks=policy.clock.proposal_blocks,
        anchor_blocks=policy.clock.anchor_blocks,
        target_block_interval_seconds=policy.clock.target_block_interval_seconds,
        selection_finality_buffer_seconds=policy.clock.selection_finality_buffer_seconds,
        issue_allowance_seconds=policy.clock.issue_allowance_seconds,
        response_window_seconds=policy.clock.response_window_seconds,
        delivery_grace_seconds=policy.clock.delivery_grace_seconds,
        reveal_margin_seconds=policy.clock.reveal_margin_seconds,
    )
    from umi.policy import scoring_policy_hash

    return announcement_timestamp, clock.derive(
        0,
        netuid=78,
        announcement_block_hash="0x" + "33" * 32,
        announcement_timestamp_ms=announcement_timestamp,
        scoring_policy_hash=scoring_policy_hash(policy),
    )


def _batch_artifact(
    *,
    ordinal: int,
    publisher_hotkey: str,
    window_id: str,
    policy_hash: str,
    response_close_round: int,
    reveal_round: int,
) -> tuple[PublicBatchManifest, GroundTruthPayload, bytes]:
    batch_id = base64url_encode(bytes([ordinal]) * 16)
    ordinary_strata = ["fingerspelling"] * 2 + ["short_utterance"] * 4 + ["continuous"] * 6
    strata = [
        *ordinary_strata,
        "fingerspelling",
        wer_canary_stratum(window_id, batch_id),
    ]
    public_items = []
    ground_items = []
    for item_index, stratum in enumerate(strata):
        unique = ordinal * 100 + item_index + 1
        challenge_id = base64url_encode(bytes([ordinal * 16 + item_index]) * 16)
        consent_hash = f"{10_000 + unique:064x}"
        public_items.append(
            {
                "challenge_id": challenge_id,
                "metric": "cer" if stratum == "fingerspelling" else "wer",
                "stratum": stratum,
                "media": {
                    "sha256": f"{20_000 + unique:064x}",
                    "frame_digest": f"{30_000 + unique:064x}",
                    "size_bytes": 1_000_000,
                    "duration_ms": 5_000,
                    "width": 1280,
                    "height": 720,
                    "frame_rate_numerator": 30_000,
                    "frame_rate_denominator": 1_001,
                    "media_type": "video/mp4",
                    "container": "mp4",
                    "video_codec": "h264",
                    "audio_track_count": 0,
                    "metadata_stripped": True,
                },
                "signer_id_sha256": f"{40_000 + ordinal * 10 + item_index // 2:064x}",
                "consent_manifest_sha256": consent_hash,
                "provenance_manifest_sha256": f"{50_000 + unique:064x}",
            }
        )
        canary = item_index >= 12
        script_hash = f"{60_000 + unique:064x}"
        if canary:
            reserved_hash = f"{70_000 + unique:064x}"
            if stratum == "fingerspelling":
                actual = ["aaaaaaaa", "aaaaaaaaa", "aaaaaaa"]
                mismatch = ["zzzzzzzz", "zzzzzzzzz", "zzzzzzz"]
            else:
                actual = ["hello world", "greetings earth", "good morning"]
                mismatch = ["purple chairs", "zebra quantum", "distant ocean"]
            canary_evidence = {
                "actual_references": actual,
                "actual_script_sha256": script_hash,
                "reserved_script_sha256": reserved_hash,
                "mismatched_references": mismatch,
            }
            references = mismatch
            retirement = sorted([script_hash, reserved_hash])
        else:
            canary_evidence = None
            references = ["hello world", "hello, world", "hi world"]
            retirement = [script_hash]
        ground_items.append(
            {
                "challenge_id": challenge_id,
                "metric": "cer" if stratum == "fingerspelling" else "wer",
                "canary": canary,
                "references": references,
                "canary_evidence": canary_evidence,
                "normalized_script_sha256": script_hash,
                "retirement_script_sha256s": retirement,
                "consent_manifest_sha256": consent_hash,
            }
        )
    ground_truth = GroundTruthPayload.model_validate(
        {
            "schema": GROUND_TRUTH_SCHEMA,
            "window_id": window_id,
            "batch_id": batch_id,
            "scoring_policy_hash": policy_hash,
            "tle_profile": "umi-tle/1",
            "response_close_round": response_close_round,
            "reveal_round": reveal_round,
            "items": ground_items,
        }
    )
    encrypted_data, encrypted_round = bittensor_core.encrypt_at_round(
        canonical_json_bytes(ground_truth),
        reveal_round,
    )
    assert encrypted_round == reveal_round
    ciphertext = bytes(
        bt.timelock.Timelocked(
            ciphertext=encrypted_data,
            reveal_round=encrypted_round,
        )
    )
    manifest = PublicBatchManifest.model_validate(
        {
            "schema": PUBLIC_BATCH_MANIFEST_SCHEMA,
            "protocol": "umi-asl/0.1",
            "window_id": window_id,
            "batch_id": batch_id,
            "publisher_hotkey": publisher_hotkey,
            "scoring_policy_hash": policy_hash,
            "tle_profile": "umi-tle/1",
            "response_close_round": response_close_round,
            "reveal_round": reveal_round,
            "ciphertext_sha256": hashlib.sha256(ciphertext).hexdigest(),
            "items": public_items,
        }
    )
    return manifest, ground_truth, ciphertext


def _signed_auth_record(
    validator_wallet: SimpleNamespace,
    miner_hotkey: str,
    request,
    nonce: int,
) -> dict:
    body = canonical_json_bytes(request)
    payload = bt.http_auth.build_payload(
        scheme="sr25519",
        method="POST",
        path="/v1/translate",
        body=body,
        nonce_ns=nonce,
        sender_ss58=validator_wallet.hotkey.ss58_address,
        receiver_ss58=miner_hotkey,
    )
    signature = validator_wallet.hotkey.sign(payload)
    return {
        "version": "btauth/1",
        "scheme": "sr25519",
        "method": "POST",
        "wire_request_target": "/v1/translate",
        "raw_body_sha256": hashlib.sha256(body).hexdigest(),
        "nonce": str(nonce),
        "sender": validator_wallet.hotkey.ss58_address,
        "receiver": miner_hotkey,
        "signature": "0x" + bytes(signature).hex(),
    }


def _fixture() -> tuple[ShadowRehearsalEvidence, dict[str, SimpleNamespace]]:
    publisher_wallets = [_wallet(f"//Publisher{index}") for index in range(1, 4)]
    validators = [_wallet(f"//Validator{index}") for index in range(4)]
    validators.sort(key=lambda wallet: account_id32(wallet.hotkey.ss58_address))
    publisher_by_address = {wallet.hotkey.ss58_address: wallet for wallet in publisher_wallets}
    policy = _policy(publisher_wallets, validators)
    from umi.policy import scoring_policy_hash

    policy_hash = scoring_policy_hash(policy)
    announcement_timestamp, schedule = _schedule(policy)

    artifacts = []
    bodies = []
    for ordinal, registry in enumerate(policy.publisher_registry, 1):
        manifest, ground_truth, ciphertext = _batch_artifact(
            ordinal=ordinal,
            publisher_hotkey=registry.publisher_hotkey,
            window_id=schedule.window_id,
            policy_hash=policy_hash,
            response_close_round=schedule.response_close_round,
            reveal_round=schedule.reveal_round,
        )
        commitment = batch_commitment(manifest, ciphertext, schedule.reveal_round)
        bodies.append(
            PoolBody.model_validate(
                {
                    "schema": POOL_MANIFEST_SCHEMA,
                    "window_id": schedule.window_id,
                    "publisher_hotkey": registry.publisher_hotkey,
                    "scoring_policy_hash": policy_hash,
                    "batches": [
                        {
                            "batch_id": manifest.batch_id,
                            "batch_commitment": commitment,
                            "public_manifest_sha256": hashlib.sha256(
                                canonical_json_bytes(manifest)
                            ).hexdigest(),
                            "ciphertext_sha256": hashlib.sha256(ciphertext).hexdigest(),
                            "reveal_round": schedule.reveal_round,
                        }
                    ],
                }
            )
        )
        artifacts.append(
            {
                "batch_id": manifest.batch_id,
                "public_manifest": manifest.model_dump(mode="json", by_alias=True),
                "ciphertext_b64": base64url_encode(ciphertext),
                "revealed_ground_truth": ground_truth.model_dump(mode="json", by_alias=True),
            }
        )
    bodies.sort(key=lambda body: account_id32(body.publisher_hotkey))
    artifacts.sort(key=lambda item: item["batch_id"])

    leaves = sorted((availability_leaf(body) for body in bodies), key=bytes.fromhex)
    root = availability_set_root(leaves)
    digest = availability_digest(schedule.window_id, root)
    signatures = []
    for wallet in validators[:3]:
        scheme, signature = sign_response_digest(wallet, digest)
        signatures.append(
            {
                "validator_hotkey": wallet.hotkey.ss58_address,
                "scheme": scheme,
                "signature": signature,
            }
        )
    certificate = AvailabilityCertificate.model_validate(
        {
            "schema": AVAILABILITY_SCHEMA,
            "availability_set_root": root,
            "qualified_pool_leaves": leaves,
            "signatures": signatures,
        }
    )

    miner_wallets = [_wallet("//MinerA"), _wallet("//MinerB")]
    roots = [_wallet("//MinerRootA"), _wallet("//MinerRootB")]
    miners = [
        {
            "hotkey": wallet.hotkey.ss58_address,
            "root": root_wallet.hotkey.ss58_address,
            "assigned_observation_count": 0,
            "uid": 10 + index,
        }
        for index, (wallet, root_wallet) in enumerate(zip(miner_wallets, roots, strict=True))
    ]
    miners.sort(key=lambda item: account_id32(item["hotkey"]))
    miner_wallet_by_address = {wallet.hotkey.ss58_address: wallet for wallet in miner_wallets}

    group_by_publisher = {
        account_id32(entry.publisher_hotkey): entry.control_group_id
        for entry in policy.publisher_registry
    }
    candidates = tuple(
        CandidateBatch(
            publisher_hotkey=body.publisher_hotkey,
            control_group_id=group_by_publisher[account_id32(body.publisher_hotkey)],
            batch_id=body.batches[0].batch_id,
            batch_commitment=body.batches[0].batch_commitment,
        )
        for body in bodies
    )
    seed = selection_seed(bytes.fromhex(SIGNATURE), candidate_pool_root(candidates))
    selected = select_batches(candidates, seed, count=2)
    artifact_by_id = {item["batch_id"]: item for item in artifacts}

    assignments = []
    validator_wallet = validators[0]
    nonce = 1_770_000_000_000_000_000
    for candidate in selected:
        artifact = artifact_by_id[candidate.batch_id]
        manifest = PublicBatchManifest.model_validate(artifact["public_manifest"])
        ground_truth = GroundTruthPayload.model_validate(artifact["revealed_ground_truth"])
        ground_by_challenge = {item.challenge_id: item for item in ground_truth.items}
        for public_item in manifest.items:
            ground_item = ground_by_challenge[public_item.challenge_id]
            for miner in miners:
                miner_wallet = miner_wallet_by_address[miner["hotkey"]]
                request_data = {
                    "protocol": "umi-asl/0.1",
                    "window_id": schedule.window_id,
                    "batch_id": manifest.batch_id,
                    "challenge_id": public_item.challenge_id,
                    "issued_block": schedule.closing_block + 1,
                    "issued_block_hash": "0x" + "44" * 32,
                    "deadline_block": (
                        schedule.closing_block + 1 + schedule.response_deadline_blocks
                    ),
                    "response_close_round": schedule.response_close_round,
                    "reveal_round": schedule.reveal_round,
                    "video": {
                        "url": f"https://objects.example/{public_item.media.sha256}",
                        "sha256": public_item.media.sha256,
                        "size_bytes": public_item.media.size_bytes,
                        "media_type": "video/mp4",
                    },
                    "task": {
                        "source_language": "ase",
                        "target_language": "en",
                        "stratum": public_item.stratum,
                    },
                    "scoring_policy_hash": policy_hash,
                }
                from umi.protocol import TranslationRequest

                request = TranslationRequest.model_validate(request_data)
                auth = _signed_auth_record(
                    validator_wallet,
                    miner["hotkey"],
                    request,
                    nonce,
                )
                nonce += 1
                hypothesis = (
                    ground_item.canary_evidence.actual_references[0]
                    if ground_item.canary_evidence is not None
                    else ground_item.references[0]
                )
                response_payload = RehearsalResponsePayload.model_validate(
                    {
                        "schema": SHADOW_RESPONSE_SCHEMA,
                        "request_digest": request_digest(request),
                        "validator_hotkey": validator_wallet.hotkey.ss58_address,
                        "serving_hotkey": miner["hotkey"],
                        "status": "ok",
                        "received_video_sha256": public_item.media.sha256,
                        "hypothesis": hypothesis,
                        "error_code": None,
                    }
                )
                scheme, response_signature = sign_response_digest(
                    miner_wallet,
                    rehearsal_response_digest(response_payload),
                )
                assignments.append(
                    {
                        "miner_hotkey": miner["hotkey"],
                        "miner_root": miner["root"],
                        "batch_id": manifest.batch_id,
                        "challenge_id": public_item.challenge_id,
                        "request": request.model_dump(mode="json", by_alias=True),
                        "auth_records": [auth],
                        "response": {
                            "payload": response_payload.model_dump(mode="json", by_alias=True),
                            "signature_scheme": scheme,
                            "signature": response_signature,
                            "received_block": request.issued_block + 1,
                        },
                    }
                )
    assignments.sort(
        key=lambda item: (
            item["batch_id"],
            item["challenge_id"],
            account_id32(item["miner_hotkey"]),
        )
    )
    evidence = ShadowRehearsalEvidence.model_validate(
        {
            "schema": SHADOW_REHEARSAL_SCHEMA,
            "translation_weights_active": False,
            "protocol_conformance": False,
            "activation_evidence": False,
            "chain_operations_authorized": False,
            "policy": policy.model_dump(mode="json", by_alias=True),
            "window_index": 0,
            "announcement_block_hash": "0x" + "33" * 32,
            "announcement_timestamp_ms": announcement_timestamp,
            "pulse": {
                "round": ROUND,
                "randomness": RANDOMNESS,
                "signature": SIGNATURE,
            },
            "validator_hotkey": validator_wallet.hotkey.ss58_address,
            "active_validator_hotkeys": [wallet.hotkey.ss58_address for wallet in validators],
            "pool_bodies": [body.model_dump(mode="json", by_alias=True) for body in bodies],
            "availability_certificate": certificate.model_dump(mode="json", by_alias=True),
            "batch_artifacts": artifacts,
            "miners": miners,
            "assignments": assignments,
            "minimum_positive_weights": 2,
            "maximum_weight_limit_u16": 65_535,
        }
    )
    signing_wallets = {**publisher_by_address, **miner_wallet_by_address}
    return evidence, signing_wallets


def test_full_offline_rehearsal_reaches_weight_build_with_only_false_claims(
    tmp_path,
) -> None:
    evidence, _ = _fixture()
    encoded = canonical_json_bytes(evidence)
    evidence_nonces = (
        int(record.nonce) for item in evidence.assignments for record in item.auth_records
    )
    assert min(evidence_nonces) > 2**53 - 1

    run = run_shadow_rehearsal(encoded, tmp_path / "bundle")

    assert run.report.terminal_classification == "shadow_rehearsal_no_weight"
    assert run.report.translation_weights_active is False
    assert run.report.protocol_conformance is False
    assert run.report.activation_evidence is False
    assert run.report.chain_writes_performed is False
    assert run.report.runner_signing_performed is False
    assert run.report.weight_submission_performed is False
    assert run.report.assignment_count == 56
    assert run.report.scored_assignment_count == 48
    assert run.report.canary_check_count == 8
    assert len(run.report.quantized_row) == 2
    assert run.audit_manifest.highest_stage == "weight_build"
    assert run.audit_manifest.stages[-1].status == "not_reached"
    assert run.audit_manifest.stages[-1].reason_code == NO_CHAIN_REASON
    assert run.audit_manifest.audit_release_block == 0
    assert run.manifest_path == tmp_path / "bundle" / "manifest.json"


def test_rehearsal_requires_exact_canonical_input_and_an_inactive_policy() -> None:
    evidence, _ = _fixture()
    encoded = canonical_json_bytes(evidence)

    with pytest.raises(ValueError, match="canonical JSON"):
        parse_shadow_rehearsal_evidence(encoded + b"\n")

    active = json.loads(encoded)
    active["policy"]["translation_weights_active"] = True
    with pytest.raises(ValueError, match=r"translation_weights_active|Input should be False"):
        parse_shadow_rehearsal_evidence(canonical_json_bytes(active))


def test_rehearsal_rejects_runtime_pin_drift_before_replay(tmp_path) -> None:
    evidence, _ = _fixture()
    drifted = evidence.model_dump(mode="json", by_alias=True)
    drifted["policy"]["implementation_pins"]["timelock"]["py_ecc_distribution_version"] = "0.0.0"

    with pytest.raises(RuntimeError, match="py_ecc_distribution_version"):
        run_shadow_rehearsal(
            canonical_json_bytes(drifted),
            tmp_path / "runtime-drift",
        )


def test_rehearsal_rejects_runtime_content_drift_before_replay(tmp_path) -> None:
    evidence, _ = _fixture()
    drifted = evidence.model_dump(mode="json", by_alias=True)
    drifted["policy"]["implementation_pins"]["timelock"]["py_ecc_distribution_content_sha256"] = (
        "00" * 32
    )

    with pytest.raises(RuntimeError, match="py_ecc_distribution_content_sha256"):
        run_shadow_rehearsal(
            canonical_json_bytes(drifted),
            tmp_path / "runtime-content-drift",
        )


def test_rehearsal_rejects_incomplete_assignment_cross_product(tmp_path) -> None:
    evidence, _ = _fixture()
    incomplete = evidence.model_dump(mode="json", by_alias=True)
    incomplete["assignments"].pop()

    with pytest.raises(ValueError, match="exact selected-batch and panel cross product"):
        run_shadow_rehearsal(
            canonical_json_bytes(incomplete),
            tmp_path / "incomplete",
        )


def test_rehearsal_rejects_tampered_response_signature(tmp_path) -> None:
    evidence, _ = _fixture()
    tampered = evidence.model_dump(mode="json", by_alias=True)
    signature = tampered["assignments"][0]["response"]["signature"]
    tampered["assignments"][0]["response"]["signature"] = signature[:-2] + (
        "00" if signature[-2:] != "00" else "01"
    )

    with pytest.raises(ValueError, match="response signature"):
        run_shadow_rehearsal(
            canonical_json_bytes(tampered),
            tmp_path / "tampered-signature",
        )


def test_rehearsal_rejects_a_validly_signed_canary_hit(tmp_path) -> None:
    evidence, signing_wallets = _fixture()
    attacked = evidence.model_dump(mode="json", by_alias=True)
    canary_reference_by_challenge = {
        item["challenge_id"]: item["references"][0]
        for artifact in attacked["batch_artifacts"]
        for item in artifact["revealed_ground_truth"]["items"]
        if item["canary"]
    }
    assignment = next(
        item
        for item in attacked["assignments"]
        if item["challenge_id"] in canary_reference_by_challenge
    )
    assignment["response"]["payload"]["hypothesis"] = canary_reference_by_challenge[
        assignment["challenge_id"]
    ]
    payload = RehearsalResponsePayload.model_validate(assignment["response"]["payload"])
    scheme, signature = sign_response_digest(
        signing_wallets[assignment["miner_hotkey"]],
        rehearsal_response_digest(payload),
    )
    assignment["response"]["signature_scheme"] = scheme
    assignment["response"]["signature"] = signature

    with pytest.raises(ValueError, match="canary hit"):
        run_shadow_rehearsal(
            canonical_json_bytes(attacked),
            tmp_path / "canary-hit",
        )


def test_rehearsal_rejects_cross_validator_copy_and_preissued_receipt(tmp_path) -> None:
    evidence, _ = _fixture()
    copied = evidence.model_dump(mode="json", by_alias=True)
    copied["assignments"][0]["response"]["payload"]["validator_hotkey"] = copied[
        "active_validator_hotkeys"
    ][1]
    with pytest.raises(ValueError, match="different validator"):
        run_shadow_rehearsal(
            canonical_json_bytes(copied),
            tmp_path / "copied-validator",
        )

    preissued = evidence.model_dump(mode="json", by_alias=True)
    assignment = preissued["assignments"][0]
    assignment["response"]["received_block"] = assignment["request"]["issued_block"] - 1
    with pytest.raises(ValueError, match="outside its block interval"):
        run_shadow_rehearsal(
            canonical_json_bytes(preissued),
            tmp_path / "preissued-receipt",
        )


@pytest.mark.parametrize(
    ("role", "match"),
    (("publisher", "publisher hotkey"), ("validator", "validator hotkey")),
)
def test_rehearsal_excludes_policy_publishers_and_validators_from_miners(role, match) -> None:
    evidence, _ = _fixture()
    data = evidence.model_dump(mode="json", by_alias=True)
    if role == "publisher":
        replacement = data["policy"]["publisher_registry"][0]["publisher_hotkey"]
    else:
        replacement = data["active_validator_hotkeys"][0]
    data["miners"][0]["hotkey"] = replacement
    data["miners"].sort(key=lambda item: account_id32(item["hotkey"]))
    with pytest.raises(ValueError, match=match):
        ShadowRehearsalEvidence.model_validate(data)


def test_rehearsal_rejects_duplicate_scripts_across_selected_batches(tmp_path) -> None:
    evidence, _ = _fixture()
    duplicated = evidence.model_dump(mode="json", by_alias=True)
    selected_batch_ids = {item["batch_id"] for item in duplicated["assignments"]}
    selected_artifacts = [
        artifact
        for artifact in duplicated["batch_artifacts"]
        if artifact["batch_id"] in selected_batch_ids
    ]
    first = selected_artifacts[0]["revealed_ground_truth"]["items"][0]
    second = selected_artifacts[1]["revealed_ground_truth"]["items"][0]
    second["normalized_script_sha256"] = first["normalized_script_sha256"]
    second["retirement_script_sha256s"] = [first["normalized_script_sha256"]]

    with pytest.raises(ValueError, match="variant of a script"):
        run_shadow_rehearsal(
            canonical_json_bytes(duplicated),
            tmp_path / "duplicate-script",
        )
