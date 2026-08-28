from __future__ import annotations

import hashlib
import itertools

import bittensor as bt
import pytest
from pydantic import ValidationError

from tests.factories import dev_wallet
from tests.test_artifacts import manifest_data
from tests.test_policy import make_policy
from umi.artifacts import PublicBatchManifest
from umi.crypto import seal_response, sign_response_digest
from umi.encoding import account_id32
from umi.policy import scoring_policy_hash
from umi.pool import (
    AVAILABILITY_SCHEMA,
    POOL_MANIFEST_SCHEMA,
    AvailabilityCertificate,
    CandidateBatch,
    MinerCandidate,
    PoolBody,
    PoolManifest,
    availability_digest,
    availability_leaf,
    availability_set_root,
    batch_commitment,
    candidate_pool_root,
    parse_pool_body_bytes,
    parse_pool_manifest_bytes,
    select_batches,
    select_miner_panel,
    selection_seed,
    verify_availability_certificate,
    verify_pool_artifacts,
)
from umi.protocol import base64url_encode, canonical_json_bytes


def _pool_body(uri: str, index: int, *, policy=None) -> tuple[PoolBody, dict, bytes]:
    publisher_hotkey = dev_wallet(uri).hotkey.ss58_address if uri.startswith("//") else uri
    batch_id = base64url_encode(bytes([index]) * 16)
    public_manifest = {"batch_id": batch_id, "items": [{"ordinal": index}]}
    ciphertext = f"ciphertext-{index}".encode()
    reveal_round = 12_345 + index
    body = PoolBody.model_validate(
        {
            "schema": POOL_MANIFEST_SCHEMA,
            "window_id": "10" * 32,
            "publisher_hotkey": publisher_hotkey,
            "scoring_policy_hash": scoring_policy_hash(policy) if policy is not None else "20" * 32,
            "batches": [
                {
                    "batch_id": batch_id,
                    "batch_commitment": batch_commitment(public_manifest, ciphertext, reveal_round),
                    "public_manifest_sha256": hashlib.sha256(
                        canonical_json_bytes(public_manifest)
                    ).hexdigest(),
                    "ciphertext_sha256": hashlib.sha256(ciphertext).hexdigest(),
                    "reveal_round": reveal_round,
                }
            ],
        }
    )
    return body, public_manifest, ciphertext


def _certificate(
    bodies: tuple[PoolBody, ...],
    signer_wallets: tuple,
    *,
    digest_override: bytes | None = None,
) -> AvailabilityCertificate:
    leaves = sorted((availability_leaf(body) for body in bodies), key=bytes.fromhex)
    root = availability_set_root(leaves)
    digest = digest_override or availability_digest(bodies[0].window_id, root)
    records = []
    for wallet in signer_wallets:
        scheme, signature = sign_response_digest(wallet, digest)
        records.append(
            {
                "validator_hotkey": wallet.hotkey.ss58_address,
                "scheme": scheme,
                "signature": signature,
            }
        )
    records.sort(key=lambda record: account_id32(record["validator_hotkey"]))
    return AvailabilityCertificate.model_validate(
        {
            "schema": AVAILABILITY_SCHEMA,
            "availability_set_root": root,
            "qualified_pool_leaves": leaves,
            "signatures": records,
        }
    )


def test_pool_hashes_reproduce_the_published_formulas() -> None:
    body, public_manifest, ciphertext = _pool_body("//Eve", 1)
    entry = body.batches[0]

    expected_commitment = hashlib.sha256(
        b"umi-batch-v1\0"
        + canonical_json_bytes(public_manifest)
        + hashlib.sha256(ciphertext).digest()
        + entry.reveal_round.to_bytes(8, "big")
    ).hexdigest()
    expected_leaf = hashlib.sha256(
        b"umi-availability-leaf-v1\0"
        + account_id32(body.publisher_hotkey)
        + hashlib.sha256(canonical_json_bytes(body)).digest()
    ).hexdigest()
    expected_root = hashlib.sha256(
        b"umi-availability-set-v1\0" + (1).to_bytes(4, "big") + bytes.fromhex(expected_leaf)
    ).hexdigest()
    expected_digest = hashlib.sha256(
        b"umi-availability-v1\0" + bytes.fromhex(body.window_id) + bytes.fromhex(expected_root)
    ).digest()

    assert entry.batch_commitment == expected_commitment
    assert availability_leaf(body) == expected_leaf
    assert availability_set_root([expected_leaf]) == expected_root
    assert availability_digest(body.window_id, expected_root) == expected_digest


def test_pool_artifacts_require_an_exact_bijection_and_reproduce_each_hash() -> None:
    policy = make_policy()
    manifest_document = manifest_data()
    reveal_round = bt.timelock.current_round() + 100
    sealed = seal_response(b"canonical-ground-truth", reveal_round=reveal_round)
    manifest_document["response_close_round"] = reveal_round - 10
    manifest_document["reveal_round"] = reveal_round
    manifest_document["ciphertext_sha256"] = sealed.sha256_hex
    manifest = PublicBatchManifest.model_validate(manifest_document)
    ciphertext = sealed.portable_bytes
    body = PoolBody.model_validate(
        {
            "schema": POOL_MANIFEST_SCHEMA,
            "window_id": manifest.window_id,
            "publisher_hotkey": manifest.publisher_hotkey,
            "scoring_policy_hash": manifest.scoring_policy_hash,
            "batches": [
                {
                    "batch_id": manifest.batch_id,
                    "batch_commitment": batch_commitment(
                        manifest, ciphertext, manifest.reveal_round
                    ),
                    "public_manifest_sha256": hashlib.sha256(
                        canonical_json_bytes(manifest)
                    ).hexdigest(),
                    "ciphertext_sha256": sealed.sha256_hex,
                    "reveal_round": manifest.reveal_round,
                }
            ],
        }
    )
    batch_id = body.batches[0].batch_id

    verify_pool_artifacts(
        body,
        public_manifests={batch_id: manifest},
        ciphertexts={batch_id: ciphertext},
        policy=policy,
    )
    with pytest.raises(ValueError, match="bijection"):
        verify_pool_artifacts(
            body,
            public_manifests={batch_id: manifest, "extra": manifest},
            ciphertexts={batch_id: ciphertext},
            policy=policy,
        )
    tampered_document = manifest.model_dump(mode="json", by_alias=True)
    tampered_document["items"][0]["provenance_manifest_sha256"] = "ab" * 32
    tampered = PublicBatchManifest.model_validate(tampered_document)
    with pytest.raises(ValueError, match="manifest hash"):
        verify_pool_artifacts(
            body,
            public_manifests={batch_id: tampered},
            ciphertexts={batch_id: ciphertext},
            policy=policy,
        )
    with pytest.raises(ValueError, match="ciphertext hash"):
        verify_pool_artifacts(
            body,
            public_manifests={batch_id: manifest},
            ciphertexts={batch_id: ciphertext + b"!"},
            policy=policy,
        )
    forged_ciphertext = bytearray(ciphertext)
    prefix_length = {0: 1, 1: 2, 2: 4}[forged_ciphertext[0] & 0b11]
    forged_ciphertext[prefix_length : prefix_length + 96] = b"\xff" * 96
    forged_bytes = bytes(forged_ciphertext)
    forged_document = manifest.model_dump(mode="json", by_alias=True)
    forged_document["ciphertext_sha256"] = hashlib.sha256(forged_bytes).hexdigest()
    forged_manifest = PublicBatchManifest.model_validate(forged_document)
    forged_body_document = body.model_dump(mode="json", by_alias=True)
    forged_entry = forged_body_document["batches"][0]
    forged_entry["ciphertext_sha256"] = forged_manifest.ciphertext_sha256
    forged_entry["public_manifest_sha256"] = hashlib.sha256(
        canonical_json_bytes(forged_manifest)
    ).hexdigest()
    forged_entry["batch_commitment"] = batch_commitment(
        forged_manifest, forged_bytes, forged_manifest.reveal_round
    )
    forged_body = PoolBody.model_validate(forged_body_document)
    with pytest.raises(ValueError, match="compressed group data"):
        verify_pool_artifacts(
            forged_body,
            public_manifests={batch_id: forged_manifest},
            ciphertexts={batch_id: forged_bytes},
            policy=policy,
        )


def test_pool_artifact_verification_rejects_untyped_or_cross_bound_artifacts() -> None:
    policy = make_policy()
    manifest_document = manifest_data()
    reveal_round = bt.timelock.current_round() + 100
    sealed = seal_response(b"canonical-ground-truth", reveal_round=reveal_round)
    manifest_document.update(
        response_close_round=reveal_round - 10,
        reveal_round=reveal_round,
        ciphertext_sha256=sealed.sha256_hex,
    )
    manifest = PublicBatchManifest.model_validate(manifest_document)
    body = PoolBody.model_validate(
        {
            "schema": POOL_MANIFEST_SCHEMA,
            "window_id": manifest.window_id,
            "publisher_hotkey": manifest.publisher_hotkey,
            "scoring_policy_hash": manifest.scoring_policy_hash,
            "batches": [
                {
                    "batch_id": manifest.batch_id,
                    "batch_commitment": batch_commitment(
                        manifest, sealed.portable_bytes, reveal_round
                    ),
                    "public_manifest_sha256": hashlib.sha256(
                        canonical_json_bytes(manifest)
                    ).hexdigest(),
                    "ciphertext_sha256": sealed.sha256_hex,
                    "reveal_round": reveal_round,
                }
            ],
        }
    )
    with pytest.raises(TypeError, match="strict PublicBatchManifest"):
        verify_pool_artifacts(
            body,
            public_manifests={manifest.batch_id: manifest.model_dump(mode="json", by_alias=True)},
            ciphertexts={manifest.batch_id: sealed.portable_bytes},
            policy=policy,
        )
    bad_manifest_document = manifest.model_dump(mode="json", by_alias=True)
    bad_manifest_document["publisher_hotkey"] = policy.publisher_registry[1].publisher_hotkey
    bad_manifest = PublicBatchManifest.model_validate(bad_manifest_document)
    with pytest.raises(ValueError, match="publisher does not match"):
        verify_pool_artifacts(
            body,
            public_manifests={manifest.batch_id: bad_manifest},
            ciphertexts={manifest.batch_id: sealed.portable_bytes},
            policy=policy,
        )


def test_pool_artifact_enforces_the_raw_portable_envelope_ceiling_at_the_boundary() -> None:
    base_policy = make_policy()
    reveal_round = bt.timelock.current_round() + 100
    sealed = seal_response(b"canonical-ground-truth", reveal_round=reveal_round)

    def build_with_limit(limit: int):
        policy = base_policy.model_copy(
            update={
                "limits": base_policy.limits.model_copy(
                    update={"maximum_ground_truth_envelope_bytes": limit}
                )
            }
        )
        document = manifest_data()
        document.update(
            publisher_hotkey=policy.publisher_registry[0].publisher_hotkey,
            scoring_policy_hash=scoring_policy_hash(policy),
            response_close_round=reveal_round - 10,
            reveal_round=reveal_round,
            ciphertext_sha256=sealed.sha256_hex,
        )
        manifest = PublicBatchManifest.model_validate(document)
        body = PoolBody.model_validate(
            {
                "schema": POOL_MANIFEST_SCHEMA,
                "window_id": manifest.window_id,
                "publisher_hotkey": manifest.publisher_hotkey,
                "scoring_policy_hash": manifest.scoring_policy_hash,
                "batches": [
                    {
                        "batch_id": manifest.batch_id,
                        "batch_commitment": batch_commitment(
                            manifest, sealed.portable_bytes, reveal_round
                        ),
                        "public_manifest_sha256": hashlib.sha256(
                            canonical_json_bytes(manifest)
                        ).hexdigest(),
                        "ciphertext_sha256": sealed.sha256_hex,
                        "reveal_round": reveal_round,
                    }
                ],
            }
        )
        return policy, manifest, body

    exact_policy, exact_manifest, exact_body = build_with_limit(len(sealed.portable_bytes))
    verify_pool_artifacts(
        exact_body,
        public_manifests={exact_manifest.batch_id: exact_manifest},
        ciphertexts={exact_manifest.batch_id: sealed.portable_bytes},
        policy=exact_policy,
    )
    short_policy, short_manifest, short_body = build_with_limit(len(sealed.portable_bytes) - 1)
    with pytest.raises(ValueError, match="envelope exceeds"):
        verify_pool_artifacts(
            short_body,
            public_manifests={short_manifest.batch_id: short_manifest},
            ciphertexts={short_manifest.batch_id: sealed.portable_bytes},
            policy=short_policy,
        )


def test_availability_certificate_accepts_exact_dev_wallet_quorum_in_any_body_order() -> None:
    policy = make_policy()
    bodies = tuple(
        _pool_body(entry.publisher_hotkey, index, policy=policy)[0]
        for index, entry in enumerate(policy.publisher_registry[:2], 1)
    )
    validators = tuple(dev_wallet(f"//Validator{index}") for index in range(4))
    signers = tuple(
        sorted(validators, key=lambda wallet: account_id32(wallet.hotkey.ss58_address))[:3]
    )
    certificate = _certificate(bodies, signers)
    active = {wallet.hotkey.ss58_address for wallet in validators}

    verify_availability_certificate(
        certificate, bodies, active_validator_hotkeys=active, policy=policy
    )
    verify_availability_certificate(
        certificate,
        tuple(reversed(bodies)),
        active_validator_hotkeys=active,
        policy=policy,
    )


def test_availability_certificate_rejects_bad_signature_inactive_signer_and_short_quorum() -> None:
    policy = make_policy()
    bodies = (_pool_body(policy.publisher_registry[0].publisher_hotkey, 1, policy=policy)[0],)
    validators = tuple(dev_wallet(f"//Validator{index}") for index in range(4))
    ordered = tuple(sorted(validators, key=lambda wallet: account_id32(wallet.hotkey.ss58_address)))
    active = {wallet.hotkey.ss58_address for wallet in validators}

    short = _certificate(bodies, ordered[:2])
    with pytest.raises(ValueError, match="quorum"):
        verify_availability_certificate(
            short, bodies, active_validator_hotkeys=active, policy=policy
        )

    wrong_digest = _certificate(bodies, ordered[:3], digest_override=b"\xff" * 32)
    with pytest.raises(ValueError, match="does not verify"):
        verify_availability_certificate(
            wrong_digest, bodies, active_validator_hotkeys=active, policy=policy
        )

    outsider = dev_wallet("//Ferdie")
    inactive = _certificate(
        bodies,
        tuple(
            sorted(
                (*ordered[:2], outsider),
                key=lambda wallet: account_id32(wallet.hotkey.ss58_address),
            )
        ),
    )
    with pytest.raises(ValueError, match="not from an active validator"):
        verify_availability_certificate(
            inactive, bodies, active_validator_hotkeys=active, policy=policy
        )


def test_pool_raw_parsers_and_certificate_backstop_enforce_manifest_ceiling() -> None:
    policy = make_policy()
    body = _pool_body(policy.publisher_registry[0].publisher_hotkey, 1, policy=policy)[0]
    validators = tuple(dev_wallet(f"//Validator{index}") for index in range(4))
    signers = tuple(
        sorted(validators, key=lambda wallet: account_id32(wallet.hotkey.ss58_address))[:3]
    )
    certificate = _certificate((body,), signers)
    final = PoolManifest.model_validate(
        {
            **body.model_dump(mode="json", by_alias=True),
            "availability_certificate": certificate.model_dump(mode="json", by_alias=True),
        }
    )
    body_bytes = canonical_json_bytes(body)
    final_bytes = canonical_json_bytes(final)
    assert parse_pool_body_bytes(body_bytes, policy=policy) == body
    assert parse_pool_manifest_bytes(final_bytes, policy=policy) == final
    with pytest.raises(ValueError, match="canonical JSON"):
        parse_pool_body_bytes(body_bytes + b" ", policy=policy)

    oversized = AvailabilityCertificate.model_validate(
        {
            "schema": AVAILABILITY_SCHEMA,
            "availability_set_root": certificate.availability_set_root,
            "qualified_pool_leaves": [f"{index:064x}" for index in range(5_000)],
            "signatures": certificate.model_dump(mode="json")["signatures"],
        }
    )
    assert (
        len(
            canonical_json_bytes(
                {
                    **body.model_dump(mode="json", by_alias=True),
                    "availability_certificate": oversized.model_dump(mode="json", by_alias=True),
                }
            )
        )
        > policy.limits.maximum_manifest_bytes
    )
    active = {wallet.hotkey.ss58_address for wallet in validators}
    with pytest.raises(ValueError, match="final pool manifest exceeds"):
        verify_availability_certificate(
            oversized,
            (body,),
            active_validator_hotkeys=active,
            policy=policy,
        )


def test_certificate_model_rejects_leaf_and_signer_ordering_ambiguity() -> None:
    bodies = (_pool_body("//Eve", 1)[0], _pool_body("//Ferdie", 2)[0])
    validators = tuple(dev_wallet(uri) for uri in ("//Alice", "//Bob", "//Charlie"))
    certificate = _certificate(bodies, validators)
    data = certificate.model_dump(mode="json", by_alias=True)
    data["qualified_pool_leaves"] = list(reversed(data["qualified_pool_leaves"]))
    with pytest.raises(ValidationError, match="sorted"):
        AvailabilityCertificate.model_validate(data)

    data = certificate.model_dump(mode="json", by_alias=True)
    data["signatures"] = list(reversed(data["signatures"]))
    with pytest.raises(ValidationError, match="sorted"):
        AvailabilityCertificate.model_validate(data)


def _candidate(index: int, group: int) -> CandidateBatch:
    return CandidateBatch(
        publisher_hotkey=bytes([index]) * 32,
        control_group_id=bytes([group]) * 32,
        batch_id=base64url_encode(bytes([index]) * 16),
        batch_commitment=bytes([index + 10]) * 32,
    )


def test_candidate_root_seed_and_selection_are_permutation_invariant() -> None:
    candidates = (_candidate(1, 1), _candidate(2, 2), _candidate(3, 3))
    roots = {candidate_pool_root(order) for order in itertools.permutations(candidates)}
    assert len(roots) == 1
    root = roots.pop()
    expected_root = hashlib.sha256(
        b"umi-pool-root-v1\0"
        + len(candidates).to_bytes(4, "big")
        + b"".join(sorted(candidate.pool_leaf for candidate in candidates))
    ).digest()
    assert root == expected_root

    signature = bytes(range(48))
    seed = selection_seed(signature, root)
    assert seed == hashlib.sha256(b"umi-select-v2\0" + signature + root).digest()
    selections = {
        tuple(item.pool_leaf for item in select_batches(order, seed))
        for order in itertools.permutations(candidates)
    }
    assert len(selections) == 1

    for invalid_signature in (b"", bytes(47), bytes(49)):
        with pytest.raises(ValueError, match="exactly 48 bytes"):
            selection_seed(invalid_signature, root)


def test_batch_selection_skips_duplicate_groups_and_requires_enough_distinct_groups() -> None:
    seed = bytes(range(32))
    candidates = (_candidate(1, 1), _candidate(2, 1), _candidate(3, 2))
    selected = select_batches(candidates, seed, count=2)
    assert len({item.control_group_id for item in selected}) == 2

    with pytest.raises(ValueError, match="distinct control groups"):
        select_batches(candidates[:2], seed, count=2)


def test_miner_panel_exploration_and_rank_selection_are_permutation_invariant() -> None:
    miners = tuple(
        MinerCandidate(
            hotkey=bytes([index]) * 32,
            root=bytes([index + 20]) * 32,
            assigned_observation_count=0 if index in {1, 2} else index,
        )
        for index in range(1, 7)
    )
    seed = b"S" * 32
    validator = b"V" * 32
    panels = {
        tuple(
            item.hotkey
            for item in select_miner_panel(order, seed, validator_hotkey=validator, panel_size=5)
        )
        for order in itertools.permutations(miners)
    }
    assert len(panels) == 1
    panel = panels.pop()
    assert len(panel) == 5
    assert panel[0] in {miners[0].hotkey, miners[1].hotkey}


def test_pool_body_rejects_noncanonical_batch_order_and_duplicate_commitments() -> None:
    first, _, _ = _pool_body("//Eve", 1)
    second, _, _ = _pool_body("//Eve", 2)
    data = first.model_dump(mode="json", by_alias=True)
    data["batches"] = [
        second.batches[0].model_dump(mode="json"),
        first.batches[0].model_dump(mode="json"),
    ]
    with pytest.raises(ValidationError, match="ordered"):
        PoolBody.model_validate(data)

    duplicate = first.model_dump(mode="json", by_alias=True)
    extra = second.batches[0].model_dump(mode="json")
    extra["batch_commitment"] = duplicate["batches"][0]["batch_commitment"]
    duplicate["batches"].append(extra)
    with pytest.raises(ValidationError, match="commitments"):
        PoolBody.model_validate(duplicate)
