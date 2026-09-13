from __future__ import annotations

import hashlib
import ipaddress
import json
import sqlite3
from dataclasses import replace

import pytest

from umi.competition_origin import FinalizedEndpointProvider, public_ip_origin
from umi.open_competition import SignedSubmission, digest, sign_object
from umi.protocol import canonical_json_bytes

from .test_competition_chain import _HEIGHT, _NOW, _hash
from .test_competition_chain import chain as chain
from .test_competition_chain import chain_config as chain_config
from .test_open_competition import policy as base_policy
from .test_open_competition import submission, wallet


@pytest.fixture
def policy():
    return base_policy.__wrapped__().model_copy(
        update={
            "valid_from_block": _HEIGHT - 100,
            "valid_through_block": _HEIGHT + 500,
        }
    )


@pytest.fixture
def origin_chain(chain):
    chain.origin_provider = FinalizedEndpointProvider(
        chain.config,
        chain.policy,
        finality=chain.finality,
        proofs=chain.proofs,
        now_ms=lambda: chain.clock.now,
    )
    sub = submission(chain.policy, start=_HEIGHT - 10, end=_HEIGHT + 300).submission
    sub = sub.model_copy(update={"endpoint_url": "https://8.8.8.8:443"})
    chain.signed = SignedSubmission(submission=sub, signature=sign_object(sub, wallet("Alice")))
    chain.axon_key = ("SubtensorModule", "Axons", (78, sub.hotkey))
    chain.rpc.values[chain.axon_key] = {
        "block": _HEIGHT - 5,
        "version": 1,
        "ip": int(ipaddress.ip_address("8.8.8.8")),
        "port": 443,
        "ip_type": 4,
        "protocol": 0,
        "placeholder1": 0,
        "placeholder2": 0,
    }
    return chain


async def test_origin_collects_proven_bidirectional_registration_and_axon(origin_chain):
    item = origin_chain
    result = await item.origin_provider.collect_origin(item.signed)
    assert result.uid == 0
    assert result.origin == "https://8.8.8.8:443"
    assert result.block_hash == item.finality.ref.block_hash
    assert result.submission_sha256 == digest(item.signed.submission)
    assert len(item.verifier.checked) == 2
    data = json.loads(result.evidence)
    assert len(data["storage_batches"]) == 2
    assert data["runtime_metadata_sha256"] == hashlib.sha256(b"metadata").hexdigest()
    assert result.status()["tls_verified"] is False
    assert result.status()["chain_submission_authorized"] is False
    with sqlite3.connect(item.origin_provider._path) as db:
        assert db.execute("SELECT evidence FROM origins").fetchone()[0] == result.evidence
    assert (await item.origin_provider.collect_origin(item.signed)) == result
    with sqlite3.connect(item.origin_provider._path) as db:
        assert db.execute("SELECT COUNT(*) FROM origins").fetchone()[0] == 1
    assert not any(method.startswith("author_") for method, _ in item.rpc.calls)


@pytest.mark.parametrize(
    "value",
    [
        "https://127.0.0.1:443",
        "https://10.0.0.1:443",
        "https://169.254.169.254:443",
        "https://[::1]:443",
        "https://[::ffff:8.8.8.8]:443",
        "https://[2002:808:808::]:443",
        "https://224.0.0.1:443",
        "https://100.64.0.1:443",
        "https://example.com",
        "https://user@8.8.8.8",
        "https://8.8.8.8?x=1",
        "https://8.8.8.8/#x",
        "https://8.8.8.8:0443",
        "https://8.8.8.8:0",
        "https://8.8.8.8/path",
        "https://8.8.8.8:\n443",
        "https://[2606:4700:4700::1111%eth0]:443",
    ],
)
def test_origin_rejects_private_noncanonical_and_unannouncable_origins(value):
    with pytest.raises(ValueError):
        public_ip_origin(value)


@pytest.mark.parametrize(
    "value,expected",
    [
        ("https://8.8.8.8", "https://8.8.8.8:443"),
        ("https://8.8.8.8:8443/", "https://8.8.8.8:8443"),
        ("https://[2606:4700:4700::1111]", "https://[2606:4700:4700::1111]:443"),
    ],
)
def test_origin_allows_canonical_public_ip(value, expected):
    assert public_ip_origin(value) == expected


@pytest.mark.parametrize(
    "mutation",
    [
        "ip",
        "private",
        "port",
        "protocol",
        "ip_type",
        "future_axon",
        "unserved",
        "bool",
        "missing",
        "inverse",
        "proof",
        "root",
        "metadata",
        "stale",
        "expired",
    ],
)
async def test_invalid_origin_never_returns_or_records_evidence(origin_chain, mutation):
    item = origin_chain
    axon = item.rpc.values[item.axon_key]
    if mutation == "ip":
        axon["ip"] += 1
    elif mutation == "private":
        axon["ip"] = int(ipaddress.ip_address("127.0.0.1"))
    elif mutation == "port":
        axon["port"] = 444
    elif mutation == "protocol":
        axon["protocol"] = 1
    elif mutation == "ip_type":
        axon["ip_type"] = 6
    elif mutation == "future_axon":
        axon["block"] = _HEIGHT + 1
    elif mutation == "unserved":
        axon["block"] = 0
    elif mutation == "bool":
        axon["version"] = True
    elif mutation == "missing":
        del item.rpc.values[item.axon_key]
    elif mutation == "inverse":
        item.rpc.values[("SubtensorModule", "Keys", (78, 0))] = wallet("Bob").hotkey.ss58_address
    elif mutation == "proof":
        item.rpc.bad_proof = True
    elif mutation == "root":
        item.rpc.header_root = _hash(99)
    elif mutation == "metadata":
        item.rpc.metadata = b"bad"
    elif mutation == "stale":
        item.clock.now += 120001
    elif mutation == "expired":
        item.finality.ref = replace(item.finality.ref, block_number=_HEIGHT + 301)
    with pytest.raises((ValueError, RuntimeError)):
        await item.origin_provider.collect_origin(item.signed)
    with sqlite3.connect(item.origin_provider._path) as db:
        assert db.execute("SELECT COUNT(*) FROM origins").fetchone()[0] == 0


async def test_origin_rechecks_freshness_after_proof_collection(origin_chain, monkeypatch):
    item = origin_chain
    original = item.proofs.storage_reads

    async def delayed(*args):
        result = await original(*args)
        item.clock.now = _NOW + 120001
        return result

    monkeypatch.setattr(item.proofs, "storage_reads", delayed)
    with pytest.raises(ValueError, match="stale"):
        await item.origin_provider.collect_origin(item.signed)


@pytest.mark.parametrize("mutation", ["height", "hash"])
async def test_origin_preserves_highwater_on_restart(origin_chain, mutation):
    item = origin_chain
    await item.origin_provider.collect_origin(item.signed)
    provider = FinalizedEndpointProvider(
        item.config,
        item.policy,
        finality=item.finality,
        proofs=item.proofs,
        now_ms=lambda: item.clock.now,
    )
    if mutation == "height":
        item.finality.ref = replace(item.finality.ref, block_number=_HEIGHT - 1)
    else:
        item.finality.ref = replace(item.finality.ref, block_hash=_hash(88))
    with pytest.raises(ValueError, match="rolled back or changed"):
        await provider.collect_origin(item.signed)


async def test_origin_cache_quota_fails_closed(origin_chain):
    item = origin_chain
    # A distinct dedicated cache config binds the same policy and pins.
    config = item.config.model_copy(
        update={
            "state_directory": item.config.state_directory + "-small",
            "maximum_cache_bytes": 1024,
        }
    )
    provider = FinalizedEndpointProvider(
        config,
        item.policy,
        finality=item.finality,
        proofs=item.proofs,
        now_ms=lambda: item.clock.now,
    )
    with pytest.raises(ValueError, match="cache is full"):
        await provider.collect_origin(item.signed)


async def test_bad_signature_rejected_before_rpc(origin_chain):
    item = origin_chain
    forged = item.signed.model_copy(
        update={
            "signature": item.signed.signature.model_copy(update={"signature": "0x" + "00" * 64})
        }
    )
    with pytest.raises(ValueError):
        await item.origin_provider.collect_origin(forged)
    assert not item.rpc.calls


@pytest.mark.parametrize(
    "field", ["storage_batches", "finality", "signature", "authority", "metadata"]
)
async def test_origin_refuses_corrupt_retained_evidence_after_restart(origin_chain, field):
    item = origin_chain
    result = await item.origin_provider.collect_origin(item.signed)
    with sqlite3.connect(item.origin_provider._path) as db:
        evidence = json.loads(result.evidence)
        if field in {"storage_batches", "finality"}:
            evidence[field] = []
        elif field == "signature":
            evidence["signed_submission"]["signature"]["signature"] = "0x" + "00" * 64
        elif field == "authority":
            evidence["chain_submission_authorized"] = True
        if field == "metadata":
            db.execute("DELETE FROM artifacts")
        else:
            db.execute("UPDATE origins SET evidence=?", (canonical_json_bytes(evidence),))
    provider = FinalizedEndpointProvider(
        item.config,
        item.policy,
        finality=item.finality,
        proofs=item.proofs,
        now_ms=lambda: item.clock.now,
    )
    with pytest.raises(ValueError, match="retained endpoint"):
        await provider.collect_origin(item.signed)


def test_old_draft_cache_schema_requires_explicit_migration(chain):
    with sqlite3.connect(chain.provider._path) as db:
        db.execute(
            "CREATE TABLE origins (block INTEGER, hash TEXT, submission TEXT, evidence BLOB)"
        )
        db.execute("INSERT INTO origins VALUES (1, 'hash', 'submission', ?)", (b"retained",))
    with pytest.raises(ValueError, match="unsupported endpoint cache schema"):
        FinalizedEndpointProvider(
            chain.config,
            chain.policy,
            finality=chain.finality,
            proofs=chain.proofs,
            now_ms=lambda: chain.clock.now,
        )
    with sqlite3.connect(chain.provider._path) as db:
        assert db.execute("SELECT evidence FROM origins").fetchone()[0] == b"retained"
