from __future__ import annotations

import ast
import asyncio
import hashlib
import json
import sqlite3
from pathlib import Path

import httpx
import pytest

from umi.audit_publication import (
    AUDIT_PUBLICATION_CONFIG_SCHEMA,
    PUBLIC_BUNDLE_INDEX_SCHEMA,
    AuditBundlePublisher,
    AuditPublicationConfig,
    AuditPublicationError,
    PublicationCandidate,
    PublicationState,
    PublicBundleIndex,
    PublicOriginVerifier,
    load_audit_publication_config,
)
from umi.policy import scoring_policy_hash
from umi.protocol import PROTOCOL_VERSION, canonical_json_bytes
from umi.validator_incident_bundle import write_incident_bundle
from umi.validator_readiness import ReplayPublishedBundleVerifier

from .test_calibration_bundle import (
    CHAIN_SPEC_SHA256,
    FINALITY_VERIFIER_SHA256,
    PROOF_VERIFIER_SHA256,
    TARGET_TRIPLE,
    VALIDATOR,
    WINDOW_ID,
    _address,
    _incident_ports,
    _incident_stage_inputs,
    _interval,
    _policy,
    _ports,
    _sign,
    _write,
)


def _private_directory(path: Path) -> Path:
    path.mkdir(mode=0o700)
    path.chmod(0o700)
    return path


def _public_directory(path: Path) -> Path:
    path.mkdir(mode=0o755)
    path.chmod(0o755)
    return path


class _StaticDocroot:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.enabled = True
        self.corrupt_suffix: str | None = None
        self.fail_index = False

    def __call__(self, request: httpx.Request) -> httpx.Response:
        relative = request.url.path.lstrip("/")
        if not self.enabled or (self.fail_index and relative.endswith("/index.json")):
            return httpx.Response(404, request=request)
        target = self.root / relative
        if not target.is_file():
            return httpx.Response(404, request=request)
        body = target.read_bytes()
        if self.corrupt_suffix is not None and relative.endswith(self.corrupt_suffix):
            body = body + b"x"
        return httpx.Response(
            200,
            headers={"Content-Length": str(len(body)), "Content-Encoding": "identity"},
            stream=httpx.ByteStream(body),
            request=request,
        )


async def _publisher(tmp_path: Path, *, static: _StaticDocroot | None = None):
    calibration = _private_directory(tmp_path / "calibration")
    incident = _private_directory(tmp_path / "incident")
    docroot = _public_directory(tmp_path / "public")
    staging = _private_directory(tmp_path / "staging")
    state_root = _private_directory(tmp_path / "private-state")
    source = calibration / WINDOW_ID
    await _write(source)
    server = static or _StaticDocroot(docroot)
    remote = PublicOriginVerifier(
        "https://audit.example",
        timeout_seconds=2,
        maximum_concurrency=4,
        transport=httpx.MockTransport(server),
    )
    publisher = AuditBundlePublisher(
        policy_hash=scoring_policy_hash(_policy()),
        validator_account_id32=VALIDATOR,
        release_manifest_sha256="ab" * 32,
        calibration_root=calibration,
        incident_root=incident,
        public_docroot=docroot,
        private_staging_root=staging,
        state_database_path=state_root / "publication.sqlite3",
        bundle_verifier=ReplayPublishedBundleVerifier(_ports()),
        origin_verifier=remote,
    )
    return publisher, server, source, docroot


def _restart(publisher: AuditBundlePublisher, server: _StaticDocroot) -> AuditBundlePublisher:
    return AuditBundlePublisher(
        policy_hash=publisher.policy_hash,
        validator_account_id32=publisher.validator_account_id32,
        release_manifest_sha256=publisher.release_manifest_sha256,
        calibration_root=publisher.calibration_root,
        incident_root=publisher.incident_root,
        public_docroot=publisher.public_docroot,
        private_staging_root=publisher.private_staging_root,
        state_database_path=publisher.state_database_path,
        bundle_verifier=publisher.bundle_verifier,
        origin_verifier=PublicOriginVerifier(
            "https://audit.example",
            timeout_seconds=2,
            maximum_concurrency=4,
            transport=httpx.MockTransport(server),
        ),
    )


@pytest.mark.asyncio
async def test_verified_bundle_is_read_back_then_indexed_and_restart_is_idempotent(
    tmp_path: Path,
) -> None:
    publisher, _server, source, docroot = await _publisher(tmp_path)

    first = await publisher.run_once()

    assert first.completed == 1
    assert first.failed == 0
    index_bytes = publisher.index_path.read_bytes()
    index = PublicBundleIndex.model_validate_json(index_bytes)
    assert canonical_json_bytes(index) == index_bytes
    assert index.schema_ == PUBLIC_BUNDLE_INDEX_SCHEMA
    assert len(index.entries) == 1
    entry = index.entries[0]
    assert entry.window_id == WINDOW_ID
    assert entry.terminal_classification == "calibration_no_weight"
    public_tree = docroot / entry.relative_path
    assert (public_tree / "manifest.json").read_bytes() == (source / "manifest.json").read_bytes()
    assert {item.name for item in (public_tree / "objects").iterdir()} == {
        item.name for item in (source / "objects").iterdir()
    }
    assert public_tree.stat().st_mode & 0o777 == 0o555
    assert (public_tree / "objects").stat().st_mode & 0o777 == 0o555
    assert (public_tree / "manifest.json").stat().st_mode & 0o777 == 0o444
    assert all(item.stat().st_mode & 0o777 == 0o444 for item in (public_tree / "objects").iterdir())
    assert publisher.index_path.stat().st_mode & 0o777 == 0o444
    record = publisher.state.get(f"calibration:{WINDOW_ID}")
    assert record is not None and record.phase == "complete"
    assert record.failure_code is None

    second = await publisher.run_once()

    assert second.already_complete == 1
    assert second.completed == 0
    assert publisher.index_path.read_bytes() == index_bytes


@pytest.mark.asyncio
async def test_local_index_rollback_is_rejected_against_durable_completion_state(
    tmp_path: Path,
) -> None:
    publisher, _server, _source, _docroot = await _publisher(tmp_path)
    assert (await publisher.run_once()).completed == 1
    publisher.index_path.unlink()

    with pytest.raises(AuditPublicationError, match="publication_complete_index_missing"):
        await publisher.run_once()


@pytest.mark.asyncio
async def test_remote_tree_failure_is_durable_and_does_not_add_index_route(tmp_path: Path) -> None:
    publisher, server, _source, _docroot = await _publisher(tmp_path)
    server.enabled = False

    failed = await publisher.run_once()

    assert failed.failed == 1
    assert not publisher.index_path.exists()
    record = publisher.state.get(f"calibration:{WINDOW_ID}")
    assert record is not None
    assert record.phase == "failed"
    assert record.retryable is True
    assert record.failure_code == "public_origin_http_status"
    assert record.entry is not None

    server.enabled = True
    recovered = await publisher.run_once()

    assert recovered.completed == 1
    assert publisher.index_path.exists()
    record = publisher.state.get(f"calibration:{WINDOW_ID}")
    assert record is not None and record.phase == "complete" and record.attempt == 2


@pytest.mark.asyncio
async def test_remote_index_failure_recovers_without_appending_a_second_route(
    tmp_path: Path,
) -> None:
    publisher, server, _source, _docroot = await _publisher(tmp_path)
    server.fail_index = True

    failed = await publisher.run_once()

    assert failed.failed == 1
    index = PublicBundleIndex.model_validate_json(publisher.index_path.read_bytes())
    assert len(index.entries) == 1
    record = publisher.state.get(f"calibration:{WINDOW_ID}")
    assert record is not None and record.failure_code == "public_origin_http_status"

    server.fail_index = False
    recovered = await publisher.run_once()

    assert recovered.completed == 1
    index = PublicBundleIndex.model_validate_json(publisher.index_path.read_bytes())
    assert len(index.entries) == 1


@pytest.mark.asyncio
async def test_restart_recovers_index_replace_before_state_transition(tmp_path: Path) -> None:
    publisher, server, source, _docroot = await _publisher(tmp_path)
    server.fail_index = True
    assert (await publisher.run_once()).failed == 1
    record = publisher.state.get(f"calibration:{WINDOW_ID}")
    assert record is not None and record.entry is not None
    candidate = PublicationCandidate("calibration", WINDOW_ID, source)
    publisher.state.transition(candidate, "remote_tree_verified", entry=record.entry)

    server.fail_index = False
    restarted = _restart(publisher, server)
    recovered = await restarted.run_once()

    assert recovered.completed == 1
    index = PublicBundleIndex.model_validate_json(restarted.index_path.read_bytes())
    assert len(index.entries) == 1
    current = restarted.state.get(candidate.source_key)
    assert current is not None and current.phase == "complete"


@pytest.mark.asyncio
async def test_wrong_remote_bytes_never_create_an_index_route(tmp_path: Path) -> None:
    publisher, server, _source, _docroot = await _publisher(tmp_path)
    server.corrupt_suffix = "manifest.json"

    summary = await publisher.run_once()

    assert summary.failed == 1
    assert not publisher.index_path.exists()
    record = publisher.state.get(f"calibration:{WINDOW_ID}")
    assert record is not None
    assert record.failure_code in {
        "public_origin_body_limit",
        "public_origin_content_length_mismatch",
    }


@pytest.mark.asyncio
async def test_source_mutation_after_local_install_is_rejected_on_retry(tmp_path: Path) -> None:
    publisher, server, source, _docroot = await _publisher(tmp_path)
    server.enabled = False
    assert (await publisher.run_once()).failed == 1
    manifest = source / "manifest.json"
    manifest.chmod(0o600)
    manifest.write_bytes(manifest.read_bytes() + b" ")

    server.enabled = True
    summary = await publisher.run_once()

    assert summary.failed == 1
    record = publisher.state.get(f"calibration:{WINDOW_ID}")
    assert record is not None
    assert record.failure_code == "terminal_source_changed_after_install"
    assert record.retryable is False
    assert not publisher.index_path.exists()


@pytest.mark.asyncio
async def test_unexpected_source_object_prevents_public_install(tmp_path: Path) -> None:
    publisher, _server, source, docroot = await _publisher(tmp_path)
    (source / "objects" / ("ff" * 32)).write_bytes(b"unexpected")

    summary = await publisher.run_once()

    assert summary.failed == 1
    record = publisher.state.get(f"calibration:{WINDOW_ID}")
    assert record is not None and record.failure_code == "terminal_bundle_object_set_invalid"
    assert not any((docroot / "validators" / VALIDATOR.hex() / "windows").iterdir())


@pytest.mark.asyncio
async def test_incomplete_window_directory_is_not_scanned_until_manifest_exists(
    tmp_path: Path,
) -> None:
    publisher, _server, _source, _docroot = await _publisher(tmp_path)
    incomplete_window = "12" * 32
    incomplete = publisher.calibration_root / incomplete_window
    incomplete.mkdir(mode=0o700)
    (incomplete / "objects").mkdir(mode=0o700)

    summary = await publisher.run_once()

    assert summary.discovered == 1
    assert publisher.state.get(f"calibration:{incomplete_window}") is None


@pytest.mark.asyncio
async def test_terminal_symlink_root_is_durably_rejected(tmp_path: Path) -> None:
    publisher, _server, source, _docroot = await _publisher(tmp_path)
    linked_window = "13" * 32
    (publisher.incident_root / linked_window).symlink_to(source, target_is_directory=True)

    summary = await publisher.run_once()

    assert summary.discovered == 2
    assert summary.failed == 1
    record = publisher.state.get(f"incident:{linked_window}")
    assert record is not None
    assert record.failure_code == "terminal_bundle_root_unsafe"
    assert record.retryable is False


@pytest.mark.asyncio
async def test_incident_bundle_is_replayed_and_routed_by_terminal_classification(
    tmp_path: Path,
) -> None:
    calibration = _private_directory(tmp_path / "calibration")
    incident = _private_directory(tmp_path / "incident")
    docroot = _public_directory(tmp_path / "public")
    staging = _private_directory(tmp_path / "staging")
    state_root = _private_directory(tmp_path / "private-state")
    policy = _policy()
    interval = await _interval()
    source = incident / WINDOW_ID
    write_incident_bundle(
        source,
        policy=policy,
        window_id=WINDOW_ID,
        window_index=0,
        software_revisions={
            "umi": "test",
            "target_triple": TARGET_TRIPLE,
            "storage_proof_verifier_sha256": PROOF_VERIFIER_SHA256,
            "finality_verifier_sha256": FINALITY_VERIFIER_SHA256,
            "finality_chain_spec_sha256": CHAIN_SPEC_SHA256,
        },
        validator_account=VALIDATOR,
        audit_release_snapshot=interval.scan.end_snapshot,
        no_weight_scan=interval,
        stages=_incident_stage_inputs(policy),
        terminal_classification="skipped",
        reason_code="response_anchor_failed",
        incident={
            "incident_id": "test/sealed_response/incident",
            "reason_code": "response_anchor_failed",
            "metadata": {"stage": "sealed_response"},
        },
        signature_scheme="ed25519",
        manifest_signer=_sign,
    )
    server = _StaticDocroot(docroot)
    publisher = AuditBundlePublisher(
        policy_hash=scoring_policy_hash(policy),
        validator_account_id32=VALIDATOR,
        release_manifest_sha256="ab" * 32,
        calibration_root=calibration,
        incident_root=incident,
        public_docroot=docroot,
        private_staging_root=staging,
        state_database_path=state_root / "publication.sqlite3",
        bundle_verifier=ReplayPublishedBundleVerifier(_incident_ports(policy)),
        origin_verifier=PublicOriginVerifier(
            "https://audit.example",
            timeout_seconds=2,
            maximum_concurrency=4,
            transport=httpx.MockTransport(server),
        ),
    )

    summary = await publisher.run_once()

    assert summary.completed == 1
    index = PublicBundleIndex.model_validate_json(publisher.index_path.read_bytes())
    assert index.entries[0].terminal_classification == "skipped"
    assert index.entries[0].reason_codes == ["response_anchor_failed"]
    assert index.entries[0].relative_path.endswith(f"/{WINDOW_ID}/skipped")


def test_hash_chained_state_detects_event_tampering(tmp_path: Path) -> None:
    parent = _private_directory(tmp_path / "state")
    path = parent / "publication.sqlite3"
    binding = {"schema": "test-binding/1"}
    state = PublicationState(path, binding=binding)
    candidate = PublicationCandidate("calibration", WINDOW_ID, tmp_path / WINDOW_ID)
    state.begin(candidate)
    with sqlite3.connect(path) as connection:
        connection.execute("UPDATE events SET phase = 'failed' WHERE sequence = 0")
        connection.commit()

    with pytest.raises(AuditPublicationError, match="publication_state_event_digest_invalid"):
        PublicationState(path, binding=binding)


def test_open_state_rejects_database_inode_replacement(tmp_path: Path) -> None:
    parent = _private_directory(tmp_path / "state")
    path = parent / "publication.sqlite3"
    state = PublicationState(path, binding={"schema": "test-binding/1"})
    path.unlink()

    with pytest.raises(AuditPublicationError, match="publication_state_database_replaced"):
        state.records()


def test_publication_config_is_canonical_https_and_has_no_capability_escape(tmp_path: Path) -> None:
    values = {
        "schema": AUDIT_PUBLICATION_CONFIG_SCHEMA,
        "protocol": PROTOCOL_VERSION,
        "mode": "live_shadow_calibration",
        "translation_weights_active": False,
        "wallet_loading_capability": False,
        "chain_write_capability": False,
        "weight_submission_capability": False,
        "validator_config_path": str(tmp_path / "validator.json"),
        "expected_release_authority_hotkey": _address("//AuditPublicationAuthority"),
        "state_database_path": str(tmp_path / "state" / "publisher.sqlite3"),
        "public_docroot": str(tmp_path / "public"),
        "private_staging_root": str(tmp_path / "staging"),
        "public_origin": "https://audit.example",
        "poll_seconds": 1,
        "remote_timeout_seconds": 2,
        "maximum_remote_concurrency": 2,
    }
    config = AuditPublicationConfig.model_validate(values)
    path = tmp_path / "publisher.json"
    path.write_bytes(canonical_json_bytes(config))

    loaded, encoded = load_audit_publication_config(path)

    assert loaded == config
    assert encoded == canonical_json_bytes(config)
    for field, value in (
        ("translation_weights_active", True),
        ("wallet_loading_capability", True),
        ("chain_write_capability", True),
        ("weight_submission_capability", True),
        ("public_origin", "http://audit.example"),
    ):
        changed = dict(values)
        changed[field] = value
        with pytest.raises(ValueError):
            AuditPublicationConfig.model_validate(changed)
    with pytest.raises(ValueError):
        AuditPublicationConfig.model_validate({**values, "wallet_name": "forbidden"})


def test_documented_production_config_shape_matches_canonical_bytes() -> None:
    encoded = Path("docs/examples/audit-publication-config.json").read_bytes()
    config = AuditPublicationConfig.model_validate_json(encoded)

    assert encoded.endswith(b"\n") and not encoded.endswith(b"\n\n")
    assert canonical_json_bytes(config) == encoded[:-1]
    assert config.translation_weights_active is False
    assert config.wallet_loading_capability is False
    assert config.chain_write_capability is False
    assert config.weight_submission_capability is False


@pytest.mark.asyncio
async def test_public_origin_rejects_mixed_or_private_dns_answers() -> None:
    async def private(_hostname: str, _port: int):
        return ("93.184.216.34", "127.0.0.1")

    verifier = PublicOriginVerifier(
        "https://audit.example",
        timeout_seconds=1,
        maximum_concurrency=1,
        resolver=private,
        transport=httpx.AsyncHTTPTransport(),
    )
    with pytest.raises(AuditPublicationError, match="public_origin_dns_non_public"):
        await verifier.verify_digest("index.json", hashlib.sha256(b"").hexdigest(), 0)


@pytest.mark.asyncio
async def test_public_origin_enforces_an_absolute_request_timeout() -> None:
    async def slow(request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(0.05)
        return httpx.Response(200, content=b"", request=request)

    verifier = PublicOriginVerifier(
        "https://audit.example",
        timeout_seconds=0.01,
        maximum_concurrency=1,
        transport=httpx.MockTransport(slow),
    )

    with pytest.raises(AuditPublicationError, match="public_origin_timeout"):
        await verifier.verify_digest("index.json", hashlib.sha256(b"").hexdigest(), 0)


def test_publication_module_has_no_wallet_or_chain_mutation_import() -> None:
    source = Path("src/umi/audit_publication.py").read_text()
    tree = ast.parse(source)
    imported = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }
    assert "bittensor" not in imported
    assert "validator_anchor_ports" not in imported
    assert "validator_extrinsics" not in imported
    assert ".validator_operator" not in imported
    assert "Wallet" not in source
    assert "submit_extrinsic" not in source


def test_public_index_rejects_reordering_and_policy_mixing(tmp_path: Path) -> None:
    # The model-level invariant is exercised with the index emitted by one real run
    # in the async tests. Here malformed documents must fail before any file write.
    base = {
        "schema": PUBLIC_BUNDLE_INDEX_SCHEMA,
        "protocol": PROTOCOL_VERSION,
        "mode": "live_shadow_calibration",
        "netuid": 78,
        "mechanism_id": 0,
        "translation_weights_active": False,
        "validator_account_id32": VALIDATOR.hex(),
        "scoring_policy_hash": "aa" * 32,
        "release_manifest_sha256": "bb" * 32,
        "entries": [],
    }
    assert PublicBundleIndex.model_validate(base).entries == []
    bad = json.loads(json.dumps(base))
    bad["entries"] = [
        {
            "sequence": 1,
            "window_id": WINDOW_ID,
            "window_index": 0,
            "terminal_classification": "calibration_no_weight",
            "bundle_schema": "umi-calibration-audit-bundle/2",
            "highest_stage": "commit_and_terminal_state",
            "reason_codes": [],
            "scoring_policy_hash": "aa" * 32,
            "audit_release_block": 1,
            "audit_release_block_hash": "0x" + "11" * 32,
            "manifest_sha256": "22" * 32,
            "audit_bundle_bytes": 1,
            "tree_sha256": "33" * 32,
            "relative_path": (
                f"validators/{VALIDATOR.hex()}/windows/{WINDOW_ID}/calibration_no_weight"
            ),
        }
    ]
    with pytest.raises(ValueError, match="sequence"):
        PublicBundleIndex.model_validate(bad)
