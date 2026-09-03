from __future__ import annotations

import hashlib
from dataclasses import replace
from pathlib import Path

import httpx
import pytest

from umi.encoding import account_id32
from umi.mirror_readiness import (
    MirrorReadinessError,
    build_mirror_readiness_set,
    check_readiness_input,
    sign_mirror_readiness,
    verify_live_mirror_readiness,
)
from umi.mirror_service import (
    MirrorServiceConfig,
    MirrorServiceError,
    check_mirror_service,
    load_mirror_service,
)
from umi.protocol import canonical_json_bytes
from umi.publisher_availability import (
    ANCHOR_INTENTS_FILENAME,
    CERTIFIED_RELEASE_FILENAME,
    parse_qualification_receipt_bytes,
)
from umi.publisher_availability_cli import run
from umi.validator_live_ports import DurablePoolMirrorSource
from umi.validator_pool_effect import PoolSourceRequest

from .factories import dev_wallet
from .test_mirror_service import _service_fixture
from .test_validator_pool_effect import _work


class _RawStream(httpx.AsyncByteStream):
    def __init__(self, data: bytes) -> None:
        self.data = data

    async def __aiter__(self):
        yield self.data


def _signed_readiness_material(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    fixture = _service_fixture(tmp_path, monkeypatch)
    receipt_rows = []
    for path in (fixture.release_root / "qualification-receipts").iterdir():
        raw = path.read_bytes()
        receipt_rows.append((parse_qualification_receipt_bytes(raw), raw))
    receipt_rows.sort(key=lambda item: account_id32(item[0].validator_hotkey))
    wallets = {
        account_id32(dev_wallet(f"//Validator{index}").hotkey.ss58_address): dev_wallet(
            f"//Validator{index}"
        )
        for index in range(4)
    }
    origins = fixture.discovery.origins[:3]
    delivery_origins = fixture.discovery.delivery_origins[:3]
    statements = []
    owner_root = fixture.config_path.parent
    for index, ((receipt, receipt_bytes), origin, delivery_origin) in enumerate(
        zip(receipt_rows, origins, delivery_origins, strict=True)
    ):
        config = fixture.config.model_copy(
            update={
                "retrieval_origin": origin,
                "delivery_origin": delivery_origin,
                "state_database_path": str(owner_root / f"mirror-{index}.sqlite3"),
            }
        )
        config_path = owner_root / f"mirror-{index}.json"
        config_path.write_bytes(canonical_json_bytes(config))
        config_path.chmod(0o600)
        checked = check_readiness_input(check_mirror_service(config_path), receipt_bytes)
        wallet = wallets[account_id32(receipt.validator_hotkey)]
        assert account_id32(wallet.hotkey.ss58_address) == account_id32(receipt.validator_hotkey)
        statements.append(
            sign_mirror_readiness(
                checked,
                signature_scheme="sr25519",
                sign_digest=lambda digest, wallet=wallet: bytes(wallet.hotkey.sign(digest)),
            )
        )
    return fixture, tuple(row[1] for row in receipt_rows), tuple(statements)


def test_every_availability_signer_binds_one_unique_checked_origin_pair(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture, receipts, statements = _signed_readiness_material(tmp_path, monkeypatch)
    readiness = build_mirror_readiness_set(
        policy=fixture.policy,
        certified_release_bytes=(fixture.release_root / CERTIFIED_RELEASE_FILENAME).read_bytes(),
        anchor_intents_bytes=(fixture.release_root / ANCHOR_INTENTS_FILENAME).read_bytes(),
        discovery_rule_bytes=fixture.discovery_bytes,
        qualification_receipt_bytes=receipts,
        statements=statements,
    )

    assert readiness.pre_anchor_readiness_gate_passed is True
    assert len(readiness.statements) == 3
    assert len({item.retrieval_origin for item in readiness.statements}) == 3
    assert len({item.delivery_origin for item in readiness.statements}) == 3
    assert (
        readiness.anchor_intents_sha256
        == hashlib.sha256((fixture.release_root / ANCHOR_INTENTS_FILENAME).read_bytes()).hexdigest()
    )
    live = verify_live_mirror_readiness(
        policy=fixture.policy,
        discovery_rule_bytes=fixture.discovery_bytes,
        readiness_set_bytes=canonical_json_bytes(readiness),
    )
    assert live.signer_accounts == {
        account_id32(item.validator_hotkey) for item in readiness.statements
    }


def test_readiness_rejects_missing_signer_and_reused_origin(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture, receipts, statements = _signed_readiness_material(tmp_path, monkeypatch)
    common = {
        "policy": fixture.policy,
        "certified_release_bytes": (fixture.release_root / CERTIFIED_RELEASE_FILENAME).read_bytes(),
        "anchor_intents_bytes": (fixture.release_root / ANCHOR_INTENTS_FILENAME).read_bytes(),
        "discovery_rule_bytes": fixture.discovery_bytes,
        "qualification_receipt_bytes": receipts,
    }
    with pytest.raises(MirrorReadinessError, match="mirror_readiness_signer_set_incomplete"):
        build_mirror_readiness_set(**common, statements=statements[:-1])

    reused = statements[1].model_copy(update={"retrieval_origin": statements[0].retrieval_origin})
    # The changed origin is not covered by the original hotkey signature.
    with pytest.raises(MirrorReadinessError, match="mirror_readiness_signature_invalid"):
        build_mirror_readiness_set(
            **common,
            statements=(statements[0], reused, statements[2]),
        )


def test_service_check_rejects_policy_with_less_than_quorum_origin_pairs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _service_fixture(tmp_path, monkeypatch)
    short_discovery = fixture.discovery.model_copy(
        update={
            "origins": [fixture.config.retrieval_origin],
            "delivery_origins": [fixture.config.delivery_origin],
        }
    )
    discovery_path = fixture.config_path.parent / "short-discovery.json"
    discovery_bytes = canonical_json_bytes(short_discovery)
    discovery_path.write_bytes(discovery_bytes)
    discovery_path.chmod(0o600)
    policy_document = fixture.policy.model_dump(mode="json", by_alias=True)
    policy_document["implementation_pins"]["rules"]["mirror_discovery_rule_sha256"] = (
        hashlib.sha256(discovery_bytes).hexdigest()
    )
    policy_path = fixture.config_path.parent / "short-policy.json"
    policy_bytes = canonical_json_bytes(type(fixture.policy).model_validate(policy_document))
    policy_path.write_bytes(policy_bytes)
    policy_path.chmod(0o600)
    config: MirrorServiceConfig = fixture.config.model_copy(
        update={
            "policy_path": str(policy_path),
            "scoring_policy_sha256": hashlib.sha256(policy_bytes).hexdigest(),
            "discovery_rule_path": str(discovery_path),
            "discovery_rule_sha256": hashlib.sha256(discovery_bytes).hexdigest(),
        }
    )
    config_path = fixture.config_path.parent / "short-config.json"
    config_path.write_bytes(canonical_json_bytes(config))
    config_path.chmod(0o600)

    with pytest.raises(MirrorServiceError, match="mirror_discovery_quorum_invalid"):
        check_mirror_service(config_path)


def test_installed_readiness_checks_and_materializes_gate_without_chain_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    fixture, receipts, statements = _signed_readiness_material(tmp_path, monkeypatch)
    receipt_paths = []
    statement_paths = []
    for index, raw in enumerate(receipts):
        path = tmp_path / f"input-receipt-{index}.json"
        path.write_bytes(raw)
        receipt_paths.append(path)
    for index, statement in enumerate(statements):
        path = tmp_path / f"readiness-{index}.json"
        path.write_bytes(canonical_json_bytes(statement))
        statement_paths.append(path)

    assert (
        run(
            [
                "attest-mirror",
                "--service-config",
                str(fixture.config_path),
                "--qualification-receipt",
                str(receipt_paths[0]),
                "--check",
            ]
        )
        == 0
    )
    assert '"signature_created":false' in capsys.readouterr().out

    output = (tmp_path / "anchor-readiness-set.json").resolve()
    arguments = [
        "verify-mirrors",
        "--policy",
        fixture.config.policy_path,
        "--certified-tree",
        str(fixture.release_root),
        "--mirror-discovery-rule",
        fixture.config.discovery_rule_path,
        "--output",
        str(output),
    ]
    for path in receipt_paths:
        arguments.extend(("--qualification-receipt", str(path)))
    for path in statement_paths:
        arguments.extend(("--statement", str(path)))
    assert run(arguments) == 0
    assert output.exists()
    result = capsys.readouterr().out
    assert '"status":"anchor_ready"' in result
    assert '"broadcast_performed":false' in result


@pytest.mark.asyncio
async def test_live_pool_accepts_only_anchor_digests_bound_by_readiness(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture, receipts, statements = _signed_readiness_material(tmp_path, monkeypatch)
    readiness = build_mirror_readiness_set(
        policy=fixture.policy,
        certified_release_bytes=(fixture.release_root / CERTIFIED_RELEASE_FILENAME).read_bytes(),
        anchor_intents_bytes=(fixture.release_root / ANCHOR_INTENTS_FILENAME).read_bytes(),
        discovery_rule_bytes=fixture.discovery_bytes,
        qualification_receipt_bytes=receipts,
        statements=statements,
    )
    binding = verify_live_mirror_readiness(
        policy=fixture.policy,
        discovery_rule_bytes=fixture.discovery_bytes,
        readiness_set_bytes=canonical_json_bytes(readiness),
    )
    runtime = load_mirror_service(
        fixture.config_path,
        clock=lambda: fixture.clock[0],
    )
    descriptors = {item.sha256: item for item in runtime.loaded.index.objects}

    def handler(request: httpx.Request) -> httpx.Response:
        digest = request.url.path.rsplit("/", 1)[-1]
        descriptor = descriptors[digest]
        body = (fixture.release_root / "v1" / "umi" / "objects" / digest).read_bytes()
        return httpx.Response(
            200,
            headers={
                "Content-Length": str(len(body)),
                "Content-Type": descriptor.media_type,
            },
            stream=_RawStream(body),
        )

    async def resolver(_hostname: str, _port: int) -> tuple[str, ...]:
        return ("93.184.216.34",)

    plan = runtime.loaded.release.window.to_plan()
    work = _work(plan)
    anchors = tuple(
        (item.publisher_hotkey, item.sha256) for item in runtime.loaded.release.pool_manifests
    )
    request = PoolSourceRequest(
        work=work,
        eligible_anchor_hashes=anchors,
        timely_anchor_hashes=anchors,
        active_validator_hotkeys=tuple(
            item.validator_hotkey for item in fixture.policy.validator_registry
        ),
    )
    headers = {
        origin: {"Authorization": f"Bearer independent-{index}"}
        for index, origin in enumerate(fixture.discovery.origins)
    }
    source = DurablePoolMirrorSource(
        policy=fixture.policy,
        discovery_rule_bytes=fixture.discovery_bytes,
        state_path=tmp_path / "live-ready.sqlite3",
        request_headers=headers,
        mirror_readiness=binding,
        require_mirror_readiness=True,
        transport=httpx.MockTransport(handler),
        resolver=resolver,
    )
    package = await source(request)
    assert len(package.final_pool_manifest_bytes) == len(anchors)

    first_publisher = account_id32(anchors[0][0])
    wrong = dict(binding.expected_pool_manifest_sha256_by_publisher_account)
    wrong[first_publisher] = "00" * 32
    restricted = replace(
        binding,
        expected_pool_manifest_sha256_by_publisher_account=wrong,
    )
    restricted_source = DurablePoolMirrorSource(
        policy=fixture.policy,
        discovery_rule_bytes=fixture.discovery_bytes,
        state_path=tmp_path / "live-restricted.sqlite3",
        request_headers=headers,
        mirror_readiness=restricted,
        require_mirror_readiness=True,
        transport=httpx.MockTransport(handler),
        resolver=resolver,
    )
    restricted_package = await restricted_source(request)
    assert len(restricted_package.final_pool_manifest_bytes) == len(anchors) - 1
