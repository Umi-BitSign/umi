"""Ordinary evidence selects an approved verifier without changing signatures.

All signing is confined to existing synthetic fixture keys. No live inputs,
wallets, providers, or deployment effects are used.
"""

import hashlib
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from umi import competition_settlement_delivery as delivery
from umi.competition_package import (
    PreparedCompetitionPackage,
    competition_release_identity_digest,
    load_competition_package,
)
from umi.competition_publication import settlement_publication_digest
from umi.competition_reward_continuity import (
    UNTIL_SUPERSEDED_BLOCK,
    RewardContinuityAuthority,
    sign_reward_continuity_authority,
)
from umi.competition_rounds import SettlementDeliveryConfig
from umi.competition_settlement_preparation import SettlementPreparation
from umi.competition_settlement_release_selection import ForwardPackageSelection
from umi.competition_settlement_signing import SettlementEndorsement
from umi.competition_successor_publication import SuccessorRoundPublicationBuilder
from umi.open_competition import digest
from umi.private_files import publish_private_model
from umi.protocol import canonical_json_bytes

from .test_competition_successor_publication import authority_wallets
from .test_competition_successor_publisher_cli import (  # noqa: F401
    chain_config,
    package_limits,
    policy,
    publication_case,
    release_identity,
    replay_limits,
    successor_case,
    successor_chain,
    successor_release,
    v3_predecessor,
    worker_capacity,
)
from .test_competition_successor_publisher_cli import (
    config as config,
)
from .test_competition_successor_publisher_cli import (
    guarded as guarded,
)
from .test_competition_successor_publisher_cli import (
    package_case as package_case,
)


@pytest.fixture
def case(config, guarded, package_case, tmp_path):
    package = load_competition_package(
        Path(package_case.prepared.package_path),
        expected_package_sha256=package_case.prepared.package_sha256,
        expected_policy_sha256=config.plan.policy_sha256,
        observed_release=config.plan.release.replay_release_identity,
        limits=config.plan.package_limits,
    )
    authority = RewardContinuityAuthority(
        schema="umi-reward-continuity-authority/1",
        policy_sha256=config.plan.policy_sha256,
        first_round_sha256=package.manifest.round_sha256,
        first_round_sequence=package.manifest.round_sequence,
        last_round_sequence=package.manifest.round_sequence,
        release_identity_sha256=package.manifest.release_identity_sha256,
        chain_pin=config.chain.chain_pin,
        issued_at_block=125,
        valid_from_block=125,
        lifetime="until_superseded_or_revoked",
        allocation_rule="latest_on_time_certified_exact_projection/1",
        recipient_change_action="hold_until_valid_certified_replacement",
        revocation_rule="stop_renewal_expire_outstanding_leases/1",
        admission_authority_hotkey=authority_wallets()[0].hotkey.ss58_address,
        maximum_write_authorization_blocks=50,
    )
    signed = sign_reward_continuity_authority(authority, authority_wallets()[:2])
    raw = json.loads(canonical_json_bytes(config))
    raw["plan"].update(
        schema="umi-successor-round-publication-plan/4",
        continuity=json.loads(canonical_json_bytes(signed)),
        renewal_interval_blocks=2,
        valid_through_block=UNTIL_SUPERSEDED_BLOCK,
    )
    raw["plan"]["consent"].update(
        reward_continuity_sha256=digest(signed), valid_through_block=UNTIL_SUPERSEDED_BLOCK
    )
    config = type(config).model_validate_json(json.dumps(raw))
    path = tmp_path / "operator" / "publisher.json"
    publish_private_model(path, config)
    old = package.release_identity.model_copy(update={"umi_revision": "01" * 20})
    queue_config = SettlementDeliveryConfig(
        state_directory=str(tmp_path / "queue"),
        certificate_directory=str(tmp_path / "certificates"),
        package_directory=str(tmp_path / "forward-packages"),
        package_limits=config.plan.package_limits,
        release_identity=old,
    )

    def reopen():
        return delivery.SettlementQueue(
            queue_config,
            guarded.store,
            guarded.provider,
            limits=package.replay_limits,
            maximum_rounds=1024,
            maximum_bytes=1024**3,
        )

    prepared = SettlementPreparation(
        schema="umi-settlement-preparation/1",
        cutoff=package.cutoff_certificate,
        publication=package.settlement_certificate.publication,
        roster=package.roster,
        evidence=package.evidence,
    )
    selection = ForwardPackageSelection(
        schema="umi-forward-package-selection/1",
        round_sha256=package.manifest.round_sha256,
        predecessor_release_identity_sha256=competition_release_identity_digest(old),
        publisher_config_path=str(path),
        publisher_config_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
    )
    selection_path = (
        Path(queue_config.state_directory)
        / "forward-releases"
        / (package.manifest.round_sha256 + ".json")
    )
    s = SimpleNamespace(
        queue=reopen(),
        reopen=reopen,
        prepared=prepared,
        package=package,
        config=config,
        config_path=path,
        selection=selection,
        selection_path=selection_path,
        old=old,
    )
    yield s
    for p in Path(queue_config.package_directory).iterdir():
        if p.is_dir():
            p.chmod(0o700)


def select(s):
    publish_private_model(s.selection_path, s.selection)


def build(s):
    return s.queue._package(s.prepared, s.package.settlement_certificate, 160)


def test_ordinary_package_reproduces_mismatch_without_explicit_selection(case, tmp_path):
    s = case
    old = build(s)
    builder = SuccessorRoundPublicationBuilder(tmp_path / "check-original", s.config.plan)
    with pytest.raises(ValueError, match="release identity"):
        builder._load(old)


def test_selected_package_preserves_signed_bytes_and_reopens_exactly(case, tmp_path):
    s = case
    with sqlite3.connect(s.queue.journal.path) as db:
        original_binding = db.execute("SELECT body FROM binding").fetchone()[0]
    select(s)
    prepared = build(s)
    builder = SuccessorRoundPublicationBuilder(tmp_path / "check-forward", s.config.plan)
    loaded = builder._load(prepared)
    assert loaded.release_identity == s.package.release_identity
    assert loaded.settlement_certificate == s.package.settlement_certificate
    assert loaded.retained_settlement == s.package.retained_settlement
    assert loaded.evidence == s.package.evidence
    assert canonical_json_bytes(loaded.settlement_certificate) == canonical_json_bytes(
        s.package.settlement_certificate
    )
    assert canonical_json_bytes(loaded.cutoff_certificate) == canonical_json_bytes(
        s.package.cutoff_certificate
    )
    s.queue = s.reopen()
    assert build(s) == prepared
    with sqlite3.connect(s.queue.journal.path) as db:
        assert db.execute("SELECT body FROM binding").fetchone()[0] == original_binding
    assert s.queue.config.release_identity == s.old


def test_crash_after_reservation_recovers_without_resigning(case, monkeypatch):
    s = case
    select(s)
    native = delivery.prepare_competition_package
    with monkeypatch.context() as patch:
        patch.setattr(
            delivery,
            "prepare_competition_package",
            lambda **_: (_ for _ in ()).throw(OSError("crash")),
        )
        with pytest.raises(OSError, match="crash"):
            build(s)
    s.queue = s.reopen()
    assert delivery.prepare_competition_package is native
    assert build(s).package_sha256
    assert s.queue.journal.get("certificate", "1") == json.loads(
        canonical_json_bytes(s.package.settlement_certificate)
    )


@pytest.mark.parametrize(
    "field", ["round_sha256", "predecessor_release_identity_sha256", "publisher_config_sha256"]
)
def test_exact_selection_bindings_cannot_change(case, field):
    s = case
    s.selection = s.selection.model_copy(update={field: "00" * 32})
    select(s)
    with pytest.raises(ValueError):
        build(s)
    assert s.queue.journal.get("certificate", "1") is None


@pytest.mark.parametrize("head", [124, 301])
def test_current_time_rechecked_before_selection(case, head):
    select(case)
    with pytest.raises(ValueError, match="scope"):
        case.queue._release_identity(case.prepared, head)


def test_missing_selection_after_reservation_does_not_fall_back(case):
    select(case)
    build(case)
    case.selection_path.unlink()
    case.queue = case.reopen()
    with pytest.raises(ValueError, match="missing"):
        build(case)


def test_cannot_rebind_an_existing_package_or_certificate(case):
    build(case)
    select(case)
    with pytest.raises(ValueError, match="too late"):
        build(case)


def test_nested_authority_change_is_revalidated_even_with_rehashed_input(case):
    s = case
    raw = json.loads(s.config_path.read_bytes())
    raw["plan"]["continuity"]["authority"]["first_round_sha256"] = "00" * 32
    s.config_path.write_bytes(canonical_json_bytes(raw))
    s.selection = s.selection.model_copy(
        update={"publisher_config_sha256": hashlib.sha256(s.config_path.read_bytes()).hexdigest()}
    )
    select(s)
    with pytest.raises(ValueError):
        build(s)
    assert s.queue.journal.get("certificate", "1") is None


def replace_config(s, raw):
    checked = type(s.config).model_validate_json(canonical_json_bytes(raw))
    s.config_path.write_bytes(canonical_json_bytes(checked))
    s.selection = s.selection.model_copy(
        update={"publisher_config_sha256": hashlib.sha256(s.config_path.read_bytes()).hexdigest()}
    )


def test_valid_signature_for_another_round_is_not_authority(case):
    s = case
    authority = s.config.plan.continuity.authority.model_copy(
        update={"first_round_sha256": "00" * 32}
    )
    signed = sign_reward_continuity_authority(authority, authority_wallets()[:2])
    raw = json.loads(canonical_json_bytes(s.config))
    raw["plan"]["continuity"] = json.loads(canonical_json_bytes(signed))
    raw["plan"]["consent"]["reward_continuity_sha256"] = digest(signed)
    replace_config(s, raw)
    select(s)
    with pytest.raises(ValueError, match="scope"):
        build(s)
    assert s.queue.journal.get("release-selection", "1") is None
    assert s.queue.journal.get("certificate", "1") is None


def test_unrelated_publisher_intake_is_not_accepted(case):
    s = case
    raw = json.loads(canonical_json_bytes(s.config))
    raw["intake_directory"] += "-unrelated"
    replace_config(s, raw)
    select(s)
    with pytest.raises(ValueError, match="scope"):
        build(s)


def test_rehashed_publisher_configuration_cannot_change_after_reservation(case):
    s = case
    select(s)
    build(s)
    # This is valid operator configuration, but differs from the exact reservation.
    raw = json.loads(canonical_json_bytes(s.config))
    raw["maximum_rounds"] += 1
    replace_config(s, raw)
    s.selection_path.write_bytes(canonical_json_bytes(s.selection))
    s.queue = s.reopen()
    with pytest.raises(ValueError, match="retained reservation"):
        build(s)


def test_selected_package_loads_in_separate_replay_process(case, tmp_path):
    s = case
    select(s)
    prepared = build(s)
    request = {
        "path": str(prepared.package_path),
        "package_sha256": prepared.package_sha256,
        "policy_sha256": s.config.plan.policy_sha256,
        "release": s.package.release_identity.model_dump(mode="json", by_alias=True),
        "limits": s.config.plan.package_limits.model_dump(mode="json", by_alias=True),
    }
    request_path = tmp_path / "replay-request.json"
    request_path.write_bytes(canonical_json_bytes(request))
    # Qualification may point this at an exact immutable historical src archive.
    source = os.environ.get(
        "UMI_TEST_REPLAY_SOURCE_DIRECTORY", str(Path(delivery.__file__).parents[1])
    )
    script = """
import hashlib, json, sys
from pathlib import Path
from umi.competition_package import (
    CompetitionReleaseIdentity, CompetitionPackageLimits, load_competition_package,
)
from umi.protocol import canonical_json_bytes
r = json.loads(Path(sys.argv[1]).read_bytes())
p = load_competition_package(Path(r['path']), expected_package_sha256=r['package_sha256'],
    expected_policy_sha256=r['policy_sha256'],
    observed_release=CompetitionReleaseIdentity.model_validate(r['release']),
    limits=CompetitionPackageLimits.model_validate(r['limits']))
certificate_sha256 = hashlib.sha256(canonical_json_bytes(p.settlement_certificate)).hexdigest()
print(json.dumps({'release': p.release_identity.model_dump(mode='json', by_alias=True),
    'certificate_sha256': certificate_sha256}))
"""
    result = subprocess.run(
        [sys.executable, "-B", "-c", script, str(request_path)],
        cwd=tmp_path,
        env={**os.environ, "PYTHONPATH": source, "PYTHONDONTWRITEBYTECODE": "1"},
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {
        "release": request["release"],
        "certificate_sha256": hashlib.sha256(
            canonical_json_bytes(s.package.settlement_certificate)
        ).hexdigest(),
    }


async def submit_existing_signatures(s):
    assert await s.queue.prepare(s.prepared) is None
    for signature in s.package.settlement_certificate.signatures:
        await s.queue.accept(
            SettlementEndorsement(
                publication_sha256=settlement_publication_digest(s.prepared.publication),
                signature=signature,
            )
        )


@pytest.mark.asyncio
async def test_public_queue_path_delivers_selected_package_and_retries(case, tmp_path):
    s = case
    select(s)
    await submit_existing_signatures(s)
    records = list(Path(s.queue.config.certificate_directory).glob("*.package.json"))
    assert len(records) == 1
    raw = records[0].read_bytes()
    package = PreparedCompetitionPackage.model_validate_json(raw)
    builder = SuccessorRoundPublicationBuilder(tmp_path / "queue-consumer", s.config.plan)
    loaded = builder._load(package)
    assert loaded.release_identity == s.package.release_identity
    assert loaded.evidence == s.package.evidence
    assert loaded.settlement_certificate.publication == s.prepared.publication
    assert set(loaded.settlement_certificate.signatures) == set(
        s.package.settlement_certificate.signatures
    )
    s.queue = s.reopen()
    assert await s.queue.prepare(s.prepared) == package
    assert records[0].read_bytes() == raw


@pytest.mark.asyncio
async def test_automatic_cycle_recovers_interrupted_package_pointer_delivery(case, monkeypatch):
    s = case
    select(s)
    native = delivery._publish

    def fail_pointer(path, value, **kwargs):
        if path.name.endswith(".package.json"):
            raise OSError("interrupted pointer publication")
        return native(path, value, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(delivery, "_publish", fail_pointer)
        with pytest.raises(OSError, match="interrupted pointer"):
            await submit_existing_signatures(s)
    retained = s.queue.journal.get("package", "1")
    assert retained is not None
    s.queue = s.reopen()
    package = await s.queue.prepare(s.prepared)
    assert json.loads(canonical_json_bytes(package)) == retained
    assert len(list(Path(s.queue.config.certificate_directory).glob("*.package.json"))) == 1


@pytest.mark.asyncio
async def test_expiry_during_selected_package_replay_still_withholds_delivery(case, monkeypatch):
    s = case
    select(s)
    native = s.queue._package

    def expire_after_replay(*args):
        package = native(*args)
        s.queue.provider.block = s.prepared.publication.round.valid_through_block + 1
        return package

    monkeypatch.setattr(s.queue, "_package", expire_after_replay)
    await submit_existing_signatures(s)
    assert s.queue.journal.get("certificate", "1") is not None
    assert s.queue.journal.get("package", "1") is None
    assert not list(Path(s.queue.config.certificate_directory).glob("*.json"))
