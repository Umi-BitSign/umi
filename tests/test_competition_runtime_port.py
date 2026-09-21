from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3
from types import SimpleNamespace

import pytest

from umi.competition_artifacts import preserve_bundle
from umi.competition_launch import PublicLaunchIdentity
from umi.competition_policy_lineage import PolicyLineage, register_lineage
from umi.competition_publication import PublicationReplayLimits
from umi.competition_review_history import EvaluatorReviewStore
from umi.competition_runtime_port import (
    RuntimePortReview,
    SignedRuntimePortReview,
    baseline_record_digest,
    verify_runtime_port,
)
from umi.competition_store import CompetitionStore
from umi.open_competition import ModelBundle, digest, sign_object
from umi.protocol import canonical_json_bytes

from . import test_open_competition
from .test_competition_chain import chain_config as chain_config
from .test_competition_package import (
    package_limits as package_limits,
)
from .test_competition_package import (
    release_identity as release_identity,
)
from .test_competition_publication import replay_limits as replay_limits
from .test_open_competition import bundle_at, round_for, snapshot, submission, suite_for, wallet

base_policy = test_open_competition.policy


@pytest.fixture
def policy(base_policy, request):
    if getattr(request, "param", None) == "burn":
        from .test_competition_model_burn import burn_policy

        return burn_policy(base_policy)
    return base_policy


def attest(review, names=("Charlie", "Dave")):
    signatures = tuple(sign_object(review, wallet(name)) for name in names)
    return SignedRuntimePortReview(
        review=review, source_signatures=signatures, target_signatures=signatures
    )


@pytest.fixture
def port(policy, tmp_path):
    original = bundle_at(tmp_path / "old")
    archive = tmp_path / "archive"
    preserve_bundle(original, tmp_path / "old", archive, policy)
    shutil.copytree(tmp_path / "old", tmp_path / "new")
    payload = b"INERT TEST CPU ENTRYPOINT"
    (tmp_path / "new/inference.txt").write_bytes(payload)
    files = tuple(
        f.model_copy(
            update={"sha256": hashlib.sha256(payload).hexdigest(), "size_bytes": len(payload)}
        )
        if f.path == "inference.txt"
        else f
        for f in original.files
    )
    replacement = ModelBundle.model_validate_json(
        canonical_json_bytes(
            original.model_copy(update={"parent_baseline_sha256": digest(original), "files": files})
        )
    )
    target = policy.model_copy(
        update={
            "sequence": 2,
            "predecessor_sha256": digest(policy),
            "evaluation_runtime_sha256": "de" * 32,
        }
    )
    preserve_bundle(replacement, tmp_path / "new", archive, target)
    store = CompetitionStore(tmp_path / "state", policy)
    baseline = store.initialize_baseline(original, archive)
    signed = submission(policy)
    store.admit(signed, snapshot(), 110)
    old_rows = rows(store)
    store = CompetitionStore(store.directory, target, predecessor_policies=(policy,))
    review = RuntimePortReview(
        schema="umi-unrewarded-runtime-port-review/1",
        policy_sha256=digest(target),
        source_policy_sha256=digest(policy),
        previous_promotion_sha256=baseline_record_digest(baseline),
        sequence=1,
        original=original,
        replacement=replacement,
        entrypoint="inference.txt",
        qualification_sha256="ab" * 32,
        source_review_sha256="ac" * 32,
        offline_reconstruction_passed=True,
        not_before_block=201,
        valid_through_block=250,
    )
    return SimpleNamespace(
        policy=policy,
        target=target,
        archive=archive,
        store=store,
        baseline=baseline,
        original=original,
        replacement=replacement,
        signed=signed,
        review=review,
        old_rows=old_rows,
    )


def rows(store):
    with store._connection() as connection:
        return {
            table: connection.execute(f"SELECT * FROM {table}").fetchall()
            for table in ("submissions", "promotions", "model_identities")
        }


def apply(port, certificate=None, block=210, store=None):
    return (store or port.store).apply_runtime_port(
        certificate or attest(port.review), archive=port.archive, observed_block=block
    )


def test_append_preserves_history_admissions_and_unallocated_credit(port):
    p = port
    result = apply(p)
    current = rows(p.store)
    assert current["submissions"] == p.old_rows["submissions"]
    assert current["promotions"][:1] == p.old_rows["promotions"]
    assert p.old_rows["model_identities"][0] in current["model_identities"]
    assert result["contributor_hotkey"] is None
    assert result["previous_promotion_sha256"] == baseline_record_digest(p.baseline)
    reopened = CompetitionStore(p.store.directory, p.target, predecessor_policies=(p.policy,))
    assert reopened.baseline() == result
    assert (
        reopened.reviewed_promotion_head("aa" * 32, maximum_bytes=1_000_000).contributor_hotkey
        is None
    )
    assert reopened.admit(p.signed, snapshot(220), 220)["status"] == "accepted_no_weight"
    # Receipt arrival and signature ordering do not change the shared decision.
    assert apply(p, attest(p.review, ("Dave", "Charlie")), block=999, store=reopened) == result
    with reopened._connection() as connection:
        receipt = json.loads(
            connection.execute(
                "SELECT value FROM metadata WHERE key='runtime_port_receipt:1'"
            ).fetchone()[0]
        )
    assert receipt["observed_block"] == 210


def test_independent_review_history_agrees_and_reopens(port, tmp_path):
    p = port
    reviews = EvaluatorReviewStore(
        tmp_path / "reviews",
        p.policy,
        limits=PublicationReplayLimits(
            maximum_roster_bytes=1_000_000,
            maximum_evidence_bytes=1_000_000,
            maximum_certificate_bytes=1_000_000,
        ),
    )
    reviews.initialize_baseline(p.original, p.archive)
    reviews = EvaluatorReviewStore(
        reviews.directory, p.target, predecessor_policies=(p.policy,), limits=reviews.limits
    )
    assert apply(p) == apply(p, attest(p.review, ("Dave", "Charlie")), block=215, store=reviews)
    reopened = EvaluatorReviewStore(
        reviews.directory, p.target, predecessor_policies=(p.policy,), limits=reviews.limits
    )
    assert reopened.baseline() == p.store.baseline()


@pytest.mark.parametrize("change", ["weights", "license", "role", "path", "parent", "no_change"])
def test_only_declared_entrypoint_may_change(port, change):
    p = port
    bundle = p.replacement
    if change in {"weights", "role", "path"}:
        files = list(bundle.files)
        index = next(i for i, f in enumerate(files) if f.role == "weights")
        update = (
            {"sha256": "bd" * 32}
            if change == "weights"
            else {"role": "dependency"}
            if change == "role"
            else {"path": "zweights.txt"}
        )
        files[index] = files[index].model_copy(update=update)
        bundle = bundle.model_copy(update={"files": tuple(files)})
    elif change == "license":
        bundle = bundle.model_copy(update={"license_id": "MIT"})
    elif change == "parent":
        bundle = bundle.model_copy(update={"parent_baseline_sha256": "cc" * 32})
    else:
        bundle = bundle.model_copy(update={"files": p.original.files})
    with pytest.raises(ValueError):
        apply(p, attest(p.review.model_copy(update={"replacement": bundle})))
    assert rows(p.store)["promotions"] == p.old_rows["promotions"]


@pytest.mark.parametrize(
    "change",
    ["insufficient", "duplicate", "unauthorized", "invalid", "source_missing", "target_missing"],
)
def test_both_policy_quorums_are_required(port, change):
    p = port
    cert = attest(p.review)
    if change == "insufficient":
        cert = attest(p.review, ("Charlie",))
    elif change == "duplicate":
        cert = attest(p.review, ("Charlie", "Charlie"))
    elif change == "unauthorized":
        cert = attest(p.review, ("Charlie", "Alice"))
    elif change == "invalid":
        cert = cert.model_copy(
            update={"review": p.review.model_copy(update={"not_before_block": 202})}
        )
    else:
        cert = cert.model_copy(
            update={
                ("source_signatures" if change == "source_missing" else "target_signatures"): ()
            }
        )
    with pytest.raises(ValueError):
        apply(p, cert)


@pytest.mark.parametrize(
    "change",
    ["terms", "same_runtime", "unrelated", "source", "parent", "sequence", "zero_evidence"],
)
def test_scope_and_parent_are_bound(port, change):
    p = port
    if change in {"terms", "same_runtime", "unrelated"}:
        update = (
            {"contribution_terms_sha256": "ee" * 32}
            if change == "terms"
            else {"evaluation_runtime_sha256": p.policy.evaluation_runtime_sha256}
            if change == "same_runtime"
            else {"predecessor_sha256": "ee" * 32}
        )
        target = p.target.model_copy(update=update)
        review = p.review.model_copy(update={"policy_sha256": digest(target)})
        with pytest.raises(ValueError):
            verify_runtime_port(attest(review), PolicyLineage(target, (p.policy,)))
    else:
        update = (
            {"source_policy_sha256": "ee" * 32}
            if change == "source"
            else {"previous_promotion_sha256": "ee" * 32}
            if change == "parent"
            else {"sequence": 2}
            if change == "sequence"
            else {"qualification_sha256": "0" * 64}
        )
        with pytest.raises(ValueError):
            apply(p, attest(p.review.model_copy(update=update)))
    assert p.store.baseline() == p.baseline


@pytest.mark.parametrize("block", [200, 251, True])
def test_activation_window_is_enforced(port, block):
    with pytest.raises(ValueError):
        apply(port, block=block)


def test_retained_round_and_observation_watermark_block_early_change(port):
    p = port
    suite = suite_for(p.target)
    round_ = round_for(p.target, suite, (p.signed,), digest(p.original))
    p.store.close_round(round_, current_block=120)
    cert = attest(p.review.model_copy(update={"not_before_block": 150}))
    with pytest.raises(ValueError, match="during a retained round"):
        apply(p, cert, block=160)
    with p.store._transaction() as connection:
        connection.execute("UPDATE metadata SET value='220' WHERE key='observed_block'")
    with pytest.raises(ValueError, match="earlier finalized"):
        apply(p)


def test_empty_published_round_also_blocks_port(port, tmp_path):
    p = port
    round_ = round_for(p.target, suite_for(p.target), (p.signed,), digest(p.original))
    launch = PublicLaunchIdentity(
        schema="umi-competition-public-launch/2",
        round_schedule=round_.public_schedule,
        eligible_tracks=round_.eligible_tracks,
        round_stride_blocks=100,
    )
    store = CompetitionStore(tmp_path / "published", p.policy, public_launch=launch)
    store.initialize_baseline(p.original, p.archive)
    store = CompetitionStore(
        store.directory, p.target, predecessor_policies=(p.policy,), public_launch=launch
    )
    cert = attest(p.review.model_copy(update={"not_before_block": 150}))
    with pytest.raises(ValueError, match="during a published round"):
        apply(p, cert, block=160, store=store)
    assert apply(p, cert, block=210, store=store)["sequence"] == 1


def test_runtime_port_cannot_assign_or_remove_earned_credit(port):
    p = port
    baseline = {
        **p.baseline,
        "contributor_hotkey": wallet("Alice").hotkey.ss58_address,
        "kind": "verified_model_promotion_no_weight",
    }
    from umi.open_competition import identity

    with p.store._transaction() as connection:
        connection.execute(
            "UPDATE promotions SET digest=?,contributor=?,body=? WHERE sequence=0",
            (
                baseline_record_digest(baseline),
                identity(baseline["contributor_hotkey"]),
                canonical_json_bytes(baseline),
            ),
        )
    cert = attest(
        p.review.model_copy(update={"previous_promotion_sha256": baseline_record_digest(baseline)})
    )
    with pytest.raises(ValueError, match="exact unrewarded parent"):
        apply(p, cert)


def test_corrupted_preserved_assets_refuse_activation(port):
    p = port
    path = p.archive / digest(p.replacement) / "model/weights.txt"
    path.chmod(0o600)
    path.write_bytes(b"corrupt")
    with pytest.raises(ValueError):
        apply(p)
    assert p.store.baseline() == p.baseline


@pytest.mark.parametrize("policy", ["burn"], indirect=True)
def test_ported_baseline_preserves_burn_through_settlement_and_package_replay(
    port,
    tmp_path,
    replay_limits,
    package_limits,
    release_identity,
):
    from pathlib import Path

    from umi.competition_package import load_competition_package, prepare_competition_package
    from umi.competition_publication import build_cutoff_publication, build_settlement_publication
    from umi.competition_settlement import CompetitionSettlement, EvidenceCutoffSchedule

    from .test_competition_model_burn import burn_snapshot
    from .test_competition_publication import _certificate, _independent
    from .test_competition_two_task_profile import launch_suite
    from .test_open_competition import result_for

    p = port
    register_lineage(p.target, (p.policy,))
    cert = attest(p.review.model_copy(update={"not_before_block": 110, "valid_through_block": 115}))
    apply(p, cert, block=110)
    suite = launch_suite(p.target)
    round_ = round_for(p.target, suite, (p.signed,), digest(p.replacement))
    schedule = EvidenceCutoffSchedule(
        schema="umi-competition-evidence-cutoff/1",
        policy_sha256=digest(p.target),
        round_sha256=digest(round_),
        evidence_cutoff_block=160,
    )

    def snap(block):
        return burn_snapshot(p.target).model_copy(
            update={"block": block, "block_hash": "0x" + f"{block:064x}"}
        )

    p.store.fix_evidence_cutoff(round_, schedule, observed_block=120)
    p.store.close_round(round_, current_block=120)
    evaluation = result_for(p.signed, round_, suite)
    evidence = ((p.signed, _independent(p.target, p.signed, round_, suite, evaluation)),)
    p.store.record_independent_evaluation(
        signed=p.signed, evidence=evidence[0][1], round_=round_, suite=suite, observed_block=150
    )
    cutoff = _certificate(
        build_cutoff_publication(
            round_=round_,
            cutoff_schedule=schedule,
            registration_snapshot=snap(120),
            submissions=(p.signed,),
            policy=p.target,
            limits=replay_limits,
        )
    )
    settlement = CompetitionSettlement.model_validate_json(
        canonical_json_bytes(
            p.store.settle(
                round_=round_, suite=suite, evidence=evidence, snapshot=snap(160), current_block=160
            )
        )
    )
    certificate = _certificate(
        build_settlement_publication(
            cutoff_certificate=cutoff,
            retained_settlement=settlement,
            submissions=(p.signed,),
            evidence=evidence,
            policy=p.target,
            limits=replay_limits,
        )
    )
    assert settlement.promotion_head.sequence == 1
    assert settlement.promotion_head.contributor_hotkey is None
    prepared = prepare_competition_package(
        policy=p.target,
        cutoff_certificate=cutoff,
        settlement_certificate=certificate,
        retained_settlement=settlement,
        roster=(p.signed,),
        evidence=evidence,
        replay_limits=replay_limits,
        release_identity=release_identity,
        destination_root=tmp_path / "packages",
        limits=package_limits,
    )
    loaded = load_competition_package(
        Path(prepared.package_path),
        expected_package_sha256=prepared.package_sha256,
        expected_policy_sha256=digest(p.target),
        observed_release=release_identity,
        limits=package_limits,
    )
    assert loaded.retained_settlement.projection.weights[0] == 19661
    assert loaded.retained_settlement.projection.weights[6] == 45874
    assert loaded.retained_settlement.projection.chain_submission_authorized is False


@pytest.mark.parametrize("tamper", ["receipt", "fence", "marker", "time", "record"])
def test_reopen_authenticates_receipt_and_fences(port, tamper):
    p = port
    apply(p)
    with p.store._connection() as connection:
        if tamper == "receipt":
            connection.execute("DELETE FROM metadata WHERE key='runtime_port_receipt:1'")
        elif tamper == "fence":
            connection.execute("DROP TRIGGER runtime_port_promotions_insert")
        elif tamper == "marker":
            connection.execute("DELETE FROM metadata WHERE key='runtime_port_writer'")
        elif tamper == "time":
            connection.execute("UPDATE metadata SET value='209' WHERE key='observed_block'")
        else:
            record = p.store.baseline()
            record["contributor_hotkey"] = wallet("Alice").hotkey.ss58_address
            connection.execute(
                "UPDATE promotions SET body=? WHERE sequence=1", (canonical_json_bytes(record),)
            )
    with pytest.raises(ValueError):
        CompetitionStore(p.store.directory, p.target, predecessor_policies=(p.policy,))


def test_already_open_old_writer_is_fenced(port):
    p = port
    old = sqlite3.connect(p.store.path, isolation_level=None)
    old.create_function("umi_writer_generation", 0, lambda: 2)
    old.create_function("umi_submission_checkpoint_binding", 0, lambda: None)
    try:
        apply(p)
        with pytest.raises(sqlite3.OperationalError, match="umi_runtime_port_writer"):
            old.execute("UPDATE metadata SET value='1' WHERE key='observed_block'")
    finally:
        old.close()


def test_failed_insert_rolls_back_record_receipt_and_fence(port, monkeypatch):
    p = port
    from umi import competition_runtime_port_history
    from umi.open_competition import model_content_digest

    monkeypatch.setattr(
        competition_runtime_port_history,
        "model_content_digest",
        lambda _: model_content_digest(p.original),
    )
    with pytest.raises(sqlite3.IntegrityError):
        apply(p)
    assert rows(p.store) == p.old_rows
    with p.store._connection() as connection:
        assert not connection.execute(
            "SELECT name FROM sqlite_master WHERE name GLOB 'runtime_port_*'"
        ).fetchall()
        assert not connection.execute(
            "SELECT key FROM metadata WHERE key GLOB 'runtime_port_*'"
        ).fetchall()


@pytest.mark.parametrize("head", [200, 210, 251])
def test_operator_command_owns_fresh_observations_and_preserves_history(
    port, tmp_path, chain_config, monkeypatch, head
):
    from umi.competition_cli import _parser, execute
    from umi.competition_commands import runtime_port as command
    from umi.competition_evaluator import EvaluatorConfig

    from .test_competition_evaluator import put
    from .test_competition_rounds import OwnedProvider

    p = port
    register_lineage(p.target, (p.policy,))
    limits = PublicationReplayLimits(
        maximum_roster_bytes=1_000_000,
        maximum_evidence_bytes=1_000_000,
        maximum_certificate_bytes=1_000_000,
    )
    reviews = EvaluatorReviewStore(tmp_path / "reviews", p.policy, limits=limits)
    reviews.initialize_baseline(p.original, p.archive)
    chain = chain_config.model_copy(
        update={
            "policy_sha256": digest(p.target),
            "state_directory": str(tmp_path / "chain"),
            "collection_timeout_seconds": 10,
        }
    )
    config = EvaluatorConfig(
        schema="umi-evaluator-config/1",
        policy_sha256=digest(p.target),
        chain=chain,
        evaluator_hotkey=wallet("Charlie").hotkey.ss58_address,
        wallet_name="test",
        hotkey_name="test",
        archive_directory=str(p.archive),
        video_directory=str(tmp_path / "videos"),
        settlement_review_directory=str(reviews.directory),
        settlement_replay_limits=limits,
        round_coordinator_origin="https://rounds.example.com",
        **{
            name: str(tmp_path / name)
            for name in (
                "wallet_path",
                "state_directory",
                "order_directory",
                "reveal_directory",
                "peer_directory",
                "outbox_directory",
            )
        },
    )
    events = []

    class Provider(OwnedProvider):
        async def start(self):
            events.append("start")

        async def wait_ready(self):
            events.append("ready")

        async def collect(self):
            events.append("collect")
            return await super().collect()

        async def aclose(self):
            events.append("close")

    monkeypatch.setattr(command, "FinalizedRegistrationProvider", lambda *_: Provider(head))
    for name, value in (
        ("certificate", attest(p.review)),
        ("config", config),
        ("chain", chain),
        ("policy", p.target),
        ("predecessor", p.policy),
    ):
        put(tmp_path / (name + ".json"), value)
    args = _parser().parse_args(
        [
            "--policy",
            str(tmp_path / "policy.json"),
            "--predecessor-policy",
            str(tmp_path / "predecessor.json"),
            "apply-runtime-port",
            "--confirm-quiesced-backup",
            "--certificate",
            str(tmp_path / "certificate.json"),
            "--evaluator-config",
            str(tmp_path / "config.json"),
            "--chain-config",
            str(tmp_path / "chain.json"),
            "--archive",
            str(p.archive),
        ]
    )
    if head == 210:
        result = execute(args)
        assert result["status"] == "unrewarded_runtime_port_applied"
        assert events == ["start", "ready", "collect", "collect", "close"]
        assert (
            EvaluatorReviewStore(
                reviews.directory, p.target, predecessor_policies=(p.policy,), limits=limits
            ).baseline()["sequence"]
            == 1
        )
    else:
        with pytest.raises(ValueError, match="application window"):
            execute(args)
        assert events == ["start", "ready", "collect", "close"]
        # An early command did not even roll the ledger to the target policy.
        assert (
            EvaluatorReviewStore(reviews.directory, p.policy, limits=limits).baseline()
            == p.baseline
        )
