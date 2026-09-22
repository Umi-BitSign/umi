"""Separate-process loopback TLS discovery probe of an existing synthetic run.

Uses a new queue and the exact prepared settlement; no production inputs.
The private self-signed TLS key is disposable and never a signing wallet.
"""

import asyncio
import gc
import json
import os
import socket
import sqlite3
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import httpx
import uvicorn
from fastapi import FastAPI
from qualify_full_settlement import SyntheticProvider

from tests.test_open_competition import wallet
from umi.competition_evaluator import EvaluatorConfig, EvaluatorJournal
from umi.competition_execution import execution_boundary, execution_slot
from umi.competition_package import (
    CompetitionPackageLimits,
    CompetitionReleaseIdentity,
    PreparedCompetitionPackage,
)
from umi.competition_publication import PublicationJournalCapacity, PublicationReplayLimits
from umi.competition_review_history import EvaluatorReviewStore
from umi.competition_rounds import RoundJournal, SettlementDeliveryConfig
from umi.competition_settlement_capacity import settlement_capacity
from umi.competition_settlement_delivery import SettlementQueue
from umi.competition_settlement_preparation import SettlementPreparation
from umi.competition_settlement_signing import IndependentSettlementSigner
from umi.competition_settlement_transport import (
    SettlementQuery,
    SignedSettlementQuery,
    attach_settlement_route,
    request_settlement,
)
from umi.competition_store import AdmissionCapacity, CompetitionStore
from umi.competition_void import VoidEvaluationEvidence
from umi.competition_worker import CompetitionReplayWorker, CompetitionWorkerCapacity
from umi.open_competition import CompetitionPolicy, RegistrationSnapshot, digest, sign_object
from umi.policy import umi_source_tree_sha256
from umi.protocol import canonical_json_bytes


def queue_from_file(path):
    doc = json.loads(path.read_bytes())
    policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(doc["policy"]))
    snapshot = RegistrationSnapshot.model_validate_json(canonical_json_bytes(doc["snapshot"]))
    limits = PublicationReplayLimits.model_validate_json(canonical_json_bytes(doc["limits"]))
    store = CompetitionStore(
        Path(doc["intake"]),
        policy,
        admission_capacity=AdmissionCapacity(maximum_records=4096, maximum_bytes=2 * 1024**3),
    )
    provider = SyntheticProvider(
        snapshot.registrations,
        snapshot.burn_destination,
        doc.get("clock_base", snapshot.block + 600),
    )
    provider.started = doc["clock_anchor"]
    return SettlementQueue(
        SettlementDeliveryConfig.model_validate_json(canonical_json_bytes(doc["config"])),
        store,
        provider,
        limits=limits,
        maximum_rounds=10,
        maximum_bytes=2 * 1024**3,
    )


async def probe(case):
    local_connection = os.environ.get("SETTLEMENT_WIRE_LOCAL") == "1"
    root = case / os.environ.get("SETTLEMENT_WIRE_NAME", "wire-probe")
    assert root.parent == case
    root.mkdir()
    # While the larger run finishes its package, an already completed pilot can
    # supply identical policy/limit/release fixture bytes. Bind them explicitly
    # to the larger proposal below; never substitute its evidence or snapshot.
    template = Path(os.environ.get("SETTLEMENT_FIXTURE_TEMPLATE", str(case))).resolve()
    package_dir = next((template / "packages").iterdir())
    policy = CompetitionPolicy.model_validate_json((package_dir / "policy.json").read_bytes())
    limits = PublicationReplayLimits.model_validate_json(
        (package_dir / "replay-limits.json").read_bytes()
    )
    release = CompetitionReleaseIdentity.model_validate_json(
        (package_dir / "release-identity.json").read_bytes()
    )
    prepared = SettlementPreparation.model_validate_json(
        next((case / "proposals").iterdir()).read_bytes()
    )
    assert digest(policy) == prepared.publication.round.policy_sha256
    config = SettlementDeliveryConfig(
        state_directory=str(root / "delivery"),
        certificate_directory=str(root / "certificates"),
        package_directory=str(root / "packages"),
        release_identity=release,
        package_limits=CompetitionPackageLimits(
            maximum_manifest_bytes=65536,
            maximum_policy_bytes=1024**2,
            maximum_cutoff_certificate_bytes=4 * 1024**2,
            maximum_settlement_certificate_bytes=4 * 1024**2,
            maximum_settlement_bytes=4 * 1024**2,
            maximum_roster_bytes=4 * 1024**2,
            maximum_evidence_bytes=256 * 1024**2,
            maximum_replay_limits_bytes=4096,
            maximum_release_identity_bytes=4096,
            maximum_aggregate_bytes=320 * 1024**2,
        ),
    )
    config_path = root / "fixture.json"
    # Reused signer journals retain a monotonic head. All probes of the same
    # synthetic case share the first clock anchor instead of resetting time.
    prior_clocks = list(case.glob("wire-*/fixture.json"))
    assert len(prior_clocks) <= 32
    clock_anchor = min(
        [time.monotonic()] + [json.loads(p.read_bytes())["clock_anchor"] for p in prior_clocks]
    )
    config_path.write_bytes(
        canonical_json_bytes(
            dict(
                policy=policy.model_dump(mode="json", by_alias=True),
                snapshot=prepared.publication.settlement.registration_snapshot.model_dump(
                    mode="json"
                ),
                limits=limits.model_dump(mode="json"),
                config=config.model_dump(mode="json", by_alias=True),
                intake=str(case / "intake"),
                clock_anchor=clock_anchor,
            )
        )
    )
    started = time.perf_counter()
    queue = queue_from_file(config_path)
    assert await queue.prepare(prepared) is None
    prep_seconds = time.perf_counter() - started
    del prepared, queue
    gc.collect()
    cert, key = root / "tls-cert.pem", root / "tls-key.pem"
    subprocess.run(
        [
            "/usr/bin/openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-days",
            "1",
            "-subj",
            "/CN=localhost",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=10,
    )
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    origin = "https://rounds.example" if local_connection else f"https://127.0.0.1:{port}"
    wire_options = (
        {"loopback_port": port}
        if local_connection
        else {"transport": httpx.AsyncHTTPTransport(verify=False, retries=0)}
    )
    log = (root / "server.log").open("w")
    server = subprocess.Popen(
        [
            sys.executable,
            str(Path(__file__).resolve()),
            "--serve",
            str(config_path),
            str(sock.fileno()),
        ],
        pass_fds=(sock.fileno(),),
        stdout=log,
        stderr=subprocess.STDOUT,
    )
    sock.close()
    result = dict(
        native_queue_prepare_seconds=prep_seconds,
        server_pid=server.pid,
        scope=(
            "explicit native loopback option, separate HTTP process"
            if local_connection
            else "independent-process loopback TLS, native profile-selected query/server timeouts"
        ),
        tls_verification=(
            "local-only HTTP explicitly selected"
            if local_connection
            else "disabled only for generated local fixture certificate"
        ),
        server_wait_seconds=getattr(settlement_capacity(limits), "operation_timeout_seconds", 25),
        client_read_seconds=getattr(settlement_capacity(limits), "read_timeout_seconds", 30),
        client_total_seconds=getattr(settlement_capacity(limits), "request_timeout_seconds", 35),
        producer_source_tree_sha256=umi_source_tree_sha256(),
    )
    try:
        # Cheap readiness GET never invokes settlement replay.
        async with httpx.AsyncClient(verify=False, trust_env=False, timeout=1) as health:
            for _ in range(100):
                if server.poll() is not None:
                    raise RuntimeError("fixture TLS server exited")
                try:
                    scheme = "http" if local_connection else "https"
                    await health.get(f"{scheme}://127.0.0.1:{port}/fixture-ready")
                    break
                except httpx.HTTPError:
                    await asyncio.sleep(0.1)
            else:
                raise RuntimeError("fixture TLS server did not start")
        signer = wallet("Validator0")
        query = SettlementQuery(
            schema="umi-settlement-query/1",
            policy_sha256=digest(policy),
            hotkey=signer.hotkey.ss58_address,
            nonce_unix_ns=str(time.time_ns()),
        )
        started = time.perf_counter()
        try:
            reply = await request_settlement(
                origin,
                SignedSettlementQuery(query=query, signature=sign_object(query, signer)),
                **wire_options,
                capacity=settlement_capacity(limits),
            )
            result.update(status="proposal_received", proposals=len(reply.proposals))
            assert len(reply.proposals) == 1
        except ValueError as exc:
            result.update(status="native_request_failed", reason=str(exc))
        result["request_wall_seconds"] = time.perf_counter() - started
        (root / "metrics.json").write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result), flush=True)
        if (
            result["status"] == "proposal_received"
            and os.environ.get("SETTLEMENT_WIRE_COMPLETE") == "1"
        ):
            await complete_wire(
                case,
                root,
                config_path,
                config,
                policy,
                limits,
                release,
                reply,
                origin,
                result,
                port if local_connection else None,
            )
    finally:
        # Only the child created above. Uvicorn drains its own outstanding request.
        server.terminate()
        try:
            server.wait(timeout=120)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait(timeout=5)
            result["owned_server_forced_cleanup"] = True
        log.close()
        result["server_exit_code"] = server.returncode
        (root / "metrics.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result), flush=True)


async def complete_wire(
    case,
    root,
    config_path,
    delivery,
    policy,
    limits,
    release,
    reply,
    origin,
    result,
    loopback_port=None,
):
    """Native retained-vote revalidation plus certificate/package over real TLS.

    The first pass already made a fresh native endorsement. Reusing that exact
    retained vote tests recovery/idempotency without changing any signed bytes.
    """
    prepared = reply.proposals[0]
    with sqlite3.connect(
        (case / "state_directory/evaluator.sqlite3").as_uri() + "?mode=ro", uri=True
    ) as db:
        raw = db.execute("select body from binding").fetchone()[0]
    config = EvaluatorConfig.model_validate_json(raw).model_copy(
        update={"maximum_journal_bytes": 2 * 1024**3}
    )
    journal = EvaluatorJournal(config)
    signer = wallet("Validator0")
    endpoint = next(
        e for e in prepared.evidence.entries if e.submission.submission.track == "endpoint"
    )
    slot = execution_slot(prepared.publication.round, endpoint.submission, config.evaluator_hotkey)
    _, _, _, own = journal.settlement_evidence(
        slot, void=isinstance(endpoint.evidence, VoidEvaluationEvidence)
    )
    legacy = own.announcement.evidence.legacy_policy
    snap = prepared.publication.settlement.registration_snapshot
    provider = SyntheticProvider(snap.registrations, snap.burn_destination, snap.block + 600)
    provider.started = json.loads(config_path.read_text())["clock_anchor"]

    async def boundary():
        return execution_boundary(await provider.collect())

    worker = SimpleNamespace(
        config=config,
        policy=policy,
        wallet=signer,
        provider=provider,
        boundary=boundary,
        journal=journal,
        legacy=legacy,
    )
    cutoffs = RoundJournal(case / "cutoff-journal", {"fixture": "full-pipeline"})
    reviews = EvaluatorReviewStore(
        case / "reviews",
        policy,
        limits=limits,
        admission_capacity=AdmissionCapacity(maximum_records=4096, maximum_bytes=2 * 1024**3),
    )
    started = time.perf_counter()
    vote = await IndependentSettlementSigner(worker, cutoffs, reviews, limits=limits).endorse(
        prepared
    )
    result["native_retained_vote_revalidation_seconds"] = time.perf_counter() - started
    del prepared, reply, own
    gc.collect()
    query = SettlementQuery(
        schema="umi-settlement-query/1",
        policy_sha256=digest(policy),
        hotkey=signer.hotkey.ss58_address,
        nonce_unix_ns=str(time.time_ns()),
        vote=vote,
    )
    started = time.perf_counter()
    reply = await request_settlement(
        origin,
        SignedSettlementQuery(query=query, signature=sign_object(query, signer)),
        **(
            {"loopback_port": loopback_port}
            if loopback_port is not None
            else {"transport": httpx.AsyncHTTPTransport(verify=False, retries=0)}
        ),
        capacity=settlement_capacity(limits),
    )
    assert reply.accepted_publication_sha256 == vote.publication_sha256
    result["vote_certificate_package_wire_seconds"] = time.perf_counter() - started
    package = PreparedCompetitionPackage.model_validate_json(
        next(Path(delivery.certificate_directory).glob("*.package.json")).read_bytes()
    )
    prior = PreparedCompetitionPackage.model_validate_json(
        next((case / "certificates").glob("*.package.json")).read_bytes()
    )
    assert package.package_sha256 == prior.package_sha256
    result["package_identical_to_first_pass"] = True
    capacity = CompetitionWorkerCapacity(
        maximum_receipts=20,
        maximum_bytes=1024**3,
        publication_journal=PublicationJournalCapacity(
            maximum_certificates=20, maximum_bytes=512 * 1024**2
        ),
    )
    started = time.perf_counter()
    retained = CompetitionReplayWorker(
        root / "replay", package_limits=delivery.package_limits, capacity=capacity
    ).run(
        Path(package.package_path),
        expected_package_sha256=package.package_sha256,
        expected_policy_sha256=digest(policy),
        observed_release=release,
    )
    assert (
        retained.current_status.settlement_certificate_retained and not retained.current_status.held
    )
    result.update(
        status="complete_real_wire_with_retained_vote",
        settlement_certificate_retained=True,
        final_worker_replay_seconds=time.perf_counter() - started,
    )


if __name__ == "__main__":
    os.umask(0o077)
    if sys.argv[1] == "--serve":
        path = Path(sys.argv[2])
        app = FastAPI()
        attach_settlement_route(app, queue_from_file(path))
        uvicorn.run(
            app,
            fd=int(sys.argv[3]),
            ssl_certfile=(
                None
                if os.environ.get("SETTLEMENT_WIRE_LOCAL") == "1"
                else str(path.parent / "tls-cert.pem")
            ),
            ssl_keyfile=(
                None
                if os.environ.get("SETTLEMENT_WIRE_LOCAL") == "1"
                else str(path.parent / "tls-key.pem")
            ),
            access_log=False,
            log_level="warning",
        )
    else:
        asyncio.run(probe(Path(sys.argv[1]).resolve()))
