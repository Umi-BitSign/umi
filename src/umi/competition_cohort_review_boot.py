"""Own the private phase review listener, signing journal and finality lifetime."""

import asyncio
import logging
import os
from contextlib import AsyncExitStack, asynccontextmanager, contextmanager
from pathlib import Path

import httpx
import uvicorn
from fastapi import FastAPI

from .competition_cohort_admission_http import (
    AdmissionHistoryHTTPClient,
    AdmissionHistoryReader,
    admission_vote_routes,
)
from .competition_cohort_admission_journal import CohortAdmissionJournal
from .competition_cohort_admission_signer import CohortAdmissionSigner
from .competition_cohort_benchmark_host import BenchmarkHost
from .competition_cohort_model_review import ModelArtifactReviewer
from .competition_cohort_model_review_http import model_review_routes
from .competition_cohort_phase_vote_http import phase_vote_routes
from .competition_cohort_progress_signer import CohortProgressSigner
from .competition_cohort_review_config import PhaseReviewServiceConfig
from .competition_cohort_review_http import _credential
from .competition_cohort_review_selection import SelectedPhaseReviewer
from .competition_cohort_service_selection import SelectedServiceReviewer
from .competition_cohort_service_vote_http import service_vote_routes
from .competition_cohort_settlement_proofs import SettlementRegistrationFiles
from .competition_historical_registration import HistoricalRegistrationProvider
from .competition_host_activation import _read_root_control_path
from .competition_reward_proof_archive import RewardProofArchive
from .competition_reward_service import _close_provider
from .competition_store import CompetitionStore
from .concurrency import await_owned_task, run_owned_thread
from .named_hotkey import load_named_hotkey
from .open_competition import digest, identity, sign_object
from .private_files import ensure_private_directory, lock_private_file
from .protocol import canonical_json_bytes

logger = logging.getLogger(__name__)


def _token(path: str) -> str:
    # Root-owned, group-readable by the service, never embedded in public config.
    return _credential(
        _read_root_control_path(Path(path), 257, modes={0o400, 0o440})
        .decode("ascii")
        .removesuffix("\n")
    )


@asynccontextmanager
async def phase_review_app(config: PhaseReviewServiceConfig):
    config = PhaseReviewServiceConfig.model_validate_json(canonical_json_bytes(config))
    root = Path(config.signing.directory)
    ensure_private_directory(root)
    lease = lock_private_file(root / "service.lock")
    async with AsyncExitStack() as resources:
        resources.callback(os.close, lease)
        owner_token, vote_token = _token(config.owner_token_file), _token(config.vote_token_file)
        if owner_token == vote_token:
            raise ValueError("owner exports and reviewer votes need separate credentials")
        provider = HistoricalRegistrationProvider(config.chain, config.policy)
        resources.push_async_callback(_close_provider, provider)
        key = await run_owned_thread(
            load_named_hotkey, Path(config.signer_key_file), config.signing.signer
        )

        async def sign(body):
            return await run_owned_thread(sign_object, body, key)

        client = await resources.enter_async_context(
            httpx.AsyncClient(
                trust_env=False,
                follow_redirects=False,
                limits=httpx.Limits(max_connections=2, max_keepalive_connections=2),
            )
        )
        proofs = RewardProofArchive(Path(config.proof_import_directory))

        async def archive(observation):
            return await run_owned_thread(SettlementRegistrationFiles._read, proofs, observation)

        reviewer = SelectedPhaseReviewer(
            config,
            provider,
            client,
            owner_token,
            archive,
            CompetitionStore(Path(config.promotion_directory), config.policy),
        )
        signer = CohortProgressSigner(config.signing, reviewer, sign)
        # Capacity, credentials and network placement can change on recovery;
        # immutable reward selections and the trusted observation owner cannot.
        await run_owned_thread(
            signer.journal.put,
            "phase_review_host",
            "selection",
            {
                "series_sha256": digest(config.series),
                "owner": identity(config.owner_hotkey),
                "eligible_tracks": list(config.eligible_tracks),
                "maximum_sample_gap_blocks": config.maximum_sample_gap_blocks,
            },
        )
        app = FastAPI(openapi_url=None, docs_url=None, redoc_url=None)
        for phase in ("intake", "preparation", "requests"):
            app.include_router(
                phase_vote_routes(
                    signer,
                    phase=phase,
                    token=vote_token,
                    timeout_seconds=config.review_timeout_seconds,
                )
            )
        if config.service_signing is not None:
            app.include_router(
                service_vote_routes(
                    SelectedServiceReviewer(config, provider, client, owner_token, archive, sign),
                    token=vote_token,
                    timeout_seconds=config.review_timeout_seconds,
                )
            )
        if config.admission_signing is not None:
            admission = CohortAdmissionJournal(config.admission_signing, config.policy)
            await run_owned_thread(
                admission.journal.put,
                "admission_review_host",
                "selection",
                {"series_sha256": digest(config.series), "owner": identity(config.owner_hotkey)},
            )
            history = AdmissionHistoryReader(
                config.owner_hotkey,
                AdmissionHistoryHTTPClient(
                    client,
                    config.owner_origin,
                    token=owner_token,
                    timeout_seconds=config.review_timeout_seconds,
                ),
                timeout_seconds=config.review_timeout_seconds,
            )
            app.include_router(
                admission_vote_routes(
                    CohortAdmissionSigner(admission, provider, history, sign, archive=archive),
                    token=vote_token,
                    timeout_seconds=config.review_timeout_seconds,
                )
            )
            if config.model_signing is not None:
                models = ModelArtifactReviewer(
                    config.model_signing, config.policy, provider.collect, history, sign
                )
                await run_owned_thread(
                    models.journal.put,
                    "model_review_host",
                    "selection",
                    {
                        "series_sha256": digest(config.series),
                        "owner": identity(config.owner_hotkey),
                    },
                )
                app.include_router(
                    model_review_routes(
                        models, token=vote_token, timeout_seconds=config.review_timeout_seconds
                    )
                )
        app.state.finality_provider = provider
        app.state.benchmark = None
        if config.benchmark is not None:
            ensure_private_directory(Path(config.benchmark.directory))
            resources.callback(
                os.close, lock_private_file(Path(config.benchmark.directory) / "service.lock")
            )
            benchmark = BenchmarkHost(config, provider, client, owner_token, vote_token, sign)
            app.include_router(benchmark.routes)
            app.state.benchmark = benchmark
        await provider.start()
        logger.info("phase_review_ready config_sha256=%s", digest(config))
        yield app


class _Server(uvicorn.Server):
    @contextmanager
    def capture_signals(self):
        # The CLI owns SIGINT/SIGTERM. Shutdown must drain owned signing work.
        yield


async def run_phase_review_service(config: PhaseReviewServiceConfig, stop: asyncio.Event):
    async with phase_review_app(config) as app:
        server = _Server(
            uvicorn.Config(
                app,
                host=config.listen_host,
                port=config.listen_port,
                access_log=False,
                log_config=None,
                timeout_graceful_shutdown=None,
            )
        )
        serving = asyncio.create_task(server.serve())
        workers = None
        try:
            while not stop.is_set() and not serving.done():
                app.state.finality_provider.ensure_observer_running()
                if server.started and app.state.benchmark is not None and workers is None:
                    workers = asyncio.create_task(app.state.benchmark.run(stop))
                await asyncio.wait((serving, *((workers,) if workers else ())), timeout=0.25)
                if workers is not None and workers.done():
                    workers.result()
                    if not stop.is_set():
                        raise RuntimeError("benchmark workers exited before shutdown")
            if serving.done():
                serving.result()
                if not stop.is_set():
                    raise RuntimeError("phase review listener exited before shutdown")
        finally:
            server.should_exit = True

            async def drain_workers():
                if workers is not None:
                    workers.cancel()
                    await asyncio.gather(workers, return_exceptions=True)

            # Uvicorn drains all HTTP tasks; request/signing budgets already
            # bound individual work. Keep the key/provider/lease until it ends.
            try:
                await await_owned_task(asyncio.create_task(drain_workers()))
            finally:
                await await_owned_task(serving)
            logger.info("phase_review_stopped config_sha256=%s", digest(config))
