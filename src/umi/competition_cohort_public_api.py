"""Read-only cohort results API, independently deployable from C5 owners."""

from __future__ import annotations

import asyncio
import hashlib
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, FastAPI, HTTPException, Query
from fastapi import Path as ApiPath
from pydantic import Field, model_validator
from starlette.concurrency import run_in_threadpool
from starlette.responses import JSONResponse

from .competition_cohort_model_scores import PublicModelScoreCache
from .competition_cohort_public_downloads import PublicModelDownload
from .competition_cohort_public_results import PublicModelCatalog, PublicPaidResults
from .competition_public_results_directory import (
    PublicResultsDirectory,
    atomic_write,
    owned_directory,
    read_owned_file,
)
from .concurrency import run_owned_thread
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes
from .r2_sigv4 import R2SigV4, load_r2_credentials

MAXIMUM_ARTIFACT_BYTES = 64 * 1024**2
_ID = r"^[0-9a-f]{64}$"


class CohortPublicApiConfig(StrictProtocolModel):
    results: PublicResultsDirectory
    model_score_corrections: dict[Hex32, Hex32] = Field(default_factory=dict)
    r2_credential_path: str | None = None
    r2_bucket: str = "umi-model-artifacts"
    url_expiry_seconds: Annotated[int, Field(ge=60, le=604800)] = 3600
    maximum_concurrent_reads: Annotated[int, Field(ge=1, le=32)] = 4
    maximum_artifact_bytes: Annotated[int, Field(gt=0)] = MAXIMUM_ARTIFACT_BYTES

    @model_validator(mode="after")
    def credentials_path(self):
        if self.r2_credential_path is not None and not Path(self.r2_credential_path).is_absolute():
            raise ValueError("public R2 credentials must have an absolute private path")
        return self


class CohortPublicDescriptor(StrictProtocolModel):
    catalog_sha256: Hex32
    paid_results_sha256: Hex32 | None
    downloads: dict[Hex32, Hex32]


def _artifact(root: Path, key: str, model, maximum: int):
    raw = read_owned_file(root / "artifacts" / (key + ".json"), maximum)
    if hashlib.sha256(raw).hexdigest() != key:
        raise ValueError("public cohort artifact needs repair: digest differs")
    return model.model_validate_json(raw)


def _publication_checkpoint(root: Path, cohort: str, maximum: int):
    try:
        raw = read_owned_file(root / "cohorts" / (cohort + ".published"), 64)
    except FileNotFoundError:
        return None
    if len(raw) != 64 or any(c not in b"0123456789abcdef" for c in raw):
        raise ValueError("public publication checkpoint needs repair: invalid descriptor digest")
    key = raw.decode("ascii")
    try:
        descriptor = _artifact(root, key, CohortPublicDescriptor, maximum)
    except FileNotFoundError as error:
        raise ValueError(
            "public publication checkpoint descriptor missing; repair required"
        ) from error
    return key, descriptor


def publish_cohort(config: CohortPublicApiConfig, catalog, paid, downloads):
    """Single publisher installs immutable artifacts before its atomic descriptor.

    Repeating after interruption restores missing identical artifacts. The caller
    owns publication sequencing; this is not a native evidence repair path.
    """
    catalog = PublicModelCatalog.model_validate_json(canonical_json_bytes(catalog))
    paid = (
        None if paid is None else PublicPaidResults.model_validate_json(canonical_json_bytes(paid))
    )
    if paid is not None and (paid.cohort_sha256, paid.policy_sha256) != (
        catalog.cohort_sha256,
        catalog.policy_sha256,
    ):
        raise ValueError("public paid and model results belong to different cohorts")
    allowed = {r.model_sha256 for r in catalog.items if r.release == "public_release_authorized"}
    root = Path(config.results.directory)
    for path in (root, root / "artifacts", root / "cohorts"):
        owned_directory(path, create=True)
    descriptor_path = root / "cohorts" / (catalog.cohort_sha256 + ".json")
    checkpoint = _publication_checkpoint(root, catalog.cohort_sha256, config.maximum_artifact_bytes)
    if checkpoint is not None:
        previous = checkpoint[1]
    else:
        try:
            previous = CohortPublicDescriptor.model_validate_json(
                read_owned_file(descriptor_path, config.maximum_artifact_bytes)
            )
        except FileNotFoundError:
            previous = None
    if previous is not None:
        try:
            old_catalog = _artifact(
                root, previous.catalog_sha256, PublicModelCatalog, config.maximum_artifact_bytes
            )
        except FileNotFoundError:
            if hashlib.sha256(canonical_json_bytes(catalog)).hexdigest() != previous.catalog_sha256:
                raise ValueError(
                    "missing public catalog needs its original native inventory"
                ) from None
            old_catalog = catalog
        if old_catalog.policy_sha256 != catalog.policy_sha256 or not {
            r.submission_sha256 for r in old_catalog.items
        } <= {r.submission_sha256 for r in catalog.items}:
            raise ValueError("public catalog cannot discard admitted history or change policy")
        if previous.paid_results_sha256 is not None:
            try:
                old_paid = _artifact(
                    root,
                    previous.paid_results_sha256,
                    PublicPaidResults,
                    config.maximum_artifact_bytes,
                )
            except FileNotFoundError:
                if (
                    paid is None
                    or hashlib.sha256(canonical_json_bytes(paid)).hexdigest()
                    != previous.paid_results_sha256
                ):
                    raise ValueError(
                        "missing public paid results need the original native projection"
                    ) from None
                old_paid = paid
            if paid is not None and paid != old_paid:
                raise ValueError("public certified paid results conflict with retained publication")
            paid = old_paid

    def install(model):
        raw = canonical_json_bytes(model)
        if len(raw) > config.maximum_artifact_bytes:
            raise ValueError("public projection exceeds configured artifact capacity")
        key = hashlib.sha256(raw).hexdigest()
        atomic_write(root / "artifacts" / (key + ".json"), raw)
        return key

    mapped = {}
    for download in downloads:
        download = PublicModelDownload.model_validate_json(canonical_json_bytes(download))
        if download.cohort_sha256 != catalog.cohort_sha256 or download.model_sha256 not in allowed:
            raise ValueError("download lacks original public release authorization")
        if download.model_sha256 in mapped:
            raise ValueError("public download repeats model")
        mapped[download.model_sha256] = install(download)
    if previous is not None and not previous.downloads.keys() <= mapped.keys():
        raise ValueError("completed public model transport missing; repair its native metadata")
    descriptor = CohortPublicDescriptor(
        catalog_sha256=install(catalog),
        paid_results_sha256=None if paid is None else install(paid),
        downloads=mapped,
    )
    checkpoint_sha256 = install(descriptor)
    atomic_write(
        root / "cohorts" / (catalog.cohort_sha256 + ".published"),
        checkpoint_sha256.encode("ascii"),
        immutable=False,
    )
    atomic_write(
        descriptor_path,
        canonical_json_bytes(descriptor),
        immutable=False,
    )
    return descriptor


def cohort_public_routes(
    config: CohortPublicApiConfig, *, signer: R2SigV4 | None = None, model_scores=None
):
    config = CohortPublicApiConfig.model_validate_json(canonical_json_bytes(config))
    if signer is None and config.r2_credential_path is not None:
        loaded = load_r2_credentials(Path(config.r2_credential_path))
        signer = R2SigV4(loaded.endpoint, config.r2_bucket, loaded.credentials)
    root, router = Path(config.results.directory), APIRouter()
    slots = asyncio.Semaphore(config.maximum_concurrent_reads)
    model_scores = model_scores or PublicModelScoreCache(
        root,
        maximum_bytes=config.maximum_artifact_bytes,
        corrections=config.model_score_corrections,
    )

    def load(cohort):
        for p in (root, root / "cohorts", root / "artifacts"):
            owned_directory(p)
        checkpoint = _publication_checkpoint(root, cohort, config.maximum_artifact_bytes)
        try:
            raw = read_owned_file(
                root / "cohorts" / (cohort + ".json"), config.maximum_artifact_bytes
            )
        except FileNotFoundError as error:
            if checkpoint is None:
                raise HTTPException(404, "cohort results not published") from error
            raise ValueError(
                "completed public cohort descriptor missing; repair required"
            ) from error
        if checkpoint is not None and hashlib.sha256(raw).hexdigest() != checkpoint[0]:
            raise ValueError(
                "public cohort descriptor differs from publication checkpoint; repair required"
            )
        descriptor = CohortPublicDescriptor.model_validate_json(raw)
        catalog = _artifact(
            root, descriptor.catalog_sha256, PublicModelCatalog, config.maximum_artifact_bytes
        )
        if catalog.cohort_sha256 != cohort:
            raise ValueError("public cohort descriptor belongs to another cohort")
        return descriptor, catalog

    async def bounded(callback):
        try:
            await asyncio.wait_for(slots.acquire(), timeout=1)
        except TimeoutError as error:
            raise HTTPException(503, "public results busy; retry unchanged") from error
        try:
            return JSONResponse(
                await run_in_threadpool(callback), headers={"Cache-Control": "no-store"}
            )
        except HTTPException:
            raise
        except (OSError, ValueError, KeyError) as error:
            raise HTTPException(503, "public results metadata needs repair") from error
        finally:
            slots.release()

    def page(items, offset, limit):
        return {
            "total": len(items),
            "offset": offset,
            "limit": limit,
            "next_offset": offset + limit if offset + limit < len(items) else None,
            "items": items[offset : offset + limit],
        }

    @router.get("/v1/competition/cohorts/{cohort}/model-results")
    async def model_results(
        cohort: Annotated[str, ApiPath(pattern=_ID)],
        offset: int = Query(0, ge=0, le=65536),
        limit: int = Query(100, ge=1, le=100),
    ):
        def result():
            try:
                body = model_scores.read(cohort)
            except FileNotFoundError as error:
                raise HTTPException(404, "certified model results not published") from error
            items = body.pop("items")
            return {**body, **page(items, offset, limit)}

        return await bounded(result)

    @router.get("/v1/competition/cohorts/{cohort}/service-results")
    async def service_results(
        cohort: Annotated[str, ApiPath(pattern=_ID)],
        offset: int = Query(0, ge=0, le=65536),
        limit: int = Query(100, ge=1, le=100),
    ):
        def result():
            descriptor, catalog = load(cohort)
            if descriptor.paid_results_sha256 is None:
                raise HTTPException(404, "certified paid results not published")
            paid = _artifact(
                root,
                descriptor.paid_results_sha256,
                PublicPaidResults,
                config.maximum_artifact_bytes,
            )
            if (paid.cohort_sha256, paid.policy_sha256) != (cohort, catalog.policy_sha256):
                raise ValueError("paid results binding differs")
            body = paid.model_dump(mode="json", by_alias=True)
            items = body.pop("items")
            return {**body, **page(items, offset, limit)}

        return await bounded(result)

    @router.get("/v1/competition/cohorts/{cohort}/models")
    async def models(
        cohort: Annotated[str, ApiPath(pattern=_ID)],
        offset: int = Query(0, ge=0, le=65536),
        limit: int = Query(100, ge=1, le=100),
    ):
        def result():
            descriptor, catalog = load(cohort)
            body = catalog.model_dump(mode="json", by_alias=True)
            items = body.pop("items")
            for item in items:
                model = item["model_sha256"]
                item["download_available"] = model in descriptor.downloads
                item["download_url"] = (
                    f"/v1/competition/cohorts/{cohort}/models/{model}/download"
                    if item["download_available"]
                    else None
                )
            return {**body, **page(items, offset, limit)}

        return await bounded(result)

    def selected(cohort, model):
        descriptor, catalog = load(cohort)
        if not any(
            r.model_sha256 == model and r.release == "public_release_authorized"
            for r in catalog.items
        ):
            raise HTTPException(404, "public model release not available")
        if model not in descriptor.downloads:
            raise HTTPException(503, "public model transport metadata pending")
        download = _artifact(
            root, descriptor.downloads[model], PublicModelDownload, config.maximum_artifact_bytes
        )
        if (download.cohort_sha256, download.model_sha256) != (cohort, model):
            raise ValueError("public model transport belongs to another model")
        if signer is None:
            raise HTTPException(503, "public model download signer unavailable")
        return download

    def capability(key, now):
        return signer.presign("GET", key, expires_seconds=config.url_expiry_seconds, at=now)

    def expiry(now):
        return (now + timedelta(seconds=config.url_expiry_seconds)).isoformat()

    @router.get("/v1/competition/cohorts/{cohort}/models/{model}/download")
    async def download(
        cohort: Annotated[str, ApiPath(pattern=_ID)], model: Annotated[str, ApiPath(pattern=_ID)]
    ):
        def result():
            d, now = selected(cohort, model), datetime.now(timezone.utc)
            return {
                "schema": "umi-public-model-download-response/1",
                "cohort_sha256": cohort,
                "model_sha256": model,
                "format": d.format,
                "bundle": d.bundle.model_dump(mode="json", by_alias=True),
                "files_url": f"/v1/competition/cohorts/{cohort}/models/{model}/download-files",
                "url_expires_at_utc": expiry(now),
                "method": "GET",
                "archive": None
                if d.archive is None
                else {**d.archive.model_dump(), "url": capability(d.archive_key(), now)},
                "payload": None
                if d.payload is None
                else {
                    "sha256": d.payload.payload_sha256,
                    "size_bytes": d.payload.total_bytes,
                    "url": capability(d.payload_key(), now),
                },
                "chain_submission_authorized": False,
            }

        return await bounded(result)

    @router.get("/v1/competition/cohorts/{cohort}/models/{model}/download-files")
    async def files(
        cohort: Annotated[str, ApiPath(pattern=_ID)],
        model: Annotated[str, ApiPath(pattern=_ID)],
        file_index: int = Query(0, ge=0, le=4095),
        offset: int = Query(0, ge=0, le=131072),
        limit: int = Query(128, ge=1, le=128),
    ):
        def result():
            d, now = selected(cohort, model), datetime.now(timezone.utc)
            if file_index >= len(d.bundle.files):
                raise HTTPException(404, "public model file not found")
            file = d.bundle.files[file_index]
            if d.format == "preserved_chunks":
                chunks = d.files[file_index].chunks
                items = [
                    {
                        "sha256": c.sha256,
                        "size_bytes": c.size_bytes,
                        "url": capability(d.chunk_key(file_index, index), now),
                    }
                    for index, c in enumerate(chunks[offset : offset + limit], start=offset)
                ]
                segments = {
                    "total": len(chunks),
                    "offset": offset,
                    "next_offset": offset + limit if offset + limit < len(chunks) else None,
                    "items": items,
                }
            else:
                start = sum(f.size_bytes for f in d.bundle.files[:file_index])
                segments = {
                    "total": 1 if file.size_bytes else 0,
                    "offset": 0,
                    "next_offset": None,
                    "items": []
                    if not file.size_bytes
                    else [
                        {
                            "url": capability(d.payload_key(), now),
                            "range_start": start,
                            "size_bytes": file.size_bytes,
                            "sha256": file.sha256,
                        }
                    ],
                }
            return {
                "model_sha256": model,
                "file_index": file_index,
                "file": file.model_dump(),
                "url_expires_at_utc": expiry(now),
                "method": "GET",
                "segments": segments,
            }

        return await bounded(result)

    return router


def create_cohort_public_app(config: CohortPublicApiConfig, *, signer: R2SigV4 | None = None):
    scores = PublicModelScoreCache(
        config.results.directory,
        maximum_bytes=config.maximum_artifact_bytes,
        corrections=config.model_score_corrections,
    )

    @asynccontextmanager
    async def lifespan(app):
        stop = asyncio.Event()
        try:
            await run_owned_thread(scores.sample)
        except (OSError, ValueError):
            scores.failed = True
        task = asyncio.create_task(scores.run(stop))
        try:
            yield
        finally:
            stop.set()
            await task

    app = FastAPI(
        title="UMI public cohort results", docs_url=None, redoc_url=None, lifespan=lifespan
    )
    app.state.model_scores = scores
    app.include_router(cohort_public_routes(config, signer=signer, model_scores=scores))
    return app
