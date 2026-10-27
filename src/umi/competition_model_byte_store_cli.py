"""Export native completed model byte facts for an explicitly selected old layout.

Run as the existing source service account with a root-controlled request. The
result grants no signing/adoption authority. Install its exact export pins in the
new account-private shared store selection before starting consumers.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
from pathlib import Path
from typing import Literal

from pydantic import Field

from .competition_cohort_history import CohortRecoveryHistory
from .competition_cohort_model_delivery_candidate import (
    ModelDeliveryAdoptionCandidate,
    ModelDeliveryAdoptionCandidateConfig,
)
from .competition_cohort_recovery import CohortRecoveryTransition
from .competition_host_activation import _read_root_control_path
from .competition_model_byte_snapshot import (
    PortableByteSnapshotPin,
    capture_portable_snapshot,
    restore_portable_snapshot,
)
from .competition_model_byte_snapshot_r2 import (
    PortableByteSnapshotRemotePin,
    download_portable_snapshot,
    replicate_portable_snapshot,
)
from .competition_model_byte_store import ModelByteStoreConfig, ModelByteStoreImport
from .competition_model_generation_store import (
    CHUNKED_MODEL_BYTE_ABI,
    grow_generation_owner,
    initialize_generation_owner,
)
from .competition_transport_verification import TransferProgress, verifier_semantics
from .open_competition import CompetitionPolicy
from .private_files import Directory
from .protocol import StrictProtocolModel, canonical_json_bytes
from .r2_evidence import R2EvidenceClient
from .r2_sigv4 import R2SigV4, load_r2_credentials


class ModelByteStoreExportRequest(StrictProtocolModel):
    schema_: Literal["umi-model-byte-store-export-request/1"] = Field(alias="schema")
    candidate: ModelDeliveryAdoptionCandidateConfig
    policy: CompetitionPolicy
    history: CohortRecoveryHistory
    transition: CohortRecoveryTransition


class PortableByteExportRequest(StrictProtocolModel):
    schema_: Literal["umi-model-byte-portable-export-request/1"] = Field(alias="schema")
    source: ModelByteStoreImport
    directory: Directory


class PortableByteRestoreRequest(StrictProtocolModel):
    schema_: Literal["umi-model-byte-portable-restore-request/1"] = Field(alias="schema")
    source: PortableByteSnapshotPin
    directory: Directory


class PortableByteUploadRequest(StrictProtocolModel):
    schema_: Literal["umi-model-byte-portable-upload-request/1"] = Field(alias="schema")
    source: PortableByteSnapshotPin
    credentials_file: Directory
    bucket: str
    prefix: str
    timeout_seconds: int = Field(default=60, ge=1, le=300)


class PortableByteDownloadRequest(StrictProtocolModel):
    schema_: Literal["umi-model-byte-portable-download-request/1"] = Field(alias="schema")
    source: PortableByteSnapshotRemotePin
    credentials_file: Directory
    directory: Directory
    timeout_seconds: int = Field(default=60, ge=1, le=300)
    repair: bool = False


class ModelGenerationInitializeRequest(StrictProtocolModel):
    schema_: Literal["umi-model-generation-owner-initialize/1"] = Field(alias="schema")
    store: ModelByteStoreConfig


class ModelGenerationCapacityRequest(StrictProtocolModel):
    schema_: Literal["umi-model-generation-owner-grow/1"] = Field(alias="schema")
    store: ModelByteStoreConfig


def _portable_r2_client(path, bucket, timeout):
    loaded = load_r2_credentials(Path(path))
    return R2EvidenceClient(
        R2SigV4(loaded.endpoint, bucket, loaded.credentials), timeout_seconds=timeout
    )


async def export_request(request, *, seed_shared=False):
    candidate = ModelDeliveryAdoptionCandidate(request.candidate, request.policy)
    if seed_shared:
        await candidate.seed_shared_completed(request.history, request.transition)
        return ()
    return await candidate.export_completed(request.history, request.transition)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "operation",
        choices=[
            "export",
            "seed-shared",
            "portable-export",
            "portable-restore",
            "portable-upload",
            "portable-download",
            "initialize-generations",
            "repair-generations",
            "grow-generations",
        ],
    )
    parser.add_argument("--request", type=Path, required=True)
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    with TransferProgress(
        "model_byte_store_request_validation",
        1,
        unit="requests",
        planning_unit_seconds=(0.01, 30.0),
    ) as progress:
        raw = _read_root_control_path(args.request, 64 * 1024**2, modes={0o444})
        request_type = {
            "portable-export": PortableByteExportRequest,
            "portable-restore": PortableByteRestoreRequest,
            "portable-upload": PortableByteUploadRequest,
            "portable-download": PortableByteDownloadRequest,
            "initialize-generations": ModelGenerationInitializeRequest,
            "grow-generations": ModelGenerationCapacityRequest,
        }.get(args.operation, ModelByteStoreExportRequest)
        request = request_type.model_validate_json(raw)
        if canonical_json_bytes(request) != raw:
            raise ValueError("model byte export request must retain canonical selected inputs")
        progress.advance(1)
    if args.operation == "initialize-generations":
        if request.store.generation_owner is None:
            raise ValueError("generation initialization requires an explicit retention owner")
        initialize_generation_owner(
            request.store.directory,
            request.store.generation_owner,
            semantics=[CHUNKED_MODEL_BYTE_ABI, verifier_semantics()],
        )
        print(
            canonical_json_bytes(
                {
                    "generation_owner_initialized": True,
                    "remote_objects_checked": 0,
                    "certification_authority": False,
                }
            ).decode()
        )
        return 0
    if args.operation == "grow-generations":
        if request.store.generation_owner is None:
            raise ValueError("generation capacity recovery requires its explicit retention owner")
        grow_generation_owner(
            request.store.directory,
            request.store.generation_owner,
            semantics=[CHUNKED_MODEL_BYTE_ABI, verifier_semantics()],
        )
        print(
            canonical_json_bytes(
                {
                    "generation_owner_capacity_updated": True,
                    "pending_event_metadata_retained": True,
                    "remote_objects_checked": 0,
                    "certification_authority": False,
                }
            ).decode()
        )
        return 0
    if args.operation == "repair-generations":
        candidate = ModelDeliveryAdoptionCandidate(request.candidate, request.policy)
        asyncio.run(candidate.repair_generations(request.history, request.transition))
        print(
            canonical_json_bytes(
                {
                    "original_generation_repair_completed": True,
                    "certification_authority": False,
                }
            ).decode()
        )
        return 0
    if args.operation == "portable-export":
        snapshot = capture_portable_snapshot(request.source, Path(request.directory))
        print(
            canonical_json_bytes(
                {
                    "snapshot": snapshot.model_dump(mode="json"),
                    "certification_authority": False,
                    "current_generation_checks_performed": False,
                }
            ).decode()
        )
        return 0
    if args.operation == "portable-restore":
        print(
            canonical_json_bytes(
                restore_portable_snapshot(request.source, Path(request.directory))
            ).decode()
        )
        return 0
    if args.operation == "portable-upload":
        client = _portable_r2_client(
            request.credentials_file, request.bucket, request.timeout_seconds
        )
        remote = replicate_portable_snapshot(request.source, client, request.prefix)
        print(
            canonical_json_bytes(
                {
                    "remote_snapshot": remote.model_dump(mode="json"),
                    "certification_authority": False,
                    "local_deletion_authorized": False,
                }
            ).decode()
        )
        return 0
    if args.operation == "portable-download":
        client = _portable_r2_client(
            request.credentials_file, request.source.bucket, request.timeout_seconds
        )
        local = download_portable_snapshot(
            request.source, client, Path(request.directory), repair=request.repair
        )
        print(
            canonical_json_bytes(
                {
                    "snapshot": local.model_dump(mode="json"),
                    "certification_authority": False,
                    "current_generation_checks_performed": False,
                }
            ).decode()
        )
        return 0
    exports = asyncio.run(export_request(request, seed_shared=args.operation == "seed-shared"))
    print(
        canonical_json_bytes(
            {
                "imports": [v.model_dump(mode="json") for v in exports],
                "certification_authority": False,
                "shared_file_seed_completed": args.operation == "seed-shared",
            }
        ).decode()
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
