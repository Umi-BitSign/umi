"""Allowlisted public model objects; never sign a caller-supplied R2 key."""

from __future__ import annotations

import hashlib
from typing import Annotated, Literal

from pydantic import Field, model_validator

from .competition_cohort_direct_model_upload import DirectModelPayload, preserved_model_object_key
from .open_competition import ModelBundle, digest
from .protocol import Hex32, StrictProtocolModel


class PublicChunk(StrictProtocolModel):
    sha256: Hex32
    size_bytes: Annotated[int, Field(gt=0, le=8 * 1024**2)]


class PublicChunkedFile(StrictProtocolModel):
    path: str
    chunks: Annotated[tuple[PublicChunk, ...], Field(max_length=131072)]


class PublicArchive(StrictProtocolModel):
    sha256: Hex32
    size_bytes: Annotated[int, Field(gt=0)]
    source_package_sha256: Hex32


class PublicModelDownload(StrictProtocolModel):
    schema_: Literal["umi-public-model-download/1"] = Field(alias="schema")
    cohort_sha256: Hex32
    model_sha256: Hex32
    bundle: ModelBundle
    format: Literal["preserved_chunks", "concatenated_payload"]
    package_sha256: Hex32 | None = None
    files: Annotated[tuple[PublicChunkedFile, ...], Field(max_length=4096)] = ()
    payload: DirectModelPayload | None = None
    archive: PublicArchive | None = None

    @model_validator(mode="after")
    def geometry(self):
        if digest(self.bundle) != self.model_sha256:
            raise ValueError("public download manifest has another model identity")
        if self.format == "preserved_chunks":
            if self.payload is not None or self.package_sha256 is None:
                raise ValueError("chunked public download requires its package identity")
            if len(self.files) != len(self.bundle.files):
                raise ValueError("chunked public download omits manifest files")
            for indexed, native in zip(self.files, self.bundle.files, strict=True):
                if (
                    indexed.path != native.path
                    or sum(c.size_bytes for c in indexed.chunks) != native.size_bytes
                ):
                    raise ValueError("chunked public file differs from native manifest")
                if any(c.size_bytes != 8 * 1024**2 for c in indexed.chunks[:-1]):
                    raise ValueError("chunked public file has noncanonical piece geometry")
        else:
            if self.payload is None or self.files or self.package_sha256 is not None:
                raise ValueError("concatenated download requires its original payload descriptor")
            if (
                self.payload.model_sha256 != self.model_sha256
                or self.payload.file_count != len(self.bundle.files)
                or self.payload.total_bytes != sum(f.size_bytes for f in self.bundle.files)
            ):
                raise ValueError("public payload differs from complete manifest")
        if self.archive is not None and self.archive.source_package_sha256 != self.package_sha256:
            raise ValueError("public archive does not bind the selected retained package")
        return self

    def chunk_key(self, file_index: int, chunk_index: int) -> str:
        return "preservation/v1/chunks/sha256/" + self.files[file_index].chunks[chunk_index].sha256

    def payload_key(self) -> str:
        if self.payload is None:
            raise ValueError("this public model has no concatenated payload")
        return preserved_model_object_key(
            self.cohort_sha256, self.model_sha256, self.payload.payload_sha256
        )

    def archive_key(self) -> str:
        if self.archive is None:
            raise ValueError("this public model has no complete archive")
        return f"downloads/v1/models/{self.model_sha256}/umi-model-bundle.tar"


def legacy_download(cohort: str, bundle: ModelBundle, association: dict, package_raw: bytes):
    """Compatibility reader for retained C5 replication metadata, no model reads."""
    import json

    model, package_sha = digest(bundle), hashlib.sha256(package_raw).hexdigest()
    package = json.loads(package_raw)
    expected_association = {
        "schema": "umi-cohort-model-backup-association/1",
        "model_sha256": model,
        "package_key": f"packages/{model}/{package_sha}.json",
        "package_sha256": package_sha,
        "verification": "all_declared_bytes_uploaded_and_read_back",
        "artifact_acceptance_certified": False,
    }
    if association != expected_association or (
        package.get("schema") != "umi-cohort-model-preserved-package/1"
        or package.get("model_sha256") != model
        or package.get("chunk_bytes") != 8 * 1024**2
        or ModelBundle.model_validate_json(json.dumps(package.get("native_bundle"))) != bundle
    ):
        raise ValueError("retained public package association or manifest differs")
    return PublicModelDownload.model_validate_json(
        json.dumps(
            {
                "schema": "umi-public-model-download/1",
                "cohort_sha256": cohort,
                "model_sha256": model,
                "bundle": bundle.model_dump(mode="json", by_alias=True),
                "format": "preserved_chunks",
                "package_sha256": package_sha,
                "files": package["files"],
            }
        )
    )
