"""Operator-approved supervisor replacement preserving the installed worker deal.

The root-owned approval selects a separately signed executable host. Original
activation controls, worker release, journals and reward authority stay intact.
"""

from __future__ import annotations

import hashlib
from typing import Literal

from pydantic import Field, model_serializer, model_validator

from .competition_host_artifacts import SignedSuccessorHostArtifact, verify_host_artifact_authority
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes


class WorkerSourceOverlayScope(StrictProtocolModel):
    package_sha256: Hex32
    release_bundle_sha256: Hex32
    recipient_amendment_sha256: Hex32
    successor_recipient_amendment_sha256: Hex32 | None = None

    @model_serializer(mode="wrap")
    def original_bytes(self, handler):
        value = handler(self)
        if self.successor_recipient_amendment_sha256 is None:
            value.pop("successor_recipient_amendment_sha256", None)
        return value


class SupervisorHostMaintenanceApproval(StrictProtocolModel):
    schema_: Literal["umi-supervisor-host-maintenance/1", "umi-supervisor-host-maintenance/2"] = (
        Field(alias="schema")
    )
    config_sha256: Hex32
    installation_receipt_sha256: Hex32
    original_host_manifest_sha256: Hex32
    signed_host: SignedSuccessorHostArtifact
    worker_overlay: WorkerSourceOverlayScope | None = None

    @model_serializer(mode="wrap")
    def original_bytes(self, handler):
        value = handler(self)
        if self.worker_overlay is None:
            value.pop("worker_overlay", None)
        return value

    @model_validator(mode="after")
    def explicit_worker_approval(self):
        if (self.schema_ == "umi-supervisor-host-maintenance/2") != (
            self.worker_overlay is not None
        ):
            raise ValueError("worker source overlay requires explicit maintenance version 2")
        return self


def verify_host_maintenance(payload: bytes, *, config, receipt):
    """Authenticate a root-approved replacement for this exact installation."""
    approval = SupervisorHostMaintenanceApproval.model_validate_json(payload)
    if canonical_json_bytes(approval) != payload:
        raise ValueError("host maintenance approval is not canonical")
    if (
        approval.config_sha256 != hashlib.sha256(canonical_json_bytes(config)).hexdigest()
        or approval.installation_receipt_sha256
        != hashlib.sha256(canonical_json_bytes(receipt)).hexdigest()
        or approval.original_host_manifest_sha256 != receipt.host_manifest_sha256
        or approval.signed_host.manifest.umi_git_revision == receipt.host_umi_git_revision
    ):
        raise ValueError("host maintenance approval belongs to another installation")
    verify_host_artifact_authority(
        approval.signed_host,
        config=config,
        expected_manifest_sha256=approval.signed_host.manifest_sha256,
    )
    return approval.signed_host
