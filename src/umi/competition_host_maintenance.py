"""Operator-approved supervisor replacement preserving the installed worker deal.

The root-owned approval selects a separately signed executable host. Original
activation controls, worker release, journals and reward authority stay intact.
"""

from __future__ import annotations

import hashlib
from typing import Literal

from pydantic import Field

from .competition_host_artifacts import SignedSuccessorHostArtifact, verify_host_artifact_authority
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes


class SupervisorHostMaintenanceApproval(StrictProtocolModel):
    schema_: Literal["umi-supervisor-host-maintenance/1"] = Field(alias="schema")
    config_sha256: Hex32
    installation_receipt_sha256: Hex32
    original_host_manifest_sha256: Hex32
    signed_host: SignedSuccessorHostArtifact


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
