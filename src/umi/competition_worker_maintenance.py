"""Apply root-approved, signed source maintenance to one historical worker image."""

import hashlib
from dataclasses import dataclass
from pathlib import Path

from .competition_host_activation import (
    AuthenticatedSuccessorWorkerInputs,
    validate_authenticated_successor_installation,
)
from .competition_host_artifacts import (
    SignedSuccessorHostArtifact,
    _read_tree,
    verify_host_artifact_authority,
)
from .competition_host_maintenance import SupervisorHostMaintenanceApproval, verify_host_maintenance
from .competition_worker_overlay_scope import WorkerSourceOverlayScope
from .open_competition import digest
from .protocol import canonical_json_bytes

_HOST_PARENT = Path("/opt/umi-validator-supervisor-hosts")


def _source_for(activation, *, scope, signed_host, root):
    authorization = activation._inputs.authorization
    continuation = authorization.authorization.continuation if authorization else None
    if (
        scope is None
        or activation.package_sha256 != scope.package_sha256
        or activation.release_identity.release_bundle_sha256 != scope.release_bundle_sha256
        or continuation is None
        or continuation.recipient_amendment is None
        or digest(continuation.recipient_amendment)
        not in {scope.recipient_amendment_sha256, scope.successor_recipient_amendment_sha256}
    ):
        raise ValueError("worker source maintenance differs from approved package or amendment")
    _read_tree(root, signed_host.manifest)
    return root / "src/umi"


@dataclass(frozen=True)
class ApprovedWorkerSourceOverlay:
    approval: SupervisorHostMaintenanceApproval
    root: Path

    @property
    def host_manifest_sha256(self):
        return self.approval.signed_host.manifest_sha256

    def source_for(self, activation):
        return _source_for(
            activation,
            scope=self.approval.worker_overlay,
            signed_host=self.approval.signed_host,
            root=self.root,
        )


@dataclass(frozen=True)
class ApprovedInitialWorkerSourceOverlay:
    signed_host: SignedSuccessorHostArtifact
    scope: WorkerSourceOverlayScope
    root: Path

    @property
    def host_manifest_sha256(self):
        return self.signed_host.manifest_sha256

    def source_for(self, activation):
        return _source_for(
            activation,
            scope=self.scope,
            signed_host=self.signed_host,
            root=self.root,
        )


def approved_initial_worker_source_overlay(
    *,
    installation: AuthenticatedSuccessorWorkerInputs,
    signed_host: SignedSuccessorHostArtifact,
) -> ApprovedInitialWorkerSourceOverlay | None:
    """Use only the source and scope sealed into the original installation."""
    validate_authenticated_successor_installation(installation)
    scope = installation.operator_consent.worker_source_overlay
    if scope is None:
        return None
    receipt = installation._receipt
    payload = canonical_json_bytes(signed_host)
    if (
        hashlib.sha256(payload).hexdigest() != receipt.signed_host_artifact_sha256
        or len(payload) != receipt.signed_host_artifact_size_bytes
        or signed_host.manifest_sha256 != receipt.host_manifest_sha256
        or signed_host.manifest.umi_git_revision != receipt.host_umi_git_revision
    ):
        raise ValueError("initial worker source differs from sealed host receipt")
    verify_host_artifact_authority(
        signed_host,
        config=installation.config,
        expected_manifest_sha256=installation.operator_consent.approved_host_manifest_sha256,
    )
    root = _HOST_PARENT / signed_host.manifest.umi_git_revision
    _read_tree(root, signed_host.manifest)
    return ApprovedInitialWorkerSourceOverlay(signed_host, scope, root)


def approved_worker_source_overlay(payload, *, installation, running_root):
    signed = verify_host_maintenance(
        payload, config=installation.config, receipt=installation._receipt
    )
    approval = SupervisorHostMaintenanceApproval.model_validate_json(payload)
    if approval.worker_overlay is None:
        return None
    root = _HOST_PARENT / signed.manifest.umi_git_revision
    if running_root != root:
        raise ValueError("worker source maintenance must use the running signed host")
    _read_tree(root, signed.manifest)
    return ApprovedWorkerSourceOverlay(approval, root)
