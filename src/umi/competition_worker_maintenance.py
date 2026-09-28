"""Apply root-approved, signed source maintenance to one historical worker image."""

from dataclasses import dataclass
from pathlib import Path

from .competition_host_artifacts import _read_tree
from .competition_host_maintenance import SupervisorHostMaintenanceApproval, verify_host_maintenance
from .open_competition import digest

_HOST_PARENT = Path("/opt/umi-validator-supervisor-hosts")


@dataclass(frozen=True)
class ApprovedWorkerSourceOverlay:
    approval: SupervisorHostMaintenanceApproval
    root: Path

    def source_for(self, activation):
        scope = self.approval.worker_overlay
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
        _read_tree(self.root, self.approval.signed_host.manifest)
        return self.root / "src/umi"


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
