import hashlib

import pytest

from umi.competition_host_maintenance import (
    SupervisorHostMaintenanceApproval,
    verify_host_maintenance,
)
from umi.protocol import Hex32, StrictProtocolModel, canonical_json_bytes

from .test_competition_host_artifacts import sign
from .test_competition_host_artifacts import staged as staged
from .test_competition_supervisor_cli import running_host as running_host


class Receipt(StrictProtocolModel):
    host_manifest_sha256: Hex32
    host_umi_git_revision: str


class RunningReceipt(Receipt):
    signed_host_artifact_sha256: Hex32


def _approval(staged):
    receipt = Receipt(host_manifest_sha256="a" * 64, host_umi_git_revision="b" * 40)
    approval = SupervisorHostMaintenanceApproval(
        schema="umi-supervisor-host-maintenance/1",
        config_sha256=hashlib.sha256(canonical_json_bytes(staged.config)).hexdigest(),
        installation_receipt_sha256=hashlib.sha256(canonical_json_bytes(receipt)).hexdigest(),
        original_host_manifest_sha256=receipt.host_manifest_sha256,
        signed_host=staged.signed,
    )
    return receipt, approval


def test_maintenance_authenticates_new_host_without_rewriting_original_receipt(staged):
    receipt, approval = _approval(staged)
    before = canonical_json_bytes(receipt)
    assert verify_host_maintenance(
        canonical_json_bytes(approval), config=staged.config, receipt=receipt
    ) == staged.signed
    assert canonical_json_bytes(receipt) == before


@pytest.mark.parametrize("field", [
    "config_sha256", "installation_receipt_sha256", "original_host_manifest_sha256",
])
def test_maintenance_rejects_wrong_installation(staged, field):
    receipt, approval = _approval(staged)
    approval = approval.model_copy(update={field: "c" * 64})
    with pytest.raises(ValueError, match="another installation"):
        verify_host_maintenance(
            canonical_json_bytes(approval), config=staged.config, receipt=receipt
        )


def test_maintenance_still_requires_release_authority_signature(staged):
    receipt, approval = _approval(staged)
    body = approval.model_dump(mode="json", by_alias=True)
    signature = body["signed_host"]["signatures"][0]["signature"]
    body["signed_host"]["signatures"][0]["signature"] = (
        ("0" if signature[0] != "0" else "1") + signature[1:]
    )
    with pytest.raises(ValueError):
        verify_host_maintenance(canonical_json_bytes(body), config=staged.config, receipt=receipt)


def test_running_maintenance_host_verifies_both_original_and_new_authority(
    running_host, monkeypatch, capsys
):
    from umi import competition_supervisor_cli as cli

    case = running_host
    original = sign(case.signed.manifest.model_copy(update={"umi_git_revision": "b" * 40}))
    payload = canonical_json_bytes(original)
    receipt = RunningReceipt(
        host_manifest_sha256=original.manifest_sha256,
        host_umi_git_revision=original.manifest.umi_git_revision,
        signed_host_artifact_sha256=hashlib.sha256(payload).hexdigest(),
    )
    case.installation._receipt = receipt
    case.installation.host_manifest_sha256 = original.manifest_sha256
    approval = SupervisorHostMaintenanceApproval(
        schema="umi-supervisor-host-maintenance/1",
        config_sha256=hashlib.sha256(canonical_json_bytes(case.installation.config)).hexdigest(),
        installation_receipt_sha256=hashlib.sha256(canonical_json_bytes(receipt)).hexdigest(),
        original_host_manifest_sha256=original.manifest_sha256,
        signed_host=case.signed,
    )
    controls = {
        "validator-supervisor-maintenance.json": canonical_json_bytes(approval),
        cli.SIGNED_HOST_ARTIFACT_FILENAME: payload,
    }
    monkeypatch.setattr(cli, "_root_control", lambda path, maximum: controls[path.name])
    cli._verify_running_host(case.installation)
    assert '"status": "verified"' in capsys.readouterr().out
    # Approval of a new host never authorizes changing the archived old host.
    controls[cli.SIGNED_HOST_ARTIFACT_FILENAME] = canonical_json_bytes(case.signed)
    with pytest.raises(ValueError, match="root receipt"):
        cli._verify_running_host(case.installation)
