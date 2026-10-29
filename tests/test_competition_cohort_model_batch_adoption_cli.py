"""Exercise the isolated actor CLI subprocess used by source-maintenance hosts."""

import json
import os
import pwd
import subprocess
import sys
from pathlib import Path

import pytest

from umi import competition_cohort_model_batch_adoption_operator as operator
from umi.protocol import canonical_json_bytes

MODULE = "umi.competition_cohort_model_batch_adoption_cli"
SOURCE = str(Path(operator.__file__).resolve().parents[1])


@pytest.fixture
def actor_payload(tmp_path):
    return {
        "target": {
            "role": "owner",
            "service_unit": "test-adoption-owner.service",
            "service_account": pwd.getpwuid(os.getuid()).pw_name,
            "config_path": str(tmp_path / "owner.json"),
            "config_sha256": "ab" * 32,
        },
        "request": {
            "schema": "umi-model-batch-adoption-review-request/1",
            "adoption": {
                "schema": "umi-model-batch-certification-adoption/1",
                "policy_sha256": "01" * 32,
                "cohort_sha256": "02" * 32,
                "authority_sha256": "03" * 32,
                "predecessor_sha256": "04" * 32,
                "history_prefix_sha256": "05" * 32,
                "effective_at_block": 225,
                "rule": "cohort_manifest_merkle_quorum/1",
                "preserve_legacy_certificates": True,
            },
            "operator_request_reference": "retained isolated CLI test request",
        },
        "signed": None,
        "check_only": False,
    }


def actor_cli(raw, *, intercept_publication=False):
    # Keep the actual runpy launch shape and its default alter_sys=False. Do not
    # import the CLI or its model names into __main__: that hides the regression.
    code = "import runpy,sys;sys.path.insert(0," + repr(SOURCE) + ")\n"
    if intercept_publication:
        # Publication authority/private I/O have their own tests. Intercept only
        # that boundary after the real child has parsed and canonicalized stdin.
        code += (
            "from umi import competition_cohort_model_batch_adoption_operator as actor\n"
            "def publish(target,request,signed=None,*,check_only=False):\n"
            " return dict(target=target.model_dump(mode='json'),"
            "request=request.model_dump(mode='json',by_alias=True),"
            "signed=signed,check_only=check_only)\n"
            "actor.publish_for_actor=publish\n"
        )
    code += f"sys.argv=[{MODULE!r},'publish'];runpy.run_module({MODULE!r},run_name='__main__')"
    result = subprocess.run(
        [sys.executable, "-I", "-B", "-c", code],
        input=raw,
        capture_output=True,
        timeout=30,
    )
    assert len(result.stdout) <= 16384
    return result.returncode, json.loads(result.stdout)


@pytest.mark.parametrize("check_only", [False, True])
def test_source_wrapper_actor_cli_round_trips_canonical_request(actor_payload, check_only):
    actor_payload["check_only"] = check_only
    raw = canonical_json_bytes(actor_payload)
    status, result = actor_cli(raw, intercept_publication=True)
    assert status == 0
    assert canonical_json_bytes(result) == raw


@pytest.mark.parametrize(
    ("case", "error_type"),
    [
        ("empty", "ValidationError"),
        ("noncanonical", "ValueError"),
        ("omitted-default", "ValueError"),
        ("invalid-boolean", "ValidationError"),
        ("oversized", "ValueError"),
    ],
)
def test_source_wrapper_actor_cli_preserves_input_refusals(actor_payload, case, error_type):
    raw = canonical_json_bytes(actor_payload)
    if case == "empty":
        raw = b""
    elif case == "noncanonical":
        raw += b"\n"
    elif case == "omitted-default":
        del actor_payload["check_only"]
        raw = canonical_json_bytes(actor_payload)
    elif case == "invalid-boolean":
        actor_payload["check_only"] = "false"
        raw = canonical_json_bytes(actor_payload)
    elif case == "oversized":
        raw = b" " * (128 * 1024 + 1)
    status, result = actor_cli(raw)
    assert status == 1
    assert result == {
        "status": "failed",
        "error_type": error_type,
        "reason_code": None,
        "retained_work_reused_on_exact_retry": True,
    }


def test_source_wrapper_actor_cli_preserves_account_refusal(actor_payload):
    body = operator.ActorPublication.model_validate_json(canonical_json_bytes(actor_payload))
    account = "umi-adoption-unrelated"
    assert account != pwd.getpwuid(os.getuid()).pw_name
    target = body.target.model_copy(update={"service_account": account})
    raw = canonical_json_bytes({**actor_payload, "target": target.model_dump(mode="json")})
    status, result = actor_cli(raw)
    assert status == 1
    assert result["error_type"] == "ModelBatchAdoptionRefused"
    assert (
        result["reason_code"] == "batch_adoption_publication_must_use_the_selected_service_account"
    )
