from __future__ import annotations

import pytest

from umi.competition_cli import _parser, execute
from umi.protocol import canonical_json_bytes

from .test_competition_retrieval import _bundle, _signed
from .test_competition_retrieval import policy as policy


def arguments(tmp_path, policy):
    bundle, _ = _bundle()
    signed = _signed(policy, bundle)
    policy_path = tmp_path / "policy.json"
    signed_path = tmp_path / "submission.json"
    policy_path.write_bytes(canonical_json_bytes(policy))
    signed_path.write_bytes(canonical_json_bytes(signed))
    return signed, [
        "--policy",
        str(policy_path),
        "retrieve-bundle",
        "--submission",
        str(signed_path),
        "--source-base-url",
        "https://models.example/bundle",
        "--archive",
        str(tmp_path / "archive"),
        "--maximum-files",
        "20",
        "--maximum-file-bytes",
        "10000",
        "--maximum-total-bytes",
        "100000",
        "--request-timeout-seconds",
        "1",
        "--total-download-timeout-seconds",
        "2",
    ]


def test_retrieval_cli_passes_explicit_bounds_and_returns_no_private_paths(
    tmp_path, policy, monkeypatch
):
    signed, argv = arguments(tmp_path, policy)

    async def retrieve(value, **kwargs):
        assert value == signed
        assert kwargs["policy"] == policy
        assert kwargs["source_base_url"] == "https://models.example/bundle"
        assert kwargs["limits"].maximum_total_bytes == 100000
        assert kwargs["limits"].total_download_timeout_seconds == 2
        return tmp_path / "private-archive-location"

    monkeypatch.setattr("umi.competition_retrieval.retrieve_signed_model_bundle", retrieve)
    assert execute(_parser().parse_args(argv)) == {
        "status": "bundle_preserved",
        "model_sha256": signed.submission.model_revision,
        "model_executed": False,
        "chain_submission_authorized": False,
    }


def test_retrieval_cli_requires_operator_download_limits(tmp_path, policy):
    _, argv = arguments(tmp_path, policy)
    index = argv.index("--maximum-total-bytes")
    with pytest.raises(SystemExit):
        _parser().parse_args(argv[:index] + argv[index + 2 :])


def test_retrieval_cli_does_not_report_success_after_retrieval_failure(
    tmp_path, policy, monkeypatch
):
    _, argv = arguments(tmp_path, policy)

    async def fail(*args, **kwargs):
        raise RuntimeError("artifact_file_sha256_mismatch")

    monkeypatch.setattr("umi.competition_retrieval.retrieve_signed_model_bundle", fail)
    with pytest.raises(RuntimeError, match="sha256_mismatch"):
        execute(_parser().parse_args(argv))
