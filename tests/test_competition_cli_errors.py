"""Public command failures retain useful codes without exposing private inputs."""

from types import SimpleNamespace

import pytest

from umi import competition_cli
from umi.competition_client import CompetitionSubmissionError


@pytest.mark.parametrize(
    ("error", "diagnostic"),
    [
        (CompetitionSubmissionError("invalid_model_upload_status"), "invalid_model_upload_status"),
        (
            CompetitionSubmissionError("model_upload_rejected", status_code=409),
            "model_upload_rejected; HTTP 409",
        ),
        (
            CompetitionSubmissionError("https://r2.invalid/?X-Amz-Signature=private"),
            "submission_failed",
        ),
        (CompetitionSubmissionError("bad\nprivate-body"), "submission_failed"),
        (CompetitionSubmissionError("x" * 97), "submission_failed"),
        (CompetitionSubmissionError("safe_code", status_code="private"), "safe_code"),
        (CompetitionSubmissionError("safe_code", status_code=600), "safe_code"),
        (CompetitionSubmissionError("safe_code", status_code=True), "safe_code"),
        (ValueError("private signed body"), "ValueError"),
        (OSError("/private/wallet/path"), "OSError"),
    ],
)
def test_cli_failure_diagnostic_is_bounded_and_redacted(monkeypatch, capsys, error, diagnostic):
    # Reach the real parser's exit path without loading a policy or wallet.
    parser = competition_cli._parser()
    monkeypatch.setattr(parser, "parse_args", lambda argv: SimpleNamespace(command="submit-model"))
    monkeypatch.setattr(competition_cli, "_parser", lambda: parser)

    def fail(args):
        raise error

    monkeypatch.setattr(competition_cli, "execute", fail)
    with pytest.raises(SystemExit) as caught:
        competition_cli.main([])
    assert caught.value.code == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert output.err == f"competition command rejected ({diagnostic}); check inputs\n"
    assert "private" not in output.err
