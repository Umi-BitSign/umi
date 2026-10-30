"""One public source qualification batch; service lifetime owns temporary files."""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from urllib.parse import parse_qs, unquote, urlsplit

BASE = "899c7c4520981a5996fab82d74bc7db6ee45eb57"
TESTS = """
tests/test_competition_acceptance_stage_eta.py
tests/test_competition_cohort_continued_model_retry.py
tests/test_competition_cohort_direct_upload_progress.py
tests/test_competition_cohort_model_scheduling.py
tests/test_competition_cohort_model_upload_continuation.py
tests/test_competition_cohort_native_pipeline.py
tests/test_competition_cohort_native_reference_compatibility.py
tests/test_competition_cohort_promotion_copy.py
tests/test_competition_cohort_request_preflight.py
tests/test_competition_cohort_service_queue.py
tests/test_competition_cohort_upload_references.py
tests/test_competition_evaluation_runtime_execution.py
tests/test_competition_history_source_externalization.py
tests/test_competition_imported_proof_retirement.py
tests/test_competition_order_continuation.py
tests/test_competition_preserved_verification_reuse.py
tests/test_competition_readonly_proof_receipts.py
tests/test_competition_registration_pin_background.py
tests/test_competition_remote_proof_completion_page.py
tests/test_competition_remote_proof_store.py
tests/test_competition_reward_admission_runner.py
tests/test_competition_reward_checkpoint_metadata_progress.py
tests/test_competition_reward_coordinator_boot.py
tests/test_competition_reward_history.py
tests/test_competition_reward_history_archive_backfill.py
tests/test_competition_reward_history_frontier.py
tests/test_competition_reward_history_progress.py
tests/test_competition_reward_preparation.py
tests/test_competition_reward_proof_archive.py
tests/test_competition_round_journal_physical_capacity.py
tests/test_competition_round_rpc_migration.py
tests/test_competition_verification_rules.py
tests/test_host_memory_requests.py
""".split()


def main():
    if os.geteuid() == 0 or not sys.flags.isolated or not sys.dont_write_bytecode:
        raise ValueError("isolated nonroot Python -I -B required")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scratch", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    source = Path(__file__).resolve().parents[1]
    scratch, output = args.scratch.resolve(strict=True), args.output.resolve(strict=True)
    if scratch != Path("/run/umi-retirement-public-v1") or any(scratch.iterdir()):
        raise ValueError("fresh service-owned scratch required")
    if any(output.iterdir()):
        raise ValueError("results already exist; do not replay this batch")
    os.chdir(source)
    os.environ.update(TMPDIR=str(scratch), HOME=str(scratch),
                      XDG_CACHE_HOME=str(scratch / "cache"),
                      PYTEST_DISABLE_PLUGIN_AUTOLOAD="1", PYTHONDONTWRITEBYTECODE="1")
    started, stage = time.monotonic(), "format_and_manifest"
    manifest = source / "src/umi/competition_verification_rules.json"
    external = json.loads(manifest.read_bytes())["external_distributions"]
    changed = subprocess.check_output(["git", "diff", "--name-only", BASE, "HEAD"], text=True).splitlines()
    paths = [name for name in changed if name.startswith(("src/", "tests/")) and name.endswith(".py")]
    if not 1 <= len(paths) <= 64:
        raise ValueError("expected a bounded nonempty source formatting scope")
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    result = dict(revision=revision, public_base=BASE, test_modules=TESTS, passed=False)

    def progress(**values):
        row = dict(stage=stage, elapsed_seconds=round(time.monotonic() - started, 3),
                   observed_utc=datetime.now(timezone.utc).isoformat(),
                   planning_eta_seconds=[60, 1800],
                   eta_basis="planning: formatting, native manifest refresh and 33 focused modules",
                   stalled_or_retrying=False)
        row.update(values)
        print(json.dumps(row), flush=True)
        with (output / "progress.jsonl").open("a") as stream:
            stream.write(json.dumps(row) + "\n")

    try:
        progress(completed=0, total=4)
        try:
            for arguments in ([str(source / ".venv/bin/ruff"), "format", "--no-cache", *paths],
                              [str(source / ".venv/bin/ruff"), "check", "--no-cache", *paths],
                              [sys.executable, "-I", "-B", "tools/verification_manifest.py"]):
                subprocess.run(arguments, check=True, timeout=120)
            if json.loads(manifest.read_bytes())["external_distributions"] != external:
                raise ValueError("qualified external dependency versions changed")
            (output / "competition_verification_rules.json").write_bytes(manifest.read_bytes())
        finally:
            with (output / "public-output.patch").open("wb") as stream:
                subprocess.run(["git", "diff", "--binary", "--", "src", "tests"],
                               check=True, stdout=stream, timeout=30)
        stage = "focused_fixtures"
        progress(completed=3, total=4)

        def audit(event, arguments):
            if event != "sqlite3.connect":
                return
            value = os.fsdecode(arguments[0])
            if value == ":memory:":
                return
            if value.startswith("file:"):
                parsed = urlsplit(value)
                if parsed.netloc:
                    raise ValueError("SQLite URI authority is not fixture-local")
                if parse_qs(parsed.query).get("mode") == ["memory"]:
                    return
                value = unquote(parsed.path)
            if not Path(value).resolve().is_relative_to(scratch):
                raise ValueError("SQLite access must stay within test scratch")

        sys.addaudithook(audit)
        sys.path[:0] = [str(source / "src"), str(source)]
        import pytest
        import umi

        if not Path(umi.__file__).resolve().is_relative_to(source / "src"):
            raise ValueError("fixtures imported another source tree")

        class Progress:
            total = completed = 0
            start = time.monotonic()

            def pytest_collection_finish(self, session):
                self.total = len(session.items)

            def pytest_runtest_logreport(self, report):
                if report.when != "teardown":
                    return
                self.completed += 1
                elapsed = time.monotonic() - self.start
                progress(completed=self.completed, total=self.total, case=report.nodeid,
                         eta_seconds=elapsed * (self.total - self.completed) / self.completed,
                         eta_basis="current fixture count rate; unequal fixture costs remain uncertain")

        code = pytest.main(["-q", "-p", "no:cacheprovider", "-p", "pytest_asyncio.plugin",
                            "-c", str(source / "pyproject.toml"),
                            "--basetemp=" + str(scratch / "pytest"),
                            "--junitxml=" + str(output / "results.xml"), *TESTS], plugins=[Progress()])
        result.update(passed=code == 0, pytest_exit_code=int(code))
        return int(code)
    except Exception as error:
        result["error"] = str(error)
        raise
    finally:
        result.update(stage=stage, elapsed_seconds=round(time.monotonic() - started, 3))
        (output / "result.json").write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
